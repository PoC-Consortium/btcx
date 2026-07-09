//! Chain-data backend speaking the Electrum protocol — the same client
//! for BTC (any public Electrum server) and Bitcoin PoCX (`electrs-pocx`,
//! the dedicated Electrum server; the explorer's indexer
//! `esplora-electrs-pocx` also serves Electrum RPC).
//!
//! All backend data is an untrusted hint: scripts and amounts are verified
//! against locally reconstructed bytes by the caller. A lying backend can
//! withhold or delay, never steal.
//!
//! Bitcoin PoCX caveat baked in: PoCX block headers are 286 bytes with
//! extra consensus fields and a generator signature that is *excluded* from
//! the block hash, so all header handling goes through
//! [`ChainParams::header_hash`]/[`ChainParams::header_time`] on raw bytes —
//! never through `electrum-client`'s Bitcoin-typed header API.

use anyhow::{Context, Result};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::Value;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use params_btcx::params::ChainParams;

/// Overflow/glitch guard on user-supplied and estimator feerates (sat/vB) —
/// NOT a fee ceiling (real caps are the caller's policy business). Shared by
/// the send fee resolution and the estimator paths.
pub const SANITY_MAX_SAT_PER_VB: u64 = 10_000;

/// Is this broadcast error really "the tx is already in the chain / mempool"?
/// Re-broadcasting an already-confirmed tx must be a no-op success, not an
/// error that loops forever. Servers phrase it as an "already in ..." /
/// "already known" message, so we match text.
fn is_already_broadcast(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}").to_ascii_lowercase();
    msg.contains("already in") || msg.contains("already known")
}

/// Estimator answer (BTC per kvB, Electrum `blockchain.estimatefee` and Core
/// `estimatesmartfee` alike) → integer sat/kvB, ROUNDED to nearest
/// (phoenix parity — its send form shows `round(feerate·1e8/100)/10`).
/// `ceil` here silently DOUBLED every fee at the bottom of the market:
/// a 1.01 sat/vB estimate became 2 on both the send presets and every
/// fee-priced spend. Rounding down by a fraction is safe everywhere this
/// feeds — callers floor the result at 1 / `min_feerate_sat_vb`. The one
/// conversion that must NEVER round down — the BIP125 incremental-relay
/// increment — keeps its own `ceil` at its use site.
pub fn btc_kvb_to_sat_kvb(btc_kvb: f64) -> u64 {
    // sat/kvB IS the estimator's native integer resolution — keep it exact.
    (btc_kvb * 1e8).round() as u64
}

/// sat/kvB → integer sat/vB, rounded to nearest (display / integer callers).
pub fn kvb_to_vb_round(sat_kvb: u64) -> u64 {
    (sat_kvb + 500) / 1000
}

/// Electrum socket bounds: TCP connect and per-request read/write. Generous —
/// a single request is one JSON line each way — but FINITE: a stalled remote
/// server must error out instead of hanging a caller (and with it every
/// queued request behind it).
const ELECTRUM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const ELECTRUM_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Short first-round connect timeout: every dial first sweeps all resolved
/// addresses at this budget (absorbing one-off blips and a dead first
/// A-record cheaply), then re-sweeps at the full
/// [`ELECTRUM_CONNECT_TIMEOUT`]. Also the budget standby-promotion dials
/// run on — waking a standby must never stall a user request for long.
const ELECTRUM_CONNECT_RETRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How a wallet send prices itself: a market estimate at a block target
/// (the Slow/Normal/Fast presets) or an explicit user-chosen rate (the send
/// form's Custom field, and the phoenix-style fallback when the estimator
/// has no data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFee {
    /// Market estimate at this conf target, with the 1 sat/vB fallback.
    Target(u16),
    /// Explicit rate in sat/kvB (milli-sat/vB — RPC boundaries speak
    /// decimal sat/vB and multiply by 1000), clamped to the coin floor /
    /// sanity max.
    RatePerKvb(u64),
}

/// The send form's fee preview: raw estimator answers for the three
/// phoenix-parity presets, `None` where the estimator has no data, plus the
/// coin's feerate floor (the custom field's minimum/default).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SendFeeEstimates {
    /// Coin floor, decimal sat/vB.
    pub min_sat_per_vb: f64,
    /// 1-block target, decimal sat/vB at the estimator's full sat/kvB
    /// resolution (e.g. 1080 sat/kvB → 1.08) — integer rounding would throw
    /// away the queue-priority fraction.
    pub fast: Option<f64>,
    /// 6-block target — the preselected preset.
    pub normal: Option<f64>,
    /// 144-block target.
    pub slow: Option<f64>,
}

/// What an unspent-output lookup tells us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutInfo {
    pub value_sat: u64,
    pub script_pubkey_hex: String,
    pub confirmations: u64,
}

/// A backend ANSWERED and the answer proves it is the wrong server for
/// this coin — wrong genesis, pruned history, too-old protocol. That is
/// **disagreement, never absence**: quorum reads may skip a server that
/// does not answer, but must fail hard on one that answers wrong.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ChainMismatch(pub String);

/// One live Electrum connection. `tcp://` is the crate's plaintext client;
/// `ssl://` is OUR rustls setup (see [`connect_electrum_ssl`]) — the crate's
/// own no-validation mode sends an EMPTY `signature_algorithms` extension
/// (its verifier returns no schemes), which strict servers answer with a
/// fatal `DecodeError` alert or a hangup. The `RawClient` supports many
/// concurrent callers (responses are routed by request id), so one
/// connection can be shared by every caller AND the wallet sync worker;
/// [`ElectrumBackend`] replaces the instance on transport errors.
pub(crate) enum ElectrumConn {
    Tcp(
        electrum_client::raw_client::RawClient<
            electrum_client::raw_client::ElectrumPlaintextStream,
        >,
    ),
    Ssl(electrum_client::raw_client::RawClient<electrum_client::raw_client::ElectrumSslStream>),
}

impl ElectrumConn {
    fn raw_call(
        &self,
        method: &str,
        params: Vec<electrum_client::Param>,
    ) -> std::result::Result<Value, electrum_client::Error> {
        use electrum_client::ElectrumApi;
        match self {
            Self::Tcp(c) => c.raw_call(method, params),
            Self::Ssl(c) => c.raw_call(method, params),
        }
    }

    /// One JSON-RPC batch: all `calls` in a single round-trip, results in
    /// call order. THE latency lever for the wallet sync — a scan is dozens
    /// of tiny requests, and against a remote server each round-trip is an
    /// RTT (an unbatched scan takes tens of seconds).
    fn raw_batch(
        &self,
        calls: Vec<(String, Vec<electrum_client::Param>)>,
    ) -> std::result::Result<Vec<Value>, electrum_client::Error> {
        use electrum_client::ElectrumApi;
        let mut batch = electrum_client::Batch::default();
        for (method, params) in calls {
            batch.raw(method, params);
        }
        match self {
            Self::Tcp(c) => c.batch_call(&batch),
            Self::Ssl(c) => c.batch_call(&batch),
        }
    }

    // -- subscription surface (the wallet sync worker) --
    //
    // Subscriptions are per RawClient INSTANCE: the crate registers each
    // scripthash locally so incoming notifications have a queue to land in,
    // and the server side dies with the socket. The worker therefore pins
    // the `Arc<ElectrumConn>` it subscribed on and rebuilds its
    // subscriptions whenever [`ElectrumBackend::pinned_conn`] hands it a
    // different instance (a reconnect happened).

    /// Subscribe to many spks in ONE round-trip; returns each spk's current
    /// status (`None` = no history). Never subscribe the same spk twice on
    /// one instance — the crate errors on double-registration.
    pub(crate) fn subscribe_spks(
        &self,
        spks: &[ScriptBuf],
    ) -> std::result::Result<Vec<Option<electrum_client::ScriptStatus>>, electrum_client::Error>
    {
        use electrum_client::ElectrumApi;
        let scripts: Vec<&bitcoin::Script> = spks.iter().map(|s| s.as_script()).collect();
        match self {
            Self::Tcp(c) => c.batch_script_subscribe(&scripts),
            Self::Ssl(c) => c.batch_script_subscribe(&scripts),
        }
    }

    /// Pop one queued status-change notification for `spk` (local, no I/O).
    /// Notifications are drained off the socket by whichever thread is
    /// reading a response — the worker's own tip poll at the latest.
    pub(crate) fn pop_spk_status(
        &self,
        spk: &ScriptBuf,
    ) -> std::result::Result<Option<electrum_client::ScriptStatus>, electrum_client::Error> {
        use electrum_client::ElectrumApi;
        match self {
            Self::Tcp(c) => c.script_pop(spk.as_script()),
            Self::Ssl(c) => c.script_pop(spk.as_script()),
        }
    }

    /// Drain queued new-tip notifications (local, no I/O). Every `tip()`
    /// call re-subscribes to headers, so notifications accumulate on any
    /// long-lived connection; draining bounds the queue. Raw variant —
    /// PoCX's 286-byte headers must never meet the crate's typed parser.
    fn drain_header_notifications(&self) {
        use electrum_client::ElectrumApi;
        let pop = || match self {
            Self::Tcp(c) => c.block_headers_pop_raw(),
            Self::Ssl(c) => c.block_headers_pop_raw(),
        };
        while let Ok(Some(_)) = pop() {}
    }
}

/// Should this electrum-client error be answered by reconnecting? Transport
/// and stream-desync errors: the socket is broken or poisoned, a fresh
/// connection can succeed. `Protocol` (the server answered — it means no),
/// subscription bookkeeping, and data-decode errors are NOT retried: the
/// answer would be the same.
fn electrum_reconnects(err: &electrum_client::Error) -> bool {
    use electrum_client::Error as E;
    matches!(
        err,
        E::IOError(_)
            | E::SharedIOError(_)
            | E::CouldntLockReader
            | E::Mpsc
            | E::JSON(_)
            | E::AllAttemptsErrored(_)
    )
}

/// Accept-any-certificate verifier that still advertises the provider's REAL
/// signature schemes (a correct ClientHello). Electrum-ecosystem convention:
/// most public servers are self-signed — often X.509 v1, which strict rustls
/// verification rejects outright ("UnsupportedCertVersion"). TLS is transport
/// privacy here, NOT server authentication — that job belongs to the genesis
/// check, the server.version capability handshake, and multi-server
/// cross-checks of the chain data itself.
#[derive(Debug)]
struct AcceptAnyServerCert {
    schemes: Vec<rustls::SignatureScheme>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// Dial `host:port` with retry — the transport half of both Electrum
/// schemes. Every resolved address (not just the first — a host with a
/// dead leading A/AAAA record must fall through to its siblings) is swept
/// once at the short [`ELECTRUM_CONNECT_RETRY_TIMEOUT`], then once more at
/// the full `connect_timeout` — the second sweep absorbs the class of
/// transient connect blips that recover within milliseconds.
///
/// Bounded connect + per-request I/O: a stalled REMOTE server must FAIL,
/// not hang — callers may serialize all requests on one lock, so an
/// unbounded read here freezes the whole app.
fn tcp_connect_with_retry(
    addr: &str,
    connect_timeout: std::time::Duration,
) -> Result<std::net::TcpStream> {
    let addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(addr)
        .with_context(|| format!("resolving Electrum server {addr}"))?
        .collect();
    anyhow::ensure!(
        !addrs.is_empty(),
        "Electrum server {addr} resolved to no address"
    );
    let mut last: Option<std::io::Error> = None;
    for timeout in [
        ELECTRUM_CONNECT_RETRY_TIMEOUT,
        connect_timeout.max(ELECTRUM_CONNECT_RETRY_TIMEOUT),
    ] {
        for sock in &addrs {
            match std::net::TcpStream::connect_timeout(sock, timeout) {
                Ok(tcp) => {
                    tcp.set_read_timeout(Some(ELECTRUM_IO_TIMEOUT))
                        .context("electrum read timeout")?;
                    tcp.set_write_timeout(Some(ELECTRUM_IO_TIMEOUT))
                        .context("electrum write timeout")?;
                    return Ok(tcp);
                }
                Err(e) => last = Some(e),
            }
        }
    }
    Err(last.expect("at least one address attempted"))
        .with_context(|| format!("connecting to Electrum server {addr}"))
}

/// Connect `host:port` over TLS with SNI, a full signature-scheme list, and
/// the accept-any verifier above, and hand the stream to the crate's
/// `RawClient` (its `From<StreamOwned<…>>` impl).
fn connect_electrum_ssl(
    addr: &str,
    connect_timeout: std::time::Duration,
) -> Result<electrum_client::raw_client::RawClient<electrum_client::raw_client::ElectrumSslStream>>
{
    let (host, _port) = addr
        .rsplit_once(':')
        .with_context(|| format!("Electrum ssl URL needs host:port, got {addr:?}"))?;
    let tcp = tcp_connect_with_retry(addr, connect_timeout)?;
    // Host applications may install a process default CryptoProvider in
    // main(); standalone users of this crate (tests, examples) fall back here.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServerCert { schemes }))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid Electrum server name {host:?}"))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
        .context("rustls client connection")?;
    Ok(rustls::StreamOwned::new(conn, tcp).into())
}

pub struct ElectrumBackend {
    params: &'static ChainParams,
    url: String,
    /// The one live connection (+ its generation), created lazily and
    /// replaced on transport errors. `RwLock` so concurrent calls share the
    /// `Arc` without serializing on each other's round-trips (the
    /// `RawClient` routes concurrent responses by request id).
    conn: std::sync::RwLock<Option<(Arc<ElectrumConn>, u64)>>,
    /// Generation allocator: each successful (re)connect takes the next
    /// value — never reused. The sync worker keys its subscriptions to the
    /// generation (they die with the socket), and [`Self::verify_chain`]
    /// caches its verdict per generation so a persistent connection is
    /// verified ONCE, not on every call.
    generation: AtomicU64,
    /// Generation that last passed `verify_chain` (0 = none yet).
    verified: AtomicU64,
    /// This server's shared health cell — the same `Arc` every other
    /// connection holder to this `(coin, url)` records into (the wallet
    /// sync worker keeps a private socket but not private health). Written
    /// passively on every dial/request outcome; never gates anything here —
    /// routing on it is [`ServerSet`](crate::server_health::ServerSet)'s job.
    health: Arc<crate::server_health::ServerHealth>,
}

impl ElectrumBackend {
    /// `url`: `tcp://host:port` or `ssl://host:port`. Connection is LAZY —
    /// the first call dials (and re-dials after transport errors), so
    /// construction never blocks and a temporarily-down server heals
    /// without rebuilding the backend.
    pub fn new(params: &'static ChainParams, url: &str) -> Result<Self> {
        Ok(Self {
            params,
            url: url.to_string(),
            conn: std::sync::RwLock::new(None),
            generation: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            health: crate::server_health::server_health(params.coin_id, url),
        })
    }

    /// The chain this backend serves.
    pub fn params(&self) -> &'static ChainParams {
        self.params
    }

    /// This server's shared health cell — for routing and tests.
    pub fn health(&self) -> &Arc<crate::server_health::ServerHealth> {
        &self.health
    }

    /// Dial the server and run the `server.version` handshake immediately:
    /// protocol 1.4 is negotiated once per CONNECTION (public servers may
    /// drop clients that skip it, and everything we call is 1.4 surface).
    /// Every outcome lands in the health cell: a refused/timed-out dial or
    /// a failed handshake is a connect incident, a completed handshake is
    /// the first success sample.
    fn dial(&self) -> Result<ElectrumConn> {
        let started = std::time::Instant::now();
        let dialed = self.dial_inner();
        match &dialed {
            Ok(_) => self.health.record_success(started.elapsed()),
            Err(e) => self.health.record_connect_failure(&format!("{e:#}")),
        }
        dialed
    }

    fn dial_inner(&self) -> Result<ElectrumConn> {
        let conn = if let Some(addr) = self.url.strip_prefix("ssl://") {
            ElectrumConn::Ssl(connect_electrum_ssl(addr, ELECTRUM_CONNECT_TIMEOUT)?)
        } else {
            let addr = self.url.strip_prefix("tcp://").unwrap_or(&self.url);
            ElectrumConn::Tcp(tcp_connect_with_retry(addr, ELECTRUM_CONNECT_TIMEOUT)?.into())
        };
        let ver = conn
            .raw_call(
                "server.version",
                vec![
                    electrum_client::Param::String("satchel".into()),
                    electrum_client::Param::String("1.4".into()),
                ],
            )
            .context("electrum server.version")?;
        let proto = ver
            .as_array()
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        anyhow::ensure!(
            proto.parse::<f32>().map(|p| p >= 1.4).unwrap_or(false),
            "Electrum server negotiated protocol {proto:?} — need 1.4+ \
             (server: {})",
            ver.as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
        Ok(conn)
    }

    /// The current connection (+ generation), dialing if there is none.
    /// Fast path is a shared read lock around an `Arc` clone.
    fn conn(&self) -> Result<(Arc<ElectrumConn>, u64)> {
        if let Some(cur) = self.conn.read().expect("electrum conn poisoned").as_ref() {
            return Ok(cur.clone());
        }
        let mut slot = self.conn.write().expect("electrum conn poisoned");
        if let Some(cur) = slot.as_ref() {
            return Ok(cur.clone()); // raced another dialer — use theirs
        }
        let conn = Arc::new(self.dial()?);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *slot = Some((conn.clone(), generation));
        Ok((conn, generation))
    }

    /// Drop `broken` if it is still the current connection (a concurrent
    /// caller may already have replaced it — never evict its successor).
    /// The eviction is what records the incident (`reason`) in the health
    /// cell — generation-keyed, so the N callers sharing the one broken
    /// socket count as ONE incident however many of them race here.
    pub(crate) fn evict(&self, broken: &Arc<ElectrumConn>, reason: &str) {
        let mut slot = self.conn.write().expect("electrum conn poisoned");
        if let Some((cur, generation)) = slot.as_ref() {
            if Arc::ptr_eq(cur, broken) {
                self.health.record_failure(*generation, reason);
                *slot = None;
            }
        }
    }

    /// The current connection, for the sync worker to pin its subscriptions
    /// to by instance identity (see [`ElectrumConn::subscribe_spks`]).
    pub(crate) fn pinned_conn(&self) -> Result<Arc<ElectrumConn>> {
        Ok(self.conn()?.0)
    }

    /// Run one call against the live connection; on a transport error,
    /// reconnect and retry ONCE. Everything we send is idempotent (reads,
    /// and broadcast treats "already known" as success), so the blind retry
    /// is safe; a second failure surfaces.
    ///
    /// Health recording: a completed round-trip is a success sample (with
    /// its latency — protocol errors included: the server answered, the
    /// transport is fine); the first transport failure is recorded by the
    /// eviction; a retry that fails again on the FRESH socket is its own
    /// incident.
    fn with_conn<T>(
        &self,
        what: &str,
        f: impl Fn(&ElectrumConn) -> std::result::Result<T, electrum_client::Error>,
    ) -> Result<T> {
        let (conn, _) = self.conn()?;
        let started = std::time::Instant::now();
        match f(&conn) {
            Ok(v) => {
                self.health.record_success(started.elapsed());
                Ok(v)
            }
            Err(e) if electrum_reconnects(&e) => {
                self.evict(&conn, &format!("electrum {what}: {e}"));
                let (conn, generation) = self
                    .conn()
                    .with_context(|| format!("electrum {what} (reconnect)"))?;
                let started = std::time::Instant::now();
                match f(&conn) {
                    Ok(v) => {
                        self.health.record_success(started.elapsed());
                        Ok(v)
                    }
                    Err(e) => {
                        if electrum_reconnects(&e) {
                            self.health
                                .record_failure(generation, &format!("electrum {what}: {e}"));
                        }
                        Err(e).with_context(|| format!("electrum {what} (after reconnect)"))
                    }
                }
            }
            Err(e) => {
                // The server answered (protocol/data error) — transport-wise
                // that is liveness, and routing must not punish it.
                self.health.record_success(started.elapsed());
                Err(e).with_context(|| format!("electrum {what}"))
            }
        }
    }

    fn raw(&self, method: &str, params: Vec<electrum_client::Param>) -> Result<Value> {
        self.with_conn(method, |conn| conn.raw_call(method, params.clone()))
    }

    fn raw_batch_calls(
        &self,
        what: &str,
        calls: Vec<(String, Vec<electrum_client::Param>)>,
    ) -> Result<Vec<Value>> {
        self.with_conn(what, |conn| conn.raw_batch(calls.clone()))
    }

    /// Electrum addresses outputs by the SHA256 of the scriptPubKey,
    /// reversed (display order).
    pub fn scripthash(spk: &ScriptBuf) -> String {
        use bitcoin::hashes::{sha256, Hash};
        let mut digest = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
        digest.reverse();
        hex::encode(digest)
    }

    /// (height, raw tip header) from headers.subscribe. On a persistent
    /// connection the server keeps pushing new-tip notifications after the
    /// first subscribe; drain them here (every caller of `tip()` wants the
    /// CURRENT tip, which the subscribe response itself carries) so the
    /// crate's local queue stays bounded.
    pub fn tip(&self) -> Result<(u64, Vec<u8>)> {
        let tip = self.raw("blockchain.headers.subscribe", vec![])?;
        if let Ok((conn, _)) = self.conn() {
            conn.drain_header_notifications();
        }
        let height = tip["height"]
            .as_u64()
            .context("headers.subscribe: no height")?;
        let raw = hex::decode(tip["hex"].as_str().context("headers.subscribe: no hex")?)?;
        Ok((height, raw))
    }

    fn confirmations(&self, entry_height: i64, tip_height: u64) -> u64 {
        if entry_height > 0 {
            tip_height.saturating_sub(entry_height as u64) + 1
        } else {
            0 // mempool (0) or mempool-with-unconfirmed-parents (-1)
        }
    }

    pub fn get_raw_tx(&self, txid: &str) -> Result<Transaction> {
        let hex_tx = self.raw(
            "blockchain.transaction.get",
            vec![electrum_client::Param::String(txid.into())],
        )?;
        let bytes = hex::decode(hex_tx.as_str().context("transaction.get: non-string")?)?;
        bitcoin::consensus::encode::deserialize(&bytes).context("transaction.get: bad tx")
    }

    /// (block hash hex, header timestamp) at `height` — raw header bytes
    /// hashed via [`ChainParams::header_hash`] (PoCX 286-byte headers safe).
    /// The wallet sync uses this for bdk anchors and checkpoints.
    pub fn header_at(&self, height: u64) -> Result<(String, u32)> {
        let raw = self.raw(
            "blockchain.block.header",
            vec![electrum_client::Param::Usize(height as usize)],
        )?;
        let raw = hex::decode(raw.as_str().context("block.header: non-string")?)?;
        Ok((
            self.params.header_hash(&raw)?,
            self.params.header_time(&raw)?,
        ))
    }

    /// Batched `get_history` for many spks — ONE round-trip, results in spk
    /// order (parsing identical to [`Self::history`]). The wallet scan is
    /// dozens of these; batching is what makes a remote-server sync take a
    /// few RTTs instead of tens of seconds.
    pub fn histories(&self, spks: &[ScriptBuf]) -> Result<Vec<Vec<(String, i64)>>> {
        if spks.is_empty() {
            return Ok(Vec::new());
        }
        let calls = spks
            .iter()
            .map(|spk| {
                (
                    "blockchain.scripthash.get_history".to_string(),
                    vec![electrum_client::Param::String(Self::scripthash(spk))],
                )
            })
            .collect();
        let results = self.raw_batch_calls("batch get_history", calls)?;
        Ok(results
            .iter()
            .map(|entries| {
                entries
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|e| {
                        Some((
                            e["tx_hash"].as_str()?.to_string(),
                            e["height"].as_i64().unwrap_or(0),
                        ))
                    })
                    .collect()
            })
            .collect())
    }

    /// Batched `transaction.get` — one round-trip, results in txid order.
    pub fn get_raw_txs(&self, txids: &[String]) -> Result<Vec<Transaction>> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let calls = txids
            .iter()
            .map(|t| {
                (
                    "blockchain.transaction.get".to_string(),
                    vec![electrum_client::Param::String(t.clone())],
                )
            })
            .collect();
        let results = self.raw_batch_calls("batch transaction.get", calls)?;
        results
            .iter()
            .map(|hex_tx| {
                let bytes = hex::decode(hex_tx.as_str().context("transaction.get: non-string")?)?;
                bitcoin::consensus::encode::deserialize(&bytes).context("transaction.get: bad tx")
            })
            .collect()
    }

    /// Batched `block.header` → (hash hex, timestamp) per height, in height
    /// order — raw bytes through the PoCX-safe header helpers, same as
    /// [`Self::header_at`].
    pub fn headers_at(&self, heights: &[u64]) -> Result<Vec<(String, u32)>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }
        let calls = heights
            .iter()
            .map(|h| {
                (
                    "blockchain.block.header".to_string(),
                    vec![electrum_client::Param::Usize(*h as usize)],
                )
            })
            .collect();
        let results = self.raw_batch_calls("batch block.header", calls)?;
        results
            .iter()
            .map(|raw| {
                let raw = hex::decode(raw.as_str().context("block.header: non-string")?)?;
                Ok((
                    self.params.header_hash(&raw)?,
                    self.params.header_time(&raw)?,
                ))
            })
            .collect()
    }

    pub fn history(&self, spk: &ScriptBuf) -> Result<Vec<(String, i64)>> {
        let entries = self.raw(
            "blockchain.scripthash.get_history",
            vec![electrum_client::Param::String(Self::scripthash(spk))],
        )?;
        Ok(entries
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|e| {
                Some((
                    e["tx_hash"].as_str()?.to_string(),
                    e["height"].as_i64().unwrap_or(0),
                ))
            })
            .collect())
    }

    /// Verify the backend serves the expected chain (genesis hash check).
    /// Everything we call is MANDATORY protocol-1.4 surface (scripthash
    /// history/listunspent, headers, transaction get/broadcast,
    /// estimatefee), so there is no per-method probing — the three real
    /// risks are an old protocol (checked in `dial`, once per CONNECTION:
    /// `server.version` doubles as the politeness handshake some public
    /// servers require), a PRUNED server (a restored seed's full scan would
    /// silently miss history), and the wrong chain. With a persistent
    /// connection the verdict is cached per connection generation, so the
    /// steady state costs zero round-trips.
    ///
    /// Wrong-chain / pruned answers are [`ChainMismatch`] — DISAGREEMENT,
    /// which a quorum must fail hard on, unlike a server that simply
    /// doesn't answer.
    pub fn verify_chain(&self) -> Result<()> {
        let (_, generation) = self.conn()?;
        if self.verified.load(Ordering::SeqCst) == generation {
            return Ok(());
        }
        // features: strict where advertised, lenient where absent.
        if let Ok(features) = self.raw("server.features", vec![]) {
            if let Some(genesis) = features["genesis_hash"].as_str() {
                if genesis != self.params.genesis_hash {
                    return Err(anyhow::Error::new(ChainMismatch(format!(
                        "Electrum server advertises the wrong chain: genesis \
                         {genesis}, expected {} ({} {:?})",
                        self.params.genesis_hash, self.params.coin_id, self.params.network
                    ))));
                }
            }
            let pruning = &features["pruning"];
            if !(pruning.is_null() || pruning.as_u64() == Some(0)) {
                return Err(anyhow::Error::new(ChainMismatch(format!(
                    "Electrum server is PRUNED (keeps {pruning} blocks) — a pruned server \
                     cannot serve full wallet history; use an unpruned one"
                ))));
            }
        }
        // Deep genesis check: fetch header 0 and hash it OURSELVES — validates
        // both the chain and our (PoCX-aware) header parsing on this server.
        let raw = self.raw(
            "blockchain.block.header",
            vec![electrum_client::Param::Usize(0)],
        )?;
        let raw = hex::decode(raw.as_str().context("block.header: non-string")?)?;
        let genesis = self.params.header_hash(&raw)?;
        if genesis != self.params.genesis_hash {
            return Err(anyhow::Error::new(ChainMismatch(format!(
                "Electrum server serves the wrong chain: genesis {genesis}, expected {} ({} {:?})",
                self.params.genesis_hash, self.params.coin_id, self.params.network
            ))));
        }
        // Cache the verdict for this connection. If the connection was
        // replaced mid-verify the stored generation simply won't match the
        // next one and the checks re-run — never a false "verified".
        self.verified.store(generation, Ordering::SeqCst);
        Ok(())
    }

    /// Broadcast a raw transaction. Already mined / in the mempool is a
    /// no-op success, not an error.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let hex_tx = bitcoin::consensus::encode::serialize_hex(tx);
        match self.raw(
            "blockchain.transaction.broadcast",
            vec![electrum_client::Param::String(hex_tx)],
        ) {
            Ok(txid) => Ok(Txid::from_str(
                txid.as_str().context("broadcast: non-string")?,
            )?),
            // Already mined / in the mempool: a no-op success, not an error.
            Err(e) if is_already_broadcast(&e) => Ok(tx.compute_txid()),
            Err(e) => Err(e),
        }
    }

    /// `None` if the outpoint does not exist or is already spent.
    /// `expected_spk` is the script the output is supposed to pay —
    /// Electrum can only look up outputs by script.
    pub fn get_txout(
        &self,
        outpoint: &OutPoint,
        expected_spk: &ScriptBuf,
    ) -> Result<Option<TxOutInfo>> {
        let utxos = self.raw(
            "blockchain.scripthash.listunspent",
            vec![electrum_client::Param::String(Self::scripthash(
                expected_spk,
            ))],
        )?;
        let (tip_height, _) = self.tip()?;
        for utxo in utxos.as_array().cloned().unwrap_or_default() {
            if utxo["tx_hash"].as_str() == Some(outpoint.txid.to_string().as_str())
                && utxo["tx_pos"].as_u64() == Some(u64::from(outpoint.vout))
            {
                return Ok(Some(TxOutInfo {
                    value_sat: utxo["value"].as_u64().context("listunspent: no value")?,
                    // Queried *by* script, so the binding is structural.
                    script_pubkey_hex: hex::encode(expected_spk.as_bytes()),
                    confirmations: self
                        .confirmations(utxo["height"].as_i64().unwrap_or(0), tip_height),
                }));
            }
        }
        Ok(None)
    }

    /// Find an unspent output paying `spk`. Returns the outpoint + its
    /// info, or `None` if nothing pays `spk` yet. Like every backend read
    /// this is a hint; callers re-verify value/script and apply their own
    /// confirmation gates.
    pub fn find_funding(&self, spk: &ScriptBuf) -> Result<Option<(OutPoint, TxOutInfo)>> {
        let utxos = self.raw(
            "blockchain.scripthash.listunspent",
            vec![electrum_client::Param::String(Self::scripthash(spk))],
        )?;
        let (tip_height, _) = self.tip()?;
        let Some(utxo) = utxos
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let txid = Txid::from_str(
            utxo["tx_hash"]
                .as_str()
                .context("listunspent: no tx_hash")?,
        )?;
        let vout = utxo["tx_pos"].as_u64().context("listunspent: no tx_pos")? as u32;
        Ok(Some((
            OutPoint { txid, vout },
            TxOutInfo {
                value_sat: utxo["value"].as_u64().context("listunspent: no value")?,
                script_pubkey_hex: hex::encode(spk.as_bytes()),
                confirmations: self.confirmations(utxo["height"].as_i64().unwrap_or(0), tip_height),
            },
        )))
    }

    /// Locate the output of `txid` paying `script_pubkey_hex`.
    pub fn find_vout(&self, txid: &str, script_pubkey_hex: &str) -> Result<u32> {
        let tx = self.get_raw_tx(txid)?;
        let wanted = hex::decode(script_pubkey_hex)?;
        tx.output
            .iter()
            .position(|out| out.script_pubkey.as_bytes() == wanted.as_slice())
            .map(|pos| pos as u32)
            .with_context(|| format!("transaction {txid} has no output paying the expected script"))
    }

    /// Witness items of the input spending `outpoint` (an output paying
    /// `watch_spk`), searched via the script's history. `None` if no spend
    /// is visible yet.
    pub fn find_spend_witness(
        &self,
        outpoint: &OutPoint,
        watch_spk: &ScriptBuf,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        // The watched scripthash history contains both the funding tx and
        // any spend of it — no block scanning needed.
        for (tx_hash, _height) in self.history(watch_spk)? {
            if tx_hash == outpoint.txid.to_string() {
                continue; // the funding tx itself
            }
            let tx = self.get_raw_tx(&tx_hash)?;
            for input in &tx.input {
                if input.previous_output == *outpoint {
                    return Ok(Some(
                        input.witness.iter().map(|item| item.to_vec()).collect(),
                    ));
                }
            }
        }
        Ok(None)
    }

    pub fn tip_height(&self) -> Result<u64> {
        Ok(self.tip()?.0)
    }

    /// Median-time-past of the tip — what CLTV is evaluated against.
    /// Median of the last (up to) 11 header timestamps, like
    /// `CBlockIndex::GetMedianTimePast`.
    pub fn tip_median_time(&self) -> Result<u64> {
        let (tip_height, _) = self.tip()?;
        let span = tip_height.min(10);
        let start = tip_height - span;
        let headers = self.raw(
            "blockchain.block.headers",
            vec![
                electrum_client::Param::Usize(start as usize),
                electrum_client::Param::Usize((span + 1) as usize),
            ],
        )?;
        let raw = hex::decode(headers["hex"].as_str().context("block.headers: no hex")?)?;
        let header_len = self.params.header_len();
        anyhow::ensure!(
            raw.len() % header_len == 0 && !raw.is_empty(),
            "block.headers returned {} bytes, not a multiple of {header_len}",
            raw.len()
        );
        let mut times: Vec<u64> = raw
            .chunks(header_len)
            .map(|hdr| self.params.header_time(hdr).map(u64::from))
            .collect::<Result<_>>()?;
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    /// Confirmations of a transaction (0 if unconfirmed or unknown). `spk`
    /// is a script the transaction pays — Electrum can only search by
    /// script.
    pub fn tx_confirmations(&self, txid: &str, spk: &ScriptBuf) -> Result<u64> {
        let (tip_height, _) = self.tip()?;
        for (tx_hash, height) in self.history(spk)? {
            if tx_hash == txid {
                return Ok(self.confirmations(height, tip_height));
            }
        }
        Ok(0)
    }

    /// Feerate in sat/vB from the server's estimator for a given
    /// confirmation target, with a conservative fallback when the estimator
    /// has no data (fresh chains, regtest): the fee market is effectively
    /// empty, so the relay minimum suffices (floored to the coin's own
    /// minimum). Electrum's `estimatefee` takes only a block target — there
    /// is no economical/conservative mode distinction.
    pub fn fee_rate_for(&self, conf_target: u16) -> Result<u64> {
        Ok(self
            .fee_estimate_kvb(conf_target)?
            .map(|kvb| kvb_to_vb_round(kvb).max(1))
            .unwrap_or(self.params.min_feerate_sat_vb.max(1)))
    }

    /// The estimator's RAW answer for `conf_target` in sat/vB — `None` when
    /// it has no data (fresh chain, quiet mempool, regtest), where
    /// [`Self::fee_rate_for`] would silently substitute the fallback.
    /// Send-form presets need the distinction: estimate-less presets are
    /// disabled and the form falls back to a custom rate at the coin floor.
    /// Estimates are floored to `min_feerate_sat_vb`.
    pub fn fee_estimate(&self, conf_target: u16) -> Result<Option<u64>> {
        Ok(self
            .fee_estimate_kvb(conf_target)?
            .map(|kvb| kvb_to_vb_round(kvb).max(1)))
    }

    /// Precise market estimate in sat/kvB (the estimator's native
    /// resolution) — the fraction is real queue priority at the bottom of
    /// the market, and fee bumps priced off this are never rounded below a
    /// node's fractional BIP125 Rule-4 minimum.
    pub fn fee_estimate_kvb(&self, conf_target: u16) -> Result<Option<u64>> {
        Ok(self
            .raw(
                "blockchain.estimatefee",
                vec![electrum_client::Param::Usize(conf_target as usize)],
            )
            .ok()
            .and_then(|v| v.as_f64())
            .filter(|btc_kb| *btc_kb > 0.0) // -1 = no estimate available
            .map(btc_kvb_to_sat_kvb)
            .map(|est| {
                est.clamp(1, SANITY_MAX_SAT_PER_VB * 1000)
                    .max(self.params.min_feerate_sat_vb * 1000)
            }))
    }

    /// [`Self::fee_rate_for`] at sat/kvB resolution (same fallback
    /// semantics).
    pub fn fee_rate_for_kvb(&self, conf_target: u16) -> Result<u64> {
        Ok(self
            .fee_estimate_kvb(conf_target)?
            .unwrap_or(self.params.min_feerate_sat_vb.max(1) * 1000))
    }

    /// Resolve a [`SendFee`] to the sat/kvB rate a send prices itself at:
    /// market estimate (with fallback) for a target, or the explicit rate
    /// clamped to the coin floor and the sanity max.
    pub fn resolve_send_fee(&self, fee: SendFee) -> Result<u64> {
        match fee {
            SendFee::Target(conf_target) => self.fee_rate_for_kvb(conf_target),
            SendFee::RatePerKvb(rate) => Ok(rate
                .clamp(1, SANITY_MAX_SAT_PER_VB * 1000)
                .max(self.params.min_feerate_sat_vb * 1000)),
        }
    }
}

/// Long-lived [`ElectrumBackend`]s keyed by `(coin_id, url)` — ONE TCP+TLS
/// connection per configured server, shared by every caller and by the
/// wallet sync worker, instead of a fresh handshake per call. The backends
/// are lazy and self-healing, so pooling them never pins a dead socket: a
/// broken connection is redialed by the next caller.
pub struct ElectrumPool {
    conns: std::sync::Mutex<BTreeMap<(String, String), Arc<ElectrumBackend>>>,
}

impl Default for ElectrumPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ElectrumPool {
    pub fn new() -> Self {
        Self {
            conns: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// The pooled backend for this server, created on first use. Also prunes
    /// the coin's entries for servers no longer in `live_urls` (the coin was
    /// reconfigured) so replaced servers don't hold sockets forever.
    pub fn get(
        &self,
        params: &'static ChainParams,
        coin_id: &str,
        url: &str,
        live_urls: &[&str],
    ) -> Result<Arc<ElectrumBackend>> {
        let mut conns = self.conns.lock().expect("electrum pool poisoned");
        conns.retain(|(coin, u), _| coin != coin_id || live_urls.contains(&u.as_str()));
        if let Some(backend) = conns.get(&(coin_id.to_string(), url.to_string())) {
            return Ok(backend.clone());
        }
        let backend = Arc::new(ElectrumBackend::new(params, url)?);
        conns.insert((coin_id.to_string(), url.to_string()), backend.clone());
        Ok(backend)
    }
}

#[cfg(test)]
mod electrum_pool_tests {
    use super::*;
    use params_btcx::params::Network;
    use params_btcx::registry;

    #[test]
    fn pool_reuses_connections_and_prunes_reconfigured_urls() {
        let params = registry::get("btc")
            .expect("built-in btc")
            .params(Network::Mainnet)
            .expect("btc mainnet params");
        let pool = ElectrumPool::new();
        let both = ["tcp://a:1", "tcp://b:1"];
        let only_a = ["tcp://a:1"];

        // Same (coin, url) → the same lazy backend (no dialing here).
        let a1 = pool.get(params, "btc", "tcp://a:1", &both).unwrap();
        let a2 = pool.get(params, "btc", "tcp://a:1", &both).unwrap();
        assert!(Arc::ptr_eq(&a1, &a2), "one connection per server");

        // Reconfiguring the coin without b prunes b; re-adding rebuilds it.
        let b1 = pool.get(params, "btc", "tcp://b:1", &both).unwrap();
        let a3 = pool.get(params, "btc", "tcp://a:1", &only_a).unwrap();
        assert!(Arc::ptr_eq(&a1, &a3), "still-configured url keeps its conn");
        let b2 = pool.get(params, "btc", "tcp://b:1", &both).unwrap();
        assert!(!Arc::ptr_eq(&b1, &b2), "pruned entry was rebuilt");

        // Pruning is per coin: another coin's entry on the same server
        // stays untouched.
        let ltc1 = pool.get(params, "ltc", "tcp://a:1", &only_a).unwrap();
        let _ = pool.get(params, "btc", "tcp://a:1", &only_a).unwrap();
        let ltc2 = pool.get(params, "ltc", "tcp://a:1", &only_a).unwrap();
        assert!(Arc::ptr_eq(&ltc1, &ltc2));
    }
}

#[cfg(test)]
mod fee_conversion_tests {
    use super::{btc_kvb_to_sat_kvb, kvb_to_vb_round};

    #[test]
    fn estimator_conversion_keeps_full_kvb_resolution() {
        // 0.00001080 BTC/kvB = 1080 sat/kvB = 1.08 sat/vB. The estimator's
        // answer survives EXACTLY: display shows 1.08, Core is paid
        // fee_rate = 1.08, bdk is paid 270 sat/kwu.
        assert_eq!(btc_kvb_to_sat_kvb(0.00001080), 1080);
        assert_eq!((1080u64 + 2) / 4, 270); // sat/kvB → sat/kwu (bdk)
        assert_eq!(btc_kvb_to_sat_kvb(0.00001012), 1012);
        assert_eq!(btc_kvb_to_sat_kvb(0.00001000), 1000);
        assert_eq!(btc_kvb_to_sat_kvb(0.00000040), 40);
        // Integer-vB derivations round to nearest.
        assert_eq!(kvb_to_vb_round(1012), 1);
        assert_eq!(kvb_to_vb_round(1500), 2);
        assert_eq!(kvb_to_vb_round(9873), 10);
        // Sub-relay dust rounds to 0 — callers clamp to ≥ 1 / the coin floor.
        assert_eq!(kvb_to_vb_round(40), 0);
    }
}
