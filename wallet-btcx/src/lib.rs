//! Nodeless on-chain wallet — bdk over the raw Electrum machinery of
//! `electrum-btcx`.
//!
//! A `bdk_wallet::Wallet` derived from a BIP39 seed
//! ([`keys_btcx::WalletSeed`]) at the standard BIP-84 (`wpkh`) or BIP-86
//! (`tr`) branch, selected per wallet by [`DescriptorKind`], synced over
//! the PoCX-header-safe raw Electrum calls of
//! [`electrum_btcx::ElectrumBackend`], and persisted per coin in the data
//! dir. [`BdkWalletBackend`] serves the wallet operations — balance,
//! addresses, sends, RBF bumps, CPFP signing, activity — that only a node
//! wallet could serve otherwise; chain reads ride the wrapped Electrum
//! backend.
//!
//! Syncing is a BACKGROUND job: the per-coin
//! [`electrum_btcx::SyncWorker`] keeps the bdk cache fresh over the coin's
//! one long-lived Electrum connection, so the wallet operations here never
//! perform chain I/O for the wallet's own state — reads serve the cache
//! as-is, writes only gate on the worker's first-sync latch.
//!
//! bdk is used at the *script* level only:
//! - Address encode/decode goes through [`ChainParams`] (per-coin HRPs).
//!   The `bitcoin::Network` handed to bdk is the constant
//!   [`bitcoin::Network::Bitcoin`] — it only affects xprv serialization
//!   (always `NetworkKind::Main`, see [`keys_btcx::WalletSeed::from_seed`])
//!   and bdk's own address strings, which are never used. The real chain
//!   binding is the per-coin genesis-hash checkpoint set at creation and
//!   checked at load.
//! - Raw headers never reach bdk: anchors and checkpoints are built from
//!   header bytes hashed via [`ChainParams::header_hash`], so Bitcoin
//!   PoCX's 286-byte headers are handled exactly like everywhere else, and
//!   stock upstream bdk needs no fork.
//!
//! [`ChainParams::header_hash`]: params_btcx::params::ChainParams::header_hash

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoin::{
    Amount, BlockHash, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxOut, Txid,
};

use electrum_btcx::{
    ElectrumBackend, SendFee, SyncWorker, WalletEntry, WalletHandle, FIRST_SYNC_WAIT,
};
use keys_btcx::{DescriptorKind, WalletSeed};
use params_btcx::params::ChainParams;
use params_btcx::registry;

/// Electrum-style handout cap: never let more than this many revealed-but-
/// unused external addresses accumulate. Past the cap, [`wallet_handout_spk`]
/// recycles the OLDEST unused address instead of revealing further — so a
/// pathological "clicked Receive 30 times, never got paid" session cannot
/// open a gap a restore's [`electrum_btcx::STOP_GAP`] scan would miss.
/// Bitcoin Core solves the same problem with brute width (a 1000-key
/// keypool); Electrum's cap gets the same guarantee without thousand-query
/// restores. Reuse only ever means "shown twice", and only past 20
/// outstanding unpaid addresses.
const MAX_UNUSED_AHEAD: usize = 20;

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode a keychain scriptPubKey as an address string via [`ChainParams`]
/// (never via bdk/rust-bitcoin `Network` HRPs). BIP-86 keychain spks are
/// P2TR; BIP-84 ones are P2WPKH.
fn spk_to_address(params: &ChainParams, spk: &ScriptBuf) -> Result<String> {
    if spk.is_p2tr() {
        let xonly = bitcoin::XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])
            .context("P2TR output key in keychain spk")?;
        params.p2tr_address(&xonly)
    } else if spk.is_p2wpkh() {
        let hrp = bech32::Hrp::parse(params.bech32_hrp)?;
        Ok(bech32::segwit::encode_v0(hrp, &spk.as_bytes()[2..])?)
    } else {
        anyhow::bail!(
            "wallet keychain script is neither P2TR nor P2WPKH: {}",
            hex::encode(spk.as_bytes())
        )
    }
}

/// The wallet's balance split into bdk's four classes (sats). For DISPLAY —
/// `confirmed + trusted_pending` is what [`Wallet::wallet_balance`] reports
/// as spendable; `untrusted_pending` is inbound value awaiting its first
/// confirmation; `immature` is unmatured coinbase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct BalanceBuckets {
    pub confirmed: u64,
    pub trusted_pending: u64,
    pub untrusted_pending: u64,
    pub immature: u64,
}

/// One entry of the wallet's activity feed: direction + net amount from
/// the wallet's point of view.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WalletTxInfo {
    pub txid: String,
    /// `"sent"` or `"received"` — the wallet's NET direction. A self-transfer
    /// nets to a pure fee payment and reads as `"sent"` with `amount_sat` 0.
    pub direction: String,
    /// Net value moved, excluding the fee on sends: what the recipient got
    /// (sent) or what landed in our keychains (received).
    pub amount_sat: u64,
    /// `None` when the wallet doesn't own every input (a receive — the fee was
    /// paid by the sender and isn't ours to report).
    pub fee_sat: Option<u64>,
    /// Virtual size in vB — with `fee_sat` this yields the effective feerate
    /// an RBF bump has to beat.
    pub vsize: u64,
    pub confirmations: u64,
    /// Block time for confirmed txs, first-seen time for mempool ones. `None`
    /// only for a built-but-unbroadcast funding awaiting its release.
    pub timestamp: Option<u64>,
}

/// Per-coin cache of open bdk wallets. The owner holds one of these for
/// the data dir: bdk wallets are stateful (sync position, revealed
/// indexes, sqlite store), so unlike stateless RPC backends they must NOT
/// be rebuilt per call — a per-call [`BdkWalletBackend`] borrows a handle
/// instead.
pub struct WalletManager {
    wallet_dir: PathBuf,
    wallets: Mutex<BTreeMap<String, (DescriptorKind, WalletHandle)>>,
    /// One background [`SyncWorker`] per open coin, keyed with the server
    /// URL its private connection points at. Spawned by
    /// [`Self::ensure_worker`], told to exit when the manager goes away.
    workers: Mutex<BTreeMap<String, (Arc<SyncWorker>, String)>>,
}

impl WalletManager {
    /// `data_dir` is the owner's data dir; wallets live under
    /// `<data_dir>/wallet/<coin_id>.sqlite`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            wallet_dir: data_dir.join("wallet"),
            wallets: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The coin's background sync worker, spawning it on first call. The
    /// worker holds only a `Weak` wallet handle, so it can never keep a
    /// dropped manager's wallet alive; a reconfigured server URL is handed
    /// over via `set_chain` (the worker picks it up on its next wakeup).
    ///
    /// The worker gets its OWN connection to the server, deliberately NOT
    /// a pooled one other callers share: with pooled calls serialized by
    /// their owner's lock, each connection then has at most ONE caller at
    /// a time — the caller is always the electrum-client socket reader and
    /// every blocking call is bounded by the socket timeouts. A second
    /// concurrent caller domain would exercise the crate's reader
    /// hand-off, where a waiter parks on an unbounded channel.
    pub fn ensure_worker(
        &self,
        coin_id: &str,
        params: &'static ChainParams,
        url: &str,
        wallet: &WalletHandle,
    ) -> Result<Arc<SyncWorker>> {
        let mut workers = self.workers.lock().expect("worker map poisoned");
        if let Some((worker, worker_url)) = workers.get_mut(coin_id) {
            if worker_url != url {
                worker.set_chain(Arc::new(ElectrumBackend::new(params, url)?));
                *worker_url = url.to_string();
            }
            return Ok(worker.clone());
        }
        let chain = Arc::new(ElectrumBackend::new(params, url)?);
        let worker = SyncWorker::spawn(coin_id, chain, wallet);
        workers.insert(coin_id.to_string(), (worker.clone(), url.to_string()));
        Ok(worker)
    }

    /// Freshness of the coin's cached wallet state: how long ago the sync
    /// worker last completed a pass against its server. `None` when no
    /// worker runs or none has completed yet.
    pub fn sync_age(&self, coin_id: &str) -> Option<std::time::Duration> {
        let workers = self.workers.lock().ok()?;
        workers.get(coin_id).and_then(|(w, _)| w.fresh_age())
    }

    /// Poke the coin's sync worker, if one is running. Owners call this
    /// when external events move the wallet — incoming payments confirm,
    /// own spends land — and only a sync makes the cached balance and
    /// activity reflect it.
    pub fn poke(&self, coin_id: &str) {
        if let Ok(workers) = self.workers.lock() {
            if let Some((worker, _)) = workers.get(coin_id) {
                worker.poke();
            }
        }
    }

    /// Open (or create) the wallet for `coin_id`, deriving its descriptors
    /// from `seed` at the `kind` branch (BIP-84 `wpkh` or BIP-86 `tr`).
    /// Loads honor-checked: descriptors AND the coin's genesis hash must
    /// match what the store was created with — a store created with the
    /// other [`DescriptorKind`] (or another seed) refuses to load rather
    /// than silently mixing keys.
    pub fn open(
        &self,
        coin_id: &str,
        params: &'static ChainParams,
        seed: &WalletSeed,
        kind: DescriptorKind,
    ) -> Result<WalletHandle> {
        let mut wallets = self.wallets.lock().expect("wallet cache poisoned");
        if let Some((open_kind, handle)) = wallets.get(coin_id) {
            anyhow::ensure!(
                *open_kind == kind,
                "wallet for {coin_id} is already open as {open_kind:?}, not {kind:?}"
            );
            return Ok(handle.clone());
        }

        std::fs::create_dir_all(&self.wallet_dir)
            .with_context(|| format!("creating {}", self.wallet_dir.display()))?;
        let db_path = self.wallet_dir.join(format!("{coin_id}.sqlite"));
        let mut conn = Connection::open(&db_path)
            .with_context(|| format!("opening wallet db {}", db_path.display()))?;

        // BTCX derives per-network: mainnet on the registered per-asset coin
        // type, testnet/regtest on the shared SLIP-44 testnet coin type 1'
        // (see `registry::btcx_coin_type`). Every other coin keeps its
        // network-blind registry coin type.
        let coin_type = if coin_id == registry::BTCX.id {
            registry::btcx_coin_type(params.network)
        } else {
            registry::bip32_coin_type(coin_id)?
        };
        let (external, internal) = seed.wallet_descriptors(kind, coin_type)?;
        let genesis = BlockHash::from_str(params.genesis_hash)
            .context("coin genesis hash is not a block hash")?;

        let loaded = Wallet::load()
            .descriptor(KeychainKind::External, Some(external.clone()))
            .descriptor(KeychainKind::Internal, Some(internal.clone()))
            .extract_keys()
            .check_genesis_hash(genesis)
            .load_wallet(&mut conn)
            .map_err(|e| anyhow!("loading wallet db {}: {e}", db_path.display()))?;
        let wallet = match loaded {
            Some(wallet) => wallet,
            None => Wallet::create(external, internal)
                .network(bitcoin::Network::Bitcoin) // constant; see module doc
                .genesis_hash(genesis)
                .create_wallet(&mut conn)
                .map_err(|e| anyhow!("creating wallet db {}: {e}", db_path.display()))?,
        };

        let handle: WalletHandle = Arc::new(Mutex::new(WalletEntry { wallet, conn }));
        wallets.insert(coin_id.to_string(), (kind, handle.clone()));
        Ok(handle)
    }
}

impl Drop for WalletManager {
    /// Owner unload / host stop: tell every worker to exit. No join — a
    /// worker may be mid-fetch (bounded by the socket timeouts) and drop
    /// must not block; it re-checks the flag before its next wallet write
    /// and its `Weak` handle dies with this manager's map anyway.
    fn drop(&mut self) {
        if let Ok(workers) = self.workers.lock() {
            for (worker, _) in workers.values() {
                worker.shutdown();
            }
        }
    }
}

// ---- the backend ------------------------------------------------------------

/// The wallet backend: chain data over Electrum, wallet over bdk. `wallet`
/// is `None` while the seed is locked — chain reads keep working, wallet
/// operations report the lock.
///
/// The wallet operations NEVER touch the network for chain data
/// themselves: reads serve the bdk cache (~0ms — the background
/// [`SyncWorker`] keeps it fresh at its cadence plus pokes), and writes
/// only gate on the worker's first-sync latch so they can't build a spend
/// from a never-synced cache at boot. `chain` is the coin's pooled
/// long-lived Electrum connection, shared with the backend's other
/// callers; the worker syncs over its own socket.
pub struct BdkWalletBackend {
    params: &'static ChainParams,
    chain: Arc<ElectrumBackend>,
    /// The coin's other ACTIVE view servers: fallback relays for the
    /// wallet's own broadcasts, so a down home cannot strand a signed
    /// spend that any healthy view would happily relay. Never used for
    /// wallet state — that stays home-synced by the worker.
    views: Vec<Arc<ElectrumBackend>>,
    wallet: Option<(WalletHandle, Arc<SyncWorker>)>,
}

impl BdkWalletBackend {
    pub fn new(
        params: &'static ChainParams,
        chain: Arc<ElectrumBackend>,
        views: Vec<Arc<ElectrumBackend>>,
        wallet: Option<(WalletHandle, Arc<SyncWorker>)>,
    ) -> Self {
        Self {
            params,
            chain,
            views,
            wallet,
        }
    }

    /// The chain this wallet lives on.
    pub fn params(&self) -> &'static ChainParams {
        self.params
    }

    /// The wallet HOME server's pooled connection — the backend's chain
    /// reads (and its view health) ride this.
    pub fn chain(&self) -> &Arc<ElectrumBackend> {
        &self.chain
    }

    /// The coin's other active view servers (broadcast fallbacks).
    pub fn views(&self) -> &[Arc<ElectrumBackend>] {
        &self.views
    }

    /// Whether the wallet is locked: no seed, so it can read chain data
    /// but cannot look at balances or SIGN.
    pub fn wallet_locked(&self) -> bool {
        self.wallet.is_none()
    }

    /// Broadcast through the home server, falling over to the active
    /// views — any acceptance wins. Serial with health-skip (wallet sends
    /// are rare; no thread ceremony): servers inside a backoff window are
    /// skipped, and if EVERYTHING is skipped the home is dialed anyway —
    /// refusing outright would strand a signed spend that a recovering
    /// server might take.
    fn broadcast_fan(&self, tx: &Transaction) -> Result<Txid> {
        let mut last_err: Option<anyhow::Error> = None;
        let mut tried = false;
        for server in std::iter::once(&self.chain).chain(self.views.iter()) {
            if !server.health().available() {
                continue;
            }
            tried = true;
            match server.broadcast(tx) {
                Ok(txid) => return Ok(txid),
                Err(e) => last_err = Some(e),
            }
        }
        if !tried {
            return self.chain.broadcast(tx);
        }
        Err(last_err.expect("tried at least one server"))
    }

    /// Nudge the sync worker: our own action changed (or is about to
    /// change) what the chain knows about us — pick it up now, not at the
    /// next tick.
    fn poke_worker(&self) {
        if let Some((_, worker)) = &self.wallet {
            worker.poke();
        }
    }

    /// Run a wallet operation on the CACHED wallet under the entry lock and
    /// persist any staged change afterwards — also on operation error, so
    /// anything already staged survives.
    fn with_wallet<T>(&self, f: impl FnOnce(&mut WalletEntry) -> Result<T>) -> Result<T> {
        let (handle, _) = self.wallet.as_ref().context(
            "wallet unavailable: the seed is locked — unlock before spending (nodeless wallet)",
        )?;
        let mut guard = handle.lock().expect("wallet entry poisoned");
        let entry = &mut *guard;
        let out = f(entry);
        let persisted = entry.wallet.persist(&mut entry.conn);
        match (out, persisted) {
            (Ok(v), Ok(_)) => Ok(v),
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(anyhow!("persisting wallet: {e}")),
        }
    }

    /// [`Self::with_wallet`] for operations that BUILD/SPEND: wait (bounded)
    /// for the worker's first completed sync of this run, so a spend can
    /// never coin-select from a cache that has not seen the chain at all
    /// (fresh restore, boot race). Steady state costs nothing — the latch
    /// is already set. A dead server surfaces as an honest error here
    /// instead of a silent double-spend risk.
    fn with_synced_wallet<T>(&self, f: impl FnOnce(&mut WalletEntry) -> Result<T>) -> Result<T> {
        let (_, worker) = self.wallet.as_ref().context(
            "wallet unavailable: the seed is locked — unlock before spending (nodeless wallet)",
        )?;
        worker.poke(); // an in-backoff worker should retry NOW
        anyhow::ensure!(
            worker.wait_first_sync(FIRST_SYNC_WAIT),
            "the nodeless wallet has not completed its first chain sync yet — check that \
             the coin's Electrum server is reachable, then retry"
        );
        self.with_wallet(f)
    }

    /// Build + sign a spend of `amount_sat` to `spk` priced by `fee` (market
    /// estimate at a target, or an explicit user rate). `confirmed_only`
    /// restricts coin selection to CONFIRMED UTXOs — the swap-funding rule
    /// (2026-08-09 post-mortem): a funding chained on an unconfirmed,
    /// bump-eligible parent is permanently orphaned when that parent is
    /// RBF-replaced, and bdk's selector is otherwise confirmation-blind.
    fn build_signed(
        &self,
        entry: &mut WalletEntry,
        spk: ScriptBuf,
        amount_sat: u64,
        fee: SendFee,
        sequence: Sequence,
        confirmed_only: bool,
    ) -> Result<Transaction> {
        // resolve_send_fee is sat/kvB; bdk's FeeRate is sat/kwu = sat/kvB ÷ 4
        // (1 vB = 4 wu), so the estimator's fraction carries exactly.
        let feerate = FeeRate::from_sat_per_kwu((self.chain.resolve_send_fee(fee)? + 2) / 4);
        let unspendable = if confirmed_only {
            unconfirmed_outpoints(entry)
        } else {
            Vec::new()
        };
        let mut builder = entry.wallet.build_tx();
        builder
            .add_recipient(spk, Amount::from_sat(amount_sat))
            .fee_rate(feerate)
            .set_exact_sequence(sequence)
            .unspendable(unspendable);
        let mut psbt = builder.finish().map_err(|e| anyhow!("building tx: {e}"))?;
        self.finalize(entry, &mut psbt)?;
        psbt.extract_tx().map_err(|e| anyhow!("extracting tx: {e}"))
    }

    fn finalize(&self, entry: &WalletEntry, psbt: &mut Psbt) -> Result<()> {
        let done = entry
            .wallet
            .sign(psbt, SignOptions::default())
            .map_err(|e| anyhow!("signing: {e}"))?;
        anyhow::ensure!(done, "wallet could not finalize the transaction");
        Ok(())
    }

    /// Broadcast an externally built transaction through the home server
    /// and let the worker fold in any of our own spks it touches.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let txid = self.chain.broadcast(tx)?;
        self.poke_worker();
        Ok(txid)
    }

    /// Locate the output of `txid` paying `script_pubkey_hex`. Home first;
    /// a failing home falls over to any available view — no Electrum
    /// server is "our node", they all see the same txs. A data-level miss
    /// gets the same answer everywhere, so the fallback is harmless there
    /// too.
    pub fn find_vout(&self, txid: &str, script_pubkey_hex: &str) -> Result<u32> {
        match self.chain.find_vout(txid, script_pubkey_hex) {
            Ok(vout) => Ok(vout),
            Err(err) => {
                for view in &self.views {
                    if !view.health().available() {
                        continue;
                    }
                    if let Ok(vout) = view.find_vout(txid, script_pubkey_hex) {
                        return Ok(vout);
                    }
                }
                Err(err)
            }
        }
    }

    // -- the wallet operations --

    /// Fresh receive address, under the [`MAX_UNUSED_AHEAD`] handout cap.
    pub fn wallet_new_address(&self) -> Result<String> {
        let address = self.with_wallet(|entry| {
            let spk = wallet_handout_spk(entry);
            spk_to_address(self.params, &spk)
        })?;
        // The Receive dialog is open: subscribe the (possibly fresh) spk and
        // refresh now, so the incoming payment is spotted promptly.
        self.poke_worker();
        Ok(address)
    }

    /// Confirmed wallet balance in base units.
    pub fn wallet_balance(&self) -> Result<u64> {
        self.with_wallet(|entry| Ok(entry.wallet.balance().trusted_spendable().to_sat()))
    }

    /// The wallet's full balance buckets (sats) — bdk's four classes, for
    /// DISPLAY: a pending inbound payment must show as "pending", never as an
    /// empty wallet. Spend gates keep using [`Self::wallet_balance`]
    /// (trusted-spendable) — these buckets never authorize anything.
    pub fn wallet_balance_buckets(&self) -> Result<BalanceBuckets> {
        self.with_wallet(|entry| {
            let b = entry.wallet.balance();
            Ok(BalanceBuckets {
                confirmed: b.confirmed.to_sat(),
                trusted_pending: b.trusted_pending.to_sat(),
                untrusted_pending: b.untrusted_pending.to_sat(),
                immature: b.immature.to_sat(),
            })
        })
    }

    /// Send exactly `amount_sat` to `address`, priced by `fee` and
    /// broadcast BIP125-replaceable (the owner bumps sends via
    /// [`Self::wallet_bumpfee`]).
    pub fn wallet_send(&self, address: &str, amount_sat: u64, fee: SendFee) -> Result<String> {
        self.send_inner(address, amount_sat, fee, false)
    }

    /// [`Self::wallet_send`] restricted to CONFIRMED inputs — the v1
    /// swap-funding send (2026-08-09 post-mortem hard rule): a funding must
    /// never chain on an unconfirmed, bump-eligible parent, because an RBF
    /// replacement of that parent orphans the funding irrecoverably (gone
    /// from every mempool, nothing on chain to re-adopt). Ordinary sends
    /// keep spending own unconfirmed change ([`Self::wallet_send`]).
    #[cfg(feature = "swap-support")]
    pub fn wallet_send_confirmed(
        &self,
        address: &str,
        amount_sat: u64,
        fee: SendFee,
    ) -> Result<String> {
        self.send_inner(address, amount_sat, fee, true)
    }

    fn send_inner(
        &self,
        address: &str,
        amount_sat: u64,
        fee: SendFee,
        confirmed_only: bool,
    ) -> Result<String> {
        let spk = self.params.parse_address(address)?;
        let txid = self.with_synced_wallet(|entry| {
            let tx = self.build_signed(
                entry,
                spk,
                amount_sat,
                fee,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                confirmed_only,
            )?;
            // Broadcast-before-persist: a crash after broadcast re-learns
            // the tx from our own spk history on the next sync, never
            // double-spends.
            let txid = self.broadcast_fan(&tx)?;
            entry.wallet.apply_unconfirmed_txs([(tx, now_ts())]);
            Ok(txid.to_string())
        })?;
        self.poke_worker();
        Ok(txid)
    }

    /// Sweep the whole wallet to `address` ("send everything"): every
    /// spendable UTXO in one tx with the fee taken out of the swept amount
    /// — the recipient receives balance − fee and the wallet is left
    /// empty. UTXOs reserved by built-but-unbroadcast fundings are not
    /// spendable, so a sweep can never claw back a reservation.
    pub fn wallet_send_all(&self, address: &str, fee: SendFee) -> Result<String> {
        let spk = self.params.parse_address(address)?;
        let txid = self.with_synced_wallet(|entry| {
            // sat/kvB → sat/kwu, same as build_signed.
            let feerate = FeeRate::from_sat_per_kwu((self.chain.resolve_send_fee(fee)? + 2) / 4);
            // drain_wallet + drain_to: every spendable UTXO in, one output
            // out, the fee off the swept amount (bdk's sweep). Inputs held by
            // built-but-unbroadcast fundings are already out of the
            // canonical UTXO set (apply_unconfirmed_txs locked them), so the
            // drain cannot claw back a reservation.
            // Sweeps keep the confirmation-blind selection deliberately: a
            // sweep MEANS "everything spendable", and its child-of-change
            // risk is the owner's explicit choice, not an engine liability.
            let mut builder = entry.wallet.build_tx();
            builder
                .drain_wallet()
                .drain_to(spk)
                .fee_rate(feerate)
                .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
            let mut psbt = builder
                .finish()
                .map_err(|e| anyhow!("building sweep: {e}"))?;
            self.finalize(entry, &mut psbt)?;
            let tx = psbt
                .extract_tx()
                .map_err(|e| anyhow!("extracting sweep: {e}"))?;
            // Broadcast-before-persist, same as wallet_send.
            let txid = self.broadcast_fan(&tx)?;
            entry.wallet.apply_unconfirmed_txs([(tx, now_ts())]);
            Ok(txid.to_string())
        })?;
        self.poke_worker();
        Ok(txid)
    }

    /// Build + sign (but DO NOT broadcast) a funding tx paying `amount_sat`
    /// to `address`, priced by `fee`, returning `(txid, vout, signed_tx_hex)`.
    /// The selected inputs are reserved so nothing else spends them before
    /// the caller broadcasts. Two-phase funding: the txid must be known
    /// before real funds are committed at broadcast. It is built
    /// NON-replaceable (no BIP125 signal): callers that commit the txid
    /// into pre-signed child spends must never RBF it — bump via CPFP
    /// instead, and the non-signal keeps external wallets from even
    /// offering a bump.
    #[cfg(feature = "swap-support")]
    pub fn wallet_build_funding(
        &self,
        address: &str,
        amount_sat: u64,
        fee: SendFee,
    ) -> Result<(String, u32, String)> {
        let spk = self.params.parse_address(address)?;
        let built = self.with_synced_wallet(|entry| {
            // Confirmed inputs only: the v2 funding txid is committed into
            // pre-signed MuSig2 redeems, so chaining it on a replaceable
            // unconfirmed parent would be even worse than the v1 shape —
            // an orphaned funding invalidates the whole signed bundle.
            let tx = self.build_signed(
                entry,
                spk.clone(),
                amount_sat,
                fee,
                Sequence::ENABLE_LOCKTIME_NO_RBF,
                true,
            )?;
            let txid = tx.compute_txid();
            let vout = tx
                .output
                .iter()
                .position(|o| o.script_pubkey == spk)
                .context("built funding pays no output to the target script")?
                as u32;
            let hex_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            // Deliberately NOT broadcast. Inserting it unconfirmed locks its
            // inputs against reuse and tracks the change — bdk's equivalent
            // of Core `lockUnspents`. A funding that dies pre-broadcast
            // releases them via wallet_cancel_funding.
            entry.wallet.apply_unconfirmed_txs([(tx, now_ts())]);
            Ok((txid.to_string(), vout, hex_tx))
        })?;
        // A change spk may have just been revealed — get it subscribed.
        self.poke_worker();
        Ok(built)
    }

    /// Release the input reservation of a [`Self::wallet_build_funding`] tx
    /// that will NEVER be broadcast. `tx_hex` is the exact signed tx the
    /// build returned. Without this, the built tx's inputs stay reserved
    /// forever — the bdk wallet persists the phantom unbroadcast tx across
    /// restarts. Callers gate on the tx being absent from the chain AND
    /// their own broadcast flag; a funding the wallet knows is confirmed is
    /// refused here as well.
    #[cfg(feature = "swap-support")]
    pub fn wallet_cancel_funding(&self, tx_hex: &str) -> Result<()> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&hex::decode(tx_hex)?)
            .context("decode built funding tx for cancel")?;
        let txid = tx.compute_txid();
        // No sync: cancel runs on abort paths and must work while the Electrum
        // view is unreachable; evicting a never-broadcast tx needs no chain
        // data. (If the tx WAS broadcast after all, the next sync re-learns it
        // from our own spk histories — its inputs spend our spks — and a
        // fresher last_seen out-cancels the eviction, so this self-heals.)
        self.with_wallet(|entry| {
            // Belt-and-suspenders (callers gate on this too): never evict
            // a funding the wallet knows is confirmed.
            if let Some(wtx) = entry.wallet.get_tx(txid) {
                anyhow::ensure!(
                    !matches!(wtx.chain_position, ChainPosition::Confirmed { .. }),
                    "refusing to cancel funding {txid}: it is confirmed on-chain"
                );
            }
            // Drop the phantom from the canonical set — this is what frees its
            // inputs — and unmark the change derivation index for reuse.
            entry.wallet.apply_evicted_txs([(txid, now_ts())]);
            entry.wallet.cancel_tx(&tx);
            Ok(())
        })
    }

    /// The wallet's transaction history, newest first — the activity feed.
    pub fn wallet_transactions(&self) -> Result<Vec<WalletTxInfo>> {
        self.with_wallet(|entry| Ok(wallet_activity(entry)))
    }

    /// Sign `tx`'s single input with the wallet and broadcast it, given the
    /// value + scriptPubKey of its prevout so a segwit/taproot input can be
    /// signed before that prevout confirms. The CPFP path: a self-funded
    /// child spending the wallet's own (possibly still unconfirmed) output.
    pub fn wallet_sign_send(
        &self,
        tx: &Transaction,
        prevout_value_sat: u64,
        prevout_spk: &ScriptBuf,
    ) -> Result<Txid> {
        anyhow::ensure!(
            tx.input.len() == 1,
            "CPFP child must spend exactly the one wallet-owned prevout"
        );
        let outpoint = tx.input[0].previous_output;
        let txid = self.with_synced_wallet(|entry| {
            // The parent (our sweep/change output) is normally already in the
            // graph via sync; a floating txout covers the race where it
            // hasn't propagated to the Electrum server yet.
            if entry.wallet.get_utxo(outpoint).is_none() {
                entry.wallet.insert_txout(
                    outpoint,
                    TxOut {
                        value: Amount::from_sat(prevout_value_sat),
                        script_pubkey: prevout_spk.clone(),
                    },
                );
            }
            let utxo = entry
                .wallet
                .get_utxo(outpoint)
                .context("CPFP prevout is not owned by the nodeless wallet")?;
            let input = entry
                .wallet
                .get_psbt_input(utxo, None, true)
                .map_err(|e| anyhow!("psbt input for CPFP prevout: {e}"))?;
            let mut psbt =
                Psbt::from_unsigned_tx(tx.clone()).context("CPFP child is not unsigned")?;
            psbt.inputs[0] = input;
            let done = entry
                .wallet
                .sign(
                    &mut psbt,
                    SignOptions {
                        trust_witness_utxo: true,
                        ..Default::default()
                    },
                )
                .map_err(|e| anyhow!("signing CPFP child: {e}"))?;
            anyhow::ensure!(done, "wallet could not finalize the CPFP child");
            let tx = psbt
                .extract_tx()
                .map_err(|e| anyhow!("extracting CPFP child: {e}"))?;
            let txid = self.broadcast_fan(&tx)?;
            entry.wallet.apply_unconfirmed_txs([(tx, now_ts())]);
            Ok(txid)
        })?;
        self.poke_worker();
        Ok(txid)
    }

    /// A wallet tx's fee (sat) + vsize (vB), for recomputing its broadcast
    /// feerate at bump time (`fee / vsize`) without persisting it.
    pub fn wallet_tx_fee_vsize(&self, txid: &str) -> Result<(u64, u64)> {
        let txid = Txid::from_str(txid)?;
        self.with_wallet(|entry| {
            let tx = entry
                .wallet
                .get_tx(txid)
                .with_context(|| format!("tx {txid} not known to the nodeless wallet"))?
                .tx_node
                .tx
                .clone();
            let fee = entry
                .wallet
                .calculate_fee(&tx)
                .map_err(|e| anyhow!("fee of {txid}: {e}"))?;
            Ok((fee.to_sat(), tx.vsize() as u64))
        })
    }

    /// The wallet's OWN copy of `txid` — a purely local read, no chain
    /// I/O. Freshly built txs (a send, an RBF replacement) are applied to
    /// the cache at broadcast, so this serves them immediately — where a
    /// server fetch of a just-broadcast tx can race the Electrum index
    /// (field: a funding bump's post-broadcast vout lookup got "missing
    /// transaction" and stranded a swap pointer on the dead pre-RBF txid).
    pub fn wallet_tx(&self, txid: &str) -> Result<Transaction> {
        let txid = Txid::from_str(txid)?;
        self.with_wallet(|entry| {
            Ok(entry
                .wallet
                .get_tx(txid)
                .with_context(|| format!("tx {txid} not known to the nodeless wallet"))?
                .tx_node
                .tx
                .as_ref()
                .clone())
        })
    }

    /// The wallet-OWNED change output of `funding_txid` — `(vout,
    /// value_sat, spk)` — for a CPFP child on a build-and-hold funding.
    /// Identified positively by ownership (`exclude_spk` — the funded
    /// output's script, which the wallet does NOT own — is skipped
    /// explicitly as a belt-and-suspenders cross-check). `None` when the
    /// funding has no change output (exact-UTXO funding → can't CPFP).
    #[cfg(feature = "swap-support")]
    pub fn wallet_change_output(
        &self,
        funding_txid: &str,
        exclude_spk: &ScriptBuf,
    ) -> Result<Option<(u32, u64, ScriptBuf)>> {
        let txid = Txid::from_str(funding_txid)?;
        self.with_wallet(|entry| {
            let tx = entry
                .wallet
                .get_tx(txid)
                .with_context(|| format!("funding {txid} not known to the nodeless wallet"))?
                .tx_node
                .tx
                .clone();
            for (vout, out) in tx.output.iter().enumerate() {
                if out.script_pubkey == *exclude_spk {
                    continue; // the funded output is never ours
                }
                if entry.wallet.is_mine(out.script_pubkey.clone()) {
                    return Ok(Some((
                        vout as u32,
                        out.value.to_sat(),
                        out.script_pubkey.clone(),
                    )));
                }
            }
            Ok(None)
        })
    }

    /// RBF-bump a wallet-owned tx, targeting `feerate_sat_kvb` (**sat/kvB**,
    /// the estimator's native resolution — so a 1.004 sat/vB tx is bumped
    /// to a precise rate that clears a node's fractional BIP125 Rule-4
    /// minimum, not rounded to a whole sat/vB that lands just below it);
    /// returns the replacement txid. Errors if not replaceable or the
    /// wallet can't afford the higher fee.
    pub fn wallet_bumpfee(&self, txid: &str, feerate_sat_kvb: u64) -> Result<String> {
        let txid = Txid::from_str(txid)?;
        // sat/kvB → sat/kwu (1 vB = 4 wu), rounding UP so the replacement never
        // lands below the node's fractional Rule-4 minimum — the same idiom the
        // send path uses, ceil'd here because this feeds an RBF acceptance check.
        let feerate = FeeRate::from_sat_per_kwu(feerate_sat_kvb.div_ceil(4));
        let txid = self.with_synced_wallet(|entry| {
            // Descendant belt (2026-08-09 post-mortem; Core's `bumpfee`
            // refuses identically): replacing a tx invalidates every child
            // chained on its outputs — an own wallet tx among them would be
            // orphaned outright, so refuse. bdk's `build_fee_bump` does not
            // check this itself. Phrase matches Core ("descendants in the
            // wallet") so callers classify both backends the same way.
            let children = wallet_descendants(entry, txid);
            anyhow::ensure!(
                children.is_empty(),
                "cannot bump {txid}: it has descendants in the wallet ({children:?}) — \
                 replacing it would orphan them"
            );
            let mut builder = entry
                .wallet
                .build_fee_bump(txid)
                .map_err(|e| anyhow!("bumpfee {txid}: {e}"))?;
            builder.fee_rate(feerate);
            let mut psbt = builder
                .finish()
                .map_err(|e| anyhow!("building bump: {e}"))?;
            self.finalize(entry, &mut psbt)?;
            let tx = psbt
                .extract_tx()
                .map_err(|e| anyhow!("extracting bump: {e}"))?;
            let new_txid = self.broadcast_fan(&tx)?;
            entry.wallet.apply_unconfirmed_txs([(tx, now_ts())]);
            Ok(new_txid.to_string())
        })?;
        self.poke_worker();
        Ok(txid)
    }
}

/// Outpoints of every UNCONFIRMED wallet UTXO — the exclusion set for
/// confirmed-only sends. Free function (no chain I/O — the caller synced)
/// so the rule is unit-testable without an Electrum server.
fn unconfirmed_outpoints(entry: &WalletEntry) -> Vec<OutPoint> {
    entry
        .wallet
        .list_unspent()
        .filter(|u| matches!(u.chain_position, ChainPosition::Unconfirmed { .. }))
        .map(|u| u.outpoint)
        .collect()
}

/// Canonical wallet txs spending any output of `txid` — the txs an RBF
/// replacement of `txid` would orphan. Free function so the bumpfee
/// descendant belt is unit-testable without an Electrum server.
fn wallet_descendants(entry: &WalletEntry, txid: Txid) -> Vec<Txid> {
    entry
        .wallet
        .transactions()
        .filter(|wtx| {
            wtx.tx_node
                .tx
                .input
                .iter()
                .any(|i| i.previous_output.txid == txid)
        })
        .map(|wtx| wtx.tx_node.txid)
        .collect()
}

/// Hand out an external address spk under the [`MAX_UNUSED_AHEAD`] cap:
/// reveal a fresh one while fewer than the cap are outstanding unused, else
/// recycle the oldest unused one (`next_unused_address` picks the lowest
/// unused index; it reveals only when nothing is unused). Free function so
/// the cap invariant is unit-testable without an Electrum server.
fn wallet_handout_spk(entry: &mut WalletEntry) -> ScriptBuf {
    let unused = entry
        .wallet
        .list_unused_addresses(KeychainKind::External)
        .count();
    let info = if unused >= MAX_UNUSED_AHEAD {
        entry.wallet.next_unused_address(KeychainKind::External)
    } else {
        entry.wallet.reveal_next_address(KeychainKind::External)
    };
    info.address.script_pubkey()
}

/// The activity feed off one wallet's canonical tx set, newest first. Free
/// function (no chain I/O — the caller syncs) so it is unit-testable
/// without an Electrum server.
fn wallet_activity(entry: &WalletEntry) -> Vec<WalletTxInfo> {
    let tip = entry.wallet.latest_checkpoint().height();
    let mut out = Vec::new();
    for wtx in entry.wallet.transactions() {
        let tx = &wtx.tx_node.tx;
        let (sent, received) = entry.wallet.sent_and_received(tx);
        let (sent, received) = (sent.to_sat(), received.to_sat());
        let fee_sat = entry.wallet.calculate_fee(tx).ok().map(Amount::to_sat);
        let (direction, amount_sat) = if sent > received {
            // Net send: inputs minus change minus the fee = what the
            // recipient got. Unknown fee (foreign input) degrades to the
            // net outflow, fee included.
            let net_out = sent - received;
            ("sent", net_out - fee_sat.unwrap_or(0).min(net_out))
        } else {
            ("received", received - sent)
        };
        let (confirmations, timestamp) = match wtx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => (
                u64::from((tip + 1).saturating_sub(anchor.block_id.height)),
                Some(anchor.confirmation_time),
            ),
            ChainPosition::Unconfirmed {
                first_seen,
                last_seen,
            } => (0, first_seen.or(last_seen)),
        };
        out.push(WalletTxInfo {
            txid: wtx.tx_node.txid.to_string(),
            direction: direction.into(),
            amount_sat,
            fee_sat,
            vsize: tx.vsize() as u64,
            confirmations,
            timestamp,
        });
    }
    // Newest first: mempool/pending (0 confs) ahead of shallow ahead of
    // deep; ties by descending time. A built-but-unbroadcast funding has
    // no timestamp and sorts to the very front.
    out.sort_by_key(|t| {
        (
            t.confirmations,
            std::cmp::Reverse(t.timestamp.unwrap_or(u64::MAX)),
        )
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
    use bdk_wallet::Update;
    use bitcoin::OutPoint;
    use params_btcx::params::Network;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn temp_data_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wallet-btcx-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn btc_mainnet() -> &'static ChainParams {
        registry::get("btc")
            .expect("built-in btc")
            .params(Network::Mainnet)
            .expect("btc mainnet params")
    }

    #[test]
    fn btcx_open_uses_network_aware_coin_type() {
        use keys_btcx::COIN_BTCX;
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Opening the BTCX wallet must derive at the per-network coin type:
        // mainnet on COIN_BTCX, testnet/regtest on the shared 1'.
        for (network, ct) in [
            (Network::Mainnet, COIN_BTCX),
            (Network::Testnet, 1u32),
            (Network::Regtest, 1u32),
        ] {
            let dir = temp_data_dir();
            let params = registry::get("btcx")
                .expect("built-in btcx")
                .params(network)
                .expect("btcx params");
            let handle = WalletManager::new(&dir)
                .open("btcx", params, &seed, DescriptorKind::Bip84)
                .unwrap();
            let desc = handle
                .lock()
                .unwrap()
                .wallet
                .public_descriptor(KeychainKind::External)
                .to_string();
            assert!(
                desc.contains(&format!("/84'/{ct}'/")) || desc.contains(&format!("/84h/{ct}h/")),
                "btcx {network:?} must derive at coin type {ct}', got descriptor {desc}"
            );
        }
    }

    #[test]
    fn first_address_matches_bip86_vector_and_persists() {
        let dir = temp_data_dir();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let params = btc_mainnet();

        let manager = WalletManager::new(&dir);
        let handle = manager
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        {
            let mut guard = handle.lock().unwrap();
            let entry = &mut *guard;
            let spk = entry
                .wallet
                .reveal_next_address(KeychainKind::External)
                .address
                .script_pubkey();
            // BIP-86 first receiving address (m/86'/0'/0'/0/0) of the
            // standard test mnemonic — COIN_BTC = 0, so this is the
            // published vector, encoded through OUR params (hrp "bc").
            assert_eq!(
                spk_to_address(params, &spk).unwrap(),
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
            );
            let persisted = entry.wallet.persist(&mut entry.conn).unwrap();
            assert!(persisted);
        }

        // A fresh manager on the same data dir resumes at index 1: the
        // revealed index survived, and the descriptors/genesis checks pass.
        let manager2 = WalletManager::new(&dir);
        let handle2 = manager2
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        {
            let mut entry = handle2.lock().unwrap();
            assert_eq!(
                entry.wallet.derivation_index(KeychainKind::External),
                Some(0)
            );
            let next = entry
                .wallet
                .reveal_next_address(KeychainKind::External)
                .address
                .script_pubkey();
            assert_eq!(
                spk_to_address(params, &next).unwrap(),
                // BIP-86 second receiving address (m/86'/0'/0'/0/1).
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bip84_first_address_matches_vector() {
        let dir = temp_data_dir();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let params = btc_mainnet();

        let handle = WalletManager::new(&dir)
            .open("btc", params, &seed, DescriptorKind::Bip84)
            .unwrap();
        {
            let mut entry = handle.lock().unwrap();
            let spk = entry
                .wallet
                .reveal_next_address(KeychainKind::External)
                .address
                .script_pubkey();
            // BIP-84 first receiving address (m/84'/0'/0'/0/0) of the
            // standard test mnemonic — the published vector, through the
            // wpkh branch of spk_to_address.
            assert_eq!(
                spk_to_address(params, &spk).unwrap(),
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn built_funding_reserves_inputs_and_cancel_releases_them() {
        use bitcoin::hashes::Hash;

        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let manager = WalletManager::new(&dir);
        let handle = manager
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        let mut guard = handle.lock().unwrap();
        let entry = &mut *guard;

        // Fund the wallet: a confirmed (non-coinbase) foreign tx paying our
        // first address, anchored in a fabricated block 1.
        let spk0 = entry
            .wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk0,
            }],
        };
        let fund_txid = funding.compute_txid();
        let h1 = BlockHash::from_byte_array([1u8; 32]);
        let genesis = entry.wallet.latest_checkpoint().block_id();
        let cp = CheckPoint::from_block_ids([
            genesis,
            BlockId {
                height: 1,
                hash: h1,
            },
        ])
        .unwrap();
        let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
        tx_update.txs.push(Arc::new(funding));
        tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 1,
                    hash: h1,
                },
                confirmation_time: 1_000,
            },
            fund_txid,
        ));
        entry
            .wallet
            .apply_update(Update {
                last_active_indices: BTreeMap::new(),
                tx_update,
                chain: Some(cp),
            })
            .unwrap();
        assert_eq!(entry.wallet.balance().trusted_spendable().to_sat(), 100_000);

        // Build-and-hold a funding (the two-phase shape): sign, insert
        // unbroadcast — its inputs must now be reserved.
        let leg_spk = ScriptBuf::from_hex(&format!("5120{}", "ab".repeat(32))).unwrap();
        let mut builder = entry.wallet.build_tx();
        builder
            .add_recipient(leg_spk, Amount::from_sat(40_000))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        let mut psbt = builder.finish().unwrap();
        assert!(entry
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .unwrap());
        let built = psbt.extract_tx().unwrap();
        let built_txid = built.compute_txid();
        let fee = entry.wallet.calculate_fee(&built).unwrap().to_sat();
        entry.wallet.apply_unconfirmed_txs([(built.clone(), 2_000)]);
        assert_eq!(
            entry.wallet.balance().trusted_spendable().to_sat(),
            100_000 - 40_000 - fee,
            "built-but-unbroadcast funding must reserve its inputs"
        );

        // Activity feed: the pending send sorts first, then the receive.
        let act = wallet_activity(entry);
        assert_eq!(act.len(), 2);
        assert_eq!(
            (
                act[0].direction.as_str(),
                act[0].amount_sat,
                act[0].confirmations
            ),
            ("sent", 40_000, 0)
        );
        assert_eq!(act[0].fee_sat, Some(fee));
        assert_eq!(
            (
                act[1].direction.as_str(),
                act[1].amount_sat,
                act[1].confirmations
            ),
            ("received", 100_000, 1)
        );

        // Cancel — the exact wallet_cancel_funding sequence (evict from the
        // canonical set + unmark the change index): the inputs are spendable
        // again and the phantom leaves the activity feed.
        entry.wallet.apply_evicted_txs([(built_txid, 3_000)]);
        entry.wallet.cancel_tx(&built);
        assert_eq!(
            entry.wallet.balance().trusted_spendable().to_sat(),
            100_000,
            "cancel must release the reserved inputs"
        );
        let act = wallet_activity(entry);
        assert_eq!(act.len(), 1);
        assert_eq!(act[0].txid, fund_txid.to_string());

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2026-08-09 post-mortem: (a) confirmed-only selection must refuse to
    /// chain a swap funding on unconfirmed change (bdk's selector is
    /// confirmation-blind without the exclusion set), and (b) the bumpfee
    /// descendant belt must see a wallet child chained on a tx's outputs.
    #[test]
    fn confirmed_only_selection_and_descendant_belt() {
        use bitcoin::hashes::Hash;

        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let handle = WalletManager::new(&dir)
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        let mut guard = handle.lock().unwrap();
        let entry = &mut *guard;

        // Confirmed 100k UTXO (same fixture as the input-reservation test).
        let spk0 = entry
            .wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk0,
            }],
        };
        let fund_txid = funding.compute_txid();
        let h1 = BlockHash::from_byte_array([1u8; 32]);
        let genesis = entry.wallet.latest_checkpoint().block_id();
        let cp = CheckPoint::from_block_ids([
            genesis,
            BlockId {
                height: 1,
                hash: h1,
            },
        ])
        .unwrap();
        let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
        tx_update.txs.push(Arc::new(funding));
        tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 1,
                    hash: h1,
                },
                confirmation_time: 1_000,
            },
            fund_txid,
        ));
        entry
            .wallet
            .apply_update(Update {
                last_active_indices: BTreeMap::new(),
                tx_update,
                chain: Some(cp),
            })
            .unwrap();

        // A first "swap funding" spends the lone confirmed coin; its change
        // is the only spendable UTXO left — and it is UNCONFIRMED.
        let leg_spk = ScriptBuf::from_hex(&format!("5120{}", "ab".repeat(32))).unwrap();
        let mut builder = entry.wallet.build_tx();
        builder
            .add_recipient(leg_spk.clone(), Amount::from_sat(40_000))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        let mut psbt = builder.finish().unwrap();
        assert!(entry
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .unwrap());
        let parent = psbt.extract_tx().unwrap();
        let parent_txid = parent.compute_txid();
        entry.wallet.apply_unconfirmed_txs([(parent, 2_000)]);

        // The exclusion set names exactly the unconfirmed change.
        let excl = unconfirmed_outpoints(entry);
        assert_eq!(excl.len(), 1, "exclusion set: {excl:?}");
        assert_eq!(excl[0].txid, parent_txid);

        // Confirmed-only selection REFUSES to chain a second funding …
        let leg2_spk = ScriptBuf::from_hex(&format!("5120{}", "cd".repeat(32))).unwrap();
        let mut builder = entry.wallet.build_tx();
        builder
            .add_recipient(leg2_spk.clone(), Amount::from_sat(10_000))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .unspendable(excl);
        assert!(
            builder.finish().is_err(),
            "confirmed-only selection must refuse the unconfirmed change"
        );

        // … while the old confirmation-blind selection happily chains on it
        // (the exact 2026-08-09 hazard).
        let mut builder = entry.wallet.build_tx();
        builder
            .add_recipient(leg2_spk, Amount::from_sat(10_000))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        let mut psbt = builder.finish().unwrap();
        assert!(entry
            .wallet
            .sign(&mut psbt, SignOptions::default())
            .unwrap());
        let child = psbt.extract_tx().unwrap();
        let child_txid = child.compute_txid();
        assert!(
            child
                .input
                .iter()
                .any(|i| i.previous_output.txid == parent_txid),
            "the blind build should have chained on the unconfirmed change"
        );
        entry.wallet.apply_unconfirmed_txs([(child, 3_000)]);

        // Descendant belt: the parent now has a wallet child (a bump would
        // orphan it); the child has none.
        assert_eq!(wallet_descendants(entry, parent_txid), vec![child_txid]);
        assert!(wallet_descendants(entry, child_txid).is_empty());

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handout_cap_bounds_the_gap_and_recycles_oldest_unused() {
        use bitcoin::hashes::Hash;

        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let handle = WalletManager::new(&dir)
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        let mut guard = handle.lock().unwrap();
        let entry = &mut *guard;

        // 30 handouts, nothing ever paid: exactly MAX_UNUSED_AHEAD distinct
        // addresses are revealed, then the OLDEST unused one (index 0)
        // recycles — the on-chain gap is bounded by construction.
        let mut spks = Vec::new();
        for _ in 0..30 {
            spks.push(wallet_handout_spk(entry));
        }
        let distinct: std::collections::HashSet<_> = spks.iter().cloned().collect();
        assert_eq!(distinct.len(), MAX_UNUSED_AHEAD);
        assert_eq!(
            entry.wallet.derivation_index(KeychainKind::External),
            Some((MAX_UNUSED_AHEAD - 1) as u32),
            "no reveal past the cap"
        );
        assert_eq!(
            spks[MAX_UNUSED_AHEAD], spks[0],
            "recycles the oldest unused"
        );
        assert!(
            electrum_btcx::STOP_GAP as usize > MAX_UNUSED_AHEAD,
            "scan must out-reach the cap"
        );

        // Pay the oldest one: it leaves the unused set, so the next handout
        // reveals a FRESH address again (index 20).
        let paid = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: spks[0].clone(),
            }],
        };
        entry.wallet.apply_unconfirmed_txs([(paid, 1_000)]);
        let next = wallet_handout_spk(entry);
        assert!(
            !distinct.contains(&next),
            "a payment frees the cap for a fresh reveal"
        );
        assert_eq!(
            entry.wallet.derivation_index(KeychainKind::External),
            Some(MAX_UNUSED_AHEAD as u32)
        );

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revealed_spks_track_reveals_across_keychains() {
        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let handle = WalletManager::new(&dir)
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();
        let mut guard = handle.lock().unwrap();
        let entry = &mut *guard;

        // Fresh store: nothing revealed — the sync side treats this as the
        // full-scan case and the worker has nothing to subscribe yet.
        assert!(electrum_btcx::revealed_spks(entry).is_empty());

        entry.wallet.reveal_next_address(KeychainKind::External);
        entry.wallet.reveal_next_address(KeychainKind::External);
        entry.wallet.reveal_next_address(KeychainKind::Internal);
        let spks = electrum_btcx::revealed_spks(entry);
        assert_eq!(spks.len(), 3, "2 external + 1 internal");
        assert_eq!(
            spks.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "all distinct"
        );

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_worker_reuses_per_coin_and_shuts_down_with_manager() {
        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let manager = WalletManager::new(&dir);
        let handle = manager
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();

        // Dead port: the lazy private connection just backs off.
        let w1 = manager
            .ensure_worker("btc", params, "tcp://127.0.0.1:1", &handle)
            .unwrap();
        let w2 = manager
            .ensure_worker("btc", params, "tcp://127.0.0.1:1", &handle)
            .unwrap();
        assert!(Arc::ptr_eq(&w1, &w2), "one worker per coin");

        // No sync ever completed against the dead server: the write gate
        // reports honestly instead of hanging.
        assert!(!w1.wait_first_sync(std::time::Duration::from_millis(10)));

        // Manager drop = owner unload: the latch releases as NOT synced,
        // so a racing write errors instead of blocking its full timeout.
        drop(manager);
        assert!(!w1.wait_first_sync(std::time::Duration::from_secs(30)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_seed_fails_descriptor_check() {
        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        WalletManager::new(&dir)
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();

        // Same store, different seed (passphrase changes everything) — the
        // load-time descriptor check must refuse, not silently mix keys.
        let other = WalletSeed::from_mnemonic(TEST_MNEMONIC, "different").unwrap();
        let err = WalletManager::new(&dir).open("btc", params, &other, DescriptorKind::Bip86);
        assert!(err.is_err(), "descriptor mismatch must fail the load");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_kind_fails_descriptor_check() {
        let dir = temp_data_dir();
        let params = btc_mainnet();
        let seed = WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let manager = WalletManager::new(&dir);
        manager
            .open("btc", params, &seed, DescriptorKind::Bip86)
            .unwrap();

        // The cached handle refuses a different kind outright...
        let err = manager.open("btc", params, &seed, DescriptorKind::Bip84);
        assert!(err.is_err(), "cached wallet must not be re-typed");

        // ...and a fresh manager on the same store fails bdk's load-time
        // descriptor check: the persisted descriptors are the BIP-86 ones.
        let err = WalletManager::new(&dir).open("btc", params, &seed, DescriptorKind::Bip84);
        assert!(err.is_err(), "kind mismatch must fail the load");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
