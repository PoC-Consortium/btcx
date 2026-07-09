//! Background Electrum sync worker for a bdk wallet.
//!
//! One plain `std::thread` per coin, owning its own long-lived Electrum
//! connection ([`ElectrumBackend`]) to the coin's primary server —
//! deliberately separate from any pooled connection other callers share,
//! so each socket has exactly one caller at a time and every blocking call
//! stays bounded by the socket timeouts. Its loop:
//!
//! `wait(poke OR ~15s tick)` → observe (subscriptions, tip poll) →
//! **snapshot** revealed spks under a brief wallet-entry lock → **fetch**
//! batched with NO locks held → **apply** via bdk `apply_update` + persist
//! under a brief entry lock (the split lives in
//! [`crate::sync::sync_wallet`]).
//!
//! This turns wallet reads into pure cache hits (~0ms, never network) and
//! caps server traffic at the worker cadence regardless of how hard the UI
//! polls. Freshness comes from the cadence plus **pokes** (after the
//! wallet's own broadcasts, on Receive-dialog opens, on events touching
//! the coin) plus `scripthash.subscribe` push notifications: the worker
//! subscribes every revealed spk, so a status change (incoming funds, a
//! confirmation) is picked up at the next socket read instead of waiting
//! for a blind re-scan; unchanged statuses let the tick skip the sync
//! entirely — an idle tick is ONE round-trip (the tip poll, which doubles
//! as keep-alive).
//!
//! Race-safety: wallet mutation stays under the per-coin entry mutex; the
//! worker never touches its owner's locks. The one primitive is the
//! `first_sync_done` latch — wallet WRITES wait on it (bounded) so a spend
//! can never coin-select from a cache that has not seen the chain this
//! run.
//!
//! Lifecycle: the thread holds only a `Weak` wallet handle and a shutdown
//! flag — it exits when the owning wallet manager drops or the host stops.
//! A dead server makes reads *stale*, not slow: the worker reconnects with
//! backoff while reads keep serving the cache.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bitcoin::ScriptBuf;

use crate::backend::ElectrumBackend;
use crate::sync::{self, WalletEntry, WalletHandle};

/// Steady-state cadence: the worker re-observes (and, if anything changed,
/// re-syncs) about four times a minute. Also the reconnect backoff base.
const TICK: Duration = Duration::from_secs(15);

/// Belt-and-suspenders full sync every this many ticks (~10 min) even when
/// the subscriptions report no change — a server that silently stops
/// pushing notifications can go stale for at most this long.
const FORCE_SYNC_TICKS: u32 = 40;

/// Reconnect/retry backoff ceiling for a down server.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// How long a wallet WRITE waits for the first completed sync of this run
/// before failing honestly. Covers the boot race (worker is already
/// dialing) with room for one slow connect; a genuinely dead server errors
/// after this.
pub const FIRST_SYNC_WAIT: Duration = Duration::from_secs(30);

/// Shared handle to one coin's background sync worker. The thread and its
/// callers communicate exclusively through this.
pub struct SyncWorker {
    coin_id: String,
    state: Mutex<WorkerState>,
    cv: Condvar,
}

struct WorkerState {
    /// The worker's private Electrum view of the coin's primary server.
    /// Replaced (with a poke) when the coin is reconfigured.
    chain: Arc<ElectrumBackend>,
    /// Wake-up requested: sync NOW instead of at the next tick.
    poked: bool,
    /// Exit requested (wallet manager dropped / host stop).
    shutdown: bool,
    /// Set after the first successful sync of this run — the latch wallet
    /// writes gate on.
    first_sync_done: bool,
    /// Last time a full worker pass completed against the server — an idle
    /// tick counts (subscriptions checked, tip polled: the cache is
    /// CONFIRMED current, not merely unchanged). `None` until the first
    /// pass. The UI's "balance as of" signal: while the home server is
    /// down this stops advancing and the cached balance is honestly stale
    /// instead of silently frozen.
    last_fresh: Option<Instant>,
}

impl SyncWorker {
    /// Spawn the worker thread for `coin_id`. It holds `wallet` only
    /// weakly: if the owning wallet manager goes away, the next loop
    /// iteration exits.
    pub fn spawn(coin_id: &str, chain: Arc<ElectrumBackend>, wallet: &WalletHandle) -> Arc<Self> {
        let worker = Arc::new(Self {
            coin_id: coin_id.to_string(),
            state: Mutex::new(WorkerState {
                chain,
                poked: false,
                shutdown: false,
                first_sync_done: false,
                last_fresh: None,
            }),
            cv: Condvar::new(),
        });
        let runner = worker.clone();
        let weak = Arc::downgrade(wallet);
        std::thread::Builder::new()
            .name(format!("wallet-sync-{coin_id}"))
            .spawn(move || run(runner, weak))
            .expect("spawning wallet sync worker");
        worker
    }

    /// Request an immediate sync pass (the wallet's own broadcast, a
    /// Receive dialog opening, an event on the coin). Cheap and race-free:
    /// if the worker is mid-pass it goes around again.
    pub fn poke(&self) {
        self.state.lock().expect("worker state poisoned").poked = true;
        self.cv.notify_all();
    }

    /// Hand the worker a (possibly) new chain backend — the coin was
    /// reconfigured. No-op when it is the same instance.
    pub fn set_chain(&self, chain: Arc<ElectrumBackend>) {
        let mut state = self.state.lock().expect("worker state poisoned");
        if !Arc::ptr_eq(&state.chain, &chain) {
            state.chain = chain;
            state.poked = true;
            self.cv.notify_all();
        }
    }

    /// Tell the thread to exit at its next wakeup (which this triggers).
    pub fn shutdown(&self) {
        self.state.lock().expect("worker state poisoned").shutdown = true;
        self.cv.notify_all();
    }

    /// Block until the first sync of this run has completed, `timeout`, or
    /// shutdown — whichever comes first. `true` iff the latch is set.
    pub fn wait_first_sync(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().expect("worker state poisoned");
        loop {
            if state.first_sync_done {
                return true;
            }
            if state.shutdown {
                return false;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (guard, _) = self
                .cv
                .wait_timeout(state, left)
                .expect("worker state poisoned");
            state = guard;
        }
    }

    /// Age of the last completed pass against the server — `None` before
    /// the first. The cached wallet state is exactly this stale; the UI
    /// turns it into a "balance as of" hint when the home is down.
    pub fn fresh_age(&self) -> Option<Duration> {
        self.state
            .lock()
            .expect("worker state poisoned")
            .last_fresh
            .map(|t| t.elapsed())
    }

    fn mark_fresh(&self) {
        self.state.lock().expect("worker state poisoned").last_fresh = Some(Instant::now());
    }

    fn chain(&self) -> Arc<ElectrumBackend> {
        self.state
            .lock()
            .expect("worker state poisoned")
            .chain
            .clone()
    }

    fn is_shutdown(&self) -> bool {
        self.state.lock().expect("worker state poisoned").shutdown
    }

    fn take_poke(&self) -> bool {
        let mut state = self.state.lock().expect("worker state poisoned");
        std::mem::take(&mut state.poked)
    }

    fn mark_first_sync(&self) {
        let mut state = self.state.lock().expect("worker state poisoned");
        if !state.first_sync_done {
            state.first_sync_done = true;
            self.cv.notify_all();
        }
    }

    /// Sleep until poked/shutdown or `timeout`. A poke that arrived DURING
    /// the pass (poked already true) returns immediately — never lost.
    fn wait(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().expect("worker state poisoned");
        while !state.poked && !state.shutdown {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            let (guard, _) = self
                .cv
                .wait_timeout(state, left)
                .expect("worker state poisoned");
            state = guard;
        }
    }
}

/// The worker's view of its scripthash subscriptions. Subscriptions are per
/// CONNECTION (they die with the socket, and the client registers them per
/// instance), so everything here is pinned to the exact connection instance
/// it was built on — `Weak` + pointer identity, which stays correct even
/// when the whole backend is swapped for a reconfigured server — and
/// rebuilt whenever the current connection is a different one.
#[derive(Default)]
struct Subscriptions {
    conn: Weak<crate::backend::ElectrumConn>,
    /// Last known status per subscribed spk (`None` = no history). Electrum
    /// defines the status as a hash over the spk's confirmed+mempool
    /// history, so ANY relevant change — incoming tx, confirmation, reorg —
    /// changes it.
    statuses: HashMap<ScriptBuf, Option<electrum_client::ScriptStatus>>,
}

fn backoff(failures: u32) -> Duration {
    // 15s, 30s, 60s, 120s, 240s, 300s cap.
    TICK.saturating_mul(2u32.saturating_pow(failures.saturating_sub(1).min(16)))
        .min(MAX_BACKOFF)
}

fn run(worker: Arc<SyncWorker>, wallet: Weak<Mutex<WalletEntry>>) {
    let mut subs = Subscriptions::default();
    let mut dirty = true; // first pass always syncs (the first_sync latch)
    let mut failures: u32 = 0;
    let mut ticks_since_sync: u32 = 0;

    loop {
        if worker.is_shutdown() {
            return;
        }
        // The wallet entry is owned by the wallet manager's map; when that
        // is gone, so is our job.
        let Some(handle) = wallet.upgrade() else {
            return;
        };
        let chain = worker.chain();
        if worker.take_poke() {
            dirty = true;
        }
        ticks_since_sync += 1;
        if ticks_since_sync >= FORCE_SYNC_TICKS {
            dirty = true;
        }

        let round: Result<()> = (|| {
            // Cached per connection generation — zero round-trips steady
            // state, the full genesis/pruning checks on every fresh socket.
            chain.verify_chain()?;
            if std::env::var_os("BTCX_WALLET_SYNC_TRACE").is_some() {
                eprintln!(
                    "[wallet-sync {}] pass: dirty={dirty} subs={} ticks={ticks_since_sync}",
                    worker.coin_id,
                    subs.statuses.len()
                );
            }
            if observe(&chain, &handle, &mut subs)? {
                dirty = true;
            }
            if dirty {
                if worker.is_shutdown() {
                    return Ok(()); // don't start a fetch we won't apply
                }
                sync::sync_wallet(&handle, &chain, || worker.is_shutdown())?;
                dirty = false;
                ticks_since_sync = 0;
                // A shutdown-aborted pass applied nothing — it must not
                // release the write gate.
                if !worker.is_shutdown() {
                    worker.mark_first_sync();
                }
            }
            Ok(())
        })();
        drop(handle);

        match round {
            Ok(()) => {
                if failures > 0 {
                    eprintln!(
                        "[wallet-sync {}] recovered after {failures} failed attempt(s)",
                        worker.coin_id
                    );
                }
                failures = 0;
                worker.mark_fresh();
            }
            Err(err) => {
                failures += 1;
                // First failure of a streak, then every 8th — not every 15s.
                if failures == 1 || failures.is_multiple_of(8) {
                    eprintln!(
                        "[wallet-sync {}] sync attempt {failures} failed: {err:#}",
                        worker.coin_id
                    );
                }
            }
        }

        let pause = if failures == 0 {
            TICK
        } else {
            backoff(failures)
        };
        worker.wait(pause);
    }
}

/// Cheap change detection, once per wakeup: keep the scripthash
/// subscriptions covering every revealed spk, drain their queued status
/// notifications, and poll the tip (one round-trip — also the keep-alive
/// that lets the client read pushed notifications off the socket). Returns
/// whether a full sync is warranted.
fn observe(
    chain: &ElectrumBackend,
    handle: &WalletHandle,
    subs: &mut Subscriptions,
) -> Result<bool> {
    let trace = std::env::var_os("BTCX_WALLET_SYNC_TRACE").is_some();
    let step = |what: &str| {
        if trace {
            eprintln!("[wallet-sync] observe step: {what}");
        }
    };
    let mut dirty = false;

    step("pin");
    let conn = chain.pinned_conn()?;
    let same_conn = subs
        .conn
        .upgrade()
        .is_some_and(|pinned| Arc::ptr_eq(&pinned, &conn));
    if !same_conn {
        // Fresh connection: the old subscriptions died with the socket, and
        // we cannot know what changed while we were away — sync.
        subs.statuses.clear();
        subs.conn = Arc::downgrade(&conn);
        dirty = true;
    }

    // Snapshot the revealed spks under a brief entry lock (pure CPU).
    step("snapshot");
    let revealed = {
        let entry = handle.lock().expect("wallet entry poisoned");
        sync::revealed_spks(&entry)
    };
    let fresh: Vec<ScriptBuf> = revealed
        .into_iter()
        .filter(|spk| !subs.statuses.contains_key(spk))
        .collect();
    if !fresh.is_empty() {
        step("subscribe");
        // One batched round-trip. On ANY failure: drop this connection —
        // the crate pre-registers the hashes before sending, so a half-done
        // batch would poison retries on the same instance with
        // AlreadySubscribed; a fresh socket starts clean.
        let statuses = match conn.subscribe_spks(&fresh) {
            Ok(statuses) => statuses,
            Err(e) => {
                chain.evict(&conn, &format!("electrum batch subscribe: {e}"));
                return Err(anyhow!("electrum batch subscribe: {e}"));
            }
        };
        for (spk, status) in fresh.into_iter().zip(statuses) {
            // A just-revealed spk that already HAS history (a recycled
            // handout, our own just-broadcast change) needs folding in.
            if status.is_some() {
                dirty = true;
            }
            subs.statuses.insert(spk, status);
        }
    }

    // Drain queued push notifications (local, no I/O). A status different
    // from the last known one is the instant-detection path: incoming
    // funds, confirmations, reorgs touching us.
    for (spk, last) in subs.statuses.iter_mut() {
        // NotSubscribed after a mid-pass reconnect: ignore — the generation
        // check next wakeup rebuilds everything.
        while let Ok(Some(status)) = conn.pop_spk_status(spk) {
            if *last != Some(status) {
                *last = Some(status);
                dirty = true;
            }
        }
    }

    // Tip poll: new block ⇒ sync (confirmation counts move even when no
    // status changed... a status DOES change on our txs' first
    // confirmation, but activity depth is computed from the wallet's own
    // checkpoint tip, which only a sync advances).
    step("tip");
    let (tip_height, _) = chain.tip()?;
    let local_tip = {
        let entry = handle.lock().expect("wallet entry poisoned");
        entry.wallet.latest_checkpoint().height()
    };
    if tip_height != u64::from(local_tip) {
        dirty = true;
    }
    if std::env::var_os("BTCX_WALLET_SYNC_TRACE").is_some() {
        eprintln!("[wallet-sync] observe: tip={tip_height} local={local_tip} dirty={dirty}");
    }

    Ok(dirty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use params_btcx::params::Network;
    use params_btcx::registry;

    fn bare_worker(chain: Arc<ElectrumBackend>) -> SyncWorker {
        SyncWorker {
            coin_id: "btc".into(),
            state: Mutex::new(WorkerState {
                chain,
                poked: false,
                shutdown: false,
                first_sync_done: false,
                last_fresh: None,
            }),
            cv: Condvar::new(),
        }
    }

    fn dead_backend() -> Arc<ElectrumBackend> {
        let params = registry::get("btc")
            .expect("built-in btc")
            .params(Network::Mainnet)
            .expect("btc mainnet params");
        // Lazy — never dialed by these tests.
        Arc::new(ElectrumBackend::new(params, "tcp://127.0.0.1:1").unwrap())
    }

    #[test]
    fn backoff_doubles_from_tick_and_caps() {
        assert_eq!(backoff(1), TICK);
        assert_eq!(backoff(2), TICK * 2);
        assert_eq!(backoff(3), TICK * 4);
        assert_eq!(backoff(6), MAX_BACKOFF);
        assert_eq!(backoff(60), MAX_BACKOFF); // no overflow far out
    }

    #[test]
    fn first_sync_latch_gates_and_releases() {
        let worker = bare_worker(dead_backend());
        // Unset latch: an honest, bounded false — this is the write gate.
        assert!(!worker.wait_first_sync(Duration::from_millis(30)));
        worker.mark_first_sync();
        assert!(worker.wait_first_sync(Duration::from_millis(30)));
        // Idempotent.
        worker.mark_first_sync();
        assert!(worker.wait_first_sync(Duration::ZERO));
    }

    #[test]
    fn shutdown_releases_latch_waiters_as_false() {
        let worker = Arc::new(bare_worker(dead_backend()));
        let waiter = worker.clone();
        let t = std::thread::spawn(move || waiter.wait_first_sync(Duration::from_secs(30)));
        worker.shutdown();
        assert!(!t.join().unwrap(), "shutdown must not read as synced");
    }

    #[test]
    fn poke_is_sticky_and_wakes_the_wait() {
        let worker = bare_worker(dead_backend());
        worker.poke();
        // A poke that lands before the wait returns immediately (never lost).
        let start = Instant::now();
        worker.wait(Duration::from_secs(10));
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(worker.take_poke());
        assert!(!worker.take_poke(), "take consumes the flag");
    }

    #[test]
    fn set_chain_pokes_only_on_a_real_change() {
        let a = dead_backend();
        let worker = bare_worker(a.clone());
        worker.set_chain(a.clone());
        assert!(!worker.take_poke(), "same instance: no wakeup");
        worker.set_chain(dead_backend());
        assert!(worker.take_poke(), "new instance: reconfigured — wake up");
    }
}
