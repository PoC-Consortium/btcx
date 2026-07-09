//! Passive per-server health for Electrum backends.
//!
//! One [`ServerHealth`] cell per `(coin_id, url)`, handed out by a
//! process-wide registry so every holder of a connection to the same server
//! feeds the same cell: a pooled [`crate::backend::ElectrumBackend`] AND
//! the wallet sync worker's private one (they deliberately keep separate
//! sockets — one caller domain each — but they are views of the same
//! server, so their health must be one fact, not two).
//!
//! Health is **observed, never probed**: every real request already
//! succeeds or fails and takes a measurable time, and that is the only
//! input. Nothing here dials a server, and nothing here *blocks* one —
//! recording and routing are separate ([`ServerSet`] turns the recorded
//! state into skip/promote routing decisions).
//!
//! Failure counting is deduplicated **per connection generation**: several
//! callers can share one broken socket (the connection is behind an
//! `RwLock` and cloned around), and when it dies they all fail together —
//! that is ONE server incident, not N, or a single hiccup would leap the
//! backoff straight to its cap.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use std::sync::Arc;

/// First `Down` window after a fresh failure streak starts. Short — a
/// server that recovers within milliseconds must cost seconds, not minutes.
const BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Ceiling for the `Down` window however long the streak gets — a dead
/// server is re-eligible for a (cheap, promotion-time) recovery attempt at
/// least this often.
const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// EWMA smoothing for request latency: `ewma += (sample - ewma) / 8`.
const EWMA_SHIFT: u32 = 3;

/// Health as routing sees it: can this server be handed a request right
/// now? (`Down` only means "inside its backoff window" — after `until`
/// passes the server is eligible again and the next real use decides.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Never used this run — standby servers live here until promoted.
    Untested,
    /// Last request succeeded.
    Healthy,
    /// In a backoff window after a failure streak.
    Down { until: Instant },
}

/// One server's health cell. All writes are passive side effects of real
/// traffic; reads are a cheap mutex-guarded copy.
pub struct ServerHealth {
    coin_id: String,
    url: String,
    inner: Mutex<Inner>,
}

struct Inner {
    state: HealthState,
    /// Consecutive failed incidents (drives the backoff exponent).
    streak: u32,
    /// Connection generation of the last counted transport failure —
    /// failures on the same generation are the same incident (dedup).
    failed_generation: u64,
    latency_ewma_micros: Option<u64>,
    last_ok: Option<Instant>,
    last_error: Option<(String, Instant)>,
    requests: u64,
    failures: u64,
}

/// Serializable snapshot for status RPCs / network status pages.
/// Durations are seconds-ago so the reader needs no clock agreement.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthSnapshot {
    pub coin_id: String,
    pub url: String,
    /// `"untested" | "healthy" | "down"`.
    pub state: String,
    /// `"wallet"` (the elected home), `"view"` (active), or `"standby"` —
    /// set by the host application from its sticky role maps; `None` when
    /// the coin has not routed yet this run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// When `down`: seconds until the backoff window expires (0 = now).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_in_secs: Option<u64>,
    /// Smoothed request latency, milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ok_secs_ago: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_secs_ago: Option<u64>,
    pub requests: u64,
    pub failures: u64,
}

impl ServerHealth {
    fn new(coin_id: &str, url: &str) -> Self {
        Self {
            coin_id: coin_id.to_string(),
            url: url.to_string(),
            inner: Mutex::new(Inner {
                state: HealthState::Untested,
                streak: 0,
                failed_generation: 0,
                latency_ewma_micros: None,
                last_ok: None,
                last_error: None,
                requests: 0,
                failures: 0,
            }),
        }
    }

    /// A request on connection `generation` completed successfully in
    /// `latency`. Clears any failure streak — the server is back.
    pub(crate) fn record_success(&self, latency: Duration) {
        let mut inner = self.lock();
        inner.state = HealthState::Healthy;
        inner.streak = 0;
        inner.requests += 1;
        inner.last_ok = Some(Instant::now());
        let sample = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        inner.latency_ewma_micros = Some(match inner.latency_ewma_micros {
            None => sample,
            // ewma += (sample - ewma) / 8, in signed space to move both ways.
            Some(ewma) => {
                (ewma as i64 + ((sample as i64) - (ewma as i64)) / (1 << EWMA_SHIFT)).max(0) as u64
            }
        });
    }

    /// A transport failure on connection `generation`. Counted as a new
    /// incident (streak++, longer backoff) only for a generation that has
    /// not failed before; repeat failures of the same broken socket only
    /// bump the raw counter.
    pub(crate) fn record_failure(&self, generation: u64, error: &str) {
        let mut inner = self.lock();
        inner.failures += 1;
        inner.requests += 1;
        inner.last_error = Some((error.to_string(), Instant::now()));
        if generation != 0 && generation == inner.failed_generation {
            return; // same broken socket, same incident
        }
        inner.failed_generation = generation;
        inner.streak = inner.streak.saturating_add(1);
        inner.state = HealthState::Down {
            until: Instant::now() + backoff(inner.streak),
        };
    }

    /// A dial (TCP/TLS connect or handshake) failure — there is no
    /// generation yet. Dials are serialized by the connection slot's write
    /// lock, so every one is its own incident.
    pub(crate) fn record_connect_failure(&self, error: &str) {
        self.record_failure(0, error);
    }

    /// Is the server outside any backoff window right now? (Routing uses
    /// this to skip `Down` servers without paying a connect timeout.)
    pub fn available(&self) -> bool {
        match self.lock().state {
            HealthState::Untested | HealthState::Healthy => true,
            HealthState::Down { until } => Instant::now() >= until,
        }
    }

    /// Current state (with the `Down` window resolved against now).
    pub fn state(&self) -> HealthState {
        self.lock().state
    }

    /// When the current backoff window expires — `None` unless `Down`.
    /// ([`ServerSet`] uses it to rank a fully-down fleet: when nothing is
    /// available, route to whoever recovers soonest.)
    pub fn down_until(&self) -> Option<Instant> {
        match self.lock().state {
            HealthState::Down { until } => Some(until),
            _ => None,
        }
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let inner = self.lock();
        let now = Instant::now();
        let (state, retry_in_secs) = match inner.state {
            HealthState::Untested => ("untested", None),
            HealthState::Healthy => ("healthy", None),
            HealthState::Down { until } => {
                ("down", Some(until.saturating_duration_since(now).as_secs()))
            }
        };
        HealthSnapshot {
            coin_id: self.coin_id.clone(),
            url: self.url.clone(),
            state: state.to_string(),
            role: None,
            retry_in_secs,
            latency_ms: inner
                .latency_ewma_micros
                .map(|us| (us as f64 / 100.0).round() / 10.0),
            last_ok_secs_ago: inner.last_ok.map(|t| now.duration_since(t).as_secs()),
            last_error: inner.last_error.as_ref().map(|(e, _)| e.clone()),
            last_error_secs_ago: inner
                .last_error
                .as_ref()
                .map(|(_, t)| now.duration_since(*t).as_secs()),
            requests: inner.requests,
            failures: inner.failures,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("server health poisoned")
    }
}

/// `Down` window for the `streak`-th consecutive incident:
/// 5s, 10s, 20s, … capped at [`BACKOFF_CAP`].
fn backoff(streak: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(streak.saturating_sub(1).min(16)))
        .min(BACKOFF_CAP)
}

// ---- registry ---------------------------------------------------------------

/// Registry key: `(coin_id, url)` — one cell per server relationship.
type HealthMap = BTreeMap<(String, String), Arc<ServerHealth>>;

static REGISTRY: OnceLock<Mutex<HealthMap>> = OnceLock::new();

fn registry() -> &'static Mutex<HealthMap> {
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The (one) health cell for this server, created on first sight. Every
/// connection holder to the same `(coin_id, url)` gets the same cell.
pub fn server_health(coin_id: &str, url: &str) -> Arc<ServerHealth> {
    let mut reg = registry().lock().expect("health registry poisoned");
    reg.entry((coin_id.to_string(), url.to_string()))
        .or_insert_with(|| Arc::new(ServerHealth::new(coin_id, url)))
        .clone()
}

/// Snapshots for a coin's configured server list, in list order. Servers
/// never seen by the registry (never used this run) report as `untested`.
pub fn coin_snapshots(coin_id: &str, urls: &[&str]) -> Vec<HealthSnapshot> {
    urls.iter()
        .map(|url| server_health(coin_id, url).snapshot())
        .collect()
}

// ---- the active set ---------------------------------------------------------

/// How many Electrum VIEW servers (besides the wallet home) are active —
/// hold a pooled connection and serve reads — at a time. Everything else
/// in a coin's configured list is cold standby: never dialed until a slot
/// frees up. This is the invariant that makes a 10+-server list free:
/// more servers add backup depth, never latency.
pub const ACTIVE_VIEWS: usize = 2;

/// Sticky per-coin selection of the active view servers. Pure bookkeeping
/// over the health registry — selecting a server dials nothing (backends
/// are lazy; the first request through it does, on the short first-round
/// connect budget).
///
/// Selection rules, in order:
/// 1. **Sticky**: a currently-active server that is still configured and
///    not inside a backoff window keeps its slot. A returning
///    earlier-in-the-list server never evicts a working one (no
///    flap-back — each unnecessary switch costs a fresh dial+verify).
/// 2. **Fill by preference**: empty slots take the first configured-order
///    candidate that is available (untested counts — that is exactly a
///    standby being promoted).
/// 3. **Last resort**: if fewer than `k` servers are available at all,
///    fill with the down servers whose backoff windows expire soonest —
///    a fully-down fleet must still route SOMEWHERE so recovery can be
///    observed the moment a window lapses.
///
/// The wallet HOME is elected separately ([`Self::select_home`]); callers
/// pass the view candidates only.
#[derive(Default)]
pub struct ServerSet {
    active: Mutex<BTreeMap<String, Vec<String>>>,
    home: Mutex<BTreeMap<String, String>>,
}

impl ServerSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sticky election of the wallet HOME server. The home carries the
    /// bdk sync worker's socket and its scripthash subscriptions, so a
    /// switch costs a fresh dial + a full resync — the election is
    /// maximally sticky: the incumbent keeps the role while it is not
    /// inside a failure backoff window, however preferred a returning
    /// earlier-in-the-list server is (no flap-back). A down incumbent is
    /// replaced by the first available candidate in configured order; a
    /// fully-down list routes to the soonest-to-recover so recovery is
    /// observed the moment a window lapses.
    pub fn select_home<'a>(&self, coin_id: &str, candidates: &[&'a str]) -> Option<&'a str> {
        let (first, rest) = candidates.split_first()?;
        let _ = rest;
        let mut map = self.home.lock().expect("server set poisoned");
        let incumbent = map.get(coin_id).and_then(|prev| {
            candidates
                .iter()
                .copied()
                .find(|c| *c == prev)
                .filter(|url| server_health(coin_id, url).available())
        });
        let home = incumbent
            .or_else(|| {
                candidates
                    .iter()
                    .copied()
                    .find(|url| server_health(coin_id, url).available())
            })
            .or_else(|| {
                candidates
                    .iter()
                    .copied()
                    .filter_map(|url| {
                        server_health(coin_id, url)
                            .down_until()
                            .map(|until| (url, until))
                    })
                    .min_by_key(|(_, until)| *until)
                    .map(|(url, _)| url)
            })
            .unwrap_or(first);
        map.insert(coin_id.to_string(), home.to_string());
        Some(home)
    }

    /// Peek the sticky home WITHOUT electing — display only (`None` until
    /// the coin has routed once this run).
    pub fn current_home(&self, coin_id: &str) -> Option<String> {
        self.home
            .lock()
            .expect("server set poisoned")
            .get(coin_id)
            .cloned()
    }

    /// Peek the sticky view slots WITHOUT selecting — display only.
    pub fn current_views(&self, coin_id: &str) -> Vec<String> {
        self.active
            .lock()
            .expect("server set poisoned")
            .get(coin_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Pick (at most) `k` active views for `coin_id` out of `candidates`
    /// (configured order = preference order). Returns them in a stable
    /// order: kept slots first, then newly promoted ones.
    pub fn select<'a>(&self, coin_id: &str, candidates: &[&'a str], k: usize) -> Vec<&'a str> {
        let mut map = self.active.lock().expect("server set poisoned");
        let prev = map.get(coin_id).cloned().unwrap_or_default();

        // 1. Sticky: previous picks that are still configured and available.
        let mut picked: Vec<&'a str> = prev
            .iter()
            .filter_map(|kept| candidates.iter().copied().find(|c| *c == kept))
            .filter(|url| server_health(coin_id, url).available())
            .take(k)
            .collect();

        // 2. Preference order for the free slots.
        for url in candidates {
            if picked.len() >= k {
                break;
            }
            if !picked.contains(url) && server_health(coin_id, url).available() {
                picked.push(url);
            }
        }

        // 3. Last resort: everything (left) is down — take soonest-to-recover.
        if picked.len() < k {
            let mut down: Vec<(&'a str, Instant)> = candidates
                .iter()
                .filter(|url| !picked.contains(url))
                .filter_map(|url| {
                    server_health(coin_id, url)
                        .down_until()
                        .map(|until| (*url, until))
                })
                .collect();
            down.sort_by_key(|(_, until)| *until);
            for (url, _) in down {
                if picked.len() >= k {
                    break;
                }
                picked.push(url);
            }
        }

        map.insert(
            coin_id.to_string(),
            picked.iter().map(|u| u.to_string()).collect(),
        );
        picked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_base_and_caps() {
        assert_eq!(backoff(1), BACKOFF_BASE);
        assert_eq!(backoff(2), BACKOFF_BASE * 2);
        assert_eq!(backoff(4), BACKOFF_BASE * 8);
        assert_eq!(backoff(10), BACKOFF_CAP);
        assert_eq!(backoff(60), BACKOFF_CAP); // no overflow far out
    }

    #[test]
    fn success_failure_transitions() {
        let h = ServerHealth::new("btc", "tcp://a:1");
        assert_eq!(h.state(), HealthState::Untested);
        assert!(h.available(), "untested must be routable (standby dial)");

        h.record_success(Duration::from_millis(20));
        assert_eq!(h.state(), HealthState::Healthy);

        h.record_failure(1, "io: broken pipe");
        assert!(matches!(h.state(), HealthState::Down { .. }));
        assert!(!h.available(), "fresh Down window blocks routing");

        // Recovery clears the streak: after success, the next failure gets
        // the BASE window again, not a continued exponent.
        h.record_success(Duration::from_millis(20));
        assert_eq!(h.state(), HealthState::Healthy);
        let snap = h.snapshot();
        assert_eq!(snap.state, "healthy");
        assert_eq!(snap.requests, 3);
        assert_eq!(snap.failures, 1);
        assert_eq!(snap.last_error.as_deref(), Some("io: broken pipe"));
    }

    #[test]
    fn failures_dedupe_per_generation() {
        let h = ServerHealth::new("btc", "tcp://a:1");
        // Three callers all failing on the same broken socket (gen 7):
        // one incident — the streak (and so the backoff) advances once.
        h.record_failure(7, "io");
        h.record_failure(7, "io");
        h.record_failure(7, "io");
        assert_eq!(h.lock().streak, 1);
        assert_eq!(h.snapshot().failures, 3, "raw counter still counts all");

        // The reconnect's NEW socket failing too is a new incident.
        h.record_failure(8, "io");
        assert_eq!(h.lock().streak, 2);

        // Dial failures (no generation) each count — they are serialized.
        h.record_connect_failure("connect timeout");
        h.record_connect_failure("connect timeout");
        assert_eq!(h.lock().streak, 4);
    }

    #[test]
    fn latency_ewma_converges_toward_samples() {
        let h = ServerHealth::new("btc", "tcp://a:1");
        h.record_success(Duration::from_millis(100));
        assert_eq!(h.snapshot().latency_ms, Some(100.0));
        // A run of faster samples pulls the average down monotonically.
        let mut last = 100.0;
        for _ in 0..20 {
            h.record_success(Duration::from_millis(10));
            let now = h.snapshot().latency_ms.unwrap();
            assert!(now <= last, "ewma must move toward the samples");
            last = now;
        }
        assert!(last < 30.0, "ewma converged near the new level, got {last}");
    }

    #[test]
    fn server_set_is_sticky_and_health_aware() {
        // Unique coin id per test — the registry is process-global.
        let coin = "test-set-sticky";
        let all = ["tcp://a:1", "tcp://b:1", "tcp://c:1", "tcp://d:1"];
        let set = ServerSet::new();

        // Fresh start: configured order wins, standbys stay untouched.
        assert_eq!(set.select(coin, &all, 2), vec!["tcp://a:1", "tcp://b:1"]);

        // b trips its breaker → replaced by the next candidate; a keeps its
        // slot (sticky).
        server_health(coin, "tcp://b:1").record_connect_failure("dead");
        assert_eq!(set.select(coin, &all, 2), vec!["tcp://a:1", "tcp://c:1"]);

        // b comes back (its window would expire; simulate with a success):
        // NO flap-back — c keeps the slot it earned.
        server_health(coin, "tcp://b:1").record_success(Duration::from_millis(5));
        assert_eq!(set.select(coin, &all, 2), vec!["tcp://a:1", "tcp://c:1"]);
    }

    #[test]
    fn server_set_last_resort_routes_to_soonest_recovery() {
        let coin = "test-set-lastresort";
        let all = ["tcp://a:1", "tcp://b:1"];
        let set = ServerSet::new();
        // Everything down — b twice (longer window), a once (shorter).
        server_health(coin, "tcp://b:1").record_connect_failure("dead");
        server_health(coin, "tcp://b:1").record_connect_failure("dead");
        server_health(coin, "tcp://a:1").record_connect_failure("dead");
        // A fully-down fleet still routes — soonest-to-recover first.
        assert_eq!(set.select(coin, &all, 2), vec!["tcp://a:1", "tcp://b:1"]);
    }

    #[test]
    fn home_election_is_sticky_with_no_flap_back() {
        let coin = "test-home-sticky";
        let all = ["tcp://a:1", "tcp://b:1", "tcp://c:1"];
        let set = ServerSet::new();

        assert_eq!(set.select_home(coin, &all), Some("tcp://a:1"));

        // Incumbent dies → first available candidate takes over.
        server_health(coin, "tcp://a:1").record_connect_failure("dead");
        assert_eq!(set.select_home(coin, &all), Some("tcp://b:1"));

        // a returns: b KEEPS the role — a switch costs a full resync and
        // must never happen while the incumbent works.
        server_health(coin, "tcp://a:1").record_success(Duration::from_millis(5));
        assert_eq!(set.select_home(coin, &all), Some("tcp://b:1"));

        // Everything down: soonest-to-recover wins. b is on its second
        // incident (10s window); a and c are on their first (5s) — a's was
        // recorded first, so its window expires first.
        server_health(coin, "tcp://b:1").record_connect_failure("dead");
        server_health(coin, "tcp://b:1").record_connect_failure("dead");
        server_health(coin, "tcp://a:1").record_connect_failure("dead");
        server_health(coin, "tcp://c:1").record_connect_failure("dead");
        let elected = set.select_home(coin, &all).unwrap();
        assert_eq!(elected, "tcp://a:1", "soonest-to-recover of a down fleet");

        // Reconfiguration that drops the incumbent falls back cleanly.
        assert_eq!(
            set.select_home(coin, &["tcp://x:1"]),
            Some("tcp://x:1"),
            "unknown-but-configured beats a stale sticky entry"
        );
        assert_eq!(set.select_home(coin, &[]), None);
    }

    #[test]
    fn server_set_handles_short_and_reconfigured_lists() {
        let coin = "test-set-short";
        let set = ServerSet::new();
        // Fewer candidates than slots: take what's there.
        assert_eq!(set.select(coin, &["tcp://a:1"], 2), vec!["tcp://a:1"]);
        // Reconfiguration drops a: the sticky entry must not survive it.
        assert_eq!(
            set.select(coin, &["tcp://x:1", "tcp://y:1"], 2),
            vec!["tcp://x:1", "tcp://y:1"]
        );
        // Empty candidate list (node-mode coin with no electrum views).
        assert_eq!(set.select(coin, &[], 2), Vec::<&str>::new());
    }

    #[test]
    fn registry_hands_out_one_cell_per_coin_url() {
        let a1 = server_health("test-reg", "tcp://x:1");
        let a2 = server_health("test-reg", "tcp://x:1");
        assert!(Arc::ptr_eq(&a1, &a2), "same (coin,url) → same cell");
        let b = server_health("test-reg", "tcp://y:1");
        assert!(!Arc::ptr_eq(&a1, &b));
        // Same url under another coin is a different server relationship.
        let c = server_health("test-reg-2", "tcp://x:1");
        assert!(!Arc::ptr_eq(&a1, &c));

        a1.record_success(Duration::from_millis(5));
        let snaps = coin_snapshots("test-reg", &["tcp://x:1", "tcp://never-used:1"]);
        assert_eq!(snaps[0].state, "healthy");
        assert_eq!(snaps[1].state, "untested");
    }
}
