//! Chain source: raw Electrum → bdk updates.
//!
//! The sync is split snapshot → fetch → apply: the wallet-entry lock is
//! held only for the pure-CPU snapshot and the final apply+persist, NEVER
//! across network I/O — the background sync worker
//! ([`crate::worker::SyncWorker`]) runs the fetch while reads keep serving
//! from the cache. The snapshot→fetch→apply gap is what bdk's monotonic
//! `Update` merge is designed for: a chain update that no longer connects
//! is rejected (and retried next tick), never corrupts.
//!
//! bdk is used at the *script* level only:
//! - Raw headers never reach bdk: anchors and checkpoints are built from
//!   header bytes hashed via [`ChainParams::header_hash`], so Bitcoin
//!   PoCX's 286-byte headers are handled exactly like everywhere else in
//!   this crate, and stock upstream bdk needs no fork.
//!
//! [`ChainParams::header_hash`]: params_btcx::params::ChainParams::header_hash

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet, Update};
use bitcoin::{BlockHash, ScriptBuf, Txid};

use crate::backend::ElectrumBackend;

/// BIP-44 gap limit for the initial full scan of a restored seed. Every
/// address a caps-respecting wallet hands out is revealed-then-persisted,
/// so steady-state syncs never probe beyond the revealed set; the gap only
/// matters when the sqlite store is fresh for a seed that may have on-chain
/// history (restore on a new machine). Because address HANDOUT is capped
/// (the wallet's unused-ahead cap), the real on-chain gap can never exceed
/// that cap — this scan width carries a safety margin on top, making a
/// restore's full scan complete BY CONSTRUCTION.
pub const STOP_GAP: u32 = 25;

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One coin's open wallet: the bdk wallet plus the sqlite connection it
/// persists into. Always lock the pair together (single mutex in the
/// owning wallet manager) — persisting after every mutation is what makes
/// a crash lose nothing but re-syncable chain data.
pub struct WalletEntry {
    pub wallet: PersistedWallet<Connection>,
    pub conn: Connection,
}

/// Shared handle to one coin's wallet.
pub type WalletHandle = Arc<Mutex<WalletEntry>>;

/// What the fetch phase needs from the wallet, captured under a brief
/// entry lock.
struct SpkSnapshot {
    /// Fresh store (nothing ever revealed) → gap-limit scan for a restored
    /// seed's history. Steady state → revealed spks only.
    full_scan: bool,
    revealed: Vec<(KeychainKind, Vec<ScriptBuf>)>,
    local_tip: CheckPoint,
}

fn snapshot_spks(entry: &WalletEntry) -> SpkSnapshot {
    let full_scan = entry
        .wallet
        .derivation_index(KeychainKind::External)
        .is_none();
    let mut revealed = Vec::new();
    if !full_scan {
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            if let Some(last) = entry.wallet.derivation_index(keychain) {
                let spks = (0..=last)
                    .map(|i| {
                        entry
                            .wallet
                            .peek_address(keychain, i)
                            .address
                            .script_pubkey()
                    })
                    .collect();
                revealed.push((keychain, spks));
            }
        }
    }
    SpkSnapshot {
        full_scan,
        revealed,
        local_tip: entry.wallet.latest_checkpoint(),
    }
}

/// Every revealed spk of both keychains — the set the sync worker keeps
/// scripthash subscriptions on. Brief pure-CPU derivation, no chain I/O.
pub fn revealed_spks(entry: &WalletEntry) -> Vec<ScriptBuf> {
    snapshot_spks(entry)
        .revealed
        .into_iter()
        .flat_map(|(_, spks)| spks)
        .collect()
}

/// Fetch phase: scripthash histories of the snapshot's spks (or a STOP_GAP
/// full scan when the store is fresh), PoCX-safe anchors from raw headers,
/// and a checkpoint update that always connects to the wallet's local chain
/// (genesis at worst). This is an unforked-bdk chain source. Network I/O
/// happens with NO wallet lock held; the full-scan windows re-take it
/// briefly for pure-CPU address derivation only.
fn fetch_update(
    chain: &ElectrumBackend,
    handle: &WalletHandle,
    snap: SpkSnapshot,
) -> Result<Update> {
    let params = chain.params();

    // Pin the server tip BEFORE fetching any history. The worker's
    // skip-the-sync change detection compares the server tip against the
    // wallet's checkpoint tip; recording a tip OLDER than every history
    // response (the server's index only moves forward) guarantees a block
    // arriving mid-fetch leaves the recorded tip behind it — so the next
    // tick re-syncs. Tip-fetched-last would record the NEW tip against
    // pre-block histories and the detection would sleep through the miss
    // until the periodic forced sync.
    let (tip_height, tip_raw) = chain.tip()?;
    let pinned_tip = (
        u32::try_from(tip_height).context("tip height")?,
        BlockHash::from_str(&params.header_hash(&tip_raw)?)?,
    );

    // Phase A — scripthash histories, BATCHED (one round-trip per batch;
    // unbatched this is one round-trip PER ADDRESS, which takes tens of
    // seconds against a remote server).
    let mut last_active: BTreeMap<KeychainKind, u32> = BTreeMap::new();
    let mut all_history: Vec<(String, i64)> = Vec::new();
    if snap.full_scan {
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            // Windowed gap scan: STOP_GAP spks per batch, stop once a full
            // STOP_GAP run of consecutive unused spks has been seen —
            // identical result to a per-spk walk (a window may peek a few
            // spks past the stop point; pure reads, harmless).
            let (mut index, mut gap) = (0u32, 0u32);
            'windows: loop {
                let spks: Vec<ScriptBuf> = {
                    let entry = handle.lock().expect("wallet entry poisoned");
                    (index..index + STOP_GAP)
                        .map(|i| {
                            entry
                                .wallet
                                .peek_address(keychain, i)
                                .address
                                .script_pubkey()
                        })
                        .collect()
                };
                for (offset, history) in chain.histories(&spks)?.into_iter().enumerate() {
                    if history.is_empty() {
                        gap += 1;
                        if gap >= STOP_GAP {
                            break 'windows;
                        }
                    } else {
                        last_active.insert(keychain, index + offset as u32);
                        gap = 0;
                        all_history.extend(history);
                    }
                }
                index += STOP_GAP;
            }
        }
    } else {
        for (_, spks) in &snap.revealed {
            for history in chain.histories(spks)? {
                all_history.extend(history);
            }
        }
    }

    // Phase B — sort the finds: which tx bodies we still need (deduped),
    // which heights need headers for anchors, what sits in the mempool.
    // One timestamp for the whole sync pass: `seen_ats` is a SET of
    // (txid, ts) pairs (bdk_chain 0.23), so a tx surfacing in several spk
    // histories must insert the identical pair to dedupe.
    let sync_ts = now_ts();
    let mut fetched: HashSet<Txid> = HashSet::new();
    let mut need_txs: Vec<String> = Vec::new();
    let mut anchor_reqs: Vec<(Txid, u32)> = Vec::new();
    let mut seen_ats: HashSet<(Txid, u64)> = HashSet::new();
    for (txid_hex, height) in &all_history {
        let txid = Txid::from_str(txid_hex).context("electrum history txid")?;
        if fetched.insert(txid) {
            need_txs.push(txid_hex.clone());
        }
        if *height > 0 {
            let height = u32::try_from(*height).context("history height")?;
            anchor_reqs.push((txid, height));
        } else {
            // 0 = mempool, -1 = mempool with unconfirmed parents.
            seen_ats.insert((txid, sync_ts));
        }
    }

    // Phase C — tx bodies, one batch. Phase D — headers, one batch.
    let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
    for tx in chain.get_raw_txs(&need_txs)? {
        tx_update.txs.push(Arc::new(tx));
    }
    let need_heights: Vec<u64> = anchor_reqs
        .iter()
        .map(|(_, h)| u64::from(*h))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut headers: BTreeMap<u32, (BlockHash, u64)> = BTreeMap::new();
    for (height, (hash_hex, time)) in need_heights.iter().zip(chain.headers_at(&need_heights)?) {
        headers.insert(
            u32::try_from(*height).context("header height")?,
            (BlockHash::from_str(&hash_hex)?, u64::from(time)),
        );
    }
    for (txid, height) in anchor_reqs {
        let (hash, time) = headers[&height];
        tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: BlockId { height, hash },
                confirmation_time: time,
            },
            txid,
        ));
    }
    tx_update.seen_ats = seen_ats;

    let chain_cp = chain_update(chain, snap.local_tip, &headers, pinned_tip)?;
    Ok(Update {
        last_active_indices: last_active,
        tx_update,
        chain: Some(chain_cp),
    })
}

/// One full sync pass: snapshot (brief lock) → fetch (no locks) → apply +
/// persist (brief lock). `abort` is checked between fetch and apply so a
/// shutting-down worker never writes into a store its manager already let
/// go of.
pub fn sync_wallet(
    handle: &WalletHandle,
    chain: &ElectrumBackend,
    abort: impl Fn() -> bool,
) -> Result<()> {
    let snap = {
        let entry = handle.lock().expect("wallet entry poisoned");
        snapshot_spks(&entry)
    };
    let update = fetch_update(chain, handle, snap)?;
    if abort() {
        return Ok(());
    }
    let mut guard = handle.lock().expect("wallet entry poisoned");
    let entry = &mut *guard;
    entry
        .wallet
        .apply_update(update)
        .map_err(|e| anyhow!("bdk chain update does not connect: {e}"))?;
    entry
        .wallet
        .persist(&mut entry.conn)
        .map_err(|e| anyhow!("persisting wallet: {e}"))?;
    Ok(())
}

/// Build the checkpoint update: every anchored block, the (pre-fetch
/// pinned) server tip, and a point of agreement with the wallet's existing
/// chain. Walking the local checkpoints tip-down, a stale (reorged) hash is
/// replaced by the server's view and the walk continues until agreement —
/// height 0 agrees by construction (both sides pin the coin's genesis).
fn chain_update(
    chain: &ElectrumBackend,
    local_tip: CheckPoint,
    anchored: &BTreeMap<u32, (BlockHash, u64)>,
    pinned_tip: (u32, BlockHash),
) -> Result<CheckPoint> {
    let (tip_height, tip_hash) = pinned_tip;

    let mut blocks: BTreeMap<u32, BlockHash> =
        anchored.iter().map(|(h, (hash, _))| (*h, *hash)).collect();
    blocks.insert(tip_height, tip_hash);

    for cp in local_tip.iter() {
        let height = cp.height();
        if height > tip_height {
            continue; // server is behind our stored tip — let agreement decide
        }
        let server = match blocks.get(&height) {
            Some(hash) => *hash,
            None => {
                let (hash_hex, _) = chain.header_at(u64::from(height))?;
                let hash = BlockHash::from_str(&hash_hex)?;
                blocks.insert(height, hash);
                hash
            }
        };
        if server == cp.hash() {
            break; // point of agreement found — the update connects here
        }
        // Reorged: blocks already holds the server's hash, displacing ours.
    }

    CheckPoint::from_block_ids(
        blocks
            .into_iter()
            .map(|(height, hash)| BlockId { height, hash }),
    )
    .map_err(|_| anyhow!("checkpoint heights not strictly ascending"))
}
