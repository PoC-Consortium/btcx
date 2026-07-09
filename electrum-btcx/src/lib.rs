//! Electrum connection layer for Bitcoin and Bitcoin PoCX (BTCX).
//!
//! - [`backend`] — [`ElectrumBackend`]: one lazy, self-healing connection
//!   per server (`tcp://` / `ssl://` with an accept-any-cert verifier),
//!   batched scripthash reads, raw-header handling via
//!   `params_btcx::params::ChainParams::header_hash` (Bitcoin PoCX 286-byte
//!   headers never meet `electrum-client`'s Bitcoin-typed header API), fee
//!   estimation, and [`ElectrumPool`] for connection reuse.
//! - [`server_health`] — passive per-server health cells and the sticky
//!   [`ServerSet`](server_health::ServerSet) routing over them.
//! - [`sync`] — the snapshot → fetch → apply wallet sync producing
//!   `bdk_wallet::Update`s from batched Electrum reads.
//! - [`worker`] — [`SyncWorker`]: one background thread per coin keeping a
//!   bdk wallet cache fresh over its own long-lived connection.
//!
//! All backend data is an untrusted hint: callers verify scripts and
//! amounts against locally reconstructed bytes. A lying server can withhold
//! or delay, never steal.

pub mod backend;
pub mod server_health;
pub mod sync;
pub mod worker;

pub use backend::{
    ChainMismatch, ElectrumBackend, ElectrumPool, SendFee, SendFeeEstimates, TxOutInfo,
    SANITY_MAX_SAT_PER_VB,
};
pub use server_health::{server_health, HealthSnapshot, HealthState, ServerHealth};
pub use sync::{revealed_spks, sync_wallet, WalletEntry, WalletHandle, STOP_GAP};
pub use worker::{SyncWorker, FIRST_SYNC_WAIT};
