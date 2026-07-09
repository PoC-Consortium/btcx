//! The trusted chain registry — chains are data, not a hardcoded enum.
//!
//! A [`ChainDef`] is the shipped, trusted definition of one coin: its stable
//! string `id` (which drives RPC routing, the wire `asset` field, and the
//! BIP32 coin-type), its per-network [`ChainParams`], and its capability
//! flags.
//!
//! Two coins (BTCX, BTC) ship in-code and trusted as the always-present
//! built-ins. A `coins.toml` next to the executables can add **more** coins
//! purely as data (see [`coins_file`](crate::coins_file)): the daemon calls
//! [`init_from_path`] at startup, which leaks the parsed defs into `'static`
//! and merges them with the built-ins. A file coin whose id collides with a
//! built-in is rejected, so the file can never redirect `btc`/`btcx`.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::path::Path;
use std::sync::OnceLock;

use crate::coins_file::{self, BuiltCoin, BuiltParams};
use crate::params::{
    ChainParams, Network, BTCX_MAINNET, BTCX_REGTEST, BTCX_TESTNET, BTC_MAINNET, BTC_REGTEST,
    BTC_TESTNET,
};
use keys_btcx::{COIN_BTC, COIN_BTCX};

/// Consensus features a chain supports, consumed by the pair resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// OP_CHECKLOCKTIMEVERIFY (BIP65) — the classic HTLC refund branch.
    pub cltv: bool,
    /// SegWit v0 (P2WSH) — the HTLC output type in pact-htlc-v1.
    pub segwit_v0: bool,
    /// Taproot (BIP341) — required by the v2 adaptor/MuSig2 path.
    pub taproot: bool,
}

/// A shipped, trusted chain definition (≈ the `params` consts, but as
/// data the engine and UI can enumerate).
pub struct ChainDef {
    /// Stable string id: drives RPC routing, the wire `asset` field, and the
    /// BIP32 coin-type. Lowercase.
    pub id: &'static str,
    pub display_name: &'static str,
    pub symbol: &'static str,
    pub decimals: u8,
    /// BIP32 coin-type for `coin(c)` (spec §4.1); SLIP-44 where it exists.
    pub bip32_coin_type: u32,
    /// Coin-level target block spacing (mirrors each network's `ChainParams`).
    pub target_spacing_secs: u32,
    pub capabilities: Capabilities,
    // Per-network params. `None` means the coin is not defined on that network
    // (a file coin may ship e.g. regtest only). Built-ins define all three.
    mainnet: Option<&'static ChainParams>,
    testnet: Option<&'static ChainParams>,
    regtest: Option<&'static ChainParams>,
}

impl ChainDef {
    /// Resolved per-network params for this coin, if it is defined on `network`.
    pub fn params(&self, network: Network) -> Option<&'static ChainParams> {
        match network {
            Network::Mainnet => self.mainnet,
            Network::Testnet => self.testnet,
            Network::Regtest => self.regtest,
        }
    }
}

pub const BTCX: ChainDef = ChainDef {
    id: "btcx",
    display_name: "Bitcoin PoCX",
    symbol: "BTCX",
    decimals: 8,
    bip32_coin_type: COIN_BTCX,
    target_spacing_secs: 120,
    // Bitcoin PoCX activated Taproot at genesis (ALWAYS_ACTIVE); CLTV +
    // segwit v0 are standard.
    capabilities: Capabilities {
        cltv: true,
        segwit_v0: true,
        taproot: true,
    },
    mainnet: Some(&BTCX_MAINNET),
    testnet: Some(&BTCX_TESTNET),
    regtest: Some(&BTCX_REGTEST),
};

pub const BTC: ChainDef = ChainDef {
    id: "btc",
    display_name: "Bitcoin",
    symbol: "BTC",
    decimals: 8,
    bip32_coin_type: COIN_BTC,
    target_spacing_secs: 600,
    capabilities: Capabilities {
        cltv: true,
        segwit_v0: true,
        taproot: true,
    },
    mainnet: Some(&BTC_MAINNET),
    testnet: Some(&BTC_TESTNET),
    regtest: Some(&BTC_REGTEST),
};

/// The always-present, trusted built-in coins. Order is display order.
fn builtins() -> Vec<&'static ChainDef> {
    vec![&BTCX, &BTC]
}

/// The active registry: built-ins plus any coins loaded from `coins.toml`.
/// Lazily initialized to the built-ins if [`init_from_path`]/[`init_from_str`]
/// was never called (CLIs, harnesses, and library tests run this way).
static REGISTRY: OnceLock<Vec<&'static ChainDef>> = OnceLock::new();

/// All registered coins (built-ins + file coins), in display order.
pub fn all() -> &'static [&'static ChainDef] {
    REGISTRY.get_or_init(builtins).as_slice()
}

/// Leak an owned [`BuiltParams`] into a `'static` [`ChainParams`]. Called once
/// per file coin/network at startup; the leak is intentional (registry lives
/// for the whole process).
fn leak_params(p: BuiltParams) -> &'static ChainParams {
    Box::leak(Box::new(ChainParams {
        coin_id: Box::leak(p.coin_id.into_boxed_str()),
        network: p.network,
        header_format: p.header_format,
        magic: p.magic,
        default_p2p_port: p.default_p2p_port,
        p2pkh_prefix: p.p2pkh_prefix,
        p2sh_prefix: p.p2sh_prefix,
        wif_prefix: p.wif_prefix,
        bech32_hrp: Box::leak(p.bech32_hrp.into_boxed_str()),
        genesis_hash: Box::leak(p.genesis_hash.into_boxed_str()),
        target_spacing_secs: p.target_spacing_secs,
        min_feerate_sat_vb: p.min_feerate_sat_vb,
    }))
}

/// Leak an owned [`BuiltCoin`] into a `'static` [`ChainDef`].
fn leak_def(c: BuiltCoin) -> &'static ChainDef {
    Box::leak(Box::new(ChainDef {
        id: Box::leak(c.id.into_boxed_str()),
        display_name: Box::leak(c.display_name.into_boxed_str()),
        symbol: Box::leak(c.symbol.into_boxed_str()),
        decimals: c.decimals,
        bip32_coin_type: c.bip32_coin_type,
        target_spacing_secs: c.target_spacing_secs,
        capabilities: c.capabilities,
        mainnet: c.mainnet.map(leak_params),
        testnet: c.testnet.map(leak_params),
        regtest: c.regtest.map(leak_params),
    }))
}

/// Parse + validate + leak a `coins.toml` document into `'static` defs (no
/// global state touched — used directly by tests).
pub fn build_defs_from_str(toml_str: &str) -> Result<Vec<&'static ChainDef>> {
    Ok(coins_file::parse_and_validate(toml_str)?
        .into_iter()
        .map(leak_def)
        .collect())
}

/// Built-ins + `extra`, where a built-in id always wins (file coins that
/// collide with `btc`/`btcx` are dropped and reported). Order: built-ins first,
/// then added coins in file order.
fn merge(extra: Vec<&'static ChainDef>) -> (Vec<&'static ChainDef>, Vec<String>) {
    let mut coins = builtins();
    let mut dropped = Vec::new();
    for e in extra {
        if coins.iter().any(|c| c.id == e.id) {
            dropped.push(e.id.to_string());
        } else {
            coins.push(e);
        }
    }
    (coins, dropped)
}

/// Initialize the registry from a `coins.toml` string. Built-ins stay
/// authoritative. Returns the ids of file coins dropped for colliding with a
/// built-in (so the caller can warn). Errors if the registry was already
/// initialized (call once, at startup, before any [`get`]/[`all`]).
pub fn init_from_str(toml_str: &str) -> Result<Vec<String>> {
    let (coins, dropped) = merge(build_defs_from_str(toml_str)?);
    REGISTRY
        .set(coins)
        .map_err(|_| anyhow!("chain registry already initialized"))?;
    Ok(dropped)
}

/// Initialize the registry from a `coins.toml` file path. See [`init_from_str`].
pub fn init_from_path(path: &Path) -> Result<Vec<String>> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("reading coins file {}", path.display()))?;
    init_from_str(&s)
}

/// The [`ChainDef`] for a coin id, if registered.
pub fn get(coin_id: &str) -> Option<&'static ChainDef> {
    all().iter().copied().find(|c| c.id == coin_id)
}

/// Resolved per-network [`ChainParams`] for `(coin_id, network)`. `None` if the
/// coin is unknown or not defined on that network.
pub fn lookup(coin_id: &str, network: Network) -> Option<&'static ChainParams> {
    get(coin_id).and_then(|c| c.params(network))
}

/// BIP32 coin-type for `coin_id` (spec §4.1 `coin(c)`).
pub fn bip32_coin_type(coin_id: &str) -> Result<u32> {
    get(coin_id)
        .map(|c| c.bip32_coin_type)
        .with_context(|| format!("unknown coin {coin_id:?} (not in the shipped registry)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lookup() {
        assert_eq!(get("btcx").unwrap().id, "btcx");
        assert_eq!(get("btc").unwrap().symbol, "BTC");
        assert_eq!(get("btcx").unwrap().display_name, "Bitcoin PoCX");
        assert_eq!(get("btcx").unwrap().symbol, "BTCX");
        assert!(get("doge").is_none());
        assert!(get("BTCX").is_none(), "ids are case-sensitive, lowercase");

        // Per-network params resolve through the registry.
        assert_eq!(
            lookup("btcx", Network::Regtest).unwrap().genesis_hash,
            BTCX_REGTEST.genesis_hash
        );
        assert_eq!(
            lookup("btc", Network::Mainnet).unwrap().bech32_hrp,
            BTC_MAINNET.bech32_hrp
        );
        assert!(lookup("doge", Network::Regtest).is_none());

        // BIP32 coin-types match the keys-crate constants (spec §4.1).
        assert_eq!(bip32_coin_type("btcx").unwrap(), COIN_BTCX);
        assert_eq!(bip32_coin_type("btc").unwrap(), COIN_BTC);
        assert!(bip32_coin_type("doge").is_err());

        // With no coins.toml loaded, the registry is exactly the two built-ins.
        let ids: Vec<_> = all().iter().map(|c| c.id).collect();
        assert_eq!(ids, vec!["btcx", "btc"]);
    }

    const DOGE_TOML: &str = r#"
[[coin]]
coin_id = "doge"
display_name = "Dogecoin"
symbol = "DOGE"
decimals = 8
bip32_coin_type = 3
target_spacing_secs = 60
capabilities = { cltv = true, segwit_v0 = true, taproot = false }
  [coin.regtest]
  consensus = { header_format = "bitcoin", magic = "fabfb5da", default_p2p_port = 18444, p2pkh_prefix = 111, p2sh_prefix = 196, wif_prefix = 239, bech32_hrp = "dcrt", genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" }
"#;

    // Exercises the parse → leak → merge path without touching the process-wide
    // OnceLock (so it can't contaminate other tests that read `all()`).
    #[test]
    fn file_coin_merges_and_resolves() {
        let defs = build_defs_from_str(DOGE_TOML).unwrap();
        let (merged, dropped) = merge(defs);
        assert!(dropped.is_empty());
        let ids: Vec<_> = merged.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec!["btcx", "btc", "doge"]);

        let doge = merged.iter().copied().find(|c| c.id == "doge").unwrap();
        assert_eq!(doge.bip32_coin_type, 3);
        assert!(!doge.capabilities.taproot);
        // regtest-only: mainnet/testnet absent, regtest resolves.
        assert!(doge.params(Network::Mainnet).is_none());
        let rt = doge.params(Network::Regtest).unwrap();
        assert_eq!(rt.bech32_hrp, "dcrt");
        assert_eq!(rt.coin_id, "doge");
    }

    // A file coin that reuses a built-in id is dropped — the file can never
    // redirect btc/btcx to different consensus params.
    #[test]
    fn builtin_id_collision_is_dropped() {
        let evil = DOGE_TOML
            .replace("coin_id = \"doge\"", "coin_id = \"btc\"")
            .replace("bech32_hrp = \"dcrt\"", "bech32_hrp = \"evil\"");
        let defs = build_defs_from_str(&evil).unwrap();
        let (merged, dropped) = merge(defs);
        assert_eq!(dropped, vec!["btc".to_string()]);
        // The surviving `btc` is still the trusted built-in.
        let btc = merged.iter().copied().find(|c| c.id == "btc").unwrap();
        assert_eq!(btc.params(Network::Mainnet).unwrap().bech32_hrp, "bc");
    }

    #[test]
    fn capability_flags() {
        // Both shipped coins are full UTXO chains with Taproot.
        for coin in [&BTCX, &BTC] {
            let c = coin.capabilities;
            assert!(c.cltv && c.segwit_v0 && c.taproot, "{} caps", coin.id);
        }
    }
}
