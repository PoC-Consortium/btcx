//! Coin templates as data — load extra coins from a TOML file at startup.
//!
//! The [`registry`](crate::registry) ships two trusted coins in code
//! (`btcx`, `btc`). A `coins.toml` next to the executables can add **more**
//! coins purely as data, so a new Bitcoin-Core-compatible chain is usable
//! with no recompile. This module owns the file *schema* and parsing/validation
//! into owned [`BuiltCoin`]s; `registry` does the `'static` leak and the merge.
//!
//! Only the **consensus** fields are read here (what a consumer needs to verify
//! genesis, build/parse addresses, and derive keys). Each per-network table may
//! also carry a `connection` sub-table (RPC host/port/auth/datadir defaults) —
//! that is Satchel's concern and is ignored here (serde drops unknown keys).
//!
//! Trust model: consensus values are trusted-by-whoever-edits-the-file. A
//! consumer still validates each coin's genesis against the live node before
//! any funds move, and a coin id that collides with a built-in is **rejected**
//! so a stray file cannot redirect `btc`/`btcx`.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;

use crate::params::{HeaderFormat, Network};
use crate::registry::Capabilities;

/// The top-level `coins.toml` document.
#[derive(Debug, Deserialize)]
pub struct CoinFile {
    /// Schema version for forward-compat (currently 1). Optional.
    #[serde(default)]
    pub schema_version: u32,
    /// `[[coin]]` array.
    #[serde(default, rename = "coin")]
    pub coins: Vec<CoinEntry>,
}

/// One `[[coin]]` entry.
#[derive(Debug, Deserialize)]
pub struct CoinEntry {
    pub coin_id: String,
    pub display_name: String,
    pub symbol: String,
    pub decimals: u8,
    pub bip32_coin_type: u32,
    pub target_spacing_secs: u32,
    /// Icon file (relative to the coins file) — read by Satchel, ignored here.
    #[serde(default)]
    pub icon: Option<String>,
    pub capabilities: CapsEntry,
    #[serde(default)]
    pub mainnet: Option<NetEntry>,
    #[serde(default)]
    pub testnet: Option<NetEntry>,
    #[serde(default)]
    pub regtest: Option<NetEntry>,
}

#[derive(Debug, Deserialize)]
pub struct CapsEntry {
    pub cltv: bool,
    pub segwit_v0: bool,
    pub taproot: bool,
}

/// One `[coin.<network>]` table. The `connection` sub-table (Satchel's RPC
/// defaults) is intentionally absent here — serde ignores it.
#[derive(Debug, Deserialize)]
pub struct NetEntry {
    /// Minimum feerate (sat/vB) this coin's node accepts for a wallet spend on
    /// this network. Litecoin's wallet `-mintxfee` is ~10 and is exposed by no
    /// RPC, so a spend below it is rejected (-6 "lower than the minimum fee rate
    /// setting"). Optional, per-network; defaults to 1 (Bitcoin's floor).
    #[serde(default)]
    pub min_feerate_sat_vb: Option<u64>,
    pub consensus: ConsensusEntry,
}

/// `[coin.<network>.consensus]` — the consumer-relevant chain params.
#[derive(Debug, Deserialize)]
pub struct ConsensusEntry {
    /// The two fields a Core-RPC coin actually needs at runtime: the chain's
    /// genesis hash (verified against the node, `getblockhash 0`) and its bech32
    /// HRP (output addresses). Everything else below is optional.
    /// Genesis block hash, 32-byte hex in display (big-endian) order.
    pub genesis_hash: String,
    pub bech32_hrp: String,

    /// `"bitcoin"` (80-byte header) | `"pocx"` (286-byte header). **Optional** —
    /// only consulted when a coin is reached over an Electrum/light backend;
    /// a Core-RPC coin ignores it. Defaults to `"bitcoin"`. An exotic header
    /// (e.g. AuxPoW) needs a code change.
    #[serde(default)]
    pub header_format: Option<String>,
    /// P2P network magic as 4-byte hex, e.g. `"f9beb4d9"`. Optional/unused at
    /// runtime today (kept for future P2P/light use).
    #[serde(default)]
    pub magic: String,
    #[serde(default)]
    pub default_p2p_port: u16,
    #[serde(default)]
    pub p2pkh_prefix: u8,
    #[serde(default)]
    pub p2sh_prefix: u8,
    #[serde(default)]
    pub wif_prefix: u8,
}

/// A validated, owned coin definition. `registry` leaks these into `'static`
/// [`ChainDef`](crate::registry::ChainDef)s.
#[derive(Debug, Clone)]
pub struct BuiltCoin {
    pub id: String,
    pub display_name: String,
    pub symbol: String,
    pub decimals: u8,
    pub bip32_coin_type: u32,
    pub target_spacing_secs: u32,
    pub capabilities: Capabilities,
    pub mainnet: Option<BuiltParams>,
    pub testnet: Option<BuiltParams>,
    pub regtest: Option<BuiltParams>,
}

/// Validated, owned per-(coin, network) params (mirror of
/// [`ChainParams`](crate::params::ChainParams) with owned strings).
#[derive(Debug, Clone)]
pub struct BuiltParams {
    pub coin_id: String,
    pub network: Network,
    pub header_format: HeaderFormat,
    pub magic: [u8; 4],
    pub default_p2p_port: u16,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub wif_prefix: u8,
    pub bech32_hrp: String,
    pub genesis_hash: String,
    pub target_spacing_secs: u32,
    pub min_feerate_sat_vb: u64,
}

/// Parse + validate a `coins.toml` document into owned [`BuiltCoin`]s.
/// Validates: lowercase coin id, no in-file duplicates, ≥1 network defined,
/// known header format, 4-byte magic, 32-byte genesis hash, parseable HRP.
pub fn parse_and_validate(toml_str: &str) -> Result<Vec<BuiltCoin>> {
    let file: CoinFile = toml::from_str(toml_str).context("parsing coins.toml")?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in &file.coins {
        let id = c.coin_id.to_ascii_lowercase();
        ensure!(!id.is_empty(), "coin_id must not be empty");
        ensure!(
            id.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()),
            "coin_id {id:?} must be lowercase ascii letters/digits"
        );
        ensure!(
            seen.insert(id.clone()),
            "duplicate coin_id {id:?} in coins file"
        );
        let capabilities = Capabilities {
            cltv: c.capabilities.cltv,
            segwit_v0: c.capabilities.segwit_v0,
            taproot: c.capabilities.taproot,
        };
        let mainnet = build_params(
            &id,
            Network::Mainnet,
            c.mainnet.as_ref(),
            c.target_spacing_secs,
        )?;
        let testnet = build_params(
            &id,
            Network::Testnet,
            c.testnet.as_ref(),
            c.target_spacing_secs,
        )?;
        let regtest = build_params(
            &id,
            Network::Regtest,
            c.regtest.as_ref(),
            c.target_spacing_secs,
        )?;
        ensure!(
            mainnet.is_some() || testnet.is_some() || regtest.is_some(),
            "coin {id:?} defines no networks (need at least one of [coin.mainnet|testnet|regtest])"
        );
        out.push(BuiltCoin {
            id,
            display_name: c.display_name.clone(),
            symbol: c.symbol.clone(),
            decimals: c.decimals,
            bip32_coin_type: c.bip32_coin_type,
            target_spacing_secs: c.target_spacing_secs,
            capabilities,
            mainnet,
            testnet,
            regtest,
        });
    }
    Ok(out)
}

fn build_params(
    coin_id: &str,
    network: Network,
    entry: Option<&NetEntry>,
    target_spacing_secs: u32,
) -> Result<Option<BuiltParams>> {
    let Some(entry) = entry else { return Ok(None) };
    // Per-network fee floor; absent → Bitcoin's 1 sat/vB.
    let min_feerate_sat_vb = entry.min_feerate_sat_vb.unwrap_or(1).max(1);
    let c = &entry.consensus;
    // header_format is optional (Core-RPC coins never use it); default Bitcoin.
    let header_format = match &c.header_format {
        Some(s) => {
            HeaderFormat::from_token(s).with_context(|| format!("coin {coin_id:?} {network:?}"))?
        }
        None => HeaderFormat::Bitcoin,
    };

    // magic is optional/unused at runtime today; absent → zeroed.
    let magic: [u8; 4] = if c.magic.trim().is_empty() {
        [0; 4]
    } else {
        let bytes = hex::decode(c.magic.trim())
            .with_context(|| format!("coin {coin_id:?} {network:?}: magic must be hex"))?;
        ensure!(
            bytes.len() == 4,
            "coin {coin_id:?} {network:?}: magic must be 4 bytes (8 hex chars), got {}",
            bytes.len()
        );
        bytes.try_into().expect("length checked")
    };

    let genesis_hash = c.genesis_hash.trim().to_ascii_lowercase();
    ensure!(
        genesis_hash.len() == 64 && hex::decode(&genesis_hash).is_ok(),
        "coin {coin_id:?} {network:?}: genesis_hash must be 32-byte hex (64 chars)"
    );

    let hrp = c.bech32_hrp.trim().to_string();
    bech32::Hrp::parse(&hrp)
        .with_context(|| format!("coin {coin_id:?} {network:?}: invalid bech32_hrp {hrp:?}"))?;

    Ok(Some(BuiltParams {
        coin_id: coin_id.to_string(),
        network,
        header_format,
        magic,
        default_p2p_port: c.default_p2p_port,
        p2pkh_prefix: c.p2pkh_prefix,
        p2sh_prefix: c.p2sh_prefix,
        wif_prefix: c.wif_prefix,
        bech32_hrp: hrp,
        genesis_hash,
        target_spacing_secs,
        min_feerate_sat_vb,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOGE: &str = r#"
schema_version = 1
[[coin]]
coin_id = "doge"
display_name = "Dogecoin"
symbol = "DOGE"
decimals = 8
bip32_coin_type = 3
target_spacing_secs = 60
icon = "doge.svg"
capabilities = { cltv = true, segwit_v0 = true, taproot = false }
  [coin.regtest]
  consensus = { header_format = "bitcoin", magic = "fabfb5da", default_p2p_port = 18444, p2pkh_prefix = 111, p2sh_prefix = 196, wif_prefix = 239, bech32_hrp = "dcrt", genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" }
"#;

    #[test]
    fn parses_a_new_coin() {
        let coins = parse_and_validate(DOGE).unwrap();
        assert_eq!(coins.len(), 1);
        let c = &coins[0];
        assert_eq!(c.id, "doge");
        assert_eq!(c.bip32_coin_type, 3);
        assert!(!c.capabilities.taproot);
        assert!(c.mainnet.is_none() && c.testnet.is_none());
        let rt = c.regtest.as_ref().unwrap();
        assert_eq!(rt.magic, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(rt.header_format, HeaderFormat::Bitcoin);
        assert_eq!(rt.bech32_hrp, "dcrt");
    }

    // A Core-RPC coin needs only genesis_hash + bech32_hrp; header_format,
    // magic and the legacy prefixes are optional (unused without Electrum).
    #[test]
    fn minimal_consensus_parses() {
        let toml = r#"
[[coin]]
coin_id = "min"
display_name = "Minimal"
symbol = "MIN"
decimals = 8
bip32_coin_type = 9
target_spacing_secs = 600
capabilities = { cltv = true, segwit_v0 = true, taproot = false }
  [coin.regtest]
  consensus = { genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", bech32_hrp = "mcrt" }
"#;
        let coins = parse_and_validate(toml).unwrap();
        let rt = coins[0].regtest.as_ref().unwrap();
        assert_eq!(rt.header_format, HeaderFormat::Bitcoin); // defaulted
        assert_eq!(rt.magic, [0, 0, 0, 0]); // unused, zeroed
        assert_eq!(rt.bech32_hrp, "mcrt");
    }

    #[test]
    fn rejects_bad_inputs() {
        let bad_header = DOGE.replace("header_format = \"bitcoin\"", "header_format = \"scrypt\"");
        assert!(parse_and_validate(&bad_header).is_err());

        let bad_magic = DOGE.replace("magic = \"fabfb5da\"", "magic = \"fabf\"");
        assert!(parse_and_validate(&bad_magic).is_err());

        let bad_genesis = DOGE.replace(
            "genesis_hash = \"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206\"",
            "genesis_hash = \"deadbeef\"",
        );
        assert!(parse_and_validate(&bad_genesis).is_err());

        let dup = format!("{DOGE}{DOGE}");
        assert!(parse_and_validate(&dup).is_err(), "duplicate ids rejected");

        let no_net = "[[coin]]\ncoin_id=\"x\"\ndisplay_name=\"X\"\nsymbol=\"X\"\ndecimals=8\nbip32_coin_type=1\ntarget_spacing_secs=60\ncapabilities={cltv=true,segwit_v0=true,taproot=false}\n";
        assert!(parse_and_validate(no_net).is_err(), "no networks rejected");
    }
}
