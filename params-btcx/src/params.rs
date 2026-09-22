//! Chain and network parameters.
//!
//! Bitcoin PoCX values were read from `bitcoin-pocx/bitcoin/src/kernel/chainparams.cpp`
//! (the `ENABLE_POCX` build) — spec §3. Do not edit without re-checking the
//! source of truth.
//!
//! Note: BTCX **regtest** shares Bitcoin regtest's network magic
//! (`fa bf b5 da`) and default port (18444); test setups must assign
//! explicit distinct ports.

use anyhow::{Context, Result};
use bech32::Hrp;
use bitcoin::hashes::Hash;
use bitcoin::witness_program::WitnessProgram;
use bitcoin::witness_version::WitnessVersion;
use bitcoin::{PubkeyHash, ScriptBuf, ScriptHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

/// How a chain's block header is laid out and hashed. Coins are otherwise
/// Bitcoin-shaped; Bitcoin PoCX differs only here (its PoC consensus fields
/// plus a generator signature that is excluded from the block hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFormat {
    /// 80-byte Bitcoin header, hashed whole.
    Bitcoin,
    /// 286-byte Bitcoin PoCX header; the trailing 65-byte signature is zeroed
    /// before hashing (`CBlockHeader::GetHash`, ENABLE_POCX).
    Pocx,
}

impl HeaderFormat {
    /// Parse the `header_format` token from a coin template (`coins.toml`).
    /// Only the two layouts this crate knows how to hash are accepted; an
    /// exotic header (e.g. AuxPoW merged-mining) needs a new variant + code.
    pub fn from_token(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "bitcoin" => Ok(Self::Bitcoin),
            "pocx" => Ok(Self::Pocx),
            other => {
                anyhow::bail!("unknown header_format {other:?} (expected \"bitcoin\" or \"pocx\")")
            }
        }
    }
}

/// Static parameters of one (coin, network) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    /// Stable coin id ("btcx", "btc") — keys this into the registry.
    pub coin_id: &'static str,
    pub network: Network,
    /// Header layout/hashing for this coin.
    pub header_format: HeaderFormat,
    pub magic: [u8; 4],
    pub default_p2p_port: u16,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub wif_prefix: u8,
    pub bech32_hrp: &'static str,
    /// Block hash of the genesis block, big-endian display order.
    pub genesis_hash: &'static str,
    /// Target block spacing in seconds.
    pub target_spacing_secs: u32,
    /// Minimum feerate in sat/kvB (100 = 0.1 sat/vB) this coin's node will
    /// accept for a wallet spend. Core v30+ defaults to a 0.1 sat/vB relay
    /// minimum, but some chains bake in a higher wallet `-mintxfee`
    /// (Litecoin's is ~10 sat/vB = 10_000) that no RPC exposes, so a spend
    /// below it is rejected outright (-6 "lower than the minimum fee rate
    /// setting"). Floors the caller's fee-rate selection. From coins.toml
    /// (`min_feerate_sat_vb`, human sat/vB, fractions allowed); 100 for the
    /// built-ins. Integer sat/kvB is the internal feerate unit everywhere —
    /// f64 only exists at human-facing edges.
    pub min_feerate_sat_kvb: u64,
}

pub const BTCX_MAINNET: ChainParams = ChainParams {
    coin_id: "btcx",
    network: Network::Mainnet,
    header_format: HeaderFormat::Pocx,
    magic: [0xa7, 0x3c, 0x91, 0x5e],
    default_p2p_port: 8338,
    p2pkh_prefix: 0x55,
    p2sh_prefix: 0x5a,
    wif_prefix: 0x80,
    bech32_hrp: "pocx",
    genesis_hash: "6ab422073e327d42a0e5dfaaa26564324ddb225e53c64da89283cd4e3dfb7ac6",
    target_spacing_secs: 120,
    min_feerate_sat_kvb: 100,
};

pub const BTCX_TESTNET: ChainParams = ChainParams {
    coin_id: "btcx",
    network: Network::Testnet,
    header_format: HeaderFormat::Pocx,
    magic: [0x6d, 0xf2, 0x48, 0xb4],
    default_p2p_port: 18338,
    p2pkh_prefix: 0x7f,
    p2sh_prefix: 0x84,
    wif_prefix: 0xef,
    bech32_hrp: "tpocx",
    genesis_hash: "181c51a172fe20c203e463f6f203b7d9be388fa0f1282e507192f94d24a57e81",
    target_spacing_secs: 120,
    min_feerate_sat_kvb: 100,
};

pub const BTCX_REGTEST: ChainParams = ChainParams {
    coin_id: "btcx",
    network: Network::Regtest,
    header_format: HeaderFormat::Pocx,
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    default_p2p_port: 18444,
    p2pkh_prefix: 0x6f,
    p2sh_prefix: 0xc4,
    wif_prefix: 0xef,
    bech32_hrp: "rpocx",
    genesis_hash: "2a98a52253aeff06093948b00568d380b7634621bc606403127973c9acbbfde0",
    target_spacing_secs: 120,
    min_feerate_sat_kvb: 100,
};

pub const BTC_MAINNET: ChainParams = ChainParams {
    coin_id: "btc",
    network: Network::Mainnet,
    header_format: HeaderFormat::Bitcoin,
    magic: [0xf9, 0xbe, 0xb4, 0xd9],
    default_p2p_port: 8333,
    p2pkh_prefix: 0x00,
    p2sh_prefix: 0x05,
    wif_prefix: 0x80,
    bech32_hrp: "bc",
    genesis_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    target_spacing_secs: 600,
    min_feerate_sat_kvb: 100,
};

pub const BTC_TESTNET: ChainParams = ChainParams {
    coin_id: "btc",
    network: Network::Testnet,
    header_format: HeaderFormat::Bitcoin,
    magic: [0x0b, 0x11, 0x09, 0x07],
    default_p2p_port: 18333,
    p2pkh_prefix: 0x6f,
    p2sh_prefix: 0xc4,
    wif_prefix: 0xef,
    bech32_hrp: "tb",
    genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
    target_spacing_secs: 600,
    min_feerate_sat_kvb: 100,
};

pub const BTC_REGTEST: ChainParams = ChainParams {
    coin_id: "btc",
    network: Network::Regtest,
    header_format: HeaderFormat::Bitcoin,
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    default_p2p_port: 18444,
    p2pkh_prefix: 0x6f,
    p2sh_prefix: 0xc4,
    wif_prefix: 0xef,
    bech32_hrp: "bcrt",
    genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    target_spacing_secs: 600,
    min_feerate_sat_kvb: 100,
};

impl ChainParams {
    /// bech32 (witness v0) address for a segwit script pubkey program.
    ///
    /// The `bitcoin` crate's `Address` type only knows the bc/tb/bcrt HRPs,
    /// so BTCX addresses are encoded with the `bech32` crate directly.
    pub fn p2wsh_address(&self, witness_script: &ScriptBuf) -> anyhow::Result<String> {
        let program = witness_script.wscript_hash();
        let hrp = Hrp::parse(self.bech32_hrp)?;
        Ok(bech32::segwit::encode_v0(hrp, program.as_ref())?)
    }

    /// bech32m (witness v1 / Taproot) address for an x-only output key.
    /// Encoded directly via `bech32` for the same custom-HRP reason as
    /// [`Self::p2wsh_address`].
    pub fn p2tr_address(&self, output_key: &bitcoin::XOnlyPublicKey) -> anyhow::Result<String> {
        let hrp = Hrp::parse(self.bech32_hrp)?;
        Ok(bech32::segwit::encode_v1(hrp, &output_key.serialize())?)
    }

    /// Serialized block-header length for this chain. Bitcoin PoCX headers
    /// carry the PoC consensus fields plus the generator pubkey and signature
    /// (`primitives/block.h`, ENABLE_POCX): 4 version + 32 prev +
    /// 32 merkle + 4 time + 4 height + 32 gensig + 8 basetarget +
    /// 72 proof + 33 pubkey + 65 signature = 286 bytes.
    pub fn header_len(&self) -> usize {
        match self.header_format {
            HeaderFormat::Pocx => 286,
            HeaderFormat::Bitcoin => 80,
        }
    }

    /// Block hash (display-order hex) of a raw serialized header. Bitcoin
    /// PoCX hashes the header with the 65-byte signature zeroed
    /// (`CBlockHeader::GetHash`); Bitcoin hashes all 80 bytes.
    pub fn header_hash(&self, raw: &[u8]) -> Result<String> {
        use bitcoin::hashes::{sha256d, Hash};
        anyhow::ensure!(
            raw.len() == self.header_len(),
            "raw header is {} bytes, expected {} for {:?}",
            raw.len(),
            self.header_len(),
            self.coin_id
        );
        let digest = match self.header_format {
            HeaderFormat::Bitcoin => sha256d::Hash::hash(raw),
            HeaderFormat::Pocx => {
                let mut unsigned = raw.to_vec();
                let sig_start = unsigned.len() - 65;
                unsigned[sig_start..].fill(0);
                sha256d::Hash::hash(&unsigned)
            }
        };
        let mut bytes = digest.to_byte_array();
        bytes.reverse();
        Ok(hex::encode(bytes))
    }

    /// `nTime` of a raw serialized header — same offset (68) on both
    /// chains: version(4) + prev(32) + merkle(32).
    pub fn header_time(&self, raw: &[u8]) -> Result<u32> {
        anyhow::ensure!(
            raw.len() == self.header_len(),
            "raw header is {} bytes, expected {} for {:?}",
            raw.len(),
            self.header_len(),
            self.coin_id
        );
        Ok(u32::from_le_bytes(
            raw[68..72].try_into().expect("length checked"),
        ))
    }

    /// Parse an address under this chain into a scriptPubKey.
    ///
    /// Accepts bech32/bech32m segwit (v0/v1) under this chain's HRP, plus
    /// base58check legacy **P2PKH** and **P2SH** under this chain's version
    /// bytes. Our own handout and sweep addresses are always bech32(m), but a
    /// send destination is whatever the counterparty hands us — exchanges and
    /// older wallets still give out `1...` / `3...` (BTC mainnet) deposit
    /// addresses, and paying them needs nothing beyond the output script.
    ///
    /// A well-formed bech32 string under a foreign HRP is a chain mismatch,
    /// not a legacy address, and is reported as such; only strings that are
    /// not bech32 at all fall through to the base58 path.
    pub fn parse_address(&self, address: &str) -> Result<ScriptBuf> {
        let (hrp, version, program) = match bech32::segwit::decode(address) {
            Ok(decoded) => decoded,
            Err(bech32_err) => {
                return self.parse_base58_address(address).map_err(|base58_err| {
                    anyhow::anyhow!(
                        "not a valid {} {:?} address: {address} \
                         (bech32: {bech32_err}; base58: {base58_err})",
                        self.coin_id,
                        self.network
                    )
                });
            }
        };
        anyhow::ensure!(
            hrp.to_lowercase() == self.bech32_hrp,
            "address HRP {hrp} does not match chain {} {:?} (expected {})",
            self.coin_id,
            self.network,
            self.bech32_hrp
        );
        let version =
            WitnessVersion::try_from(version.to_u8()).context("unsupported witness version")?;
        let witness_program = WitnessProgram::new(version, &program)?;
        Ok(ScriptBuf::new_witness_program(&witness_program))
    }

    /// Base58check legacy address → scriptPubKey: `version || hash160`
    /// (21 bytes), version byte matched against this chain's P2PKH / P2SH
    /// prefixes. A checksum failure, wrong length, or foreign version byte is
    /// an error — never a silent mis-parse onto another chain.
    fn parse_base58_address(&self, address: &str) -> Result<ScriptBuf> {
        let payload = bitcoin::base58::decode_check(address).context("not base58check")?;
        anyhow::ensure!(
            payload.len() == 21,
            "base58 payload is {} bytes, expected 21 (version + hash160)",
            payload.len()
        );
        let version = payload[0];
        let hash: [u8; 20] = payload[1..].try_into().expect("length checked");
        if version == self.p2pkh_prefix {
            Ok(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)))
        } else if version == self.p2sh_prefix {
            Ok(ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)))
        } else {
            anyhow::bail!(
                "address version byte 0x{version:02x} does not match chain {} {:?} \
                 (expected P2PKH 0x{:02x} or P2SH 0x{:02x})",
                self.coin_id,
                self.network,
                self.p2pkh_prefix,
                self.p2sh_prefix
            )
        }
    }
}

/// Parse "btcx:50.0" / "btc:0.001" into (coin_id, base units). The coin must
/// be in the shipped registry. Shared by CLIs and daemon APIs so all speak
/// the same amount grammar.
pub fn parse_coin_amount(input: &str) -> Result<(String, u64)> {
    let (coin, amount) = input
        .split_once(':')
        .with_context(|| format!("expected coin:amount, got {input:?}"))?;
    let coin_id = coin.to_ascii_lowercase();
    anyhow::ensure!(
        crate::registry::get(&coin_id).is_some(),
        "unknown coin {coin_id:?} (not in the shipped registry)"
    );
    let (whole, frac) = match amount.split_once('.') {
        Some((w, f)) => (w, f),
        None => (amount, ""),
    };
    anyhow::ensure!(!amount.is_empty(), "empty amount");
    anyhow::ensure!(frac.len() <= 8, "more than 8 decimal places in {amount:?}");
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().context("bad amount")?
    };
    let frac: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<8}").parse().context("bad amount")?
    };
    Ok((coin_id, whole * 100_000_000 + frac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_amount_parsing() {
        assert_eq!(
            parse_coin_amount("btcx:50.0").unwrap(),
            ("btcx".to_string(), 50_0000_0000)
        );
        assert_eq!(
            parse_coin_amount("btc:0.001").unwrap(),
            ("btc".to_string(), 10_0000)
        );
        assert_eq!(
            parse_coin_amount("btc:1").unwrap(),
            ("btc".to_string(), 1_0000_0000)
        );
        assert_eq!(
            parse_coin_amount("btcx:0.00000001").unwrap(),
            ("btcx".to_string(), 1)
        );
        // Case is normalized to the lowercase registry id.
        assert_eq!(
            parse_coin_amount("BTC:1").unwrap(),
            ("btc".to_string(), 1_0000_0000)
        );
        assert!(parse_coin_amount("doge:1").is_err());
        assert!(parse_coin_amount("btc:0.000000001").is_err());
        assert!(parse_coin_amount("btc").is_err());
        assert!(parse_coin_amount("btc:").is_err());
    }

    /// Raw genesis headers captured from the actual regtest nodes
    /// (`getblockheader <hash> false`).
    const BTCX_REGTEST_GENESIS_HDR: &str = "0100000000000000000000000000000000000000000000000000000000000000000000000be75d2dc2fe8764301873275063cf1a90dc8d1e2b0f5b824bcb5f3963f74ad5dae5494d00000000687c09c2b4c2392a47717f58c468698b998fef0eed2ec9c8f8736d42a1b8c26a88888888888808000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// A *signed* Bitcoin PoCX header (regtest block 1) — exercises the
    /// signature-zeroing in the hash, which the all-zero genesis cannot.
    const BTCX_REGTEST_BLOCK1_HDR: &str = "00000020e0fdbbacc9737912036460bc214663b780d36805b048390906ffae5322a5982adab218fc21ce6ede59560ba029473e4a8c79aa5dd129c7fd7ddc796728dc293011fa2b6a01000000a2f101e6f06c41def4c20fdb0735415fc2f5fee9bed0b76787c2823a10ace195888888888888080000000000000000000000000000000000000000000000000000000000000000001e50bcc17e3c6ab42d39a6a5d79b0d7a6983a765010000002d000000000000003df666390df1ad07034dadda25869b914d92b499fe7cd1face013db3d57fdaae2f97766b483e94753a1f1e405b88bb4425c7f5f01723b8d527cbb5b30160b72223683a408ef86702275843b2e2d999717e78e406a139c4da55752bee53746a94a42817264dbda7bab484";
    const BTCX_REGTEST_BLOCK1_HASH: &str =
        "93e81357d64a6060f60d9da3c16c07bc46f4a8ddf8c398155fb1a52daeeba1cd";
    const BTC_REGTEST_GENESIS_HDR: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000";

    #[test]
    fn header_hash_and_time() {
        let btcx_genesis = hex::decode(BTCX_REGTEST_GENESIS_HDR).unwrap();
        assert_eq!(
            BTCX_REGTEST.header_hash(&btcx_genesis).unwrap(),
            BTCX_REGTEST.genesis_hash
        );
        assert_eq!(BTCX_REGTEST.header_time(&btcx_genesis).unwrap(), 1296688602);

        let btcx_block1 = hex::decode(BTCX_REGTEST_BLOCK1_HDR).unwrap();
        assert_eq!(
            BTCX_REGTEST.header_hash(&btcx_block1).unwrap(),
            BTCX_REGTEST_BLOCK1_HASH
        );

        let btc_genesis = hex::decode(BTC_REGTEST_GENESIS_HDR).unwrap();
        assert_eq!(
            BTC_REGTEST.header_hash(&btc_genesis).unwrap(),
            BTC_REGTEST.genesis_hash
        );
        assert_eq!(BTC_REGTEST.header_time(&btc_genesis).unwrap(), 1296688602);

        // Wrong-length input must be rejected, not silently mis-hashed.
        assert!(BTCX_REGTEST.header_hash(&btc_genesis).is_err());
        assert!(BTC_REGTEST.header_hash(&btcx_genesis).is_err());
    }

    #[test]
    fn address_roundtrip() {
        // P2WSH of an arbitrary script encodes and parses back to the spk.
        let script = ScriptBuf::from(vec![0x51u8]); // OP_TRUE
        let addr = BTCX_REGTEST.p2wsh_address(&script).unwrap();
        assert!(addr.starts_with("rpocx1"));
        let spk = BTCX_REGTEST.parse_address(&addr).unwrap();
        assert_eq!(spk, ScriptBuf::new_p2wsh(&script.wscript_hash()));
        // Wrong-chain parse must fail.
        assert!(BTC_REGTEST.parse_address(&addr).is_err());
    }
    fn h160(hex_str: &str) -> [u8; 20] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }

    /// Legacy base58check destinations (exchange deposit addresses) parse to
    /// the P2PKH / P2SH script under the chain's own version bytes. Vectors
    /// were decoded independently (pure-Python base58check), not with this
    /// crate.
    #[test]
    fn base58_legacy_addresses_parse() {
        // BTC mainnet P2PKH (version 0x00).
        let spk = BTC_MAINNET
            .parse_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
            .unwrap();
        assert_eq!(
            spk,
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(h160(
                "77bff20c60e522dfaa3350c39b030a5d004e839a"
            )))
        );
        assert!(spk.is_p2pkh());

        // BTC mainnet P2SH (version 0x05) — the "3..." exchange case.
        let spk = BTC_MAINNET
            .parse_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
            .unwrap();
        assert_eq!(
            spk,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(h160(
                "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
            )))
        );
        assert!(spk.is_p2sh());

        // Testnet/regtest P2PKH (0x6f) and P2SH (0xc4).
        let spk = BTC_TESTNET
            .parse_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")
            .unwrap();
        assert_eq!(
            spk,
            ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(h160(
                "243f1394f44554f4ce3fd68649c19adc483ce924"
            )))
        );
        let spk = BTC_REGTEST
            .parse_address("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc")
            .unwrap();
        assert_eq!(
            spk,
            ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(h160(
                "4e9f39ca4688ff102128ea4ccda34105324305b0"
            )))
        );
    }

    /// Base58 addresses of another chain, corrupted checksums, and junk are
    /// all rejected with a version/checksum reason — never mis-parsed.
    #[test]
    fn base58_foreign_or_corrupt_addresses_rejected() {
        // Mainnet BTC address offered to testnet / BTCX: version byte mismatch.
        let err = BTC_TESTNET
            .parse_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
            .unwrap_err();
        assert!(err.to_string().contains("version byte 0x05"), "{err:#}");
        assert!(BTCX_MAINNET
            .parse_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
            .is_err());
        // Testnet address offered to mainnet.
        assert!(BTC_MAINNET
            .parse_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")
            .is_err());
        // One character flipped → checksum failure.
        assert!(BTC_MAINNET
            .parse_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz")
            .is_err());
        // Junk stays junk, and the message names both decoders.
        let err = BTC_MAINNET.parse_address("not-an-address").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bech32:") && msg.contains("base58:"), "{msg}");
        // A well-formed bech32 string under a foreign HRP is reported as an
        // HRP mismatch, not shunted into the base58 path.
        let addr = BTCX_REGTEST
            .p2wsh_address(&ScriptBuf::from(vec![0x51u8]))
            .unwrap();
        let err = BTC_REGTEST.parse_address(&addr).unwrap_err();
        assert!(err.to_string().contains("HRP"), "{err:#}");
    }
}
