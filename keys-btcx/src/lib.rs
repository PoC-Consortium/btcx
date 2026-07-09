//! Wallet key derivation from a BIP39 seed.
//!
//! [`WalletSeed`] wraps the BIP32 master key derived from one BIP39 mnemonic
//! (+ optional passphrase). The on-chain wallet branches are the standard
//! single-key purposes — BIP-84 (`m/84'/coin_type'/0'`, segwit v0 `wpkh`)
//! and BIP-86 (`m/86'/coin_type'/0'`, taproot `tr`), selected by
//! [`DescriptorKind`] — where `coin_type` is the per-asset constant
//! ([`COIN_BTC`], [`COIN_BTCX`]) — asset, not network (spec §4.1).
//! Standard paths keep the funds recoverable in any descriptor wallet.
//!
//! Protocol-specific trees (e.g. Pact's `m/7228'` purpose) are NOT defined
//! here — consumers build them on top via [`WalletSeed::master_xpriv`] /
//! [`WalletSeed::derive_hardened`].

use anyhow::Result;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::NetworkKind;

/// Asset constants for `coin(c)` — asset, not network (spec §4.1).
pub const COIN_BTC: u32 = 0;
/// `0x504F4358` = ASCII "POCX" (matches the node's `POCX` assignment marker).
pub const COIN_BTCX: u32 = 0x504F_4358;

/// Which standard single-key wallet descriptor family to derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorKind {
    /// BIP-84 `wpkh(...)` — segwit v0 P2WPKH. The BTCX mining ecosystem
    /// (a plot account_id is a 20-byte witness program) and Phoenix are
    /// segwit v0 only.
    Bip84,
    /// BIP-86 `tr(...)` — taproot key-spend. Existing live Satchel wallets
    /// and taproot swaps.
    Bip86,
}

impl DescriptorKind {
    /// The BIP-43 purpose level for this descriptor family.
    pub fn purpose(self) -> u32 {
        match self {
            DescriptorKind::Bip84 => 84,
            DescriptorKind::Bip86 => 86,
        }
    }
}

/// A BIP39-derived wallet seed: the BIP32 master key plus a secp context.
pub struct WalletSeed {
    master: Xpriv,
    secp: Secp256k1<All>,
}

impl WalletSeed {
    /// From a BIP39 mnemonic phrase (+ optional passphrase).
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self> {
        let mnemonic = bip39::Mnemonic::parse_normalized(phrase)?;
        Self::from_seed(&mnemonic.to_seed_normalized(passphrase))
    }

    /// From raw BIP39 seed bytes. The BIP32 network kind only affects
    /// xprv/xpub serialization, never derived keys; Main is used throughout.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self {
            master: Xpriv::new_master(NetworkKind::Main, seed)?,
            secp: Secp256k1::new(),
        })
    }

    /// The BIP32 master xprv — for consumers that derive their own
    /// (non-BIP-84/86) branches on top of the same seed.
    pub fn master_xpriv(&self) -> &Xpriv {
        &self.master
    }

    /// The secp256k1 context this seed derives with.
    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    /// Private key at an all-hardened path below the master (each `path`
    /// element is a hardened index).
    pub fn derive_hardened(&self, path: &[u32]) -> Result<SecretKey> {
        let path: Vec<ChildNumber> = path
            .iter()
            .map(|&i| ChildNumber::from_hardened_idx(i).map_err(Into::into))
            .collect::<Result<_>>()?;
        Ok(self.master.derive_priv(&self.secp, &path)?.private_key)
    }

    /// Account xprv of the on-chain wallet at `m/purpose'/coin_type'/0'` —
    /// the standard BIP-84/BIP-86 branch of the seed. Standard paths keep
    /// the funds recoverable in any descriptor wallet. `coin_type` is the
    /// registry's `bip32_coin_type` (spec §4.1), NOT the SLIP-44 network
    /// constant of whatever network the coin happens to run.
    pub fn wallet_account_xpriv(&self, kind: DescriptorKind, coin_type: u32) -> Result<Xpriv> {
        let path: Vec<ChildNumber> = [kind.purpose(), coin_type, 0]
            .iter()
            .map(|&i| ChildNumber::from_hardened_idx(i).map_err(Into::into))
            .collect::<Result<_>>()?;
        Ok(self.master.derive_priv(&self.secp, &path)?)
    }

    /// bdk descriptor pair `(external, internal)` for the wallet:
    /// `wpkh([fingerprint/84'/coin'/0']xprv/{0,1}/*)` for [`DescriptorKind::Bip84`],
    /// `tr([fingerprint/86'/coin'/0']xprv/{0,1}/*)` for [`DescriptorKind::Bip86`].
    /// Private descriptors — they carry the account xprv so bdk can sign; they
    /// must never be logged or persisted (bdk stores only the public form).
    pub fn wallet_descriptors(
        &self,
        kind: DescriptorKind,
        coin_type: u32,
    ) -> Result<(String, String)> {
        let purpose = kind.purpose();
        let fingerprint = self.master.fingerprint(&self.secp);
        let account = self.wallet_account_xpriv(kind, coin_type)?;
        let origin = format!("[{fingerprint}/{purpose}'/{coin_type}'/0']");
        Ok(match kind {
            DescriptorKind::Bip84 => (
                format!("wpkh({origin}{account}/0/*)"),
                format!("wpkh({origin}{account}/1/*)"),
            ),
            DescriptorKind::Bip86 => (
                format!("tr({origin}{account}/0/*)"),
                format!("tr({origin}{account}/1/*)"),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard BIP39 test mnemonic; used for spec test vectors too.
    pub const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed() -> WalletSeed {
        WalletSeed::from_mnemonic(TEST_MNEMONIC, "").unwrap()
    }

    #[test]
    fn wallet_account_matches_bip86_vector() {
        // COIN_BTC = 0, so m/86'/0'/0' from the standard test mnemonic is
        // exactly BIP-86's published account-xprv test vector.
        let account = seed()
            .wallet_account_xpriv(DescriptorKind::Bip86, COIN_BTC)
            .unwrap();
        assert_eq!(
            account.to_string(),
            "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk"
        );
    }

    #[test]
    fn wallet_account_matches_bip84_vector() {
        // BIP-84's published test vector for the same mnemonic: the first
        // receiving key m/84'/0'/0'/0/0 has this exact pubkey (the account
        // xprv itself is published as a zprv, which rust-bitcoin does not
        // serialize, so the child pubkey is the byte-exact check).
        let secp = Secp256k1::new();
        let account = seed()
            .wallet_account_xpriv(DescriptorKind::Bip84, COIN_BTC)
            .unwrap();
        let child = account
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(0).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(
            child.private_key.public_key(&secp).to_string(),
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
    }

    #[test]
    fn wallet_descriptors_shape_and_disjointness() {
        let s = seed();
        let (ext, int) = s
            .wallet_descriptors(DescriptorKind::Bip86, COIN_BTCX)
            .unwrap();
        // tr() descriptors with full origin, distinct keychains.
        assert!(ext.starts_with("tr(["));
        assert!(ext.contains(&format!("/86'/{COIN_BTCX}'/0']")));
        assert!(ext.ends_with("/0/*)"));
        assert!(int.ends_with("/1/*)"));
        assert_ne!(ext, int);
        // Deterministic; distinct per coin type.
        assert_eq!(
            ext,
            seed()
                .wallet_descriptors(DescriptorKind::Bip86, COIN_BTCX)
                .unwrap()
                .0
        );
        assert_ne!(
            ext,
            s.wallet_descriptors(DescriptorKind::Bip86, COIN_BTC)
                .unwrap()
                .0
        );
    }

    #[test]
    fn bip84_descriptors_shape_and_disjoint_from_bip86() {
        let s = seed();
        let (ext, int) = s
            .wallet_descriptors(DescriptorKind::Bip84, COIN_BTCX)
            .unwrap();
        // wpkh() descriptors with full origin, distinct keychains.
        assert!(ext.starts_with("wpkh(["));
        assert!(ext.contains(&format!("/84'/{COIN_BTCX}'/0']")));
        assert!(ext.ends_with("/0/*)"));
        assert!(int.ends_with("/1/*)"));
        assert_ne!(ext, int);
        // The two purposes derive different accounts — never the same keys.
        let (tr_ext, _) = s
            .wallet_descriptors(DescriptorKind::Bip86, COIN_BTCX)
            .unwrap();
        assert_ne!(ext, tr_ext);
        assert_ne!(
            s.wallet_account_xpriv(DescriptorKind::Bip84, COIN_BTCX)
                .unwrap(),
            s.wallet_account_xpriv(DescriptorKind::Bip86, COIN_BTCX)
                .unwrap()
        );
    }

    #[test]
    fn derive_hardened_matches_manual_bip32() {
        // derive_hardened is the hook protocol trees build on: it must agree
        // with a manual hardened derivation from the exposed master xprv.
        let s = seed();
        let secp = Secp256k1::new();
        let path: Vec<ChildNumber> = [86u32, 0, 0]
            .iter()
            .map(|&i| ChildNumber::from_hardened_idx(i).unwrap())
            .collect();
        let manual = s
            .master_xpriv()
            .derive_priv(&secp, &path)
            .unwrap()
            .private_key;
        assert_eq!(s.derive_hardened(&[86, 0, 0]).unwrap(), manual);
        // ... and with the BIP-86 account helper.
        assert_eq!(
            manual,
            s.wallet_account_xpriv(DescriptorKind::Bip86, COIN_BTC)
                .unwrap()
                .private_key
        );
    }
}
