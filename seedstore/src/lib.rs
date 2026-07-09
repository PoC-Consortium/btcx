//! Seed-at-rest storage (#120).
//!
//! A user passphrase encrypts the BIP39 mnemonic with scrypt +
//! ChaCha20-Poly1305 (`PACTSEEDv1`). With NO passphrase the seed is still
//! never written plaintext — it is ChaCha20-Poly1305'd under a machine key
//! held in the OS keystore (`PACTSEEDv2-keyring`, Windows/macOS only), or,
//! where no keystore is compiled/available (all Linux — see the `os-keyring`
//! feature and the Cargo target gate), under a built-in obfuscation key
//! (`PACTSEEDv2-obfs`). The obfuscation key ships in the binary, so an obfs
//! seed is treated as UNENCRYPTED wherever trust is decided (mainnet gate,
//! `walletstatus`); it only lifts the file off plaintext ASCII. The machine
//! key auto-unlocks, so a daemon keeps signing across restarts; only a
//! passphrase seed can be `locked`.

use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SEED_FILE: &str = "seed.mnemonic";
const SEED_MAGIC: &str = "PACTSEEDv1";
/// scrypt cost: N=2^15, r=8, p=1 (~30 MB, tens of ms) — interactive-grade.
const SCRYPT_LOG_N: u8 = 15;
/// The two *unattended* at-rest wraps (#120), used when no passphrase is set.
/// `-keyring`: `MAGIC:key_id:nonce:ct`, key held in the OS keystore under
/// `key_id`. `-obfs`: `MAGIC:nonce:ct`, the fallback constant key.
const SEED_V2_KEYRING: &str = "PACTSEEDv2-keyring";
const SEED_V2_OBFS: &str = "PACTSEEDv2-obfs";
/// OS-keystore service name; the per-seed account is the random `key_id` stored
/// in the seed line itself (so the entry survives a same-machine folder move,
/// but not a copy to a different machine — which is the point). Only referenced
/// by the Windows/macOS keystore path, so it's gated to avoid an unused-const
/// warning where the seed always takes the obfuscation wrap.
#[cfg(all(feature = "os-keyring", any(windows, target_os = "macos")))]
const KEYRING_SERVICE: &str = "pactd-seed";
/// The obfuscation fallback key. This is NOT a secret — it ships in the
/// open-source binary. It only raises a no-keystore seed from plaintext ASCII to
/// a binary blob (Bitcoin-Core-unencrypted parity) and is always treated as
/// UNENCRYPTED for trust. Bytes spell "PACT-seed-obfs-v2-do-not-trust!!".
const OBFUSCATION_KEY: [u8; 32] = [
    0x50, 0x41, 0x43, 0x54, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x6f, 0x62, 0x66, 0x73, 0x2d, 0x76,
    0x32, 0x2d, 0x64, 0x6f, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x74, 0x72, 0x75, 0x73, 0x74, 0x21, 0x21,
];

/// Seed-lifecycle status for a `walletstatus`-style RPC and first-run wizards.
///
/// A user with no seed yet is in first-run state (`seed_exists=false`).
/// An `encrypted` seed with no passphrase loaded is `locked`: the daemon is
/// up but cannot sign until an `unlock` (or a restart with the passphrase).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WalletStatus {
    pub seed_exists: bool,
    pub encrypted: bool,
    pub locked: bool,
}

/// The seed file in one data dir, plus the in-memory passphrase (if any)
/// that decrypts it.
pub struct SeedStore {
    dir: PathBuf,
    passphrase: Option<String>,
}

impl SeedStore {
    /// Create a fresh data dir with a new random seed (encrypted when a
    /// passphrase is given). Fails if a seed already exists — never
    /// overwrite key material.
    pub fn init(dir: &Path, passphrase: Option<&str>) -> Result<Self> {
        let mut store = Self::open(dir, None)?;
        store.create_seed(passphrase, 12)?;
        Ok(store)
    }

    pub fn open(dir: &Path, passphrase: Option<&str>) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let store = Self {
            dir: dir.to_path_buf(),
            passphrase: passphrase.map(str::to_string),
        };
        // #120: bring any pre-existing plaintext seed up to the never-plaintext
        // bar in place. Best-effort — a keystore/disk hiccup must never block
        // startup; the next boot retries. Only touches plaintext (see below).
        if let Err(e) = store.migrate_seed_at_rest() {
            eprintln!("seed: at-rest migration skipped ({e:#})");
        }
        Ok(store)
    }

    /// #120: re-wrap an existing *plaintext* seed in place (OS-keystore key, or
    /// obfuscation + warning) so a legacy seed stops sitting on disk as ASCII.
    /// Only ever touches a plaintext file — passphrase (`PACTSEEDv1`) and
    /// already-wrapped (`PACTSEEDv2-*`) seeds are left exactly as they are, so
    /// this can never *downgrade* a stronger wrap (guardrail 2).
    fn migrate_seed_at_rest(&self) -> Result<()> {
        let seed_path = self.dir.join(SEED_FILE);
        let Ok(contents) = std::fs::read_to_string(&seed_path) else {
            return Ok(()); // no seed yet
        };
        let line = contents.trim();
        if line.is_empty()
            || line.starts_with(SEED_MAGIC)
            || line.starts_with(SEED_V2_KEYRING)
            || line.starts_with(SEED_V2_OBFS)
        {
            return Ok(()); // already wrapped (or empty) — nothing to migrate
        }
        let wrapped = wrap_unattended(line)?;
        write_seed_atomic(&seed_path, &wrapped)?;
        eprintln!(
            "seed: migrated a plaintext seed to encrypted-at-rest ({})",
            seed_path.display()
        );
        Ok(())
    }

    /// Seed-lifecycle snapshot — drives `walletstatus`, the first-run wizard,
    /// and the lock/unlock UX. Cheap: no scrypt, just a file probe.
    pub fn wallet_status(&self) -> Result<WalletStatus> {
        let path = self.dir.join(SEED_FILE);
        if !path.exists() {
            return Ok(WalletStatus {
                seed_exists: false,
                encrypted: false,
                locked: false,
            });
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("reading seed at {}", path.display()))?;
        let encrypted = is_encrypted_seed_file(&contents);
        // Only a passphrase seed can be *locked*: it needs an in-memory
        // passphrase to read. Keyring seeds auto-unlock from the OS keystore, so
        // they are encrypted-but-never-locked (a keyring seed the machine can no
        // longer decrypt surfaces at read time as a reconfirm-with-mnemonic
        // error, #120 guardrail 2 — not as a lock). We only ever hold a
        // passphrase that has actually decrypted the seed, so "held" ⇒ "usable".
        let locked = is_passphrase_seed_file(&contents) && self.passphrase.is_none();
        Ok(WalletStatus {
            seed_exists: true,
            encrypted,
            locked,
        })
    }

    /// Write a mnemonic to disk and adopt it as this store's live seed. A
    /// non-empty passphrase encrypts it (`PACTSEEDv1`); otherwise it is wrapped
    /// unattended (#120: OS-keystore key, or obfuscation) — never plaintext.
    /// Refuses to clobber a seed we can still read.
    fn install_seed(&mut self, phrase: &str, passphrase: Option<&str>) -> Result<()> {
        let seed_path = self.dir.join(SEED_FILE);
        if seed_path.exists() {
            // The one clobber we allow is the reconfirm-with-mnemonic recovery
            // (#120 guardrail 2): a `PACTSEEDv2-keyring` seed whose OS-keystore
            // key has vanished (moved to a new machine / reset keychain) is
            // unreadable, so re-importing the mnemonic re-provisions it under a
            // fresh machine key. A seed we can still read is never overwritten.
            let existing = std::fs::read_to_string(&seed_path).unwrap_or_default();
            let unreadable_keyring =
                existing.trim().starts_with(SEED_V2_KEYRING) && self.mnemonic().is_err();
            anyhow::ensure!(
                unreadable_keyring,
                "{} already exists — refusing to overwrite a seed",
                seed_path.display()
            );
        }
        let pass = passphrase.filter(|p| !p.is_empty());
        let contents = match pass {
            Some(pass) => encrypt_seed(phrase, pass)?,
            None => wrap_unattended(phrase)?,
        };
        write_seed_atomic(&seed_path, &contents)?;
        self.passphrase = pass.map(str::to_string);
        Ok(())
    }

    /// Generate a new random BIP39 seed and return the mnemonic **once** for
    /// the user to back up — no recovery copy is kept. Encrypted when a
    /// passphrase is supplied. `words` is 12 or 24 (phoenix parity): 12
    /// (128-bit) is the DEFAULT — this is a hot wallet, not custody
    /// storage, and 128 bits already matches secp256k1's security level — 24
    /// (256-bit) for those who want the longer phrase.
    pub fn create_seed(&mut self, passphrase: Option<&str>, words: usize) -> Result<String> {
        let phrase = self.generate_mnemonic(words)?;
        self.install_seed(&phrase, passphrase)?;
        Ok(phrase)
    }

    /// Generate a fresh random BIP39 mnemonic **without persisting it** — for an
    /// onboarding flow that shows + confirms the phrase before committing. The
    /// mnemonic is only written once it's passed back to [`Self::import_seed`].
    /// `words`: 12 or 24, see [`Self::create_seed`].
    pub fn generate_mnemonic(&self, words: usize) -> Result<String> {
        let bytes = match words {
            12 => 16,
            24 => 32,
            n => bail!("seed length must be 12 or 24 words, not {n}"),
        };
        let mut entropy = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut entropy[..bytes]);
        Ok(bip39::Mnemonic::from_entropy(&entropy[..bytes])?.to_string())
    }

    /// Import a user-supplied BIP39 mnemonic (validated). Returns the
    /// normalized phrase. Encrypted when a passphrase is supplied.
    pub fn import_seed(&mut self, mnemonic: &str, passphrase: Option<&str>) -> Result<String> {
        let parsed = bip39::Mnemonic::parse_normalized(mnemonic.trim())
            .context("not a valid BIP39 mnemonic")?;
        let phrase = parsed.to_string();
        self.install_seed(&phrase, passphrase)?;
        Ok(phrase)
    }

    /// Supply the passphrase for an existing encrypted seed, verifying it by
    /// trial decryption before holding it in memory (`lncli unlock`-style).
    /// Idempotent on an already-unlocked store; a no-op error on plaintext.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        let path = self.dir.join(SEED_FILE);
        let contents =
            std::fs::read_to_string(&path).context("no seed yet — create or import one first")?;
        // Only a passphrase seed needs unlocking; keyring/obfs auto-read.
        anyhow::ensure!(
            is_passphrase_seed_file(&contents),
            "seed is not passphrase-encrypted — no unlock needed"
        );
        // Errors (wrong passphrase) before we adopt anything.
        decrypt_seed(contents.trim(), passphrase)?;
        self.passphrase = Some(passphrase.to_string());
        Ok(())
    }

    /// Whether the on-disk seed is *encrypted* — the file is useless without an
    /// external secret (a passphrase, or the OS-keystore key). Obfuscation and
    /// plaintext are NOT encrypted. Callers gate networks on this (#120).
    pub fn seed_is_encrypted(&self) -> Result<bool> {
        let path = self.dir.join(SEED_FILE);
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("no seed at {} — create or import one first", path.display()))?;
        Ok(is_encrypted_seed_file(&contents))
    }

    /// Read and decrypt the stored mnemonic phrase.
    pub fn mnemonic(&self) -> Result<String> {
        let path = self.dir.join(SEED_FILE);
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("no seed at {} — create or import one first", path.display()))?;
        self.decrypt_contents(contents.trim())
    }

    /// Decrypt on-disk seed contents to the raw mnemonic, dispatching on the
    /// wrap: passphrase (`PACTSEEDv1`, needs the in-memory passphrase), keyring
    /// (`PACTSEEDv2-keyring`, key from the OS keystore), obfuscation
    /// (`PACTSEEDv2-obfs`), or legacy plaintext (pre-#120, not yet migrated).
    fn decrypt_contents(&self, line: &str) -> Result<String> {
        if line.starts_with(SEED_MAGIC) {
            let pass = self
                .passphrase
                .as_deref()
                .context("seed is encrypted — supply the passphrase or run `unlock`")?;
            decrypt_seed(line, pass)
        } else if let Some(rest) = line.strip_prefix(&format!("{SEED_V2_KEYRING}:")) {
            let mut parts = rest.split(':');
            let key_id = parts.next().context("malformed keyring seed")?;
            let nonce = parts.next().context("malformed keyring seed")?;
            let ct = parts.next().context("malformed keyring seed")?;
            let key = keyring_get(key_id).context(
                "this machine can no longer unlock the seed (OS-keystore key missing) — \
                 re-import your recovery phrase to continue",
            )?;
            decrypt_v2(nonce, ct, &key)
        } else if let Some(rest) = line.strip_prefix(&format!("{SEED_V2_OBFS}:")) {
            let mut parts = rest.split(':');
            let nonce = parts.next().context("malformed obfs seed")?;
            let ct = parts.next().context("malformed obfs seed")?;
            decrypt_v2(nonce, ct, &OBFUSCATION_KEY)
        } else {
            // Legacy plaintext (migrated to a wrap on the next `SeedStore::open`).
            Ok(line.to_string())
        }
    }
}

/// Whether an on-disk seed file is *encrypted* — useless without an external
/// secret (a passphrase, or the OS-keystore key). Obfuscation-wrapped and
/// plaintext seeds are NOT encrypted. Public so callers that only hold file
/// contents can decide trust with the format magics in one place (#120).
pub fn is_encrypted_seed_file(contents: &str) -> bool {
    let line = contents.trim_start();
    line.starts_with(SEED_MAGIC) || line.starts_with(SEED_V2_KEYRING)
}

/// Whether the seed is passphrase-encrypted (`PACTSEEDv1`) — the only wrap that
/// needs an `unlock` before it can be read.
fn is_passphrase_seed_file(contents: &str) -> bool {
    contents.trim_start().starts_with(SEED_MAGIC)
}

/// Whether to use the OS keystore. Compiled to `true`-capable only on
/// Windows/macOS with the `os-keyring` feature (native, unattended-friendly,
/// no C deps); elsewhere it is a const `false`, so those always take the
/// obfuscation wrap and the `keyring` crate is never linked (see the Cargo
/// target gate). Also off under the crate's own unit tests (so they never
/// touch the developer's real keychain) and when `PACT_DISABLE_KEYRING` is
/// set (e2e/CI determinism).
#[cfg(all(feature = "os-keyring", any(windows, target_os = "macos")))]
fn keyring_enabled() -> bool {
    !cfg!(test) && std::env::var_os("PACT_DISABLE_KEYRING").is_none()
}
#[cfg(not(all(feature = "os-keyring", any(windows, target_os = "macos"))))]
fn keyring_enabled() -> bool {
    false
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Encrypt a mnemonic with a raw 32-byte key into `MAGIC[:key_id]:nonce:ct`.
fn encrypt_v2(magic: &str, key_id: Option<&str>, key: &[u8; 32], mnemonic: &str) -> Result<String> {
    let nonce = random_bytes::<12>();
    let cipher = ChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt((&nonce).into(), mnemonic.as_bytes())
        .map_err(|_| anyhow::anyhow!("seed encryption failed"))?;
    Ok(match key_id {
        Some(id) => format!("{magic}:{id}:{}:{}\n", hex::encode(nonce), hex::encode(ct)),
        None => format!("{magic}:{}:{}\n", hex::encode(nonce), hex::encode(ct)),
    })
}

fn decrypt_v2(nonce_hex: &str, ct_hex: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = hex::decode(nonce_hex)?;
    let pt = cipher
        .decrypt(nonce.as_slice().into(), hex::decode(ct_hex)?.as_slice())
        .map_err(|_| anyhow::anyhow!("seed decryption failed"))?;
    String::from_utf8(pt).context("decrypted seed is not UTF-8")
}

/// Store a fresh random seed-key in the OS keystore, returning `(key_id, key)`.
#[cfg(all(feature = "os-keyring", any(windows, target_os = "macos")))]
fn keyring_put_new() -> Result<(String, [u8; 32])> {
    let key_id = hex::encode(random_bytes::<8>());
    let key = random_bytes::<32>();
    let entry =
        keyring::Entry::new(KEYRING_SERVICE, &key_id).context("opening OS keystore entry")?;
    entry
        .set_password(&hex::encode(key))
        .context("writing seed key to OS keystore")?;
    Ok((key_id, key))
}
#[cfg(not(all(feature = "os-keyring", any(windows, target_os = "macos"))))]
fn keyring_put_new() -> Result<(String, [u8; 32])> {
    anyhow::bail!("no OS keystore on this platform")
}

/// Fetch a seed-key from the OS keystore by `key_id`. Errors (→ reconfirm) when
/// the entry is missing (new machine / reset keychain), or on a platform with no
/// keystore (a keyring seed copied from Windows/macOS to Linux).
#[cfg(all(feature = "os-keyring", any(windows, target_os = "macos")))]
fn keyring_get(key_id: &str) -> Result<[u8; 32]> {
    let entry =
        keyring::Entry::new(KEYRING_SERVICE, key_id).context("opening OS keystore entry")?;
    let hexkey = entry
        .get_password()
        .context("reading seed key from OS keystore")?;
    let bytes = hex::decode(hexkey.trim()).context("bad keystore key encoding")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("keystore key has wrong length"))
}
#[cfg(not(all(feature = "os-keyring", any(windows, target_os = "macos"))))]
fn keyring_get(_key_id: &str) -> Result<[u8; 32]> {
    anyhow::bail!("this build has no OS keystore — re-import your recovery phrase to continue")
}

/// The *unattended* at-rest wrap (#120) for a seed created/migrated without a
/// passphrase: OS-keystore key when available, else the obfuscation key (with a
/// warning). Never fails — the obfuscation path always succeeds.
fn wrap_unattended(mnemonic: &str) -> Result<String> {
    if keyring_enabled() {
        match keyring_put_new() {
            Ok((key_id, key)) => return encrypt_v2(SEED_V2_KEYRING, Some(&key_id), &key, mnemonic),
            Err(e) => eprintln!(
                "warning: no OS keystore available ({e:#}); storing the seed with obfuscation \
                 only — treat it as UNENCRYPTED. Set a passphrase for real at-rest encryption."
            ),
        }
    }
    encrypt_v2(SEED_V2_OBFS, None, &OBFUSCATION_KEY, mnemonic)
}

/// Atomically write seed-file `contents` (temp file + fsync + rename): a plain
/// truncating write can leave a corrupt/partial seed on a crash and there is no
/// backup copy, so the file is only ever observed fully written or not at all.
fn write_seed_atomic(seed_path: &Path, contents: &str) -> Result<()> {
    let tmp_path = seed_path.with_extension("seed.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?; // flush to disk before the rename
    }
    std::fs::rename(&tmp_path, seed_path)
        .with_context(|| format!("installing seed at {}", seed_path.display()))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let params = scrypt::Params::new(SCRYPT_LOG_N, 8, 1, 32)
        .map_err(|e| anyhow::anyhow!("scrypt params: {e}"))?;
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| anyhow::anyhow!("scrypt key derivation: {e}"))?;
    Ok(key)
}

fn encrypt_seed(mnemonic: &str, passphrase: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt((&nonce).into(), mnemonic.as_bytes())
        .map_err(|_| anyhow::anyhow!("seed encryption failed"))?;
    Ok(format!(
        "{SEED_MAGIC}:{}:{}:{}\n",
        hex::encode(salt),
        hex::encode(nonce),
        hex::encode(ciphertext)
    ))
}

fn decrypt_seed(line: &str, passphrase: &str) -> Result<String> {
    let mut parts = line.split(':');
    let (magic, salt, nonce, ciphertext) = (
        parts.next().unwrap_or_default(),
        parts.next().context("malformed seed file")?,
        parts.next().context("malformed seed file")?,
        parts.next().context("malformed seed file")?,
    );
    if magic != SEED_MAGIC {
        bail!("unknown seed file format {magic:?}");
    }
    let key = derive_key(passphrase, &hex::decode(salt)?)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = hex::decode(nonce)?;
    let plaintext = cipher
        .decrypt(nonce.as_slice().into(), hex::decode(ciphertext)?.as_slice())
        .map_err(|_| anyhow::anyhow!("seed decryption failed — wrong passphrase?"))?;
    String::from_utf8(plaintext).context("decrypted seed is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("seedstore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn init_refuses_overwrite_and_roundtrips() {
        let dir = temp_dir("plain");
        let store = SeedStore::init(&dir, None).unwrap();
        assert!(
            SeedStore::init(&dir, None).is_err(),
            "must not overwrite a seed"
        );
        store.mnemonic().unwrap();
        assert!(!store.seed_is_encrypted().unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn encrypted_seed_roundtrip() {
        let dir = temp_dir("enc");
        let store = SeedStore::init(&dir, Some("correct horse")).unwrap();
        assert!(store.seed_is_encrypted().unwrap());
        let mnemonic = store.mnemonic().unwrap();

        // Reopen with the right passphrase: same seed.
        let reopened = SeedStore::open(&dir, Some("correct horse")).unwrap();
        assert_eq!(reopened.mnemonic().unwrap(), mnemonic);

        // Wrong or missing passphrase must fail, not yield a different seed.
        assert!(SeedStore::open(&dir, Some("wrong"))
            .unwrap()
            .mnemonic()
            .is_err());
        assert!(SeedStore::open(&dir, None).unwrap().mnemonic().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unattended_seed_is_never_plaintext_and_roundtrips() {
        // #120: a no-passphrase seed is wrapped, not written as ASCII. Under the
        // crate's own tests the keyring is disabled, so it takes the obfuscation
        // wrap — which is "not plaintext" but is treated as UNENCRYPTED.
        let dir = temp_dir("unattended");
        let store = SeedStore::init(&dir, None).unwrap();
        let on_disk = std::fs::read_to_string(dir.join(SEED_FILE)).unwrap();
        assert!(
            on_disk.starts_with(SEED_V2_OBFS),
            "no-passphrase seed must be wrapped, got: {on_disk}"
        );
        assert!(
            !is_encrypted_seed_file(&on_disk),
            "obfs counts as unencrypted"
        );
        let status = store.wallet_status().unwrap();
        assert!(status.seed_exists && !status.encrypted && !status.locked);
        // Readable now and after reopen (auto-unlock, no passphrase).
        let mnemonic = store.mnemonic().unwrap();
        let reopened = SeedStore::open(&dir, None).unwrap();
        assert_eq!(reopened.mnemonic().unwrap(), mnemonic);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrates_legacy_plaintext_seed_on_open() {
        // A pre-#120 seed sits on disk as the raw mnemonic. Opening the store
        // must re-wrap it in place (never-plaintext), preserving the same seed.
        let dir = temp_dir("migrate");
        std::fs::create_dir_all(&dir).unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        std::fs::write(dir.join(SEED_FILE), format!("{phrase}\n")).unwrap();
        assert!(!is_encrypted_seed_file(phrase), "precondition: plaintext");

        let store = SeedStore::open(&dir, None).unwrap();
        let migrated = std::fs::read_to_string(dir.join(SEED_FILE)).unwrap();
        assert!(
            migrated.starts_with(SEED_V2_OBFS),
            "plaintext seed re-wrapped on open, got: {migrated}"
        );
        // Same seed, still readable.
        assert_eq!(store.mnemonic().unwrap(), phrase);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_seed_roundtrip_unencrypted() {
        let dir = temp_dir("create-plain");
        let mut store = SeedStore::open(&dir, None).unwrap();
        assert!(!store.wallet_status().unwrap().seed_exists);

        let mnemonic = store.create_seed(None, 12).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        let status = store.wallet_status().unwrap();
        assert!(status.seed_exists && !status.encrypted && !status.locked);
        // The seed is usable immediately and matches the returned mnemonic.
        assert_eq!(store.mnemonic().unwrap(), mnemonic);

        // Never overwrite an existing seed.
        assert!(store.create_seed(None, 12).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_seed_roundtrip_encrypted_and_unlock() {
        let dir = temp_dir("create-enc");
        let mut store = SeedStore::open(&dir, None).unwrap();
        store.create_seed(Some("hunter2"), 12).unwrap();
        let status = store.wallet_status().unwrap();
        assert!(
            status.encrypted && !status.locked,
            "creator holds the passphrase: {status:?}"
        );
        let mnemonic = store.mnemonic().unwrap();

        // A fresh open with no passphrase is locked; mnemonic() refuses.
        let mut reopened = SeedStore::open(&dir, None).unwrap();
        let st = reopened.wallet_status().unwrap();
        assert!(st.encrypted && st.locked, "reopen must be locked: {st:?}");
        assert!(
            reopened.mnemonic().is_err(),
            "locked store must not yield a seed"
        );

        // Wrong passphrase fails and leaves it locked.
        assert!(reopened.unlock("wrong").is_err());
        assert!(reopened.wallet_status().unwrap().locked);

        // Right passphrase unlocks; same mnemonic as the creator saw.
        reopened.unlock("hunter2").unwrap();
        assert!(!reopened.wallet_status().unwrap().locked);
        assert_eq!(reopened.mnemonic().unwrap(), mnemonic);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn import_seed_roundtrip_and_validation() {
        const PHRASE: &str =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let dir = temp_dir("import");
        let mut store = SeedStore::open(&dir, None).unwrap();
        assert!(store.import_seed("not a real mnemonic", None).is_err());
        let returned = store.import_seed(PHRASE, None).unwrap();
        assert_eq!(returned, PHRASE);
        assert_eq!(store.mnemonic().unwrap(), PHRASE);

        // Importing the same phrase encrypted into a *second* data dir
        // yields the same seed — the data dir is the only difference.
        let dir2 = temp_dir("import2");
        let mut store2 = SeedStore::open(&dir2, None).unwrap();
        store2.import_seed(PHRASE, Some("pw")).unwrap();
        assert!(store2.wallet_status().unwrap().encrypted);
        assert_eq!(store2.mnemonic().unwrap(), PHRASE);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&dir2).ok();
    }

    #[test]
    fn two_data_dirs_have_distinct_seeds() {
        // One seed = one data dir; switching wallets is just pointing the
        // daemon at another dir. Two created seeds are unlinkable.
        let dir_a = temp_dir("dir-a");
        let dir_b = temp_dir("dir-b");
        let seed_a = {
            let mut s = SeedStore::open(&dir_a, None).unwrap();
            s.create_seed(None, 12).unwrap();
            s.mnemonic().unwrap()
        };
        let seed_b = {
            let mut s = SeedStore::open(&dir_b, Some("pw")).unwrap();
            s.create_seed(Some("pw"), 12).unwrap();
            s.mnemonic().unwrap()
        };
        assert_ne!(seed_a, seed_b, "independent seeds must be unlinkable");

        // Reopening dir A still yields A's seed (state is the dir).
        let reopened = SeedStore::open(&dir_a, None).unwrap();
        assert_eq!(reopened.mnemonic().unwrap(), seed_a);
        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }
}
