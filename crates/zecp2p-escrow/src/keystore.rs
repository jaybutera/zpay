//! Per-escrow key generation and durable storage.
//!
//! Spec section 2: the user holds an "ephemeral secp256k1 key `u` per escrow".
//! Reusing one key across escrows is not a theft path - the escrows are
//! separate scripts and separate outpoints - but it links them to anyone
//! watching the chain, which is the opposite of what a Zcash offramp is for.
//! It also means one leaked key loses every escrow rather than one.
//!
//! Spec 5.3 is the hard part: the key must be on disk **before** the funding
//! transaction is broadcast, because losing it loses the refund path and the
//! ZEC with it. So generation and persistence happen together, and the file is
//! created 0600 with `create_new` - never overwritten, never briefly wider.

use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("a key already exists at {0}; refusing to overwrite it")]
    AlreadyExists(String),
    #[error("could not write the key at {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("could not read the key at {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("the key at {0} is not 64 hex characters")]
    Malformed(String),
    #[error(
        "the key at {path} is mode {mode:o}; it can spend an escrow and must be 0600. \
         Fix it with: chmod 600 {path}"
    )]
    TooOpen { path: String, mode: u32 },
}

/// A directory of per-escrow keys.
#[derive(Debug, Clone)]
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path_for(&self, label: &str) -> PathBuf {
        self.dir.join(format!("{label}.key"))
    }

    /// Generates a fresh key for one escrow and writes it before returning.
    ///
    /// The write happens first on purpose: a caller that gets a key back has a
    /// key that survives a crash. `create_new` means a label is used once, so a
    /// second escrow cannot silently reuse the first one's key.
    pub fn create(&self, label: &str) -> Result<SecretKey, KeystoreError> {
        let path = self.path_for(label);
        if path.exists() {
            return Err(KeystoreError::AlreadyExists(path.display().to_string()));
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| KeystoreError::Write {
            path: self.dir.display().to_string(),
            source: e,
        })?;

        let key = SecretKey::new(&mut rand::thread_rng());

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&path).map_err(|e| KeystoreError::Write {
            path: path.display().to_string(),
            source: e,
        })?;
        f.write_all(hex::encode(key.secret_bytes()).as_bytes())
            .map_err(|e| KeystoreError::Write {
                path: path.display().to_string(),
                source: e,
            })?;
        // The refund depends on this surviving a power cut between here and the
        // funding broadcast.
        f.sync_all().map_err(|e| KeystoreError::Write {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(key)
    }

    /// Loads a key, refusing one any other account can read.
    pub fn load(&self, label: &str) -> Result<SecretKey, KeystoreError> {
        let path = self.path_for(label);
        Self::check_mode(&path)?;
        let text = std::fs::read_to_string(&path).map_err(|e| KeystoreError::Read {
            path: path.display().to_string(),
            source: e,
        })?;
        let bytes = hex::decode(text.trim())
            .map_err(|_| KeystoreError::Malformed(path.display().to_string()))?;
        SecretKey::from_slice(&bytes)
            .map_err(|_| KeystoreError::Malformed(path.display().to_string()))
    }

    /// Loads a key, or creates one if the label is new.
    pub fn load_or_create(&self, label: &str) -> Result<SecretKey, KeystoreError> {
        if self.path_for(label).exists() {
            self.load(label)
        } else {
            self.create(label)
        }
    }

    pub fn exists(&self, label: &str) -> bool {
        self.path_for(label).exists()
    }

    pub fn path_of(&self, label: &str) -> PathBuf {
        self.path_for(label)
    }

    #[cfg(unix)]
    fn check_mode(path: &Path) -> Result<(), KeystoreError> {
        let mode = std::fs::metadata(path)
            .map_err(|e| KeystoreError::Read {
                path: path.display().to_string(),
                source: e,
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeystoreError::TooOpen {
                path: path.display().to_string(),
                mode,
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_mode(_path: &Path) -> Result<(), KeystoreError> {
        Ok(())
    }
}

/// The compressed public key for a secret key.
pub fn public_key(key: &SecretKey) -> [u8; 33] {
    PublicKey::from_secret_key(&Secp256k1::new(), key).serialize()
}
