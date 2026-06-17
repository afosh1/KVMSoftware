#![forbid(unsafe_code)]
//! Secure persistence for the LAN KVM.
//!
//! The **private key** goes to a [`SecretBackend`]:
//! * [`KeyringBackend`] — OS keychain (Windows Credential Manager / macOS
//!   Keychain / Linux Secret Service). Preferred.
//! * [`FileBackend`] — fallback for headless Linux with no Secret Service. Stores
//!   secrets in a directory locked to `0700`/`0600`. (Production hardening note:
//!   layer OS-level disk encryption or a TPM on top — tracked as a follow-up.)
//!
//! Non-secret state (our certificate, the device registry) is stored as files in
//! the state directory by [`Keystore`].

use std::path::{Path, PathBuf};

use thiserror::Error;

use kvm_core::device::RegistrySnapshot;

/// A loaded device identity (certificate + private key, both DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

const KEY_DEVICE_PRIVKEY: &str = "device_private_key";
const CERT_FILE: &str = "device_cert.der";
const REGISTRY_FILE: &str = "registry.json";

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("keychain: {0}")]
    Keyring(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("serialize: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Pluggable backend for *secret* material (the device private key).
pub trait SecretBackend: Send + Sync {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), KeystoreError>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete(&self, key: &str) -> Result<(), KeystoreError>;
    fn name(&self) -> &'static str;
}

/// OS keychain backend (hex-encodes binary key material into a password slot).
pub struct KeyringBackend {
    service: String,
}

impl KeyringBackend {
    pub fn new(service: impl Into<String>) -> Self {
        KeyringBackend {
            service: service.into(),
        }
    }
}

fn map_keyring(e: keyring::Error) -> KeystoreError {
    KeystoreError::Keyring(e.to_string())
}

impl SecretBackend for KeyringBackend {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let entry = keyring::Entry::new(&self.service, key).map_err(map_keyring)?;
        entry.set_password(&hex::encode(value)).map_err(map_keyring)
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let entry = keyring::Entry::new(&self.service, key).map_err(map_keyring)?;
        match entry.get_password() {
            Ok(s) => Ok(Some(
                hex::decode(s).map_err(|e| KeystoreError::Decode(e.to_string()))?,
            )),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring(e)),
        }
    }

    fn delete(&self, key: &str) -> Result<(), KeystoreError> {
        let entry = keyring::Entry::new(&self.service, key).map_err(map_keyring)?;
        match entry.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_keyring(e)),
        }
    }

    fn name(&self) -> &'static str {
        "os-keychain"
    }
}

/// Permission-restricted file backend (headless fallback).
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    pub fn new(dir: PathBuf) -> Result<Self, KeystoreError> {
        std::fs::create_dir_all(&dir)?;
        restrict(&dir, 0o700)?;
        Ok(FileBackend { dir })
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.secret"))
    }
}

impl SecretBackend for FileBackend {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let path = self.path(key);
        std::fs::write(&path, hex::encode(value))?;
        restrict(&path, 0o600)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let path = self.path(key);
        if !path.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&path)?;
        let bytes = hex::decode(s.trim()).map_err(|e| KeystoreError::Decode(e.to_string()))?;
        Ok(Some(bytes))
    }

    fn delete(&self, key: &str) -> Result<(), KeystoreError> {
        let path = self.path(key);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "file"
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> std::io::Result<()> {
    // On Windows, ACL inheritance from the user profile directory is relied upon.
    Ok(())
}

/// High-level store: device identity (cert + private key) and the registry.
pub struct Keystore {
    backend: Box<dyn SecretBackend>,
    state_dir: PathBuf,
}

impl Keystore {
    pub fn new(backend: Box<dyn SecretBackend>, state_dir: PathBuf) -> Result<Self, KeystoreError> {
        std::fs::create_dir_all(&state_dir)?;
        restrict(&state_dir, 0o700)?;
        Ok(Keystore { backend, state_dir })
    }

    /// Open the default store.
    ///
    /// The device private key is persisted in a `0600` file rather than the OS
    /// keychain. Identity MUST be byte-stable across restarts: a locked,
    /// session-scoped, or flaky keychain would silently regenerate our
    /// certificate fingerprint and break every existing pairing — the single
    /// most confusing failure mode for users. ([`KeyringBackend`] remains
    /// available for callers that explicitly want it.)
    pub fn open_default() -> Result<Self, KeystoreError> {
        let state_dir = default_state_dir();
        std::fs::create_dir_all(&state_dir)?;
        let backend: Box<dyn SecretBackend> =
            Box::new(FileBackend::new(state_dir.join("secrets"))?);
        tracing::info!(backend = backend.name(), "keystore backend selected");
        Keystore::new(backend, state_dir)
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    pub fn save_identity(&self, cert_der: &[u8], key_der: &[u8]) -> Result<(), KeystoreError> {
        self.backend.store(KEY_DEVICE_PRIVKEY, key_der)?;
        let cert_path = self.state_dir.join(CERT_FILE);
        std::fs::write(&cert_path, cert_der)?;
        restrict(&cert_path, 0o600)?;
        Ok(())
    }

    /// Load the device identity if both the certificate and key are present.
    pub fn load_identity(&self) -> Result<Option<StoredIdentity>, KeystoreError> {
        let cert_path = self.state_dir.join(CERT_FILE);
        if !cert_path.exists() {
            return Ok(None);
        }
        let cert_der = std::fs::read(cert_path)?;
        match self.backend.load(KEY_DEVICE_PRIVKEY)? {
            Some(key_der) => Ok(Some(StoredIdentity { cert_der, key_der })),
            None => Ok(None),
        }
    }

    pub fn save_registry(&self, snapshot: &RegistrySnapshot) -> Result<(), KeystoreError> {
        let json = serde_json::to_vec_pretty(snapshot)?;
        std::fs::write(self.state_dir.join(REGISTRY_FILE), json)?;
        Ok(())
    }

    pub fn load_registry(&self) -> Result<RegistrySnapshot, KeystoreError> {
        let path = self.state_dir.join(REGISTRY_FILE);
        if !path.exists() {
            return Ok(RegistrySnapshot::default());
        }
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

/// Default per-user state directory.
pub fn default_state_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "kvm", "kvmshare")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".kvm-state"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("kvm-keystore-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn file_backend_round_trip() {
        let dir = temp_dir("fb");
        let be = FileBackend::new(dir.clone()).unwrap();
        assert_eq!(be.load("k").unwrap(), None);
        be.store("k", &[1, 2, 3, 4]).unwrap();
        assert_eq!(be.load("k").unwrap(), Some(vec![1, 2, 3, 4]));
        be.delete("k").unwrap();
        assert_eq!(be.load("k").unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keystore_identity_and_registry_round_trip() {
        let dir = temp_dir("ks");
        let be = Box::new(FileBackend::new(dir.join("secrets")).unwrap());
        let ks = Keystore::new(be, dir.clone()).unwrap();

        assert_eq!(ks.load_identity().unwrap(), None);
        ks.save_identity(&[10, 20, 30], &[40, 50, 60]).unwrap();
        assert_eq!(
            ks.load_identity().unwrap(),
            Some(StoredIdentity {
                cert_der: vec![10, 20, 30],
                key_der: vec![40, 50, 60]
            })
        );

        // Registry: default when absent, then persisted.
        assert_eq!(ks.load_registry().unwrap(), RegistrySnapshot::default());
        ks.save_registry(&RegistrySnapshot::default()).unwrap();
        assert_eq!(ks.load_registry().unwrap(), RegistrySnapshot::default());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
