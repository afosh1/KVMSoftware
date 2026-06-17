//! Device registry — identity, metadata, and trust state for known peers.
//!
//! Pure data + map operations. Persistence is the engine's job: it serializes a
//! [`RegistrySnapshot`] and restores it on startup.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::trust::TrustState;
use kvm_proto::v1::handshake::{Capabilities, Platform};

/// Stable, globally-unique device identity (the subject of its pinned cert).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    /// Generate a fresh random identity (done once, at first launch).
    pub fn generate() -> Self {
        DeviceId(Uuid::new_v4())
    }

    pub fn nil() -> Self {
        DeviceId(Uuid::nil())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SHA-256 fingerprint of a device's self-signed certificate. This is what gets
/// pinned during pairing and verified by the transport's custom TLS verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertFingerprint(pub [u8; 32]);

impl CertFingerprint {
    /// Lowercase hex, the form shown in the UI and embedded in mDNS TXT.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form for logs: first 8 hex chars.
        write!(f, "{}…", &self.to_hex()[..8])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub name: String,
    pub platform: Platform,
    pub fingerprint: CertFingerprint,
    pub trust: TrustState,
    pub capabilities: Capabilities,
    /// Unix seconds of last discovery/contact. `None` until first seen. The
    /// domain stays clock-free; the engine supplies timestamps.
    pub last_seen: Option<u64>,
}

/// Serializable snapshot for persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: HashMap<DeviceId, Device>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snap: RegistrySnapshot) -> Self {
        let devices = snap.devices.into_iter().map(|d| (d.id, d)).collect();
        Self { devices }
    }

    pub fn snapshot(&self) -> RegistrySnapshot {
        let mut devices: Vec<_> = self.devices.values().cloned().collect();
        devices.sort_by_key(|d| d.id.0);
        RegistrySnapshot { devices }
    }

    /// Insert or refresh a device seen via discovery. Preserves an existing
    /// trust state (we never *downgrade* trust just because we re-saw a peer),
    /// but updates mutable metadata (name, platform, capabilities, last_seen).
    pub fn upsert_discovered(
        &mut self,
        id: DeviceId,
        name: String,
        platform: Platform,
        fingerprint: CertFingerprint,
        capabilities: Capabilities,
        last_seen: Option<u64>,
    ) {
        match self.devices.get_mut(&id) {
            Some(existing) => {
                existing.name = name;
                existing.platform = platform;
                existing.capabilities = capabilities;
                existing.last_seen = last_seen;
                // If the advertised fingerprint changed for a trusted device,
                // that is a security event — do NOT silently accept it. We keep
                // the pinned fingerprint; the engine surfaces the mismatch.
                if existing.trust == TrustState::Untrusted {
                    existing.fingerprint = fingerprint;
                }
            }
            None => {
                self.devices.insert(
                    id,
                    Device {
                        id,
                        name,
                        platform,
                        fingerprint,
                        trust: TrustState::Untrusted,
                        capabilities,
                        last_seen,
                    },
                );
            }
        }
    }

    /// Record a successful pairing: pin the fingerprint and set trust.
    pub fn mark_paired(
        &mut self,
        id: DeviceId,
        fingerprint: CertFingerprint,
        trust: TrustState,
    ) -> bool {
        if let Some(d) = self.devices.get_mut(&id) {
            d.fingerprint = fingerprint;
            d.trust = trust;
            true
        } else {
            false
        }
    }

    pub fn rename(&mut self, id: DeviceId, name: String) -> bool {
        if let Some(d) = self.devices.get_mut(&id) {
            d.name = name;
            true
        } else {
            false
        }
    }

    pub fn set_trust(&mut self, id: DeviceId, trust: TrustState) -> bool {
        if let Some(d) = self.devices.get_mut(&id) {
            d.trust = trust;
            true
        } else {
            false
        }
    }

    pub fn revoke(&mut self, id: DeviceId) -> bool {
        self.set_trust(id, TrustState::Revoked)
    }

    pub fn forget(&mut self, id: DeviceId) -> Option<Device> {
        self.devices.remove(&id)
    }

    pub fn get(&self, id: DeviceId) -> Option<&Device> {
        self.devices.get(&id)
    }

    pub fn contains(&self, id: DeviceId) -> bool {
        self.devices.contains_key(&id)
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Devices currently allowed to connect (Paired or Trusted).
    pub fn connectable(&self) -> impl Iterator<Item = &Device> {
        self.devices.values().filter(|d| d.trust.is_connectable())
    }

    pub fn list_by_trust(&self, trust: TrustState) -> Vec<&Device> {
        let mut v: Vec<_> = self.devices.values().filter(|d| d.trust == trust).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn all(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> CertFingerprint {
        CertFingerprint([byte; 32])
    }

    fn reg_with_one() -> (DeviceRegistry, DeviceId) {
        let mut r = DeviceRegistry::new();
        let id = DeviceId::generate();
        r.upsert_discovered(
            id,
            "laptop-a".into(),
            Platform::Linux,
            fp(1),
            Capabilities::default(),
            Some(100),
        );
        (r, id)
    }

    #[test]
    fn upsert_inserts_as_untrusted() {
        let (r, id) = reg_with_one();
        assert_eq!(r.get(id).unwrap().trust, TrustState::Untrusted);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn upsert_preserves_trust_but_updates_metadata() {
        let (mut r, id) = reg_with_one();
        r.mark_paired(id, fp(1), TrustState::Trusted);
        // Re-discovery must not reset trust to Untrusted.
        r.upsert_discovered(
            id,
            "laptop-a-renamed".into(),
            Platform::Linux,
            fp(9), // a different advertised fingerprint
            Capabilities::default(),
            Some(200),
        );
        let d = r.get(id).unwrap();
        assert_eq!(d.trust, TrustState::Trusted);
        assert_eq!(d.name, "laptop-a-renamed");
        assert_eq!(d.last_seen, Some(200));
        // Pinned fingerprint of a trusted device is NOT overwritten by mDNS.
        assert_eq!(d.fingerprint, fp(1));
    }

    #[test]
    fn revoke_and_connectable_filter() {
        let (mut r, id) = reg_with_one();
        r.mark_paired(id, fp(1), TrustState::Trusted);
        assert_eq!(r.connectable().count(), 1);
        r.revoke(id);
        assert_eq!(r.connectable().count(), 0);
        assert_eq!(r.get(id).unwrap().trust, TrustState::Revoked);
    }

    #[test]
    fn snapshot_round_trips() {
        let (mut r, id) = reg_with_one();
        r.mark_paired(id, fp(2), TrustState::Paired);
        let snap = r.snapshot();
        let r2 = DeviceRegistry::from_snapshot(snap.clone());
        assert_eq!(r2.snapshot(), snap);
        assert_eq!(r2.get(id).unwrap().trust, TrustState::Paired);
    }

    #[test]
    fn fingerprint_hex() {
        assert_eq!(fp(0xab).to_hex(), "ab".repeat(32));
    }
}
