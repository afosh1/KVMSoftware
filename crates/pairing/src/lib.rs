#![forbid(unsafe_code)]
//! Secure pairing for the LAN KVM.
//!
//! Flow (orchestrated by the engine over the discovery/pairing channel):
//! 1. One device shows a 6-digit [`generate_code`]; the user types it on the other.
//! 2. Both run SPAKE2 ([`PairingSession`]) with that code as the password,
//!    exchanging one message each, and derive a shared key.
//! 3. Both derive a [`sas::Sas`] from the key + cert fingerprints; the user
//!    confirms it matches on both screens (defeats MITM).
//! 4. Each pins the other's certificate fingerprint — used thereafter by the
//!    transport's mutual-TLS verifier.
//!
//! Identity certificates are self-signed (no CA) and generated once at first
//! launch via [`generate_identity`].

pub mod sas;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub use sas::{short_auth_string, Sas};

/// Context string bound into the SPAKE2 transcript so a pairing exchange can't
/// be replayed in a different protocol/version.
const PAIRING_CONTEXT: &[u8] = b"kvm-lan-pairing-v1";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PairingError {
    #[error("certificate generation failed: {0}")]
    Cert(String),
    #[error("SPAKE2 failed: {0}")]
    Spake(String),
    #[error("pairing session already finished")]
    AlreadyFinished,
}

/// A freshly generated device TLS identity.
#[derive(Clone)]
pub struct GeneratedIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl std::fmt::Debug for GeneratedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedIdentity")
            .field("fingerprint", &fingerprint_hex(&self.fingerprint))
            .finish_non_exhaustive()
    }
}

/// SHA-256 fingerprint of a certificate (DER).
pub fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cert_der);
    h.finalize().into()
}

pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate this device's long-lived self-signed certificate + key.
pub fn generate_identity(device_id: Uuid) -> Result<GeneratedIdentity, PairingError> {
    let san = format!("{device_id}.kvm.local");
    let ck = rcgen::generate_simple_self_signed(vec![san])
        .map_err(|e| PairingError::Cert(e.to_string()))?;
    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.key_pair.serialize_der();
    let fingerprint = fingerprint(&cert_der);
    Ok(GeneratedIdentity {
        cert_der,
        key_der,
        fingerprint,
    })
}

/// A random 6-digit pairing code shown on one device, entered on the other.
pub fn generate_code() -> String {
    use rand::Rng;
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{n:06}")
}

/// One side of a SPAKE2 exchange. Symmetric: both peers call [`start`](Self::start)
/// with the same code, swap the produced messages, and [`finish`](Self::finish).
pub struct PairingSession {
    inner: Option<spake2::Spake2<spake2::Ed25519Group>>,
}

/// The outbound SPAKE2 message + the in-progress session.
pub struct PairingStart {
    pub session: PairingSession,
    pub outbound: Vec<u8>,
}

impl PairingSession {
    /// Begin pairing with the shared `code`. Returns the message to send to the
    /// peer and the session to finish once the peer's message arrives.
    pub fn start(code: &str) -> PairingStart {
        let (spake, outbound) = spake2::Spake2::<spake2::Ed25519Group>::start_symmetric(
            &spake2::Password::new(code.as_bytes()),
            &spake2::Identity::new(PAIRING_CONTEXT),
        );
        PairingStart {
            session: PairingSession { inner: Some(spake) },
            outbound,
        }
    }

    /// Complete the exchange with the peer's message, yielding the shared key.
    /// Note: SPAKE2 always yields *a* key; mismatched codes yield *different*
    /// keys, which the SAS comparison then catches.
    pub fn finish(mut self, inbound: &[u8]) -> Result<Vec<u8>, PairingError> {
        let spake = self.inner.take().ok_or(PairingError::AlreadyFinished)?;
        spake
            .finish(inbound)
            .map_err(|e| PairingError::Spake(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full in-process handshake: matching codes → identical key & SAS.
    #[test]
    fn matching_codes_agree() {
        let code = "428193";
        let a = PairingSession::start(code);
        let b = PairingSession::start(code);
        let key_a = a.session.finish(&b.outbound).unwrap();
        let key_b = b.session.finish(&a.outbound).unwrap();
        assert_eq!(key_a, key_b);

        let fp_a = [1u8; 32];
        let fp_b = [2u8; 32];
        assert_eq!(
            short_auth_string(&key_a, &fp_a, &fp_b),
            short_auth_string(&key_b, &fp_a, &fp_b)
        );
    }

    /// Mismatched codes → different keys → different SAS (user would reject).
    #[test]
    fn mismatched_codes_diverge() {
        let a = PairingSession::start("111111");
        let b = PairingSession::start("999999");
        let key_a = a.session.finish(&b.outbound).unwrap();
        let key_b = b.session.finish(&a.outbound).unwrap();
        assert_ne!(key_a, key_b);
        let (fp_a, fp_b) = ([7u8; 32], [8u8; 32]);
        assert_ne!(
            short_auth_string(&key_a, &fp_a, &fp_b),
            short_auth_string(&key_b, &fp_a, &fp_b)
        );
    }

    #[test]
    fn identity_generation_yields_stable_fingerprint() {
        let id = generate_identity(Uuid::nil()).unwrap();
        assert_eq!(id.fingerprint, fingerprint(&id.cert_der));
        assert_eq!(fingerprint_hex(&id.fingerprint).len(), 64);
        assert!(!id.key_der.is_empty());
    }

    #[test]
    fn codes_are_six_digits() {
        for _ in 0..50 {
            let c = generate_code();
            assert_eq!(c.len(), 6);
            assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        }
    }
}
