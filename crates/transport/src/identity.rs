use sha2::{Digest, Sha256};

/// This device's TLS identity: its self-signed certificate (DER), its private
/// key (PKCS#8 DER), and the SHA-256 fingerprint peers pin during pairing.
///
/// Certificate *generation* lives in `kvm-pairing`; this type just carries the
/// material and derives the fingerprint the transport's verifier checks.
#[derive(Clone)]
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Identity {
    pub fn new(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        let fingerprint = sha256(&cert_der);
        Identity {
            cert_der,
            key_der,
            fingerprint,
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log key material.
        f.debug_struct("Identity")
            .field("fingerprint", &hex8(&self.fingerprint))
            .finish_non_exhaustive()
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hex8(fp: &[u8; 32]) -> String {
    fp.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
