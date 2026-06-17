//! Certificate-pinning mutual TLS.
//!
//! There is no CA on a LAN. Instead, each device has a self-signed certificate
//! whose SHA-256 fingerprint is exchanged during pairing. Both the client and
//! server sides install a custom verifier that accepts a peer **iff** the
//! presented end-entity certificate hashes to a pinned/allowed fingerprint.
//! Signature validity is still checked via the crypto provider, so a peer must
//! actually possess the matching private key — pinning the fingerprint is what
//! defeats impersonation.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::error::TransportError;
use crate::identity::{sha256, Identity};

/// The set of peer fingerprints a server endpoint will accept. Shared + RwLocked
/// so the engine can add a freshly-paired peer without rebuilding the endpoint.
pub type AllowedPeers = Arc<RwLock<HashSet<[u8; 32]>>>;

pub fn allowed_peers<I: IntoIterator<Item = [u8; 32]>>(iter: I) -> AllowedPeers {
    Arc::new(RwLock::new(iter.into_iter().collect()))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Ensure a process-wide default provider exists (some quinn/rustls paths look
/// it up). Idempotent; ignores the "already installed" outcome.
pub fn ensure_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn cert_fp(cert: &CertificateDer<'_>) -> [u8; 32] {
    sha256(cert.as_ref())
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Client-side verifier: pins exactly one server fingerprint.
#[derive(Debug)]
struct PinnedServerVerifier {
    pinned: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_fp(end_entity) == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned server certificate fingerprint mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server-side verifier: accepts any client whose fingerprint is in the allowed
/// set (the set of currently-paired peers).
#[derive(Debug)]
struct PinnedClientVerifier {
    allowed: AllowedPeers,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp = cert_fp(end_entity);
        let allowed = self
            .allowed
            .read()
            .map_err(|_| rustls::Error::General("allowed-peers lock poisoned".into()))?;
        if allowed.contains(&fp) {
            Ok(ClientCertVerified::assertion())
        } else {
            let trusted: Vec<String> = allowed.iter().map(hex32).collect();
            tracing::warn!(
                peer_presented = %hex32(&fp),
                we_trust = ?trusted,
                "REJECTED inbound peer: its fingerprint is not in our trusted set. \
                 The `peer_presented` value must exactly match a `we_trust` entry — \
                 if it doesn't, that peer's identity changed (old build / state not cleared) \
                 or the wrong fingerprint was paired."
            );
            Err(rustls::Error::General(
                "client certificate fingerprint not in allowed set".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn our_cert_and_key(id: &Identity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    (vec![cert], key)
}

/// Build a TLS 1.3 client config that pins `peer_fingerprint` and presents our
/// own client certificate for mutual auth.
pub fn client_config(
    id: &Identity,
    peer_fingerprint: [u8; 32],
) -> Result<rustls::ClientConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(PinnedServerVerifier {
        pinned: peer_fingerprint,
        provider: provider.clone(),
    });
    let (certs, key) = our_cert_and_key(id);
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|e| TransportError::Tls(e.to_string()))
}

/// Build a TLS 1.3 server config that accepts any client in `allowed` and
/// presents our own certificate.
pub fn server_config(
    id: &Identity,
    allowed: AllowedPeers,
) -> Result<rustls::ServerConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(PinnedClientVerifier {
        allowed,
        provider: provider.clone(),
    });
    let (certs, key) = our_cert_and_key(id);
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| TransportError::Tls(e.to_string()))
}

/// Compute the fingerprint of a peer certificate presented during a handshake
/// (used on the server side to learn which paired peer connected).
pub fn fingerprint_of_cert(cert: &CertificateDer<'_>) -> [u8; 32] {
    cert_fp(cert)
}
