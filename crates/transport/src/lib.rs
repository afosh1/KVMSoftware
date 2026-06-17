#![forbid(unsafe_code)]
//! Encrypted transport for the LAN KVM.
//!
//! Primary: [`quic::QuicTransport`] (QUIC via quinn — unreliable datagrams for
//! hot-path input, reliable streams for control/clipboard/files). Fallback:
//! [`tls_tcp::TlsTcpTransport`] (reliable-only, for networks that block UDP).
//! Both use the same pinned mutual-TLS identity ([`Identity`] + [`pinning`]).
//!
//! The engine programs against the [`Transport`] / [`Connection`] / [`MsgStream`]
//! traits, so swapping QUIC for the fallback is transparent.

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;

pub mod error;
pub mod health;
pub mod identity;
pub mod pinning;
pub mod quic;
pub mod stream;
pub mod tls_tcp;

pub use error::TransportError;
pub use health::ConnectionHealth;
pub use identity::Identity;
pub use pinning::{allowed_peers, AllowedPeers};
pub use quic::QuicTransport;
pub use stream::MsgStream;
pub use tls_tcp::TlsTcpTransport;

pub use kvm_proto::v1::control::StreamKind;

/// Default SNI presented on dial. Our verifier ignores the name (it pins the
/// fingerprint), but a syntactically-valid name is still required.
pub const SERVER_NAME: &str = "kvm.local";

/// Default LAN UDP port for the QUIC endpoint. A *stable* port (vs. an ephemeral
/// one) keeps the mDNS advert constant across restarts and lets users add a
/// firewall rule. [`QuicTransport::bind_lan`] falls back to an ephemeral port if
/// this one is already in use.
pub const DEFAULT_PORT: u16 = 47823;

/// A bound endpoint that can both dial and accept mutually-authenticated peers.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Dial `addr`, pinning the peer's certificate `peer_fingerprint`.
    async fn connect(
        &self,
        addr: SocketAddr,
        peer_fingerprint: [u8; 32],
        server_name: &str,
    ) -> Result<Box<dyn Connection>, TransportError>;

    /// Accept the next inbound, already-authenticated connection. `None` when the
    /// endpoint is shut down.
    async fn accept(&self) -> Option<Result<Box<dyn Connection>, TransportError>>;

    fn local_addr(&self) -> Result<SocketAddr, TransportError>;
}

/// A live, mutually-authenticated link to one peer.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send a hot-path datagram (unreliable; may be dropped). On the TCP/TLS
    /// fallback this is delivered reliably over a dedicated NODELAY substream.
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), TransportError>;

    /// Receive the next hot-path datagram.
    async fn recv_datagram(&self) -> Result<Bytes, TransportError>;

    /// Open a reliable, ordered stream of the given kind.
    async fn open_stream(&self, kind: StreamKind) -> Result<Box<dyn MsgStream>, TransportError>;

    /// Accept the next inbound reliable stream (tag-classified).
    async fn accept_stream(&self) -> Result<(StreamKind, Box<dyn MsgStream>), TransportError>;

    fn health(&self) -> ConnectionHealth;

    /// SHA-256 fingerprint of the authenticated peer's certificate.
    fn peer_fingerprint(&self) -> [u8; 32];

    async fn close(&self, code: u32, reason: String);
}
