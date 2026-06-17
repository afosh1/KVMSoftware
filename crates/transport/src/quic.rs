//! QUIC transport (primary) via `quinn`.
//!
//! * Hot-path input → unreliable datagrams (fire-and-forget).
//! * Control / clipboard / files → separate bidirectional streams (each tagged
//!   with its [`StreamKind`]) so a large transfer never head-of-line-blocks
//!   time-sensitive control traffic.
//! * Mutual auth via the pinned-certificate verifiers in [`crate::pinning`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};

use kvm_proto::codec::{decode, encode_frame, FrameDecoder};
use kvm_proto::v1::control::{ControlMsg, StreamKind};

use crate::error::TransportError;
use crate::health::ConnectionHealth;
use crate::identity::Identity;
use crate::pinning::{self, AllowedPeers};
use crate::stream::{kind_tag, tag_kind, MsgStream};
use crate::{Connection, Transport};

/// Idle timeout + keep-alive applied to every QUIC connection. The keep-alive is
/// the transport-level heartbeat that holds the path open during quiet periods.
fn transport_config() -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("30s is a valid idle timeout"),
    ));
    tc.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(tc)
}

pub struct QuicTransport {
    endpoint: Endpoint,
    identity: Arc<Identity>,
}

impl QuicTransport {
    /// Bind a dual-role (server + client) QUIC endpoint.
    pub fn bind(
        bind: SocketAddr,
        identity: Identity,
        allowed: AllowedPeers,
    ) -> Result<Self, TransportError> {
        pinning::ensure_default_provider();
        let identity = Arc::new(identity);
        let rustls_server = pinning::server_config(&identity, allowed)?;
        let qsc = QuicServerConfig::try_from(rustls_server)
            .map_err(|e| TransportError::Config(e.to_string()))?;
        let mut server_cfg = ServerConfig::with_crypto(Arc::new(qsc));
        server_cfg.transport_config(transport_config());
        let endpoint = Endpoint::server(server_cfg, bind)?;
        Ok(QuicTransport { endpoint, identity })
    }

    /// Bind on the stable [`crate::DEFAULT_PORT`], falling back to an ephemeral
    /// port if it is already in use.
    pub fn bind_lan(identity: Identity, allowed: AllowedPeers) -> Result<Self, TransportError> {
        let default: SocketAddr = ([0, 0, 0, 0], crate::DEFAULT_PORT).into();
        match Self::bind(default, identity.clone(), allowed.clone()) {
            Ok(t) => Ok(t),
            Err(_) => Self::bind(([0, 0, 0, 0], 0).into(), identity, allowed),
        }
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn connect(
        &self,
        addr: SocketAddr,
        peer_fingerprint: [u8; 32],
        server_name: &str,
    ) -> Result<Box<dyn Connection>, TransportError> {
        let rustls_client = pinning::client_config(&self.identity, peer_fingerprint)?;
        let qcc = QuicClientConfig::try_from(rustls_client)
            .map_err(|e| TransportError::Config(e.to_string()))?;
        let mut client_cfg = ClientConfig::new(Arc::new(qcc));
        client_cfg.transport_config(transport_config());

        let connecting = self
            .endpoint
            .connect_with(client_cfg, addr, server_name)
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let conn = connecting
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        Ok(Box::new(QuicConnection {
            conn,
            peer_fp: peer_fingerprint,
        }))
    }

    async fn accept(&self) -> Option<Result<Box<dyn Connection>, TransportError>> {
        let incoming = self.endpoint.accept().await?;
        Some(accept_one(incoming).await)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(Into::into)
    }
}

async fn accept_one(incoming: quinn::Incoming) -> Result<Box<dyn Connection>, TransportError> {
    let conn = incoming
        .await
        .map_err(|e| TransportError::Connect(e.to_string()))?;
    // The client cert was already pinned-verified by the server config; here we
    // just learn *which* paired peer it was.
    let peer_fp = peer_fp_from_conn(&conn).ok_or(TransportError::FingerprintMismatch)?;
    Ok(Box::new(QuicConnection { conn, peer_fp }))
}

fn peer_fp_from_conn(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let first = certs.first()?;
    Some(pinning::fingerprint_of_cert(first))
}

pub struct QuicConnection {
    conn: quinn::Connection,
    peer_fp: [u8; 32],
}

#[async_trait]
impl Connection for QuicConnection {
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), TransportError> {
        self.conn
            .send_datagram(bytes)
            .map_err(|e| TransportError::Stream(e.to_string()))
    }

    async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.conn
            .read_datagram()
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn open_stream(&self, kind: StreamKind) -> Result<Box<dyn MsgStream>, TransportError> {
        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        send.write_all(&[kind_tag(kind)])
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        Ok(Box::new(QuicStream::new(send, recv)))
    }

    async fn accept_stream(&self) -> Result<(StreamKind, Box<dyn MsgStream>), TransportError> {
        let (send, mut recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let mut tag = [0u8; 1];
        recv.read_exact(&mut tag)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let kind = tag_kind(tag[0])?;
        Ok((kind, Box::new(QuicStream::new(send, recv))))
    }

    fn health(&self) -> ConnectionHealth {
        ConnectionHealth {
            rtt: self.conn.rtt(),
        }
    }

    fn peer_fingerprint(&self) -> [u8; 32] {
        self.peer_fp
    }

    async fn close(&self, code: u32, reason: String) {
        self.conn.close(code.into(), reason.as_bytes());
    }
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    dec: FrameDecoder,
}

impl QuicStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicStream {
            send,
            recv,
            dec: FrameDecoder::new(),
        }
    }
}

#[async_trait]
impl MsgStream for QuicStream {
    async fn send(&mut self, msg: &ControlMsg) -> Result<(), TransportError> {
        let frame = encode_frame(msg)?;
        self.send
            .write_all(&frame)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))
    }

    async fn recv(&mut self) -> Result<Option<ControlMsg>, TransportError> {
        loop {
            if let Some(body) = self.dec.next_frame()? {
                return Ok(Some(decode(&body)?));
            }
            let mut buf = [0u8; 16 * 1024];
            match self
                .recv
                .read(&mut buf)
                .await
                .map_err(|e| TransportError::Stream(e.to_string()))?
            {
                Some(n) if n > 0 => self.dec.push(&buf[..n]),
                _ => return Ok(None), // clean finish
            }
        }
    }

    async fn finish(&mut self) -> Result<(), TransportError> {
        self.send
            .finish()
            .map_err(|e| TransportError::Stream(e.to_string()))
    }
}
