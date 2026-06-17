//! TCP + TLS 1.3 fallback transport (reliable-only).
//!
//! Used when a network blocks/rate-limits UDP and QUIC can't establish. A single
//! mutually-authenticated TLS connection carries everything, multiplexed by a
//! tiny framing layer so the [`Connection`]/[`MsgStream`] API is identical to
//! QUIC's. Trade-off (documented): being a single TCP stream, this reintroduces
//! head-of-line blocking and higher input latency — acceptable for a fallback.
//!
//! Frame: `[type:u8][channel:u32 LE][len:u32 LE][body]`.
//!   type 0 DATA(channel) · 1 OPEN(channel, [kind]) · 2 FIN(channel) · 3 DATAGRAM

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use rustls::pki_types::{CertificateDer, ServerName};

use kvm_proto::codec::{decode, encode, MAX_FRAME_LEN};
use kvm_proto::v1::control::{ControlMsg, StreamKind};

use crate::error::TransportError;
use crate::health::ConnectionHealth;
use crate::identity::Identity;
use crate::pinning::{self, AllowedPeers};
use crate::stream::{kind_tag, tag_kind, MsgStream};
use crate::{Connection, Transport};

const F_DATA: u8 = 0;
const F_OPEN: u8 = 1;
const F_FIN: u8 = 2;
const F_DATAGRAM: u8 = 3;

type Registry = Arc<Mutex<HashMap<u32, mpsc::Sender<Option<ControlMsg>>>>>;

fn frame(ftype: u8, channel: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + body.len());
    v.push(ftype);
    v.extend_from_slice(&channel.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

pub struct TlsTcpTransport {
    listener: TcpListener,
    identity: Arc<Identity>,
    allowed: AllowedPeers,
}

impl TlsTcpTransport {
    pub async fn bind(
        addr: SocketAddr,
        identity: Identity,
        allowed: AllowedPeers,
    ) -> Result<Self, TransportError> {
        pinning::ensure_default_provider();
        let listener = TcpListener::bind(addr).await?;
        Ok(TlsTcpTransport {
            listener,
            identity: Arc::new(identity),
            allowed,
        })
    }
}

#[async_trait]
impl Transport for TlsTcpTransport {
    async fn connect(
        &self,
        addr: SocketAddr,
        peer_fingerprint: [u8; 32],
        server_name: &str,
    ) -> Result<Box<dyn Connection>, TransportError> {
        let cfg = pinning::client_config(&self.identity, peer_fingerprint)?;
        let connector = TlsConnector::from(Arc::new(cfg));
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let dns = ServerName::try_from(server_name.to_string())
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let tls = connector.connect(dns, tcp).await?;
        let peer_fp = peer_cert_fp(tls.get_ref().1.peer_certificates()).unwrap_or(peer_fingerprint);
        Ok(build_conn(tls, peer_fp, true))
    }

    async fn accept(&self) -> Option<Result<Box<dyn Connection>, TransportError>> {
        let res = self.accept_one().await;
        Some(res)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(Into::into)
    }
}

impl TlsTcpTransport {
    async fn accept_one(&self) -> Result<Box<dyn Connection>, TransportError> {
        let (tcp, _peer) = self.listener.accept().await?;
        tcp.set_nodelay(true)?;
        let cfg = pinning::server_config(&self.identity, self.allowed.clone())?;
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let tls = acceptor.accept(tcp).await?;
        let peer_fp = peer_cert_fp(tls.get_ref().1.peer_certificates())
            .ok_or(TransportError::FingerprintMismatch)?;
        Ok(build_conn(tls, peer_fp, false))
    }
}

fn peer_cert_fp(certs: Option<&[CertificateDer<'_>]>) -> Option<[u8; 32]> {
    certs?.first().map(pinning::fingerprint_of_cert)
}

fn build_conn<S>(tls: S, peer_fp: [u8; 32], is_client: bool) -> Box<dyn Connection>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (rd, wr) = tokio::io::split(tls);
    let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(256);
    let (datagram_tx, datagram_rx) = mpsc::channel::<Bytes>(256);
    let (accept_tx, accept_rx) = mpsc::channel::<(StreamKind, TlsStream)>(32);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(writer_task(wr, writer_rx));
    tokio::spawn(reader_task(
        rd,
        datagram_tx,
        accept_tx,
        writer_tx.clone(),
        registry.clone(),
    ));

    // Client opens even channel ids, server odd, so the two never collide.
    let base = if is_client { 0 } else { 1 };
    Box::new(TlsConn {
        peer_fp,
        writer_tx,
        datagram_rx: tokio::sync::Mutex::new(datagram_rx),
        accept_rx: tokio::sync::Mutex::new(accept_rx),
        registry,
        next_channel: AtomicU32::new(base),
    })
}

async fn writer_task<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
            break;
        }
    }
}

async fn reader_task<R: AsyncRead + Unpin>(
    mut rd: R,
    datagram_tx: mpsc::Sender<Bytes>,
    accept_tx: mpsc::Sender<(StreamKind, TlsStream)>,
    writer_tx: mpsc::Sender<Vec<u8>>,
    registry: Registry,
) {
    let mut hdr = [0u8; 9];
    loop {
        if rd.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let ftype = hdr[0];
        let channel = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let len = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
        if len > MAX_FRAME_LEN {
            break;
        }
        let mut body = vec![0u8; len];
        if len > 0 && rd.read_exact(&mut body).await.is_err() {
            break;
        }

        match ftype {
            F_DATAGRAM => {
                let _ = datagram_tx.send(Bytes::from(body)).await;
            }
            F_OPEN => {
                let kind = match tag_kind(body.first().copied().unwrap_or(255)) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                let (in_tx, in_rx) = mpsc::channel(128);
                registry.lock().unwrap().insert(channel, in_tx);
                let stream = TlsStream {
                    channel,
                    writer_tx: writer_tx.clone(),
                    inbound_rx: in_rx,
                };
                let _ = accept_tx.send((kind, stream)).await;
            }
            F_DATA => {
                if let Ok(msg) = decode::<ControlMsg>(&body) {
                    let tx = registry.lock().unwrap().get(&channel).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(Some(msg)).await;
                    }
                }
            }
            F_FIN => {
                let tx = registry.lock().unwrap().remove(&channel);
                if let Some(tx) = tx {
                    let _ = tx.send(None).await;
                }
            }
            _ => {}
        }
    }

    // Connection ended: notify every open stream of the close.
    let entries: Vec<_> = registry.lock().unwrap().drain().collect();
    for (_id, tx) in entries {
        let _ = tx.send(None).await;
    }
}

pub struct TlsConn {
    peer_fp: [u8; 32],
    writer_tx: mpsc::Sender<Vec<u8>>,
    datagram_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(StreamKind, TlsStream)>>,
    registry: Registry,
    next_channel: AtomicU32,
}

#[async_trait]
impl Connection for TlsConn {
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), TransportError> {
        self.writer_tx
            .send(frame(F_DATAGRAM, 0, &bytes))
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.datagram_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::Closed)
    }

    async fn open_stream(&self, kind: StreamKind) -> Result<Box<dyn MsgStream>, TransportError> {
        let channel = self.next_channel.fetch_add(2, Ordering::Relaxed);
        let (in_tx, in_rx) = mpsc::channel(128);
        self.registry.lock().unwrap().insert(channel, in_tx);
        self.writer_tx
            .send(frame(F_OPEN, channel, &[kind_tag(kind)]))
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok(Box::new(TlsStream {
            channel,
            writer_tx: self.writer_tx.clone(),
            inbound_rx: in_rx,
        }))
    }

    async fn accept_stream(&self) -> Result<(StreamKind, Box<dyn MsgStream>), TransportError> {
        let (kind, stream) = self
            .accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::Closed)?;
        Ok((kind, Box::new(stream)))
    }

    fn health(&self) -> ConnectionHealth {
        // TCP exposes no app-meaningful RTT here; the engine measures it via
        // control-plane heartbeats instead.
        ConnectionHealth {
            rtt: Duration::ZERO,
        }
    }

    fn peer_fingerprint(&self) -> [u8; 32] {
        self.peer_fp
    }

    async fn close(&self, _code: u32, _reason: String) {
        // Dropping the connection (and thus all writer_tx senders) ends the
        // writer task and tears down the TLS stream.
    }
}

pub struct TlsStream {
    channel: u32,
    writer_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: mpsc::Receiver<Option<ControlMsg>>,
}

#[async_trait]
impl MsgStream for TlsStream {
    async fn send(&mut self, msg: &ControlMsg) -> Result<(), TransportError> {
        let body = encode(msg)?;
        self.writer_tx
            .send(frame(F_DATA, self.channel, &body))
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn recv(&mut self) -> Result<Option<ControlMsg>, TransportError> {
        match self.inbound_rx.recv().await {
            Some(Some(msg)) => Ok(Some(msg)),
            _ => Ok(None),
        }
    }

    async fn finish(&mut self) -> Result<(), TransportError> {
        self.writer_tx
            .send(frame(F_FIN, self.channel, &[]))
            .await
            .map_err(|_| TransportError::Closed)
    }
}
