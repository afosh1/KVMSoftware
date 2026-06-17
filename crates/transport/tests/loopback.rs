//! Loopback integration tests for both transports over 127.0.0.1.
//!
//! Covers: mutual pinned-cert handshake, reliable stream message exchange,
//! hot-path datagrams, fingerprint-mismatch rejection, and the TCP/TLS fallback.

use bytes::Bytes;

use kvm_proto::codec::{decode, encode};
use kvm_proto::v1::control::ControlMsg;
use kvm_proto::v1::handshake::{Capabilities, Hello, Platform, ScreenGeom};
use kvm_proto::v1::input::{InputEvent, InputKind};
use kvm_transport::{
    allowed_peers, Connection, Identity, QuicTransport, StreamKind, TlsTcpTransport, Transport,
    SERVER_NAME,
};

fn gen_identity() -> Identity {
    let ck = rcgen::generate_simple_self_signed(vec!["kvm.local".to_string()]).unwrap();
    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.key_pair.serialize_der();
    Identity::new(cert_der, key_der)
}

fn hello(name: &str) -> ControlMsg {
    ControlMsg::Hello(Hello {
        protocol_version: 1,
        device_id: uuid::Uuid::nil(),
        device_name: name.to_string(),
        platform: Platform::Linux,
        capabilities: Capabilities::default(),
        source_slot: 1,
        screen: ScreenGeom::default(),
    })
}

/// Run a full handshake + stream + datagram exchange and assert both ends agree.
async fn exchange(server: Box<dyn Connection>, client: Box<dyn Connection>, client_fp: [u8; 32]) {
    // Server side: accept a control stream, read a Hello, then a datagram.
    let server_task = tokio::spawn(async move {
        assert_eq!(server.peer_fingerprint(), client_fp);
        let (kind, mut s) = server.accept_stream().await.unwrap();
        assert_eq!(kind, StreamKind::Control);
        match s.recv().await.unwrap().unwrap() {
            ControlMsg::Hello(h) => assert_eq!(h.device_name, "client"),
            other => panic!("expected Hello, got {other:?}"),
        }
        let dg = server.recv_datagram().await.unwrap();
        let ev: InputEvent = decode(&dg).unwrap();
        assert_eq!(ev.seq, 7);
        // keep the connection alive until the client is done
        let _ = server;
    });

    let mut s = client.open_stream(StreamKind::Control).await.unwrap();
    s.send(&hello("client")).await.unwrap();
    let ev = InputEvent::new(1, 7, InputKind::MouseMoveRel { dx: 3, dy: -2 });
    client
        .send_datagram(Bytes::from(encode(&ev).unwrap()))
        .await
        .unwrap();

    server_task.await.unwrap();
    let _ = client; // hold the client connection open across the exchange
}

#[tokio::test]
async fn quic_pinned_mutual_tls_roundtrip() {
    let a = gen_identity();
    let b = gen_identity();
    let (a_fp, b_fp) = (a.fingerprint, b.fingerprint);

    let server =
        QuicTransport::bind("127.0.0.1:0".parse().unwrap(), a, allowed_peers([b_fp])).unwrap();
    let client =
        QuicTransport::bind("127.0.0.1:0".parse().unwrap(), b, allowed_peers([a_fp])).unwrap();
    let addr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move { server.accept().await.unwrap().unwrap() });
    let client_conn = client.connect(addr, a_fp, SERVER_NAME).await.unwrap();
    assert_eq!(client_conn.peer_fingerprint(), a_fp);
    let server_conn = accept.await.unwrap();

    exchange(server_conn, client_conn, b_fp).await;
    // keep `client` endpoint alive until the end
    drop(client);
}

#[tokio::test]
async fn quic_rejects_unpinned_peer() {
    let a = gen_identity();
    let b = gen_identity();
    let (a_fp, b_fp) = (a.fingerprint, b.fingerprint);
    let wrong_fp = [0xAAu8; 32];

    let server =
        QuicTransport::bind("127.0.0.1:0".parse().unwrap(), a, allowed_peers([b_fp])).unwrap();
    let client =
        QuicTransport::bind("127.0.0.1:0".parse().unwrap(), b, allowed_peers([a_fp])).unwrap();
    let addr = server.local_addr().unwrap();

    // Server may see a failing handshake; just drain it.
    let _accept = tokio::spawn(async move {
        let _ = server.accept().await;
    });

    // Client pins the WRONG server fingerprint → handshake must fail.
    let res = client.connect(addr, wrong_fp, SERVER_NAME).await;
    assert!(res.is_err(), "connection with wrong pinned fp must fail");
}

#[tokio::test]
async fn tls_tcp_fallback_roundtrip() {
    let a = gen_identity();
    let b = gen_identity();
    let (a_fp, b_fp) = (a.fingerprint, b.fingerprint);

    let server = TlsTcpTransport::bind("127.0.0.1:0".parse().unwrap(), a, allowed_peers([b_fp]))
        .await
        .unwrap();
    let client = TlsTcpTransport::bind("127.0.0.1:0".parse().unwrap(), b, allowed_peers([a_fp]))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move { server.accept().await.unwrap().unwrap() });
    let client_conn = client.connect(addr, a_fp, SERVER_NAME).await.unwrap();
    let server_conn = accept.await.unwrap();

    exchange(server_conn, client_conn, b_fp).await;
    drop(client);
}
