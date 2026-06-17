//! End-to-end: two engines over real QUIC + mock adapters. Verifies the full
//! handoff path (edge → switch → control), input forwarding, hotkey release, and
//! the transport-loss fail-safe (`release_all`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kvm_adapter_api::mock::{
    InjectionCall, MockCapture, MockClipboard, MockGeometry, MockInjection,
};
use kvm_adapter_api::{CursorGeometry, LocalInput, PlatformAdapters};
use kvm_core::{
    Capabilities, CertFingerprint, DeviceId, DeviceRegistry, Edge, FocusState, LayoutGraph,
    Platform, Rect, ScreenRegion, TrustState,
};
use kvm_engine::{spawn, EngineCommand, EngineConfig, EngineHandle};
use kvm_transport::{allowed_peers, Identity, QuicTransport, Transport};

fn ident() -> Identity {
    let ck = rcgen::generate_simple_self_signed(vec!["kvm.local".to_string()]).unwrap();
    Identity::new(ck.cert.der().to_vec(), ck.key_pair.serialize_der())
}

fn registry_with(peer: DeviceId, fp: [u8; 32]) -> DeviceRegistry {
    let mut r = DeviceRegistry::new();
    r.upsert_discovered(
        peer,
        "peer".into(),
        Platform::Linux,
        CertFingerprint(fp),
        Capabilities::default(),
        None,
    );
    r.mark_paired(peer, CertFingerprint(fp), TrustState::Trusted);
    r
}

struct Mocks {
    capture: MockCapture,
    injection: MockInjection,
    clipboard: MockClipboard,
    geometry: MockGeometry,
}

fn adapters() -> (PlatformAdapters, Mocks) {
    let capture = MockCapture::new();
    let injection = MockInjection::new();
    let clipboard = MockClipboard::new();
    let geometry = MockGeometry::single_1080p();
    let platform = PlatformAdapters {
        capture: Box::new(capture.clone()),
        injection: Box::new(injection.clone()),
        clipboard: Box::new(clipboard.clone()),
        geometry: Box::new(geometry.clone()),
    };
    (
        platform,
        Mocks {
            capture,
            injection,
            clipboard,
            geometry,
        },
    )
}

async fn wait_connected(h: &EngineHandle) {
    for _ in 0..150 {
        if let Some(s) = h.snapshot().await {
            if !s.connected_peers.is_empty() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("peer never connected");
}

async fn wait_focus(h: &EngineHandle, pred: impl Fn(FocusState) -> bool) -> FocusState {
    for _ in 0..200 {
        if let Some(s) = h.snapshot().await {
            if pred(s.focus) {
                return s.focus;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let s = h.snapshot().await.unwrap();
    panic!("focus condition never met; last = {:?}", s.focus);
}

/// Build A (controller) and B (controlled), connect them, and return handles.
async fn connected_pair() -> (EngineHandle, Mocks, DeviceId, EngineHandle, Mocks, DeviceId) {
    let a_id = DeviceId::generate();
    let b_id = DeviceId::generate();
    let a_ident = ident();
    let b_ident = ident();
    let a_fp = a_ident.fingerprint;
    let b_fp = b_ident.fingerprint;

    let a_tx: Arc<dyn Transport> = Arc::new(
        QuicTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            a_ident,
            allowed_peers([b_fp]),
        )
        .unwrap(),
    );
    let b_tx: Arc<dyn Transport> = Arc::new(
        QuicTransport::bind(
            "127.0.0.1:0".parse().unwrap(),
            b_ident,
            allowed_peers([a_fp]),
        )
        .unwrap(),
    );
    let b_addr: SocketAddr = b_tx.local_addr().unwrap();

    let (a_ad, a_mocks) = adapters();
    let (b_ad, b_mocks) = adapters();

    let a = spawn(
        EngineConfig {
            device_id: a_id,
            device_name: "A".into(),
            platform: Platform::Linux,
            source_slot: 1,
            downloads_dir: std::env::temp_dir(),
        },
        a_tx,
        a_ad,
        registry_with(b_id, b_fp),
    );
    let b = spawn(
        EngineConfig {
            device_id: b_id,
            device_name: "B".into(),
            platform: Platform::Linux,
            source_slot: 2,
            downloads_dir: std::env::temp_dir(),
        },
        b_tx,
        b_ad,
        registry_with(a_id, a_fp),
    );

    // A's layout: A on the left of B (so the right edge hands off to B).
    let mut layout = LayoutGraph::new();
    layout.upsert_region(ScreenRegion {
        device: a_id,
        bounds: Rect::new(0, 0, 1920, 1080),
        scale: 1.0,
    });
    layout.upsert_region(ScreenRegion {
        device: b_id,
        bounds: Rect::new(0, 0, 1920, 1080),
        scale: 1.0,
    });
    layout.link_bidirectional(a_id, Edge::Right, b_id);
    a.set_layout(layout).await;

    a.connect_peer(b_id, b_addr, b_fp).await;
    wait_connected(&a).await;
    wait_connected(&b).await;

    (a, a_mocks, a_id, b, b_mocks, b_id)
}

/// Drive A's cursor into the shared edge until the handoff commits.
async fn drive_to_edge(a_mocks: &Mocks) {
    for _ in 0..6 {
        a_mocks
            .capture
            .emit(LocalInput::MouseMoveAbs { x: 1919, y: 540 });
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

#[tokio::test]
async fn edge_handoff_forwards_input_and_releases() {
    let (a, a_mocks, _a_id, b, b_mocks, b_id) = connected_pair().await;

    // 1) Cursor to the right edge → A takes control of B.
    drive_to_edge(&a_mocks).await;
    let fa = wait_focus(&a, |f| matches!(f, FocusState::RemoteControl { .. })).await;
    assert_eq!(fa, FocusState::RemoteControl { target: b_id });
    wait_focus(&b, |f| matches!(f, FocusState::Receiving { .. })).await;

    // 2) A types a key → forwarded over the datagram path → injected on B.
    a_mocks.capture.emit(LocalInput::Key {
        code: 30,
        pressed: true,
    });
    for _ in 0..100 {
        if b_mocks
            .injection
            .calls()
            .contains(&InjectionCall::Key(30, true))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        b_mocks
            .injection
            .calls()
            .contains(&InjectionCall::Key(30, true)),
        "key was not injected on the controlled peer: {:?}",
        b_mocks.injection.calls()
    );

    // 3) Hotkey release → both return to local control; B flushes held keys.
    a.release().await;
    wait_focus(&a, |f| matches!(f, FocusState::LocalControl)).await;
    wait_focus(&b, |f| matches!(f, FocusState::LocalControl)).await;
    assert!(b_mocks.injection.release_all_count() >= 1);

    a.send(EngineCommand::Shutdown).await;
    b.send(EngineCommand::Shutdown).await;
}

#[tokio::test]
async fn handoff_hides_grabs_and_parks_local_cursor() {
    // The "one crosshair" guarantee: on handoff the controller grabs local input,
    // hides its own cursor, and parks it at screen center — so exactly one visible
    // cursor exists. Releasing restores all of that (fail-safe).
    let (a, a_mocks, _a_id, b, _b_mocks, _b_id) = connected_pair().await;

    drive_to_edge(&a_mocks).await;
    wait_focus(&a, |f| matches!(f, FocusState::RemoteControl { .. })).await;

    assert!(
        a_mocks.capture.is_exclusive(),
        "controller must grab (suppress) local input while driving the peer"
    );
    assert!(
        a_mocks.geometry.is_hidden(),
        "controller must hide its local cursor — only one crosshair may be visible"
    );
    let pos = a_mocks.geometry.cursor_position().unwrap();
    assert_eq!(
        (pos.x, pos.y),
        (960, 540),
        "local cursor must be parked at screen center so motion never pins at an edge"
    );

    a.release().await;
    wait_focus(&a, |f| matches!(f, FocusState::LocalControl)).await;
    assert!(
        !a_mocks.geometry.is_hidden(),
        "local cursor must be restored when control returns home"
    );
    assert!(
        !a_mocks.capture.is_exclusive(),
        "input grab must be released when control returns home"
    );

    a.send(EngineCommand::Shutdown).await;
    b.send(EngineCommand::Shutdown).await;
}

#[tokio::test]
async fn forwards_absolute_position_in_peer_resolution() {
    // Resolution match: with B a *larger* 2560x1440 screen, the controller must
    // forward an ABSOLUTE position in B's own pixel space — not the controller's
    // 1080p coordinates. This is the fix for "the language between the two
    // devices is broken".
    let (a, a_mocks, a_id, b, b_mocks, b_id) = connected_pair().await;

    let mut layout = LayoutGraph::new();
    layout.upsert_region(ScreenRegion {
        device: a_id,
        bounds: Rect::new(0, 0, 1920, 1080),
        scale: 1.0,
    });
    layout.upsert_region(ScreenRegion {
        device: b_id,
        bounds: Rect::new(1920, 0, 2560, 1440),
        scale: 1.0,
    });
    layout.link_bidirectional(a_id, Edge::Right, b_id);
    a.set_layout(layout).await;

    // Use a manual switch (not an edge graze) so the entry point is exact and no
    // stray edge samples perturb the virtual cursor before our single move.
    a.manual_switch(b_id).await;
    wait_focus(&a, |f| matches!(f, FocusState::RemoteControl { .. })).await;
    wait_focus(&b, |f| matches!(f, FocusState::Receiving { .. })).await;

    // Entry is B's left edge at the vertical midpoint → (1928, 720) in layout
    // space; the local cursor is parked at center (960, 540). A (+10,+5) physical
    // move → virtual (1938, 725) → B-local pixels (18, 725).
    a_mocks
        .capture
        .emit(LocalInput::MouseMoveAbs { x: 970, y: 545 });
    let want = InjectionCall::MoveAbs(18, 725);
    for _ in 0..100 {
        if b_mocks.injection.calls().contains(&want) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        b_mocks.injection.calls().contains(&want),
        "expected absolute {want:?} in B's pixel space; got {:?}",
        b_mocks.injection.calls()
    );

    a.send(EngineCommand::Shutdown).await;
    b.send(EngineCommand::Shutdown).await;
}

#[tokio::test]
async fn extended_cursor_crosses_back_over_the_seam() {
    let (a, a_mocks, _a_id, b, b_mocks, _b_id) = connected_pair().await;

    // Cross A -> B by hitting the right edge.
    drive_to_edge(&a_mocks).await;
    wait_focus(&a, |f| matches!(f, FocusState::RemoteControl { .. })).await;
    wait_focus(&b, |f| matches!(f, FocusState::Receiving { .. })).await;

    // Now move the (virtual) cursor back left across B's left edge: control must
    // return home to A on its own — no hotkey/release needed.
    for _ in 0..6 {
        a_mocks
            .capture
            .emit(LocalInput::MouseMoveAbs { x: 50, y: 540 });
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    wait_focus(&a, |f| matches!(f, FocusState::LocalControl)).await;
    wait_focus(&b, |f| matches!(f, FocusState::LocalControl)).await;
    let _ = &b_mocks;

    a.send(EngineCommand::Shutdown).await;
    b.send(EngineCommand::Shutdown).await;
}

#[tokio::test]
async fn transport_loss_releases_on_receiver() {
    let (a, a_mocks, _a_id, b, b_mocks, _b_id) = connected_pair().await;

    drive_to_edge(&a_mocks).await;
    wait_focus(&a, |f| matches!(f, FocusState::RemoteControl { .. })).await;
    wait_focus(&b, |f| matches!(f, FocusState::Receiving { .. })).await;

    // Kill the controller. B must detect the drop, return to local control, and
    // release any held keys (fail-safe — never leave B stranded).
    a.send(EngineCommand::Shutdown).await;

    wait_focus(&b, |f| matches!(f, FocusState::LocalControl)).await;
    assert!(
        b_mocks.injection.release_all_count() >= 1,
        "receiver must release all keys on transport loss"
    );
}

#[tokio::test]
async fn clipboard_text_syncs_with_default_policy() {
    let (a, _a_mocks, _a_id, b, b_mocks, _b_id) = connected_pair().await;

    a.send(EngineCommand::LocalClipboardChanged("hello world".into()))
        .await;

    for _ in 0..100 {
        if b_mocks.clipboard.current() == Some("hello world".to_string()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(b_mocks.clipboard.current(), Some("hello world".to_string()));

    a.send(EngineCommand::Shutdown).await;
    b.send(EngineCommand::Shutdown).await;
}
