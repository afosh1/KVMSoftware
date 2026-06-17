#![forbid(unsafe_code)]
//! Engine — the orchestrator.
//!
//! Owns the tokio runtime tasks and a single-threaded **actor** that holds all
//! mutable state (registry, layout, focus/session state machines, policies,
//! peer links). Everything reaches it through channels, so there are no locks on
//! the hot path and the domain stays the sole source of truth.
//!
//! Data flow:
//! * OS capture → `capture_rx` → focus logic → either an edge transition or a
//!   forwarded [`InputEvent`] datagram.
//! * Inbound control stream → `control_in_rx` → focus/clipboard handling.
//! * Inbound datagrams → `datagram_in_rx` → injection (when [`FocusState::Receiving`]).
//! * Connection setup/teardown → `new_conn_rx` / `conn_lost_rx`.

mod commands;
mod events;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot};

use kvm_adapter_api::{ClipboardImage, LocalInput, Monitor, PlatformAdapters};
use kvm_core::{
    backoff_delay, evaluate_clipboard, BackoffParams, ClipboardPolicy, ContentKind, DeviceId,
    DeviceRegistry, DomainEffect, Edge, EntryPoint, Flow, FocusConfig, FocusEvent, FocusState,
    LayoutGraph, PayloadMeta, PendingTransition, Point, Rect, ScreenGeom, ScreenRegion, SeqWindow,
    SessionEvent, SessionState,
};
use kvm_proto::codec::{decode, encode};
use kvm_proto::v1::control::{ClipboardData, ClipboardKind, ControlMsg, PolicyUpdate, StreamKind};
use kvm_proto::v1::file::{FileChunk, FileMeta, FileOffer, FILE_CHUNK_SIZE};
use kvm_proto::v1::handshake::{Hello, Platform};
use kvm_proto::v1::input::{InputEvent, InputKind};
use kvm_proto::version::PROTOCOL_VERSION;
use kvm_transport::{Connection, MsgStream, Transport, SERVER_NAME};

pub use commands::{EngineCommand, EngineSnapshot, Placement};
pub use events::EngineEvent;

/// Edge-detection band in pixels.
const EDGE_BAND: i32 = 3;

/// A square corner zone (px) where edge crossings are suppressed, so reaching for
/// a corner UI target (close button, hot corner) doesn't trip a handoff.
const CORNER_DEAD: i32 = 24;

/// How far inside a destination screen the cursor enters after crossing a seam —
/// a buffer so it doesn't immediately re-trigger the seam it just came through.
const ENTRY_INSET: i32 = 8;

/// How long a committed handoff waits for the peer's `SwitchAck` before giving up
/// and returning control home (so a lost ack can't strand local input).
const SWITCH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2000);

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub device_id: DeviceId,
    pub device_name: String,
    pub platform: Platform,
    /// Compact session slot stamped on our outgoing hot-path events.
    pub source_slot: u32,
    /// Directory where received files are written.
    pub downloads_dir: PathBuf,
}

/// Cloneable handle to drive the engine and observe its events.
#[derive(Clone)]
pub struct EngineHandle {
    cmd_tx: mpsc::Sender<EngineCommand>,
    event_tx: broadcast::Sender<EngineEvent>,
}

impl EngineHandle {
    pub async fn send(&self, cmd: EngineCommand) {
        let _ = self.cmd_tx.send(cmd).await;
    }
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.event_tx.subscribe()
    }
    pub async fn connect_peer(&self, peer: DeviceId, addr: SocketAddr, peer_fingerprint: [u8; 32]) {
        self.send(EngineCommand::ConnectPeer {
            peer,
            addr,
            peer_fingerprint,
        })
        .await;
    }
    pub async fn set_layout(&self, layout: LayoutGraph) {
        self.send(EngineCommand::SetLayout(Box::new(layout))).await;
    }
    /// Set the screen arrangement as a grid; the engine computes real pixel
    /// regions from each device's actual resolution.
    pub async fn set_arrangement(&self, placements: Vec<Placement>) {
        self.send(EngineCommand::SetArrangement(placements)).await;
    }
    pub async fn manual_switch(&self, target: DeviceId) {
        self.send(EngineCommand::ManualSwitch { target }).await;
    }
    pub async fn release(&self) {
        self.send(EngineCommand::Release).await;
    }
    pub async fn local_clipboard_changed(&self, text: String) {
        self.send(EngineCommand::LocalClipboardChanged(text)).await;
    }
    pub async fn snapshot(&self) -> Option<EngineSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.send(EngineCommand::Snapshot(tx)).await;
        rx.await.ok()
    }
}

/// Inbound channels handed to per-connection pump tasks.
#[derive(Clone)]
struct Channels {
    control_in: mpsc::Sender<(DeviceId, ControlMsg)>,
    datagram_in: mpsc::Sender<(DeviceId, Vec<u8>)>,
    conn_lost: mpsc::Sender<DeviceId>,
}

/// Context for receiving files on inbound `Files` streams.
#[derive(Clone)]
struct FileCtx {
    downloads: PathBuf,
    /// Whether we currently accept incoming files (mirrors the local policy).
    enabled: Arc<AtomicBool>,
    events: broadcast::Sender<EngineEvent>,
}

/// A live link to one peer (owned by the actor).
struct PeerLink {
    conn: Arc<dyn Connection>,
    control_tx: mpsc::Sender<ControlMsg>,
    seq: u16,
    in_seq: SeqWindow,
}

/// Spawn the engine; returns a handle. Must run inside a tokio runtime.
pub fn spawn(
    config: EngineConfig,
    transport: Arc<dyn Transport>,
    mut adapters: PlatformAdapters,
    registry: DeviceRegistry,
) -> EngineHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, _) = broadcast::channel(256);
    let (capture_tx, capture_rx) = mpsc::channel(1024);
    let (control_in_tx, control_in_rx) = mpsc::channel(256);
    let (datagram_in_tx, datagram_in_rx) = mpsc::channel(1024);
    let (conn_lost_tx, conn_lost_rx) = mpsc::channel(16);
    let (new_conn_tx, new_conn_rx) = mpsc::channel(16);

    // Wire OS capture → channel (drop on backpressure: input is high-rate).
    let ctx = capture_tx.clone();
    if let Err(e) = adapters.capture.start(Arc::new(move |li: LocalInput| {
        let _ = ctx.try_send(li);
    })) {
        let _ = event_tx.send(EngineEvent::Error(format!("capture start: {e}")));
    }

    // This device's real combined-desktop geometry, queried once from the OS.
    // Drives the local screen region, the cursor park point, and the geometry we
    // advertise to peers in our Hello.
    let monitors = adapters.geometry.monitors().unwrap_or_default();
    let local_geom = desktop_geom(&monitors);
    // Center of the primary monitor, used to park the cursor under exclusive grab.
    let screen_center = monitors
        .iter()
        .find(|m| m.is_primary)
        .or_else(|| monitors.first())
        .map(|m| Point {
            x: m.bounds.x + m.bounds.w / 2,
            y: m.bounds.y + m.bounds.h / 2,
        });

    // Seed the layout with our own region at the origin so we're always present;
    // peers are added (and the whole thing re-arranged) as their Hellos arrive.
    let mut initial_layout = LayoutGraph::new();
    initial_layout.upsert_region(ScreenRegion {
        device: config.device_id,
        bounds: Rect::new(0, 0, local_geom.w, local_geom.h),
        scale: local_geom.scale,
    });

    // fingerprint → device id, for the accept loop to classify inbound peers.
    let mut idx = HashMap::new();
    for d in registry.all() {
        idx.insert(d.fingerprint.0, d.id);
    }
    let peer_index = Arc::new(RwLock::new(idx));

    let channels = Channels {
        control_in: control_in_tx,
        datagram_in: datagram_in_tx,
        conn_lost: conn_lost_tx,
    };
    let hello = make_hello(&config, local_geom);
    let file_enabled = Arc::new(AtomicBool::new(false));
    let file_ctx = FileCtx {
        downloads: config.downloads_dir.clone(),
        enabled: file_enabled.clone(),
        events: event_tx.clone(),
    };

    spawn_accept(
        transport.clone(),
        channels.clone(),
        hello.clone(),
        new_conn_tx.clone(),
        peer_index.clone(),
        event_tx.clone(),
        file_ctx,
    );

    let actor = Actor {
        config,
        transport,
        adapters,
        registry,
        layout: initial_layout,
        local_geom,
        peer_geom: HashMap::new(),
        arrangement: Vec::new(),
        layout_pinned: false,
        focus: FocusState::LocalControl,
        focus_cfg: FocusConfig::default(),
        session: SessionState::Idle,
        local_policy: ClipboardPolicy::default(),
        peer_policies: HashMap::new(),
        links: HashMap::new(),
        reconnect: HashMap::new(),
        last_cursor: Point { x: 0, y: 0 },
        virtual_cursor: Point { x: 0, y: 0 },
        last_clipboard: None,
        last_image: None,
        exclusive: true,
        screen_center,
        switch_gen: 0,
        hotkey_ctrl: false,
        hotkey_alt: false,
        file_enabled,
        event_tx: event_tx.clone(),
        channels,
        hello,
        new_conn_tx,
        peer_index,
        cmd_tx: cmd_tx.clone(),
        cmd_rx,
        capture_rx,
        control_in_rx,
        datagram_in_rx,
        conn_lost_rx,
        new_conn_rx,
    };
    tokio::spawn(actor.run());

    EngineHandle { cmd_tx, event_tx }
}

fn make_hello(cfg: &EngineConfig, screen: ScreenGeom) -> ControlMsg {
    ControlMsg::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        device_id: cfg.device_id.0,
        device_name: cfg.device_name.clone(),
        platform: cfg.platform,
        capabilities: Default::default(),
        source_slot: cfg.source_slot,
        screen,
    })
}

/// Compute a device's combined-desktop geometry (the bounding box of all its
/// monitors) and HiDPI scale, used both locally and advertised to peers.
fn desktop_geom(monitors: &[Monitor]) -> ScreenGeom {
    if monitors.is_empty() {
        return ScreenGeom::default();
    }
    let min_x = monitors.iter().map(|m| m.bounds.x).min().unwrap_or(0);
    let min_y = monitors.iter().map(|m| m.bounds.y).min().unwrap_or(0);
    let max_r = monitors
        .iter()
        .map(|m| m.bounds.x + m.bounds.w)
        .max()
        .unwrap_or(0);
    let max_b = monitors
        .iter()
        .map(|m| m.bounds.y + m.bounds.h)
        .max()
        .unwrap_or(0);
    let scale = monitors
        .iter()
        .find(|m| m.is_primary)
        .or_else(|| monitors.first())
        .map(|m| m.scale)
        .unwrap_or(1.0);
    ScreenGeom::new((max_r - min_x).max(1), (max_b - min_y).max(1), scale)
}

fn spawn_accept(
    transport: Arc<dyn Transport>,
    channels: Channels,
    hello: ControlMsg,
    new_conn_tx: mpsc::Sender<(DeviceId, PeerLink)>,
    peer_index: Arc<RwLock<HashMap<[u8; 32], DeviceId>>>,
    event_tx: broadcast::Sender<EngineEvent>,
    file_ctx: FileCtx,
) {
    tokio::spawn(async move {
        while let Some(item) = transport.accept().await {
            let conn: Arc<dyn Connection> = match item {
                Ok(c) => Arc::from(c),
                Err(e) => {
                    let _ = event_tx.send(EngineEvent::Error(format!("accept: {e}")));
                    continue;
                }
            };
            let fp = conn.peer_fingerprint();
            let peer = peer_index.read().unwrap().get(&fp).copied();
            let Some(peer) = peer else {
                // Unknown fingerprint: not a paired peer. Drop.
                continue;
            };
            match conn.accept_stream().await {
                Ok((_, stream)) => {
                    let link = establish(
                        conn,
                        stream,
                        channels.clone(),
                        peer,
                        hello.clone(),
                        file_ctx.clone(),
                    )
                    .await;
                    let _ = new_conn_tx.send((peer, link)).await;
                }
                Err(_) => continue,
            }
        }
    });
}

/// Set up a peer link: send our Hello, then run the control-stream pump and the
/// datagram reader. Returns the actor-owned [`PeerLink`].
async fn establish(
    conn: Arc<dyn Connection>,
    mut control: Box<dyn MsgStream>,
    channels: Channels,
    peer: DeviceId,
    hello: ControlMsg,
    file_ctx: FileCtx,
) -> PeerLink {
    let _ = control.send(&hello).await;
    let (out_tx, mut out_rx) = mpsc::channel::<ControlMsg>(64);

    // Control-stream pump: outbound from the actor, inbound to the actor.
    {
        let control_in = channels.control_in.clone();
        let conn_lost = channels.conn_lost.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    out = out_rx.recv() => match out {
                        Some(msg) => if control.send(&msg).await.is_err() { break },
                        None => break,
                    },
                    inbound = control.recv() => match inbound {
                        Ok(Some(msg)) => if control_in.send((peer, msg)).await.is_err() { break },
                        _ => break,
                    },
                }
            }
            let _ = conn_lost.send(peer).await;
        });
    }

    // Datagram reader.
    {
        let conn = conn.clone();
        let datagram_in = channels.datagram_in.clone();
        let conn_lost = channels.conn_lost.clone();
        tokio::spawn(async move {
            while let Ok(bytes) = conn.recv_datagram().await {
                if datagram_in.send((peer, bytes.to_vec())).await.is_err() {
                    break;
                }
            }
            let _ = conn_lost.send(peer).await;
        });
    }

    // Inbound-stream acceptor: handle file-transfer streams the peer opens.
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            loop {
                match conn.accept_stream().await {
                    Ok((StreamKind::Files, stream)) => {
                        tokio::spawn(receive_file(stream, peer, file_ctx.clone()));
                    }
                    Ok((_, _stream)) => {} // other kinds unused for now
                    Err(_) => break,
                }
            }
        });
    }

    PeerLink {
        conn,
        control_tx: out_tx,
        seq: 0,
        in_seq: SeqWindow::new(),
    }
}

/// Send a local file to a peer over a fresh `Files` stream.
async fn send_file(
    conn: Arc<dyn Connection>,
    path: PathBuf,
    peer: DeviceId,
    events: broadcast::Sender<EngineEvent>,
) {
    let result: Result<String, String> = async {
        let data = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let total = data.len() as u64;
        let offer = FileOffer {
            transfer_id: 1,
            files: vec![FileMeta {
                name: name.clone(),
                size: total,
                mime: "application/octet-stream".into(),
                sha256: sha,
            }],
            total_bytes: total,
        };
        let mut stream = conn
            .open_stream(StreamKind::Files)
            .await
            .map_err(|e| e.to_string())?;
        stream
            .send(&ControlMsg::FileOffer(offer))
            .await
            .map_err(|e| e.to_string())?;
        let mut offset = 0u64;
        for chunk in data.chunks(FILE_CHUNK_SIZE) {
            stream
                .send(&ControlMsg::FileChunk(FileChunk {
                    transfer_id: 1,
                    file_index: 0,
                    offset,
                    bytes: chunk.to_vec(),
                }))
                .await
                .map_err(|e| e.to_string())?;
            offset += chunk.len() as u64;
        }
        stream.finish().await.map_err(|e| e.to_string())?;
        Ok(name)
    }
    .await;
    match result {
        Ok(name) => {
            let _ = events.send(EngineEvent::FileSent { to: peer, name });
        }
        Err(e) => {
            let _ = events.send(EngineEvent::Error(format!("send file: {e}")));
        }
    }
}

/// Receive a file offered on an inbound `Files` stream, writing it to disk and
/// verifying its checksum.
async fn receive_file(mut stream: Box<dyn MsgStream>, peer: DeviceId, ctx: FileCtx) {
    use tokio::io::AsyncWriteExt;

    let offer = match stream.recv().await {
        Ok(Some(ControlMsg::FileOffer(o))) => o,
        _ => return,
    };
    if !ctx.enabled.load(Ordering::Relaxed) {
        return; // file receiving disabled by policy
    }
    let meta = match offer.files.first() {
        Some(m) => m.clone(),
        None => return,
    };
    // Strip any directory components from the offered name (path-traversal safe).
    let safe_name = std::path::Path::new(&meta.name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let _ = tokio::fs::create_dir_all(&ctx.downloads).await;
    let path = ctx.downloads.join(&safe_name);
    let mut file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    while let Ok(Some(msg)) = stream.recv().await {
        if let ControlMsg::FileChunk(c) = msg {
            if file.write_all(&c.bytes).await.is_err() {
                return;
            }
            hasher.update(&c.bytes);
            received += c.bytes.len() as u64;
        }
    }
    let _ = file.flush().await;
    let digest: [u8; 32] = hasher.finalize().into();
    let ok = digest == meta.sha256 && received == meta.size;
    let _ = ctx.events.send(EngineEvent::FileReceived {
        from: peer,
        name: safe_name,
        path: path.to_string_lossy().to_string(),
        ok,
    });
}

struct Actor {
    config: EngineConfig,
    transport: Arc<dyn Transport>,
    adapters: PlatformAdapters,
    registry: DeviceRegistry,
    layout: LayoutGraph,
    /// This device's real desktop geometry (its own screen region's size).
    local_geom: ScreenGeom,
    /// Real geometry reported by each peer in its Hello, keyed by device.
    peer_geom: HashMap<DeviceId, ScreenGeom>,
    /// User-chosen grid arrangement (empty = auto: peers to the right).
    arrangement: Vec<Placement>,
    /// When true, the layout was set explicitly and handshake geometry must not
    /// auto-rearrange it.
    layout_pinned: bool,
    focus: FocusState,
    focus_cfg: FocusConfig,
    session: SessionState,
    local_policy: ClipboardPolicy,
    peer_policies: HashMap<DeviceId, ClipboardPolicy>,
    links: HashMap<DeviceId, PeerLink>,
    reconnect: HashMap<DeviceId, (SocketAddr, [u8; 32])>,
    last_cursor: Point,
    /// Where the cursor is on the *remote* screen while we control it, in the
    /// target's layout coordinates — so we can detect crossing back over a seam.
    virtual_cursor: Point,
    /// Last clipboard contents we've seen locally, to detect changes (and to
    /// suppress echo when we just wrote a received clipboard).
    last_clipboard: Option<String>,
    last_image: Option<ClipboardImage>,
    /// When true (default), controlling a remote grabs + hides + parks the local
    /// cursor so exactly ONE crosshair exists across both machines. Turning it
    /// off forwards input without suppressing the local cursor (debug/observe).
    exclusive: bool,
    screen_center: Option<Point>,
    /// Monotonic counter so a stale `Switching` timeout from an earlier handoff
    /// can't abort a newer one.
    switch_gen: u64,
    /// Release-hotkey (Ctrl+Alt+Q) modifier tracking — always lets the user
    /// escape an exclusive grab even though local apps are suppressed.
    hotkey_ctrl: bool,
    hotkey_alt: bool,
    /// Shared with file-receive tasks; mirrors `local_policy.share_files`.
    file_enabled: Arc<AtomicBool>,
    event_tx: broadcast::Sender<EngineEvent>,
    channels: Channels,
    hello: ControlMsg,
    new_conn_tx: mpsc::Sender<(DeviceId, PeerLink)>,
    /// Shared fingerprint→id map the accept loop uses to classify inbound peers.
    /// Updated live on pairing/forgetting so trust changes take effect at once.
    peer_index: Arc<RwLock<HashMap<[u8; 32], DeviceId>>>,
    cmd_tx: mpsc::Sender<EngineCommand>,
    cmd_rx: mpsc::Receiver<EngineCommand>,
    capture_rx: mpsc::Receiver<LocalInput>,
    control_in_rx: mpsc::Receiver<(DeviceId, ControlMsg)>,
    datagram_in_rx: mpsc::Receiver<(DeviceId, Vec<u8>)>,
    conn_lost_rx: mpsc::Receiver<DeviceId>,
    new_conn_rx: mpsc::Receiver<(DeviceId, PeerLink)>,
}

impl Actor {
    async fn run(mut self) {
        // Poll the local clipboard for changes to share (text + images).
        let mut clip_tick = tokio::time::interval(std::time::Duration::from_millis(700));
        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    if !self.handle_command(cmd) { break; }
                }
                Some(input) = self.capture_rx.recv() => self.handle_local_input(input).await,
                Some((peer, msg)) = self.control_in_rx.recv() => self.handle_control(peer, msg),
                Some((peer, dg)) = self.datagram_in_rx.recv() => self.handle_datagram(peer, &dg),
                Some(peer) = self.conn_lost_rx.recv() => self.handle_conn_lost(peer),
                Some((peer, link)) = self.new_conn_rx.recv() => self.handle_new_link(peer, link),
                _ = clip_tick.tick() => self.poll_clipboard(),
                else => break,
            }
        }
    }

    /// Detect a local clipboard change and offer it to connected peers.
    fn poll_clipboard(&mut self) {
        if self.links.is_empty() {
            return;
        }
        if let Ok(Some(text)) = self.adapters.clipboard.read_text() {
            if !text.is_empty() && self.last_clipboard.as_deref() != Some(text.as_str()) {
                self.last_clipboard = Some(text.clone());
                self.offer_text(&text);
            }
        }
        // Only touch the (more expensive) image clipboard if we'd share it.
        if self.local_policy.share_images {
            if let Ok(Some(img)) = self.adapters.clipboard.read_image() {
                if self.last_image.as_ref() != Some(&img) {
                    self.last_image = Some(img.clone());
                    self.offer_image(&img);
                }
            }
        }
    }

    fn emit(&self, ev: EngineEvent) {
        let _ = self.event_tx.send(ev);
    }

    fn handle_command(&mut self, cmd: EngineCommand) -> bool {
        match cmd {
            EngineCommand::SetLayout(g) => {
                self.layout = *g;
                self.layout_pinned = true;
            }
            EngineCommand::SetArrangement(placements) => {
                self.arrangement = placements;
                self.layout_pinned = false;
                self.rebuild_layout();
            }
            EngineCommand::SetLocalClipboardPolicy(p) => {
                self.local_policy = p;
                self.file_enabled.store(p.share_files, Ordering::Relaxed);
                let update = policy_update(&p);
                for link in self.links.values() {
                    let _ = link.control_tx.try_send(ControlMsg::PolicyUpdate(update));
                }
            }
            EngineCommand::ConnectPeer {
                peer,
                addr,
                peer_fingerprint,
            } => {
                self.reconnect.insert(peer, (addr, peer_fingerprint));
                // Don't pile up dials to a peer we're already linked to (the
                // discovery loop re-fires ConnectPeer on every advert).
                if !self.links.contains_key(&peer) {
                    self.session = self.session.handle(SessionEvent::Connect);
                    self.spawn_connect(peer, addr, peer_fingerprint);
                }
            }
            EngineCommand::TrustPeer { peer, fingerprint } => {
                // Accept inbound connections from this peer from now on.
                self.peer_index.write().unwrap().insert(fingerprint, peer);
            }
            EngineCommand::ForgetPeer { peer } => {
                self.peer_index.write().unwrap().retain(|_, v| *v != peer);
                self.reconnect.remove(&peer);
                if let Some(link) = self.links.remove(&peer) {
                    let conn = link.conn;
                    tokio::spawn(async move { conn.close(0, "device removed".into()).await });
                }
                let involved = matches!(self.focus, FocusState::RemoteControl { target } if target == peer)
                    || matches!(self.focus, FocusState::Switching { target } if target == peer)
                    || matches!(self.focus, FocusState::Receiving { source } if source == peer);
                if involved {
                    self.apply_focus(FocusEvent::TransportLost);
                }
                self.emit(EngineEvent::PeerDisconnected { peer });
            }
            EngineCommand::ManualSwitch { target } => {
                if let Some(pt) = self.transition_to(target) {
                    self.apply_focus(FocusEvent::ManualSwitch(pt));
                }
            }
            EngineCommand::Release => self.apply_focus(FocusEvent::HotkeyRelease),
            EngineCommand::SwitchTimeout { target, generation } => {
                // Only act if this is the current handoff and we're still waiting.
                if generation == self.switch_gen
                    && matches!(self.focus, FocusState::Switching { target: t } if t == target)
                {
                    self.emit(EngineEvent::Error(format!(
                        "handoff to {target} timed out; returning control home"
                    )));
                    self.apply_focus(FocusEvent::SwitchTimeout);
                }
            }
            EngineCommand::SetExclusiveControl(on) => {
                self.exclusive = on;
                // Turning it off must immediately release any active grab.
                if !on {
                    let _ = self.adapters.capture.set_exclusive(false);
                }
            }
            EngineCommand::SendFile { peer, path } => self.spawn_send_file(peer, path),
            EngineCommand::LocalClipboardChanged(text) => self.offer_text(&text),
            EngineCommand::Snapshot(tx) => {
                let _ = tx.send(EngineSnapshot {
                    focus: self.focus,
                    session: self.session,
                    connected_peers: self.links.keys().copied().collect(),
                });
            }
            EngineCommand::Shutdown => return false,
        }
        true
    }

    async fn handle_local_input(&mut self, input: LocalInput) {
        // Release hotkey (Ctrl+Alt+Q): always available so the user can escape an
        // exclusive grab even when local apps are suppressed.
        if let LocalInput::Key { code, pressed } = input {
            match code {
                29 | 97 => self.hotkey_ctrl = pressed, // L/R Ctrl
                56 | 100 => self.hotkey_alt = pressed, // L/R Alt
                16 if pressed && self.hotkey_ctrl && self.hotkey_alt => {
                    self.apply_focus(FocusEvent::HotkeyRelease);
                    return; // consume Q; don't forward it
                }
                _ => {}
            }
        }

        match self.focus {
            FocusState::LocalControl | FocusState::EdgeArmed { .. } => {
                if let LocalInput::MouseMoveAbs { x, y } = input {
                    self.last_cursor = Point { x, y };
                    let ev = self.edge_event(Point { x, y });
                    self.apply_focus(ev);
                }
            }
            FocusState::RemoteControl { target } => match input {
                LocalInput::MouseMoveAbs { x, y } => {
                    let dx = x - self.last_cursor.x;
                    let dy = y - self.last_cursor.y;
                    self.last_cursor = Point { x, y };
                    if dx != 0 || dy != 0 {
                        self.remote_motion(target, dx, dy).await;
                    }
                }
                LocalInput::MouseMoveRel { dx, dy } => {
                    if dx != 0 || dy != 0 {
                        self.remote_motion(target, dx, dy).await;
                    }
                }
                other => {
                    if let Some(kind) = self.input_kind(other) {
                        self.forward_input(target, kind).await;
                    }
                }
            },
            // Receiving / Switching / Lost: don't forward local input.
            _ => {}
        }
    }

    fn handle_control(&mut self, peer: DeviceId, msg: ControlMsg) {
        match msg {
            ControlMsg::Hello(h) => {
                // Learn the peer's REAL screen size so seam crossings map to its
                // actual resolution. Re-arrange the extended desktop unless the
                // user pinned an explicit layout.
                let geom = ScreenGeom::new(h.screen.w.max(1), h.screen.h.max(1), h.screen.scale);
                let changed = self.peer_geom.insert(peer, geom) != Some(geom);
                if changed && !self.layout_pinned {
                    self.rebuild_layout();
                }
            }
            ControlMsg::SwitchRequest { entry } => {
                self.apply_focus(FocusEvent::RemoteSwitchRequest {
                    source: peer,
                    entry,
                });
            }
            ControlMsg::SwitchAck => self.apply_focus(FocusEvent::SwitchAck),
            ControlMsg::SwitchNack { .. } => self.apply_focus(FocusEvent::SwitchNack),
            ControlMsg::Release => self.apply_focus(FocusEvent::RemoteRelease),
            ControlMsg::PolicyUpdate(p) => {
                self.peer_policies.insert(peer, policy_from_update(p));
            }
            ControlMsg::ClipboardData(d) => self.receive_clipboard(peer, d),
            ControlMsg::Heartbeat { nonce } => {
                if let Some(link) = self.links.get(&peer) {
                    let _ = link.control_tx.try_send(ControlMsg::HeartbeatAck { nonce });
                }
            }
            ControlMsg::HeartbeatAck { .. } => {
                if let Some(link) = self.links.get(&peer) {
                    let rtt = link.conn.health().rtt.as_millis() as u64;
                    self.emit(EngineEvent::Latency { peer, rtt_ms: rtt });
                }
            }
            _ => {}
        }
    }

    fn handle_datagram(&mut self, peer: DeviceId, bytes: &[u8]) {
        // Only inject when this peer is actively controlling us.
        let FocusState::Receiving { source } = self.focus else {
            return;
        };
        if source != peer {
            return;
        }
        let Ok(ev) = decode::<InputEvent>(bytes) else {
            return;
        };
        if let Some(link) = self.links.get_mut(&peer) {
            if !link.in_seq.accept(ev.seq) {
                return; // stale/duplicate
            }
        }
        self.inject(ev.kind);
    }

    fn handle_conn_lost(&mut self, peer: DeviceId) {
        if self.links.remove(&peer).is_none() {
            return; // already torn down (both pump + reader report loss)
        }
        self.emit(EngineEvent::PeerDisconnected { peer });

        let involved = matches!(self.focus, FocusState::RemoteControl { target } if target == peer)
            || matches!(self.focus, FocusState::Switching { target } if target == peer)
            || matches!(self.focus, FocusState::Receiving { source } if source == peer);
        if involved {
            self.apply_focus(FocusEvent::TransportLost);
        }

        self.session = self.session.handle(SessionEvent::Lost);
        self.emit(EngineEvent::SessionChanged(self.session));

        // Reconnect (we know how to re-dial): backoff then retry.
        if let Some((addr, fp)) = self.reconnect.get(&peer).copied() {
            let cmd_tx = self.cmd_tx.clone();
            let delay = backoff_delay(0, BackoffParams::default());
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                let _ = cmd_tx
                    .send(EngineCommand::ConnectPeer {
                        peer,
                        addr,
                        peer_fingerprint: fp,
                    })
                    .await;
            });
        }
    }

    fn handle_new_link(&mut self, peer: DeviceId, link: PeerLink) {
        // Announce our clipboard policy on connect.
        let _ = link
            .control_tx
            .try_send(ControlMsg::PolicyUpdate(policy_update(&self.local_policy)));
        self.links.insert(peer, link);
        self.session = self.session.handle(SessionEvent::Established);
        self.emit(EngineEvent::SessionChanged(self.session));
        self.emit(EngineEvent::PeerConnected { peer });
    }

    // ---- focus / effects ----

    fn apply_focus(&mut self, ev: FocusEvent) {
        let prev = self.focus;
        let tr = self.focus.handle(ev, &self.focus_cfg);
        if tr.next != self.focus {
            self.focus = tr.next;
            self.emit(EngineEvent::FocusChanged(self.focus));
        }
        for eff in tr.effects {
            self.apply_effect(eff);
        }
        // Arm a watchdog when we newly enter `Switching`: if the peer's ack never
        // arrives, return control home instead of stranding local input.
        if let FocusState::Switching { target } = self.focus {
            if !matches!(prev, FocusState::Switching { .. }) {
                self.switch_gen = self.switch_gen.wrapping_add(1);
                let generation = self.switch_gen;
                let cmd_tx = self.cmd_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(SWITCH_TIMEOUT).await;
                    let _ = cmd_tx
                        .send(EngineCommand::SwitchTimeout { target, generation })
                        .await;
                });
            }
        }
    }

    fn apply_effect(&mut self, eff: DomainEffect) {
        match eff {
            DomainEffect::StartCapture => {
                if self.exclusive {
                    // Grab local input AND park the (now hidden) cursor at center
                    // so physical motion can't pin against a screen edge and
                    // starve the forwarded delta stream.
                    let _ = self.adapters.capture.set_exclusive(true);
                    if let Some(c) = self.screen_center {
                        let _ = self.adapters.geometry.warp_cursor(c.x, c.y);
                        self.last_cursor = c;
                    }
                }
            }
            DomainEffect::StopCapture => {
                // Always release the grab on any path that stops capture (this is
                // the fail-safe that prevents a stuck, session-locking grab).
                let _ = self.adapters.capture.set_exclusive(false);
            }
            DomainEffect::HideLocalCursor => {
                if self.exclusive {
                    let _ = self.adapters.geometry.hide_cursor();
                }
            }
            DomainEffect::RestoreLocalCursor => {
                // Always restore — fail-safe against a stranded invisible cursor.
                let _ = self.adapters.geometry.show_cursor();
            }
            DomainEffect::SetVirtualCursor { entry } => {
                // Seed the virtual cursor at the entry point on the target screen.
                if let FocusState::Switching { target } = self.focus {
                    if let Some(p) = self.layout.entry_to_point(target, entry, ENTRY_INSET) {
                        self.virtual_cursor = p;
                    }
                }
            }
            DomainEffect::SendSwitchRequest { target, entry } => {
                self.send_control(target, ControlMsg::SwitchRequest { entry });
            }
            DomainEffect::SendRelease { target } => {
                self.send_control(target, ControlMsg::Release);
            }
            DomainEffect::SendSwitchAck { source } => {
                self.send_control(source, ControlMsg::SwitchAck);
            }
            DomainEffect::BeginInjecting { entry, .. } => {
                // Warp OUR cursor to the entry point in our own 0-based screen
                // pixels (not layout space) so it lands on-screen regardless of
                // where this device sits in the shared arrangement.
                let p = entry_pixel(entry, self.local_geom.w, self.local_geom.h, 2);
                let _ = self.adapters.geometry.warp_cursor(p.x, p.y);
            }
            DomainEffect::StopInjecting => {
                let _ = self.adapters.injection.release_all();
            }
            DomainEffect::ReleaseAllKeys => {
                let _ = self.adapters.injection.release_all();
            }
        }
    }

    fn edge_event(&self, point: Point) -> FocusEvent {
        let me = self.config.device_id;
        if let Some((edge, pos)) =
            self.layout
                .edge_at_with_corner(me, point, EDGE_BAND, CORNER_DEAD)
        {
            if let Some((target, entry)) = self.layout.resolve_transition(me, edge, pos) {
                // Require both a live link AND a connectable trust state.
                if self.links.contains_key(&target) && self.is_trusted(target) {
                    return FocusEvent::EdgeReached(PendingTransition {
                        target,
                        edge,
                        entry,
                    });
                }
            }
        }
        FocusEvent::EdgeCleared
    }

    /// A peer is switch-eligible unless the registry has explicitly revoked it
    /// (an unknown device is implicitly trusted by virtue of the pinned-mTLS
    /// link existing at all).
    fn is_trusted(&self, target: DeviceId) -> bool {
        self.registry
            .get(target)
            .is_none_or(|d| d.trust.is_connectable())
    }

    /// Build a manual-switch transition to `target` using the configured link.
    fn transition_to(&self, target: DeviceId) -> Option<PendingTransition> {
        if !self.links.contains_key(&target) {
            return None;
        }
        let me = self.config.device_id;
        let link = self
            .layout
            .links()
            .iter()
            .find(|l| l.from == me && l.to == target)?;
        Some(PendingTransition {
            target,
            edge: link.from_edge,
            entry: kvm_proto::geometry::EntryPoint::new(link.to_edge, 0.5),
        })
    }

    fn input_kind(&mut self, input: LocalInput) -> Option<InputKind> {
        match input {
            LocalInput::MouseMoveAbs { x, y } => {
                let dx = x - self.last_cursor.x;
                let dy = y - self.last_cursor.y;
                self.last_cursor = Point { x, y };
                // Skip no-op moves (e.g. the echo from a center-warp).
                if dx == 0 && dy == 0 {
                    None
                } else {
                    Some(InputKind::MouseMoveRel { dx, dy })
                }
            }
            LocalInput::MouseMoveRel { dx, dy } => Some(InputKind::MouseMoveRel { dx, dy }),
            LocalInput::Button { button, pressed } => {
                Some(InputKind::MouseButton { button, pressed })
            }
            LocalInput::Wheel { dx, dy } => Some(InputKind::Wheel { dx, dy }),
            LocalInput::Key { code, pressed } => Some(InputKind::Key { code, pressed }),
        }
    }

    async fn forward_input(&mut self, target: DeviceId, kind: InputKind) {
        if let Some(link) = self.links.get_mut(&target) {
            let seq = link.seq;
            link.seq = link.seq.wrapping_add(1);
            let ev = InputEvent {
                source: self.config.source_slot,
                seq,
                kind,
            };
            if let Ok(bytes) = encode(&ev) {
                let _ = link.conn.send_datagram(Bytes::from(bytes)).await;
            }
        }
    }

    /// Move the cursor on the remote screen. Tracks the virtual cursor in the
    /// target's layout space; if it would cross a seam back home, returns control
    /// to this machine (the "extended desktop" round-trip). Otherwise it clamps
    /// to the target screen and forwards the relative motion.
    async fn remote_motion(&mut self, target: DeviceId, dx: i32, dy: i32) {
        let nx = self.virtual_cursor.x + dx;
        let ny = self.virtual_cursor.y + dy;

        if let Some((to, entry)) = self.check_remote_seam(target, nx, ny) {
            if to == self.config.device_id {
                // Crossing back to our own screen — warp our cursor to the entry
                // point (in our own 0-based screen pixels) and release the remote.
                let p = entry_pixel(entry, self.local_geom.w, self.local_geom.h, ENTRY_INSET);
                let _ = self.adapters.geometry.warp_cursor(p.x, p.y);
                self.last_cursor = p;
                self.apply_focus(FocusEvent::ReturnHome { entry });
                return;
            }
            // (Crossing to a *third* device — chaining — is a post-MVP item.)
        }

        // No crossing: clamp the virtual cursor to the target screen and forward
        // an ABSOLUTE position in the target's own pixel space. Absolute (not
        // relative) keeps the two machines in exact agreement regardless of
        // resolution or the remote's pointer acceleration — the controller is the
        // single source of truth for where the one cursor is.
        if let Some(region) = self.layout.region(target) {
            let b = region.bounds;
            self.virtual_cursor = Point {
                x: nx.clamp(b.x, b.right() - 1),
                y: ny.clamp(b.y, b.bottom() - 1),
            };
            // Translate layout-space → the target's local (origin-relative) pixels.
            let x = self.virtual_cursor.x - b.x;
            let y = self.virtual_cursor.y - b.y;
            self.forward_input(target, InputKind::MouseMoveAbs { x, y })
                .await;
        } else {
            // No known geometry yet: best-effort relative passthrough.
            self.virtual_cursor = Point { x: nx, y: ny };
            self.forward_input(target, InputKind::MouseMoveRel { dx, dy })
                .await;
        }

        // Re-park the local (hidden) cursor at center under exclusive grab so the
        // next physical motion is measured from center, never a screen edge.
        if self.exclusive {
            if let Some(c) = self.screen_center {
                let _ = self.adapters.geometry.warp_cursor(c.x, c.y);
                self.last_cursor = c;
            }
        }
    }

    /// Rebuild the layout graph from real per-device geometry + the user's grid
    /// arrangement. This is what makes the two machines behave as one extended
    /// desktop at their *actual* resolutions. No-op while an explicit layout is
    /// pinned. (Pure logic in [`compute_layout`], so it is unit-tested directly.)
    fn rebuild_layout(&mut self) {
        if self.layout_pinned {
            return;
        }
        self.layout = compute_layout(
            self.config.device_id,
            self.local_geom,
            &self.peer_geom,
            &self.arrangement,
        );
    }

    /// If the point `(vx, vy)` lies beyond an edge of `target`'s screen that has
    /// a seam, return where it leads.
    fn check_remote_seam(
        &self,
        target: DeviceId,
        vx: i32,
        vy: i32,
    ) -> Option<(DeviceId, EntryPoint)> {
        let region = self.layout.region(target)?;
        let b = region.bounds;
        let (edge, pos) = if vx < b.x {
            (Edge::Left, norm(vy, b.y, b.h))
        } else if vx >= b.right() {
            (Edge::Right, norm(vy, b.y, b.h))
        } else if vy < b.y {
            (Edge::Top, norm(vx, b.x, b.w))
        } else if vy >= b.bottom() {
            (Edge::Bottom, norm(vx, b.x, b.w))
        } else {
            return None;
        };
        self.layout.resolve_transition(target, edge, pos)
    }

    fn inject(&self, kind: InputKind) {
        let inj = &self.adapters.injection;
        let _ = match kind {
            InputKind::MouseMoveRel { dx, dy } => inj.move_rel(dx, dy),
            InputKind::MouseMoveAbs { x, y } => inj.move_abs(x, y),
            InputKind::MouseButton { button, pressed } => inj.button(button, pressed),
            InputKind::Wheel { dx, dy } => inj.wheel(dx, dy),
            InputKind::Key { code, pressed } => inj.key(code, pressed),
            InputKind::Modifiers { .. } => Ok(()),
        };
    }

    fn send_control(&self, peer: DeviceId, msg: ControlMsg) {
        if let Some(link) = self.links.get(&peer) {
            let _ = link.control_tx.try_send(msg);
        }
    }

    fn file_ctx(&self) -> FileCtx {
        FileCtx {
            downloads: self.config.downloads_dir.clone(),
            enabled: self.file_enabled.clone(),
            events: self.event_tx.clone(),
        }
    }

    /// Stream a local file to a connected peer (runs off the actor loop).
    fn spawn_send_file(&self, peer: DeviceId, path: PathBuf) {
        match self.links.get(&peer) {
            Some(link) => {
                let conn = link.conn.clone();
                tokio::spawn(send_file(conn, path, peer, self.event_tx.clone()));
            }
            None => {
                let _ = self
                    .event_tx
                    .send(EngineEvent::Error("send file: peer not connected".into()));
            }
        }
    }

    fn spawn_connect(&self, peer: DeviceId, addr: SocketAddr, fp: [u8; 32]) {
        let transport = self.transport.clone();
        let channels = self.channels.clone();
        let hello = self.hello.clone();
        let new_conn_tx = self.new_conn_tx.clone();
        let event_tx = self.event_tx.clone();
        let file_ctx = self.file_ctx();
        tokio::spawn(async move {
            match transport.connect(addr, fp, SERVER_NAME).await {
                Ok(conn) => {
                    let conn: Arc<dyn Connection> = Arc::from(conn);
                    match conn.open_stream(StreamKind::Control).await {
                        Ok(stream) => {
                            let link =
                                establish(conn, stream, channels, peer, hello, file_ctx).await;
                            let _ = new_conn_tx.send((peer, link)).await;
                        }
                        Err(e) => {
                            let _ = event_tx.send(EngineEvent::Error(format!("open stream: {e}")));
                        }
                    }
                }
                Err(e) => {
                    let _ = event_tx.send(EngineEvent::Error(format!("connect: {e}")));
                }
            }
        });
    }

    // ---- clipboard ----

    fn offer_text(&self, text: &str) {
        let meta = PayloadMeta {
            kind: ContentKind::Text,
            size: text.len() as u64,
        };
        self.offer_clipboard_data(
            meta,
            ClipboardKind::Text,
            "text/plain",
            text.as_bytes().to_vec(),
        );
    }

    fn offer_image(&self, img: &ClipboardImage) {
        let bytes = encode_image(img);
        let meta = PayloadMeta {
            kind: ContentKind::Image,
            size: bytes.len() as u64,
        };
        self.offer_clipboard_data(meta, ClipboardKind::Image, "image/x-rgba", bytes);
    }

    /// Send a clipboard payload to every peer whose policy (both ends) allows it.
    fn offer_clipboard_data(
        &self,
        meta: PayloadMeta,
        kind: ClipboardKind,
        mime: &str,
        bytes: Vec<u8>,
    ) {
        for (peer, link) in &self.links {
            let peer_policy = self.peer_policies.get(peer).copied().unwrap_or_default();
            if evaluate_clipboard(&self.local_policy, &peer_policy, &meta, Flow::Outgoing)
                .is_allowed()
            {
                let _ = link
                    .control_tx
                    .try_send(ControlMsg::ClipboardData(ClipboardData {
                        kind,
                        mime: mime.to_string(),
                        bytes: bytes.clone(),
                    }));
            }
        }
    }

    fn receive_clipboard(&mut self, peer: DeviceId, data: ClipboardData) {
        let peer_policy = self.peer_policies.get(&peer).copied().unwrap_or_default();
        let kind = match data.kind {
            ClipboardKind::Text => ContentKind::Text,
            ClipboardKind::Image => ContentKind::Image,
            ClipboardKind::Files => return, // file transfer handled separately
        };
        let meta = PayloadMeta {
            kind,
            size: data.bytes.len() as u64,
        };
        if !evaluate_clipboard(&self.local_policy, &peer_policy, &meta, Flow::Incoming).is_allowed()
        {
            return;
        }
        match data.kind {
            ClipboardKind::Text => {
                if let Ok(text) = String::from_utf8(data.bytes) {
                    self.last_clipboard = Some(text.clone()); // suppress echo
                    let _ = self.adapters.clipboard.write_text(&text);
                    self.emit(EngineEvent::ClipboardReceived { from: peer, text });
                }
            }
            ClipboardKind::Image => {
                if let Some(img) = decode_image(&data.bytes) {
                    self.last_image = Some(img.clone()); // suppress echo
                    let _ = self.adapters.clipboard.write_image(&img);
                }
            }
            ClipboardKind::Files => {}
        }
    }
}

/// Wire form for a clipboard image: `[width u32 LE][height u32 LE][rgba...]`.
fn encode_image(img: &ClipboardImage) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + img.rgba.len());
    out.extend_from_slice(&img.width.to_le_bytes());
    out.extend_from_slice(&img.height.to_le_bytes());
    out.extend_from_slice(&img.rgba);
    out
}

fn decode_image(bytes: &[u8]) -> Option<ClipboardImage> {
    if bytes.len() < 8 {
        return None;
    }
    let width = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let rgba = bytes[8..].to_vec();
    // sanity: pixel count must match the dimensions
    if rgba.len() != (width as usize) * (height as usize) * 4 {
        return None;
    }
    Some(ClipboardImage {
        width,
        height,
        rgba,
    })
}

/// Whether two 1-D spans `[a0,a1)` and `[b0,b1)` overlap by a positive amount —
/// used to decide whether two adjacent screens actually share a seam.
fn spans_overlap(a0: i32, a1: i32, b0: i32, b1: i32) -> bool {
    a0.max(b0) < a1.min(b1)
}

/// Where a normalized [`EntryPoint`] lands on the LOCAL screen, in the local
/// window system's own 0-based pixels (size `w`×`h`), nudged `inset` px inward.
///
/// Used for warps/injection that act on *this* machine's display — those must be
/// origin-relative, independent of where this device sits in the shared layout
/// (which may place it at a non-zero offset).
fn entry_pixel(entry: EntryPoint, w: i32, h: i32, inset: i32) -> Point {
    let along =
        |pos: f32, extent: i32| (pos.clamp(0.0, 1.0) * (extent.max(1) - 1) as f32).round() as i32;
    match entry.edge {
        Edge::Left => Point::new(inset, along(entry.pos, h)),
        Edge::Right => Point::new(w - 1 - inset, along(entry.pos, h)),
        Edge::Top => Point::new(along(entry.pos, w), inset),
        Edge::Bottom => Point::new(along(entry.pos, w), h - 1 - inset),
    }
}

/// Build the layout graph from each device's REAL geometry plus a grid
/// arrangement. With no arrangement it falls back to a side-by-side row ordered
/// by device id — deterministic and *symmetric*, so both machines independently
/// compute the same physical adjacency (peer-to-the-right on one is
/// peer-to-the-left on the other). Screens line up at their true resolutions and
/// adjacent ones are seam-linked, so the pair behaves as one extended desktop.
fn compute_layout(
    me: DeviceId,
    local_geom: ScreenGeom,
    peer_geom: &HashMap<DeviceId, ScreenGeom>,
    arrangement: &[Placement],
) -> LayoutGraph {
    // device → its real geometry (self + every peer that has said Hello).
    let mut geom: HashMap<DeviceId, ScreenGeom> = peer_geom.clone();
    geom.insert(me, local_geom);

    // Placements: explicit arrangement if given, else auto — every device in a
    // single row, left→right by id (same order on both ends).
    let placements: Vec<Placement> = if arrangement.is_empty() {
        let mut all: Vec<DeviceId> = geom.keys().copied().collect();
        all.sort_by_key(|d| d.0);
        all.into_iter()
            .enumerate()
            .map(|(i, device)| Placement {
                device,
                col: i as i32,
                row: 0,
            })
            .collect()
    } else {
        arrangement
            .iter()
            .copied()
            .filter(|p| geom.contains_key(&p.device))
            .collect()
    };

    // Assign pixel origins: lay each row out left→right by real widths; stack
    // rows top→bottom by each row's tallest screen.
    let mut rows: std::collections::BTreeMap<i32, Vec<Placement>> = Default::default();
    for p in &placements {
        rows.entry(p.row).or_default().push(*p);
    }
    let mut layout = LayoutGraph::new();
    let mut placed: Vec<(DeviceId, Rect)> = Vec::new();
    let mut y = 0;
    for (_row, mut cells) in rows {
        cells.sort_by_key(|c| c.col);
        let row_h = cells.iter().map(|c| geom[&c.device].h).max().unwrap_or(0);
        let mut x = 0;
        for c in cells {
            let g = geom[&c.device];
            let bounds = Rect::new(x, y, g.w, g.h);
            layout.upsert_region(ScreenRegion {
                device: c.device,
                bounds,
                scale: g.scale,
            });
            placed.push((c.device, bounds));
            x += g.w;
        }
        y += row_h;
    }

    // Link screens that are physically adjacent (share an edge with an
    // overlapping span). `link_bidirectional` adds the reverse automatically.
    for i in 0..placed.len() {
        for j in 0..placed.len() {
            if i == j {
                continue;
            }
            let (a, ra) = placed[i];
            let (b, rb) = placed[j];
            // b is directly to the right of a.
            if ra.right() == rb.x && spans_overlap(ra.y, ra.bottom(), rb.y, rb.bottom()) {
                layout.link_bidirectional(a, Edge::Right, b);
            }
            // b is directly below a.
            if ra.bottom() == rb.y && spans_overlap(ra.x, ra.right(), rb.x, rb.right()) {
                layout.link_bidirectional(a, Edge::Bottom, b);
            }
        }
    }

    layout
}

/// Normalize `v` to `[0,1]` within the span `[start, start+extent)`.
fn norm(v: i32, start: i32, extent: i32) -> f32 {
    if extent <= 0 {
        0.0
    } else {
        ((v - start) as f32 / extent as f32).clamp(0.0, 1.0)
    }
}

fn policy_update(p: &ClipboardPolicy) -> PolicyUpdate {
    PolicyUpdate {
        share_text: p.share_text,
        share_images: p.share_images,
        share_files: p.share_files,
        max_payload: p.max_payload,
    }
}

fn policy_from_update(p: PolicyUpdate) -> ClipboardPolicy {
    ClipboardPolicy {
        share_text: p.share_text,
        share_images: p.share_images,
        share_files: p.share_files,
        max_payload: p.max_payload,
        direction: kvm_core::Direction::Both,
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    fn dev(n: u128) -> DeviceId {
        DeviceId(uuid::Uuid::from_u128(n))
    }

    /// Auto layout places two different-resolution screens side by side at their
    /// REAL sizes, links the shared seam, and maps a crossing proportionally into
    /// the destination's own pixel space — the core "resolution match" fix.
    #[test]
    fn auto_layout_uses_real_resolutions_and_links_seam() {
        let a = dev(1);
        let b = dev(2);
        let mut peers = HashMap::new();
        peers.insert(b, ScreenGeom::new(2560, 1440, 1.0));
        let g = compute_layout(a, ScreenGeom::new(1920, 1080, 1.0), &peers, &[]);

        // Real bounds, contiguous (id order: a left, b right).
        assert_eq!(g.region(a).unwrap().bounds, Rect::new(0, 0, 1920, 1080));
        assert_eq!(g.region(b).unwrap().bounds, Rect::new(1920, 0, 2560, 1440));

        // The right edge of A, at its vertical midpoint, hands off to B...
        let (edge, pos) = g.edge_at(a, Point::new(1919, 540), 3).unwrap();
        assert_eq!(edge, Edge::Right);
        let (to, entry) = g.resolve_transition(a, edge, pos).unwrap();
        assert_eq!(to, b);
        // ...landing proportionally (~mid-height) inside B's 1440px screen.
        let p = g.entry_to_point(b, entry, ENTRY_INSET).unwrap();
        assert!(g.region(b).unwrap().bounds.contains(p));
        assert!((p.y - 720).abs() <= 2, "entry y={} not ~mid of 1440", p.y);
    }

    /// Both machines independently derive the SAME physical arrangement, so a
    /// crossing on one is the mirrored crossing on the other (no disagreement
    /// about who is on the left).
    #[test]
    fn auto_layout_is_symmetric_across_peers() {
        let a = dev(1);
        let b = dev(2);
        let ga = ScreenGeom::new(1920, 1080, 1.0);
        let gb = ScreenGeom::new(2560, 1440, 1.0);

        let mut a_peers = HashMap::new();
        a_peers.insert(b, gb);
        let from_a = compute_layout(a, ga, &a_peers, &[]);

        let mut b_peers = HashMap::new();
        b_peers.insert(a, ga);
        let from_b = compute_layout(b, gb, &b_peers, &[]);

        assert_eq!(
            from_a.region(a).unwrap().bounds,
            from_b.region(a).unwrap().bounds
        );
        assert_eq!(
            from_a.region(b).unwrap().bounds,
            from_b.region(b).unwrap().bounds
        );
    }

    #[test]
    fn entry_pixel_is_screen_local_and_zero_based() {
        // Entry points map to THIS screen's own 0-based pixels, independent of any
        // layout offset — so warps always land on-screen.
        let p = entry_pixel(EntryPoint::new(Edge::Right, 0.5), 1920, 1080, 8);
        assert_eq!(p.x, 1911); // 1920 - 1 - 8
        assert!((p.y - 540).abs() <= 1);
        let p2 = entry_pixel(EntryPoint::new(Edge::Left, 0.0), 2560, 1440, 2);
        assert_eq!((p2.x, p2.y), (2, 0));
        let p3 = entry_pixel(EntryPoint::new(Edge::Bottom, 1.0), 800, 600, 4);
        assert_eq!((p3.x, p3.y), (799, 595));
    }

    /// An explicit arrangement overrides the id ordering (here B is placed to the
    /// LEFT of A) and still uses each device's real width.
    #[test]
    fn explicit_arrangement_positions_by_grid() {
        let a = dev(1);
        let b = dev(2);
        let mut peers = HashMap::new();
        peers.insert(b, ScreenGeom::new(2560, 1440, 1.0));
        let arrangement = vec![
            Placement {
                device: b,
                col: 0,
                row: 0,
            },
            Placement {
                device: a,
                col: 1,
                row: 0,
            },
        ];
        let g = compute_layout(a, ScreenGeom::new(1920, 1080, 1.0), &peers, &arrangement);

        assert_eq!(g.region(b).unwrap().bounds, Rect::new(0, 0, 2560, 1440));
        assert_eq!(g.region(a).unwrap().bounds, Rect::new(2560, 0, 1920, 1080));
        // A's LEFT edge now hands off to B.
        let (edge, pos) = g.edge_at(a, Point::new(2560, 540), 3).unwrap();
        assert_eq!(edge, Edge::Left);
        assert_eq!(g.resolve_transition(a, edge, pos).unwrap().0, b);
    }
}
