//! Tauri shell — bridges the Svelte UI to the `kvm-engine`.
//!
//! The shell owns persistent device management (registry + keystore + mDNS
//! discovery) and drives the engine (connect, switch, release, clipboard
//! policy). Engine events are forwarded to the webview as `engine-event`.
//!
//! NOTE (documented follow-ups): full SPAKE2-over-network pairing and per-peer
//! clipboard policy are simplified here — `confirm_pairing` performs a
//! manual-fingerprint TOFU trust, and `set_policy` applies one local policy.
//! The trait/command seams are in place to complete these without UI changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

use kvm_core::device::CertFingerprint;
use kvm_core::{Capabilities, ClipboardPolicy, DeviceId, DeviceRegistry, Platform, TrustState};
use kvm_discovery::{DeviceAdvert, DiscoveredPeer, Discovery};
use kvm_engine::{
    spawn as spawn_engine, EngineCommand, EngineConfig, EngineEvent, EngineHandle,
    Placement as EnginePlacement,
};
use kvm_keystore::Keystore;
use kvm_pairing::{fingerprint_hex, generate_code, generate_identity};
use kvm_proto::version::PROTOCOL_VERSION;
use kvm_transport::{allowed_peers, AllowedPeers, Identity, QuicTransport, Transport};

// ---------- DTOs (mirror the TypeScript interfaces) ----------

#[derive(Serialize)]
struct IdentityInfo {
    device_id: String,
    device_name: String,
    fingerprint: String,
    platform: String,
}

#[derive(Serialize, Clone)]
struct PermissionState {
    capture: String,
    injection: String,
}

#[derive(Serialize)]
struct DeviceInfo {
    id: String,
    name: String,
    platform: String,
    fingerprint: String,
    trust: String,
    connected: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct PolicyDto {
    share_text: bool,
    share_images: bool,
    share_files: bool,
}

#[derive(Serialize)]
struct DiagnosticsDto {
    focus: String,
    session: String,
    connected_peers: Vec<String>,
    rtt_ms: Option<u64>,
    loss_pct: f32,
}

#[derive(Deserialize)]
struct Placement {
    id: String,
    col: i32,
    row: i32,
}

#[derive(Deserialize)]
struct LayoutDto {
    placements: Vec<Placement>,
}

// ---------- shared state ----------

struct AppState {
    keystore: Keystore,
    device_id: DeviceId,
    identity: Identity,
    platform: Platform,
    perms: Mutex<PermissionState>,
    registry: Mutex<DeviceRegistry>,
    discovered: Mutex<HashMap<DeviceId, DiscoveredPeer>>,
    engine: OnceLock<EngineHandle>,
    last_rtt: Mutex<Option<u64>>,
    /// Live transport allow-list (peer fingerprints). Shared with the QUIC
    /// endpoint so pairing/forgetting takes effect without a restart.
    allowed: AllowedPeers,
}

impl AppState {
    fn engine(&self) -> Result<&EngineHandle, String> {
        self.engine.get().ok_or_else(|| "engine not ready".to_string())
    }
}

fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

fn platform_str(p: Platform) -> &'static str {
    match p {
        Platform::Windows => "windows",
        Platform::MacOs => "macos",
        Platform::Linux => "linux",
    }
}

// ---------- commands ----------

#[tauri::command]
fn get_identity(state: State<'_, AppState>) -> IdentityInfo {
    IdentityInfo {
        device_id: state.device_id.to_string(),
        device_name: hostname(),
        fingerprint: fingerprint_hex(&state.identity.fingerprint),
        platform: platform_str(state.platform).into(),
    }
}

#[tauri::command]
fn get_permissions(state: State<'_, AppState>) -> PermissionState {
    state.perms.lock().unwrap().clone()
}

#[tauri::command]
async fn list_devices(state: State<'_, AppState>) -> Result<Vec<DeviceInfo>, String> {
    let connected: Vec<DeviceId> = match state.engine()?.snapshot().await {
        Some(s) => s.connected_peers,
        None => vec![],
    };
    let registry = state.registry.lock().unwrap();
    let discovered = state.discovered.lock().unwrap();

    // Union of known (registry) + discovered devices.
    let mut out: HashMap<DeviceId, DeviceInfo> = HashMap::new();
    for d in registry.all() {
        out.insert(
            d.id,
            DeviceInfo {
                id: d.id.to_string(),
                name: d.name.clone(),
                platform: platform_str(d.platform).into(),
                fingerprint: d.fingerprint.to_hex(),
                trust: format!("{:?}", d.trust),
                connected: connected.contains(&d.id),
            },
        );
    }
    for (id, p) in discovered.iter() {
        out.entry(*id).or_insert_with(|| DeviceInfo {
            id: id.to_string(),
            name: p.name.clone(),
            platform: platform_str(p.platform).into(),
            fingerprint: p.fingerprint_hex.clone(),
            trust: "Untrusted".into(),
            connected: false,
        });
    }
    Ok(out.into_values().collect())
}

#[tauri::command]
fn begin_pairing(_peer_id: String) -> String {
    // Display this code on both devices; the operator confirms the match.
    generate_code()
}

#[tauri::command]
async fn confirm_pairing(
    state: State<'_, AppState>,
    peer_id: String,
    code: String,
) -> Result<(), String> {
    let _ = code; // SAS comparison is done visually by the operator in this MVP.
    let id = parse_id(&peer_id)?;
    let (fp, addr) = {
        let discovered = state.discovered.lock().unwrap();
        let peer = discovered.get(&id).ok_or("peer not discovered")?;
        let ip = peer
            .best_addr()
            .ok_or("peer has no reachable IPv4 address yet")?;
        (
            parse_fp(&peer.fingerprint_hex)?,
            SocketAddr::new(ip, peer.quic_port),
        )
    };
    let snapshot = {
        let mut registry = state.registry.lock().unwrap();
        registry.upsert_discovered(
            id,
            format!("{id}"),
            Platform::Linux,
            CertFingerprint(fp),
            Capabilities::default(),
            None,
        );
        registry.mark_paired(id, CertFingerprint(fp), TrustState::Trusted);
        registry.snapshot()
    };
    state.keystore.save_registry(&snapshot).map_err(e)?;
    // Take effect immediately (no restart): admit + map the new peer.
    state.allowed.write().unwrap().insert(fp);
    if let Some(h) = state.engine.get().cloned() {
        h.send(EngineCommand::TrustPeer {
            peer: id,
            fingerprint: fp,
        })
        .await;
        // Dial right away so the link comes up the moment both sides have paired.
        h.connect_peer(id, addr, fp).await;
    }
    Ok(())
}

#[tauri::command]
async fn revoke_device(state: State<'_, AppState>, peer_id: String) -> Result<(), String> {
    let id = parse_id(&peer_id)?;
    block_peer(&state, id).await;
    let snapshot = {
        let mut registry = state.registry.lock().unwrap();
        registry.revoke(id);
        registry.snapshot()
    };
    state.keystore.save_registry(&snapshot).map_err(e)
}

/// Fully remove a device so it returns to "Untrusted" and can be paired again.
#[tauri::command]
async fn forget_device(state: State<'_, AppState>, peer_id: String) -> Result<(), String> {
    let id = parse_id(&peer_id)?;
    block_peer(&state, id).await;
    let snapshot = {
        let mut registry = state.registry.lock().unwrap();
        registry.forget(id);
        registry.snapshot()
    };
    state.keystore.save_registry(&snapshot).map_err(e)
    // Note: we keep it in `discovered`, so a still-online peer immediately
    // reappears as Untrusted and can be re-paired without re-searching.
}

/// Disconnect + stop trusting a peer, live: drop it from the transport allow-list
/// and tell the engine to tear down any link and stop accepting/reconnecting.
async fn block_peer(state: &AppState, id: DeviceId) {
    let fp = state.registry.lock().unwrap().get(id).map(|d| d.fingerprint.0);
    if let Some(fp) = fp {
        state.allowed.write().unwrap().remove(&fp);
    }
    if let Some(h) = state.engine.get().cloned() {
        h.send(EngineCommand::ForgetPeer { peer: id }).await;
    }
}

#[tauri::command]
fn rename_device(state: State<'_, AppState>, peer_id: String, name: String) -> Result<(), String> {
    let id = parse_id(&peer_id)?;
    let mut registry = state.registry.lock().unwrap();
    registry.rename(id, name);
    state.keystore.save_registry(&registry.snapshot()).map_err(e)
}

#[tauri::command]
async fn connect_device(state: State<'_, AppState>, peer_id: String) -> Result<(), String> {
    let id = parse_id(&peer_id)?;
    let (addr, fp) = {
        let discovered = state.discovered.lock().unwrap();
        let peer = discovered.get(&id).ok_or("peer not discovered")?;
        let ip = peer.best_addr().ok_or("peer has no reachable IPv4 address")?;
        (
            SocketAddr::new(ip, peer.quic_port),
            parse_fp(&peer.fingerprint_hex)?,
        )
    };
    state.engine()?.connect_peer(id, addr, fp).await;
    Ok(())
}

#[tauri::command]
fn get_policy(_peer_id: String) -> PolicyDto {
    // MVP: a single local policy; default text-on.
    PolicyDto {
        share_text: true,
        share_images: false,
        share_files: false,
    }
}

#[tauri::command]
async fn set_policy(state: State<'_, AppState>, _peer_id: String, policy: PolicyDto) -> Result<(), String> {
    let p = ClipboardPolicy {
        share_text: policy.share_text,
        share_images: policy.share_images,
        share_files: policy.share_files,
        ..ClipboardPolicy::default()
    };
    state
        .engine()?
        .send(EngineCommand::SetLocalClipboardPolicy(p))
        .await;
    Ok(())
}

#[tauri::command]
async fn save_layout(state: State<'_, AppState>, graph: LayoutDto) -> Result<(), String> {
    // Send the grid arrangement only; the engine turns each cell into a pixel
    // region using that device's REAL resolution (exchanged at handshake), so
    // screens of different sizes line up — no hardcoded 1920x1080 anymore.
    let mut placements = Vec::with_capacity(graph.placements.len());
    for p in &graph.placements {
        placements.push(EnginePlacement {
            device: parse_id(&p.id)?,
            col: p.col,
            row: p.row,
        });
    }
    if let Some(h) = state.engine.get().cloned() {
        h.set_arrangement(placements).await;
    }
    Ok(())
}

#[tauri::command]
async fn manual_switch(state: State<'_, AppState>, target: String) -> Result<(), String> {
    state.engine()?.manual_switch(parse_id(&target)?).await;
    Ok(())
}

#[tauri::command]
async fn release(state: State<'_, AppState>) -> Result<(), String> {
    state.engine()?.release().await;
    Ok(())
}

#[tauri::command]
async fn set_exclusive_control(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if let Some(h) = state.engine.get().cloned() {
        h.send(EngineCommand::SetExclusiveControl(enabled)).await;
    }
    Ok(())
}

#[tauri::command]
async fn send_file(state: State<'_, AppState>, peer_id: String, path: String) -> Result<(), String> {
    let id = parse_id(&peer_id)?;
    if let Some(h) = state.engine.get().cloned() {
        h.send(EngineCommand::SendFile {
            peer: id,
            path: path.into(),
        })
        .await;
    }
    Ok(())
}

#[tauri::command]
async fn diagnostics(state: State<'_, AppState>) -> Result<DiagnosticsDto, String> {
    let snap = state.engine()?.snapshot().await.ok_or("engine not ready")?;
    Ok(DiagnosticsDto {
        focus: format!("{:?}", snap.focus),
        session: format!("{:?}", snap.session),
        connected_peers: snap.connected_peers.iter().map(|p| p.to_string()).collect(),
        rtt_ms: *state.last_rtt.lock().unwrap(),
        loss_pct: 0.0,
    })
}

// ---------- bootstrap ----------

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let keystore = Keystore::open_default().expect("keystore");
    let (device_id, identity) = load_or_create_identity(&keystore).expect("identity");
    let registry = DeviceRegistry::from_snapshot(keystore.load_registry().unwrap_or_default());
    // The allow-list seeds from already-trusted peers and is mutated live.
    let allowed = allowed_peers(registry.connectable().map(|d| d.fingerprint.0));

    let state = AppState {
        keystore,
        device_id,
        identity,
        platform: current_platform(),
        perms: Mutex::new(PermissionState {
            capture: "Unknown".into(),
            injection: "Unknown".into(),
        }),
        registry: Mutex::new(registry),
        discovered: Mutex::new(HashMap::new()),
        engine: OnceLock::new(),
        last_rtt: Mutex::new(None),
        allowed,
    };

    tauri::Builder::default()
        .manage(state)
        .setup(|app| {
            // quinn's Endpoint::bind requires a tokio runtime context, which the
            // Tauri setup closure does not have on its own — enter the app's
            // async runtime to build transport + engine.
            tauri::async_runtime::block_on(init_runtime(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_identity,
            get_permissions,
            list_devices,
            begin_pairing,
            confirm_pairing,
            revoke_device,
            forget_device,
            rename_device,
            connect_device,
            get_policy,
            set_policy,
            save_layout,
            manual_switch,
            release,
            set_exclusive_control,
            send_file,
            diagnostics
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn init_runtime(app: tauri::AppHandle) {
    let state = app.state::<AppState>();
    // Build transport + adapters + engine, sharing the live allow-list.
    let transport = Arc::new(
        QuicTransport::bind_lan(state.identity.clone(), state.allowed.clone()).expect("bind quic"),
    );
    let quic_port = transport.local_addr().expect("local addr").port();

    let adapters = kvm_adapter_native::platform_adapters().expect("native adapters");
    // Capture permission status before handing adapters to the engine.
    // (Trait methods resolve via the `dyn` type, so no `use` is needed.)
    {
        let mut perms = state.perms.lock().unwrap();
        perms.capture = format!("{:?}", adapters.capture.permission_status());
        perms.injection = format!("{:?}", adapters.injection.permission_status());
    }

    let registry_snapshot =
        DeviceRegistry::from_snapshot(state.registry.lock().unwrap().snapshot());
    let handle = spawn_engine(
        EngineConfig {
            device_id: state.device_id,
            device_name: hostname(),
            platform: state.platform,
            source_slot: 1,
            downloads_dir: downloads_dir(),
        },
        transport as Arc<dyn Transport>,
        adapters,
        registry_snapshot,
    );
    let _ = state.engine.set(handle.clone());

    // Forward engine events to the webview.
    let app_for_events = app.clone();
    let mut events = handle.subscribe();
    tauri::async_runtime::spawn(async move {
        while let Ok(ev) = events.recv().await {
            if let EngineEvent::Latency { rtt_ms, .. } = &ev {
                let st = app_for_events.state::<AppState>();
                *st.last_rtt.lock().unwrap() = Some(*rtt_ms);
            }
            let _ = app_for_events.emit("engine-event", event_json(&ev));
        }
    });

    // Advertise + browse; auto-connect trusted discovered peers.
    if let Ok(mut discovery) = Discovery::new() {
        let _ = discovery.advertise(&DeviceAdvert {
            device_id: state.device_id.0,
            name: hostname(),
            platform: state.platform,
            fingerprint_hex: fingerprint_hex(&state.identity.fingerprint),
            protocol_version: PROTOCOL_VERSION,
            quic_port,
            tcp_port: 0,
        });
        if let Ok(mut peers) = discovery.browse() {
            let app_for_disc = app.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(peer) = peers.recv().await {
                    let id = DeviceId(peer.device_id);
                    let st = app_for_disc.state::<AppState>();
                    st.discovered.lock().unwrap().insert(id, peer.clone());
                    // Auto-connect if already trusted.
                    let trusted = st
                        .registry
                        .lock()
                        .unwrap()
                        .get(id)
                        .map(|d| d.trust.is_connectable())
                        .unwrap_or(false);
                    if trusted {
                        if let (Some(ip), Some(h)) = (peer.best_addr(), st.engine.get()) {
                            if let Ok(fp) = parse_fp(&peer.fingerprint_hex) {
                                h.connect_peer(id, SocketAddr::new(ip, peer.quic_port), fp).await;
                            }
                        }
                    }
                }
            });
            // Keep the discovery daemon alive for the process lifetime.
            std::mem::forget(discovery);
        }
    }
}

// ---------- helpers ----------

fn event_json(ev: &EngineEvent) -> serde_json::Value {
    use serde_json::json;
    match ev {
        EngineEvent::PeerConnected { peer } => json!({"type":"peerConnected","peer":peer.to_string()}),
        EngineEvent::PeerDisconnected { peer } => json!({"type":"peerDisconnected","peer":peer.to_string()}),
        EngineEvent::FocusChanged(f) => json!({"type":"focus","value":format!("{f:?}")}),
        EngineEvent::SessionChanged(s) => json!({"type":"session","value":format!("{s:?}")}),
        EngineEvent::Latency { peer, rtt_ms } => json!({"type":"latency","peer":peer.to_string(),"rtt_ms":rtt_ms}),
        EngineEvent::ClipboardReceived { from, .. } => json!({"type":"clipboard","from":from.to_string()}),
        EngineEvent::FileReceived { from, name, ok, .. } => {
            json!({"type":"fileReceived","from":from.to_string(),"name":name,"ok":ok})
        }
        EngineEvent::FileSent { to, name } => {
            json!({"type":"fileSent","to":to.to_string(),"name":name})
        }
        EngineEvent::PeerDiscovered(p) => json!({"type":"discovered","name":p.name}),
        EngineEvent::Error(m) => json!({"type":"error","message":m}),
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "kvm-device".to_string())
}

fn downloads_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| std::path::PathBuf::from(h).join("Downloads"))
        .unwrap_or_else(std::env::temp_dir)
}

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn parse_id(s: &str) -> Result<DeviceId, String> {
    Ok(DeviceId(uuid::Uuid::parse_str(s).map_err(e)?))
}

fn parse_fp(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(e)?;
    bytes.try_into().map_err(|_| "bad fingerprint length".to_string())
}

fn load_or_create_identity(keystore: &Keystore) -> Result<(DeviceId, Identity), String> {
    let id_path = kvm_keystore::default_state_dir().join("device_id");
    if let Some(stored) = keystore.load_identity().map_err(e)? {
        let id = std::fs::read_to_string(&id_path)
            .ok()
            .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok())
            .map(DeviceId)
            .unwrap_or_else(DeviceId::generate);
        return Ok((id, Identity::new(stored.cert_der, stored.key_der)));
    }
    let id = DeviceId::generate();
    let gen = generate_identity(id.0).map_err(e)?;
    keystore.save_identity(&gen.cert_der, &gen.key_der).map_err(e)?;
    let _ = std::fs::write(id_path, id.0.to_string());
    Ok((id, Identity::new(gen.cert_der, gen.key_der)))
}
