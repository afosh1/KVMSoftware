//! Headless daemon for the LAN KVM.
//!
//! Responsibilities:
//! * Load (or generate + persist) this device's identity and trusted-peer
//!   registry via the keystore.
//! * Advertise over mDNS and browse for peers; auto-connect to any discovered
//!   peer that is already trusted.
//! * Spawn the engine wired to the native OS adapters.
//!
//! Trust bootstrap (manual TOFU): set `KVM_TRUST=<uuid>:<fingerprint_hex>` to
//! add a trusted peer at startup (the richer SPAKE2 + SAS pairing flow lives in
//! the desktop UI). Print this device's own id + fingerprint so the other side
//! can trust it.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use kvm_adapter_native::platform_adapters;
use kvm_core::device::CertFingerprint;
use kvm_core::{Capabilities, DeviceId, DeviceRegistry, Platform, TrustState};
use kvm_discovery::{DeviceAdvert, Discovery};
use kvm_engine::{spawn, EngineConfig, EngineEvent};
use kvm_keystore::Keystore;
use kvm_pairing::{fingerprint_hex, generate_identity};
use kvm_proto::version::PROTOCOL_VERSION;
use kvm_transport::{allowed_peers, Identity, QuicTransport, Transport};

fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let device_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "kvm-device".to_string());

    // --- identity (load or generate) ---
    let keystore = Keystore::open_default()?;
    let (device_id, identity) = load_or_create_identity(&keystore)?;
    tracing::info!(
        device = %device_name,
        id = %device_id,
        fingerprint = %fingerprint_hex(&identity.fingerprint),
        backend = keystore.backend_name(),
        "identity ready"
    );
    println!("This device:");
    println!("  id:          {device_id}");
    println!("  fingerprint: {}", fingerprint_hex(&identity.fingerprint));
    println!(
        "  (trust me on the other machine with KVM_TRUST={}:{})",
        device_id,
        fingerprint_hex(&identity.fingerprint)
    );

    // --- registry (load + optional KVM_TRUST bootstrap) ---
    let mut registry = DeviceRegistry::from_snapshot(keystore.load_registry()?);
    if let Some((id, fp)) = parse_trust_env() {
        registry.upsert_discovered(
            id,
            "trusted-peer".into(),
            Platform::Linux,
            CertFingerprint(fp),
            Capabilities::default(),
            None,
        );
        registry.mark_paired(id, CertFingerprint(fp), TrustState::Trusted);
        keystore.save_registry(&registry.snapshot())?;
        tracing::info!(peer = %id, "added trusted peer from KVM_TRUST");
    }

    let allowed: Vec<[u8; 32]> = registry.connectable().map(|d| d.fingerprint.0).collect();
    println!("Trusted peers ({}):", allowed.len());
    for d in registry.connectable() {
        println!("  - {} {}", d.id, d.fingerprint.to_hex());
    }
    if allowed.is_empty() {
        println!("  (none — set KVM_TRUST=<peer-id>:<peer-fingerprint> to trust one)");
    }

    // --- transport + adapters + engine ---
    let transport = Arc::new(QuicTransport::bind_lan(
        identity.clone(),
        allowed_peers(allowed),
    )?);
    let quic_port = transport.local_addr()?.port();
    tracing::info!(port = quic_port, "QUIC endpoint bound");

    let adapters = match platform_adapters() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(%e, "failed to initialize OS adapters (need a desktop session)");
            return Err(e.into());
        }
    };

    let trusted: Vec<(DeviceId, [u8; 32])> = registry
        .connectable()
        .map(|d| (d.id, d.fingerprint.0))
        .collect();

    let handle = spawn(
        EngineConfig {
            device_id,
            device_name: device_name.clone(),
            platform: current_platform(),
            source_slot: 1,
            downloads_dir: kvm_keystore::default_state_dir().join("received"),
        },
        transport as Arc<dyn Transport>,
        adapters,
        registry,
    );

    // Print engine events.
    let mut events = handle.subscribe();
    tokio::spawn(async move {
        while let Ok(ev) = events.recv().await {
            match ev {
                EngineEvent::PeerConnected { peer } => println!("[+] connected: {peer}"),
                EngineEvent::PeerDisconnected { peer } => println!("[-] disconnected: {peer}"),
                EngineEvent::FocusChanged(f) => println!("[focus] {f:?}"),
                EngineEvent::Latency { peer, rtt_ms } => {
                    tracing::debug!(%peer, rtt_ms, "latency")
                }
                EngineEvent::ClipboardReceived { from, .. } => println!("[clip] from {from}"),
                EngineEvent::Error(e) => tracing::warn!(error = %e, "engine error"),
                _ => {}
            }
        }
    });

    // --- discovery: advertise + browse + auto-connect trusted peers ---
    let mut discovery = Discovery::new()?;
    discovery.advertise(&DeviceAdvert {
        device_id: device_id.0,
        name: device_name,
        platform: current_platform(),
        fingerprint_hex: fingerprint_hex(&identity.fingerprint),
        protocol_version: PROTOCOL_VERSION,
        quic_port,
        tcp_port: 0,
    })?;
    let mut peers = discovery.browse()?;
    let handle2 = handle.clone();
    tokio::spawn(async move {
        while let Some(peer) = peers.recv().await {
            let pid = DeviceId(peer.device_id);
            println!("[discovered] {} ({})", peer.name, pid);
            if let Some((_, fp)) = trusted.iter().find(|(id, _)| *id == pid) {
                match peer.best_addr() {
                    Some(ip) => {
                        let addr = SocketAddr::new(ip, peer.quic_port);
                        println!("    -> trusted; connecting at {addr}");
                        handle2.connect_peer(pid, addr, *fp).await;
                    }
                    None => println!("    -> trusted, but no routable IPv4 address yet"),
                }
            }
        }
    });

    println!("\nkvm daemon running. Ctrl-C to quit.");
    tokio::signal::ctrl_c().await?;
    discovery.shutdown();
    Ok(())
}

fn load_or_create_identity(
    keystore: &Keystore,
) -> Result<(DeviceId, Identity), Box<dyn std::error::Error>> {
    if let Some(stored) = keystore.load_identity()? {
        // Recover device id from the persisted registry-adjacent id file is not
        // needed: derive a stable id from the cert is overkill; we persist it.
        let device_id = load_device_id(keystore)?;
        return Ok((device_id, Identity::new(stored.cert_der, stored.key_der)));
    }
    let device_id = DeviceId::generate();
    let gen = generate_identity(device_id.0)?;
    keystore.save_identity(&gen.cert_der, &gen.key_der)?;
    save_device_id(keystore, device_id)?;
    Ok((device_id, Identity::new(gen.cert_der, gen.key_der)))
}

fn device_id_path(keystore: &Keystore) -> std::path::PathBuf {
    let _ = keystore;
    kvm_keystore::default_state_dir().join("device_id")
}

fn save_device_id(keystore: &Keystore, id: DeviceId) -> std::io::Result<()> {
    std::fs::write(device_id_path(keystore), id.0.to_string())
}

fn load_device_id(keystore: &Keystore) -> Result<DeviceId, Box<dyn std::error::Error>> {
    let s = std::fs::read_to_string(device_id_path(keystore))?;
    Ok(DeviceId(Uuid::parse_str(s.trim())?))
}

/// Parse `KVM_TRUST=<uuid>:<fingerprint_hex>`.
fn parse_trust_env() -> Option<(DeviceId, [u8; 32])> {
    let raw = std::env::var("KVM_TRUST").ok()?;
    let (id, fp_hex) = raw.split_once(':')?;
    let id = DeviceId(Uuid::parse_str(id.trim()).ok()?);
    let bytes = hex::decode(fp_hex.trim()).ok()?;
    let fp: [u8; 32] = bytes.try_into().ok()?;
    Some((id, fp))
}
