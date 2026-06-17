//! Events emitted by the engine for the UI/CLI to render.

use kvm_core::{DeviceId, FocusState, SessionState};
use kvm_discovery::DiscoveredPeer;

#[derive(Debug, Clone)]
pub enum EngineEvent {
    PeerDiscovered(DiscoveredPeer),
    PeerConnected {
        peer: DeviceId,
    },
    PeerDisconnected {
        peer: DeviceId,
    },
    FocusChanged(FocusState),
    SessionChanged(SessionState),
    ClipboardReceived {
        from: DeviceId,
        text: String,
    },
    /// A file finished arriving from a peer (`ok` = checksum/size verified).
    FileReceived {
        from: DeviceId,
        name: String,
        path: String,
        ok: bool,
    },
    /// A file finished sending to a peer.
    FileSent {
        to: DeviceId,
        name: String,
    },
    /// Latest measured round-trip time to a peer.
    Latency {
        peer: DeviceId,
        rtt_ms: u64,
    },
    Error(String),
}
