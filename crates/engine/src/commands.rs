//! Commands the UI/CLI sends to the engine.

use std::net::SocketAddr;

use tokio::sync::oneshot;

use kvm_core::{ClipboardPolicy, DeviceId, FocusState, LayoutGraph, SessionState};

/// One device's cell in the layout grid (from the layout editor). The engine
/// turns placements into real pixel regions using each device's *actual*
/// resolution (exchanged at handshake), so screens of different sizes line up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub device: DeviceId,
    pub col: i32,
    pub row: i32,
}

#[derive(Debug)]
pub enum EngineCommand {
    /// Replace the screen-arrangement graph directly (explicit/full override —
    /// pins the layout so handshake geometry won't auto-rearrange it).
    SetLayout(Box<LayoutGraph>),
    /// Set the screen arrangement as a grid of placements; the engine computes
    /// pixel regions from each device's real geometry and keeps them in sync as
    /// peers report their resolution.
    SetArrangement(Vec<Placement>),
    /// Update this device's clipboard sharing policy; broadcast to peers.
    SetLocalClipboardPolicy(ClipboardPolicy),
    /// Dial a (already-paired) peer.
    ConnectPeer {
        peer: DeviceId,
        addr: SocketAddr,
        peer_fingerprint: [u8; 32],
    },
    /// Mark a peer trusted at runtime (right after pairing) so inbound
    /// connections from it are accepted without a restart.
    TrustPeer {
        peer: DeviceId,
        fingerprint: [u8; 32],
    },
    /// Drop a peer at runtime (revoke/forget): stop accepting it, stop
    /// auto-reconnecting, and tear down any live link.
    ForgetPeer {
        peer: DeviceId,
    },
    /// Hotkey: take control of `target` immediately.
    ManualSwitch {
        target: DeviceId,
    },
    /// Hotkey: release remote control and reclaim local focus.
    Release,
    /// Internal: a `Switching` handoff has waited too long for the peer's ack.
    /// `generation` guards against a stale timer firing after a newer switch.
    SwitchTimeout {
        target: DeviceId,
        generation: u64,
    },
    /// Turn exclusive control (local input grab) on/off. Off by default.
    SetExclusiveControl(bool),
    /// Send a local file to a connected peer.
    SendFile {
        peer: DeviceId,
        path: std::path::PathBuf,
    },
    /// The local clipboard changed; offer it to connected peers per policy.
    LocalClipboardChanged(String),
    /// Diagnostics snapshot request.
    Snapshot(oneshot::Sender<EngineSnapshot>),
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct EngineSnapshot {
    pub focus: FocusState,
    pub session: SessionState,
    pub connected_peers: Vec<DeviceId>,
}
