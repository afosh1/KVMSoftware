//! Clipboard policy engine.
//!
//! A clipboard sync is permitted only when **both ends consent** — the decision
//! is the intersection of the local and peer policies, plus size and direction
//! checks. Secure default: text on, images/files off. No clipboard I/O here.

use serde::{Deserialize, Serialize};

use kvm_proto::v1::control::ClipboardKind;

/// Per-peer clipboard sharing policy. Mirrors the toggles in the Settings UI and
/// is exchanged with the peer via `ControlMsg::PolicyUpdate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardPolicy {
    pub share_text: bool,
    pub share_images: bool,
    pub share_files: bool,
    /// Max payload bytes this side will send/accept.
    pub max_payload: u64,
    pub direction: Direction,
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        ClipboardPolicy {
            share_text: true,
            share_images: false,
            share_files: false,
            // 12 MiB: fits a 1080p RGBA image inline under the frame cap. Larger
            // images (e.g. 4K) are a future "chunk over the file stream" item.
            max_payload: 12 * 1024 * 1024,
            direction: Direction::Both,
        }
    }
}

impl ClipboardPolicy {
    fn allows_kind(&self, kind: ContentKind) -> bool {
        match kind {
            ContentKind::Text => self.share_text,
            ContentKind::Image => self.share_images,
            ContentKind::Files => self.share_files,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Only push local clipboard to peers.
    Send,
    /// Only accept peers' clipboard.
    Recv,
    Both,
}

impl Direction {
    fn permits(self, flow: Flow) -> bool {
        matches!(
            (self, flow),
            (Direction::Both, _)
                | (Direction::Send, Flow::Outgoing)
                | (Direction::Recv, Flow::Incoming)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Text,
    Image,
    Files,
}

impl From<ClipboardKind> for ContentKind {
    fn from(k: ClipboardKind) -> Self {
        match k {
            ClipboardKind::Text => ContentKind::Text,
            ClipboardKind::Image => ContentKind::Image,
            ClipboardKind::Files => ContentKind::Files,
        }
    }
}

/// Direction of a clipboard transfer relative to *this* device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// This device is sending its clipboard to the peer.
    Outgoing,
    /// This device is receiving the peer's clipboard.
    Incoming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadMeta {
    pub kind: ContentKind,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    /// Our own policy forbids this kind/direction.
    DenyByLocal,
    /// The peer's policy forbids this kind.
    DenyByPeer,
    /// Exceeds the smaller of the two sides' size caps.
    DenyBySize,
}

impl PolicyDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// Decide whether a clipboard payload may flow, given both policies.
///
/// `flow` is from this device's perspective. For an outgoing transfer, the local
/// side must permit sending the kind and the peer must permit the kind; the size
/// must fit the smaller cap.
pub fn evaluate(
    local: &ClipboardPolicy,
    peer: &ClipboardPolicy,
    meta: &PayloadMeta,
    flow: Flow,
) -> PolicyDecision {
    if !local.direction.permits(flow) || !local.allows_kind(meta.kind) {
        return PolicyDecision::DenyByLocal;
    }
    if !peer.allows_kind(meta.kind) {
        return PolicyDecision::DenyByPeer;
    }
    let cap = local.max_payload.min(peer.max_payload);
    if meta.size > cap {
        return PolicyDecision::DenyBySize;
    }
    PolicyDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(size: u64) -> PayloadMeta {
        PayloadMeta {
            kind: ContentKind::Text,
            size,
        }
    }

    #[test]
    fn default_allows_small_text_both_ways() {
        let p = ClipboardPolicy::default();
        assert_eq!(
            evaluate(&p, &p, &text(10), Flow::Outgoing),
            PolicyDecision::Allow
        );
        assert_eq!(
            evaluate(&p, &p, &text(10), Flow::Incoming),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn default_denies_images() {
        let p = ClipboardPolicy::default();
        let img = PayloadMeta {
            kind: ContentKind::Image,
            size: 10,
        };
        assert_eq!(
            evaluate(&p, &p, &img, Flow::Outgoing),
            PolicyDecision::DenyByLocal
        );
    }

    #[test]
    fn peer_veto() {
        let local = ClipboardPolicy::default();
        let peer = ClipboardPolicy {
            share_text: false,
            ..ClipboardPolicy::default()
        };
        assert_eq!(
            evaluate(&local, &peer, &text(10), Flow::Outgoing),
            PolicyDecision::DenyByPeer
        );
    }

    #[test]
    fn size_cap_uses_minimum() {
        let local = ClipboardPolicy {
            max_payload: 1000,
            ..ClipboardPolicy::default()
        };
        let peer = ClipboardPolicy {
            max_payload: 100,
            ..ClipboardPolicy::default()
        };
        assert_eq!(
            evaluate(&local, &peer, &text(500), Flow::Outgoing),
            PolicyDecision::DenyBySize
        );
        assert_eq!(
            evaluate(&local, &peer, &text(100), Flow::Outgoing),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn direction_send_only_blocks_incoming() {
        let local = ClipboardPolicy {
            direction: Direction::Send,
            ..ClipboardPolicy::default()
        };
        let peer = ClipboardPolicy::default();
        assert_eq!(
            evaluate(&local, &peer, &text(10), Flow::Incoming),
            PolicyDecision::DenyByLocal
        );
        assert_eq!(
            evaluate(&local, &peer, &text(10), Flow::Outgoing),
            PolicyDecision::Allow
        );
    }
}
