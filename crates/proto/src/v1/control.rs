//! Control plane — reliable, length-prefixed frames.
//!
//! Everything that must arrive in order and intact: handshake, focus handoff,
//! clipboard, file transfer, policy sync, heartbeat, and graceful shutdown.

use serde::{Deserialize, Serialize};

use crate::geometry::EntryPoint;
use crate::v1::file::{FileAck, FileChunk, FileOffer, FileOfferAck};
use crate::v1::handshake::Hello;

/// Logical reliable stream a control/data message travels on. Splitting these
/// into separate QUIC streams prevents a large clipboard/file payload from
/// head-of-line-blocking time-sensitive control traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    Control,
    Clipboard,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardKind {
    Text,
    Image,
    Files,
}

/// Announces clipboard content availability so the receiver can apply policy
/// before the (potentially large) payload is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardOffer {
    pub kind: ClipboardKind,
    pub mime: String,
    pub size: u64,
}

/// Inline clipboard payload (used for text and small blobs). Large image/file
/// clipboard content is delivered via the file-transfer streams instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardData {
    pub kind: ClipboardKind,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// A peer's current clipboard sharing policy. Exchanged on connect and whenever
/// the user toggles a setting, so each side knows what the other will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub share_text: bool,
    pub share_images: bool,
    pub share_files: bool,
    pub max_payload: u64,
}

/// The reliable control/data message envelope.
///
/// Not `Eq` because [`ControlMsg::SwitchRequest`] carries a float `EntryPoint`;
/// `PartialEq` is sufficient for all comparisons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// First message after the tunnel opens (see [`Hello`]).
    Hello(Hello),
    /// Request to take control of the peer, entering at `entry`.
    SwitchRequest {
        entry: EntryPoint,
    },
    /// Peer accepted control handoff.
    SwitchAck,
    /// Peer refused (e.g. not trusted, busy) with a human-readable reason.
    SwitchNack {
        reason: String,
    },
    /// Controller is releasing the peer (hotkey or edge return).
    Release,
    ClipboardOffer(ClipboardOffer),
    ClipboardData(ClipboardData),
    FileOffer(FileOffer),
    FileOfferAck(FileOfferAck),
    FileChunk(FileChunk),
    FileAck(FileAck),
    PolicyUpdate(PolicyUpdate),
    /// Liveness probe; `nonce` is echoed back to measure RTT.
    Heartbeat {
        nonce: u64,
    },
    /// Heartbeat reply.
    HeartbeatAck {
        nonce: u64,
    },
    /// Graceful shutdown with a reason for logs/diagnostics.
    Goodbye {
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode, encode_frame, FrameDecoder};
    use crate::geometry::Edge;
    use crate::v1::handshake::{Capabilities, Platform, ScreenGeom};
    use uuid::Uuid;

    fn sample_messages() -> Vec<ControlMsg> {
        vec![
            ControlMsg::Hello(Hello {
                protocol_version: 1,
                device_id: Uuid::nil(),
                device_name: "a".into(),
                platform: Platform::Windows,
                capabilities: Capabilities::default(),
                source_slot: 2,
                screen: ScreenGeom::new(3840, 2160, 2.0),
            }),
            ControlMsg::SwitchRequest {
                entry: EntryPoint::new(Edge::Left, 0.5),
            },
            ControlMsg::SwitchAck,
            ControlMsg::SwitchNack {
                reason: "device not trusted".into(),
            },
            ControlMsg::Release,
            ControlMsg::ClipboardOffer(ClipboardOffer {
                kind: ClipboardKind::Text,
                mime: "text/plain".into(),
                size: 5,
            }),
            ControlMsg::ClipboardData(ClipboardData {
                kind: ClipboardKind::Text,
                mime: "text/plain".into(),
                bytes: b"hello".to_vec(),
            }),
            ControlMsg::PolicyUpdate(PolicyUpdate {
                share_text: true,
                share_images: false,
                share_files: false,
                max_payload: 1 << 20,
            }),
            ControlMsg::Heartbeat { nonce: 7 },
            ControlMsg::HeartbeatAck { nonce: 7 },
            ControlMsg::Goodbye {
                reason: "user quit".into(),
            },
        ]
    }

    #[test]
    fn every_control_msg_round_trips() {
        for msg in sample_messages() {
            let back: ControlMsg = decode(&encode(&msg).unwrap()).unwrap();
            assert_eq!(msg, back, "round-trip mismatch for {msg:?}");
        }
    }

    #[test]
    fn messages_round_trip_through_framing() {
        // Concatenate all sample messages as frames into one buffer, then stream
        // them back through a single FrameDecoder — models a real stream read.
        let msgs = sample_messages();
        let mut wire = Vec::new();
        for m in &msgs {
            wire.extend_from_slice(&encode_frame(m).unwrap());
        }
        let mut dec = FrameDecoder::new();
        dec.push(&wire);
        let mut decoded = Vec::new();
        while let Some(body) = dec.next_frame().unwrap() {
            decoded.push(decode::<ControlMsg>(&body).unwrap());
        }
        assert_eq!(decoded, msgs);
    }
}
