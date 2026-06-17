//! Connection handshake — the first control-plane exchange.
//!
//! After the mTLS tunnel is established (peer cert already pinned during
//! pairing), each side sends a [`Hello`] on the Control stream **before any
//! input flows**. This re-confirms the protocol version and exchanges
//! capabilities so feature use is the intersection of both ends.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::geometry::ScreenGeom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    MacOs,
    Linux,
}

/// Feature flags a peer supports. Use is always the AND of both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub clipboard_text: bool,
    pub clipboard_image: bool,
    pub file_transfer: bool,
    /// Whether the peer can send/receive hot-path input over unreliable
    /// datagrams. `false` on the TCP/TLS fallback transport (reliable-only).
    pub datagram_input: bool,
}

impl Capabilities {
    /// Intersect two capability sets — what both ends can actually do.
    pub fn intersect(self, other: Capabilities) -> Capabilities {
        Capabilities {
            clipboard_text: self.clipboard_text && other.clipboard_text,
            clipboard_image: self.clipboard_image && other.clipboard_image,
            file_transfer: self.file_transfer && other.file_transfer,
            datagram_input: self.datagram_input && other.datagram_input,
        }
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        // Secure-by-default: only text clipboard + datagram input on by default.
        Capabilities {
            clipboard_text: true,
            clipboard_image: false,
            file_transfer: false,
            datagram_input: true,
        }
    }
}

/// Not `Eq` because [`ScreenGeom::scale`] is a float.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u16,
    pub device_id: Uuid,
    pub device_name: String,
    pub platform: Platform,
    pub capabilities: Capabilities,
    /// Session-scoped source slot the sender will stamp on its hot-path events.
    pub source_slot: u32,
    /// The sender's real combined-desktop size, so the receiver maps seam
    /// crossings to the sender's *actual* resolution rather than a default.
    pub screen: ScreenGeom,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    #[test]
    fn hello_round_trip() {
        let h = Hello {
            protocol_version: 1,
            device_id: Uuid::nil(),
            device_name: "studio-laptop".into(),
            platform: Platform::Linux,
            capabilities: Capabilities::default(),
            source_slot: 1,
            screen: ScreenGeom::new(2560, 1440, 1.5),
        };
        let back: Hello = decode(&encode(&h).unwrap()).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn capabilities_intersection_is_conservative() {
        let a = Capabilities {
            clipboard_text: true,
            clipboard_image: true,
            file_transfer: false,
            datagram_input: true,
        };
        let b = Capabilities {
            clipboard_text: true,
            clipboard_image: false,
            file_transfer: true,
            datagram_input: false,
        };
        let i = a.intersect(b);
        assert!(i.clipboard_text);
        assert!(!i.clipboard_image);
        assert!(!i.file_transfer);
        assert!(!i.datagram_input);
    }
}
