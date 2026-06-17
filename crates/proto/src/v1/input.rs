//! Hot-path input events — the latency-critical plane.
//!
//! These are sent over **unreliable QUIC datagrams**, fire-and-forget. The
//! receiver keeps a per-source sequence window and drops stale/out-of-order
//! events, so a dropped datagram simply means a skipped intermediate sample
//! (a later one supersedes it) rather than a retransmit stall.
//!
//! Keycodes on the wire are **canonical Linux `evdev` codes** (`KEY_*`). Each
//! OS adapter maps its native scancodes to/from this space. This gives one
//! well-defined, dense, documented keycode universe across platforms.

use serde::{Deserialize, Serialize};

/// Per-source monotonically increasing sequence number (wraps; compared with
/// wrapping-aware logic in the domain layer).
pub type Seq = u16;

/// A single input sample from a controller device.
///
/// Encoded compactly by postcard: small integers are LEB128 varints, so a
/// typical relative mouse move is ~5 bytes and a keypress ~6 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEvent {
    /// Session-scoped source slot (assigned at handshake). Keeps the hot path
    /// tiny vs. embedding a 16-byte UUID per event.
    pub source: u32,
    /// Sequence number for stale-drop / ordering at the receiver.
    pub seq: Seq,
    /// The actual input.
    pub kind: InputKind,
}

impl InputEvent {
    pub fn new(source: u32, seq: Seq, kind: InputKind) -> Self {
        Self { source, seq, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputKind {
    /// Relative pointer motion (preferred on the hot path).
    MouseMoveRel {
        dx: i32,
        dy: i32,
    },
    /// Absolute pointer position in the destination screen's logical pixels.
    /// Used for the initial warp on seam entry.
    MouseMoveAbs {
        x: i32,
        y: i32,
    },
    MouseButton {
        button: MouseButton,
        pressed: bool,
    },
    /// Scroll wheel; positive `dy` scrolls up, positive `dx` scrolls right.
    Wheel {
        dx: i32,
        dy: i32,
    },
    /// Key transition. `code` is a canonical evdev keycode.
    Key {
        code: u32,
        pressed: bool,
    },
    /// Full modifier state snapshot — sent on focus transitions so the receiver
    /// can resync (and on release to guarantee no modifier stays stuck).
    Modifiers {
        state: Modifiers,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

/// Modifier key bitmask. A plain newtype (no foreign `bitflags` dep) so `proto`
/// stays dependency-light; serializes as a single `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Modifiers(pub u8);

impl Modifiers {
    pub const SHIFT: Modifiers = Modifiers(0b0000_0001);
    pub const CTRL: Modifiers = Modifiers(0b0000_0010);
    pub const ALT: Modifiers = Modifiers(0b0000_0100);
    pub const META: Modifiers = Modifiers(0b0000_1000); // Win / Cmd / Super
    pub const CAPS: Modifiers = Modifiers(0b0001_0000);

    pub const fn empty() -> Modifiers {
        Modifiers(0)
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Modifiers) -> bool {
        (self.0 & other.0) == other.0
    }
    pub fn insert(&mut self, other: Modifiers) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Modifiers) {
        self.0 &= !other.0;
    }
}

impl core::ops::BitOr for Modifiers {
    type Output = Modifiers;
    fn bitor(self, rhs: Modifiers) -> Modifiers {
        Modifiers(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Modifiers {
    fn bitor_assign(&mut self, rhs: Modifiers) {
        self.0 |= rhs.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode, MAX_DATAGRAM_LEN};

    fn round_trip(ev: InputEvent) {
        let bytes = encode(&ev).unwrap();
        assert!(
            bytes.len() <= MAX_DATAGRAM_LEN,
            "hot-path event must fit a datagram"
        );
        let back: InputEvent = decode(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn round_trips_all_kinds() {
        round_trip(InputEvent::new(
            1,
            0,
            InputKind::MouseMoveRel { dx: -3, dy: 7 },
        ));
        round_trip(InputEvent::new(
            1,
            1,
            InputKind::MouseMoveAbs { x: 1920, y: 0 },
        ));
        round_trip(InputEvent::new(
            1,
            2,
            InputKind::MouseButton {
                button: MouseButton::Left,
                pressed: true,
            },
        ));
        round_trip(InputEvent::new(1, 3, InputKind::Wheel { dx: 0, dy: -1 }));
        round_trip(InputEvent::new(
            1,
            4,
            InputKind::Key {
                code: 30,
                pressed: true,
            },
        ));
        round_trip(InputEvent::new(
            1,
            5,
            InputKind::Modifiers {
                state: Modifiers::CTRL | Modifiers::SHIFT,
            },
        ));
    }

    #[test]
    fn typical_event_is_tiny() {
        // Budget check: a relative move with small deltas should be <= 16 bytes.
        let bytes = encode(&InputEvent::new(
            1,
            100,
            InputKind::MouseMoveRel { dx: 2, dy: -2 },
        ))
        .unwrap();
        assert!(bytes.len() <= 16, "got {} bytes", bytes.len());
    }

    #[test]
    fn modifiers_set_ops() {
        let m = Modifiers::CTRL | Modifiers::ALT;
        assert!(m.contains(Modifiers::CTRL));
        assert!(!m.contains(Modifiers::SHIFT));
        assert_eq!((Modifiers::empty()).bits(), 0);
    }
}
