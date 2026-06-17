//! Wire-level geometry primitives shared by the protocol and the domain layer.
//!
//! These live in `proto` (not `core`) because they appear on the wire — e.g. a
//! [`crate::v1::ControlMsg::SwitchRequest`] carries the [`EntryPoint`] at which
//! the cursor should re-enter the destination screen. `core` re-exports them.

use serde::{Deserialize, Serialize};

/// A screen edge. Used both for layout adjacency and for seam crossings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Edge {
    Top,
    Bottom,
    Left,
    Right,
}

impl Edge {
    /// The opposing edge — where the cursor enters on the neighbour screen.
    pub fn opposite(self) -> Edge {
        match self {
            Edge::Top => Edge::Bottom,
            Edge::Bottom => Edge::Top,
            Edge::Left => Edge::Right,
            Edge::Right => Edge::Left,
        }
    }

    /// Whether this edge is horizontal (Top/Bottom) — the cursor varies in X.
    pub fn is_horizontal(self) -> bool {
        matches!(self, Edge::Top | Edge::Bottom)
    }
}

/// Where the cursor re-enters a destination screen after crossing a seam.
///
/// `pos` is normalized to `[0.0, 1.0]` along the entry `edge`, independent of
/// resolution/DPI, so the entry point survives screens of different sizes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EntryPoint {
    pub edge: Edge,
    pub pos: f32,
}

impl EntryPoint {
    pub fn new(edge: Edge, pos: f32) -> Self {
        Self {
            edge,
            pos: pos.clamp(0.0, 1.0),
        }
    }
}

/// A device's combined desktop size, exchanged in the [`crate::v1::Hello`] so the
/// peer can place this device's screen region at its *real* resolution (not a
/// hardcoded default). `scale` is the HiDPI factor (logical→physical).
///
/// Not `Eq` because `scale` is a float.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScreenGeom {
    /// Logical-pixel width of the device's combined desktop.
    pub w: i32,
    /// Logical-pixel height of the device's combined desktop.
    pub h: i32,
    /// HiDPI scale factor (1.0 = no scaling).
    pub scale: f32,
}

impl ScreenGeom {
    pub fn new(w: i32, h: i32, scale: f32) -> Self {
        ScreenGeom { w, h, scale }
    }
}

impl Default for ScreenGeom {
    /// A neutral 1920x1080 @1.0 — used only as a fallback when a peer predates
    /// geometry exchange or no display can be queried.
    fn default() -> Self {
        ScreenGeom {
            w: 1920,
            h: 1080,
            scale: 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opposite_is_involutive() {
        for e in [Edge::Top, Edge::Bottom, Edge::Left, Edge::Right] {
            assert_eq!(e.opposite().opposite(), e);
            assert_ne!(e.opposite(), e);
        }
    }

    #[test]
    fn entry_point_clamps() {
        assert_eq!(EntryPoint::new(Edge::Left, 1.5).pos, 1.0);
        assert_eq!(EntryPoint::new(Edge::Left, -0.5).pos, 0.0);
    }
}
