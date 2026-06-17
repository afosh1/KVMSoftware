//! Screen layout graph + edge-transition geometry.
//!
//! Nodes are devices' screen regions; edges are user-arranged adjacency links.
//! This module owns *all* coordinate math for seam crossings so it can be tested
//! exhaustively without any display hardware. Positions along a seam are
//! normalized to `[0,1]`, which makes transitions independent of resolution and
//! HiDPI scale (the destination adapter converts the normalized entry back to
//! physical pixels at injection time).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::device::DeviceId;
pub use kvm_proto::geometry::{Edge, EntryPoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub fn new(x: i32, y: i32) -> Self {
        Point { x, y }
    }
}

/// A rectangle in a device's logical-pixel desktop space (origin top-left).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Rect { x, y, w, h }
    }
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub fn contains(&self, p: Point) -> bool {
        p.x >= self.x && p.x < self.right() && p.y >= self.y && p.y < self.bottom()
    }
}

/// One device's combined screen region (its primary/virtual desktop for MVP).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScreenRegion {
    pub device: DeviceId,
    pub bounds: Rect,
    /// HiDPI scale factor (informational for the UI; seam math is normalized).
    pub scale: f32,
}

/// A directed adjacency: leaving `from`'s `from_edge` enters `to`'s `to_edge`.
/// `from_range`/`to_range` are normalized `[start,end]` spans along each edge so
/// partial overlaps (screens of different heights) map correctly. For a simple
/// full-edge link both ranges are `(0.0, 1.0)`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EdgeLink {
    pub from: DeviceId,
    pub from_edge: Edge,
    pub to: DeviceId,
    pub to_edge: Edge,
    pub from_range: (f32, f32),
    pub to_range: (f32, f32),
}

impl EdgeLink {
    /// A full-edge link plus its reverse (the common case from the layout editor
    /// when the user drops one screen beside another).
    pub fn simple(from: DeviceId, from_edge: Edge, to: DeviceId) -> EdgeLink {
        EdgeLink {
            from,
            from_edge,
            to,
            to_edge: from_edge.opposite(),
            from_range: (0.0, 1.0),
            to_range: (0.0, 1.0),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LayoutGraph {
    regions: HashMap<DeviceId, ScreenRegion>,
    links: Vec<EdgeLink>,
}

impl LayoutGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_region(&mut self, region: ScreenRegion) {
        self.regions.insert(region.device, region);
    }

    pub fn region(&self, device: DeviceId) -> Option<&ScreenRegion> {
        self.regions.get(&device)
    }

    /// Add a link and its symmetric reverse (so crossing back returns home).
    pub fn link_bidirectional(&mut self, from: DeviceId, from_edge: Edge, to: DeviceId) {
        self.links.push(EdgeLink::simple(from, from_edge, to));
        self.links
            .push(EdgeLink::simple(to, from_edge.opposite(), from));
    }

    pub fn add_link(&mut self, link: EdgeLink) {
        self.links.push(link);
    }

    pub fn links(&self) -> &[EdgeLink] {
        &self.links
    }

    /// Remove every region and link referencing `device` (e.g. on revoke).
    pub fn remove_device(&mut self, device: DeviceId) {
        self.regions.remove(&device);
        self.links.retain(|l| l.from != device && l.to != device);
    }

    /// If `cursor` (in `device`'s space) sits within `band` pixels of an edge
    /// that has an outgoing link, return that edge and the normalized position
    /// along it. Returns the *nearest linked* edge if multiple apply.
    pub fn edge_at(&self, device: DeviceId, cursor: Point, band: i32) -> Option<(Edge, f32)> {
        self.edge_at_with_corner(device, cursor, band, 0)
    }

    /// Like [`LayoutGraph::edge_at`], but suppresses crossings within `corner`
    /// pixels of a screen corner (a "dead corner") so reaching for a corner UI
    /// target — a close button, a hot corner — doesn't accidentally hand off.
    pub fn edge_at_with_corner(
        &self,
        device: DeviceId,
        cursor: Point,
        band: i32,
        corner: i32,
    ) -> Option<(Edge, f32)> {
        let region = self.regions.get(&device)?;
        let b = region.bounds;
        if b.w <= 0 || b.h <= 0 {
            return None;
        }

        // Dead corner: too close to BOTH a vertical and a horizontal edge at once.
        if corner > 0 {
            let near_vert = (cursor.x - b.x).min(b.right() - 1 - cursor.x) < corner;
            let near_horiz = (cursor.y - b.y).min(b.bottom() - 1 - cursor.y) < corner;
            if near_vert && near_horiz {
                return None;
            }
        }

        // Distance to each edge; only consider edges that actually have a link.
        let mut best: Option<(Edge, i32, f32)> = None;
        let mut consider = |edge: Edge, dist: i32, pos: f32| {
            if dist <= band && self.has_link(device, edge) {
                let pos = pos.clamp(0.0, 1.0);
                match best {
                    Some((_, d, _)) if d <= dist => {}
                    _ => best = Some((edge, dist, pos)),
                }
            }
        };

        let nx = (cursor.x - b.x) as f32 / b.w as f32; // normalized x within region
        let ny = (cursor.y - b.y) as f32 / b.h as f32;

        consider(Edge::Left, cursor.x - b.x, ny);
        consider(Edge::Right, b.right() - 1 - cursor.x, ny);
        consider(Edge::Top, cursor.y - b.y, nx);
        consider(Edge::Bottom, b.bottom() - 1 - cursor.y, nx);

        best.map(|(edge, _, pos)| (edge, pos))
    }

    fn has_link(&self, device: DeviceId, edge: Edge) -> bool {
        self.links
            .iter()
            .any(|l| l.from == device && l.from_edge == edge)
    }

    /// Resolve a seam crossing: leaving `device` via `edge` at normalized `pos`,
    /// which device do we enter and at what [`EntryPoint`]?
    pub fn resolve_transition(
        &self,
        device: DeviceId,
        edge: Edge,
        pos: f32,
    ) -> Option<(DeviceId, EntryPoint)> {
        let link = self
            .links
            .iter()
            .find(|l| l.from == device && l.from_edge == edge && in_range(pos, l.from_range))?;
        // Map pos from the source span onto the destination span.
        let mapped = remap(pos, link.from_range, link.to_range);
        Some((link.to, EntryPoint::new(link.to_edge, mapped)))
    }

    /// Convert a normalized [`EntryPoint`] to an absolute pixel point a few
    /// pixels inside the destination region — where the cursor should warp to.
    pub fn entry_to_point(&self, device: DeviceId, entry: EntryPoint, inset: i32) -> Option<Point> {
        let b = self.regions.get(&device)?.bounds;
        let p = match entry.edge {
            Edge::Left => Point::new(b.x + inset, b.y + along(entry.pos, b.h)),
            Edge::Right => Point::new(b.right() - 1 - inset, b.y + along(entry.pos, b.h)),
            Edge::Top => Point::new(b.x + along(entry.pos, b.w), b.y + inset),
            Edge::Bottom => Point::new(b.x + along(entry.pos, b.w), b.bottom() - 1 - inset),
        };
        Some(p)
    }
}

fn along(pos: f32, extent: i32) -> i32 {
    ((pos.clamp(0.0, 1.0)) * (extent.max(1) - 1) as f32).round() as i32
}

fn in_range(pos: f32, range: (f32, f32)) -> bool {
    let (lo, hi) = (range.0.min(range.1), range.0.max(range.1));
    pos >= lo - f32::EPSILON && pos <= hi + f32::EPSILON
}

/// Linearly remap `pos` from the `src` span onto the `dst` span.
fn remap(pos: f32, src: (f32, f32), dst: (f32, f32)) -> f32 {
    let span = src.1 - src.0;
    let t = if span.abs() < f32::EPSILON {
        0.0
    } else {
        ((pos - src.0) / span).clamp(0.0, 1.0)
    };
    (dst.0 + t * (dst.1 - dst.0)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u128) -> DeviceId {
        DeviceId(uuid::Uuid::from_u128(n))
    }

    /// Two side-by-side 1920x1080 screens: A on the left of B.
    fn two_screen_graph() -> (LayoutGraph, DeviceId, DeviceId) {
        let a = dev(1);
        let b = dev(2);
        let mut g = LayoutGraph::new();
        g.upsert_region(ScreenRegion {
            device: a,
            bounds: Rect::new(0, 0, 1920, 1080),
            scale: 1.0,
        });
        g.upsert_region(ScreenRegion {
            device: b,
            bounds: Rect::new(0, 0, 1920, 1080),
            scale: 1.0,
        });
        g.link_bidirectional(a, Edge::Right, b);
        (g, a, b)
    }

    #[test]
    fn detects_right_edge_within_band() {
        let (g, a, _b) = two_screen_graph();
        // Cursor at far right, vertically centered.
        let hit = g.edge_at(a, Point::new(1919, 540), 2);
        assert!(hit.is_some());
        let (edge, pos) = hit.unwrap();
        assert_eq!(edge, Edge::Right);
        assert!((pos - 0.5).abs() < 0.01, "pos={pos}");
    }

    #[test]
    fn no_edge_when_centered() {
        let (g, a, _b) = two_screen_graph();
        assert_eq!(g.edge_at(a, Point::new(960, 540), 2), None);
    }

    #[test]
    fn dead_corner_suppresses_crossing() {
        let (g, a, _b) = two_screen_graph();
        // Top-right corner of A (linked on the right): within the dead corner.
        assert!(g
            .edge_at_with_corner(a, Point::new(1919, 5), 3, 24)
            .is_none());
        // Mid-right edge, well clear of any corner: still crosses.
        let hit = g.edge_at_with_corner(a, Point::new(1919, 540), 3, 24);
        assert_eq!(hit.map(|(e, _)| e), Some(Edge::Right));
        // With no corner dead-zone, the corner crosses as before.
        assert!(g
            .edge_at_with_corner(a, Point::new(1919, 5), 3, 0)
            .is_some());
    }

    #[test]
    fn unlinked_edge_is_ignored() {
        let (g, a, _b) = two_screen_graph();
        // Left edge of A has no link → no transition armed there.
        assert_eq!(g.edge_at(a, Point::new(0, 540), 2), None);
    }

    #[test]
    fn resolve_maps_to_opposite_edge_same_position() {
        let (g, a, b) = two_screen_graph();
        let (to, entry) = g.resolve_transition(a, Edge::Right, 0.5).unwrap();
        assert_eq!(to, b);
        assert_eq!(entry.edge, Edge::Left); // enters B on its left
        assert!((entry.pos - 0.5).abs() < 0.001);
    }

    #[test]
    fn round_trip_back_home() {
        let (g, a, b) = two_screen_graph();
        // Going A->B then B->A (the reverse link) should resolve home.
        let (to_b, _e) = g.resolve_transition(a, Edge::Right, 0.3).unwrap();
        assert_eq!(to_b, b);
        let (to_a, entry) = g.resolve_transition(b, Edge::Left, 0.3).unwrap();
        assert_eq!(to_a, a);
        assert_eq!(entry.edge, Edge::Right);
    }

    #[test]
    fn entry_to_point_lands_inside_region() {
        let (g, _a, b) = two_screen_graph();
        let p = g
            .entry_to_point(b, EntryPoint::new(Edge::Left, 0.5), 2)
            .unwrap();
        assert_eq!(p.x, 2); // 2px inset from left
        assert!((p.y - 539).abs() <= 1); // ~vertical center of 1080
        assert!(g.region(b).unwrap().bounds.contains(p));
    }

    #[test]
    fn partial_overlap_remaps_position() {
        // A (tall) links to B (short) covering only A's top half.
        let a = dev(1);
        let b = dev(2);
        let mut g = LayoutGraph::new();
        g.upsert_region(ScreenRegion {
            device: a,
            bounds: Rect::new(0, 0, 100, 200),
            scale: 1.0,
        });
        g.upsert_region(ScreenRegion {
            device: b,
            bounds: Rect::new(0, 0, 100, 100),
            scale: 1.0,
        });
        g.add_link(EdgeLink {
            from: a,
            from_edge: Edge::Right,
            to: b,
            to_edge: Edge::Left,
            from_range: (0.0, 0.5), // top half of A
            to_range: (0.0, 1.0),   // full height of B
        });
        // Midpoint of the source span (pos 0.25) maps to B's middle (0.5).
        let (to, entry) = g.resolve_transition(a, Edge::Right, 0.25).unwrap();
        assert_eq!(to, b);
        assert!((entry.pos - 0.5).abs() < 0.001, "pos={}", entry.pos);
        // Outside the source span → no transition.
        assert!(g.resolve_transition(a, Edge::Right, 0.9).is_none());
    }

    #[test]
    fn remove_device_clears_links() {
        let (mut g, a, b) = two_screen_graph();
        g.remove_device(b);
        assert!(g.region(b).is_none());
        assert!(g.edge_at(a, Point::new(1919, 540), 2).is_none());
    }
}
