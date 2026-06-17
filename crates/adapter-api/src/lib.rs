#![forbid(unsafe_code)]
//! OS-adapter trait boundary.
//!
//! `core` and `engine` depend only on these traits, never on platform code, so
//! the domain stays testable against [`mock`] implementations and the real
//! per-OS backends (`kvm-adapter-native`) are swappable. Keycodes crossing this
//! boundary are canonical Linux `evdev` codes (see `kvm-proto`); each backend
//! maps to/from its native scancodes.

pub mod mock;

use thiserror::Error;

pub use kvm_proto::v1::input::{Modifiers, MouseButton};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("permission required/denied: {0}")]
    PermissionDenied(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, AdapterError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// A physical display attached to this device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Monitor {
    pub index: u32,
    pub bounds: Rect,
    pub scale: f32,
    pub is_primary: bool,
}

/// A raw local input sample produced by [`InputCapture`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalInput {
    /// Absolute cursor position (logical pixels in the virtual desktop).
    MouseMoveAbs {
        x: i32,
        y: i32,
    },
    /// Relative motion.
    MouseMoveRel {
        dx: i32,
        dy: i32,
    },
    Button {
        button: MouseButton,
        pressed: bool,
    },
    Wheel {
        dx: i32,
        dy: i32,
    },
    Key {
        code: u32,
        pressed: bool,
    },
}

/// OS permission state for a capability — drives the setup-wizard UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionStatus {
    Granted,
    Denied,
    NotDetermined,
    /// The platform needs no special permission for this capability.
    NotRequired,
}

/// Callback the capture backend invokes for each captured event. `Arc` so it can
/// be cheaply shared with the (often OS-thread) capture loop.
pub type EventSink = std::sync::Arc<dyn Fn(LocalInput) + Send + Sync>;

/// Global input capture (used when this machine is the controller).
pub trait InputCapture: Send + Sync {
    /// Begin delivering events to `sink`. Idempotent backends may no-op if armed.
    fn start(&mut self, sink: EventSink) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn permission_status(&self) -> PermissionStatus;
    /// Enter/leave **exclusive** mode: while exclusive, local input must NOT reach
    /// local apps (so driving a remote peer doesn't also act locally). Default:
    /// unsupported (no-op). MUST be safe to call repeatedly; turning it off must
    /// always fully release, even if it was already off.
    fn set_exclusive(&self, on: bool) -> Result<()> {
        let _ = on;
        Ok(())
    }
}

/// Synthesize input locally (used when a remote peer is controlling this machine).
pub trait InputInjection: Send + Sync {
    fn move_abs(&self, x: i32, y: i32) -> Result<()>;
    fn move_rel(&self, dx: i32, dy: i32) -> Result<()>;
    fn button(&self, button: MouseButton, pressed: bool) -> Result<()>;
    fn wheel(&self, dx: i32, dy: i32) -> Result<()>;
    fn key(&self, code: u32, pressed: bool) -> Result<()>;
    /// FAIL-SAFE: release every key/button this injector currently holds down.
    fn release_all(&self) -> Result<()>;
    fn permission_status(&self) -> PermissionStatus;
}

/// A clipboard image as raw RGBA pixels (no codec needed on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub trait Clipboard: Send + Sync {
    fn read_text(&self) -> Result<Option<String>>;
    fn write_text(&self, text: &str) -> Result<()>;
    /// Read an image from the clipboard. Default: unsupported (returns `None`).
    fn read_image(&self) -> Result<Option<ClipboardImage>> {
        Ok(None)
    }
    /// Write an image to the clipboard. Default: no-op.
    fn write_image(&self, image: &ClipboardImage) -> Result<()> {
        let _ = image;
        Ok(())
    }
}

/// Cursor position + warping + multi-monitor geometry.
pub trait CursorGeometry: Send + Sync {
    fn cursor_position(&self) -> Result<Point>;
    /// Warp the cursor. Implementations MUST use native warp APIs (not a generic
    /// input library) to avoid stalling the edge-detection loop.
    fn warp_cursor(&self, x: i32, y: i32) -> Result<()>;
    fn monitors(&self) -> Result<Vec<Monitor>>;
    /// Hide the local hardware cursor while a remote peer is being controlled, so
    /// only ONE visible crosshair exists across both machines. MUST be balanced
    /// with [`CursorGeometry::show_cursor`] and idempotent (hiding twice then
    /// showing once still shows). Default: unsupported (no-op).
    fn hide_cursor(&self) -> Result<()> {
        Ok(())
    }
    /// Restore the local cursor. MUST always make the cursor visible again even
    /// if called when not hidden — the fail-safe against a stranded invisible
    /// pointer. Default: no-op.
    fn show_cursor(&self) -> Result<()> {
        Ok(())
    }
}

/// Bundle of the four adapters for a platform, handed to the engine.
pub struct PlatformAdapters {
    pub capture: Box<dyn InputCapture>,
    pub injection: Box<dyn InputInjection>,
    pub clipboard: Box<dyn Clipboard>,
    pub geometry: Box<dyn CursorGeometry>,
}
