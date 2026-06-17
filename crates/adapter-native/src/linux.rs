//! Linux X11 injection + geometry via pure-Rust `x11rb` (no libxdo).
//!
//! Injection uses the XTEST extension; the X11 keycode is `evdev + 8`. Geometry
//! uses core X (`query_pointer`/`warp_pointer`) and RandR for multi-monitor
//! bounds. Held keys/buttons are tracked so `release_all` is precise.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use kvm_adapter_api::{
    AdapterError, CursorGeometry, InputInjection, Monitor, MouseButton, PermissionStatus,
    PlatformAdapters, Point, Rect, Result,
};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{
    ConnectionExt as _, EventMask, GrabMode, GrabStatus, Window, BUTTON_PRESS_EVENT,
    BUTTON_RELEASE_EVENT, KEY_PRESS_EVENT, KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::capture::RdevCapture;
use crate::clipboard::ArboardClipboard;
use crate::keymap::{button_to_x11, evdev_to_x11_keycode};

fn be<E: std::fmt::Display>(e: E) -> AdapterError {
    AdapterError::Backend(e.to_string())
}

fn open() -> Result<(RustConnection, Window)> {
    let (conn, screen) = x11rb::connect(None).map_err(be)?;
    let root = conn.setup().roots[screen].root;
    Ok((conn, root))
}

/// Assemble the Linux adapter bundle.
pub fn adapters() -> Result<PlatformAdapters> {
    Ok(PlatformAdapters {
        capture: Box::new(RdevCapture::new()),
        injection: Box::new(X11Injection::new()?),
        clipboard: Box::new(ArboardClipboard::new()),
        geometry: Box::new(X11Geometry::new()?),
    })
}

pub struct X11Injection {
    conn: RustConnection,
    root: Window,
    pressed_keys: Mutex<HashSet<u8>>,
    pressed_buttons: Mutex<HashSet<u8>>,
}

impl X11Injection {
    pub fn new() -> Result<Self> {
        let (conn, root) = open()?;
        // Confirm XTEST is present.
        conn.xtest_get_version(2, 2)
            .map_err(be)?
            .reply()
            .map_err(be)?;
        Ok(X11Injection {
            conn,
            root,
            pressed_keys: Mutex::new(HashSet::new()),
            pressed_buttons: Mutex::new(HashSet::new()),
        })
    }

    fn fake(&self, type_: u8, detail: u8, x: i16, y: i16) -> Result<()> {
        self.conn
            .xtest_fake_input(type_, detail, 0, self.root, x, y, 0)
            .map_err(be)?;
        self.conn.flush().map_err(be)?;
        Ok(())
    }
}

impl InputInjection for X11Injection {
    fn move_abs(&self, x: i32, y: i32) -> Result<()> {
        self.conn
            .warp_pointer(x11rb::NONE, self.root, 0, 0, 0, 0, x as i16, y as i16)
            .map_err(be)?;
        self.conn.flush().map_err(be)?;
        Ok(())
    }

    fn move_rel(&self, dx: i32, dy: i32) -> Result<()> {
        // XTEST relative motion: detail=1 means deltas in (x, y).
        self.conn
            .xtest_fake_input(
                MOTION_NOTIFY_EVENT,
                1,
                0,
                x11rb::NONE,
                dx as i16,
                dy as i16,
                0,
            )
            .map_err(be)?;
        self.conn.flush().map_err(be)?;
        Ok(())
    }

    fn button(&self, button: MouseButton, pressed: bool) -> Result<()> {
        let detail = button_to_x11(button);
        let type_ = if pressed {
            BUTTON_PRESS_EVENT
        } else {
            BUTTON_RELEASE_EVENT
        };
        self.fake(type_, detail, 0, 0)?;
        let mut set = self.pressed_buttons.lock().unwrap();
        if pressed {
            set.insert(detail);
        } else {
            set.remove(&detail);
        }
        Ok(())
    }

    fn wheel(&self, dx: i32, dy: i32) -> Result<()> {
        // Wheel is modeled as button clicks: 4=up,5=down,6=left,7=right.
        let click = |btn: u8, n: i32| -> Result<()> {
            for _ in 0..n.unsigned_abs() {
                self.fake(BUTTON_PRESS_EVENT, btn, 0, 0)?;
                self.fake(BUTTON_RELEASE_EVENT, btn, 0, 0)?;
            }
            Ok(())
        };
        if dy != 0 {
            click(if dy > 0 { 4 } else { 5 }, dy)?;
        }
        if dx != 0 {
            click(if dx > 0 { 7 } else { 6 }, dx)?;
        }
        Ok(())
    }

    fn key(&self, code: u32, pressed: bool) -> Result<()> {
        let kc = evdev_to_x11_keycode(code)
            .ok_or_else(|| AdapterError::Backend(format!("keycode {code} out of range")))?;
        let type_ = if pressed {
            KEY_PRESS_EVENT
        } else {
            KEY_RELEASE_EVENT
        };
        self.fake(type_, kc, 0, 0)?;
        let mut set = self.pressed_keys.lock().unwrap();
        if pressed {
            set.insert(kc);
        } else {
            set.remove(&kc);
        }
        Ok(())
    }

    fn release_all(&self) -> Result<()> {
        let keys: Vec<u8> = self.pressed_keys.lock().unwrap().drain().collect();
        for kc in keys {
            let _ = self.fake(KEY_RELEASE_EVENT, kc, 0, 0);
        }
        let buttons: Vec<u8> = self.pressed_buttons.lock().unwrap().drain().collect();
        for b in buttons {
            let _ = self.fake(BUTTON_RELEASE_EVENT, b, 0, 0);
        }
        Ok(())
    }

    fn permission_status(&self) -> PermissionStatus {
        PermissionStatus::NotRequired
    }
}

/// Exclusive input grab (X11). While grabbed, pointer + keyboard events are
/// withheld from local applications, so driving a remote peer doesn't also act
/// locally. `rdev`'s XRecord capture still observes the events for forwarding.
///
/// Ungrabs on drop as a safety backstop — a stuck grab would lock the session.
pub struct X11Grabber {
    conn: RustConnection,
    root: Window,
    grabbed: std::sync::atomic::AtomicBool,
}

impl X11Grabber {
    pub fn new() -> Result<Self> {
        let (conn, root) = open()?;
        Ok(X11Grabber {
            conn,
            root,
            grabbed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn grab(&self) -> Result<()> {
        // event_mask = NO_EVENT: we don't want the events ourselves; the grab
        // still withholds them from other clients. Confine the pointer to the
        // screen; keep the existing cursor.
        let p = self
            .conn
            .grab_pointer(
                false,
                self.root,
                EventMask::NO_EVENT,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
                self.root,
                x11rb::NONE,
                x11rb::CURRENT_TIME,
            )
            .map_err(be)?
            .reply()
            .map_err(be)?;
        if p.status != GrabStatus::SUCCESS {
            return Err(AdapterError::Backend(format!(
                "pointer grab refused: {:?} (another client holds an active grab?)",
                p.status
            )));
        }
        let k = self
            .conn
            .grab_keyboard(
                false,
                self.root,
                x11rb::CURRENT_TIME,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
            )
            .map_err(be)?
            .reply()
            .map_err(be)?;
        if k.status != GrabStatus::SUCCESS {
            // Don't leave a half-grab (pointer held, keyboard not): release the
            // pointer so local input is never silently half-suppressed.
            let _ = self.conn.ungrab_pointer(x11rb::CURRENT_TIME);
            let _ = self.conn.flush();
            return Err(AdapterError::Backend(format!(
                "keyboard grab refused: {:?}",
                k.status
            )));
        }
        self.conn.flush().map_err(be)?;
        self.grabbed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn ungrab(&self) -> Result<()> {
        self.conn.ungrab_pointer(x11rb::CURRENT_TIME).map_err(be)?;
        self.conn.ungrab_keyboard(x11rb::CURRENT_TIME).map_err(be)?;
        self.conn.flush().map_err(be)?;
        self.grabbed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

impl Drop for X11Grabber {
    fn drop(&mut self) {
        if self.grabbed.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self.conn.ungrab_pointer(x11rb::CURRENT_TIME);
            let _ = self.conn.ungrab_keyboard(x11rb::CURRENT_TIME);
            let _ = self.conn.flush();
        }
    }
}

pub struct X11Geometry {
    conn: RustConnection,
    root: Window,
    /// Whether XFixes negotiated successfully (hide/show available).
    xfixes_ok: bool,
    /// Tracks our own hide so hide/show stay balanced and idempotent (XFixes
    /// cursor visibility is reference-counted server-side).
    hidden: AtomicBool,
}

impl X11Geometry {
    pub fn new() -> Result<Self> {
        let (conn, root) = open()?;
        // XFixes must be version-negotiated before any of its requests are used.
        // Treat absence as non-fatal: hide/show degrade to no-ops (the grab and
        // warp-to-center still suppress local action; only the cosmetic hide is
        // lost on ancient servers).
        let xfixes_ok = conn
            .xfixes_query_version(5, 0)
            .ok()
            .and_then(|c| c.reply().ok())
            .is_some();
        if !xfixes_ok {
            tracing::warn!("XFixes unavailable; local cursor will not be hidden during handoff");
        }
        Ok(X11Geometry {
            conn,
            root,
            xfixes_ok,
            hidden: AtomicBool::new(false),
        })
    }
}

impl CursorGeometry for X11Geometry {
    fn cursor_position(&self) -> Result<Point> {
        let r = self
            .conn
            .query_pointer(self.root)
            .map_err(be)?
            .reply()
            .map_err(be)?;
        Ok(Point {
            x: r.root_x as i32,
            y: r.root_y as i32,
        })
    }

    fn warp_cursor(&self, x: i32, y: i32) -> Result<()> {
        self.conn
            .warp_pointer(x11rb::NONE, self.root, 0, 0, 0, 0, x as i16, y as i16)
            .map_err(be)?;
        self.conn.flush().map_err(be)?;
        Ok(())
    }

    fn monitors(&self) -> Result<Vec<Monitor>> {
        let reply = self
            .conn
            .randr_get_monitors(self.root, true)
            .map_err(be)?
            .reply()
            .map_err(be)?;
        let mut out: Vec<Monitor> = reply
            .monitors
            .iter()
            .enumerate()
            .map(|(i, m)| Monitor {
                index: i as u32,
                bounds: Rect {
                    x: m.x as i32,
                    y: m.y as i32,
                    w: m.width as i32,
                    h: m.height as i32,
                },
                scale: 1.0,
                is_primary: m.primary,
            })
            .collect();

        if out.is_empty() {
            let g = self
                .conn
                .get_geometry(self.root)
                .map_err(be)?
                .reply()
                .map_err(be)?;
            out.push(Monitor {
                index: 0,
                bounds: Rect {
                    x: 0,
                    y: 0,
                    w: g.width as i32,
                    h: g.height as i32,
                },
                scale: 1.0,
                is_primary: true,
            });
        }
        Ok(out)
    }

    fn hide_cursor(&self) -> Result<()> {
        // Only hide once (XFixes ref-counts), and only if XFixes is present.
        if self.xfixes_ok && !self.hidden.swap(true, Ordering::SeqCst) {
            self.conn.xfixes_hide_cursor(self.root).map_err(be)?;
            self.conn.flush().map_err(be)?;
        }
        Ok(())
    }

    fn show_cursor(&self) -> Result<()> {
        // Fail-safe: always restore. Balance our own hide (avoid driving the
        // server ref-count negative when we never hid).
        if self.xfixes_ok && self.hidden.swap(false, Ordering::SeqCst) {
            self.conn.xfixes_show_cursor(self.root).map_err(be)?;
            self.conn.flush().map_err(be)?;
        }
        Ok(())
    }
}
