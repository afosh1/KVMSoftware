//! Windows/macOS injection + geometry via `enigo` (no extra system libs).
//!
//! Compiled only on non-Linux targets and verified by the Windows/macOS CI
//! runners (and on-hardware). A fresh `Enigo` is created per call to avoid
//! `Send`/`Sync` concerns with stored platform state. Keymap coverage is the
//! common set; extend on hardware.

#![cfg(not(target_os = "linux"))]

use enigo::{
    Axis, Button as EButton, Coordinate, Direction, Enigo, Key as EKey, Keyboard, Mouse, Settings,
};

use kvm_adapter_api::{
    AdapterError, CursorGeometry, InputInjection, Monitor, MouseButton, PermissionStatus,
    PlatformAdapters, Point, Rect, Result,
};

use crate::capture::RdevCapture;
use crate::clipboard::ArboardClipboard;

fn be<E: std::fmt::Display>(e: E) -> AdapterError {
    AdapterError::Backend(e.to_string())
}

fn enigo() -> Result<Enigo> {
    Enigo::new(&Settings::default()).map_err(be)
}

fn dir(pressed: bool) -> Direction {
    if pressed {
        Direction::Press
    } else {
        Direction::Release
    }
}

pub fn adapters() -> Result<PlatformAdapters> {
    Ok(PlatformAdapters {
        capture: Box::new(RdevCapture::new()),
        injection: Box::new(EnigoInjection),
        clipboard: Box::new(ArboardClipboard::new()),
        geometry: Box::new(EnigoGeometry),
    })
}

pub struct EnigoInjection;

/// enigo has no Back/Forward buttons on macOS, so those presses are dropped there.
fn map_button(b: MouseButton) -> Option<EButton> {
    match b {
        MouseButton::Left => Some(EButton::Left),
        MouseButton::Right => Some(EButton::Right),
        MouseButton::Middle => Some(EButton::Middle),
        #[cfg(not(target_os = "macos"))]
        MouseButton::Back => Some(EButton::Back),
        #[cfg(not(target_os = "macos"))]
        MouseButton::Forward => Some(EButton::Forward),
        #[cfg(target_os = "macos")]
        MouseButton::Back | MouseButton::Forward => None,
    }
}

/// Map a canonical evdev code to an enigo key. Printable keys use their US-layout
/// unshifted character; named keys map directly.
fn map_key(code: u32) -> Option<EKey> {
    let unicode = |c: char| Some(EKey::Unicode(c));
    match code {
        1 => Some(EKey::Escape),
        2 => unicode('1'),
        3 => unicode('2'),
        4 => unicode('3'),
        5 => unicode('4'),
        6 => unicode('5'),
        7 => unicode('6'),
        8 => unicode('7'),
        9 => unicode('8'),
        10 => unicode('9'),
        11 => unicode('0'),
        12 => unicode('-'),
        13 => unicode('='),
        14 => Some(EKey::Backspace),
        15 => Some(EKey::Tab),
        16 => unicode('q'),
        17 => unicode('w'),
        18 => unicode('e'),
        19 => unicode('r'),
        20 => unicode('t'),
        21 => unicode('y'),
        22 => unicode('u'),
        23 => unicode('i'),
        24 => unicode('o'),
        25 => unicode('p'),
        26 => unicode('['),
        27 => unicode(']'),
        28 => Some(EKey::Return),
        29 => Some(EKey::Control),
        30 => unicode('a'),
        31 => unicode('s'),
        32 => unicode('d'),
        33 => unicode('f'),
        34 => unicode('g'),
        35 => unicode('h'),
        36 => unicode('j'),
        37 => unicode('k'),
        38 => unicode('l'),
        39 => unicode(';'),
        40 => unicode('\''),
        41 => unicode('`'),
        42 => Some(EKey::Shift),
        43 => unicode('\\'),
        44 => unicode('z'),
        45 => unicode('x'),
        46 => unicode('c'),
        47 => unicode('v'),
        48 => unicode('b'),
        49 => unicode('n'),
        50 => unicode('m'),
        51 => unicode(','),
        52 => unicode('.'),
        53 => unicode('/'),
        54 => Some(EKey::Shift),
        56 => Some(EKey::Alt),
        57 => Some(EKey::Space),
        58 => Some(EKey::CapsLock),
        59 => Some(EKey::F1),
        60 => Some(EKey::F2),
        61 => Some(EKey::F3),
        62 => Some(EKey::F4),
        63 => Some(EKey::F5),
        64 => Some(EKey::F6),
        65 => Some(EKey::F7),
        66 => Some(EKey::F8),
        67 => Some(EKey::F9),
        68 => Some(EKey::F10),
        87 => Some(EKey::F11),
        88 => Some(EKey::F12),
        97 => Some(EKey::Control),
        100 => Some(EKey::Alt),
        102 => Some(EKey::Home),
        103 => Some(EKey::UpArrow),
        104 => Some(EKey::PageUp),
        105 => Some(EKey::LeftArrow),
        106 => Some(EKey::RightArrow),
        107 => Some(EKey::End),
        108 => Some(EKey::DownArrow),
        109 => Some(EKey::PageDown),
        111 => Some(EKey::Delete),
        125 => Some(EKey::Meta),
        126 => Some(EKey::Meta),
        _ => None,
    }
}

impl InputInjection for EnigoInjection {
    fn move_abs(&self, x: i32, y: i32) -> Result<()> {
        enigo()?.move_mouse(x, y, Coordinate::Abs).map_err(be)
    }
    fn move_rel(&self, dx: i32, dy: i32) -> Result<()> {
        enigo()?.move_mouse(dx, dy, Coordinate::Rel).map_err(be)
    }
    fn button(&self, button: MouseButton, pressed: bool) -> Result<()> {
        let Some(button) = map_button(button) else {
            return Ok(());
        };
        enigo()?.button(button, dir(pressed)).map_err(be)
    }
    fn wheel(&self, dx: i32, dy: i32) -> Result<()> {
        let mut e = enigo()?;
        if dy != 0 {
            e.scroll(-dy, Axis::Vertical).map_err(be)?;
        }
        if dx != 0 {
            e.scroll(dx, Axis::Horizontal).map_err(be)?;
        }
        Ok(())
    }
    fn key(&self, code: u32, pressed: bool) -> Result<()> {
        if let Some(k) = map_key(code) {
            enigo()?.key(k, dir(pressed)).map_err(be)
        } else {
            Ok(()) // drop unmapped keys rather than inject the wrong one
        }
    }
    fn release_all(&self) -> Result<()> {
        // Without stored state, conservatively release the common modifiers.
        let mut e = enigo()?;
        for k in [EKey::Shift, EKey::Control, EKey::Alt, EKey::Meta] {
            let _ = e.key(k, Direction::Release);
        }
        let _ = e.button(EButton::Left, Direction::Release);
        Ok(())
    }
    fn permission_status(&self) -> PermissionStatus {
        #[cfg(target_os = "macos")]
        {
            PermissionStatus::NotDetermined
        }
        #[cfg(not(target_os = "macos"))]
        {
            PermissionStatus::NotRequired
        }
    }
}

pub struct EnigoGeometry;

impl CursorGeometry for EnigoGeometry {
    fn cursor_position(&self) -> Result<Point> {
        let (x, y) = enigo()?.location().map_err(be)?;
        Ok(Point { x, y })
    }
    fn warp_cursor(&self, x: i32, y: i32) -> Result<()> {
        enigo()?.move_mouse(x, y, Coordinate::Abs).map_err(be)
    }
    fn monitors(&self) -> Result<Vec<Monitor>> {
        // enigo exposes the main display size; multi-monitor enumeration is a
        // per-OS follow-up (EnumDisplayMonitors / NSScreen).
        let (w, h) = enigo()?.main_display().map_err(be)?;
        Ok(vec![Monitor {
            index: 0,
            bounds: Rect { x: 0, y: 0, w, h },
            scale: 1.0,
            is_primary: true,
        }])
    }
}
