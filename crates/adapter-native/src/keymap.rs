//! Keycode + button mapping between `rdev` (capture) and the canonical Linux
//! `evdev` keycodes used on the wire.
//!
//! The evdev space is canonical because on X11 the injection keycode is simply
//! `evdev + 8`, making Linux injection trivial. This map covers the common
//! keyboard; unmapped keys are dropped (extend as needed for full coverage —
//! the on-hardware completion item).

use kvm_adapter_api::MouseButton;
use rdev::{Button as RButton, Key as RKey};

/// Map an `rdev` key to its canonical evdev code.
pub fn rdev_key_to_evdev(k: RKey) -> Option<u32> {
    use RKey::*;
    let code = match k {
        Escape => 1,
        Num1 => 2,
        Num2 => 3,
        Num3 => 4,
        Num4 => 5,
        Num5 => 6,
        Num6 => 7,
        Num7 => 8,
        Num8 => 9,
        Num9 => 10,
        Num0 => 11,
        Minus => 12,
        Equal => 13,
        Backspace => 14,
        Tab => 15,
        KeyQ => 16,
        KeyW => 17,
        KeyE => 18,
        KeyR => 19,
        KeyT => 20,
        KeyY => 21,
        KeyU => 22,
        KeyI => 23,
        KeyO => 24,
        KeyP => 25,
        LeftBracket => 26,
        RightBracket => 27,
        Return => 28,
        ControlLeft => 29,
        KeyA => 30,
        KeyS => 31,
        KeyD => 32,
        KeyF => 33,
        KeyG => 34,
        KeyH => 35,
        KeyJ => 36,
        KeyK => 37,
        KeyL => 38,
        SemiColon => 39,
        Quote => 40,
        BackQuote => 41,
        ShiftLeft => 42,
        BackSlash => 43,
        KeyZ => 44,
        KeyX => 45,
        KeyC => 46,
        KeyV => 47,
        KeyB => 48,
        KeyN => 49,
        KeyM => 50,
        Comma => 51,
        Dot => 52,
        Slash => 53,
        ShiftRight => 54,
        Alt => 56,
        Space => 57,
        CapsLock => 58,
        F1 => 59,
        F2 => 60,
        F3 => 61,
        F4 => 62,
        F5 => 63,
        F6 => 64,
        F7 => 65,
        F8 => 66,
        F9 => 67,
        F10 => 68,
        NumLock => 69,
        ScrollLock => 70,
        F11 => 87,
        F12 => 88,
        ControlRight => 97,
        AltGr => 100,
        Home => 102,
        UpArrow => 103,
        PageUp => 104,
        LeftArrow => 105,
        RightArrow => 106,
        End => 107,
        DownArrow => 108,
        PageDown => 109,
        Insert => 110,
        Delete => 111,
        MetaLeft => 125,
        MetaRight => 126,
        // rdev exposes raw platform codes for unmapped keys; we can't assume
        // they're evdev, so drop them rather than inject the wrong key.
        Unknown(_) => return None,
        _ => return None,
    };
    Some(code)
}

pub fn button_from_rdev(b: RButton) -> Option<MouseButton> {
    match b {
        RButton::Left => Some(MouseButton::Left),
        RButton::Right => Some(MouseButton::Right),
        RButton::Middle => Some(MouseButton::Middle),
        RButton::Unknown(8) => Some(MouseButton::Back),
        RButton::Unknown(9) => Some(MouseButton::Forward),
        RButton::Unknown(_) => None,
    }
}

/// X11 injection keycode for an evdev code (the well-known `+8` offset).
#[cfg(target_os = "linux")]
pub fn evdev_to_x11_keycode(code: u32) -> Option<u8> {
    let kc = code + 8;
    u8::try_from(kc).ok()
}

/// XTEST button number for a logical mouse button.
#[cfg(target_os = "linux")]
pub fn button_to_x11(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
        MouseButton::Back => 8,
        MouseButton::Forward => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_keys_map_to_evdev() {
        assert_eq!(rdev_key_to_evdev(RKey::KeyA), Some(30));
        assert_eq!(rdev_key_to_evdev(RKey::Space), Some(57));
        assert_eq!(rdev_key_to_evdev(RKey::Escape), Some(1));
        assert_eq!(rdev_key_to_evdev(RKey::Unknown(999)), None);
    }

    #[test]
    fn buttons_map() {
        assert_eq!(button_from_rdev(RButton::Left), Some(MouseButton::Left));
        assert_eq!(button_from_rdev(RButton::Middle), Some(MouseButton::Middle));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn x11_keycode_offset() {
        assert_eq!(evdev_to_x11_keycode(30), Some(38)); // 'A': 30 + 8
        assert_eq!(button_to_x11(MouseButton::Right), 3);
    }
}
