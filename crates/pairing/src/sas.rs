//! Short Authentication String (SAS) derivation.
//!
//! After SPAKE2 yields a shared key, both devices derive the *same* SAS from
//! that key plus both certificate fingerprints (order-independent). The user
//! compares the SAS on both screens; a mismatch reveals a man-in-the-middle,
//! because an attacker who didn't know the pairing code derives a different key.

use sha2::{Digest, Sha256};

/// A human-comparable authentication string: 6 digits + 3 emoji (two redundant
/// representations so users can pick whichever is easier to compare aloud).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas {
    pub digits: String,
    pub emojis: [&'static str; 3],
}

/// 64-entry emoji alphabet (6 bits each). Visually distinct, widely rendered.
const EMOJI: [&str; 64] = [
    "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🐦", "🦆", "🦉",
    "🐝", "🦋", "🐢", "🐙", "🦀", "🐬", "🐳", "🐠", "🌵", "🌲", "🍀", "🍎", "🍋", "🍉", "🍇", "🍓",
    "🍒", "🥕", "🌽", "🍔", "🍕", "🌮", "🍩", "🍪", "🎈", "🎁", "⚽", "🏀", "🎸", "🎺", "🚗", "✈️",
    "🚀", "⛵", "🏠", "🌙", "⭐", "🔥", "❄️", "🌈", "☂️", "🔔", "🔑", "💡", "📷", "🎲", "🧩", "🎯",
];

/// Derive the SAS. `fp_a`/`fp_b` are the two peers' cert fingerprints; the order
/// they are passed does not matter (we sort internally).
pub fn short_auth_string(shared_key: &[u8], fp_a: &[u8; 32], fp_b: &[u8; 32]) -> Sas {
    let (lo, hi) = if fp_a <= fp_b {
        (fp_a, fp_b)
    } else {
        (fp_b, fp_a)
    };
    let mut h = Sha256::new();
    h.update(b"kvm-sas-v1");
    h.update(shared_key);
    h.update(lo);
    h.update(hi);
    let d = h.finalize();

    let num = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    let digits = format!("{num:06}");
    let emojis = [
        EMOJI[(d[4] & 0x3f) as usize],
        EMOJI[(d[5] & 0x3f) as usize],
        EMOJI[(d[6] & 0x3f) as usize],
    ];
    Sas { digits, emojis }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_order_independent() {
        let key = [1u8; 32];
        let a = [9u8; 32];
        let b = [3u8; 32];
        assert_eq!(
            short_auth_string(&key, &a, &b),
            short_auth_string(&key, &b, &a)
        );
    }

    #[test]
    fn different_keys_give_different_sas() {
        let a = [9u8; 32];
        let b = [3u8; 32];
        let s1 = short_auth_string(&[1u8; 32], &a, &b);
        let s2 = short_auth_string(&[2u8; 32], &a, &b);
        assert_ne!(s1, s2);
    }

    #[test]
    fn digits_are_six_chars() {
        let s = short_auth_string(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert_eq!(s.digits.len(), 6);
    }
}
