//! Native OS adapters implementing [`kvm_adapter_api`].
//!
//! * **Linux** ([`linux`]): pure-Rust `x11rb` (XTEST injection + RandR geometry).
//! * **Windows/macOS** ([`fallback`]): `enigo`.
//! * **Capture** ([`capture`]): `rdev` (all platforms).
//! * **Clipboard** ([`clipboard`]): `arboard` (all platforms).
//!
//! Use [`platform_adapters`] to build the bundle for the current OS.

pub mod capture;
pub mod clipboard;
pub mod keymap;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
pub mod fallback;

use kvm_adapter_api::{PlatformAdapters, Result};

/// Construct the input/clipboard/geometry adapters for the current platform.
pub fn platform_adapters() -> Result<PlatformAdapters> {
    #[cfg(target_os = "linux")]
    {
        linux::adapters()
    }
    #[cfg(not(target_os = "linux"))]
    {
        fallback::adapters()
    }
}
