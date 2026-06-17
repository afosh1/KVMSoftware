#![forbid(unsafe_code)]
//! Pure domain layer for the LAN KVM.
//!
//! Deliberately free of async, I/O, and OS/FFI dependencies so every rule —
//! the focus state machine, layout geometry, clipboard policy, trust lifecycle,
//! session backoff, and message validation — is unit-testable on any runner
//! with no hardware or permissions. The `kvm-engine` crate owns the runtime and
//! executes the [`focus::DomainEffect`]s this layer emits.

pub mod clipboard_policy;
pub mod device;
pub mod error;
pub mod focus;
pub mod layout;
pub mod message;
pub mod session;
pub mod trust;

pub use clipboard_policy::{
    evaluate as evaluate_clipboard, ClipboardPolicy, ContentKind, Direction, Flow, PayloadMeta,
    PolicyDecision,
};
pub use device::{CertFingerprint, Device, DeviceId, DeviceRegistry, RegistrySnapshot};
pub use error::DomainError;
pub use focus::{DomainEffect, FocusConfig, FocusEvent, FocusState, PendingTransition, Transition};
pub use layout::{EdgeLink, LayoutGraph, Point, Rect, ScreenRegion};
pub use message::{validate_control, SeqWindow, SessionCtx, ValidationError};
pub use session::{backoff_delay, BackoffParams, SessionEvent, SessionState};
pub use trust::{advance as advance_trust, PairingEvent, TrustError, TrustState};

// Wire types re-exported at the domain boundary for convenience.
pub use kvm_proto::geometry::{Edge, EntryPoint, ScreenGeom};
pub use kvm_proto::v1::handshake::{Capabilities, Platform};
