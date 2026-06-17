#![forbid(unsafe_code)]
//! Wire protocol for the LAN KVM.
//!
//! This crate is **pure**: no async, no I/O, no OS dependencies. It defines the
//! on-the-wire message types, the binary codec, and version negotiation so that
//! both the transport layer and the UI can share a single, versioned schema.
//!
//! Two planes exist:
//! * **Hot path** ([`v1::InputEvent`]) — fixed, compact, sent over unreliable
//!   QUIC datagrams. Fire-and-forget; stale events are dropped by sequence.
//! * **Control plane** ([`v1::ControlMsg`]) — reliable, length-prefixed frames
//!   for handshake, clipboard, file transfer, policy, and lifecycle.
//!
//! Serialization is [`postcard`] (compact, fast, stable byte layout). JSON is
//! intentionally never used on the wire — only at the UI/IPC boundary.

pub mod codec;
pub mod geometry;
pub mod v1;
pub mod version;

pub use codec::{
    decode, encode, encode_frame, CodecError, FrameDecoder, MAX_DATAGRAM_LEN, MAX_FRAME_LEN,
};
pub use geometry::{Edge, EntryPoint};
pub use version::{negotiate, VersionError, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION};
