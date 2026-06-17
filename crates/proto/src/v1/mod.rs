//! Protocol **version 1** message types.
//!
//! A future breaking revision adds a `v2` module alongside this one; the
//! negotiated version (see [`crate::version`]) selects which to use.

pub mod control;
pub mod file;
pub mod handshake;
pub mod input;

pub use control::{
    ClipboardData, ClipboardKind, ClipboardOffer, ControlMsg, PolicyUpdate, StreamKind,
};
pub use file::{FileAck, FileChunk, FileMeta, FileOffer, FileOfferAck, FILE_CHUNK_SIZE};
pub use handshake::{Capabilities, Hello, Platform, ScreenGeom};
pub use input::{InputEvent, InputKind, Modifiers, MouseButton, Seq};
