//! The reliable message-stream abstraction.

use async_trait::async_trait;

use kvm_proto::v1::control::{ControlMsg, StreamKind};

use crate::error::TransportError;

/// A reliable, ordered, framed channel that speaks [`ControlMsg`] directly.
/// Backed by a QUIC bidirectional stream (or a muxed TLS substream on the
/// fallback transport).
#[async_trait]
pub trait MsgStream: Send {
    async fn send(&mut self, msg: &ControlMsg) -> Result<(), TransportError>;
    /// Returns `Ok(None)` on a clean stream finish.
    async fn recv(&mut self) -> Result<Option<ControlMsg>, TransportError>;
    /// Signal we are done writing (half-close).
    async fn finish(&mut self) -> Result<(), TransportError>;
}

/// One-byte stream-kind tag written as the first byte of every reliable stream,
/// so the acceptor can route it to the right handler.
pub(crate) fn kind_tag(kind: StreamKind) -> u8 {
    match kind {
        StreamKind::Control => 0,
        StreamKind::Clipboard => 1,
        StreamKind::Files => 2,
    }
}

pub(crate) fn tag_kind(tag: u8) -> Result<StreamKind, TransportError> {
    match tag {
        0 => Ok(StreamKind::Control),
        1 => Ok(StreamKind::Clipboard),
        2 => Ok(StreamKind::Files),
        other => Err(TransportError::UnknownStreamKind(other)),
    }
}
