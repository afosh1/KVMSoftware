//! Binary codec + stream framing.
//!
//! * Datagrams (hot path) are encoded bare with [`encode`]/[`decode`].
//! * Reliable streams use length-prefixed frames ([`encode_frame`]) decoded
//!   incrementally by [`FrameDecoder`] as bytes arrive.
//!
//! Kept pure (no async) so it is trivially unit-testable; the transport layer
//! owns the actual socket/stream I/O.

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Hard cap on a single reliable frame body (16 MiB) — a safety valve against
/// a malicious/garbled length prefix allocating unbounded memory.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Conservative datagram payload budget. QUIC datagrams must fit the path MTU
/// without fragmentation; 1200 B is safe on virtually all LANs (sub-1280 IPv6
/// minimum minus headers). Hot-path input events are ~5–24 B, far below this.
pub const MAX_DATAGRAM_LEN: usize = 1200;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("serialize failed: {0}")]
    Serialize(String),
    #[error("deserialize failed: {0}")]
    Deserialize(String),
    #[error("frame length {0} exceeds MAX_FRAME_LEN ({MAX_FRAME_LEN})")]
    FrameTooLarge(usize),
}

/// Encode a value to a bare postcard byte vector (used for datagrams).
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    postcard::to_allocvec(value).map_err(|e| CodecError::Serialize(e.to_string()))
}

/// Decode a value from bare postcard bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    postcard::from_bytes(bytes).map_err(|e| CodecError::Deserialize(e.to_string()))
}

/// Encode a value as a length-prefixed frame: `u32` little-endian length + body.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let body = encode(value)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Incremental, allocation-frugal frame decoder for byte streams.
///
/// Feed it bytes as they arrive with [`push`](Self::push); drain complete frame
/// bodies with [`next_frame`](Self::next_frame). Partial frames are buffered
/// until enough bytes are present.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append received bytes to the internal buffer.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pull the next complete frame body, if one is fully buffered.
    ///
    /// Returns `Ok(None)` when more bytes are needed, and an error if the
    /// declared length is implausibly large (treated as a protocol violation).
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME_LEN {
            return Err(CodecError::FrameTooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let body = self.buf[4..4 + len].to_vec();
        self.buf.drain(0..4 + len);
        Ok(Some(body))
    }

    /// Bytes currently buffered but not yet forming a complete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_round_trip() {
        let v: Vec<u32> = vec![1, 2, 3, 4];
        let bytes = encode(&v).unwrap();
        let back: Vec<u32> = decode(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn framed_round_trip_single() {
        let bytes = encode_frame(&"hello".to_string()).unwrap();
        let mut dec = FrameDecoder::new();
        dec.push(&bytes);
        let frame = dec.next_frame().unwrap().unwrap();
        let back: String = decode(&frame).unwrap();
        assert_eq!(back, "hello");
        assert_eq!(dec.next_frame().unwrap(), None);
    }

    #[test]
    fn framed_handles_split_and_coalesced_reads() {
        let a = encode_frame(&"first".to_string()).unwrap();
        let b = encode_frame(&"second".to_string()).unwrap();
        let mut dec = FrameDecoder::new();

        // Deliver one byte at a time, then both frames together — decoder must
        // reassemble regardless of chunk boundaries.
        for chunk in a.chunks(1) {
            assert_eq!(dec.next_frame().unwrap(), None);
            dec.push(chunk);
        }
        let f1: String = decode(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(f1, "first");

        dec.push(&b);
        let f2: String = decode(&dec.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(f2, "second");
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn rejects_oversized_frame_length() {
        let mut dec = FrameDecoder::new();
        dec.push(&(u32::MAX).to_le_bytes());
        assert!(matches!(
            dec.next_frame(),
            Err(CodecError::FrameTooLarge(_))
        ));
    }
}
