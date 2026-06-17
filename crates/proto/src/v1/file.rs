//! File-transfer protocol.
//!
//! Designed now, implemented post-MVP. Frozen here so the wire shape is
//! forward-compatible. Transfers run on a **dedicated reliable stream**
//! (`StreamKind::Files`) so large payloads never head-of-line-block input or
//! control. Image clipboard reuses this with a single synthetic `image/png`
//! file.

use serde::{Deserialize, Serialize};

/// Max bytes per [`FileChunk`] payload. 64 KiB balances throughput against
/// fairness with other streams.
pub const FILE_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub mime: String,
    /// SHA-256 of the whole file, verified by the receiver on completion.
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOffer {
    pub transfer_id: u64,
    pub files: Vec<FileMeta>,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOfferAck {
    pub transfer_id: u64,
    pub accept: bool,
    /// Byte offset to resume from (0 for a fresh transfer).
    pub resume_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: u64,
    pub file_index: u32,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAck {
    pub transfer_id: u64,
    pub file_index: u32,
    pub bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    #[test]
    fn file_offer_round_trip() {
        let offer = FileOffer {
            transfer_id: 42,
            files: vec![FileMeta {
                name: "snippet.rs".into(),
                size: 1234,
                mime: "text/x-rust".into(),
                sha256: [7u8; 32],
            }],
            total_bytes: 1234,
        };
        let back: FileOffer = decode(&encode(&offer).unwrap()).unwrap();
        assert_eq!(offer, back);
    }

    #[test]
    fn file_chunk_round_trip() {
        let chunk = FileChunk {
            transfer_id: 42,
            file_index: 0,
            offset: 128,
            bytes: vec![1, 2, 3, 4, 5],
        };
        let back: FileChunk = decode(&encode(&chunk).unwrap()).unwrap();
        assert_eq!(chunk, back);
    }
}
