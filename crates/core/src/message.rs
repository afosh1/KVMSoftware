//! Semantic message validation + hot-path sequence windowing.
//!
//! Wire *format* lives in `kvm-proto`; this module enforces *semantics* on top:
//! payload caps, trust gating, version compatibility, and stale-input dropping.

use thiserror::Error;

use crate::trust::TrustState;
use kvm_proto::v1::control::ControlMsg;
use kvm_proto::v1::input::Seq;
use kvm_proto::version;

/// Per-connection context needed to validate inbound messages.
#[derive(Debug, Clone, Copy)]
pub struct SessionCtx {
    /// Trust level of the peer on this connection.
    pub peer_trust: TrustState,
    /// Negotiated protocol version.
    pub protocol_version: u16,
    /// Maximum accepted inline payload (clipboard) in bytes.
    pub max_payload: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("payload too large: {got} > {max}")]
    PayloadTooLarge { got: u64, max: u64 },
    #[error("action requires full trust, peer is {trust:?}")]
    Untrusted { trust: TrustState },
    #[error("protocol version mismatch: {0}")]
    Version(#[from] version::VersionError),
    #[error("peer is not allowed to connect (trust: {trust:?})")]
    NotConnectable { trust: TrustState },
}

/// Validate an inbound control message against the session context.
pub fn validate_control(msg: &ControlMsg, ctx: &SessionCtx) -> Result<(), ValidationError> {
    // A peer that isn't at least Paired must never reach message handling.
    if !ctx.peer_trust.is_connectable() {
        return Err(ValidationError::NotConnectable {
            trust: ctx.peer_trust,
        });
    }

    match msg {
        ControlMsg::Hello(h) => {
            version::negotiate(h.protocol_version)?;
            Ok(())
        }
        ControlMsg::ClipboardData(d) => check_size(d.bytes.len() as u64, ctx.max_payload),
        ControlMsg::ClipboardOffer(o) => check_size(o.size, ctx.max_payload),
        // File transfer is privileged: only fully-trusted peers may offer files.
        ControlMsg::FileOffer(o) => {
            require_full_trust(ctx)?;
            check_size(o.total_bytes, u64::MAX) // size capped per-chunk on the stream
        }
        ControlMsg::FileChunk(c) => {
            require_full_trust(ctx)?;
            check_size(
                c.bytes.len() as u64,
                kvm_proto::v1::file::FILE_CHUNK_SIZE as u64,
            )
        }
        // The rest are small control frames with no extra constraints.
        _ => Ok(()),
    }
}

fn check_size(got: u64, max: u64) -> Result<(), ValidationError> {
    if got > max {
        Err(ValidationError::PayloadTooLarge { got, max })
    } else {
        Ok(())
    }
}

fn require_full_trust(ctx: &SessionCtx) -> Result<(), ValidationError> {
    if ctx.peer_trust.is_fully_trusted() {
        Ok(())
    } else {
        Err(ValidationError::Untrusted {
            trust: ctx.peer_trust,
        })
    }
}

/// Tracks the highest accepted hot-path sequence number to drop stale/duplicate
/// datagrams. Uses wrapping comparison so it survives `u16` rollover: an event
/// is "newer" if it lies within the forward half of the sequence space.
#[derive(Debug, Default, Clone, Copy)]
pub struct SeqWindow {
    last: Option<Seq>,
}

impl SeqWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` (and advances) if `seq` is newer than the last accepted;
    /// `false` if it is stale/duplicate and should be dropped.
    pub fn accept(&mut self, seq: Seq) -> bool {
        match self.last {
            None => {
                self.last = Some(seq);
                true
            }
            Some(last) => {
                let diff = seq.wrapping_sub(last);
                // diff in (0, 0x8000) ⇒ strictly newer within the forward half.
                if diff != 0 && diff < 0x8000 {
                    self.last = Some(seq);
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_proto::v1::control::{ClipboardData, ClipboardKind};
    use kvm_proto::v1::file::{FileMeta, FileOffer};

    fn ctx(trust: TrustState) -> SessionCtx {
        SessionCtx {
            peer_trust: trust,
            protocol_version: 1,
            max_payload: 1024,
        }
    }

    #[test]
    fn rejects_untrusted_peer_entirely() {
        let msg = ControlMsg::SwitchAck;
        assert!(matches!(
            validate_control(&msg, &ctx(TrustState::Untrusted)),
            Err(ValidationError::NotConnectable { .. })
        ));
    }

    #[test]
    fn clipboard_size_capped() {
        let big = ControlMsg::ClipboardData(ClipboardData {
            kind: ClipboardKind::Text,
            mime: "text/plain".into(),
            bytes: vec![0u8; 2048],
        });
        assert!(matches!(
            validate_control(&big, &ctx(TrustState::Trusted)),
            Err(ValidationError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn file_offer_requires_full_trust() {
        let offer = ControlMsg::FileOffer(FileOffer {
            transfer_id: 1,
            files: vec![FileMeta {
                name: "x".into(),
                size: 1,
                mime: "application/octet-stream".into(),
                sha256: [0; 32],
            }],
            total_bytes: 1,
        });
        // Paired (not Trusted) may connect but may NOT receive files.
        assert!(matches!(
            validate_control(&offer, &ctx(TrustState::Paired)),
            Err(ValidationError::Untrusted { .. })
        ));
        assert!(validate_control(&offer, &ctx(TrustState::Trusted)).is_ok());
    }

    #[test]
    fn seq_window_drops_stale_and_duplicates() {
        let mut w = SeqWindow::new();
        assert!(w.accept(10));
        assert!(w.accept(11));
        assert!(!w.accept(11)); // duplicate
        assert!(!w.accept(5)); // stale
        assert!(w.accept(12));
    }

    #[test]
    fn seq_window_survives_wraparound() {
        let mut w = SeqWindow::new();
        assert!(w.accept(65530));
        assert!(w.accept(65535));
        assert!(w.accept(3)); // wrapped past 0 → still newer
        assert!(!w.accept(65534)); // now stale relative to 3
    }
}
