//! Protocol version + capability negotiation.
//!
//! The version is advertised in the mDNS TXT record and exchanged again inside
//! [`crate::v1::Hello`] before any input flows. Within a major version, only
//! *additive* changes are allowed; a breaking change bumps `PROTOCOL_VERSION`
//! and ships a new `v2` module side-by-side.

use thiserror::Error;

/// The protocol version this build speaks.
///
/// v2 added real screen-geometry exchange to [`crate::v1::Hello`] (the `screen`
/// field) so seam crossings map to each peer's actual resolution. The wire layout
/// is pre-release, so v2 does not interoperate with v1.
pub const PROTOCOL_VERSION: u16 = 2;

/// The oldest peer protocol version this build can still interoperate with.
pub const MIN_SUPPORTED_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VersionError {
    #[error(
        "incompatible protocol version: this build supports >= {local_min}, peer offered {remote}"
    )]
    Incompatible { local_min: u16, remote: u16 },
}

/// Negotiate the effective protocol version given a peer's advertised version.
///
/// Returns `min(local, remote)` when compatible, so both ends speak the lower
/// common version. Refuses (with a clear error) when the peer is too old.
pub fn negotiate(remote: u16) -> Result<u16, VersionError> {
    if remote < MIN_SUPPORTED_VERSION {
        return Err(VersionError::Incompatible {
            local_min: MIN_SUPPORTED_VERSION,
            remote,
        });
    }
    Ok(PROTOCOL_VERSION.min(remote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_equal_version() {
        assert_eq!(negotiate(PROTOCOL_VERSION), Ok(PROTOCOL_VERSION));
    }

    #[test]
    fn negotiates_down_to_lower_common_version() {
        // A future peer advertising a higher version negotiates down to ours.
        assert_eq!(negotiate(PROTOCOL_VERSION + 5), Ok(PROTOCOL_VERSION));
    }

    #[test]
    fn refuses_too_old_peer() {
        if MIN_SUPPORTED_VERSION > 0 {
            let remote = MIN_SUPPORTED_VERSION - 1;
            assert_eq!(
                negotiate(remote),
                Err(VersionError::Incompatible {
                    local_min: MIN_SUPPORTED_VERSION,
                    remote
                })
            );
        }
    }
}
