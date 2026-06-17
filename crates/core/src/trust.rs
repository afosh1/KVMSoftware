//! Trust lifecycle — a pure state machine.
//!
//! The cryptography (SPAKE2, SAS, certificate generation/pinning) lives in the
//! `kvm-pairing` crate; `core` only models the *lifecycle* so it stays
//! dependency-light and exhaustively testable.
//!
//! TOFU model: a peer is discovered `Untrusted`, runs the PAKE to become
//! cryptographically `Paired` (cert pinned), and is promoted to `Trusted` once
//! the user confirms the Short Authentication String on both ends.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustState {
    /// Discovered on the LAN but not yet paired.
    Untrusted,
    /// PAKE handshake underway.
    PairingInProgress,
    /// Cryptographically paired; certificate pinned. May connect.
    Paired,
    /// User-confirmed via SAS. Full privileges (e.g. file transfer).
    Trusted,
    /// Explicitly revoked by the user. Connections refused until reset.
    Revoked,
}

impl TrustState {
    /// Whether a peer in this state is allowed to open a transport connection.
    /// Secure default: only `Paired` or `Trusted`.
    pub fn is_connectable(self) -> bool {
        matches!(self, TrustState::Paired | TrustState::Trusted)
    }

    /// Whether privileged actions (file transfer) are allowed.
    pub fn is_fully_trusted(self) -> bool {
        matches!(self, TrustState::Trusted)
    }
}

/// Events that drive the trust lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingEvent {
    /// User initiated pairing on this device.
    Begin,
    /// SPAKE2 completed; shared secret established and cert pinned.
    PakeSucceeded,
    /// PAKE failed (wrong code, timeout, abort).
    PakeFailed,
    /// User confirmed the SAS matches on both ends.
    SasConfirmed,
    /// User reported the SAS did NOT match — possible MITM; abort hard.
    SasRejected,
    /// User revoked trust.
    Revoke,
    /// Reset a revoked/aborted device back to a pairable state.
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid trust transition: {event:?} is not valid from {from:?}")]
pub struct TrustError {
    pub from: TrustState,
    pub event: PairingEvent,
}

/// Advance the trust state machine. Returns the new state or a precise error.
pub fn advance(state: TrustState, event: PairingEvent) -> Result<TrustState, TrustError> {
    use PairingEvent as E;
    use TrustState as S;

    // Revoke is always permitted (except it's a no-op when already revoked).
    if event == E::Revoke {
        return Ok(S::Revoked);
    }

    let next = match (state, event) {
        (S::Untrusted, E::Begin) => S::PairingInProgress,
        (S::PairingInProgress, E::PakeSucceeded) => S::Paired,
        (S::PairingInProgress, E::PakeFailed) => S::Untrusted,
        (S::PairingInProgress, E::SasRejected) => S::Untrusted,
        (S::Paired, E::SasConfirmed) => S::Trusted,
        (S::Paired, E::SasRejected) => S::Untrusted,
        // Re-running pairing from a trusted/paired state is allowed (re-key).
        (S::Trusted, E::Begin) => S::PairingInProgress,
        (S::Paired, E::Begin) => S::PairingInProgress,
        (S::Revoked, E::Reset) => S::Untrusted,
        (S::Untrusted, E::Reset) => S::Untrusted,
        _ => return Err(TrustError { from: state, event }),
    };
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_untrusted_to_trusted() {
        let s = TrustState::Untrusted;
        let s = advance(s, PairingEvent::Begin).unwrap();
        assert_eq!(s, TrustState::PairingInProgress);
        let s = advance(s, PairingEvent::PakeSucceeded).unwrap();
        assert_eq!(s, TrustState::Paired);
        assert!(s.is_connectable());
        assert!(!s.is_fully_trusted());
        let s = advance(s, PairingEvent::SasConfirmed).unwrap();
        assert_eq!(s, TrustState::Trusted);
        assert!(s.is_fully_trusted());
    }

    #[test]
    fn sas_rejection_aborts_to_untrusted() {
        let s = advance(TrustState::Paired, PairingEvent::SasRejected).unwrap();
        assert_eq!(s, TrustState::Untrusted);
    }

    #[test]
    fn revoke_from_any_state() {
        for s in [
            TrustState::Untrusted,
            TrustState::PairingInProgress,
            TrustState::Paired,
            TrustState::Trusted,
        ] {
            assert_eq!(
                advance(s, PairingEvent::Revoke).unwrap(),
                TrustState::Revoked
            );
        }
    }

    #[test]
    fn revoked_can_reset_and_repair() {
        let s = advance(TrustState::Revoked, PairingEvent::Reset).unwrap();
        assert_eq!(s, TrustState::Untrusted);
    }

    #[test]
    fn invalid_transition_errors() {
        // Cannot jump straight to Trusted without pairing.
        let err = advance(TrustState::Untrusted, PairingEvent::SasConfirmed).unwrap_err();
        assert_eq!(err.from, TrustState::Untrusted);
        assert_eq!(err.event, PairingEvent::SasConfirmed);
    }

    #[test]
    fn untrusted_not_connectable() {
        assert!(!TrustState::Untrusted.is_connectable());
        assert!(!TrustState::Revoked.is_connectable());
        assert!(!TrustState::PairingInProgress.is_connectable());
    }
}
