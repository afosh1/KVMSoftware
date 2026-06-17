//! Session lifecycle + reconnect backoff.
//!
//! The state machine models the connection's health; the backoff function is
//! deterministic (jitter is added by the engine) so the schedule is testable.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// No connection desired/active.
    Idle,
    /// Dialing / handshaking.
    Connecting,
    /// Healthy and exchanging traffic.
    Active,
    /// Connected but unhealthy (high RTT or datagram loss).
    Degraded,
    /// Lost; retrying with backoff.
    Reconnecting,
    /// Terminated; will not retry.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Connect,
    Established,
    /// Health probe indicates degradation (RTT/loss over threshold).
    Degrade,
    /// Health recovered.
    Recover,
    /// The link dropped.
    Lost,
    /// Reconnect attempts exhausted / peer gone from discovery.
    GaveUp,
    /// User or peer requested a clean shutdown.
    Close,
}

impl SessionState {
    pub fn handle(self, event: SessionEvent) -> SessionState {
        use SessionEvent as E;
        use SessionState as S;
        match (self, event) {
            (_, E::Close) => S::Closed,
            (S::Idle, E::Connect) => S::Connecting,
            (S::Connecting, E::Established) => S::Active,
            (S::Connecting, E::Lost) => S::Reconnecting,
            (S::Active, E::Degrade) => S::Degraded,
            (S::Degraded, E::Recover) => S::Active,
            (S::Active, E::Lost) | (S::Degraded, E::Lost) => S::Reconnecting,
            (S::Reconnecting, E::Established) => S::Active,
            (S::Reconnecting, E::GaveUp) => S::Closed,
            // Any unmodeled event leaves the state unchanged.
            (state, _) => state,
        }
    }

    pub fn is_connected(self) -> bool {
        matches!(self, SessionState::Active | SessionState::Degraded)
    }
}

/// Tunable backoff parameters. Defaults: 200 ms base, ×2, capped at 10 s.
#[derive(Debug, Clone, Copy)]
pub struct BackoffParams {
    pub base_ms: u64,
    pub factor: u64,
    pub cap_ms: u64,
}

impl Default for BackoffParams {
    fn default() -> Self {
        BackoffParams {
            base_ms: 200,
            factor: 2,
            cap_ms: 10_000,
        }
    }
}

/// Deterministic exponential backoff delay (milliseconds) for a 0-based attempt
/// number. The engine adds full jitter on top: `rand(0..=delay)`.
pub fn backoff_delay(attempt: u32, p: BackoffParams) -> u64 {
    let mult = p.factor.checked_pow(attempt).unwrap_or(u64::MAX);
    p.base_ms.saturating_mul(mult).min(p.cap_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_happy_path() {
        let s = SessionState::Idle.handle(SessionEvent::Connect);
        assert_eq!(s, SessionState::Connecting);
        let s = s.handle(SessionEvent::Established);
        assert_eq!(s, SessionState::Active);
        assert!(s.is_connected());
    }

    #[test]
    fn degrade_and_recover() {
        let s = SessionState::Active.handle(SessionEvent::Degrade);
        assert_eq!(s, SessionState::Degraded);
        assert!(s.is_connected());
        let s = s.handle(SessionEvent::Recover);
        assert_eq!(s, SessionState::Active);
    }

    #[test]
    fn lost_then_reconnect_then_giveup() {
        let s = SessionState::Active.handle(SessionEvent::Lost);
        assert_eq!(s, SessionState::Reconnecting);
        let s2 = s.handle(SessionEvent::Established);
        assert_eq!(s2, SessionState::Active);
        let s3 = s.handle(SessionEvent::GaveUp);
        assert_eq!(s3, SessionState::Closed);
    }

    #[test]
    fn close_from_anywhere() {
        for s in [
            SessionState::Idle,
            SessionState::Connecting,
            SessionState::Active,
            SessionState::Degraded,
            SessionState::Reconnecting,
        ] {
            assert_eq!(s.handle(SessionEvent::Close), SessionState::Closed);
        }
    }

    #[test]
    fn backoff_sequence_is_capped_exponential() {
        let p = BackoffParams::default();
        assert_eq!(backoff_delay(0, p), 200);
        assert_eq!(backoff_delay(1, p), 400);
        assert_eq!(backoff_delay(2, p), 800);
        assert_eq!(backoff_delay(3, p), 1600);
        assert_eq!(backoff_delay(4, p), 3200);
        assert_eq!(backoff_delay(5, p), 6400);
        // 200 * 2^6 = 12800 → capped at 10000
        assert_eq!(backoff_delay(6, p), 10_000);
        assert_eq!(backoff_delay(100, p), 10_000); // never overflows past cap
    }
}
