use std::time::Duration;

/// Transport-level connection health. We deliberately expose only the
/// link-layer RTT here; application-level datagram loss and heartbeat freshness
/// are computed by the engine from sequence gaps + heartbeat replies, which is
/// more meaningful than QUIC's internal packet counters for *input* events.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionHealth {
    pub rtt: Duration,
}

impl Default for ConnectionHealth {
    fn default() -> Self {
        ConnectionHealth {
            rtt: Duration::ZERO,
        }
    }
}
