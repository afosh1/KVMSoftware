//! Domain error types. Kept small and `PartialEq` so tests can assert on them.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("device not found: {0}")]
    DeviceNotFound(crate::device::DeviceId),
    #[error("layout: {0}")]
    Layout(String),
}
