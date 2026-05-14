//! Shared application error classifications.

use thiserror::Error;

/// Errors that reflect an attempt result rather than a process crash.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AttemptError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("service rejected the request: {0}")]
    Rejected(String),
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("feature not implemented for this protocol yet")]
    Unsupported,
}
