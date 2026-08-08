//! Library surface for the `brute` multi-protocol credential testing toolkit.
//!
//! The CLI binary links this crate; integration tests under `tests/` import pure
//! helpers and protocol modules through this library root.

pub mod app;
pub mod cli;
pub mod credentials;
pub mod database;
pub mod error;
pub mod output;
pub mod protocol;
pub mod proxy;
pub mod targets;
pub mod tls;
