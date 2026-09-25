//! Shared attempt fault classification.
//!
//! Credential attempts report success or an [`AttemptFault`]. The class decides
//! whether the scheduler retries the attempt. Protocol modules should not invent
//! a parallel error enum for this boundary.

use std::ops::Deref;

use serde::Serialize;
use thiserror::Error;

/// Why a credential attempt did not succeed.
///
/// # Examples
///
/// ```
/// use brute::error::AttemptFaultClass;
///
/// assert_ne!(AttemptFaultClass::Auth, AttemptFaultClass::Transport);
/// assert_ne!(AttemptFaultClass::Lockout, AttemptFaultClass::Auth);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptFaultClass {
    /// Credentials were rejected. Not retried.
    Auth,
    /// Connection, timeout, or protocol transport failure. Retried.
    Transport,
    /// Account or service lockout. Not retried.
    Lockout,
}

/// Structured non-success result carried by [`crate::protocol::AttemptOutcome`].
///
/// `Display` and `Deref` expose `message` so existing printers can keep using the
/// operator text. Callers that branch on retry or status must read `class`.
///
/// # Examples
///
/// ```
/// use brute::error::{AttemptFault, AttemptFaultClass};
///
/// let fault = AttemptFault::transport("connection refused");
/// assert_eq!(fault.class, AttemptFaultClass::Transport);
/// assert!(fault.is_retriable());
/// assert_eq!(fault.as_str(), "connection refused");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
#[error("{message}")]
pub struct AttemptFault {
    /// Classification used by retry and report status.
    pub class: AttemptFaultClass,
    /// Operator-facing detail. Not used to decide retry.
    pub message: String,
}

impl AttemptFault {
    /// Builds an authentication rejection.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing rejection detail.
    ///
    /// # Returns
    ///
    /// A fault with [`AttemptFaultClass::Auth`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::{AttemptFault, AttemptFaultClass};
    ///
    /// let fault = AttemptFault::auth("rejected");
    /// assert_eq!(fault.class, AttemptFaultClass::Auth);
    /// assert!(!fault.is_retriable());
    /// ```
    pub fn auth(message: impl Into<String>) -> Self {
        Self {
            class: AttemptFaultClass::Auth,
            message: message.into(),
        }
    }

    /// Builds a retriable transport failure.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing transport detail.
    ///
    /// # Returns
    ///
    /// A fault with [`AttemptFaultClass::Transport`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::AttemptFault;
    ///
    /// assert!(AttemptFault::transport("timed out").is_retriable());
    /// ```
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            class: AttemptFaultClass::Transport,
            message: message.into(),
        }
    }

    /// Builds an account or service lockout.
    ///
    /// # Parameters
    ///
    /// * `message`: Operator-facing lockout detail.
    ///
    /// # Returns
    ///
    /// A fault with [`AttemptFaultClass::Lockout`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::{AttemptFault, AttemptFaultClass};
    ///
    /// let fault = AttemptFault::lockout("account locked");
    /// assert_eq!(fault.class, AttemptFaultClass::Lockout);
    /// assert!(!fault.is_retriable());
    /// ```
    pub fn lockout(message: impl Into<String>) -> Self {
        Self {
            class: AttemptFaultClass::Lockout,
            message: message.into(),
        }
    }

    /// Returns the operator-facing message.
    ///
    /// # Returns
    ///
    /// Borrowed message text.
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::AttemptFault;
    ///
    /// assert_eq!(AttemptFault::auth("rejected").as_str(), "rejected");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.message
    }

    /// Reports whether the scheduler should retry this fault.
    ///
    /// # Returns
    ///
    /// `true` only for [`AttemptFaultClass::Transport`].
    ///
    /// # Errors
    ///
    /// Does not return [`Result`].
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::error::AttemptFault;
    ///
    /// assert!(AttemptFault::transport("down").is_retriable());
    /// assert!(!AttemptFault::auth("rejected").is_retriable());
    /// assert!(!AttemptFault::lockout("locked").is_retriable());
    /// ```
    pub fn is_retriable(&self) -> bool {
        self.class == AttemptFaultClass::Transport
    }
}

impl Deref for AttemptFault {
    type Target = str;

    fn deref(&self) -> &str {
        &self.message
    }
}

impl AsRef<str> for AttemptFault {
    fn as_ref(&self) -> &str {
        &self.message
    }
}
