//! Credential attempts with cancellable pacing and transport retries.

use tokio_util::sync::CancellationToken;

use crate::protocol::{AttemptContext, AttemptOutcome, BruteModule};

/// Result of one scheduled credential try.
pub(super) enum AttemptControl {
    /// The attempt finished, including a transport error observed before cancel.
    Finished(AttemptOutcome),
    /// Cancelled before a result was produced. Callers count this as skipped.
    Cancelled,
}

/// Runs one credential try, retrying only transport faults.
///
/// The pre-attempt wait runs once. `ctx.target.retries` is extra tries after the
/// first attempt. Success, auth failure, and lockout return immediately. Retry
/// backoff stays `150ms * (failed attempts + 1)`, starting at 150ms.
///
/// # Parameters
///
/// - `module`: Protocol implementation. Each call performs exactly one try.
/// - `ctx`: Attempt context, including delay, jitter, and the retry budget.
/// - `cancel`: Parent or per-target token. A cancelled token skips the try, or
///   stops a retry backoff after an outcome already exists.
///
/// # Returns
///
/// [`AttemptControl::Finished`] with the first non-transport outcome, or the last
/// transport fault after the budget is spent. [`AttemptControl::Cancelled`] when
/// no outcome should be recorded.
///
/// # Errors
///
/// Does not return [`Result`]. Transport failures remain [`AttemptOutcome::Error`].
///
/// # Examples
///
/// ```ignore
/// match attempt_with_retries(module.as_ref(), &ctx, cancel).await {
///     AttemptControl::Cancelled => skipped.fetch_add(1, Ordering::Relaxed),
///     AttemptControl::Finished(outcome) => record(outcome),
/// };
/// ```
pub(super) async fn attempt_with_retries(
    module: &dyn BruteModule,
    ctx: &AttemptContext,
    cancel: &CancellationToken,
) -> AttemptControl {
    if !super::pacing::wait_before_attempt(ctx.target.delay_ms, ctx.target.jitter_ms, cancel).await
    {
        return AttemptControl::Cancelled;
    }

    let mut failed_attempts = 0usize;
    loop {
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => return AttemptControl::Cancelled,
            outcome = module.attempt(ctx) => outcome,
        };
        if !outcome.is_retriable_transport() || failed_attempts >= ctx.target.retries {
            return AttemptControl::Finished(outcome);
        }
        let delay_ms = transport_retry_backoff_ms(failed_attempts);
        if !super::pacing::cancellable_sleep(delay_ms, cancel).await {
            return AttemptControl::Finished(outcome);
        }
        failed_attempts += 1;
    }
}

/// Returns the delay before the next transport retry.
///
/// # Parameters
///
/// - `failed_attempts`: Number of failed tries already completed, starting at 0.
///
/// # Returns
///
/// Delay in milliseconds. The first retry waits 150ms, the second 300ms, and so on.
///
/// # Errors
///
/// Does not return [`Result`].
///
/// # Examples
///
/// ```ignore
/// assert_eq!(transport_retry_backoff_ms(0), 150);
/// assert_eq!(transport_retry_backoff_ms(1), 300);
/// ```
fn transport_retry_backoff_ms(failed_attempts: usize) -> u64 {
    150 * (failed_attempts as u64 + 1)
}

#[cfg(test)]
pub(super) fn scripted_ctx(retries: usize) -> AttemptContext {
    use crate::cli::{CommonArgs, HttpUrlScheme, Protocol};
    use crate::credentials::CredentialSet;

    AttemptContext {
        protocol: Protocol::Ssh,
        target_host: "127.0.0.1".into(),
        url_scheme: HttpUrlScheme::Http,
        target: CommonArgs {
            targets: vec!["127.0.0.1".into()],
            usernames: vec!["root".into()],
            passwords: vec!["secret".into()],
            credential_id: None,
            port: Some(22),
            threads: 1,
            retries,
            timeout_ms: 1000,
            delay_ms: 0,
            jitter_ms: 0,
            continue_on_success: false,
            proxy: None,
        },
        path: None,
        execute: None,
        credential: CredentialSet {
            username: Some("root".into()),
            password: Some("secret".into()),
            service_name: None,
            sid: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use super::{AttemptControl, attempt_with_retries, scripted_ctx, transport_retry_backoff_ms};
    use crate::protocol::{AttemptContext, AttemptOutcome, BruteModule};

    struct ScriptedModule {
        outcomes: std::sync::Mutex<Vec<AttemptOutcome>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl BruteModule for ScriptedModule {
        fn name(&self) -> &'static str {
            "scripted"
        }

        async fn attempt(&self, _ctx: &AttemptContext) -> AttemptOutcome {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.outcomes.lock().expect("scripted outcomes").remove(0)
        }
    }

    fn finished(control: AttemptControl) -> AttemptOutcome {
        match control {
            AttemptControl::Finished(outcome) => outcome,
            AttemptControl::Cancelled => panic!("attempt was cancelled"),
        }
    }

    /// Transport errors are retried; the final success is the recorded outcome.
    #[tokio::test]
    async fn retries_transport_error_then_returns_success() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![
                AttemptOutcome::error("ssh transport failed"),
                AttemptOutcome::Success(crate::protocol::AttemptSuccess::new("ok")),
            ]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = finished(attempt_with_retries(&module, &scripted_ctx(1), &cancel).await);
        assert!(matches!(outcome, AttemptOutcome::Success(_)));
        assert_eq!(module.calls.load(Ordering::Relaxed), 2);
    }

    /// Authentication failures are not transport retries.
    #[tokio::test]
    async fn does_not_retry_auth_failure() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![
                AttemptOutcome::failure("auth failed"),
                AttemptOutcome::Success(crate::protocol::AttemptSuccess::new("should not run")),
            ]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = finished(attempt_with_retries(&module, &scripted_ctx(3), &cancel).await);
        assert!(matches!(outcome, AttemptOutcome::Failure(_)));
        assert_eq!(module.calls.load(Ordering::Relaxed), 1);
    }

    /// `--retries 0` means one try, even when that try is a transport error.
    #[tokio::test]
    async fn zero_retries_returns_first_error() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![
                AttemptOutcome::error("down"),
                AttemptOutcome::Success(crate::protocol::AttemptSuccess::new("should not run")),
            ]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = finished(attempt_with_retries(&module, &scripted_ctx(0), &cancel).await);
        assert!(matches!(outcome, AttemptOutcome::Error(_)));
        assert_eq!(module.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn backoff_grows_by_150ms() {
        assert_eq!(transport_retry_backoff_ms(0), 150);
        assert_eq!(transport_retry_backoff_ms(1), 300);
        assert_eq!(transport_retry_backoff_ms(2), 450);
    }

    /// Lockout is not a transport retry.
    #[tokio::test]
    async fn does_not_retry_lockout() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![AttemptOutcome::lockout("account locked")]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = finished(attempt_with_retries(&module, &scripted_ctx(3), &cancel).await);
        assert!(!outcome.is_retriable_transport());
        assert_eq!(module.calls.load(Ordering::Relaxed), 1);
    }

    /// A cancelled token skips pacing and does not call the module.
    #[tokio::test]
    async fn cancelled_token_does_not_call_module() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![AttemptOutcome::error("should not run")]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let mut ctx = scripted_ctx(3);
        ctx.target.delay_ms = 60_000;
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let started = Instant::now();

        let control = attempt_with_retries(&module, &ctx, &cancel).await;

        assert!(matches!(control, AttemptControl::Cancelled));
        assert_eq!(module.calls.load(Ordering::Relaxed), 0);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    /// Cancelling during backoff keeps the transport error and does not retry.
    #[tokio::test]
    async fn cancel_during_backoff_returns_observed_transport_error() {
        let module = ScriptedModule {
            outcomes: std::sync::Mutex::new(vec![AttemptOutcome::error("connection reset")]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_later = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_later.cancel();
        });
        let started = Instant::now();

        let outcome = finished(attempt_with_retries(&module, &scripted_ctx(3), &cancel).await);

        assert!(matches!(outcome, AttemptOutcome::Error(_)));
        assert_eq!(module.calls.load(Ordering::Relaxed), 1);
        assert!(started.elapsed() < Duration::from_millis(250));
    }
}
