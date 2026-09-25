//! Fixed delay and inclusive jitter before a credential attempt.
//!
//! Transport retries keep their own backoff. This wait runs once per credential
//! try, before the first attempt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;

/// Combines a fixed delay with one inclusive jitter sample.
///
/// # Parameters
///
/// - `delay_ms`: Fixed wait before the attempt, in milliseconds. Zero is valid.
/// - `jitter_ms`: Inclusive upper bound of the extra wait, in milliseconds. Zero
///   disables the random component.
/// - `sample`: Arbitrary sample. Used only when `jitter_ms` is non-zero.
///
/// # Returns
///
/// Total wait in milliseconds. With zero jitter the result is `delay_ms`.
/// Otherwise it is `delay_ms + (sample % (jitter_ms + 1))`, saturating on overflow.
/// A `jitter_ms` of `u64::MAX` saturates the span, so the extra wait cannot reach
/// `u64::MAX`.
///
/// # Errors
///
/// Does not return [`Result`].
///
/// # Examples
///
/// ```
/// use brute::engine::paced_delay_ms;
///
/// assert_eq!(paced_delay_ms(100, 0, 99), 100);
/// assert_eq!(paced_delay_ms(100, 10, 0), 100);
/// assert_eq!(paced_delay_ms(100, 10, 12), 101);
/// assert_eq!(paced_delay_ms(100, 10, 11), 100);
/// assert_eq!(paced_delay_ms(0, 0, 7), 0);
/// ```
pub fn paced_delay_ms(delay_ms: u64, jitter_ms: u64, sample: u64) -> u64 {
    if jitter_ms == 0 {
        return delay_ms;
    }
    let span = jitter_ms.saturating_add(1);
    delay_ms.saturating_add(sample % span)
}

/// Sleeps for [`paced_delay_ms`] before a credential attempt.
///
/// # Parameters
///
/// - `delay_ms`: Fixed wait in milliseconds.
/// - `jitter_ms`: Inclusive extra wait in milliseconds.
/// - `cancel`: Token that aborts the wait. An already cancelled token returns
///   immediately, including when the computed wait is zero.
///
/// # Returns
///
/// `true` after the wait completes. `false` when `cancel` fires first.
///
/// # Errors
///
/// Does not return [`Result`].
///
/// # Examples
///
/// ```ignore
/// if !wait_before_attempt(ctx.target.delay_ms, ctx.target.jitter_ms, cancel).await {
///     return AttemptControl::Cancelled;
/// }
/// ```
pub(super) async fn wait_before_attempt(
    delay_ms: u64,
    jitter_ms: u64,
    cancel: &CancellationToken,
) -> bool {
    cancellable_sleep(paced_delay_ms(delay_ms, jitter_ms, jitter_sample()), cancel).await
}

/// Sleeps for `total_ms` unless `cancel` fires.
///
/// # Parameters
///
/// - `total_ms`: Wait in milliseconds. Zero does not sleep.
/// - `cancel`: Token checked before and during the wait.
///
/// # Returns
///
/// `true` when the wait finished or was zero and the token was still active.
/// `false` when the token was already cancelled or cancelled during the wait.
///
/// # Errors
///
/// Does not return [`Result`].
///
/// # Examples
///
/// ```ignore
/// if !cancellable_sleep(150, cancel).await {
///     return AttemptControl::Finished(outcome);
/// }
/// ```
pub(super) async fn cancellable_sleep(total_ms: u64, cancel: &CancellationToken) -> bool {
    if cancel.is_cancelled() {
        return false;
    }
    if total_ms == 0 {
        return true;
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(Duration::from_millis(total_ms)) => true,
    }
}

/// Mixes a process-local counter with the clock so concurrent attempts do not
/// share one sequence. This is pacing noise, not a cryptographic generator.
fn jitter_sample() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let tick = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    tick.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ nanos
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;

    use super::{cancellable_sleep, paced_delay_ms, wait_before_attempt};

    /// Verifies zero jitter ignores the sample and zero delay with zero jitter stays zero.
    #[test]
    fn zero_jitter_is_the_fixed_delay() {
        assert_eq!(paced_delay_ms(0, 0, 99), 0);
        assert_eq!(paced_delay_ms(250, 0, u64::MAX), 250);
    }

    /// Verifies the extra wait stays inside `0..=jitter_ms`.
    #[test]
    fn jitter_sample_maps_into_the_inclusive_span() {
        for sample in [0, 1, 4, 5, 6, 100, u64::MAX] {
            let wait = paced_delay_ms(20, 5, sample);
            assert!(
                (20..=25).contains(&wait),
                "sample {sample} mapped to {wait}"
            );
        }
        assert_eq!(paced_delay_ms(20, 5, 0), 20);
        assert_eq!(paced_delay_ms(20, 5, 5), 25);
        assert_eq!(paced_delay_ms(20, 5, 6), 20);
    }

    /// An already cancelled token does not sleep, even when the wait is zero.
    #[tokio::test]
    async fn cancelled_token_skips_zero_wait() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let started = Instant::now();

        assert!(!wait_before_attempt(0, 0, &cancel).await);
        assert!(!cancellable_sleep(0, &cancel).await);
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    /// Cancelling during a long wait returns before the sleep ends.
    #[tokio::test]
    async fn cancel_during_wait_returns_false() {
        let cancel = CancellationToken::new();
        let cancel_later = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_later.cancel();
        });
        let started = Instant::now();

        assert!(!cancellable_sleep(60_000, &cancel).await);
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
