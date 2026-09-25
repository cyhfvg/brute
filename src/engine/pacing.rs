//! Fixed delay and inclusive jitter before a credential attempt.
//!
//! Transport retries keep their own backoff. This wait runs once per credential
//! try, before the first attempt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
///
/// # Returns
///
/// Completes after the computed wait. A zero total does not sleep.
///
/// # Errors
///
/// Does not return [`Result`]. Cancellation of this sleep is not implemented here.
///
/// # Examples
///
/// ```ignore
/// wait_before_attempt(ctx.target.delay_ms, ctx.target.jitter_ms).await;
/// ```
pub(super) async fn wait_before_attempt(delay_ms: u64, jitter_ms: u64) {
    let wait_ms = paced_delay_ms(delay_ms, jitter_ms, jitter_sample());
    if wait_ms == 0 {
        return;
    }
    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
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
    use super::paced_delay_ms;

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
}
