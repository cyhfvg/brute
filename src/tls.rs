//! Process-wide TLS initialization helpers.

/// Installs the rustls crypto provider selected by this crate.
///
/// Multiple transitive dependencies can enable different rustls providers. Choosing one provider
/// explicitly at startup keeps later TLS client builders from panicking during auto-detection.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
