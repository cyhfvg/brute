//! HTTP-family client, URL, and Basic Auth request construction.
//!
//! Status classification stays in [`super::http_auth`]. This module does not
//! copy the 2xx/401/403 table. [`super::http_attempt`] re-exports these
//! helpers and maps client build failures onto `HttpAttemptFailure`.

use reqwest::RequestBuilder;

use crate::cli::HttpUrlScheme;

use super::http::build_http_basic_client;
use super::{AttemptContext, TargetContext};

/// Returns whether both username and password are empty.
///
/// Missing fields are treated as empty. A password with an empty username is
/// not absent.
///
/// # Parameters
///
/// - `ctx`: Attempt credentials.
///
/// # Returns
///
/// `true` when both credential fields are missing or empty.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let unauthenticated = credentials_absent(ctx);
/// ```
pub fn credentials_absent(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

/// Builds `{scheme}://host:port{path}` for an HTTP-family service.
///
/// This is the shared replacement for per-module `api_url` / `cluster_url`
/// wrappers. It does not add or strip path characters.
///
/// # Parameters
///
/// - `scheme`: CLI `--protocol` value.
/// - `host`: Target hostname or IP.
/// - `port`: Effective service port.
/// - `path`: Request path, including a leading `/` when the caller has one.
///
/// # Returns
///
/// URL string.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::cli::HttpUrlScheme;
/// use brute::protocol::http_attempt::http_service_url;
/// assert_eq!(
///     http_service_url(HttpUrlScheme::Http, "10.0.0.5", 8080, "/api/json"),
///     "http://10.0.0.5:8080/api/json"
/// );
/// ```
pub fn http_service_url(scheme: HttpUrlScheme, host: &str, port: u16, path: &str) -> String {
    super::http::build_http_basic_url(scheme, host, port, path)
}

/// Builds the service URL for one attempt.
///
/// # Parameters
///
/// - `ctx`: Attempt host, scheme, and port.
/// - `path`: Request path.
///
/// # Returns
///
/// URL string from [`http_service_url`] and [`AttemptContext::port`].
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let url = http_attempt_url(ctx, "/api/json");
/// ```
pub fn http_attempt_url(ctx: &AttemptContext, path: &str) -> String {
    http_service_url(ctx.url_scheme, &ctx.target_host, ctx.port(), path)
}

/// Builds the service URL for a target probe.
///
/// # Parameters
///
/// - `ctx`: Probe host, scheme, and port.
/// - `path`: Request path.
///
/// # Returns
///
/// URL string from [`http_service_url`] and [`TargetContext::port`].
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let url = http_target_url(ctx, "/api/json");
/// ```
pub fn http_target_url(ctx: &TargetContext, path: &str) -> String {
    http_service_url(ctx.url_scheme, &ctx.target_host, ctx.port(), path)
}

/// Builds the redirect-following HTTP client for one attempt.
///
/// String-error modules map the `reqwest::Error` with `err.to_string()`.
/// Modules that already use `HttpAttemptFailure` should call
/// `open_attempt_client` instead.
///
/// # Parameters
///
/// - `ctx`: Attempt timeout, scheme, and proxy.
///
/// # Returns
///
/// Configured client.
///
/// # Errors
///
/// Returns `reqwest::Error` when the client cannot be built.
///
/// # Examples
///
/// ```ignore
/// let client = attempt_http_client(ctx).map_err(|err| err.to_string())?;
/// ```
pub fn attempt_http_client(ctx: &AttemptContext) -> Result<reqwest::Client, reqwest::Error> {
    build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
}

/// Builds the redirect-following HTTP client for a target probe.
///
/// Probe callers use `.ok()?` so a build failure stays `None`.
///
/// # Parameters
///
/// - `ctx`: Probe timeout, scheme, and proxy.
///
/// # Returns
///
/// Configured client.
///
/// # Errors
///
/// Returns `reqwest::Error` when the client cannot be built.
///
/// # Examples
///
/// ```ignore
/// let client = target_http_client(ctx).ok()?;
/// ```
pub fn target_http_client(ctx: &TargetContext) -> Result<reqwest::Client, reqwest::Error> {
    build_http_basic_client(ctx.timeout(), ctx.url_scheme, ctx.target.proxy.as_ref())
}

/// Applies HTTP Basic Auth when either credential field is non-empty.
///
/// Empty credentials leave the request unchanged. This is not a Digest, Bearer,
/// cookie, or form-login applicator.
///
/// # Parameters
///
/// - `request`: Request that does not yet have Authorization applied here.
/// - `ctx`: Attempt credentials.
///
/// # Returns
///
/// The same builder, with Basic Auth when credentials are present.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let request = with_basic_auth(client.get(&url), ctx);
/// ```
pub fn with_basic_auth(request: RequestBuilder, ctx: &AttemptContext) -> RequestBuilder {
    if credentials_absent(ctx) {
        return request;
    }
    request.basic_auth(
        ctx.credential.username.as_deref().unwrap_or(""),
        Some(ctx.credential.password.as_deref().unwrap_or("")),
    )
}
