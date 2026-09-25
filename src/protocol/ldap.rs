//! LDAP simple bind, anonymous probe, and post-auth search / whoami (`-x`).
//!
//! Empty username and password perform an anonymous bind plus a Root DSE read.
//! Non-empty `-u` is the bind DN. Host:port clients use the shared TCP proxy bridge.

use async_trait::async_trait;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use tokio::net::TcpStream;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule, TargetContext};

/// LDAP module configuration.
#[derive(Debug, Clone)]
pub struct LdapModule;

impl LdapModule {
    /// Creates a new LDAP module instance.
    ///
    /// # Parameters
    ///
    /// - `_timeout_ms`: Unused; timeout is read from context.
    ///
    /// # Returns
    ///
    /// A stateless [`LdapModule`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use brute::protocol::ldap::LdapModule;
    ///
    /// let _module = LdapModule::new(5000);
    /// ```
    pub fn new(_timeout_ms: u64) -> Self {
        Self
    }
}

#[async_trait]
impl BruteModule for LdapModule {
    fn name(&self) -> &'static str {
        "ldap"
    }

    async fn probe_target(&self, ctx: &TargetContext) -> Option<String> {
        match tokio::time::timeout(ctx.timeout(), probe_tcp(ctx)).await {
            Ok(true) => Some("LDAP".to_string()),
            _ => None,
        }
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        crate::protocol::http_attempt::run_http_attempt(ctx.timeout(), "ldap", String::new, async {
            attempt_once(ctx)
                .await
                .map_err(crate::protocol::http_attempt::classify_auth_prefix)
        })
        .await
    }
}

/// Runs one LDAP simple bind, then optional `-x` search or whoami.
///
/// # Parameters
///
/// - `ctx`: Target, credential, timeout, proxy, and optional execute text.
///
/// # Returns
///
/// [`AttemptSuccess`] when the bind is accepted.
///
/// # Errors
///
/// Returns `auth:...` on invalid credentials and a transport string otherwise.
///
/// # Examples
///
/// ```ignore
/// let success = attempt_once(&ctx).await?;
/// ```
async fn attempt_once(ctx: &AttemptContext) -> Result<AttemptSuccess, String> {
    let unauthenticated = is_unauthenticated(ctx);
    let bind_dn = ctx.credential.username.as_deref().unwrap_or("");
    let password = ctx.credential.password.as_deref().unwrap_or("");
    let host = ctx.target_host.as_str();
    let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
    let endpoint =
        crate::proxy::resolve_tcp_endpoint(ctx.target.proxy.as_ref(), host, port).await?;
    let (connect_host, connect_port, _bridge) = endpoint;
    let url = format!("ldap://{connect_host}:{connect_port}");
    let (conn, mut ldap) = LdapConnAsync::new(&url)
        .await
        .map_err(|err| err.to_string())?;
    ldap3::drive!(conn);
    let bind = ldap
        .simple_bind(bind_dn, password)
        .await
        .map_err(|err| err.to_string())?;
    if let Err(err) = bind.success() {
        let text = err.to_string();
        if is_auth_error(&text) {
            return Err(format!("auth:{text}"));
        }
        return Err(text);
    }
    if unauthenticated {
        let search = ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["namingContexts"])
            .await
            .map_err(|err| err.to_string())?;
        if search.success().is_err() {
            return Err("auth:anonymous search denied".to_string());
        }
    }
    let message = success_message(unauthenticated);
    if let Some(command) = ctx.execute.as_deref() {
        let output = run_command(&mut ldap, bind_dn, command).await;
        let _ = ldap.unbind().await;
        return Ok(match output {
            Ok(text) => AttemptSuccess::with_command(message, text),
            Err(err) => AttemptSuccess::with_command_error(message, err),
        });
    }
    let _ = ldap.unbind().await;
    Ok(AttemptSuccess::new(message))
}

async fn run_command(
    ldap: &mut ldap3::Ldap,
    bind_dn: &str,
    command: &str,
) -> Result<String, String> {
    let trimmed = command.trim();
    if trimmed.eq_ignore_ascii_case("whoami") {
        let (exop, _res) = ldap
            .extended(WhoAmI)
            .await
            .map_err(|err| err.to_string())?
            .success()
            .map_err(|err| err.to_string())?;
        let who = exop.parse::<WhoAmIResp>();
        return Ok(who.authzid);
    }
    let (base, scope, filter) = search_args(trimmed, bind_dn);
    let (rs, _res) = ldap
        .search(&base, scope, &filter, vec!["dn"])
        .await
        .map_err(|err| err.to_string())?
        .success()
        .map_err(|err| err.to_string())?;
    let mut lines = Vec::new();
    for entry in rs.into_iter().take(10) {
        let dn = SearchEntry::construct(entry).dn;
        lines.push(if dn.is_empty() {
            "(root DSE)".to_string()
        } else {
            dn
        });
    }
    if lines.is_empty() {
        Ok("(no entries)".to_string())
    } else {
        Ok(lines.join("\n"))
    }
}

/// Maps `-x` text into an LDAP search base, scope, and filter.
///
/// # Parameters
///
/// - `command`: CLI `-x` value (`rootdse`, a filter, or a DN).
/// - `bind_dn`: Bind DN used to derive a default search base.
///
/// # Returns
///
/// `(base, scope, filter)`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::ldap::search_args;
/// use ldap3::Scope;
///
/// let (base, scope, filter) = search_args("rootdse", "cn=admin,dc=example,dc=org");
/// assert_eq!(base, "");
/// assert_eq!(scope, Scope::Base);
/// assert_eq!(filter, "(objectClass=*)");
/// ```
pub fn search_args(command: &str, bind_dn: &str) -> (String, Scope, String) {
    let trimmed = command.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("rootdse")
        || trimmed.eq_ignore_ascii_case("root")
    {
        return (String::new(), Scope::Base, "(objectClass=*)".to_string());
    }
    if trimmed.starts_with('(') {
        return (search_base(bind_dn), Scope::Subtree, trimmed.to_string());
    }
    if looks_like_dn(trimmed) {
        return (
            trimmed.to_string(),
            Scope::Base,
            "(objectClass=*)".to_string(),
        );
    }
    (
        search_base(bind_dn),
        Scope::Subtree,
        format!("(objectClass={trimmed})"),
    )
}

/// Derives a search base by stripping the first RDN from a bind DN.
///
/// # Parameters
///
/// - `bind_dn`: Bind distinguished name.
///
/// # Returns
///
/// Parent DN, or an empty string when `bind_dn` has no comma.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::ldap::search_base;
///
/// assert_eq!(search_base("cn=admin,dc=example,dc=org"), "dc=example,dc=org");
/// assert_eq!(search_base(""), "");
/// ```
pub fn search_base(bind_dn: &str) -> String {
    match bind_dn.split_once(',') {
        Some((_, rest)) => rest.to_string(),
        None => String::new(),
    }
}

/// Returns whether LDAP error text is an authentication failure.
///
/// # Parameters
///
/// - `err`: Driver or result error text.
///
/// # Returns
///
/// `true` for invalidCredentials / result code 49 wording.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```
/// use brute::protocol::ldap::is_auth_error;
///
/// assert!(is_auth_error("invalidCredentials (49)"));
/// assert!(!is_auth_error("connection refused"));
/// ```
pub fn is_auth_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("invalidcredentials")
        || lower.contains("invalid credentials")
        || lower.contains("inappropriate authentication")
        || lower.contains("rc=49")
        || lower.contains("(49)")
}

fn looks_like_dn(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("dc=")
        || lower.contains("ou=")
        || lower.contains("cn=")
        || lower.contains("uid=")
}

async fn probe_tcp(ctx: &TargetContext) -> bool {
    TcpStream::connect((ctx.target_host.as_str(), ctx.port()))
        .await
        .is_ok()
}

fn is_unauthenticated(ctx: &AttemptContext) -> bool {
    ctx.credential.username.as_deref().unwrap_or("").is_empty()
        && ctx.credential.password.as_deref().unwrap_or("").is_empty()
}

fn success_message(unauthenticated: bool) -> &'static str {
    if unauthenticated {
        "LDAP unauthorized access!"
    } else {
        "LDAP access!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_args_maps_shorthand() {
        let (base, scope, filter) = search_args("rootdse", "cn=admin,dc=example,dc=org");
        assert_eq!(base, "");
        assert_eq!(scope, Scope::Base);
        assert_eq!(filter, "(objectClass=*)");
        let (base, _, filter) = search_args("(cn=admin)", "cn=admin,dc=example,dc=org");
        assert_eq!(base, "dc=example,dc=org");
        assert_eq!(filter, "(cn=admin)");
    }

    #[test]
    fn is_auth_error_detects_result_49() {
        assert!(is_auth_error("LDAP result: invalidCredentials (49)"));
        assert!(!is_auth_error("connection refused"));
    }
}
