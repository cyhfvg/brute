//! MCP tool input types and conversion into engine requests.

use rmcp::schemars;
use serde::Deserialize;

use crate::engine::SprayRequest;
use crate::proxy::ProxyConfig;

/// Shared protocol options accepted by verify and spray tools.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct ProtocolOptions {
    /// TCP port override. Defaults to the protocol service port.
    pub port: Option<u16>,
    /// Per-attempt timeout in milliseconds. Default: 5000.
    pub timeout_ms: Option<u64>,
    /// Transient transport retry count. Default: 3.
    pub retries: Option<usize>,
    /// Outbound proxy URL: `http://[user[:pass]@]host:port` or `socks5://...`.
    pub proxy: Option<String>,
    /// Workspace for `--id` lookup and success persistence. Defaults to current.
    pub workspace: Option<String>,
    /// Post-auth command for ssh/ftp/mysql/postgresql/redis/oracle/winrm.
    pub execute: Option<String>,
    /// HTTP or Tomcat request path.
    pub path: Option<String>,
    /// HTTP URL scheme: `http` or `https`. Default: `http`.
    pub url_scheme: Option<String>,
    /// Oracle Service Name values or wordlist paths. Mutually exclusive with `sids`.
    #[serde(default)]
    pub service_names: Vec<String>,
    /// Oracle SID values or wordlist paths. Mutually exclusive with `service_names`.
    #[serde(default)]
    pub sids: Vec<String>,
    /// Enumerate SMB shares after a successful login.
    #[serde(default)]
    pub shares: bool,
    /// WinRM shell type: `cmd` or `powershell`.
    pub shell_type: Option<String>,
}

/// Parameters for a single-account validity check.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct VerifyAccountParams {
    /// Protocol name: ssh, ftp, mysql, postgresql, redis, oracle, tomcat, smb, rdp, winrm, http, vnc.
    pub protocol: String,
    /// Target IP, hostname, or FQDN.
    pub target: String,
    /// Username. Use an empty string for password-only services. Required unless `credential_id` is set.
    pub username: Option<String>,
    /// Password. Use an empty string for empty-password logins. Required unless `credential_id` is set.
    pub password: Option<String>,
    /// Saved credential id from the selected workspace. Mutually exclusive with username/password.
    pub credential_id: Option<i64>,
    /// Shared protocol options.
    #[serde(default)]
    pub options: ProtocolOptions,
}

/// Parameters for a multi-account password spray.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SprayPasswordsParams {
    /// Protocol name: ssh, ftp, mysql, postgresql, redis, oracle, tomcat, smb, rdp, winrm, http, vnc.
    pub protocol: String,
    /// Target hosts and/or target-file paths.
    pub targets: Vec<String>,
    /// Usernames and/or username wordlist paths. Required unless `credential_id` is set.
    #[serde(default)]
    pub usernames: Vec<String>,
    /// Passwords and/or password wordlist paths. Required unless `credential_id` is set.
    #[serde(default)]
    pub passwords: Vec<String>,
    /// Saved credential id from the selected workspace. Mutually exclusive with usernames/passwords.
    pub credential_id: Option<i64>,
    /// Global in-flight attempt cap. Default: 16.
    pub threads: Option<usize>,
    /// Continue a target after the first success. Default: false.
    #[serde(default)]
    pub continue_on_success: bool,
    /// Shared protocol options.
    #[serde(default)]
    pub options: ProtocolOptions,
}

/// Parameters for listing saved credentials.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct ListCredentialsParams {
    /// Workspace to search. Defaults to the current workspace.
    pub workspace: Option<String>,
    /// Protocol filter such as `ssh` or `http`.
    pub protocol: Option<String>,
    /// Exact host/IP filter.
    pub host: Option<String>,
}

impl VerifyAccountParams {
    /// Converts verify-tool arguments into an engine request.
    ///
    /// # Parameters
    ///
    /// None. Uses the fields on `self`.
    ///
    /// # Returns
    ///
    /// A single-target [`SprayRequest`].
    ///
    /// # Errors
    ///
    /// Returns an error when protocol, proxy, or credential sources are invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let request = params.into_request()?;
    /// ```
    pub fn into_request(self) -> anyhow::Result<SprayRequest> {
        let mut request = SprayRequest {
            protocol: crate::engine::parse_protocol(&self.protocol)?,
            targets: vec![self.target],
            credential_id: self.credential_id,
            ..SprayRequest::default()
        };
        if self.credential_id.is_none() {
            request.usernames = vec![self.username.unwrap_or_default()];
            request.passwords = vec![self.password.unwrap_or_default()];
        }
        apply_options(&mut request, self.options)?;
        Ok(request)
    }
}

impl SprayPasswordsParams {
    /// Converts spray-tool arguments into an engine request.
    ///
    /// # Parameters
    ///
    /// None. Uses the fields on `self`.
    ///
    /// # Returns
    ///
    /// A multi-target [`SprayRequest`].
    ///
    /// # Errors
    ///
    /// Returns an error when protocol, proxy, or credential sources are invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let request = params.into_request()?;
    /// ```
    pub fn into_request(self) -> anyhow::Result<SprayRequest> {
        if self.targets.is_empty() {
            anyhow::bail!("targets must not be empty");
        }
        let mut request = SprayRequest {
            protocol: crate::engine::parse_protocol(&self.protocol)?,
            targets: self.targets,
            usernames: self.usernames,
            passwords: self.passwords,
            credential_id: self.credential_id,
            threads: self.threads.unwrap_or(16),
            continue_on_success: self.continue_on_success,
            ..SprayRequest::default()
        };
        apply_options(&mut request, self.options)?;
        Ok(request)
    }
}

fn apply_options(request: &mut SprayRequest, options: ProtocolOptions) -> anyhow::Result<()> {
    if let Some(port) = options.port {
        request.port = Some(port);
    }
    if let Some(timeout_ms) = options.timeout_ms {
        request.timeout_ms = timeout_ms;
    }
    if let Some(retries) = options.retries {
        request.retries = retries;
    }
    if let Some(proxy) = options.proxy {
        request.proxy = Some(ProxyConfig::parse(&proxy).map_err(anyhow::Error::msg)?);
    }
    request.workspace = options.workspace;
    request.execute = options.execute;
    request.path = options.path;
    if let Some(scheme) = options.url_scheme {
        request.url_scheme = crate::engine::parse_http_scheme(&scheme)?;
    }
    request.service_names = options.service_names;
    request.sids = options.sids;
    request.shares = options.shares;
    if let Some(shell) = options.shell_type {
        request.shell_type = Some(crate::engine::parse_shell_type(&shell)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{HttpUrlScheme, Protocol};

    /// Verifies verify-tool params become a single-target engine request.
    #[test]
    fn verify_params_build_single_target_request() {
        let params = VerifyAccountParams {
            protocol: "ssh".into(),
            target: "10.0.0.8".into(),
            username: Some("root".into()),
            password: Some("toor".into()),
            credential_id: None,
            options: ProtocolOptions {
                port: Some(2222),
                timeout_ms: Some(1_000),
                ..ProtocolOptions::default()
            },
        };
        let request = params.into_request().expect("verify params should convert");
        assert_eq!(request.protocol, Protocol::Ssh);
        assert_eq!(request.targets, ["10.0.0.8"]);
        assert_eq!(request.usernames, ["root"]);
        assert_eq!(request.passwords, ["toor"]);
        assert_eq!(request.port, Some(2222));
        assert_eq!(request.timeout_ms, 1_000);
    }

    /// Verifies HTTP scheme and Oracle identifier options are parsed.
    #[test]
    fn spray_params_parse_http_and_oracle_options() {
        let params = SprayPasswordsParams {
            protocol: "http".into(),
            targets: vec!["app.internal".into()],
            usernames: vec!["admin".into()],
            passwords: vec!["secret".into()],
            credential_id: None,
            threads: Some(4),
            continue_on_success: true,
            options: ProtocolOptions {
                url_scheme: Some("https".into()),
                path: Some("/login".into()),
                ..ProtocolOptions::default()
            },
        };
        let request = params
            .into_request()
            .expect("http spray params should convert");
        assert_eq!(request.protocol, Protocol::Http);
        assert_eq!(request.url_scheme, HttpUrlScheme::Https);
        assert_eq!(request.path.as_deref(), Some("/login"));
        assert_eq!(request.threads, 4);
        assert!(request.continue_on_success);
    }
}
