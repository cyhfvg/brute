//! PostgreSQL login attempts.

use std::sync::Arc;

use async_trait::async_trait;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::{Config, SimpleQueryMessage};
use tokio_postgres_rustls::MakeRustlsConnect;

use super::{AttemptContext, AttemptOutcome, AttemptSuccess, BruteModule};
use crate::cli::PgSslMode;

/// PostgreSQL attempt errors split auth/connect failures from post-auth command failures.
type PostgreSqlAttemptError = crate::protocol::http_attempt::HttpAttemptFailure;

/// PostgreSQL module configuration.
#[derive(Debug, Clone)]
pub struct PostgreSqlModule {
    ssl_mode: PgSslMode,
}

impl PostgreSqlModule {
    /// Creates a new PostgreSQL module instance.
    pub fn new(_timeout_ms: u64, ssl_mode: PgSslMode) -> Self {
        Self { ssl_mode }
    }
}

/// Certificate verifier for scanner-style PostgreSQL TLS negotiation.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    /// Accepts any server certificate so self-signed database certificates do not hide auth results.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    /// Accepts TLS 1.2 handshake signatures after certificate verification is bypassed.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Accepts TLS 1.3 handshake signatures after certificate verification is bypassed.
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Returns the signature algorithms supported by the rustls client verifier.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

#[async_trait]
impl BruteModule for PostgreSqlModule {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    async fn attempt(&self, ctx: &AttemptContext) -> AttemptOutcome {
        let host = ctx.target_host.clone();
        let port = ctx.target.port.unwrap_or(ctx.protocol.default_port());
        let proxy = ctx.target.proxy.clone();
        let mut config = Config::new();
        config.host(&host);
        config.port(port);
        config.user(ctx.credential.username.as_deref().unwrap_or_default());
        config.password(ctx.credential.password.as_deref().unwrap_or_default());
        config.dbname("postgres");
        let command = ctx.execute.clone();
        let ssl_mode = self.ssl_mode;

        let attempt = async move {
            // Always open the TCP socket ourselves so proxy and direct paths share one type.
            let stream = match proxy {
                Some(proxy) => crate::proxy::connect_async(&proxy, &host, port)
                    .await
                    .map_err(PostgreSqlAttemptError::Auth)?,
                None => tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?,
            };
            match ssl_mode {
                PgSslMode::Disable => {
                    let (client, connection) = config
                        .connect_raw(stream, tokio_postgres::NoTls)
                        .await
                        .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    run_postgres_query(client, command).await
                }
                PgSslMode::Require | PgSslMode::VerifyFull => {
                    let mut tls = tls_connector(ssl_mode);
                    let tls = <MakeRustlsConnect as MakeTlsConnect<tokio::net::TcpStream>>::make_tls_connect(
                        &mut tls,
                        &host,
                    )
                    .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?;
                    let (client, connection) = config
                        .connect_raw(stream, tls)
                        .await
                        .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    run_postgres_query(client, command).await
                }
            }
        };

        crate::protocol::http_attempt::run_http_attempt(
            ctx.timeout(),
            "postgresql",
            || "PostgreSQL access!".to_string(),
            attempt,
        )
        .await
    }
}

/// Builds a rustls connector matching the requested verification level.
fn tls_connector(ssl_mode: PgSslMode) -> MakeRustlsConnect {
    match ssl_mode {
        PgSslMode::VerifyFull => {
            let config = ClientConfig::builder()
                .with_root_certificates(system_roots())
                .with_no_client_auth();
            MakeRustlsConnect::new(config)
        }
        PgSslMode::Require => {
            let mut config = ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
            MakeRustlsConnect::new(config)
        }
        PgSslMode::Disable => {
            unreachable!("disable sslmode must not build a TLS connector")
        }
    }
}

/// Returns the bundled Mozilla CA roots used by `verify-full`.
fn system_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Runs an optional query on an authenticated client and formats the result.
async fn run_postgres_query(
    client: tokio_postgres::Client,
    command: Option<String>,
) -> Result<AttemptSuccess, PostgreSqlAttemptError> {
    let Some(command) = command else {
        return Ok(AttemptSuccess::new("PostgreSQL access!"));
    };
    match client.simple_query(&command).await {
        Ok(messages) => Ok(AttemptSuccess::with_command(
            "PostgreSQL access!",
            format_simple_query_messages(&messages),
        )),
        Err(err) => Ok(AttemptSuccess::with_command_error(
            "PostgreSQL access!",
            format!("postgresql command execution failed: {err}"),
        )),
    }
}

/// Formats PostgreSQL simple-query output into a compact preview.
fn format_simple_query_messages(messages: &[SimpleQueryMessage]) -> String {
    let rows = messages
        .iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                row.columns()
                    .iter()
                    .enumerate()
                    .map(|(index, column)| {
                        let value = row.get(index).unwrap_or("<null>");
                        format!("{}={}", column.name(), value)
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        })
        .take(10)
        .collect::<Vec<_>>();

    if rows.is_empty() {
        "0 row(s) returned".to_string()
    } else {
        format!("{} row(s) returned\n{}", rows.len(), rows.join("\n"))
    }
}
