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

/// PostgreSQL attempt errors split auth/connect failures from post-auth command failures.
#[derive(Debug)]
enum PostgreSqlAttemptError {
    Auth(String),
}

/// PostgreSQL module configuration.
#[derive(Debug, Clone)]
pub struct PostgreSqlModule;

impl PostgreSqlModule {
    /// Creates a new PostgreSQL module instance.
    pub fn new(_timeout_ms: u64) -> Self {
        Self
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

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
        let mut tls = MakeRustlsConnect::new(tls_config);

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
            let tls =
                <MakeRustlsConnect as MakeTlsConnect<tokio::net::TcpStream>>::make_tls_connect(
                    &mut tls, &host,
                )
                .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?;
            let (client, connection) = config
                .connect_raw(stream, tls)
                .await
                .map_err(|err| PostgreSqlAttemptError::Auth(err.to_string()))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            if let Some(command) = command {
                let success = match client.simple_query(&command).await {
                    Ok(messages) => AttemptSuccess::with_command(
                        "PostgreSQL access!",
                        format_simple_query_messages(&messages),
                    ),
                    Err(err) => AttemptSuccess::with_command_error(
                        "PostgreSQL access!",
                        format!("postgresql command execution failed: {err}"),
                    ),
                };
                Ok::<_, PostgreSqlAttemptError>(success)
            } else {
                Ok::<_, PostgreSqlAttemptError>(AttemptSuccess::new("PostgreSQL access!"))
            }
        };

        match tokio::time::timeout(ctx.timeout(), attempt).await {
            Ok(Ok(success)) => AttemptOutcome::Success(success),
            Ok(Err(PostgreSqlAttemptError::Auth(err))) => {
                AttemptOutcome::Failure(format!("postgresql auth failed: {err}"))
            }
            Err(_) => AttemptOutcome::Error("attempt timed out".to_string()),
        }
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
