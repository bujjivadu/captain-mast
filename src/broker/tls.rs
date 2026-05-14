//! captain-mast custom client-cert verifier.
//!
//! Wraps rumqttd's stock `WebPkiClientVerifier` so every rejection logs the
//! cert details and the actual webpki `Error` variant, instead of the
//! flattened `InvalidCertificate(UnknownIssuer)` message rumqttd would emit on
//! its own.
//!
//! Wired in via `rumqttd::server::tls::WRAP_VERIFIER` — an `OnceCell` hook we
//! added in our local rumqttd fork. `install()` registers the wrapper at
//! startup; rumqttd then applies it after it constructs its base verifier.

use std::sync::Arc;

use rumqttd::tokio_rustls::rustls::{
    self,
    pki_types::CertificateDer,
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
};
use tracing::warn;

#[derive(Debug)]
pub struct LoggingClientVerifier(Arc<dyn ClientCertVerifier>);

impl LoggingClientVerifier {
    pub fn wrap(inner: Arc<dyn ClientCertVerifier>) -> Arc<dyn ClientCertVerifier> {
        Arc::new(Self(inner))
    }
}

impl ClientCertVerifier for LoggingClientVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.0
            .verify_client_cert(end_entity, intermediates, now)
            .map_err(|e| {
                if let Ok((_, cert)) = x509_parser::parse_x509_certificate(end_entity.as_ref()) {
                    warn!(
                        subject = %cert.subject(),
                        issuer = %cert.issuer(),
                        not_before = %cert.validity().not_before,
                        not_after = %cert.validity().not_after,
                        sig_alg = ?cert.signature_algorithm.algorithm,
                        presented_intermediates = intermediates.len(),
                        rustls_error = ?e,
                        "client cert rejected"
                    );
                } else {
                    warn!(rustls_error = ?e, "client cert rejected (cert parse failed)");
                }
                e
            })
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn offer_client_auth(&self) -> bool {
        self.0.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }
}

/// Register the logging wrapper with rumqttd's verifier hook. Call once at
/// startup, before any broker code that opens a TLS listener.
///
/// Idempotent — `OnceCell::set` only succeeds on the first call; further calls
/// are silently ignored.
pub fn install() {
    let _ = rumqttd::server::tls::WRAP_VERIFIER
        .set(Box::new(|base| LoggingClientVerifier::wrap(base)));
}
