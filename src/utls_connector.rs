//! BoringSSL-backed TLS connector with Chrome ClientHello shape.
//!
//! Real Chrome ships BoringSSL, so the bytes on the wire match what
//! a real browser would send. Tracks roadmap item #369 §2. Compiled
//! only with `--features utls` because BoringSSL needs CMake + clang
//! at build time.

use std::io;
use std::sync::Arc;

use rama_boring::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use rama_boring_tokio::SslStream;
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum UtlsError {
    #[error("boringssl error: {0}")]
    Ssl(#[from] rama_boring::error::ErrorStack),
    #[error("tls handshake error: {0}")]
    Handshake(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnPolicy {
    H2Then11,
    Http1Only,
}

impl AlpnPolicy {
    fn wire_bytes(self) -> Vec<u8> {
        // ALPN wire format: each protocol prefixed with its length byte.
        match self {
            AlpnPolicy::H2Then11 => b"\x02h2\x08http/1.1".to_vec(),
            AlpnPolicy::Http1Only => b"\x08http/1.1".to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintProfile {
    Chrome,
}

pub struct UtlsConnector {
    inner: SslConnector,
    verify: bool,
}

impl UtlsConnector {
    pub fn new(
        profile: FingerprintProfile,
        alpn: AlpnPolicy,
        verify: bool,
    ) -> Result<Self, UtlsError> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        match profile {
            FingerprintProfile::Chrome => apply_chrome_profile(&mut builder)?,
        }
        builder.set_alpn_protos(&alpn.wire_bytes())?;
        if !verify {
            builder.set_verify(SslVerifyMode::NONE);
        }
        Ok(Self {
            inner: builder.build(),
            verify,
        })
    }

    pub async fn connect(
        &self,
        sni: &str,
        tcp: TcpStream,
    ) -> Result<SslStream<TcpStream>, UtlsError> {
        let mut config = self.inner.configure()?;
        config.set_use_server_name_indication(true);
        config.set_verify_hostname(self.verify);
        rama_boring_tokio::connect(config, Some(sni), tcp)
            .await
            .map_err(|e| UtlsError::Handshake(e.to_string()))
    }
}

// Cipher list, curves, and sigalgs are in Chrome's preference order —
// order is part of the JA3/JA4 fingerprint, so changing it changes the
// shape on the wire.
fn apply_chrome_profile(
    builder: &mut rama_boring::ssl::SslConnectorBuilder,
) -> Result<(), UtlsError> {
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    // BoringSSL hardcodes the TLS 1.3 cipher set to match Chrome, so
    // there's no `set_ciphersuites` to call here. Only the TLS 1.2
    // cipher list is settable, below.
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:\
         AES128-GCM-SHA256:\
         AES256-GCM-SHA384:\
         AES128-SHA:\
         AES256-SHA",
    )?;
    builder.set_curves_list("X25519:P-256:P-384")?;
    builder.set_sigalgs_list(
        "ecdsa_secp256r1_sha256:\
         rsa_pss_rsae_sha256:\
         rsa_pkcs1_sha256:\
         ecdsa_secp384r1_sha384:\
         rsa_pss_rsae_sha384:\
         rsa_pkcs1_sha384:\
         rsa_pss_rsae_sha512:\
         rsa_pkcs1_sha512",
    )?;
    builder.enable_ocsp_stapling();
    builder.set_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1,
    );
    Ok(())
}

pub type SharedUtlsConnector = Arc<UtlsConnector>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_h2_then_11_wire_format() {
        let bytes = AlpnPolicy::H2Then11.wire_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[..3], b"\x02h2");
        assert_eq!(&bytes[3..], b"\x08http/1.1");
    }

    #[test]
    fn alpn_http1_only_wire_format() {
        let bytes = AlpnPolicy::Http1Only.wire_bytes();
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[..], b"\x08http/1.1");
    }

    #[test]
    fn chrome_profile_builds_clean() {
        let conn = UtlsConnector::new(FingerprintProfile::Chrome, AlpnPolicy::H2Then11, true);
        assert!(
            conn.is_ok(),
            "Chrome profile failed to build: {:?}",
            conn.err()
        );
    }

    #[test]
    fn no_verify_path_builds() {
        let conn = UtlsConnector::new(FingerprintProfile::Chrome, AlpnPolicy::Http1Only, false);
        assert!(conn.is_ok());
        assert!(!conn.unwrap().verify);
    }
}
