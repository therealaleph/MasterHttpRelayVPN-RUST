use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("pem parse: {0}")]
    Pem(String),
    #[error("invalid cert/key material: {0}")]
    Invalid(String),
}

pub const CERT_NAME: &str = "MasterHttpRelayVPN";
pub const CA_DIR: &str = "ca";
pub const CA_KEY_FILE: &str = "ca/ca.key";
pub const CA_CERT_FILE: &str = "ca/ca.crt";

pub struct MitmCertManager {
    /// The CA certificate bytes as they appear on disk.
    /// This is what we chain onto leaves so browsers validate against
    /// the exact cert they've trusted.
    ca_cert_der: CertificateDer<'static>,
    /// The CA key pair used to sign leaves.
    ca_key_pair: KeyPair,
    /// An in-memory `Certificate` (the rcgen type) whose params match the
    /// on-disk CA. Used as the `issuer` argument when signing leaves. Its
    /// DER may differ from `ca_cert_der` (different serial, signature
    /// re-made), but that's fine — we never send this cert to browsers.
    ca_cert: Certificate,
    cache: HashMap<String, Arc<ServerConfig>>,
}

impl MitmCertManager {
    pub fn new() -> Result<Self, MitmError> {
        Self::new_in(Path::new("."))
    }

    pub fn new_in(base: &Path) -> Result<Self, MitmError> {
        let ca_dir = base.join(CA_DIR);
        let ca_key_path = base.join(CA_KEY_FILE);
        let ca_cert_path = base.join(CA_CERT_FILE);

        if ca_key_path.exists() && ca_cert_path.exists() {
            Self::load(&ca_key_path, &ca_cert_path)
        } else {
            std::fs::create_dir_all(&ca_dir)?;
            Self::generate(&ca_key_path, &ca_cert_path)
        }
    }

    fn load(key_path: &Path, cert_path: &Path) -> Result<Self, MitmError> {
        let key_pem = std::fs::read_to_string(key_path)?;
        let cert_pem = std::fs::read_to_string(cert_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)?;

        let mut cert_bytes = cert_pem.as_bytes();
        let mut certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_bytes).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(MitmError::Pem("no certificate in ca.crt".into()));
        }
        let ca_cert_der = certs.remove(0);

        // Rebuild params from the DER, then self-sign an in-memory Certificate
        // for use as the signing-issuer. Its DER signature will differ from
        // the on-disk one, but DN, SAN, and key identifier match.
        let params = CertificateParams::from_ca_cert_der(&ca_cert_der)?;
        let ca_cert = params.self_signed(&key_pair)?;

        tracing::info!("Loaded MITM CA from {}", cert_path.display());

        Ok(Self {
            ca_cert_der,
            ca_key_pair: key_pair,
            ca_cert,
            cache: HashMap::new(),
        })
    }

    fn generate(key_path: &Path, cert_path: &Path) -> Result<Self, MitmError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CERT_NAME);
        dn.push(DnType::OrganizationName, CERT_NAME);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(3650);

        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;

        let cert_pem = ca_cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(cert_path, cert_pem.as_bytes())?;
        std::fs::write(key_path, key_pem.as_bytes())?;
        tracing::warn!(
            "Generated new MITM CA at {} — install it as a trusted root CA",
            cert_path.display()
        );

        let ca_cert_der = ca_cert.der().clone();

        Ok(Self {
            ca_cert_der,
            ca_key_pair: key_pair,
            ca_cert,
            cache: HashMap::new(),
        })
    }

    pub fn ca_cert_path(base: &Path) -> PathBuf {
        base.join(CA_CERT_FILE)
    }

    /// Return a rustls ServerConfig for the given domain, ALPN ["http/1.1"].
    pub fn get_server_config(&mut self, domain: &str) -> Result<Arc<ServerConfig>, MitmError> {
        if let Some(cfg) = self.cache.get(domain) {
            return Ok(cfg.clone());
        }
        let (leaf_der, leaf_key_der) = self.issue_leaf(domain)?;

        let chain = vec![leaf_der, self.ca_cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let arc = Arc::new(cfg);
        self.cache.insert(domain.to_string(), arc.clone());
        Ok(arc)
    }

    fn issue_leaf(&self, domain: &str) -> Result<(CertificateDer<'static>, Vec<u8>), MitmError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;
        let dns_name = domain.try_into().map_err(|e: rcgen::Error| {
            MitmError::Invalid(format!("bad dns name '{}': {}", domain, e))
        })?;
        params.subject_alt_names.push(SanType::DnsName(dns_name));

        // Modern browsers (Chrome/Firefox, all current versions) reject TLS
        // leaves that don't carry:
        //   - ExtendedKeyUsage: serverAuth   → NET::ERR_CERT_INVALID otherwise
        //   - KeyUsage: digitalSignature + keyEncipherment
        // rcgen's `CertificateParams::default()` doesn't set these — we have
        // to add them explicitly. Skipping this was the root cause of issue #11
        // where users reinstalled the trusted CA dozens of times and browsers
        // still refused to load HTTPS sites through the proxy.
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Backdate not_before by 5 min to absorb clock skew between the
        // MITM process and the browser / system clock.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);

        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key_pair)?;
        let leaf_der = leaf.der().clone();
        let leaf_key_der = leaf_key.serialize_der();
        Ok((leaf_der, leaf_key_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_crypto() {
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn generate_and_reload_ca() {
        init_crypto();
        let tmp = tempdir();
        let _ = MitmCertManager::new_in(&tmp).unwrap();
        let mut m = MitmCertManager::new_in(&tmp).unwrap();
        let cfg = m.get_server_config("example.com").unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn leaf_has_serverauth_eku_and_key_usage() {
        // Regression guard for issue #11. rcgen's CertificateParams::default()
        // doesn't set these extensions; without them modern Chrome/Firefox
        // reject every leaf with NET::ERR_CERT_INVALID even after the CA is
        // trusted. Verified by spot-checking the DER with x509-parser.
        use x509_parser::prelude::*;

        init_crypto();
        let tmp = tempdir();
        let m = MitmCertManager::new_in(&tmp).unwrap();
        let (leaf_der, _) = m.issue_leaf("example.com").unwrap();
        let (_, parsed) = X509Certificate::from_der(&leaf_der).unwrap();

        // ExtendedKeyUsage: serverAuth present.
        let eku = parsed
            .extended_key_usage()
            .expect("eku extension lookup")
            .expect("eku extension present");
        assert!(eku.value.server_auth, "leaf must have serverAuth EKU");

        // KeyUsage: digitalSignature + keyEncipherment present.
        let ku = parsed
            .key_usage()
            .expect("key_usage extension lookup")
            .expect("key_usage extension present");
        assert!(ku.value.digital_signature(), "leaf must have digitalSignature KU");
        assert!(ku.value.key_encipherment(), "leaf must have keyEncipherment KU");

        // SAN has the domain we asked for.
        let san = parsed
            .subject_alternative_name()
            .expect("san extension lookup")
            .expect("san extension present");
        let has_name = san.value.general_names.iter().any(|n| {
            matches!(n, GeneralName::DNSName(s) if *s == "example.com")
        });
        assert!(has_name, "leaf SAN must contain example.com");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn issues_different_certs_per_domain() {
        init_crypto();
        let tmp = tempdir();
        let mut m = MitmCertManager::new_in(&tmp).unwrap();
        let _ = m.get_server_config("a.example.com").unwrap();
        let _ = m.get_server_config("b.example.com").unwrap();
        assert_eq!(m.cache.len(), 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("mhrv-test-{:x}", n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
