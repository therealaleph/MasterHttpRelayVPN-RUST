//! Polymorphic TLS dialer over rustls or BoringSSL (uTLS).
//!
//! Captures negotiated ALPN at handshake time so callers don't need
//! to know which backend produced the stream — the relay's h2-fast-
//! path sticky-disable check still works after the swap. Tracks
//! roadmap item #369 §2.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as RustlsTlsConnector;

#[cfg(feature = "utls")]
use crate::utls_connector::UtlsConnector;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncReadWrite for T {}

pub struct DialedStream {
    inner: Box<dyn AsyncReadWrite>,
    alpn: Option<Vec<u8>>,
}

impl DialedStream {
    fn new<S: AsyncReadWrite + 'static>(inner: S, alpn: Option<Vec<u8>>) -> Self {
        Self {
            inner: Box::new(inner),
            alpn,
        }
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }
}

impl AsyncRead for DialedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DialedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
pub enum TlsDialer {
    Rustls(RustlsTlsConnector, AlpnPolicy),
    #[cfg(feature = "utls")]
    Utls(Arc<UtlsConnector>, AlpnPolicy),
}

impl TlsDialer {
    // SNI is supplied separately so callers can keep the SNI-rewrite
    // trick (dial Google IP X but hand the server `www.google.com`).
    // All handshake errors fold into io::Error so callers' existing
    // `?`-on-io::Error propagation still works.
    pub async fn connect(&self, sni: &str, tcp: TcpStream) -> io::Result<DialedStream> {
        match self {
            TlsDialer::Rustls(c, _) => {
                let name = ServerName::try_from(sni.to_string())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let tls = c.connect(name, tcp).await?;
                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                Ok(DialedStream::new(tls, alpn))
            }
            #[cfg(feature = "utls")]
            TlsDialer::Utls(c, _) => {
                let stream = c
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let alpn = stream.ssl().selected_alpn_protocol().map(|p| p.to_vec());
                Ok(DialedStream::new(stream, alpn))
            }
        }
    }

    /// Policy this dialer was built with — exposes the ALPN intent so
    /// `DomainFronter` tests can confirm the right policy was wired to
    /// the right slot (`dialer` vs `dialer_h1`) without round-tripping
    /// a real handshake.
    pub fn alpn_policy(&self) -> AlpnPolicy {
        match self {
            TlsDialer::Rustls(_, a) => *a,
            #[cfg(feature = "utls")]
            TlsDialer::Utls(_, a) => *a,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnPolicy {
    H2Then11,
    Http1Only,
}

impl AlpnPolicy {
    fn rustls_protos(self) -> Vec<Vec<u8>> {
        match self {
            AlpnPolicy::H2Then11 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            AlpnPolicy::Http1Only => vec![b"http/1.1".to_vec()],
        }
    }
}

fn build_rustls_config(verify: bool, alpn: AlpnPolicy) -> Arc<rustls::ClientConfig> {
    let mut cfg = if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.rustls_protos();
    Arc::new(cfg)
}

// Returns (dialer, fell_back_to_rustls). The flag is true when the
// caller asked for a non-rustls profile but the binary wasn't built
// with the matching feature — caller logs once at startup.
pub fn build_dialer(
    fingerprint: &str,
    verify: bool,
    alpn: AlpnPolicy,
) -> Result<(TlsDialer, bool), DialerBuildError> {
    let want_chrome = fingerprint.trim().eq_ignore_ascii_case("chrome");

    if want_chrome {
        #[cfg(feature = "utls")]
        {
            use crate::utls_connector::{AlpnPolicy as UAlpn, FingerprintProfile, UtlsConnector};
            let ualpn = match alpn {
                AlpnPolicy::H2Then11 => UAlpn::H2Then11,
                AlpnPolicy::Http1Only => UAlpn::Http1Only,
            };
            let conn = UtlsConnector::new(FingerprintProfile::Chrome, ualpn, verify)
                .map_err(|e| DialerBuildError::Utls(e.to_string()))?;
            return Ok((TlsDialer::Utls(Arc::new(conn), alpn), false));
        }
        #[cfg(not(feature = "utls"))]
        {
            let cfg = build_rustls_config(verify, alpn);
            return Ok((TlsDialer::Rustls(RustlsTlsConnector::from(cfg), alpn), true));
        }
    }

    let cfg = build_rustls_config(verify, alpn);
    Ok((TlsDialer::Rustls(RustlsTlsConnector::from(cfg), alpn), false))
}

#[derive(Debug, thiserror::Error)]
pub enum DialerBuildError {
    #[error("utls connector init failed: {0}")]
    Utls(String),
}

// Duplicated from domain_fronter so this module is independent of the
// relay implementation file.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rustls_dialer_builds_default() {
        let (d, fallback) = build_dialer("rustls", true, AlpnPolicy::H2Then11).unwrap();
        assert!(!fallback);
        match d {
            TlsDialer::Rustls(_, _) => {}
            #[cfg(feature = "utls")]
            TlsDialer::Utls(_, _) => panic!("expected Rustls"),
        }
    }

    #[test]
    fn unknown_fingerprint_falls_back_to_rustls() {
        let (d, _) = build_dialer("not-a-real-profile", true, AlpnPolicy::Http1Only).unwrap();
        match d {
            TlsDialer::Rustls(_, _) => {}
            #[cfg(feature = "utls")]
            TlsDialer::Utls(_, _) => panic!("unknown profile must not select Utls"),
        }
    }

    #[test]
    fn chrome_without_feature_reports_fallback() {
        let (_, fallback) = build_dialer("chrome", true, AlpnPolicy::H2Then11).unwrap();
        #[cfg(not(feature = "utls"))]
        assert!(fallback);
        #[cfg(feature = "utls")]
        assert!(!fallback);
    }

    #[cfg(feature = "utls")]
    #[test]
    fn chrome_with_feature_selects_utls_variant() {
        let (d, fallback) = build_dialer("chrome", true, AlpnPolicy::H2Then11).unwrap();
        assert!(!fallback);
        match d {
            TlsDialer::Utls(_, _) => {}
            TlsDialer::Rustls(_, _) => panic!("chrome with --features utls must pick Utls"),
        }
    }

    #[test]
    fn alpn_h2_then_11_protos() {
        assert_eq!(
            AlpnPolicy::H2Then11.rustls_protos(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn alpn_http1_only_protos() {
        assert_eq!(
            AlpnPolicy::Http1Only.rustls_protos(),
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn dialed_stream_alpn_getter_round_trips() {
        let (a, _b) = tokio::io::duplex(64);
        let s = DialedStream::new(a, Some(b"h2".to_vec()));
        assert_eq!(s.negotiated_alpn(), Some(b"h2".as_slice()));
    }

    #[test]
    fn dialed_stream_alpn_none_when_unset() {
        let (a, _b) = tokio::io::duplex(64);
        let s = DialedStream::new(a, None);
        assert_eq!(s.negotiated_alpn(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dialed_stream_round_trips_data() {
        // Catches Pin/AsyncRead/AsyncWrite delegation bugs in the
        // boxed-trait-object glue. If poll_read/poll_write don't
        // forward to inner correctly, this hangs or drops bytes.
        let (a, b) = tokio::io::duplex(1024);
        let mut wrapped = DialedStream::new(a, None);
        let mut peer = b;

        let payload = b"hello via dialed stream";
        wrapped.write_all(payload).await.unwrap();
        wrapped.flush().await.unwrap();

        let mut buf = vec![0u8; payload.len()];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);

        // Reverse direction.
        peer.write_all(b"and back").await.unwrap();
        let mut back = [0u8; 8];
        wrapped.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"and back");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rustls_dialer_handshakes_against_local_server() {
        // End-to-end: build a TlsDialer::Rustls, dial a self-signed
        // local rustls server with ALPN=h2, confirm handshake succeeds
        // and negotiated_alpn() reads back what the server picked.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _tls = acceptor.accept(sock).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (dialer, _) = build_dialer("rustls", false, AlpnPolicy::H2Then11).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let stream = dialer.connect("127.0.0.1", tcp).await.unwrap();
        assert_eq!(stream.negotiated_alpn(), Some(b"h2".as_slice()));

        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rustls_dialer_returns_invalid_input_on_bad_sni() {
        // Pin SNI parse-error wrapping: dialer must surface as
        // io::ErrorKind::InvalidInput, not panic. We still need a
        // listener so TcpStream::connect succeeds — the error happens
        // during the handshake setup, before any TLS bytes flow.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let (dialer, _) = build_dialer("rustls", false, AlpnPolicy::Http1Only).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = match dialer.connect("not a valid sni!!", tcp).await {
            Err(e) => e,
            Ok(_) => panic!("malformed SNI must error"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn utls_dialer_handshakes_against_local_h2_server() {
        // Equivalent of rustls_dialer_handshakes_against_local_server
        // but exercising the BoringSSL path. Confirms ALPN selection
        // is extracted correctly from the boring SslStream.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _tls = acceptor.accept(sock).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (dialer, _) = build_dialer("chrome", false, AlpnPolicy::H2Then11).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let stream = dialer.connect("127.0.0.1", tcp).await.unwrap();
        assert_eq!(stream.negotiated_alpn(), Some(b"h2".as_slice()));

        let _ = server.await;
    }

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn utls_dialer_handshakes_against_local_h1_only_server() {
        // BoringSSL ALPN-refused path: server only advertises h1,
        // client requested h2-then-h1, BoringSSL must report
        // selected_alpn_protocol() == "http/1.1".
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _tls = acceptor.accept(sock).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (dialer, _) = build_dialer("chrome", false, AlpnPolicy::H2Then11).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let stream = dialer.connect("127.0.0.1", tcp).await.unwrap();
        assert_eq!(stream.negotiated_alpn(), Some(b"http/1.1".as_slice()));

        let _ = server.await;
    }

    // -- Task #6: build_dialer trim/case tolerance ------------------------

    #[test]
    fn build_dialer_accepts_chrome_case_and_whitespace_variants() {
        // The config layer trims/lowercases before validation, but
        // `build_dialer` is also called from places (tests, future
        // direct callers) that don't go through Config. Pin that the
        // dialer itself tolerates the same input shape. Without this,
        // an upstream refactor that drops one of the two normalisations
        // would let one path accept "  Chrome  " and the other reject.
        for value in ["chrome", "Chrome", "CHROME", "  chrome", "chrome  ", "  CHROME  "] {
            let (dialer, fell_back) = build_dialer(value, true, AlpnPolicy::H2Then11)
                .unwrap_or_else(|e| panic!("variant '{}' must build: {}", value, e));
            #[cfg(feature = "utls")]
            {
                assert!(!fell_back, "variant '{}' must select Utls, not fall back", value);
                assert!(matches!(dialer, TlsDialer::Utls(_, _)));
            }
            #[cfg(not(feature = "utls"))]
            {
                assert!(fell_back, "variant '{}' must report fallback flag", value);
                assert!(matches!(dialer, TlsDialer::Rustls(_, _)));
            }
        }
    }

    #[test]
    fn build_dialer_unknown_value_does_not_match_chrome_loosely() {
        // Adjacent regression: matcher is `eq_ignore_ascii_case` after
        // `trim()`, NOT `contains`. `"chromeish"` must not be treated
        // as chrome.
        for value in ["chromeish", "chrom", "rustls-extra", "ChromeSafari"] {
            let (dialer, fell_back) = build_dialer(value, true, AlpnPolicy::Http1Only).unwrap();
            assert!(
                !fell_back,
                "variant '{}' must not be treated as a recognised non-rustls profile",
                value
            );
            assert!(
                matches!(dialer, TlsDialer::Rustls(_, _)),
                "variant '{}' must default to Rustls",
                value
            );
        }
    }

    // -- Task #7: DialedStream poll_shutdown delegates --------------------

    #[test]
    fn dialed_stream_is_send_and_unpin() {
        // The pool holds these inside `Arc<Mutex<Vec<PoolEntry>>>`,
        // and h2 handshakes spawn tasks that move the stream across
        // threads — so DialedStream must remain Send + Unpin. If a
        // future refactor relaxes the AsyncReadWrite trait bound to
        // drop Send, this test fails to compile, which is the goal.
        fn assert_send<T: Send>() {}
        fn assert_unpin<T: Unpin>() {}
        assert_send::<DialedStream>();
        assert_unpin::<DialedStream>();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dialed_stream_survives_arc_mutex_pool_storage() {
        // Mirror the relay's pool data structure exactly:
        // `Arc<tokio::sync::Mutex<Vec<DialedStream>>>`. A regression
        // that, say, accidentally adds a `!Send` field to DialedStream
        // would break compilation here. Cheap insurance for a hot path.
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let (a, _b) = tokio::io::duplex(64);
        let stream = DialedStream::new(a, Some(b"h2".to_vec()));
        let pool: Arc<Mutex<Vec<DialedStream>>> = Arc::new(Mutex::new(Vec::new()));
        pool.lock().await.push(stream);
        // Spawn requires Send+'static; if DialedStream isn't Send the
        // task move below won't compile.
        let pool2 = pool.clone();
        tokio::spawn(async move {
            let popped = pool2.lock().await.pop();
            assert!(popped.is_some(), "pushed stream must be retrievable");
            assert_eq!(popped.unwrap().negotiated_alpn(), Some(b"h2".as_slice()));
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dialed_stream_poll_shutdown_propagates_to_inner() {
        // If `poll_shutdown` doesn't delegate to the boxed inner
        // stream, the peer never sees EOF and a half-closed read on
        // the other side hangs forever. Cheap regression hook for the
        // boxed-trait-object glue.
        let (a, mut peer) = tokio::io::duplex(64);
        let mut wrapped = DialedStream::new(a, None);
        wrapped.write_all(b"bye").await.unwrap();
        wrapped.shutdown().await.unwrap();

        let mut buf = Vec::new();
        // read_to_end returns once the inner half is closed; if shutdown
        // didn't propagate, this hangs and the test times out.
        peer.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"bye");
    }

    // -- Task #8: bad SNI surfaces FronterError variant cleanly -----------
    //
    // The variant-collapse from `FronterError::Dns(InvalidDnsNameError)`
    // (pre-branch) to `FronterError::Io(InvalidInput)` (post-branch) is
    // a deliberate consequence of folding handshake errors through
    // `io::Error` so the dialer abstraction hides which backend ran.
    // The existing `rustls_dialer_returns_invalid_input_on_bad_sni` test
    // pins the kind. This test pins the message content so callers that
    // grep error strings (logs, user-visible diagnostics) still see
    // "invalid dns name" semantics surfaced through the io error.

    #[tokio::test(flavor = "current_thread")]
    async fn bad_sni_io_error_message_mentions_dns() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let (dialer, _) = build_dialer("rustls", false, AlpnPolicy::Http1Only).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = match dialer.connect("not a valid sni!!", tcp).await {
            Err(e) => e,
            Ok(_) => panic!("malformed SNI must error"),
        };
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("dns") || msg.contains("name") || msg.contains("invalid"),
            "bad-SNI io error must surface dns/name semantics, got: {}",
            err
        );
    }

    // -- Task #5: Chrome ClientHello shape characterization ---------------
    //
    // The whole point of `tls_fingerprint=chrome` is to make the bytes
    // on the wire match what real Chrome would send. Constructing the
    // connector without error proves wiring; only inspecting the actual
    // ClientHello proves shape. This test runs only on `--features utls`
    // because the rustls path doesn't pretend to be Chrome.

    #[cfg(feature = "utls")]
    async fn capture_chrome_client_hello(sni: &str, alpn: AlpnPolicy) -> Vec<u8> {
        use std::time::Duration;
        // Spin a TCP listener, capture the first ClientHello frame, then
        // close — the dialer's handshake will fail (which we ignore), but
        // the bytes we care about have already crossed the socket.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let capture = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            buf.truncate(n);
            drop(sock);
            buf
        });
        let (dialer, _) = build_dialer("chrome", false, alpn).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), dialer.connect(sni, tcp)).await;
        capture.await.unwrap()
    }

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn chrome_clienthello_advertises_chrome_shape() {
        let bytes = capture_chrome_client_hello("example.com", AlpnPolicy::H2Then11).await;
        let hello = parse_client_hello(&bytes).expect("must parse a ClientHello");

        // ALPN extension (type 0x0010) must be present and exactly the
        // h2,http/1.1 vector — anything else means the policy didn't
        // thread through, or BoringSSL silently mutated it.
        let alpn = hello.extension(0x0010).expect("ALPN extension required");
        assert_eq!(
            alpn,
            b"\x00\x0c\x02h2\x08http/1.1",
            "ALPN extension must contain exactly h2,http/1.1 in that order"
        );

        // supported_versions (0x002b) must list TLS 1.3 (0x0304). Real
        // Chrome always advertises TLS 1.3.
        let sv = hello
            .extension(0x002b)
            .expect("supported_versions extension required");
        assert!(
            sv.windows(2).any(|w| w == [0x03, 0x04]),
            "supported_versions must include TLS 1.3 (0x0304); got {:02x?}",
            sv
        );

        // supported_groups (0x000a) must start with X25519 (0x001d), then
        // P-256 (0x0017), then P-384 (0x0018) — Chrome's preference order.
        // The order is part of the JA3 fingerprint.
        let sg = hello
            .extension(0x000a)
            .expect("supported_groups extension required");
        // first 2 bytes are the list length, then 2 bytes per group
        assert!(sg.len() >= 2 + 6, "supported_groups too short: {:?}", sg);
        assert_eq!(&sg[2..4], &[0x00, 0x1d], "first group must be X25519");
        assert_eq!(&sg[4..6], &[0x00, 0x17], "second group must be P-256");
        assert_eq!(&sg[6..8], &[0x00, 0x18], "third group must be P-384");

        // signature_algorithms (0x000d) must start with
        // ecdsa_secp256r1_sha256 (0x0403) — first sigalg in Chrome's list.
        let sa = hello
            .extension(0x000d)
            .expect("signature_algorithms extension required");
        assert!(sa.len() >= 4, "signature_algorithms too short: {:?}", sa);
        assert_eq!(
            &sa[2..4],
            &[0x04, 0x03],
            "first sigalg must be ecdsa_secp256r1_sha256"
        );

        // Cipher-suites: must contain all three TLS 1.3 ciphers BoringSSL
        // hardcodes (0x1301, 0x1302, 0x1303) AND the top TLS 1.2 ECDHE
        // GCM ciphers from the Chrome list (0xc02b, 0xc02f). We don't
        // pin exact order across the whole list because BoringSSL
        // version bumps may shuffle TLS 1.2 entries; we DO pin the
        // TLS 1.3 set since that's the part of the fingerprint that
        // diverges most from a default rustls connector.
        for needle in [
            [0x13u8, 0x01],
            [0x13, 0x02],
            [0x13, 0x03],
            [0xc0, 0x2b],
            [0xc0, 0x2f],
        ] {
            assert!(
                hello
                    .cipher_suites
                    .chunks(2)
                    .any(|c| c == needle),
                "cipher 0x{:02x}{:02x} missing from ClientHello",
                needle[0],
                needle[1]
            );
        }
    }

    // -- Task #13: SNI extension on chrome ClientHello -------------------
    //
    // BoringSSL only sends SNI when `set_use_server_name_indication(true)`
    // is in effect — `UtlsConnector::connect` sets it. If a refactor
    // flips that to false, this test fails: the ClientHello won't carry
    // the SNI extension, the Google edge can't pick the right cert, and
    // every relay request fails with a TLS handshake error. Fast hint
    // for a hard-to-debug regression.

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn chrome_clienthello_carries_sni_extension() {
        let bytes = capture_chrome_client_hello("www.google.com", AlpnPolicy::H2Then11).await;
        let hello = parse_client_hello(&bytes).expect("must parse a ClientHello");

        // server_name extension wire format:
        //   list_length(2) | name_type(1=0x00) | name_length(2) | name
        let sni = hello
            .extension(0x0000)
            .expect("server_name (SNI) extension required");
        assert!(sni.len() >= 5, "SNI extension too short: {:?}", sni);
        assert_eq!(sni[2], 0x00, "SNI name_type must be host_name (0x00)");
        let name_len = u16::from_be_bytes([sni[3], sni[4]]) as usize;
        let name = &sni[5..5 + name_len];
        assert_eq!(
            name, b"www.google.com",
            "SNI hostname mismatch — set_use_server_name_indication likely off"
        );
    }

    // -- Task #14: OCSP status_request on chrome ClientHello -------------
    //
    // `apply_chrome_profile` calls `enable_ocsp_stapling()`. Real Chrome
    // always sends the status_request extension. A future refactor that
    // drops the call would not break any existing test — but JA3/JA4
    // fingerprints would silently diverge. Pin the on-the-wire result.

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn chrome_clienthello_advertises_ocsp_status_request() {
        let bytes = capture_chrome_client_hello("example.com", AlpnPolicy::H2Then11).await;
        let hello = parse_client_hello(&bytes).expect("must parse a ClientHello");

        let sr = hello
            .extension(0x0005)
            .expect("status_request (OCSP) extension required");
        // status_request body: certificate_status_type(1=0x01 ocsp) +
        // responder_id_list_length(2) + responder_id_list +
        // request_extensions_length(2) + request_extensions.
        // Minimum well-formed body = 1 + 2 + 0 + 2 + 0 = 5 bytes.
        assert!(sr.len() >= 5, "status_request too short: {:?}", sr);
        assert_eq!(
            sr[0], 0x01,
            "status_request certificate_status_type must be ocsp (0x01)"
        );
    }

    // -- Task #15: Http1Only ALPN on chrome path -------------------------

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn chrome_clienthello_with_http1_only_alpn() {
        // Pairs with chrome_clienthello_advertises_chrome_shape: when
        // `force_http1=true` threads `AlpnPolicy::Http1Only` to the
        // chrome dialer, the wire-level ALPN extension must drop "h2".
        let bytes = capture_chrome_client_hello("example.com", AlpnPolicy::Http1Only).await;
        let hello = parse_client_hello(&bytes).expect("must parse a ClientHello");

        let alpn = hello.extension(0x0010).expect("ALPN extension required");
        assert_eq!(
            alpn,
            b"\x00\x09\x08http/1.1",
            "Http1Only ALPN must encode http/1.1 as the only entry; got {:02x?}",
            alpn
        );
    }

    /// Minimal TLS 1.x ClientHello parser — just enough to look up
    /// extensions by type and read the cipher-suites list. Not a full
    /// TLS implementation; intentionally fails fast on truncated input
    /// so test failures point at where the parse went off the rails.
    #[cfg(feature = "utls")]
    struct ClientHello<'a> {
        cipher_suites: &'a [u8],
        extensions: &'a [u8],
    }

    #[cfg(feature = "utls")]
    impl<'a> ClientHello<'a> {
        fn extension(&self, ty: u16) -> Option<&'a [u8]> {
            let mut p = self.extensions;
            while p.len() >= 4 {
                let t = u16::from_be_bytes([p[0], p[1]]);
                let len = u16::from_be_bytes([p[2], p[3]]) as usize;
                if p.len() < 4 + len {
                    return None;
                }
                if t == ty {
                    return Some(&p[4..4 + len]);
                }
                p = &p[4 + len..];
            }
            None
        }
    }

    #[cfg(feature = "utls")]
    fn parse_client_hello(buf: &[u8]) -> Option<ClientHello<'_>> {
        // Record layer: type(1) + version(2) + length(2)
        if buf.len() < 5 || buf[0] != 0x16 {
            return None;
        }
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let record = buf.get(5..5 + rec_len)?;
        // Handshake header: type(1) + length(3)
        if record.len() < 4 || record[0] != 0x01 {
            return None;
        }
        let hs_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
        let body = record.get(4..4 + hs_len)?;
        // client_version(2) + random(32) = 34 bytes
        let mut p = body.get(34..)?;
        // session_id
        let sid_len = *p.first()? as usize;
        p = p.get(1 + sid_len..)?;
        // cipher_suites
        if p.len() < 2 {
            return None;
        }
        let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
        let cipher_suites = p.get(2..2 + cs_len)?;
        p = p.get(2 + cs_len..)?;
        // compression_methods
        let cm_len = *p.first()? as usize;
        p = p.get(1 + cm_len..)?;
        // extensions
        if p.len() < 2 {
            return None;
        }
        let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
        let extensions = p.get(2..2 + ext_len)?;
        Some(ClientHello {
            cipher_suites,
            extensions,
        })
    }

    // -- Task #10: verify_ssl=false on chrome path actually skips check ---

    #[cfg(feature = "utls")]
    #[tokio::test(flavor = "current_thread")]
    async fn chrome_dialer_with_verify_true_rejects_self_signed() {
        // Adjacent contract: with verify=true, the chrome dialer MUST
        // reject a self-signed cert. The matching success-path test
        // (`utls_dialer_handshakes_against_local_h2_server`) builds the
        // dialer with verify=false; without this counterpart, a
        // refactor that hard-codes verify=false on the boring path
        // would silently disable cert checking everywhere.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            // The accept will likely fail mid-handshake when the client
            // bails on the bad cert; ignore the result.
            if let Ok((sock, _)) = listener.accept().await {
                let _ = acceptor.accept(sock).await;
            }
        });

        let (dialer, _) = build_dialer("chrome", true, AlpnPolicy::H2Then11).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let result = dialer.connect("127.0.0.1", tcp).await;
        assert!(
            result.is_err(),
            "chrome dialer with verify=true must reject a self-signed cert"
        );
    }
}
