//! Minimal Google Drive REST client for `google_drive` tunnel mode.
//!
//! This intentionally avoids a heavyweight Google SDK. It uses the same
//! domain-fronting shape as the rest of the project: TCP goes to
//! `config.google_ip:443`, TLS SNI is `config.front_domain`, and the HTTP
//! Host header is `www.googleapis.com`.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::config::Config;

const GOOGLE_API_HOST: &str = "www.googleapis.com";
const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid dns name: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("oauth: {0}")]
    OAuth(String),
}

#[derive(Clone)]
struct GoogleApiClient {
    connect_host: String,
    sni: String,
    host_header: String,
    tls_connector: TlsConnector,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl GoogleApiClient {
    fn new(connect_host: String, sni: String, host_header: String, verify_ssl: bool) -> Self {
        let tls_config = if verify_ssl {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };

        Self {
            connect_host,
            sni,
            host_header,
            tls_connector: TlsConnector::from(Arc::new(tls_config)),
        }
    }

    async fn open(&self) -> Result<TlsStream<TcpStream>, DriveError> {
        let tcp = TcpStream::connect(connect_addr(&self.connect_host)).await?;
        let _ = tcp.set_nodelay(true);
        let server_name = ServerName::try_from(self.sni.clone())?;
        Ok(self.tls_connector.connect(server_name, tcp).await?)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> Result<HttpResponse, DriveError> {
        let mut stream = timeout(HTTP_TIMEOUT, self.open())
            .await
            .map_err(|_| DriveError::BadResponse("connect timeout".into()))??;

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: mhrv-rs-drive/{version}\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n",
            method = method,
            path = path,
            host = self.host_header,
            version = env!("CARGO_PKG_VERSION"),
        );
        let mut has_content_length = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            req.push_str(&k);
            req.push_str(": ");
            req.push_str(&v);
            req.push_str("\r\n");
        }
        if !has_content_length && (method == "POST" || method == "PATCH" || method == "PUT") {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await?;

        timeout(HTTP_TIMEOUT, read_http_response(&mut stream))
            .await
            .map_err(|_| DriveError::BadResponse("response timeout".into()))?
    }
}

pub struct GoogleDriveBackend {
    api: GoogleApiClient,
    credentials_path: PathBuf,
    token_path: PathBuf,
    client_id: String,
    client_secret: String,
    auth_uri: String,
    redirect_uri: String,
    folder_id: Mutex<Option<String>>,
    token: Mutex<Option<TokenState>>,
    /// Single-flight guard so concurrent token() callers don't all
    /// stampede the OAuth refresh endpoint after expiry.
    refresh_guard: Mutex<()>,
    file_ids: Mutex<HashMap<String, String>>,
}

#[derive(Clone)]
struct TokenState {
    access_token: String,
    refresh_token: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct OAuthFile {
    installed: Option<OAuthClient>,
    web: Option<OAuthClient>,
}

#[derive(Deserialize)]
struct OAuthClient {
    client_id: String,
    client_secret: String,
    auth_uri: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct TokenCache {
    refresh_token: String,
}

#[derive(Deserialize)]
struct DriveFile {
    id: String,
    name: String,
    /// RFC 3339 timestamp from Drive itself. We use Drive's clock for
    /// staleness checks instead of the timestamp embedded in the
    /// filename, otherwise clock skew between two peers writing into
    /// the same shared folder can cause one side to delete the other's
    /// fresh files (a "5-minute stale" file from a peer 5+ min behind
    /// looks ancient on first poll).
    #[serde(default, rename = "createdTime")]
    created_time: Option<String>,
}

#[derive(Deserialize)]
struct DriveList {
    #[serde(default)]
    files: Vec<DriveFile>,
}

/// What `list_query` hands back. `created_time` is parsed best-effort
/// from Drive's RFC 3339 stamp; on parse failure it's `None` and the
/// caller treats the file as "age unknown".
#[derive(Clone, Debug)]
pub struct DriveFileMeta {
    pub name: String,
    pub created_time: Option<SystemTime>,
}

impl GoogleDriveBackend {
    pub fn from_config(config: &Config) -> Result<Self, DriveError> {
        let credentials_path = PathBuf::from(&config.drive_credentials_path);
        let token_path = config
            .drive_token_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{}.token", config.drive_credentials_path)));
        let data = fs::read_to_string(&credentials_path)?;
        let oauth: OAuthFile = serde_json::from_str(&data)?;
        let client = oauth.installed.or(oauth.web).ok_or_else(|| {
            DriveError::OAuth("credentials JSON has neither installed nor web client".into())
        })?;
        let redirect_uri = client
            .redirect_uris
            .first()
            .cloned()
            .unwrap_or_else(|| "http://localhost".into());
        let folder_id = if config.drive_folder_id.trim().is_empty() {
            None
        } else {
            Some(config.drive_folder_id.trim().to_string())
        };

        Ok(Self {
            api: GoogleApiClient::new(
                config.google_ip.clone(),
                config.front_domain.clone(),
                GOOGLE_API_HOST.into(),
                config.verify_ssl,
            ),
            credentials_path,
            token_path,
            client_id: client.client_id,
            client_secret: client.client_secret,
            auth_uri: client.auth_uri,
            redirect_uri,
            folder_id: Mutex::new(folder_id),
            token: Mutex::new(None),
            refresh_guard: Mutex::new(()),
            file_ids: Mutex::new(HashMap::new()),
        })
    }

    /// Best-effort login: try cached refresh token, otherwise fall through
    /// to the (CLI-only) interactive prompt. UIs should call
    /// [`try_login_with_cached_token`] first and, if it errors with
    /// [`DriveError::NeedsOAuth`], drive the [`auth_url`] / [`apply_auth_code`]
    /// pair from their own widget instead.
    pub async fn login(&self) -> Result<(), DriveError> {
        if self.try_login_with_cached_token().await? {
            return Ok(());
        }
        self.interactive_login().await
    }

    /// Returns `Ok(true)` if a cached refresh token was found and an access
    /// token was successfully minted from it; `Ok(false)` if no cached token
    /// exists at all. Errors propagate transport / OAuth failures.
    pub async fn try_login_with_cached_token(&self) -> Result<bool, DriveError> {
        let Ok(data) = fs::read_to_string(&self.token_path) else {
            return Ok(false);
        };
        let Ok(cache) = serde_json::from_str::<TokenCache>(&data) else {
            return Ok(false);
        };
        if cache.refresh_token.is_empty() {
            return Ok(false);
        }
        *self.token.lock().await = Some(TokenState {
            access_token: String::new(),
            refresh_token: cache.refresh_token,
            expires_at: Instant::now(),
        });
        self.refresh_access_token().await?;
        Ok(true)
    }

    /// Build the authorization URL. UIs show this to the user (clickable
    /// link or QR code) and then ask them to paste the redirect URL or
    /// raw code into a text field — which they hand back to
    /// [`apply_auth_code`].
    pub fn auth_url(&self) -> String {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        ser.append_pair("client_id", &self.client_id);
        ser.append_pair("redirect_uri", &self.redirect_uri);
        ser.append_pair("response_type", "code");
        ser.append_pair("scope", DRIVE_SCOPE);
        ser.append_pair("access_type", "offline");
        ser.append_pair("prompt", "consent");
        format!("{}?{}", self.auth_uri, ser.finish())
    }

    /// Accept either a raw authorization code or the full redirect URL
    /// (`http(s)://.../?code=…`). Exchanges it for tokens, persists the
    /// refresh token to disk (chmod 0600 on Unix), and leaves the in-memory
    /// state ready for API calls. Idempotent — safe to call multiple times
    /// with fresh codes.
    pub async fn apply_auth_code(&self, raw: &str) -> Result<(), DriveError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DriveError::OAuth("empty authorization code".into()));
        }
        let code = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let parsed = url::Url::parse(trimmed)
                .map_err(|e| DriveError::OAuth(format!("bad redirect URL: {}", e)))?;
            parsed
                .query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.into_owned())
                .ok_or_else(|| DriveError::OAuth("redirect URL did not contain a code".into()))?
        } else {
            trimmed.to_string()
        };
        if code.is_empty() {
            return Err(DriveError::OAuth("empty authorization code".into()));
        }

        self.exchange_code(&code).await?;
        let refresh_token = self
            .token
            .lock()
            .await
            .as_ref()
            .map(|t| t.refresh_token.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DriveError::OAuth("Google did not return a refresh token".into()))?;
        let cache = serde_json::to_vec_pretty(&TokenCache { refresh_token })?;
        write_secret_file(&self.token_path, &cache)?;
        Ok(())
    }

    /// Whether a refresh token is already cached on disk for this
    /// credentials JSON. Cheap — does no network I/O. UIs use this to
    /// decide whether to show the "Authorize" dialog at all.
    pub fn has_cached_token(&self) -> bool {
        let Ok(data) = fs::read_to_string(&self.token_path) else {
            return false;
        };
        serde_json::from_str::<TokenCache>(&data)
            .map(|c| !c.refresh_token.is_empty())
            .unwrap_or(false)
    }

    /// Path to where the cached refresh token will be written by
    /// [`apply_auth_code`]. Surfaced for UIs that want to display it.
    pub fn token_path(&self) -> &PathBuf {
        &self.token_path
    }

    async fn interactive_login(&self) -> Result<(), DriveError> {
        let auth_url = self.auth_url();

        println!();
        println!("==================== GOOGLE DRIVE OAUTH REQUIRED ====================");
        println!("1. Open this URL in your browser:\n");
        println!("{}", auth_url);
        println!("\n2. Approve access, then paste the full redirected URL or just the code.");
        print!("\nEnter URL or code: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        self.apply_auth_code(&input).await?;
        println!("Saved Drive OAuth token to {}", self.token_path.display());
        println!("=====================================================================");
        println!();
        Ok(())
    }

    async fn exchange_code(&self, code: &str) -> Result<(), DriveError> {
        let body = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("grant_type", "authorization_code");
            ser.append_pair("code", code);
            ser.append_pair("client_id", &self.client_id);
            ser.append_pair("client_secret", &self.client_secret);
            ser.append_pair("redirect_uri", &self.redirect_uri);
            ser.finish().into_bytes()
        };
        let response = self.execute_token_request(body).await?;
        self.apply_token_response(response, None).await;
        Ok(())
    }

    async fn refresh_access_token(&self) -> Result<(), DriveError> {
        let refresh_token = self
            .token
            .lock()
            .await
            .as_ref()
            .map(|t| t.refresh_token.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DriveError::OAuth("no refresh token cached".into()))?;

        let body = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("grant_type", "refresh_token");
            ser.append_pair("refresh_token", &refresh_token);
            ser.append_pair("client_id", &self.client_id);
            ser.append_pair("client_secret", &self.client_secret);
            ser.finish().into_bytes()
        };
        let response = self.execute_token_request(body).await?;
        self.apply_token_response(response, Some(refresh_token))
            .await;
        Ok(())
    }

    async fn execute_token_request(&self, body: Vec<u8>) -> Result<TokenResponse, DriveError> {
        let resp = self
            .api
            .request(
                "POST",
                "/oauth2/v4/token",
                vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                &body,
            )
            .await?;
        if resp.status != 200 {
            return Err(http_error(resp));
        }
        Ok(serde_json::from_slice(&resp.body)?)
    }

    async fn apply_token_response(
        &self,
        response: TokenResponse,
        fallback_refresh: Option<String>,
    ) {
        let refresh_token = response
            .refresh_token
            .or(fallback_refresh)
            .unwrap_or_default();
        // Use the token for at most `expires_in - 60s` so we refresh
        // ahead of expiry. If the server returned an unusually short
        // lifetime (or none at all), fall back to a small floor rather
        // than over-claiming validity.
        let raw = response.expires_in.unwrap_or(3600);
        let expires = if raw > 90 { raw - 60 } else { raw / 2 + 1 };
        *self.token.lock().await = Some(TokenState {
            access_token: response.access_token,
            refresh_token,
            expires_at: Instant::now() + Duration::from_secs(expires),
        });
    }

    async fn token(&self) -> Result<String, DriveError> {
        if let Some(tok) = self.live_token().await {
            return Ok(tok);
        }
        // Single-flight: if another caller is already refreshing, wait
        // for it to finish and use the freshly-set token instead of
        // hitting /oauth2/v4/token a second time.
        let _refresh = self.refresh_guard.lock().await;
        if let Some(tok) = self.live_token().await {
            return Ok(tok);
        }
        self.refresh_access_token().await?;
        self.live_token()
            .await
            .ok_or_else(|| DriveError::OAuth("token refresh returned no access token".into()))
    }

    async fn live_token(&self) -> Option<String> {
        let guard = self.token.lock().await;
        let token = guard.as_ref()?;
        if token.access_token.is_empty() || Instant::now() >= token.expires_at {
            return None;
        }
        Some(token.access_token.clone())
    }

    pub async fn ensure_folder(&self, name: &str) -> Result<String, DriveError> {
        if let Some(id) = self.folder_id.lock().await.clone() {
            return Ok(id);
        }
        if let Some(id) = self.find_folder(name).await? {
            *self.folder_id.lock().await = Some(id.clone());
            tracing::info!("Drive folder '{}' found: {}", name, id);
            return Ok(id);
        }
        let id = self.create_folder(name).await?;
        *self.folder_id.lock().await = Some(id.clone());
        tracing::info!("Drive folder '{}' created: {}", name, id);
        Ok(id)
    }

    pub async fn upload(&self, filename: &str, data: Vec<u8>) -> Result<(), DriveError> {
        let token = self.token().await?;
        let folder_id = self.folder_id.lock().await.clone();
        let boundary = format!("mhrv{}", random_hex(12));
        let meta = if let Some(folder_id) = folder_id {
            json!({ "name": filename, "parents": [folder_id] })
        } else {
            json!({ "name": filename })
        };

        let mut body = Vec::with_capacity(data.len() + 512);
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(serde_json::to_string(&meta)?.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let resp = self
            .api
            .request(
                "POST",
                "/upload/drive/v3/files?uploadType=multipart",
                vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    (
                        "Content-Type".into(),
                        format!("multipart/related; boundary={}", boundary),
                    ),
                ],
                &body,
            )
            .await?;
        if resp.status != 200 && resp.status != 201 {
            return Err(http_error(resp));
        }
        Ok(())
    }

    pub async fn list_query(&self, prefix: &str) -> Result<Vec<DriveFileMeta>, DriveError> {
        let token = self.token().await?;
        let mut q = format!(
            "name contains '{}' and trashed = false",
            drive_query_quote(prefix)
        );
        if let Some(folder_id) = self.folder_id.lock().await.clone() {
            q.push_str(&format!(
                " and '{}' in parents",
                drive_query_quote(&folder_id)
            ));
        }
        let path = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("q", &q);
            ser.append_pair("fields", "files(id,name,createdTime)");
            ser.append_pair("pageSize", "1000");
            format!("/drive/v3/files?{}", ser.finish())
        };

        let resp = self
            .api
            .request(
                "GET",
                &path,
                vec![("Authorization".into(), format!("Bearer {}", token))],
                &[],
            )
            .await?;
        if resp.status != 200 {
            return Err(http_error(resp));
        }

        let parsed: DriveList = serde_json::from_slice(&resp.body)?;
        let mut metas = Vec::new();
        let mut ids = self.file_ids.lock().await;
        if ids.len() > 2000 {
            ids.clear();
        }
        for file in parsed.files {
            if file.name.starts_with(prefix) {
                ids.insert(file.name.clone(), file.id);
                let created_time = file.created_time.as_deref().and_then(parse_rfc3339);
                metas.push(DriveFileMeta {
                    name: file.name,
                    created_time,
                });
            }
        }
        Ok(metas)
    }

    pub async fn download(&self, filename: &str) -> Result<Vec<u8>, DriveError> {
        let file_id = match self.file_ids.lock().await.get(filename).cloned() {
            Some(id) => id,
            None => {
                let _ = self.list_query(filename).await?;
                self.file_ids
                    .lock()
                    .await
                    .get(filename)
                    .cloned()
                    .ok_or_else(|| {
                        DriveError::BadResponse(format!("Drive file id not found for {}", filename))
                    })?
            }
        };
        let token = self.token().await?;
        let path = format!("/drive/v3/files/{}?alt=media", url_path_escape(&file_id));
        let resp = self
            .api
            .request(
                "GET",
                &path,
                vec![("Authorization".into(), format!("Bearer {}", token))],
                &[],
            )
            .await?;
        if resp.status != 200 {
            return Err(http_error(resp));
        }
        Ok(resp.body)
    }

    pub async fn delete(&self, filename: &str) -> Result<(), DriveError> {
        let Some(file_id) = self.file_ids.lock().await.get(filename).cloned() else {
            return Ok(());
        };
        let token = self.token().await?;
        let path = format!("/drive/v3/files/{}", url_path_escape(&file_id));
        let resp = self
            .api
            .request(
                "DELETE",
                &path,
                vec![("Authorization".into(), format!("Bearer {}", token))],
                &[],
            )
            .await?;
        if resp.status != 204 && resp.status != 200 && resp.status != 404 {
            return Err(http_error(resp));
        }
        self.file_ids.lock().await.remove(filename);
        Ok(())
    }

    async fn create_folder(&self, name: &str) -> Result<String, DriveError> {
        let token = self.token().await?;
        let body = serde_json::to_vec(&json!({
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
        }))?;
        let resp = self
            .api
            .request(
                "POST",
                "/drive/v3/files",
                vec![
                    ("Authorization".into(), format!("Bearer {}", token)),
                    ("Content-Type".into(), "application/json".into()),
                ],
                &body,
            )
            .await?;
        if resp.status != 200 && resp.status != 201 {
            return Err(http_error(resp));
        }
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        Ok(serde_json::from_slice::<Created>(&resp.body)?.id)
    }

    async fn find_folder(&self, name: &str) -> Result<Option<String>, DriveError> {
        let token = self.token().await?;
        let q = format!(
            "name = '{}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
            drive_query_quote(name)
        );
        let path = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("q", &q);
            ser.append_pair("fields", "files(id,name)");
            ser.append_pair("pageSize", "10");
            format!("/drive/v3/files?{}", ser.finish())
        };
        let resp = self
            .api
            .request(
                "GET",
                &path,
                vec![("Authorization".into(), format!("Bearer {}", token))],
                &[],
            )
            .await?;
        if resp.status != 200 {
            return Err(http_error(resp));
        }
        let parsed: DriveList = serde_json::from_slice(&resp.body)?;
        Ok(parsed.files.into_iter().next().map(|f| f.id))
    }

    pub fn credentials_path(&self) -> &PathBuf {
        &self.credentials_path
    }
}

fn http_error(resp: HttpResponse) -> DriveError {
    DriveError::Http {
        status: resp.status,
        body: String::from_utf8_lossy(&resp.body)
            .chars()
            .take(500)
            .collect(),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn connect_addr(host: &str) -> String {
    if host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .is_some()
    {
        host.to_string()
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:443", host)
    } else {
        format!("{}:443", host)
    }
}

fn drive_query_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Parse a Drive `createdTime` (RFC 3339, always UTC `Z`) into a
/// `SystemTime`. Returns `None` for any oddity rather than panicking;
/// the caller treats unparseable timestamps as "age unknown" and skips
/// the staleness check rather than risking a wrong delete.
fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    // Expected: 2024-05-13T07:21:34.512Z (fractional seconds optional).
    let bytes = s.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if !s.ends_with('Z') {
        return None;
    }
    let year: i64 = s.get(..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }
    // Howard Hinnant's days_from_civil. Treats March as month 1, so
    // Jan/Feb roll back into the previous year. Valid for any year.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m_index = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m_index + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hour * 3600 + minute * 60 + second;
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Percent-encode for use inside a URL path component. `form_urlencoded`
/// would map space to `+` (which is wrong inside a path), so we hand-roll
/// per RFC 3986: keep unreserved chars, percent-encode the rest. Drive
/// file IDs only contain `[A-Za-z0-9_-]` in practice but a stricter
/// encoder costs nothing and keeps us safe if Google ever widens that.
fn url_path_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Write data and try to set 0600 on Unix so the OAuth refresh token isn't
/// world-readable. Best-effort: a permission failure after the write is
/// logged but doesn't fail the call.
fn write_secret_file(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            if let Err(e) = fs::set_permissions(path, perms) {
                tracing::warn!(
                    "could not chmod 0600 on {}: {} (refresh token may be world-readable)",
                    path.display(),
                    e
                );
            }
        }
    }
    Ok(())
}

async fn read_http_response<S>(stream: &mut S) -> Result<HttpResponse, DriveError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(DriveError::BadResponse(
                "connection closed before headers".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return Err(DriveError::BadResponse("headers too large".into()));
        }
    };

    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| DriveError::BadResponse("non-utf8 headers".into()))?;
    let mut lines = header_text.split("\r\n");
    let status = parse_status_line(lines.next().unwrap_or(""))?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    let content_length = header_get(&headers, "content-length").and_then(|v| v.parse().ok());
    let is_chunked = header_get(&headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if is_chunked {
        body = read_chunked(stream, body).await?;
    } else if let Some(len) = content_length {
        while body.len() < len {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(DriveError::BadResponse(
                    "connection closed before full body".into(),
                ));
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(len);
    } else {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
    }

    if header_get(&headers, "content-encoding")
        .map(|v| v.eq_ignore_ascii_case("gzip"))
        .unwrap_or(false)
    {
        body = decode_gzip(&body)?;
    }

    Ok(HttpResponse { status, body })
}

async fn read_chunked<S>(stream: &mut S, mut buf: Vec<u8>) -> Result<Vec<u8>, DriveError>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let line = read_crlf_line(stream, &mut buf, &mut tmp).await?;
        let line = std::str::from_utf8(&line)
            .map_err(|_| DriveError::BadResponse("bad chunk header".into()))?
            .trim();
        if line.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(line.split(';').next().unwrap_or(""), 16)
            .map_err(|_| DriveError::BadResponse(format!("bad chunk size '{}'", line)))?;
        if size == 0 {
            loop {
                if read_crlf_line(stream, &mut buf, &mut tmp).await?.is_empty() {
                    return Ok(out);
                }
            }
        }
        while buf.len() < size + 2 {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(DriveError::BadResponse(
                    "connection closed mid-chunk".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(DriveError::BadResponse(
                "chunk missing trailing CRLF".into(),
            ));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<Vec<u8>, DriveError>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..pos].to_vec();
            buf.drain(..pos + 2);
            return Ok(line);
        }
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(DriveError::BadResponse("connection closed mid-line".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, DriveError> {
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| DriveError::BadResponse(format!("bad status line: {}", line)))?;
    code.parse::<u16>()
        .map_err(|_| DriveError::BadResponse(format!("bad status code: {}", code)))
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::with_capacity(data.len() * 2);
    flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn url_path_escape_keeps_unreserved_and_encodes_specials() {
        assert_eq!(url_path_escape("AbC-_.~123"), "AbC-_.~123");
        assert_eq!(url_path_escape("hello world"), "hello%20world");
        assert_eq!(url_path_escape("a+b/c?d"), "a%2Bb%2Fc%3Fd");
    }

    #[test]
    fn parse_rfc3339_handles_drive_timestamps() {
        // Drive returns timestamps with millisecond fractional precision
        // and always-Z UTC offset; our parser ignores the fraction and
        // produces a SystemTime relative to the unix epoch.
        let ts = parse_rfc3339("2024-05-13T07:21:34.512Z").unwrap();
        let secs = ts.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 2024-05-13T07:21:34Z = 1715584894s since the epoch.
        assert_eq!(secs, 1715584894);
        // Sub-second component is intentionally truncated.
        let ts_no_frac = parse_rfc3339("2024-05-13T07:21:34Z").unwrap();
        assert_eq!(ts, ts_no_frac);
        // Junk and non-Z offsets are rejected (we don't risk getting
        // tz math wrong for a stale-file decision).
        assert!(parse_rfc3339("not a date").is_none());
        assert!(parse_rfc3339("2024-05-13T07:21:34+02:00").is_none());
    }

    #[tokio::test]
    async fn read_http_response_decodes_chunked_body() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        let body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        w.write_all(body).await.unwrap();
        drop(w);
        let resp = read_http_response(&mut r).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body, b"hello world");
    }

    #[tokio::test]
    async fn read_http_response_decodes_content_length_body() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        let body = b"HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nbody";
        w.write_all(body).await.unwrap();
        drop(w);
        let resp = read_http_response(&mut r).await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(&resp.body, b"body");
    }
}
