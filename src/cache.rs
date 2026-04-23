use std::collections::{HashMap, VecDeque};
// AtomicU64 polyfill via portable-atomic — mipsel is MIPS32 with no
// native 64-bit atomic instructions, so std::sync::atomic::AtomicU64
// doesn't exist on that target. portable-atomic falls back to a
// global spinlock on 32-bit MIPS; compiles to native insns on x86_64
// and aarch64.
use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024;
const MAX_ENTRY_FRACTION: usize = 4;

pub struct ResponseCache {
    inner: Mutex<Inner>,
    max_bytes: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

struct Inner {
    entries: HashMap<String, CachedResponse>,
    order: VecDeque<String>,
    size: usize,
}

struct CachedResponse {
    bytes: Vec<u8>,
    expires: Instant,
}

impl ResponseCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                order: VecDeque::new(),
                size: 0,
            }),
            max_bytes,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn with_default() -> Self {
        Self::new(DEFAULT_MAX_BYTES)
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get(key) {
            if entry.expires > now {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.bytes.clone());
            }
            let size = entry.bytes.len();
            inner.entries.remove(key);
            inner.order.retain(|k| k != key);
            inner.size = inner.size.saturating_sub(size);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn put(&self, key: String, bytes: Vec<u8>, ttl: Duration) {
        let size = bytes.len();
        if size == 0 || size > self.max_bytes / MAX_ENTRY_FRACTION {
            return;
        }
        let expires = Instant::now() + ttl;
        let mut inner = self.inner.lock().unwrap();

        if let Some(old) = inner.entries.remove(&key) {
            inner.size = inner.size.saturating_sub(old.bytes.len());
            inner.order.retain(|k| k != &key);
        }

        while inner.size + size > self.max_bytes {
            let Some(oldest_key) = inner.order.pop_front() else {
                break;
            };
            if let Some(removed) = inner.entries.remove(&oldest_key) {
                inner.size = inner.size.saturating_sub(removed.bytes.len());
            }
        }

        inner.entries.insert(key.clone(), CachedResponse { bytes, expires });
        inner.order.push_back(key);
        inner.size += size;
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size
    }
}

pub fn parse_ttl(raw_response: &[u8], url: &str) -> Option<Duration> {
    let sep = b"\r\n\r\n";
    let hdr_end = raw_response
        .windows(sep.len())
        .position(|w| w == sep)?;
    let hdr = std::str::from_utf8(&raw_response[..hdr_end]).ok()?;
    let hdr_lower = hdr.to_ascii_lowercase();

    let first_line = hdr_lower.lines().next()?;
    if !first_line.starts_with("http/1.1 200") && !first_line.starts_with("http/1.0 200") {
        return None;
    }
    if hdr_lower.contains("no-store") || hdr_lower.contains("no-cache") || hdr_lower.contains("private") {
        return None;
    }
    if hdr_lower.contains("set-cookie:") {
        return None;
    }

    if let Some(pos) = hdr_lower.find("max-age=") {
        let rest = &hdr_lower[pos + 8..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if let Ok(secs) = rest[..end].parse::<u64>() {
            if secs == 0 {
                return None;
            }
            return Some(Duration::from_secs(secs.min(86400)));
        }
    }

    let path_no_query = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    const STATIC_EXTS: &[&str] = &[
        ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif",
        ".mp3", ".mp4", ".wasm", ".webm", ".ogg",
    ];
    for ext in STATIC_EXTS {
        if path_no_query.ends_with(ext) {
            return Some(Duration::from_secs(3600));
        }
    }

    let ct_key = "content-type:";
    if let Some(pos) = hdr_lower.find(ct_key) {
        let rest = &hdr_lower[pos + ct_key.len()..];
        let line_end = rest.find('\r').unwrap_or(rest.len());
        let ct = &rest[..line_end];
        if ct.contains("image/") || ct.contains("font/") {
            return Some(Duration::from_secs(3600));
        }
        if ct.contains("text/css") || ct.contains("javascript") || ct.contains("application/wasm") {
            return Some(Duration::from_secs(1800));
        }
    }

    None
}

pub fn is_cacheable_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD"
    )
}

pub fn cache_key(method: &str, url: &str) -> String {
    format!("{}:{}", method.to_ascii_uppercase(), url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_resp(headers: &str, body: &str) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(headers.as_bytes());
        r.extend_from_slice(b"\r\n\r\n");
        r.extend_from_slice(body.as_bytes());
        r
    }

    #[test]
    fn get_miss_then_put_then_hit() {
        let c = ResponseCache::new(1024);
        assert!(c.get("k").is_none());
        c.put("k".into(), b"hello".to_vec(), Duration::from_secs(60));
        assert_eq!(c.get("k").unwrap(), b"hello");
        assert_eq!(c.hits(), 1);
        assert_eq!(c.misses(), 1);
    }

    #[test]
    fn expired_entry_is_removed_on_get() {
        let c = ResponseCache::new(1024);
        c.put("k".into(), b"hi".to_vec(), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(c.get("k").is_none());
        assert_eq!(c.size(), 0);
    }

    #[test]
    fn too_large_entry_rejected() {
        let c = ResponseCache::new(100);
        c.put("k".into(), vec![0u8; 60], Duration::from_secs(60));
        assert!(c.get("k").is_none());
    }

    #[test]
    fn fifo_eviction_when_full() {
        let c = ResponseCache::new(1000);
        c.put("a".into(), vec![0u8; 200], Duration::from_secs(60));
        c.put("b".into(), vec![0u8; 200], Duration::from_secs(60));
        c.put("c".into(), vec![0u8; 200], Duration::from_secs(60));
        c.put("d".into(), vec![0u8; 200], Duration::from_secs(60));
        c.put("e".into(), vec![0u8; 200], Duration::from_secs(60));
        c.put("f".into(), vec![0u8; 200], Duration::from_secs(60));
        assert!(c.get("a").is_none());
        assert!(c.get("f").is_some());
    }

    #[test]
    fn max_age_parsed() {
        let raw = mk_resp(
            "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=300\r\nContent-Type: text/html",
            "body",
        );
        let ttl = parse_ttl(&raw, "http://example.com/page").unwrap();
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn no_store_rejects_cache() {
        let raw = mk_resp(
            "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Type: text/css",
            "body",
        );
        assert!(parse_ttl(&raw, "http://x.com/a.css").is_none());
    }

    #[test]
    fn static_extension_heuristic() {
        let raw = mk_resp("HTTP/1.1 200 OK\r\nContent-Type: text/css", "body");
        let ttl = parse_ttl(&raw, "http://x.com/style.css").unwrap();
        assert_eq!(ttl, Duration::from_secs(3600));
    }

    #[test]
    fn set_cookie_rejects_cache() {
        let raw = mk_resp(
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nCache-Control: max-age=600",
            "body",
        );
        assert!(parse_ttl(&raw, "http://x.com/page").is_none());
    }

    #[test]
    fn non_200_rejected() {
        let raw = mk_resp("HTTP/1.1 404 Not Found\r\nCache-Control: max-age=600", "body");
        assert!(parse_ttl(&raw, "http://x.com/page").is_none());
    }

    #[test]
    fn method_check() {
        assert!(is_cacheable_method("GET"));
        assert!(is_cacheable_method("get"));
        assert!(is_cacheable_method("HEAD"));
        assert!(!is_cacheable_method("POST"));
        assert!(!is_cacheable_method("DELETE"));
    }
}
