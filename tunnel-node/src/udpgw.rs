//! Native implementation of the tun2proxy udpgw wire protocol.
//!
//! Wire format (all fields big-endian):
//! ```text
//! +-----+-------+---------+------+----------+----------+----------+
//! | LEN | FLAGS | CONN_ID | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +-----+-------+---------+------+----------+----------+----------+
//! |  2  |   1   |    2    |  1   | Variable |    2     | Variable |
//! +-----+-------+---------+------+----------+----------+----------+
//! ```
//!
//! Flags: KEEPALIVE=0x01, DATA=0x02, ERR=0x20
//! ATYP: 0x01=IPv4(4B), 0x03=Domain(1B len + name), 0x04=IPv6(16B)

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;

/// Magic address that the client connects to via the tunnel protocol.
/// `198.18.0.0/15` is reserved for benchmarking (RFC 2544) and will
/// never be a real destination.
pub const UDPGW_MAGIC_IP: [u8; 4] = [198, 18, 0, 1];
pub const UDPGW_MAGIC_PORT: u16 = 7300;

const FLAG_KEEPALIVE: u8 = 0x01;
const FLAG_DATA: u8 = 0x02;
const FLAG_ERR: u8 = 0x20;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Maximum UDP payload we'll handle.
const UDP_MTU: usize = 10240;

// -------------------------------------------------------------------------
// Frame types
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum DstAddr {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl DstAddr {
    fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            DstAddr::V4(ip, port) => Ok(SocketAddr::V4(SocketAddrV4::new(*ip, *port))),
            DstAddr::V6(ip, port) => Ok(SocketAddr::V6(SocketAddrV6::new(*ip, *port, 0, 0))),
            DstAddr::Domain(name, port) => {
                use std::net::ToSocketAddrs;
                (name.as_str(), *port)
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "DNS resolution failed"))
            }
        }
    }

    /// Serialise into SOCKS5 address format: ATYP + addr + port.
    fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            DstAddr::V4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            DstAddr::V6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            DstAddr::Domain(name, port) => {
                buf.push(ATYP_DOMAIN);
                buf.push(name.len() as u8);
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    fn serialised_len(&self) -> usize {
        match self {
            DstAddr::V4(..) => 1 + 4 + 2,       // ATYP + IPv4 + port
            DstAddr::V6(..) => 1 + 16 + 2,       // ATYP + IPv6 + port
            DstAddr::Domain(n, _) => 1 + 1 + n.len() + 2, // ATYP + len + name + port
        }
    }
}

#[derive(Debug)]
struct Frame {
    flags: u8,
    conn_id: u16,
    addr: Option<DstAddr>,
    payload: Vec<u8>,
}

// -------------------------------------------------------------------------
// Parse / serialise
// -------------------------------------------------------------------------

/// Try to parse one frame from `buf`. Returns `(frame, bytes_consumed)` or
/// `None` if the buffer doesn't contain a complete frame yet.
fn try_parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, std::io::Error> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let body_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = 2 + body_len;
    if buf.len() < total {
        return Ok(None);
    }

    let body = &buf[2..total];
    if body.len() < 3 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too short"));
    }
    let flags = body[0];
    let conn_id = u16::from_be_bytes([body[1], body[2]]);
    let rest = &body[3..];

    let (addr, payload_start) = if flags & FLAG_DATA != 0 {
        // Parse SOCKS5-style address.
        if rest.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing ATYP"));
        }
        let atyp = rest[0];
        match atyp {
            ATYP_IPV4 => {
                if rest.len() < 1 + 4 + 2 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short IPv4 addr"));
                }
                let ip = Ipv4Addr::new(rest[1], rest[2], rest[3], rest[4]);
                let port = u16::from_be_bytes([rest[5], rest[6]]);
                (Some(DstAddr::V4(ip, port)), 7)
            }
            ATYP_IPV6 => {
                if rest.len() < 1 + 16 + 2 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short IPv6 addr"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rest[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([rest[17], rest[18]]);
                (Some(DstAddr::V6(ip, port)), 19)
            }
            ATYP_DOMAIN => {
                if rest.len() < 2 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short domain addr"));
                }
                let dlen = rest[1] as usize;
                if rest.len() < 2 + dlen + 2 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short domain addr"));
                }
                let name = String::from_utf8_lossy(&rest[2..2 + dlen]).into_owned();
                let port = u16::from_be_bytes([rest[2 + dlen], rest[3 + dlen]]);
                (Some(DstAddr::Domain(name, port)), 2 + dlen + 2)
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unknown ATYP 0x{:02x}", atyp)));
            }
        }
    } else {
        (None, 0)
    };

    let payload = rest[payload_start..].to_vec();

    Ok(Some((Frame { flags, conn_id, addr, payload }, total)))
}

fn serialise_frame(frame: &Frame) -> Vec<u8> {
    // Body = flags(1) + conn_id(2) + [addr] + payload
    let addr_len = frame.addr.as_ref().map_or(0, |a| a.serialised_len());
    let body_len = 1 + 2 + addr_len + frame.payload.len();

    let mut buf = Vec::with_capacity(2 + body_len);
    buf.extend_from_slice(&(body_len as u16).to_be_bytes());
    buf.push(frame.flags);
    buf.extend_from_slice(&frame.conn_id.to_be_bytes());
    if let Some(ref addr) = frame.addr {
        addr.write_to(&mut buf);
    }
    buf.extend_from_slice(&frame.payload);
    buf
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// Returns `true` if the connect destination is the magic udpgw address.
pub fn is_udpgw_dest(host: &str, port: u16) -> bool {
    port == UDPGW_MAGIC_PORT && host == format!("{}.{}.{}.{}", UDPGW_MAGIC_IP[0], UDPGW_MAGIC_IP[1], UDPGW_MAGIC_IP[2], UDPGW_MAGIC_IP[3])
}

/// Per-conn_id persistent UDP socket with a background reader that
/// continuously receives datagrams and queues response frames.
struct ConnSocket {
    sock: Arc<UdpSocket>,
    _reader: tokio::task::JoinHandle<()>,
}

/// Run the udpgw server over a duplex stream. Reads udpgw frames from the
/// client half, sends real UDP datagrams, and writes response frames back.
/// Maintains persistent sockets per conn_id so Telegram VoIP (which expects
/// a stable source port) works correctly.
pub async fn udpgw_server_task(stream: DuplexStream) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Writer task: drains response channel → duplex stream.
    let mut read_half = {
        let (read_half, write_half) = tokio::io::split(stream);
        tokio::spawn(async move {
            let mut w = write_half;
            while let Some(data) = rx.recv().await {
                if w.write_all(&data).await.is_err() {
                    break;
                }
                let _ = w.flush().await;
            }
        });
        read_half
    };

    // Persistent sockets keyed by (conn_id, dest_addr).
    let mut sockets: std::collections::HashMap<(u16, SocketAddr), ConnSocket> = std::collections::HashMap::new();

    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 65536];

    loop {
        let n = match read_half.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);

        loop {
            match try_parse_frame(&buf) {
                Ok(Some((frame, consumed))) => {
                    buf.drain(..consumed);
                    handle_frame(&frame, &tx, &mut sockets).await;
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("udpgw frame parse error: {}", e);
                    if buf.len() >= 2 {
                        let skip = 2 + u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        buf.drain(..skip.min(buf.len()));
                    } else {
                        buf.clear();
                    }
                    break;
                }
            }
        }
    }

    // Abort all reader tasks on shutdown.
    for (_, cs) in sockets {
        cs._reader.abort();
    }
    tracing::debug!("udpgw session ended");
}

/// Get or create a persistent UDP socket for this (conn_id, dest_addr) pair.
/// A background reader task continuously receives datagrams and queues
/// response frames — no per-packet timeout needed.
async fn get_or_create_socket(
    conn_id: u16,
    dst: &SocketAddr,
    addr: &DstAddr,
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    sockets: &mut std::collections::HashMap<(u16, SocketAddr), ConnSocket>,
) -> Option<Arc<UdpSocket>> {
    let key = (conn_id, *dst);
    if let Some(cs) = sockets.get(&key) {
        return Some(cs.sock.clone());
    }

    let bind_addr: SocketAddr = if dst.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::debug!("udpgw bind failed: {}", e);
            return None;
        }
    };
    if let Err(e) = sock.connect(dst).await {
        tracing::debug!("udpgw connect {} failed: {}", dst, e);
        return None;
    }

    // Spawn continuous reader for this socket.
    let sock_clone = sock.clone();
    let tx_clone = tx.clone();
    let addr_clone = addr.clone();
    let reader = tokio::spawn(async move {
        let mut recv_buf = vec![0u8; UDP_MTU];
        loop {
            match sock_clone.recv(&mut recv_buf).await {
                Ok(n) => {
                    let resp = serialise_frame(&Frame {
                        flags: FLAG_DATA,
                        conn_id,
                        addr: Some(addr_clone.clone()),
                        payload: recv_buf[..n].to_vec(),
                    });
                    if tx_clone.send(resp).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    sockets.insert(key, ConnSocket { sock: sock.clone(), _reader: reader });
    Some(sock)
}

async fn handle_frame(
    frame: &Frame,
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    sockets: &mut std::collections::HashMap<(u16, SocketAddr), ConnSocket>,
) {
    if frame.flags & FLAG_KEEPALIVE != 0 {
        let resp = serialise_frame(&Frame {
            flags: FLAG_KEEPALIVE,
            conn_id: frame.conn_id,
            addr: None,
            payload: vec![],
        });
        let _ = tx.send(resp).await;
        return;
    }

    if frame.flags & FLAG_DATA == 0 {
        return;
    }

    let Some(ref dst) = frame.addr else {
        let _ = tx.send(serialise_err(frame.conn_id)).await;
        return;
    };

    let dst_addr = match dst.to_socket_addr() {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!("udpgw resolve failed: {}", e);
            let _ = tx.send(serialise_err(frame.conn_id)).await;
            return;
        }
    };

    let Some(sock) = get_or_create_socket(frame.conn_id, &dst_addr, dst, tx, sockets).await else {
        let _ = tx.send(serialise_err(frame.conn_id)).await;
        return;
    };

    // Send the datagram. Response comes asynchronously via the reader task.
    if let Err(e) = sock.send(&frame.payload).await {
        tracing::debug!("udpgw send to {} failed: {}", dst_addr, e);
        let _ = tx.send(serialise_err(frame.conn_id)).await;
    }
}

fn serialise_err(conn_id: u16) -> Vec<u8> {
    serialise_frame(&Frame {
        flags: FLAG_ERR,
        conn_id,
        addr: None,
        payload: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_round_trip() {
        let frame = Frame { flags: FLAG_KEEPALIVE, conn_id: 42, addr: None, payload: vec![] };
        let bytes = serialise_frame(&frame);
        let (parsed, consumed) = try_parse_frame(&bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.flags, FLAG_KEEPALIVE);
        assert_eq!(parsed.conn_id, 42);
        assert!(parsed.addr.is_none());
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn data_ipv4_round_trip() {
        let frame = Frame {
            flags: FLAG_DATA,
            conn_id: 7,
            addr: Some(DstAddr::V4(Ipv4Addr::new(8, 8, 8, 8), 53)),
            payload: vec![1, 2, 3, 4],
        };
        let bytes = serialise_frame(&frame);
        let (parsed, consumed) = try_parse_frame(&bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.flags, FLAG_DATA);
        assert_eq!(parsed.conn_id, 7);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);
        match parsed.addr.unwrap() {
            DstAddr::V4(ip, port) => {
                assert_eq!(ip, Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(port, 53);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn data_ipv6_round_trip() {
        let frame = Frame {
            flags: FLAG_DATA,
            conn_id: 100,
            addr: Some(DstAddr::V6(Ipv6Addr::LOCALHOST, 443)),
            payload: b"hello".to_vec(),
        };
        let bytes = serialise_frame(&frame);
        let (parsed, _) = try_parse_frame(&bytes).unwrap().unwrap();
        assert_eq!(parsed.conn_id, 100);
        match parsed.addr.unwrap() {
            DstAddr::V6(ip, port) => {
                assert_eq!(ip, Ipv6Addr::LOCALHOST);
                assert_eq!(port, 443);
            }
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn data_domain_round_trip() {
        let frame = Frame {
            flags: FLAG_DATA,
            conn_id: 5,
            addr: Some(DstAddr::Domain("example.com".into(), 80)),
            payload: b"GET /".to_vec(),
        };
        let bytes = serialise_frame(&frame);
        let (parsed, _) = try_parse_frame(&bytes).unwrap().unwrap();
        match parsed.addr.unwrap() {
            DstAddr::Domain(name, port) => {
                assert_eq!(name, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn err_frame_round_trip() {
        let bytes = serialise_err(99);
        let (parsed, _) = try_parse_frame(&bytes).unwrap().unwrap();
        assert_eq!(parsed.flags, FLAG_ERR);
        assert_eq!(parsed.conn_id, 99);
    }

    #[test]
    fn partial_frame_returns_none() {
        let frame = Frame { flags: FLAG_KEEPALIVE, conn_id: 1, addr: None, payload: vec![] };
        let bytes = serialise_frame(&frame);
        // Give it only half the bytes.
        assert!(try_parse_frame(&bytes[..bytes.len() / 2]).unwrap().is_none());
    }

    #[test]
    fn two_frames_in_buffer() {
        let f1 = serialise_frame(&Frame { flags: FLAG_KEEPALIVE, conn_id: 1, addr: None, payload: vec![] });
        let f2 = serialise_frame(&Frame { flags: FLAG_KEEPALIVE, conn_id: 2, addr: None, payload: vec![] });
        let mut buf = f1.clone();
        buf.extend_from_slice(&f2);

        let (p1, c1) = try_parse_frame(&buf).unwrap().unwrap();
        assert_eq!(p1.conn_id, 1);
        let (p2, _) = try_parse_frame(&buf[c1..]).unwrap().unwrap();
        assert_eq!(p2.conn_id, 2);
    }

    #[test]
    fn is_udpgw_dest_works() {
        assert!(is_udpgw_dest("198.18.0.1", 7300));
        assert!(!is_udpgw_dest("198.18.0.1", 80));
        assert!(!is_udpgw_dest("8.8.8.8", 7300));
    }
}
