// Language: Rust 2021 | File: src/socks5_udp.rs | Target: RFC 1928 / RFC 1929 SOCKS5 UDP Associate AsyncUdpSocket for quinn
//! Native SOCKS5 UDP Associate (`CMD = 0x03`) transport implementing `quinn::AsyncUdpSocket`.
//!
//! Enables HTTP/3 (UDP QUIC) tunneling through any RFC 1928 / RFC 1929 SOCKS5 proxy
//! supporting `UDP ASSOCIATE`, including No-Auth (`0x00`) and Username/Password (`0x02`).
//! The TCP control channel is retained for the lifetime of the socket and cleanly closed on drop.

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{lookup_host, TcpStream, UdpSocket};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Return true if `proxy_url` uses the `socks5://` or `socks5h://` scheme.
pub fn is_socks5_proxy(proxy_url: &str) -> bool {
    let low = proxy_url.trim().to_ascii_lowercase();
    low.starts_with("socks5://") || low.starts_with("socks5h://")
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

struct ParsedSocks5Proxy {
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
}

fn parse_socks5_proxy(proxy_url: &str) -> io::Result<ParsedSocks5Proxy> {
    let parsed = url::Url::parse(proxy_url.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid SOCKS5 proxy URL: {e}")))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "socks5" && scheme != "socks5h" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported SOCKS5 scheme '{scheme}'"),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 proxy URL missing host"))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = parsed.port().unwrap_or(1080);

    let credentials = if !parsed.username().is_empty() || parsed.password().is_some() {
        let user = percent_decode(parsed.username());
        let pass = percent_decode(parsed.password().unwrap_or(""));
        Some((user, pass))
    } else {
        None
    };

    Ok(ParsedSocks5Proxy {
        host,
        port,
        credentials,
    })
}

fn socks5_reply_error(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported (UDP ASSOCIATE disabled on proxy)",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

/// A `quinn::AsyncUdpSocket` that encapsulates/decapsulates UDP QUIC datagrams over
/// an RFC 1928 SOCKS5 `UDP ASSOCIATE` relay.
pub struct Socks5UdpSocket {
    /// Underlying local UDP socket exchanging framed packets with `relay_addr`.
    udp: UdpSocket,
    /// Relay UDP endpoint returned by the SOCKS5 server's `UDP ASSOCIATE` reply.
    relay_addr: SocketAddr,
    /// Kept open for the entire lifetime of the UDP association (RFC 1928 Section 7).
    _control_tcp: TcpStream,
    /// Reusable scratch buffer for incoming SOCKS5 UDP frames (avoids per-packet allocation).
    recv_scratch: Mutex<Vec<u8>>,
}

impl fmt::Debug for Socks5UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5UdpSocket")
            .field("local_addr", &self.udp.local_addr().ok())
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

impl Socks5UdpSocket {
    /// Perform the SOCKS5 TCP handshake (`UDP ASSOCIATE`) and bind the local UDP socket.
    pub async fn connect(
        proxy_url: &str,
        local_address: Option<IpAddr>,
        timeout: Duration,
    ) -> io::Result<Self> {
        tokio::time::timeout(timeout, Self::connect_inner(proxy_url, local_address))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS5 UDP ASSOCIATE handshake timed out",
                )
            })?
    }

    async fn connect_inner(proxy_url: &str, local_address: Option<IpAddr>) -> io::Result<Self> {
        let cfg = parse_socks5_proxy(proxy_url)?;
        let target = format!("{}:{}", cfg.host, cfg.port);
        let mut addrs: Vec<SocketAddr> = lookup_host(&target).await?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("No addresses resolved for SOCKS5 proxy '{target}'"),
            ));
        }
        // Prefer IPv4 if available to match standard loopback/proxy listeners
        addrs.sort_by_key(|a| a.is_ipv6());

        let mut last_err: Option<io::Error> = None;
        let mut tcp_opt: Option<TcpStream> = None;
        for sa in addrs {
            match TcpStream::connect(sa).await {
                Ok(s) => {
                    tcp_opt = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut tcp = match tcp_opt {
            Some(s) => s,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::ConnectionRefused, "SOCKS5 TCP connect failed")
                }));
            }
        };
        let _ = tcp.set_nodelay(true);
        let proxy_peer_ip = tcp.peer_addr()?.ip();

        // 1. Method negotiation (RFC 1928 Section 3)
        if cfg.credentials.is_some() {
            tcp.write_all(&[SOCKS5_VERSION, 0x02, AUTH_NONE, AUTH_USERPASS])
                .await?;
        } else {
            tcp.write_all(&[SOCKS5_VERSION, 0x01, AUTH_NONE]).await?;
        }
        let mut method_reply = [0u8; 2];
        tcp.read_exact(&mut method_reply).await?;
        if method_reply[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SOCKS5 version byte: {}", method_reply[0]),
            ));
        }
        match method_reply[1] {
            AUTH_NONE => {}
            AUTH_USERPASS => {
                let (user, pass) = cfg.credentials.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 proxy requires username/password authentication",
                    )
                })?;
                let u_bytes = user.as_bytes();
                let p_bytes = pass.as_bytes();
                if u_bytes.len() > 255 || p_bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS5 username/password exceeds 255 bytes",
                    ));
                }
                let mut auth_req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
                auth_req.push(0x01); // RFC 1929 subnegotiation version
                auth_req.push(u_bytes.len() as u8);
                auth_req.extend_from_slice(u_bytes);
                auth_req.push(p_bytes.len() as u8);
                auth_req.extend_from_slice(p_bytes);
                tcp.write_all(&auth_req).await?;

                let mut auth_reply = [0u8; 2];
                tcp.read_exact(&mut auth_reply).await?;
                if auth_reply[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 username/password authentication failed",
                    ));
                }
            }
            AUTH_NO_ACCEPTABLE => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 proxy rejected authentication methods",
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported SOCKS5 auth method 0x{other:02x}"),
                ));
            }
        }

        // 2. UDP ASSOCIATE request (RFC 1928 Section 4: DST.ADDR = 0, DST.PORT = 0)
        if proxy_peer_ip.is_ipv6() {
            let mut req = [0u8; 22];
            req[0] = SOCKS5_VERSION;
            req[1] = CMD_UDP_ASSOCIATE;
            req[2] = 0x00;
            req[3] = ATYP_IPV6;
            tcp.write_all(&req).await?;
        } else {
            let req = [
                SOCKS5_VERSION,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            tcp.write_all(&req).await?;
        }

        // 3. Parse UDP ASSOCIATE reply
        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr).await?;
        if hdr[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SOCKS5 UDP ASSOCIATE reply version {}", hdr[0]),
            ));
        }
        if hdr[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SOCKS5 UDP ASSOCIATE rejected (0x{:02x}): {}",
                    hdr[1],
                    socks5_reply_error(hdr[1])
                ),
            ));
        }

        let bnd_ip: IpAddr = match hdr[3] {
            ATYP_IPV4 => {
                let mut ip_buf = [0u8; 4];
                tcp.read_exact(&mut ip_buf).await?;
                IpAddr::V4(Ipv4Addr::from(ip_buf))
            }
            ATYP_IPV6 => {
                let mut ip_buf = [0u8; 16];
                tcp.read_exact(&mut ip_buf).await?;
                IpAddr::V6(Ipv6Addr::from(ip_buf))
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                tcp.read_exact(&mut len_buf).await?;
                let mut dom = vec![0u8; len_buf[0] as usize];
                tcp.read_exact(&mut dom).await?;
                let dom_s = String::from_utf8_lossy(&dom).into_owned();
                let resolved = lookup_host(format!("{dom_s}:0"))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!("Failed to resolve SOCKS5 relay host '{dom_s}'"),
                        )
                    })?;
                resolved.ip()
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 BND.ATYP 0x{other:02x}"),
                ));
            }
        };

        let mut port_buf = [0u8; 2];
        tcp.read_exact(&mut port_buf).await?;
        let bnd_port = u16::from_be_bytes(port_buf);
        if bnd_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 proxy returned UDP relay port 0",
            ));
        }

        // RFC 1928 real-world convention: 0.0.0.0 / :: means use the proxy TCP peer IP
        let relay_ip = if bnd_ip.is_unspecified() {
            proxy_peer_ip
        } else {
            bnd_ip
        };
        let relay_addr = SocketAddr::new(relay_ip, bnd_port);

        let bind_sa = match local_address {
            Some(ip) if ip.is_ipv6() == relay_addr.is_ipv6() => SocketAddr::new(ip, 0),
            _ => {
                if relay_addr.is_ipv6() {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                }
            }
        };
        let udp = UdpSocket::bind(bind_sa).await?;

        Ok(Self {
            udp,
            relay_addr,
            _control_tcp: tcp,
            recv_scratch: Mutex::new(vec![0u8; 65536]),
        })
    }
}

/// Parse an RFC 1928 SOCKS5 UDP datagram header and return `(source_addr, header_len)`.
fn parse_socks5_udp_header(pkt: &[u8]) -> Option<(SocketAddr, usize)> {
    if pkt.len() < 10 {
        return None;
    }
    // RSV (2 bytes = 0x0000), FRAG (1 byte = 0x00 — fragmented UDP unsupported per RFC 1928)
    if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
        return None;
    }
    match pkt[3] {
        ATYP_IPV4 => {
            if pkt.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
            let port = u16::from_be_bytes([pkt[8], pkt[9]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 10))
        }
        ATYP_IPV6 => {
            if pkt.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([pkt[20], pkt[21]]);
            Some((SocketAddr::new(IpAddr::V6(ip), port), 22))
        }
        ATYP_DOMAIN => {
            let dlen = pkt[4] as usize;
            let hdr_len = 5 + dlen + 2;
            if pkt.len() < hdr_len {
                return None;
            }
            let port = u16::from_be_bytes([pkt[5 + dlen], pkt[6 + dlen]]);
            let dom_s = std::str::from_utf8(&pkt[5..5 + dlen]).ok()?;
            let ip = dom_s.parse::<IpAddr>().ok()?;
            Some((SocketAddr::new(ip, port), hdr_len))
        }
        _ => None,
    }
}

/// Write an RFC 1928 SOCKS5 UDP header + payload into `out`.
fn encode_socks5_udp_packet(dst: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    match dst {
        SocketAddr::V4(v4) => {
            out.reserve(10 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, ATYP_IPV4]);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.reserve(22 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x00, ATYP_IPV6]);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
}

#[derive(Debug)]
struct Socks5UdpPoller {
    socket: Arc<Socks5UdpSocket>,
}

impl UdpPoller for Socks5UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.udp.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5UdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut framed = Vec::with_capacity(22 + transmit.contents.len());
        encode_socks5_udp_packet(transmit.destination, transmit.contents, &mut framed);
        let sent = self.udp.try_send_to(&framed, self.relay_addr)?;
        if sent < framed.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Short UDP write to SOCKS5 relay",
            ));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut scratch = self.recv_scratch.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            let mut read_buf = ReadBuf::new(&mut scratch[..]);
            match self.udp.poll_recv_from(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(from)) => {
                    if from != self.relay_addr {
                        // Drop stray UDP datagrams not originating from the negotiated SOCKS5 relay
                        continue;
                    }
                    let filled = read_buf.filled();
                    let Some((src_addr, hdr_len)) = parse_socks5_udp_header(filled) else {
                        // Ignore stray/malformed datagrams and keep polling
                        continue;
                    };
                    let payload = &filled[hdr_len..];
                    let dst_buf = &mut bufs[0];
                    let copy_len = payload.len().min(dst_buf.len());
                    dst_buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    meta[0] = RecvMeta {
                        addr: src_addr,
                        len: copy_len,
                        stride: copy_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}
