// Language: Rust 2021 | File: src/tcp_ech.rs | Target: Pure BoringSSL TCP TLS 1.3 Real ECH + HTTP/2 Engine
//! Direct BoringSSL (`btls` + `tokio-btls` + `http2`) TCP HTTP/2 client supporting Real ECH
//! (`SSL_set1_ech_config_list`, `SSL_get0_ech_retry_configs`, `SSL_ech_accepted`),
//! post-handshake TLS 1.3 session ticket resumption (`SSL_CTX_sess_set_new_cb`),
//! `SSLKEYLOGFILE` / `keylog_file`, and incremental chunk-by-chunk HTTP/2 streaming.

use crate::doh::{fetch_ech_config_list, DohResolver, EchCache};
use crate::options::RawHttp2Config;
use crate::quic_boring::{
    cert_decompress_brotli, cert_decompress_zlib, cert_decompress_zstd, keylog_cb,
    keylog_ex_data_idx, load_ca_certs_into_store, load_client_identity, TicketCache,
};
use crate::socks5_udp::percent_decode;
use crate::H3StreamDecoder;
use btls::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use btls_sys as ffi;
use bytes::Bytes;
use foreign_types::{ForeignType, ForeignTypeRef};
use futures_util::Stream;
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::raw::{c_int, c_long, c_void};
use std::pin::Pin;
use std::ptr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
use tokio_btls::SslStream;
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::Client;

const CERT_COMP_ZLIB: u16 = 1;
const CERT_COMP_BROTLI: u16 = 2;
const CERT_COMP_ZSTD: u16 = 3;
const SSL_SESS_CACHE_CLIENT: c_int = 0x0001;

struct TcpTicketTarget {
    cache: TicketCache,
    key: String,
}

unsafe extern "C" fn free_tcp_ticket_target(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr as *mut TcpTicketTarget));
    }
}

fn tcp_ticket_ex_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            None,
            Some(free_tcp_ticket_target),
        )
    })
}

unsafe extern "C" fn tcp_new_session_cb(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int {
    if ssl.is_null() || session.is_null() {
        return 0;
    }
    let ptr_t = ffi::SSL_get_ex_data(ssl, tcp_ticket_ex_idx()) as *const TcpTicketTarget;
    if let Some(target) = ptr_t.as_ref() {
        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        if ffi::SSL_SESSION_to_bytes(session, &mut out_ptr, &mut out_len) == 1
            && !out_ptr.is_null()
            && out_len > 0
        {
            let bytes = std::slice::from_raw_parts(out_ptr, out_len).to_vec();
            ffi::OPENSSL_free(out_ptr as *mut c_void);
            let mut guard = target.cache.lock().unwrap_or_else(|p| p.into_inner());
            if guard.len() >= 128 {
                guard.clear();
            }
            guard.insert(target.key.clone(), bytes);
        }
    }
    // Return 0 so BoringSSL retains ownership and frees `session`.
    0
}

/// Owns `SslContext` before `_keylog_path` so `SSL_CTX_free` always runs while the
/// `ex_data` CString pointer is still valid.
struct TcpSslCtx {
    ctx: SslContext,
    _keylog_path: Option<CString>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct TcpEchSpec {
    pub method: String,
    pub url: url::Url,
    pub headers: Vec<(String, String)>,
    pub header_order: Option<Vec<String>>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub allow_redirects: bool,
    pub max_redirects: usize,
    pub verify: bool,
    pub ca_bundle: Option<Vec<u8>>,
    pub identity_pair: Option<(Vec<u8>, Vec<u8>)>,
    pub resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    pub local_address: Option<IpAddr>,
    pub proxy: Option<String>,
    pub tls_info: bool,
    pub keylog_file: Option<String>,
    pub preset: String,
    pub ech_doh_url: String,
    pub ech_config_list: Option<Vec<u8>>,
    pub http2_config: Option<RawHttp2Config>,
}

/// Apply per-browser Akamai HTTP/2 fingerprint defaults (`SETTINGS`, exact setting order,
/// connection `WINDOW_UPDATE`, pseudo-header order, priorities) and overlay any custom
/// `http2_options` / `akamai_h2` overrides onto `http2::client::Builder`.
pub(crate) fn apply_h2_fingerprint(
    b: &mut http2::client::Builder,
    preset: &str,
    custom: Option<&RawHttp2Config>,
) {
    use http2::frame::{
        Priorities, Priority, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency,
        StreamId,
    };

    let lower = preset.trim().to_ascii_lowercase();
    if lower.starts_with("firefox") || lower.starts_with("tor") {
        // Firefox: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
        b.header_table_size(65_536)
            .enable_push(false)
            .initial_window_size(131_072)
            .max_frame_size(16_384)
            .initial_connection_window_size(12_582_912)
            .settings_order(
                SettingsOrder::builder()
                    .extend([
                        SettingId::HeaderTableSize,
                        SettingId::EnablePush,
                        SettingId::InitialWindowSize,
                        SettingId::MaxFrameSize,
                    ])
                    .build(),
            )
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Path,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                    ])
                    .build(),
            );
    } else if lower.starts_with("safari") {
        // Safari: 2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p
        b.enable_push(false)
            .max_concurrent_streams(100)
            .initial_window_size(2_097_152)
            .no_rfc7540_priorities(true)
            .initial_connection_window_size(10_485_760)
            .settings_order(
                SettingsOrder::builder()
                    .extend([
                        SettingId::EnablePush,
                        SettingId::MaxConcurrentStreams,
                        SettingId::InitialWindowSize,
                        SettingId::NoRfc7540Priorities,
                    ])
                    .build(),
            )
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Scheme,
                        PseudoId::Authority,
                        PseudoId::Path,
                    ])
                    .build(),
            );
    } else if lower.starts_with("okhttp") {
        // OkHttp: 4:16777216|16711681|0|m,p,a,s
        b.initial_window_size(16_777_216)
            .initial_connection_window_size(16_777_216)
            .settings_order(
                SettingsOrder::builder()
                    .extend([SettingId::InitialWindowSize])
                    .build(),
            )
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Path,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                    ])
                    .build(),
            );
    } else {
        // Chrome / Edge / Opera: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
        b.header_table_size(65_536)
            .enable_push(false)
            .initial_window_size(6_291_456)
            .max_header_list_size(262_144)
            .initial_connection_window_size(15_728_640)
            .settings_order(
                SettingsOrder::builder()
                    .extend([
                        SettingId::HeaderTableSize,
                        SettingId::EnablePush,
                        SettingId::InitialWindowSize,
                        SettingId::MaxHeaderListSize,
                    ])
                    .build(),
            )
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                        PseudoId::Path,
                    ])
                    .build(),
            );
    }

    if let Some(cfg) = custom {
        if let Some(v) = cfg.header_table_size {
            b.header_table_size(v);
        }
        if let Some(v) = cfg.enable_push {
            b.enable_push(v);
        }
        if let Some(v) = cfg.max_concurrent_streams {
            b.max_concurrent_streams(v);
        }
        if let Some(v) = cfg.initial_window_size {
            b.initial_window_size(v);
        }
        if let Some(v) = cfg.initial_connection_window_size {
            b.initial_connection_window_size(v);
        }
        if let Some(v) = cfg.max_frame_size {
            b.max_frame_size(v);
        }
        if let Some(v) = cfg.max_header_list_size {
            b.max_header_list_size(v);
        }
        if let Some(v) = cfg.enable_connect_protocol {
            b.enable_connect_protocol(v);
        }
        if let Some(v) = cfg.no_rfc7540_priorities {
            b.no_rfc7540_priorities(v);
        }
        if let Some(v) = cfg.initial_stream_id {
            b.initial_stream_id(v);
        }
        if let Some(ref order) = cfg.settings_order {
            let mapped: Vec<SettingId> = order
                .iter()
                .filter_map(|&n| match n {
                    1 => Some(SettingId::HeaderTableSize),
                    2 => Some(SettingId::EnablePush),
                    3 => Some(SettingId::MaxConcurrentStreams),
                    4 => Some(SettingId::InitialWindowSize),
                    5 => Some(SettingId::MaxFrameSize),
                    6 => Some(SettingId::MaxHeaderListSize),
                    8 => Some(SettingId::EnableConnectProtocol),
                    9 => Some(SettingId::NoRfc7540Priorities),
                    _ => None,
                })
                .collect();
            if !mapped.is_empty() {
                b.settings_order(SettingsOrder::builder().extend(mapped).build());
            }
        }
        if let Some(ref pseudo) = cfg.headers_pseudo_order {
            let mapped: Vec<PseudoId> = pseudo
                .iter()
                .filter_map(|&p| match p {
                    0 => Some(PseudoId::Method),
                    1 => Some(PseudoId::Authority),
                    2 => Some(PseudoId::Scheme),
                    3 => Some(PseudoId::Path),
                    _ => None,
                })
                .collect();
            if !mapped.is_empty() {
                b.headers_pseudo_order(PseudoOrder::builder().extend(mapped).build());
            }
        }
        if let Some((dep_id, weight, exclusive)) = cfg.headers_stream_dependency {
            b.headers_stream_dependency(StreamDependency::new(
                StreamId::from(dep_id),
                weight,
                exclusive,
            ));
        }
        if let Some(ref prios) = cfg.priorities {
            let mut pb = Priorities::builder();
            for &(sid, dep_id, weight, exclusive) in prios {
                pb = pb.push(Priority::new(
                    StreamId::from(sid),
                    StreamDependency::new(StreamId::from(dep_id), weight, exclusive),
                ));
            }
            b.priorities(pb.build());
        }
    }
}

pub struct TcpEchOutcome {
    pub status_code: u16,
    pub wreq_headers: HeaderMap,
    pub headers_map: HashMap<String, String>,
    pub content_encoding: Option<String>,
    pub raw_body: Vec<u8>,
    pub final_url: String,
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    pub history: Vec<(u16, String, String, HashMap<String, String>)>,
    pub ech_accepted: bool,
    pub tls_resumed: bool,
    pub elapsed: f64,
}

#[allow(dead_code)]
pub type TcpEchBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send + 'static>>;

#[allow(dead_code)]
pub struct TcpEchStreamOutcome {
    pub status_code: u16,
    pub wreq_headers: HeaderMap,
    pub headers_map: HashMap<String, String>,
    pub final_url: String,
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    pub history: Vec<(u16, String, String, HashMap<String, String>)>,
    pub ech_accepted: bool,
    pub tls_resumed: bool,
    pub elapsed: f64,
    pub body_stream: TcpEchBodyStream,
}

struct OpenTcpHop {
    status_code: u16,
    wreq_headers: HeaderMap,
    headers_map: HashMap<String, String>,
    content_encoding: Option<String>,
    remote_addr: Option<String>,
    peer_certificate: Option<Vec<u8>>,
    ech_accepted: bool,
    tls_resumed: bool,
    recv_stream: http2::RecvStream,
    conn_guard: AbortOnDrop,
}

async fn connect_tcp_target(
    host: &str,
    port: u16,
    resolve_entries: &[(String, Vec<SocketAddr>)],
    doh_resolver: Option<&DohResolver>,
    local_address: Option<IpAddr>,
    proxy: Option<&str>,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), String> {
    if let Some(proxy_url) = proxy {
        let low = proxy_url.trim().to_ascii_lowercase();
        if low.starts_with("socks5://") || low.starts_with("socks5h://") {
            let stream = tokio::time::timeout(
                timeout,
                connect_via_socks5_tcp(proxy_url, host, port),
            )
            .await
            .map_err(|_| "[connect_timeout] SOCKS5 TCP CONNECT timed out".to_string())?
            .map_err(|e| format!("[connect] SOCKS5 TCP CONNECT failed: {e}"))?;
            let peer = stream
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], port)));
            return Ok((stream, peer));
        }
        return Err(
            "[connect] TCP ECH currently supports direct connections or socks5:// / socks5h:// proxies"
                .to_string(),
        );
    }

    let prefer_v6 = local_address.map(|ip| ip.is_ipv6());
    let sa = resolve_tcp_target(host, port, resolve_entries, doh_resolver, prefer_v6).await?;

    let fut = async {
        if let Some(ip) = local_address {
            let sock = if sa.is_ipv6() {
                TcpSocket::new_v6()?
            } else {
                TcpSocket::new_v4()?
            };
            sock.bind(SocketAddr::new(ip, 0))?;
            sock.connect(sa).await
        } else {
            TcpStream::connect(sa).await
        }
    };

    let stream = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| "[connect_timeout] TCP ECH connect timed out".to_string())?
        .map_err(|e| format!("[connect] TCP connect to {sa} failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok((stream, sa))
}

async fn resolve_tcp_target(
    host: &str,
    port: u16,
    resolve_entries: &[(String, Vec<SocketAddr>)],
    doh_resolver: Option<&DohResolver>,
    prefer_ipv6: Option<bool>,
) -> Result<SocketAddr, String> {
    for (dom, addrs) in resolve_entries {
        if dom.eq_ignore_ascii_case(host) {
            if let Some(&first) = addrs.first() {
                let p = if first.port() == 0 { port } else { first.port() };
                return Ok(SocketAddr::new(first.ip(), p));
            }
        }
    }
    if let Ok(ip) = IpAddr::from_str(host.trim_matches(|c| c == '[' || c == ']')) {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(doh) = doh_resolver {
        return doh
            .resolve_socket_addr(host, port, prefer_ipv6)
            .await
            .map_err(|e| format!("[connect] DoH DNS lookup failed: {e}"));
    }
    let addrs: Vec<SocketAddr> = lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("[connect] DNS lookup failed for '{host}:{port}': {e}"))?
        .collect();
    if let Some(want_v6) = prefer_ipv6 {
        if let Some(&matched) = addrs.iter().find(|a| a.is_ipv6() == want_v6) {
            return Ok(matched);
        }
    }
    if let Some(&v4) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(v4);
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("[connect] No addresses resolved for '{host}:{port}'"))
}

async fn connect_via_socks5_tcp(proxy_url: &str, dst_host: &str, dst_port: u16) -> io::Result<TcpStream> {
    let parsed = url::Url::parse(proxy_url.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid proxy URL: {e}")))?;
    let p_host = parsed
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Proxy URL missing host"))?;
    let p_port = parsed.port().unwrap_or(1080);

    let mut tcp = TcpStream::connect(format!("{p_host}:{p_port}")).await?;
    let _ = tcp.set_nodelay(true);

    let has_auth = !parsed.username().is_empty() || parsed.password().is_some();
    if has_auth {
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut rep = [0u8; 2];
    tcp.read_exact(&mut rep).await?;
    if rep[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid SOCKS5 version"));
    }
    if rep[1] == 0x02 {
        let user_dec = percent_decode(parsed.username());
        let pass_dec = percent_decode(parsed.password().unwrap_or(""));
        let u = user_dec.as_bytes();
        let p = pass_dec.as_bytes();
        if u.len() > 255 || p.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 username/password exceeds 255 bytes",
            ));
        }
        let mut req = Vec::with_capacity(3 + u.len() + p.len());
        req.push(0x01);
        req.push(u.len() as u8);
        req.extend_from_slice(u);
        req.push(p.len() as u8);
        req.extend_from_slice(p);
        tcp.write_all(&req).await?;
        let mut arep = [0u8; 2];
        tcp.read_exact(&mut arep).await?;
        if arep[1] != 0x00 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 auth failed"));
        }
    } else if rep[1] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SOCKS5 auth rejected"));
    }

    // CMD = 0x01 CONNECT using ATYP=0x03 (domain)
    let h_bytes = dst_host.as_bytes();
    if h_bytes.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target hostname exceeds 255 bytes for SOCKS5 ATYP_DOMAIN",
        ));
    }
    let mut creq = Vec::with_capacity(7 + h_bytes.len());
    creq.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, h_bytes.len() as u8]);
    creq.extend_from_slice(h_bytes);
    creq.extend_from_slice(&dst_port.to_be_bytes());
    tcp.write_all(&creq).await?;

    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT rejected (0x{:02x})", hdr[1]),
        ));
    }
    let skip = match hdr[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad SOCKS5 ATYP")),
    };
    let mut junk = vec![0u8; skip];
    tcp.read_exact(&mut junk).await?;
    Ok(tcp)
}

fn build_boring_tcp_ctx(
    preset: &str,
    verify: bool,
    ca_bundle: Option<&[u8]>,
    identity_pair: Option<&(Vec<u8>, Vec<u8>)>,
    keylog_file: Option<&str>,
) -> Result<TcpSslCtx, String> {
    let lower = preset.trim().to_ascii_lowercase();
    let is_firefox = lower.starts_with("firefox") || lower.starts_with("tor");
    let is_safari = lower.starts_with("safari");

    let mut builder = SslContext::builder(SslMethod::tls())
        .map_err(|e| format!("[builder] SslContext::builder failed: {e}"))?;
    builder.set_grease_enabled(!is_firefox);
    builder.set_permute_extensions(!is_firefox && !is_safari);

    let curves = if is_safari {
        "X25519:P-256:P-384:P-521"
    } else if is_firefox {
        "X25519MLKEM768:X25519:P-256:P-384:P-521"
    } else {
        "X25519MLKEM768:X25519:P-256:P-384"
    };
    if builder.set_curves_list(curves).is_err() {
        let _ = builder.set_curves_list("X25519:P-256:P-384");
    }

    // Negotiate HTTP/2 over TLS 1.3 (ECH requires TLS 1.3)
    let _ = builder.set_alpn_protos(b"\x02h2");

    if verify {
        builder.set_verify(SslVerifyMode::PEER);
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let ctx = builder.build();
    let mut keylog_cstr: Option<CString> = None;
    unsafe {
        let raw_ctx = ctx.as_ptr();
        ffi::SSL_CTX_set_min_proto_version(raw_ctx, ffi::TLS1_3_VERSION as u16);
        ffi::SSL_CTX_set_max_proto_version(raw_ctx, ffi::TLS1_3_VERSION as u16);
        ffi::SSL_CTX_set_session_cache_mode(raw_ctx, SSL_SESS_CACHE_CLIENT);
        ffi::SSL_CTX_sess_set_new_cb(raw_ctx, Some(tcp_new_session_cb));

        let sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
        if let Ok(c_sig) = CString::new(sigalgs) {
            ffi::SSL_CTX_set1_sigalgs_list(raw_ctx, c_sig.as_ptr());
        }

        if is_safari {
            ffi::SSL_CTX_add_cert_compression_alg(raw_ctx, CERT_COMP_ZLIB, None, Some(cert_decompress_zlib));
        } else if is_firefox {
            ffi::SSL_CTX_add_cert_compression_alg(raw_ctx, CERT_COMP_ZLIB, None, Some(cert_decompress_zlib));
            ffi::SSL_CTX_add_cert_compression_alg(raw_ctx, CERT_COMP_BROTLI, None, Some(cert_decompress_brotli));
            ffi::SSL_CTX_add_cert_compression_alg(raw_ctx, CERT_COMP_ZSTD, None, Some(cert_decompress_zstd));
        } else {
            ffi::SSL_CTX_add_cert_compression_alg(raw_ctx, CERT_COMP_BROTLI, None, Some(cert_decompress_brotli));
        }

        if verify {
            let store = ffi::SSL_CTX_get_cert_store(raw_ctx);
            if !store.is_null() {
                load_ca_certs_into_store(store, ca_bundle);
            }
        }
        if let Some((cert_pem, key_pem)) = identity_pair {
            load_client_identity(raw_ctx, cert_pem, key_pem)?;
        }

        let want_env_kl = std::env::var("SSLKEYLOGFILE")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if let Some(kl) = keylog_file {
            if let Ok(c_kl) = CString::new(kl) {
                ffi::SSL_CTX_set_ex_data(raw_ctx, keylog_ex_data_idx(), c_kl.as_ptr() as *mut c_void);
                ffi::SSL_CTX_set_keylog_callback(raw_ctx, Some(keylog_cb));
                keylog_cstr = Some(c_kl);
            }
        } else if want_env_kl {
            ffi::SSL_CTX_set_keylog_callback(raw_ctx, Some(keylog_cb));
        }
    }
    Ok(TcpSslCtx {
        ctx,
        _keylog_path: keylog_cstr,
    })
}

#[allow(clippy::too_many_arguments)]
async fn open_tcp_ech_single_hop(
    spec: &TcpEchSpec,
    current_url: &url::Url,
    method_str: &str,
    body_opt: Option<&[u8]>,
    jar: &Arc<Jar>,
    ech_cache: &EchCache,
    ticket_cache: &TicketCache,
    doh_resolver: Option<&DohResolver>,
    doh_client: Option<&Client>,
) -> Result<OpenTcpHop, String> {
    if current_url.scheme() != "https" {
        return Err("[connect] Real ECH requires an https:// URL".to_string());
    }
    let host = current_url
        .host_str()
        .ok_or_else(|| "[request] URL missing host".to_string())?
        .to_string();
    let port = current_url.port().unwrap_or(443);
    let clean_sni = host.trim_matches(|c| c == '[' || c == ']');

    let mut active_ech: Option<Vec<u8>> = if let Some(ref explicit) = spec.ech_config_list {
        Some(explicit.clone())
    } else if let Some(dc) = doh_client {
        fetch_ech_config_list(clean_sni, &spec.ech_doh_url, ech_cache, dc, spec.connect_timeout).await
    } else {
        None
    };

    // If the target domain publishes no ECH config, bail early so the caller falls back to full
    // `wreq` (preserving connection pooling and full Akamai H2 settings/pseudo-header fidelity).
    if active_ech.as_ref().map(|v| v.is_empty()).unwrap_or(true) {
        return Err("no_ech_config".to_string());
    }

    let tcp_ctx = build_boring_tcp_ctx(
        &spec.preset,
        spec.verify,
        spec.ca_bundle.as_deref(),
        spec.identity_pair.as_ref(),
        spec.keylog_file.as_deref(),
    )?;
    let lower = spec.preset.trim().to_ascii_lowercase();
    let chrome_alps = !lower.starts_with("firefox") && !lower.starts_with("tor") && !lower.starts_with("safari");

    let ticket_key = format!("tcp:{}:{}:{}:true", clean_sni.to_ascii_lowercase(), port, spec.verify);
    let saved_ticket = ticket_cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&ticket_key)
        .cloned();

    let mut tls_opt: Option<(SslStream<TcpStream>, SocketAddr)> = None;
    let mut last_err = String::new();

    for attempt in 0..2 {
        let (tcp, remote_sa) = connect_tcp_target(
            clean_sni,
            port,
            &spec.resolve_entries,
            doh_resolver,
            spec.local_address,
            spec.proxy.as_deref(),
            spec.connect_timeout,
        )
        .await?;

        let mut ssl = Ssl::new(&tcp_ctx.ctx).map_err(|e| format!("[ssl] Ssl::new failed: {e}"))?;
        ssl.set_hostname(clean_sni)
            .map_err(|e| format!("[ssl] set_hostname failed: {e}"))?;

        if let Some(ref ech_bytes) = active_ech {
            if !ech_bytes.is_empty() {
                let _ = ssl.set_ech_config_list(ech_bytes);
            }
        }
        if chrome_alps {
            ssl.set_alps_use_new_codepoint(true);
            let _ = ssl.add_application_settings(b"h2");
        }

        unsafe {
            let raw_ssl = ssl.as_ptr();
            // Attach ticket target owned by BoringSSL via CRYPTO_EX_free destructor
            let target = Box::new(TcpTicketTarget {
                cache: Arc::clone(ticket_cache),
                key: ticket_key.clone(),
            });
            ffi::SSL_set_ex_data(
                raw_ssl,
                tcp_ticket_ex_idx(),
                Box::into_raw(target) as *mut c_void,
            );

            if spec.verify {
                if let Ok(c_sni) = CString::new(clean_sni) {
                    let param = ffi::SSL_get0_param(raw_ssl);
                    if !param.is_null() {
                        if IpAddr::from_str(clean_sni).is_ok() {
                            ffi::X509_VERIFY_PARAM_set1_ip_asc(param, c_sni.as_ptr());
                        } else {
                            ffi::X509_VERIFY_PARAM_set1_host(param, c_sni.as_ptr(), clean_sni.len());
                        }
                    }
                }
            }
            if attempt == 0 {
                if let Some(ref tbytes) = saved_ticket {
                    let raw_ctx = tcp_ctx.ctx.as_ptr();
                    let sess = ffi::SSL_SESSION_from_bytes(tbytes.as_ptr(), tbytes.len(), raw_ctx);
                    if !sess.is_null() {
                        ffi::SSL_set_session(raw_ssl, sess);
                        ffi::SSL_SESSION_free(sess);
                    }
                }
            }
        }

        let mut tls_stream =
            SslStream::new(ssl, tcp).map_err(|e| format!("[ssl] SslStream::new failed: {e}"))?;
        match tokio::time::timeout(spec.connect_timeout, Pin::new(&mut tls_stream).connect()).await {
            Ok(Ok(())) => {
                tls_opt = Some((tls_stream, remote_sa));
                break;
            }
            Ok(Err(e)) => {
                if attempt == 0 {
                    let retry_cfg = unsafe {
                        let raw_ssl = tls_stream.ssl().as_ptr();
                        let mut ptr_r: *const u8 = ptr::null();
                        let mut len_r: usize = 0;
                        ffi::SSL_get0_ech_retry_configs(raw_ssl, &mut ptr_r, &mut len_r);
                        if !ptr_r.is_null() && len_r > 0 {
                            Some(std::slice::from_raw_parts(ptr_r, len_r).to_vec())
                        } else {
                            None
                        }
                    };
                    if let Some(fresh) = retry_cfg {
                        ticket_cache
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&ticket_key);
                        let mut cache = ech_cache.lock().await;
                        cache.insert(
                            clean_sni.to_ascii_lowercase(),
                            (fresh.clone(), Instant::now() + Duration::from_secs(300)),
                        );
                        active_ech = Some(fresh);
                        continue;
                    }
                }
                last_err = format!("[ssl] BoringSSL TCP ECH handshake failed: {e}");
                break;
            }
            Err(_) => {
                last_err = "[connect_timeout] BoringSSL TCP ECH handshake timed out".to_string();
                break;
            }
        }
    }

    let (tls_stream, remote_sa) = match tls_opt {
        Some(pair) => pair,
        None => return Err(last_err),
    };

    let ech_accepted = tls_stream.ssl().ech_accepted();
    let tls_resumed = tls_stream.ssl().session_reused();
    let peer_cert_der = if spec.tls_info {
        tls_stream
            .ssl()
            .peer_certificate()
            .and_then(|c| c.to_der().ok())
    } else {
        None
    };

    // HTTP/2 handshake with per-browser Akamai H2 settings + custom `http2_options` parity
    let mut h2_builder = http2::client::Builder::new();
    apply_h2_fingerprint(&mut h2_builder, &spec.preset, spec.http2_config.as_ref());

    let (mut send_req, conn) = h2_builder
        .handshake::<_, Bytes>(tls_stream)
        .await
        .map_err(|e| format!("[connect] HTTP/2 handshake over TCP ECH failed: {e}"))?;

    // Keep `tcp_ctx` (and its keylog CString) alive for the full lifetime of the HTTP/2 connection.
    let conn_guard = AbortOnDrop(tokio::spawn(async move {
        let _keep_ctx_alive = tcp_ctx;
        let _ = conn.await;
    }));

    let path_and_query = match current_url.query() {
        Some(q) => format!("{}?{}", current_url.path(), q),
        None => current_url.path().to_string(),
    };
    let authority = match current_url.port() {
        Some(p) if p != 443 => format!("{host}:{p}"),
        _ => host.clone(),
    };
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(if path_and_query.is_empty() { "/" } else { &path_and_query })
        .build()
        .map_err(|e| format!("[request] Invalid URI: {e}"))?;
    let method = http::Method::from_bytes(method_str.as_bytes())
        .map_err(|e| format!("[request] Invalid HTTP method '{method_str}': {e}"))?;

    let mut merged = spec.headers.clone();
    let jar_cookies: Vec<String> = jar
        .matches(current_url.as_str())
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect();
    if !jar_cookies.is_empty() {
        let jar_hdr = jar_cookies.join("; ");
        if let Some(pos) = merged.iter().position(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
            let ex = merged[pos].1.trim().to_string();
            merged[pos].1 = if ex.is_empty() { jar_hdr } else { format!("{jar_hdr}; {ex}") };
        } else {
            merged.push(("cookie".to_string(), jar_hdr));
        }
    }
    if let Some(ref order) = spec.header_order {
        merged.sort_by_key(|(k, _)| {
            order
                .iter()
                .position(|o| o.eq_ignore_ascii_case(k))
                .unwrap_or(usize::MAX)
        });
    }

    let mut req_b = http::Request::builder().method(method).uri(uri);
    for (k, v) in &merged {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || (body_opt.is_none()
                && (k.eq_ignore_ascii_case("content-length")
                    || ((method_str == "GET" || method_str == "HEAD")
                        && k.eq_ignore_ascii_case("content-type"))))
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(v),
        ) {
            req_b = req_b.header(hn, hv);
        }
    }
    let req = req_b
        .body(())
        .map_err(|e| format!("[request] HTTP/2 request build failed: {e}"))?;

    let has_body = body_opt.map(|b| !b.is_empty()).unwrap_or(false);
    let (resp_fut, mut send_stream) = send_req
        .send_request(req, !has_body)
        .map_err(|e| format!("[request] HTTP/2 send_request failed: {e}"))?;

    if let Some(body) = body_opt {
        if !body.is_empty() {
            send_stream
                .send_data(Bytes::copy_from_slice(body), true)
                .map_err(|e| format!("[request] HTTP/2 send_data failed: {e}"))?;
        }
    }

    let resp = resp_fut
        .await
        .map_err(|e| format!("[request] HTTP/2 response failed: {e}"))?;

    let status_code = resp.status().as_u16();
    let mut wreq_headers = HeaderMap::new();
    let mut headers_map: HashMap<String, String> = HashMap::new();
    let mut content_encoding: Option<String> = None;

    for (name, value) in resp.headers() {
        let name_s = name.as_str().to_string();
        let val_s = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if name_s.eq_ignore_ascii_case("set-cookie") {
            jar.add(val_s.clone(), current_url.as_str());
        }
        if name_s.eq_ignore_ascii_case("content-encoding") {
            content_encoding = Some(val_s.clone());
        }
        if let (Ok(wn), Ok(wv)) = (
            HeaderName::from_str(&name_s),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            wreq_headers.append(wn, wv);
        }
        match headers_map.get_mut(&name_s) {
            Some(ex) => {
                ex.push_str(", ");
                ex.push_str(&val_s);
            }
            None => {
                headers_map.insert(name_s, val_s);
            }
        }
    }

    Ok(OpenTcpHop {
        status_code,
        wreq_headers,
        headers_map,
        content_encoding,
        remote_addr: Some(remote_sa.to_string()),
        peer_certificate: peer_cert_der,
        ech_accepted,
        tls_resumed,
        recv_stream: resp.into_body(),
        conn_guard,
    })
}

pub async fn execute_tcp_ech_request(
    mut spec: TcpEchSpec,
    jar: Arc<Jar>,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> Result<TcpEchOutcome, String> {
    let start = Instant::now();
    let total_timeout = spec.timeout;
    let fut = async {
        let mut current_url = spec.url.clone();
        let mut current_method = spec.method.to_uppercase();
        let mut current_body = spec.body.clone();
        let mut history = Vec::new();

        for hop in 0..=spec.max_redirects {
            let mut open = open_tcp_ech_single_hop(
                &spec,
                &current_url,
                &current_method,
                current_body.as_deref(),
                &jar,
                &ech_cache,
                &ticket_cache,
                doh_resolver.as_ref(),
                doh_client.as_ref(),
            )
            .await?;

            let is_redir = matches!(open.status_code, 301 | 302 | 303 | 307 | 308);
            if spec.allow_redirects && is_redir {
                if let Some(loc) = open
                    .wreq_headers
                    .get(wreq::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    if hop >= spec.max_redirects {
                        return Err(format!(
                            "[redirect] Too many redirects (max {})",
                            spec.max_redirects
                        ));
                    }
                    let next_url = current_url
                        .join(loc)
                        .map_err(|e| format!("[request] Invalid redirect URL '{loc}': {e}"))?;
                    history.push((
                        open.status_code,
                        current_url.to_string(),
                        next_url.to_string(),
                        open.headers_map,
                    ));
                    let stripped_body = open.status_code == 303
                        || ((open.status_code == 301 || open.status_code == 302)
                            && current_method != "GET"
                            && current_method != "HEAD");
                    if stripped_body {
                        current_method = "GET".to_string();
                        current_body = None;
                    }
                    crate::sanitize_redirect_headers(
                        &mut spec.headers,
                        &current_url,
                        &next_url,
                        stripped_body,
                    );
                    drop(open.conn_guard);
                    current_url = next_url;
                    continue;
                }
            }

            let mut raw_body = Vec::new();
            while let Some(chunk_res) = open.recv_stream.data().await {
                let chunk = chunk_res.map_err(|e| format!("[request] HTTP/2 body read failed: {e}"))?;
                let _ = open.recv_stream.flow_control().release_capacity(chunk.len());
                raw_body.extend_from_slice(&chunk);
            }

            return Ok(TcpEchOutcome {
                status_code: open.status_code,
                wreq_headers: open.wreq_headers,
                headers_map: open.headers_map,
                content_encoding: open.content_encoding,
                raw_body,
                final_url: current_url.to_string(),
                remote_addr: open.remote_addr,
                peer_certificate: open.peer_certificate,
                history,
                ech_accepted: open.ech_accepted,
                tls_resumed: open.tls_resumed,
                elapsed: start.elapsed().as_secs_f64(),
            });
        }
        Err("[redirect] Too many redirects".to_string())
    };

    tokio::time::timeout(total_timeout, fut)
        .await
        .map_err(|_| "[timeout] TCP ECH request timed out".to_string())?
}

#[allow(dead_code)]
pub async fn execute_tcp_ech_stream(
    mut spec: TcpEchSpec,
    jar: Arc<Jar>,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> Result<TcpEchStreamOutcome, String> {
    let start = Instant::now();
    let total_timeout = spec.timeout;
    let open_fut = async {
        let mut current_url = spec.url.clone();
        let mut current_method = spec.method.to_uppercase();
        let mut current_body = spec.body.clone();
        let mut history = Vec::new();

        for hop in 0..=spec.max_redirects {
            let open = open_tcp_ech_single_hop(
                &spec,
                &current_url,
                &current_method,
                current_body.as_deref(),
                &jar,
                &ech_cache,
                &ticket_cache,
                doh_resolver.as_ref(),
                doh_client.as_ref(),
            )
            .await?;

            let is_redir = matches!(open.status_code, 301 | 302 | 303 | 307 | 308);
            if spec.allow_redirects && is_redir {
                if let Some(loc) = open
                    .wreq_headers
                    .get(wreq::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    if hop >= spec.max_redirects {
                        return Err(format!(
                            "[redirect] Too many redirects (max {})",
                            spec.max_redirects
                        ));
                    }
                    let next_url = current_url
                        .join(loc)
                        .map_err(|e| format!("[request] Invalid redirect URL '{loc}': {e}"))?;
                    history.push((
                        open.status_code,
                        current_url.to_string(),
                        next_url.to_string(),
                        open.headers_map,
                    ));
                    let stripped_body = open.status_code == 303
                        || ((open.status_code == 301 || open.status_code == 302)
                            && current_method != "GET"
                            && current_method != "HEAD");
                    if stripped_body {
                        current_method = "GET".to_string();
                        current_body = None;
                    }
                    crate::sanitize_redirect_headers(
                        &mut spec.headers,
                        &current_url,
                        &next_url,
                        stripped_body,
                    );
                    drop(open.conn_guard);
                    current_url = next_url;
                    continue;
                }
            }

            let decoder = H3StreamDecoder::from_encoding(open.content_encoding.as_deref());
            let body_stream: TcpEchBodyStream = Box::pin(futures_util::stream::unfold(
                (open.recv_stream, Some(decoder), open.conn_guard),
                |(mut recv, mut dec_opt, conn_guard)| async move {
                    let dec = dec_opt.as_mut()?;
                    loop {
                        match recv.data().await {
                            Some(Ok(chunk)) => {
                                let _ = recv.flow_control().release_capacity(chunk.len());
                                if chunk.is_empty() {
                                    continue;
                                }
                                let out = match dec {
                                    H3StreamDecoder::Identity => chunk,
                                    _ => dec.push(&chunk),
                                };
                                if !out.is_empty() {
                                    return Some((Ok(out), (recv, dec_opt, conn_guard)));
                                }
                            }
                            None => {
                                let finished = dec_opt.take().map(|d| d.finish()).unwrap_or_default();
                                if !finished.is_empty() {
                                    return Some((Ok(finished), (recv, None, conn_guard)));
                                }
                                return None;
                            }
                            Some(Err(e)) => {
                                dec_opt.take();
                                return Some((
                                    Err(format!("[request] HTTP/2 body read failed: {e}")),
                                    (recv, None, conn_guard),
                                ));
                            }
                        }
                    }
                },
            ));

            return Ok(TcpEchStreamOutcome {
                status_code: open.status_code,
                wreq_headers: open.wreq_headers,
                headers_map: open.headers_map,
                final_url: current_url.to_string(),
                remote_addr: open.remote_addr,
                peer_certificate: open.peer_certificate,
                history,
                ech_accepted: open.ech_accepted,
                tls_resumed: open.tls_resumed,
                elapsed: start.elapsed().as_secs_f64(),
                body_stream,
            });
        }
        Err("[redirect] Too many redirects".to_string())
    };

    tokio::time::timeout(total_timeout, open_fut)
        .await
        .map_err(|_| "[timeout] TCP ECH stream timed out".to_string())?
}
