// Language: Rust 2021 | File: src/h3_transport.rs | Target: Pure BoringSSL UDP QUIC HTTP/3 Transport, Multiplexed Pool & Incremental Streaming
use crate::doh::{fetch_ech_config_list, DohResolver, EchCache};
use crate::error::{CoreError, CoreResult};
use crate::options::QuicOptions;
use crate::presets::default_h3_browser_headers;
use crate::quic_boring::{self, TicketCache};
use crate::socks5_udp;
use crate::{
    charset_of, collect_cookies, decode_body, runtime, BodyStream, HistoryTuple, NativeResponse,
    NativeStream,
};

use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::Client;

#[derive(Clone)]
pub(crate) struct H3RequestSpec {
    pub(crate) method: String,
    pub(crate) url: url::Url,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) header_order: Option<Vec<String>>,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) allow_redirects: bool,
    pub(crate) max_redirects: usize,
    pub(crate) verify: bool,
    pub(crate) ca_bundle: Option<Vec<u8>>,
    pub(crate) identity_pair: Option<(Vec<u8>, Vec<u8>)>,
    pub(crate) resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    pub(crate) local_address: Option<IpAddr>,
    pub(crate) proxy: Option<String>,
    pub(crate) tls_info: bool,
    pub(crate) keylog_file: Option<String>,
    pub(crate) preset: String,
    pub(crate) ua_override: Option<String>,
    pub(crate) sec_ch_ua_override: Option<String>,
    pub(crate) alt_svc_port: Option<u16>,
    pub(crate) strict_h3: bool,
    pub(crate) ech: bool,
    pub(crate) ech_doh_url: String,
    pub(crate) ech_config_list: Option<Vec<u8>>,
    pub(crate) quic_options: Option<QuicOptions>,
}

pub(crate) fn decompress_h3_body(raw: Vec<u8>, content_encoding: Option<&str>) -> Vec<u8> {
    let enc = match content_encoding {
        Some(s) => s.trim().to_ascii_lowercase(),
        None => return raw,
    };
    if enc == "gzip" || enc == "x-gzip" {
        let mut dec = flate2::read::GzDecoder::new(&raw[..]);
        let mut out = Vec::new();
        if dec.read_to_end(&mut out).is_ok() {
            return out;
        }
    } else if enc == "deflate" {
        let mut dec = flate2::read::ZlibDecoder::new(&raw[..]);
        let mut out = Vec::new();
        if dec.read_to_end(&mut out).is_ok() {
            return out;
        }
        let mut raw_dec = flate2::read::DeflateDecoder::new(&raw[..]);
        out.clear();
        if raw_dec.read_to_end(&mut out).is_ok() {
            return out;
        }
    } else if enc == "br" {
        let mut dec = brotli::Decompressor::new(&raw[..], 4096);
        let mut out = Vec::new();
        if dec.read_to_end(&mut out).is_ok() {
            return out;
        }
    } else if enc == "zstd" {
        if let Ok(out) = zstd::stream::decode_all(&raw[..]) {
            return out;
        }
    }
    raw
}

#[allow(clippy::too_many_arguments)]
fn build_h3_client_config(
    preset: &str,
    verify: bool,
    ca_bundle: Option<&[u8]>,
    identity_pair: Option<&(Vec<u8>, Vec<u8>)>,
    keylog_file: Option<&str>,
    ech_config_list: Option<Vec<u8>>,
    ech_retry_out: Arc<Mutex<Option<Vec<u8>>>>,
    ticket_cache: TicketCache,
    ticket_key: String,
    quic_options: Option<&QuicOptions>,
) -> CoreResult<quinn::ClientConfig> {
    let boring_cfg = quic_boring::BoringQuicClientConfig::new(
        preset,
        verify,
        ca_bundle,
        identity_pair,
        keylog_file,
        ech_config_list,
        ech_retry_out,
        ticket_cache,
        ticket_key,
    )
    .map_err(|e| CoreError::runtime(format!("[builder] BoringSSL QUIC init failed: {e}")))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(boring_cfg));

    // Per-browser QUIC transport parameters (0x0039): Chrome/Edge/Opera vs Firefox vs Safari
    let lower = preset.trim().to_ascii_lowercase();
    let is_firefox = lower.starts_with("firefox") || lower.starts_with("tor");
    let is_safari = lower.starts_with("safari");

    let mut transport = quinn::TransportConfig::default();
    let idle_dur = quic_options
        .and_then(|q| q.max_idle_timeout)
        .unwrap_or_else(|| Duration::from_secs(30));
    if let Ok(idle) = idle_dur.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    let ka_dur = quic_options
        .and_then(|q| q.keep_alive_interval)
        .unwrap_or_else(|| Duration::from_secs(15));
    transport.keep_alive_interval(Some(ka_dur));
    if is_firefox {
        transport.receive_window(25_165_824u32.into());
        transport.stream_receive_window(12_582_912u32.into());
        transport.send_window(25_165_824);
        transport.max_concurrent_bidi_streams(16u32.into());
        transport.max_concurrent_uni_streams(16u32.into());
    } else if is_safari {
        transport.receive_window(16_777_216u32.into());
        transport.stream_receive_window(4_194_304u32.into());
        transport.send_window(16_777_216);
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(100u32.into());
    } else {
        transport.receive_window(15_728_640u32.into());
        transport.stream_receive_window(6_291_456u32.into());
        transport.send_window(15_728_640);
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.max_concurrent_uni_streams(103u32.into());
    }
    if let Some(q) = quic_options {
        if let Some(v) = q.receive_window {
            transport.receive_window(v.into());
        }
        if let Some(v) = q.stream_receive_window {
            transport.stream_receive_window(v.into());
        }
        if let Some(v) = q.send_window {
            transport.send_window(v);
        }
        if let Some(v) = q.max_concurrent_bidi_streams {
            transport.max_concurrent_bidi_streams(v.into());
        }
        if let Some(v) = q.max_concurrent_uni_streams {
            transport.max_concurrent_uni_streams(v.into());
        }
    }
    transport.send_fairness(false);
    client_cfg.transport_config(Arc::new(transport));

    Ok(client_cfg)
}

/// Build an RFC 9114 HTTP/3 client session builder with per-browser `SETTINGS` framing
/// (`SETTINGS` GREASE, `MAX_FIELD_SECTION_SIZE`, `H3_DATAGRAM`, `ENABLE_CONNECT_PROTOCOL`)
/// and optional `quic_options` overrides.
pub(crate) fn build_h3_session_builder(
    preset: &str,
    quic_options: Option<&QuicOptions>,
) -> h3::client::Builder {
    let lower = preset.trim().to_ascii_lowercase();
    let is_firefox = lower.starts_with("firefox") || lower.starts_with("tor");
    let is_safari = lower.starts_with("safari");

    let send_grease = quic_options.and_then(|q| q.send_grease).unwrap_or(true);
    let max_field_section = quic_options
        .and_then(|q| q.max_field_section_size)
        .unwrap_or(if is_firefox { 65_536 } else { 262_144 });
    let enable_datagram = quic_options
        .and_then(|q| q.enable_datagram)
        .unwrap_or(!is_safari);
    let enable_ext_connect = quic_options
        .and_then(|q| q.enable_extended_connect)
        .unwrap_or(!is_safari);

    let mut builder = h3::client::builder();
    builder
        .send_grease(send_grease)
        .max_field_section_size(max_field_section)
        .enable_datagram(enable_datagram)
        .enable_extended_connect(enable_ext_connect);
    builder
}

async fn resolve_h3_target(
    host: &str,
    port: u16,
    resolve_entries: &[(String, Vec<SocketAddr>)],
    doh_resolver: Option<&DohResolver>,
    prefer_ipv6: Option<bool>,
) -> CoreResult<SocketAddr> {
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
            .map_err(|e| CoreError::runtime(format!("[connect] DoH DNS lookup failed: {e}")));
    }
    let lookup_target = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = lookup_host(&lookup_target)
        .await
        .map_err(|e| CoreError::runtime(format!("[connect] DNS lookup failed for '{lookup_target}': {e}")))?
        .collect();
    if let Some(want_v6) = prefer_ipv6 {
        if let Some(&matched) = addrs.iter().find(|a| a.is_ipv6() == want_v6) {
            return Ok(matched);
        }
    }
    // Prefer IPv4 first when local_address is unspecified to avoid dual-stack UDP routing blackholes
    if let Some(&v4) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(v4);
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| CoreError::runtime(format!("[connect] No addresses resolved for '{lookup_target}'")))
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct H3PoolKey {
    host: String,
    port: u16,
    verify: bool,
    local_address: Option<IpAddr>,
    ca_hash: Option<Vec<u8>>,
    proxy: Option<String>,
    ech: bool,
}

pub(crate) struct PooledH3Conn {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_handle: tokio::task::JoinHandle<()>,
    remote_addr: Option<String>,
    peer_certificate: Option<Vec<u8>>,
    ech_accepted: bool,
    tls_resumed: bool,
}

impl PooledH3Conn {
    fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none() && !self.driver_handle.is_finished()
    }

    fn close(&self) {
        self.driver_handle.abort();
        self.endpoint.close(0u32.into(), b"close");
    }
}

#[derive(Default)]
pub(crate) struct H3PoolInner {
    pub(crate) conns: HashMap<H3PoolKey, PooledH3Conn>,
    dial_locks: HashMap<H3PoolKey, Arc<tokio::sync::Mutex<()>>>,
}

pub(crate) type H3Pool = Arc<tokio::sync::Mutex<H3PoolInner>>;

pub(crate) fn clear_h3_pool_sync(h3_pool: &H3Pool) {
    if let Ok(mut guard) = h3_pool.try_lock() {
        for (_, entry) in guard.conns.drain() {
            entry.close();
        }
        guard.dial_locks.clear();
        return;
    }
    let pool = Arc::clone(h3_pool);
    runtime().spawn(async move {
        let mut guard = pool.lock().await;
        for (_, entry) in guard.conns.drain() {
            entry.close();
        }
        guard.dial_locks.clear();
    });
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
async fn acquire_h3_conn(
    spec: &H3RequestSpec,
    host: &str,
    port: u16,
    h3_pool: &H3Pool,
    ech_cache: &EchCache,
    ticket_cache: &TicketCache,
    doh_resolver: Option<&DohResolver>,
    doh_client: Option<&Client>,
) -> CoreResult<(
    H3PoolKey,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    Option<String>,
    Option<Vec<u8>>,
    bool,
    bool,
    bool,
)> {
    let key = H3PoolKey {
        host: host.to_ascii_lowercase(),
        port,
        verify: spec.verify,
        local_address: spec.local_address,
        ca_hash: spec.ca_bundle.clone(),
        proxy: spec.proxy.clone(),
        ech: spec.ech || spec.ech_config_list.is_some(),
    };

    let dial_lock = {
        let mut pool = h3_pool.lock().await;
        if let Some(entry) = pool.conns.get(&key) {
            if entry.is_alive() {
                return Ok((
                    key,
                    entry.send_request.clone(),
                    entry.remote_addr.clone(),
                    entry.peer_certificate.clone(),
                    entry.ech_accepted,
                    entry.tls_resumed,
                    true,
                ));
            }
        }
        if let Some(stale) = pool.conns.remove(&key) {
            stale.close();
        }
        if pool.dial_locks.len() >= 64 && !pool.dial_locks.contains_key(&key) {
            pool.dial_locks.retain(|_, lk| Arc::strong_count(lk) > 1);
        }
        Arc::clone(
            pool.dial_locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };

    // Single-flight per-key dial lock prevents thundering-herd concurrent QUIC handshakes
    // from evicting each other's in-flight streams during cold bursts (e.g. `gather()`).
    let _dial_guard = dial_lock.lock().await;
    {
        let mut pool = h3_pool.lock().await;
        if let Some(entry) = pool.conns.get(&key) {
            if entry.is_alive() {
                return Ok((
                    key,
                    entry.send_request.clone(),
                    entry.remote_addr.clone(),
                    entry.peer_certificate.clone(),
                    entry.ech_accepted,
                    entry.tls_resumed,
                    true,
                ));
            }
        }
        if let Some(stale) = pool.conns.remove(&key) {
            stale.close();
        }
    }

    let prefer_v6 = spec.local_address.map(|ip| ip.is_ipv6());
    let remote_sa = resolve_h3_target(host, port, &spec.resolve_entries, doh_resolver, prefer_v6).await?;

    let mut active_ech: Option<Vec<u8>> = if let Some(ref explicit) = spec.ech_config_list {
        Some(explicit.clone())
    } else if spec.ech {
        if let Some(dc) = doh_client {
            fetch_ech_config_list(host, &spec.ech_doh_url, ech_cache, dc, spec.connect_timeout).await
        } else {
            None
        }
    } else {
        None
    };

    let clean_sni = host.trim_matches(|c| c == '[' || c == ']');
    let ticket_key = format!(
        "quic:{}:{}:{}:{}",
        clean_sni.to_ascii_lowercase(),
        port,
        spec.verify,
        active_ech.is_some()
    );
    let mut final_pair: Option<(quinn::Endpoint, quinn::Connection)> = None;
    let mut last_err: Option<CoreError> = None;

    // Up to 2 attempts: second attempt runs only if BoringSSL returns ECH retry configs.
    for ech_attempt in 0..2 {
        let ech_retry_out: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let client_cfg = build_h3_client_config(
            &spec.preset,
            spec.verify,
            spec.ca_bundle.as_deref(),
            spec.identity_pair.as_ref(),
            spec.keylog_file.as_deref(),
            active_ech.clone(),
            Arc::clone(&ech_retry_out),
            Arc::clone(ticket_cache),
            ticket_key.clone(),
            spec.quic_options.as_ref(),
        )?;

        let ep_cfg = quinn::EndpointConfig::new(Arc::new(quic_boring::BoringHmacKey::random()));
        let mut endpoint = if let Some(ref proxy_url) = spec.proxy {
            let socks5_sock = socks5_udp::Socks5UdpSocket::connect(
                proxy_url,
                spec.local_address,
                spec.connect_timeout,
            )
            .await
            .map_err(|e| {
                CoreError::runtime(format!(
                    "[connect] SOCKS5 UDP ASSOCIATE failed via '{proxy_url}': {e}"
                ))
            })?;
            quinn::Endpoint::new_with_abstract_socket(
                ep_cfg,
                None,
                Arc::new(socks5_sock),
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| {
                CoreError::runtime(format!(
                    "[connect] QUIC SOCKS5 endpoint init failed: {e}"
                ))
            })?
        } else {
            let bind_addr = match spec.local_address {
                Some(ip) => SocketAddr::new(ip, 0),
                None => {
                    if remote_sa.is_ipv6() {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                    } else {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                    }
                }
            };
            let udp_sock = std::net::UdpSocket::bind(bind_addr).map_err(|e| {
                CoreError::runtime(format!("[connect] UDP socket bind failed on {bind_addr}: {e}"))
            })?;
            quinn::Endpoint::new(ep_cfg, None, udp_sock, Arc::new(quinn::TokioRuntime)).map_err(|e| {
                CoreError::runtime(format!("[connect] QUIC endpoint init failed on {bind_addr}: {e}"))
            })?
        };
        endpoint.set_default_client_config(client_cfg);

        let connecting = endpoint
            .connect(remote_sa, clean_sni)
            .map_err(|e| CoreError::runtime(format!("[connect] QUIC connect init failed: {e}")))?;

        match tokio::time::timeout(spec.connect_timeout, connecting).await {
            Ok(Ok(c)) => {
                final_pair = Some((endpoint, c));
                break;
            }
            Ok(Err(e)) => {
                endpoint.close(0u32.into(), b"handshake_err");
                if ech_attempt == 0 {
                    let retry_cfg = ech_retry_out
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take();
                    if let Some(fresh) = retry_cfg {
                        ticket_cache
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&ticket_key);
                        let mut cache = ech_cache.lock().await;
                        cache.insert(
                            host.to_ascii_lowercase(),
                            (fresh.clone(), Instant::now() + Duration::from_secs(300)),
                        );
                        active_ech = Some(fresh);
                        continue;
                    }
                }
                let low = e.to_string().to_lowercase();
                let tag = if low.contains("certificate") || low.contains("tls") || low.contains("crypto") || low.contains("ech") {
                    "ssl"
                } else {
                    "connect"
                };
                last_err = Some(CoreError::runtime(format!("[{tag}] QUIC handshake failed: {e}")));
                break;
            }
            Err(_) => {
                endpoint.close(0u32.into(), b"timeout");
                last_err = Some(CoreError::runtime(
                    "[connect_timeout] QUIC UDP handshake timed out",
                ));
                break;
            }
        }
    }

    let (endpoint, conn) = match final_pair {
        Some(pair) => pair,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                CoreError::runtime("[connect] QUIC handshake failed")
            }));
        }
    };

    let remote_addr_str = Some(conn.remote_address().to_string());
    let (ech_accepted, tls_resumed) = conn
        .handshake_data()
        .and_then(|any| any.downcast::<quic_boring::BoringHandshakeData>().ok())
        .map(|d| (d.ech_accepted, d.tls_resumed))
        .unwrap_or((false, false));
    let peer_cert_der = if spec.tls_info {
        conn.peer_identity()
            .and_then(|any| any.downcast::<Vec<Vec<u8>>>().ok())
            .and_then(|certs| certs.into_iter().next())
    } else {
        None
    };

    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, send_request) = build_h3_session_builder(&spec.preset, spec.quic_options.as_ref())
        .build(quinn_conn)
        .await
        .map_err(|e| {
            endpoint.close(0u32.into(), b"h3_init_err");
            CoreError::runtime(format!("[connect] HTTP/3 session init failed: {e}"))
        })?;

    let driver_handle = tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let pooled_sr = send_request.clone();
    {
        let mut pool = h3_pool.lock().await;
        if pool.conns.len() >= 16 {
            for (_, old) in pool.conns.drain() {
                old.close();
            }
        }
        if let Some(existing) = pool.conns.get(&key) {
            if existing.is_alive() {
                // Keep the already-alive pooled connection intact; close the redundant one.
                driver_handle.abort();
                endpoint.close(0u32.into(), b"redundant");
                return Ok((
                    key,
                    existing.send_request.clone(),
                    existing.remote_addr.clone(),
                    existing.peer_certificate.clone(),
                    existing.ech_accepted,
                    existing.tls_resumed,
                    true,
                ));
            }
        }
        if let Some(prev) = pool.conns.insert(
            key.clone(),
            PooledH3Conn {
                endpoint,
                conn,
                send_request,
                driver_handle,
                remote_addr: remote_addr_str.clone(),
                peer_certificate: peer_cert_der.clone(),
                ech_accepted,
                tls_resumed,
            },
        ) {
            prev.close();
        }
    }

    Ok((
        key,
        pooled_sr,
        remote_addr_str,
        peer_cert_der,
        ech_accepted,
        tls_resumed,
        false,
    ))
}

#[allow(dead_code)]
#[derive(Clone, Default)]
pub(crate) struct SharedVec(Arc<Mutex<Vec<u8>>>);

#[allow(dead_code)]
impl SharedVec {
    fn drain_bytes(&self) -> Vec<u8> {
        let mut guard = self.0.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *guard)
    }
}

impl Write for SharedVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().unwrap_or_else(|p| p.into_inner());
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) enum H3StreamDecoder {
    Identity,
    Gzip(flate2::write::GzDecoder<SharedVec>, SharedVec),
    Zlib(flate2::write::ZlibDecoder<SharedVec>, SharedVec),
    Brotli(Box<brotli::DecompressorWriter<SharedVec>>, SharedVec),
    Zstd(zstd::stream::write::Decoder<'static, SharedVec>, SharedVec),
}

#[allow(dead_code)]
impl H3StreamDecoder {
    pub(crate) fn from_encoding(content_encoding: Option<&str>) -> Self {
        let enc = match content_encoding {
            Some(s) => s.trim().to_ascii_lowercase(),
            None => return Self::Identity,
        };
        if enc == "gzip" || enc == "x-gzip" {
            let sink = SharedVec::default();
            Self::Gzip(flate2::write::GzDecoder::new(sink.clone()), sink)
        } else if enc == "deflate" {
            let sink = SharedVec::default();
            Self::Zlib(flate2::write::ZlibDecoder::new(sink.clone()), sink)
        } else if enc == "br" {
            let sink = SharedVec::default();
            Self::Brotli(Box::new(brotli::DecompressorWriter::new(sink.clone(), 4096)), sink)
        } else if enc == "zstd" {
            let sink = SharedVec::default();
            match zstd::stream::write::Decoder::new(sink.clone()) {
                Ok(dec) => Self::Zstd(dec, sink),
                Err(_) => Self::Identity,
            }
        } else {
            Self::Identity
        }
    }

    pub(crate) fn push(&mut self, input: &[u8]) -> Bytes {
        if input.is_empty() {
            return Bytes::new();
        }
        match self {
            Self::Identity => Bytes::copy_from_slice(input),
            Self::Gzip(dec, sink) => {
                if dec.write_all(input).is_err() {
                    return Bytes::copy_from_slice(input);
                }
                let _ = dec.flush();
                Bytes::from(sink.drain_bytes())
            }
            Self::Zlib(dec, sink) => {
                if dec.write_all(input).is_err() {
                    return Bytes::copy_from_slice(input);
                }
                let _ = dec.flush();
                Bytes::from(sink.drain_bytes())
            }
            Self::Brotli(dec, sink) => {
                if dec.write_all(input).is_err() {
                    return Bytes::copy_from_slice(input);
                }
                let _ = dec.flush();
                Bytes::from(sink.drain_bytes())
            }
            Self::Zstd(dec, sink) => {
                if dec.write_all(input).is_err() {
                    return Bytes::copy_from_slice(input);
                }
                let _ = dec.flush();
                Bytes::from(sink.drain_bytes())
            }
        }
    }

    pub(crate) fn finish(self) -> Bytes {
        match self {
            Self::Identity => Bytes::new(),
            Self::Gzip(mut dec, sink) => {
                let _ = dec.try_finish();
                drop(dec);
                Bytes::from(sink.drain_bytes())
            }
            Self::Zlib(mut dec, sink) => {
                let _ = dec.try_finish();
                drop(dec);
                Bytes::from(sink.drain_bytes())
            }
            Self::Brotli(mut dec, sink) => {
                let _ = dec.flush();
                drop(dec);
                Bytes::from(sink.drain_bytes())
            }
            Self::Zstd(mut dec, sink) => {
                let _ = dec.flush();
                drop(dec);
                Bytes::from(sink.drain_bytes())
            }
        }
    }
}

type H3OpenHop = (
    u16,
    HeaderMap,
    HashMap<String, String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    bool,
    bool,
    h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
);

#[allow(clippy::too_many_arguments)]
async fn open_h3_single_hop(
    spec: &H3RequestSpec,
    current_url: &url::Url,
    method_str: &str,
    body_opt: Option<&[u8]>,
    jar: &Arc<Jar>,
    h3_pool: &H3Pool,
    ech_cache: &EchCache,
    ticket_cache: &TicketCache,
    doh_resolver: Option<&DohResolver>,
    doh_client: Option<&Client>,
    port_override: Option<u16>,
) -> CoreResult<H3OpenHop> {
    if current_url.scheme() != "https" {
        return Err(CoreError::runtime(
            "[connect] HTTP/3 (QUIC) requires an https:// URL",
        ));
    }
    let host = current_url
        .host_str()
        .ok_or_else(|| CoreError::value("HTTP/3 URL missing host"))?
        .to_string();
    let port = port_override.or_else(|| current_url.port()).unwrap_or(443);

    // Assemble request URI & browser-accurate headers once
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
        .map_err(|e| CoreError::value(format!("Invalid HTTP/3 URI: {e}")))?;

    let method = http::Method::from_bytes(method_str.as_bytes())
        .map_err(|e| CoreError::value(format!("Invalid HTTP method '{method_str}': {e}")))?;

    // Merge browser defaults + session/caller headers + cookie jar
    let defaults = default_h3_browser_headers(
        &spec.preset,
        spec.ua_override.as_deref(),
        spec.sec_ch_ua_override.as_deref(),
    );
    let mut merged: Vec<(String, String)> = Vec::new();
    for (dk, dv) in defaults {
        if !spec.headers.iter().any(|(ck, _)| ck.eq_ignore_ascii_case(&dk)) {
            merged.push((dk, dv));
        }
    }
    for (ck, cv) in &spec.headers {
        if let Some(pos) = merged.iter().position(|(k, _)| k.eq_ignore_ascii_case(ck)) {
            merged[pos] = (ck.clone(), cv.clone());
        } else {
            merged.push((ck.clone(), cv.clone()));
        }
    }

    // Attach cookies from shared RFC 6265 Jar
    let jar_cookies: Vec<String> = jar
        .matches(current_url.as_str())
        .map(|c| format!("{}={}", c.name(), c.value()))
        .collect();
    if !jar_cookies.is_empty() {
        let jar_hdr = jar_cookies.join("; ");
        if let Some(pos) = merged.iter().position(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
            let existing = merged[pos].1.trim().to_string();
            if existing.is_empty() {
                merged[pos].1 = jar_hdr;
            } else {
                merged[pos].1 = format!("{jar_hdr}; {existing}");
            }
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

    for attempt in 0..2 {
        let (key, mut send_request, remote_addr_str, peer_cert_der, ech_accepted, tls_resumed, reused) =
            acquire_h3_conn(
                spec,
                &host,
                port,
                h3_pool,
                ech_cache,
                ticket_cache,
                doh_resolver,
                doh_client,
            )
            .await?;

        let mut req_builder = http::Request::builder().method(method.clone()).uri(uri.clone());
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
                req_builder = req_builder.header(hn, hv);
            }
        }
        let req = req_builder
            .body(())
            .map_err(|e| CoreError::runtime(format!("[request] HTTP/3 request build error: {e}")))?;

        let mut stream = match send_request.send_request(req).await {
            Ok(s) => s,
            Err(e) => {
                if reused && attempt == 0 {
                    let mut pool = h3_pool.lock().await;
                    if let Some(stale) = pool.conns.remove(&key) {
                        stale.close();
                    }
                    continue;
                }
                return Err(CoreError::runtime(format!(
                    "[request] HTTP/3 send_request failed: {e}"
                )));
            }
        };

        if let Some(body_bytes) = body_opt {
            if !body_bytes.is_empty() {
                if let Err(e) = stream.send_data(Bytes::copy_from_slice(body_bytes)).await {
                    if reused && attempt == 0 {
                        let mut pool = h3_pool.lock().await;
                        if let Some(stale) = pool.conns.remove(&key) {
                            stale.close();
                        }
                        continue;
                    }
                    return Err(CoreError::runtime(format!(
                        "[request] HTTP/3 send_data failed: {e}"
                    )));
                }
            }
        }
        if let Err(e) = stream.finish().await {
            if reused && attempt == 0 {
                let mut pool = h3_pool.lock().await;
                if let Some(stale) = pool.conns.remove(&key) {
                    stale.close();
                }
                continue;
            }
            return Err(CoreError::runtime(format!(
                "[request] HTTP/3 stream finish failed: {e}"
            )));
        }

        let mut resp = match stream.recv_response().await {
            Ok(r) => r,
            Err(e) => {
                if reused && attempt == 0 {
                    let mut pool = h3_pool.lock().await;
                    if let Some(stale) = pool.conns.remove(&key) {
                        stale.close();
                    }
                    continue;
                }
                return Err(CoreError::runtime(format!(
                    "[request] HTTP/3 recv_response failed: {e}"
                )));
            }
        };

        // RFC 9110 / RFC 8297: skip interim 1xx frames (e.g. Cloudflare 103 Early Hints) until final headers.
        while resp.status().is_informational() && resp.status().as_u16() != 101 {
            resp = stream
                .recv_response()
                .await
                .map_err(|e| CoreError::runtime(format!("[request] HTTP/3 recv_response failed: {e}")))?;
        }

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
                Some(existing) => {
                    existing.push_str(", ");
                    existing.push_str(&val_s);
                }
                None => {
                    headers_map.insert(name_s, val_s);
                }
            }
        }

        return Ok((
            status_code,
            wreq_headers,
            headers_map,
            content_encoding,
            remote_addr_str,
            peer_cert_der,
            ech_accepted,
            tls_resumed,
            stream,
        ));
    }

    Err(CoreError::runtime("[connect] HTTP/3 connection retry exhausted"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_h3_request(
    mut spec: H3RequestSpec,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> CoreResult<NativeResponse> {
    let start = Instant::now();
    let total_timeout = spec.timeout;
    let fut = async {
        let mut current_url = spec.url.clone();
        let mut current_method = spec.method.to_uppercase();
        let mut current_body = spec.body.clone();
        let mut history: Vec<HistoryTuple> = Vec::new();
        let mut hop_port = spec.alt_svc_port;

        for hop in 0..=spec.max_redirects {
            let (
                status_code,
                wreq_hdrs,
                headers_map,
                content_encoding,
                remote_addr,
                peer_certificate,
                ech_accepted,
                tls_resumed,
                mut stream,
            ) = open_h3_single_hop(
                &spec,
                &current_url,
                &current_method,
                current_body.as_deref(),
                &jar,
                &h3_pool,
                &ech_cache,
                &ticket_cache,
                doh_resolver.as_ref(),
                doh_client.as_ref(),
                hop_port,
            )
            .await?;
            hop_port = None;

            let is_redir = matches!(status_code, 301 | 302 | 303 | 307 | 308);
            if spec.allow_redirects && is_redir {
                if let Some(loc) = wreq_hdrs
                    .get(wreq::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    if hop >= spec.max_redirects {
                        return Err(CoreError::runtime(format!(
                            "[redirect] Too many redirects (max {})",
                            spec.max_redirects
                        )));
                    }
                    let next_url = current_url.join(loc).map_err(|e| {
                        CoreError::value(format!("Invalid redirect URL '{loc}': {e}"))
                    })?;
                    history.push((
                        status_code,
                        current_url.to_string(),
                        next_url.to_string(),
                        headers_map,
                    ));
                    let stripped_body = status_code == 303
                        || ((status_code == 301 || status_code == 302)
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
                    drop(stream);
                    current_url = next_url;
                    continue;
                }
            }

            let mut raw_body = Vec::new();
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .map_err(|e| CoreError::runtime(format!("[request] HTTP/3 recv_data failed: {e}")))?
            {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    raw_body.extend_from_slice(slice);
                    let len = slice.len();
                    chunk.advance(len);
                }
            }
            let body_bytes = decompress_h3_body(raw_body, content_encoding.as_deref());

            let elapsed = start.elapsed().as_secs_f64();
            let final_url_str = current_url.to_string();
            let (text, encoding) = decode_body(&body_bytes, &wreq_hdrs);
            let cookies = collect_cookies(&jar, &final_url_str, &wreq_hdrs);
            return Ok(NativeResponse {
                status_code,
                headers: headers_map,
                cookies,
                url: final_url_str,
                content: body_bytes,
                text,
                encoding,
                elapsed,
                http_version: "HTTP/3".to_string(),
                remote_addr,
                peer_certificate,
                history,
                ech_accepted,
                tls_resumed,
            });
        }
        Err(CoreError::runtime("[redirect] Too many redirects"))
    };

    match tokio::time::timeout(total_timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(CoreError::runtime("[timeout] HTTP/3 request timed out")),
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) async fn execute_h3_stream(
    mut spec: H3RequestSpec,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> CoreResult<NativeStream> {
    let start = Instant::now();
    let total_timeout = spec.timeout;
    let open_fut = async {
        let mut current_url = spec.url.clone();
        let mut current_method = spec.method.to_uppercase();
        let mut current_body = spec.body.clone();
        let mut history: Vec<HistoryTuple> = Vec::new();
        let mut hop_port = spec.alt_svc_port;

        for hop in 0..=spec.max_redirects {
            let (
                status_code,
                wreq_hdrs,
                headers_map,
                content_encoding,
                remote_addr,
                peer_certificate,
                ech_accepted,
                tls_resumed,
                stream,
            ) = open_h3_single_hop(
                &spec,
                &current_url,
                &current_method,
                current_body.as_deref(),
                &jar,
                &h3_pool,
                &ech_cache,
                &ticket_cache,
                doh_resolver.as_ref(),
                doh_client.as_ref(),
                hop_port,
            )
            .await?;
            hop_port = None;

            let is_redir = matches!(status_code, 301 | 302 | 303 | 307 | 308);
            if spec.allow_redirects && is_redir {
                if let Some(loc) = wreq_hdrs
                    .get(wreq::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    if hop >= spec.max_redirects {
                        return Err(CoreError::runtime(format!(
                            "[redirect] Too many redirects (max {})",
                            spec.max_redirects
                        )));
                    }
                    let next_url = current_url.join(loc).map_err(|e| {
                        CoreError::value(format!("Invalid redirect URL '{loc}': {e}"))
                    })?;
                    history.push((
                        status_code,
                        current_url.to_string(),
                        next_url.to_string(),
                        headers_map,
                    ));
                    let stripped_body = status_code == 303
                        || ((status_code == 301 || status_code == 302)
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
                    drop(stream);
                    current_url = next_url;
                    continue;
                }
            }

            let elapsed = start.elapsed().as_secs_f64();
            let final_url_str = current_url.to_string();
            let encoding = charset_of(&wreq_hdrs)
                .map(|e| e.name().to_ascii_lowercase())
                .unwrap_or_default();
            let cookies = collect_cookies(&jar, &final_url_str, &wreq_hdrs);
            let decoder = H3StreamDecoder::from_encoding(content_encoding.as_deref());

            // Incremental QUIC DATA frame stream: zero whole-body buffering in RAM.
            let body_stream: BodyStream = Box::pin(futures_util::stream::unfold(
                (stream, Some(decoder)),
                |(mut req_stream, mut dec_opt)| async move {
                    let dec = dec_opt.as_mut()?;
                    loop {
                        match req_stream.recv_data().await {
                            Ok(Some(mut buf)) => {
                                let raw = buf.copy_to_bytes(buf.remaining());
                                if raw.is_empty() {
                                    continue;
                                }
                                let out = match dec {
                                    H3StreamDecoder::Identity => raw,
                                    _ => dec.push(&raw),
                                };
                                if !out.is_empty() {
                                    return Some((Ok(out), (req_stream, dec_opt)));
                                }
                            }
                            Ok(None) => {
                                let finished = dec_opt.take().map(|d| d.finish()).unwrap_or_default();
                                if !finished.is_empty() {
                                    return Some((Ok(finished), (req_stream, None)));
                                }
                                return None;
                            }
                            Err(e) => {
                                dec_opt.take();
                                return Some((
                                    Err(CoreError::runtime(format!(
                                        "[request] HTTP/3 recv_data failed: {e}"
                                    ))),
                                    (req_stream, None),
                                ));
                            }
                        }
                    }
                },
            ));

            return Ok(NativeStream {
                status_code,
                headers: headers_map,
                cookies,
                encoding,
                url: final_url_str,
                elapsed,
                http_version: "HTTP/3".to_string(),
                remote_addr,
                peer_certificate,
                history,
                ech_accepted,
                tls_resumed,
                inner: Arc::new(tokio::sync::Mutex::new(Some(body_stream))),
            });
        }
        Err(CoreError::runtime("[redirect] Too many redirects"))
    };

    match tokio::time::timeout(total_timeout, open_fut).await {
        Ok(res) => res,
        Err(_) => Err(CoreError::runtime("[timeout] HTTP/3 stream timed out")),
    }
}
