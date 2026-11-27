// Language: Rust 2021 | File: src/options.rs | Target: Custom BoringSSL TLS, HTTP/2, JA3/Akamai H2, OrigHeaderMap & DNS Resolve Option Parsers
use crate::error::{CoreError, CoreResult};
use crate::safe_duration;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::{PyDict, PyList};
use serde_json::{Map, Value};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use wreq::header::OrigHeaderMap;
use wreq::http2::{
    Http2Options, Priorities, Priority, PseudoId, PseudoOrder, SettingId, SettingsOrder,
    StreamDependency, StreamId,
};
use wreq::tls::compress::CertificateCompressor;
use wreq::tls::{AlpnProtocol, AlpsProtocol, ExtensionType, TlsOptions, TlsVersion};
use wreq_util::emulate::compress::{BrotliCompressor, ZlibCompressor, ZstdCompressor};

/// Pure-Rust mirror of custom HTTP/2 fingerprint settings so both `wreq` and the
/// direct BoringSSL TCP ECH HTTP/2 transport (`src/tcp_ech.rs`) enforce identical
/// Akamai HTTP/2 frames (`SETTINGS` order, `WINDOW_UPDATE`, pseudo-header order, priorities).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RawHttp2Config {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: Option<bool>,
    pub no_rfc7540_priorities: Option<bool>,
    pub initial_stream_id: Option<u32>,
    pub settings_order: Option<Vec<u16>>,
    /// Encoded pseudo-header order: 0=Method, 1=Authority, 2=Scheme, 3=Path.
    pub headers_pseudo_order: Option<Vec<u8>>,
    /// `(stream_id, weight, exclusive)`
    pub headers_stream_dependency: Option<(u32, u8, bool)>,
    /// `[(stream_id, dependency_id, weight, exclusive)]`
    pub priorities: Option<Vec<(u32, u32, u8, bool)>>,
}

/// Optional QUIC transport & HTTP/3 framing overrides (`quic_options`).
#[derive(Clone, Debug, Default)]
pub(crate) struct QuicOptions {
    pub receive_window: Option<u32>,
    pub stream_receive_window: Option<u32>,
    pub send_window: Option<u64>,
    pub max_concurrent_bidi_streams: Option<u32>,
    pub max_concurrent_uni_streams: Option<u32>,
    pub max_idle_timeout: Option<Duration>,
    pub keep_alive_interval: Option<Duration>,
    pub send_grease: Option<bool>,
    pub max_field_section_size: Option<u64>,
    pub enable_datagram: Option<bool>,
    pub enable_extended_connect: Option<bool>,
}

fn setting_id_to_u16(id: SettingId) -> u16 {
    match id {
        SettingId::HeaderTableSize => 1,
        SettingId::EnablePush => 2,
        SettingId::MaxConcurrentStreams => 3,
        SettingId::InitialWindowSize => 4,
        SettingId::MaxFrameSize => 5,
        SettingId::MaxHeaderListSize => 6,
        SettingId::EnableConnectProtocol => 8,
        SettingId::NoRfc7540Priorities => 9,
        _ => 0,
    }
}

fn pseudo_id_to_u8(id: PseudoId) -> u8 {
    match id {
        PseudoId::Method => 0,
        PseudoId::Authority => 1,
        PseudoId::Scheme => 2,
        PseudoId::Path => 3,
        _ => 0,
    }
}

fn parse_tls_version_core(s: &str) -> CoreResult<TlsVersion> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1.0" | "tls1.0" | "tls_1_0" => Ok(TlsVersion::TLS_1_0),
        "1.1" | "tls1.1" | "tls_1_1" => Ok(TlsVersion::TLS_1_1),
        "1.2" | "tls1.2" | "tls_1_2" => Ok(TlsVersion::TLS_1_2),
        "1.3" | "tls1.3" | "tls_1_3" => Ok(TlsVersion::TLS_1_3),
        other => Err(CoreError::value(format!("Unsupported TLS version '{other}'"))),
    }
}

fn parse_setting_id_num(num: u16) -> CoreResult<SettingId> {
    match num {
        1 => Ok(SettingId::HeaderTableSize),
        2 => Ok(SettingId::EnablePush),
        3 => Ok(SettingId::MaxConcurrentStreams),
        4 => Ok(SettingId::InitialWindowSize),
        5 => Ok(SettingId::MaxFrameSize),
        6 => Ok(SettingId::MaxHeaderListSize),
        8 => Ok(SettingId::EnableConnectProtocol),
        9 => Ok(SettingId::NoRfc7540Priorities),
        other => Err(CoreError::value(format!("Unsupported HTTP/2 setting id {other}"))),
    }
}

fn parse_setting_id_str(name: &str) -> CoreResult<SettingId> {
    match name.trim().to_ascii_lowercase().as_str() {
        "1" | "header_table_size" => Ok(SettingId::HeaderTableSize),
        "2" | "enable_push" => Ok(SettingId::EnablePush),
        "3" | "max_concurrent_streams" => Ok(SettingId::MaxConcurrentStreams),
        "4" | "initial_window_size" => Ok(SettingId::InitialWindowSize),
        "5" | "max_frame_size" => Ok(SettingId::MaxFrameSize),
        "6" | "max_header_list_size" => Ok(SettingId::MaxHeaderListSize),
        "8" | "enable_connect_protocol" => Ok(SettingId::EnableConnectProtocol),
        "9" | "no_rfc7540_priorities" => Ok(SettingId::NoRfc7540Priorities),
        other => Err(CoreError::value(format!("Unsupported HTTP/2 setting '{other}'"))),
    }
}

fn parse_pseudo_id_core(name: &str) -> CoreResult<PseudoId> {
    match name.trim().to_ascii_lowercase().as_str() {
        "m" | "method" | ":method" => Ok(PseudoId::Method),
        "a" | "authority" | ":authority" => Ok(PseudoId::Authority),
        "s" | "scheme" | ":scheme" => Ok(PseudoId::Scheme),
        "p" | "path" | ":path" => Ok(PseudoId::Path),
        other => Err(CoreError::value(format!("Unsupported HTTP/2 pseudo-header '{other}'"))),
    }
}

pub(crate) fn build_orig_headers(order: &[String]) -> OrigHeaderMap {
    let mut map = OrigHeaderMap::new();
    for name in order {
        map.insert(name.clone());
    }
    map
}

// ---------------------------------------------------------------------------
// Pure Rust JSON Option Builders (used by C-ABI FFI)
// ---------------------------------------------------------------------------
fn json_str_list(v: &Value, field: &str) -> CoreResult<Vec<String>> {
    let arr = v
        .as_array()
        .ok_or_else(|| CoreError::value(format!("'{field}' must be an array of strings")))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| CoreError::value(format!("'{field}' elements must be strings")))?;
        out.push(s.to_string());
    }
    Ok(out)
}

#[allow(dead_code)]
pub(crate) fn parse_tls_options_json(v: &Value) -> CoreResult<TlsOptions> {
    let obj = v
        .as_object()
        .ok_or_else(|| CoreError::value("tls_options must be a JSON object"))?;
    let mut b = TlsOptions::builder();
    if let Some(s) = obj.get("cipher_list").and_then(Value::as_str) {
        b = b.cipher_list(s.to_string());
    }
    if let Some(s) = obj.get("curves_list").and_then(Value::as_str) {
        b = b.curves_list(s.to_string());
    }
    if let Some(s) = obj.get("sigalgs_list").and_then(Value::as_str) {
        b = b.sigalgs_list(s.to_string());
    }
    if let Some(alpn) = obj.get("alpn") {
        let mut protos = Vec::new();
        for p in json_str_list(alpn, "alpn")? {
            match p.trim().to_ascii_lowercase().as_str() {
                "h2" | "http2" | "http/2" => protos.push(AlpnProtocol::HTTP2),
                "http/1.1" | "http1" | "h1" => protos.push(AlpnProtocol::HTTP1),
                "h3" | "http3" | "http/3" => protos.push(AlpnProtocol::HTTP3),
                other => return Err(CoreError::value(format!("Unsupported ALPN protocol '{other}'"))),
            }
        }
        b = b.alpn_protocols(protos);
    }
    if let Some(s) = obj.get("min_tls_version").and_then(Value::as_str) {
        b = b.min_tls_version(parse_tls_version_core(s)?);
    }
    if let Some(s) = obj.get("max_tls_version").and_then(Value::as_str) {
        b = b.max_tls_version(parse_tls_version_core(s)?);
    }
    if let Some(x) = obj.get("grease_enabled").and_then(Value::as_bool) {
        b = b.grease_enabled(x);
    }
    if let Some(x) = obj.get("permute_extensions").and_then(Value::as_bool) {
        b = b.permute_extensions(x);
    }
    if let Some(x) = obj.get("enable_ech_grease").and_then(Value::as_bool) {
        b = b.enable_ech_grease(x);
    }
    if let Some(x) = obj.get("enable_ocsp_stapling").and_then(Value::as_bool) {
        b = b.enable_ocsp_stapling(x);
    }
    if let Some(x) = obj.get("enable_signed_cert_timestamps").and_then(Value::as_bool) {
        b = b.enable_signed_cert_timestamps(x);
    }
    if let Some(x) = obj.get("alps_use_new_codepoint").and_then(Value::as_bool) {
        b = b.alps_use_new_codepoint(x);
    }
    if let Some(x) = obj.get("session_ticket").and_then(Value::as_bool) {
        b = b.session_ticket(x);
    }
    if let Some(x) = obj.get("pre_shared_key").and_then(Value::as_bool) {
        b = b.pre_shared_key(x);
    }
    if let Some(x) = obj.get("preserve_tls13_cipher_list").and_then(Value::as_bool) {
        b = b.preserve_tls13_cipher_list(x);
    }
    if let Some(alps) = obj.get("alps_protocols") {
        let mut protos = Vec::new();
        for p in json_str_list(alps, "alps_protocols")? {
            match p.trim().to_ascii_lowercase().as_str() {
                "h2" | "http2" | "http/2" => protos.push(AlpsProtocol::HTTP2),
                "http/1.1" | "http1" | "h1" => protos.push(AlpsProtocol::HTTP1),
                "h3" | "http3" | "http/3" => protos.push(AlpsProtocol::HTTP3),
                other => return Err(CoreError::value(format!("Unsupported ALPS protocol '{other}'"))),
            }
        }
        b = b.alps_protocols(protos);
    }
    if let Some(n) = obj.get("record_size_limit").and_then(Value::as_u64) {
        let v = u16::try_from(n)
            .map_err(|_| CoreError::value(format!("record_size_limit {n} out of u16 range")))?;
        b = b.record_size_limit(v);
    }
    if let Some(s) = obj.get("delegated_credentials").and_then(Value::as_str) {
        b = b.delegated_credentials(s.to_string());
    }
    if let Some(x) = obj.get("psk_skip_session_ticket").and_then(Value::as_bool) {
        b = b.psk_skip_session_ticket(x);
    }
    if let Some(x) = obj.get("psk_dhe_ke").and_then(Value::as_bool) {
        b = b.psk_dhe_ke(x);
    }
    if let Some(x) = obj.get("renegotiation").and_then(Value::as_bool) {
        b = b.renegotiation(x);
    }
    if let Some(x) = obj.get("aes_hw_override").and_then(Value::as_bool) {
        b = b.aes_hw_override(x);
    }
    if let Some(x) = obj.get("random_aes_hw_override").and_then(Value::as_bool) {
        b = b.random_aes_hw_override(x);
    }
    if let Some(cc) = obj.get("certificate_compressors") {
        let mut comps: Vec<&'static dyn CertificateCompressor> = Vec::new();
        for c in json_str_list(cc, "certificate_compressors")? {
            match c.trim().to_ascii_lowercase().as_str() {
                "brotli" | "br" => comps.push(&BrotliCompressor),
                "zlib" | "deflate" => comps.push(&ZlibCompressor),
                "zstd" => comps.push(&ZstdCompressor),
                other => return Err(CoreError::value(format!("Unsupported certificate compressor '{other}'"))),
            }
        }
        b = b.certificate_compressors(comps);
    }
    if let Some(ext_arr) = obj.get("extension_permutation").and_then(Value::as_array) {
        let mut exts = Vec::with_capacity(ext_arr.len());
        for item in ext_arr {
            let id = item
                .as_u64()
                .ok_or_else(|| CoreError::value("extension_permutation elements must be integers"))?;
            let id16 = u16::try_from(id).map_err(|_| {
                CoreError::value(format!("extension_permutation id {id} out of u16 range"))
            })?;
            exts.push(ExtensionType::from(id16));
        }
        b = b.extension_permutation(exts);
    }
    Ok(b.build())
}

#[allow(dead_code)]
pub(crate) fn parse_http2_options_json(v: &Value) -> CoreResult<(Http2Options, RawHttp2Config)> {
    let obj = v
        .as_object()
        .ok_or_else(|| CoreError::value("http2_options must be a JSON object"))?;
    let mut b = Http2Options::builder();
    let mut raw = RawHttp2Config::default();
    if let Some(n) = obj.get("header_table_size").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("header_table_size out of u32 range"))?;
        b = b.header_table_size(v32);
        raw.header_table_size = Some(v32);
    }
    if let Some(x) = obj.get("enable_push").and_then(Value::as_bool) {
        b = b.enable_push(x);
        raw.enable_push = Some(x);
    }
    if let Some(n) = obj.get("max_concurrent_streams").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("max_concurrent_streams out of u32 range"))?;
        b = b.max_concurrent_streams(v32);
        raw.max_concurrent_streams = Some(v32);
    }
    if let Some(n) = obj.get("initial_window_size").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("initial_window_size out of u32 range"))?;
        b = b.initial_window_size(v32);
        raw.initial_window_size = Some(v32);
    }
    if let Some(n) = obj.get("initial_connection_window_size").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("initial_connection_window_size out of u32 range"))?;
        b = b.initial_connection_window_size(v32);
        raw.initial_connection_window_size = Some(v32);
    }
    if let Some(n) = obj.get("max_frame_size").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("max_frame_size out of u32 range"))?;
        b = b.max_frame_size(v32);
        raw.max_frame_size = Some(v32);
    }
    if let Some(n) = obj.get("max_header_list_size").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("max_header_list_size out of u32 range"))?;
        b = b.max_header_list_size(v32);
        raw.max_header_list_size = Some(v32);
    }
    if let Some(x) = obj.get("enable_connect_protocol").and_then(Value::as_bool) {
        b = b.enable_connect_protocol(x);
        raw.enable_connect_protocol = Some(x);
    }
    if let Some(x) = obj.get("no_rfc7540_priorities").and_then(Value::as_bool) {
        b = b.no_rfc7540_priorities(x);
        raw.no_rfc7540_priorities = Some(x);
    }
    if let Some(n) = obj.get("initial_stream_id").and_then(Value::as_u64) {
        let v32 = u32::try_from(n).map_err(|_| CoreError::value("initial_stream_id out of u32 range"))?;
        b = b.initial_stream_id(v32);
        raw.initial_stream_id = Some(v32);
    }
    if let Some(x) = obj.get("adaptive_window").and_then(Value::as_bool) {
        b = b.adaptive_window(x);
    }
    if let Some(n) = obj.get("max_send_buf_size").and_then(Value::as_u64) {
        b = b.max_send_buf_size(n as usize);
    }
    if let Some(n) = obj.get("keep_alive_interval").and_then(Value::as_f64) {
        b = b.keep_alive_interval(safe_duration(n, 0.1, 86_400.0));
    }
    if let Some(n) = obj.get("keep_alive_timeout").and_then(Value::as_f64) {
        b = b.keep_alive_timeout(safe_duration(n, 0.1, 86_400.0));
    }
    if let Some(x) = obj.get("keep_alive_while_idle").and_then(Value::as_bool) {
        b = b.keep_alive_while_idle(x);
    }
    if let Some(arr) = obj.get("settings_order").and_then(Value::as_array) {
        let mut ids = Vec::with_capacity(arr.len());
        let mut raw_ids = Vec::with_capacity(arr.len());
        for item in arr {
            let sid = if let Some(num) = item.as_u64() {
                let n16 = u16::try_from(num).map_err(|_| {
                    CoreError::value(format!("Unsupported HTTP/2 setting id {num}"))
                })?;
                parse_setting_id_num(n16)?
            } else if let Some(s) = item.as_str() {
                parse_setting_id_str(s)?
            } else {
                return Err(CoreError::value("settings_order elements must be integers or strings"));
            };
            raw_ids.push(setting_id_to_u16(sid));
            ids.push(sid);
        }
        b = b.settings_order(SettingsOrder::builder().extend(ids).build());
        raw.settings_order = Some(raw_ids);
    }
    if let Some(pseudo) = obj.get("headers_pseudo_order") {
        let mut ids = Vec::new();
        let mut raw_ids = Vec::new();
        for name in json_str_list(pseudo, "headers_pseudo_order")? {
            let pid = parse_pseudo_id_core(&name)?;
            raw_ids.push(pseudo_id_to_u8(pid));
            ids.push(pid);
        }
        b = b.headers_pseudo_order(PseudoOrder::builder().extend(ids).build());
        raw.headers_pseudo_order = Some(raw_ids);
    }
    if let Some(dep) = obj.get("headers_stream_dependency").and_then(Value::as_object) {
        let dep_id = dep
            .get("stream_id")
            .or_else(|| dep.get("dependency_id"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let weight = dep.get("weight").and_then(Value::as_u64).unwrap_or(219) as u8;
        let exclusive = dep.get("exclusive").and_then(Value::as_bool).unwrap_or(true);
        b = b.headers_stream_dependency(StreamDependency::new(StreamId::from(dep_id), weight, exclusive));
        raw.headers_stream_dependency = Some((dep_id, weight, exclusive));
    }
    if let Some(arr) = obj.get("priorities").and_then(Value::as_array) {
        let mut pb = Priorities::builder();
        let mut raw_prios = Vec::with_capacity(arr.len());
        for item in arr {
            let pd = item
                .as_object()
                .ok_or_else(|| CoreError::value("priorities entries must be objects"))?;
            let sid = pd
                .get("stream_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| CoreError::value("priority entry requires 'stream_id'"))? as u32;
            let dep_id = pd.get("dependency_id").and_then(Value::as_u64).unwrap_or(0) as u32;
            let weight = pd.get("weight").and_then(Value::as_u64).unwrap_or(0) as u8;
            let exclusive = pd.get("exclusive").and_then(Value::as_bool).unwrap_or(false);
            pb = pb.push(Priority::new(
                StreamId::from(sid),
                StreamDependency::new(StreamId::from(dep_id), weight, exclusive),
            ));
            raw_prios.push((sid, dep_id, weight, exclusive));
        }
        b = b.priorities(pb.build());
        raw.priorities = Some(raw_prios);
    }
    Ok((b.build(), raw))
}

#[allow(dead_code)]
pub(crate) fn parse_quic_options_json(v: &Value) -> CoreResult<QuicOptions> {
    let obj = v
        .as_object()
        .ok_or_else(|| CoreError::value("quic_options must be a JSON object"))?;
    let mut q = QuicOptions::default();
    if let Some(n) = obj.get("receive_window") {
        let val = n
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .filter(|&x| x >= 1024)
            .ok_or_else(|| CoreError::value("quic_options.receive_window must be an integer >= 1024 and <= u32::MAX"))?;
        q.receive_window = Some(val);
    }
    if let Some(n) = obj.get("stream_receive_window") {
        let val = n
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .filter(|&x| x >= 1024)
            .ok_or_else(|| CoreError::value("quic_options.stream_receive_window must be an integer >= 1024 and <= u32::MAX"))?;
        q.stream_receive_window = Some(val);
    }
    if let Some(n) = obj.get("send_window") {
        let val = n
            .as_u64()
            .filter(|&x| x >= 1024)
            .ok_or_else(|| CoreError::value("quic_options.send_window must be an integer >= 1024"))?;
        q.send_window = Some(val);
    }
    if let Some(n) = obj.get("max_concurrent_bidi_streams") {
        let val = n
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .filter(|&x| x >= 1)
            .ok_or_else(|| CoreError::value("quic_options.max_concurrent_bidi_streams must be >= 1 and <= u32::MAX"))?;
        q.max_concurrent_bidi_streams = Some(val);
    }
    if let Some(n) = obj.get("max_concurrent_uni_streams") {
        let val = n
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .filter(|&x| x >= 1)
            .ok_or_else(|| CoreError::value("quic_options.max_concurrent_uni_streams must be >= 1 and <= u32::MAX"))?;
        q.max_concurrent_uni_streams = Some(val);
    }
    if let Some(n) = obj.get("max_idle_timeout") {
        let secs = n
            .as_f64()
            .ok_or_else(|| CoreError::value("quic_options.max_idle_timeout must be a number (seconds)"))?;
        q.max_idle_timeout = Some(safe_duration(secs, 0.5, 3600.0));
    }
    if let Some(n) = obj.get("keep_alive_interval") {
        let secs = n
            .as_f64()
            .ok_or_else(|| CoreError::value("quic_options.keep_alive_interval must be a number (seconds)"))?;
        q.keep_alive_interval = Some(safe_duration(secs, 0.5, 3600.0));
    }
    if let Some(x) = obj.get("send_grease") {
        q.send_grease = Some(
            x.as_bool()
                .ok_or_else(|| CoreError::value("quic_options.send_grease must be a boolean"))?,
        );
    }
    if let Some(n) = obj.get("max_field_section_size") {
        let val = n
            .as_u64()
            .filter(|&x| x >= 1024)
            .ok_or_else(|| CoreError::value("quic_options.max_field_section_size must be an integer >= 1024"))?;
        q.max_field_section_size = Some(val);
    }
    if let Some(x) = obj.get("enable_datagram") {
        q.enable_datagram = Some(
            x.as_bool()
                .ok_or_else(|| CoreError::value("quic_options.enable_datagram must be a boolean"))?,
        );
    }
    if let Some(x) = obj.get("enable_extended_connect") {
        q.enable_extended_connect = Some(
            x.as_bool()
                .ok_or_else(|| CoreError::value("quic_options.enable_extended_connect must be a boolean"))?,
        );
    }
    Ok(q)
}

#[allow(dead_code)]
pub(crate) fn parse_resolve_map_json(v: &Value) -> CoreResult<Vec<(String, Vec<SocketAddr>)>> {
    let obj = v
        .as_object()
        .ok_or_else(|| CoreError::value("resolve must be a JSON object mapping domain -> ip or [ips]"))?;
    let mut out = Vec::with_capacity(obj.len());
    for (domain, val) in obj {
        let raw_list: Vec<String> = if let Some(s) = val.as_str() {
            vec![s.to_string()]
        } else {
            json_str_list(val, domain)?
        };
        let mut addrs = Vec::with_capacity(raw_list.len());
        for entry in raw_list {
            let sa = if let Ok(s) = SocketAddr::from_str(&entry) {
                s
            } else if let Ok(ip) = IpAddr::from_str(&entry) {
                SocketAddr::new(ip, 0)
            } else {
                return Err(CoreError::value(format!(
                    "Invalid IP/SocketAddr '{entry}' for resolve['{domain}']"
                )));
            };
            addrs.push(sa);
        }
        out.push((domain.clone(), addrs));
    }
    Ok(out)
}

/// Translate a standard 5-field JA3 string into a `tls_options` JSON object.
#[allow(dead_code)]
pub(crate) fn parse_ja3_to_tls_json(ja3: &str) -> CoreResult<Map<String, Value>> {
    let parts: Vec<&str> = ja3.trim().split(',').collect();
    if parts.len() != 5 {
        return Err(CoreError::value(
            "Invalid JA3 string: expected 5 comma-separated fields",
        ));
    }
    let mut opts = Map::new();
    if let Ok(ver) = parts[0].trim().parse::<u16>() {
        let v_str = match ver {
            769 => Some("1.0"),
            770 => Some("1.1"),
            771 => Some("1.2"),
            772 => Some("1.3"),
            _ => None,
        };
        if let Some(vs) = v_str {
            opts.insert("min_tls_version".to_string(), Value::String(vs.to_string()));
        }
    }
    if !parts[1].is_empty() {
        let mut mapped = Vec::new();
        for c in parts[1].split('-') {
            if let Ok(code) = c.trim().parse::<u16>() {
                let name = match code {
                    4865 => Some("TLS_AES_128_GCM_SHA256"),
                    4866 => Some("TLS_AES_256_GCM_SHA384"),
                    4867 => Some("TLS_CHACHA20_POLY1305_SHA256"),
                    49195 => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
                    49196 => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
                    49199 => Some("ECDHE-RSA-AES128-GCM-SHA256"),
                    49200 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
                    52392 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
                    52393 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
                    49171 => Some("ECDHE-RSA-AES128-SHA"),
                    49172 => Some("ECDHE-RSA-AES256-SHA"),
                    49161 => Some("ECDHE-ECDSA-AES128-SHA"),
                    49162 => Some("ECDHE-ECDSA-AES256-SHA"),
                    156 => Some("AES128-GCM-SHA256"),
                    157 => Some("AES256-GCM-SHA384"),
                    47 => Some("AES128-SHA"),
                    53 => Some("AES256-SHA"),
                    _ => None,
                };
                if let Some(n) = name {
                    mapped.push(n);
                }
            }
        }
        if !mapped.is_empty() {
            opts.insert("cipher_list".to_string(), Value::String(mapped.join(":")));
        }
    }
    if !parts[3].is_empty() {
        let mut mapped = Vec::new();
        for c in parts[3].split('-') {
            if let Ok(code) = c.trim().parse::<u16>() {
                let name = match code {
                    4588 => Some("X25519MLKEM768"),
                    25497 => Some("X25519Kyber768Draft00"),
                    29 => Some("X25519"),
                    23 => Some("P-256"),
                    24 => Some("P-384"),
                    25 => Some("P-521"),
                    _ => None,
                };
                if let Some(n) = name {
                    mapped.push(n);
                }
            }
        }
        if !mapped.is_empty() {
            opts.insert("curves_list".to_string(), Value::String(mapped.join(":")));
        }
    }
    Ok(opts)
}

/// Translate an Akamai HTTP/2 fingerprint string (`SETTINGS|WINDOW_UPDATE|PRIORITIES|PSEUDO_ORDER`)
/// into an `http2_options` JSON object.
#[allow(dead_code)]
pub(crate) fn parse_akamai_h2_to_http2_json(akamai_fp: &str) -> CoreResult<Map<String, Value>> {
    let parts: Vec<&str> = akamai_fp.trim().split('|').collect();
    if parts.len() != 4 {
        return Err(CoreError::value(
            "Invalid Akamai HTTP/2 fingerprint: expected 4 pipe-separated fields (SETTINGS|WINDOW_UPDATE|PRIORITIES|PSEUDO_ORDER)",
        ));
    }
    let mut opts = Map::new();
    let (settings_s, win_s, prio_s, pseudo_s) = (parts[0], parts[1], parts[2], parts[3]);

    if !settings_s.is_empty() {
        let mut order = Vec::new();
        for pair in settings_s.split(';') {
            let pair = pair.trim();
            let Some((sid_s, val_s)) = pair.split_once(':') else {
                continue;
            };
            let sid: u16 = sid_s
                .trim()
                .parse()
                .map_err(|_| CoreError::value(format!("Invalid Akamai setting id '{sid_s}'")))?;
            let val: u64 = val_s
                .trim()
                .parse()
                .map_err(|_| CoreError::value(format!("Invalid Akamai setting value '{val_s}'")))?;
            let key = match sid {
                1 => "header_table_size",
                2 => "enable_push",
                3 => "max_concurrent_streams",
                4 => "initial_window_size",
                5 => "max_frame_size",
                6 => "max_header_list_size",
                8 => "enable_connect_protocol",
                9 => "no_rfc7540_priorities",
                _ => continue,
            };
            order.push(Value::from(sid));
            if matches!(key, "enable_push" | "enable_connect_protocol" | "no_rfc7540_priorities") {
                opts.insert(key.to_string(), Value::Bool(val != 0));
            } else {
                opts.insert(key.to_string(), Value::from(val));
            }
        }
        if !order.is_empty() {
            opts.insert("settings_order".to_string(), Value::Array(order));
        }
    }

    let win_trim = win_s.trim();
    if !win_trim.is_empty() && win_trim != "0" && win_trim != "00" {
        let win_update: u64 = win_trim
            .parse()
            .map_err(|_| CoreError::value(format!("Invalid Akamai window update '{win_trim}'")))?;
        opts.insert(
            "initial_connection_window_size".to_string(),
            Value::from(win_update + 65535),
        );
    }

    let prio_trim = prio_s.trim();
    if !prio_trim.is_empty() && prio_trim != "0" {
        let mut prios = Vec::new();
        for entry in prio_trim.split(',') {
            let fields: Vec<&str> = entry.trim().split(':').collect();
            if fields.len() == 4 {
                if let (Ok(sid), Ok(excl), Ok(dep), Ok(w)) = (
                    fields[0].parse::<u32>(),
                    fields[1].parse::<u32>(),
                    fields[2].parse::<u32>(),
                    fields[3].parse::<u32>(),
                ) {
                    let mut obj = Map::new();
                    obj.insert("stream_id".to_string(), Value::from(sid));
                    obj.insert("exclusive".to_string(), Value::Bool(excl != 0));
                    obj.insert("dependency_id".to_string(), Value::from(dep));
                    obj.insert("weight".to_string(), Value::from(w.saturating_sub(1).min(255)));
                    prios.push(Value::Object(obj));
                }
            }
        }
        if !prios.is_empty() {
            opts.insert("priorities".to_string(), Value::Array(prios));
        }
    }

    if !pseudo_s.is_empty() {
        let pseudo: Vec<Value> = pseudo_s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect();
        if !pseudo.is_empty() {
            opts.insert("headers_pseudo_order".to_string(), Value::Array(pseudo));
        }
    }
    Ok(opts)
}

// ---------------------------------------------------------------------------
// PyO3 Option Builders (compiled only with `feature = "python"`)
// ---------------------------------------------------------------------------
#[cfg(feature = "python")]
fn parse_tls_version(s: &str) -> PyResult<TlsVersion> {
    parse_tls_version_core(s).map_err(Into::into)
}

#[cfg(feature = "python")]
pub(crate) fn parse_tls_options(d: &Bound<'_, PyDict>) -> PyResult<TlsOptions> {
    let mut b = TlsOptions::builder();
    if let Some(v) = d.get_item("cipher_list")? {
        b = b.cipher_list(v.extract::<String>()?);
    }
    if let Some(v) = d.get_item("curves_list")? {
        b = b.curves_list(v.extract::<String>()?);
    }
    if let Some(v) = d.get_item("sigalgs_list")? {
        b = b.sigalgs_list(v.extract::<String>()?);
    }
    if let Some(v) = d.get_item("alpn")? {
        let items: Vec<String> = v.extract()?;
        let mut protos = Vec::new();
        for p in items {
            match p.trim().to_ascii_lowercase().as_str() {
                "h2" | "http2" | "http/2" => protos.push(AlpnProtocol::HTTP2),
                "http/1.1" | "http1" | "h1" => protos.push(AlpnProtocol::HTTP1),
                "h3" | "http3" | "http/3" => protos.push(AlpnProtocol::HTTP3),
                other => return Err(PyValueError::new_err(format!("Unsupported ALPN protocol '{other}'"))),
            }
        }
        b = b.alpn_protocols(protos);
    }
    if let Some(v) = d.get_item("min_tls_version")? {
        b = b.min_tls_version(parse_tls_version(&v.extract::<String>()?)?);
    }
    if let Some(v) = d.get_item("max_tls_version")? {
        b = b.max_tls_version(parse_tls_version(&v.extract::<String>()?)?);
    }
    if let Some(v) = d.get_item("grease_enabled")? {
        b = b.grease_enabled(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("permute_extensions")? {
        b = b.permute_extensions(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("enable_ech_grease")? {
        b = b.enable_ech_grease(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("enable_ocsp_stapling")? {
        b = b.enable_ocsp_stapling(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("enable_signed_cert_timestamps")? {
        b = b.enable_signed_cert_timestamps(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("alps_use_new_codepoint")? {
        b = b.alps_use_new_codepoint(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("session_ticket")? {
        b = b.session_ticket(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("pre_shared_key")? {
        b = b.pre_shared_key(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("preserve_tls13_cipher_list")? {
        b = b.preserve_tls13_cipher_list(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("alps_protocols")? {
        let items: Vec<String> = v.extract()?;
        let mut protos = Vec::with_capacity(items.len());
        for p in items {
            match p.trim().to_ascii_lowercase().as_str() {
                "h2" | "http2" | "http/2" => protos.push(AlpsProtocol::HTTP2),
                "http/1.1" | "http1" | "h1" => protos.push(AlpsProtocol::HTTP1),
                "h3" | "http3" | "http/3" => protos.push(AlpsProtocol::HTTP3),
                other => return Err(PyValueError::new_err(format!("Unsupported ALPS protocol '{other}'"))),
            }
        }
        b = b.alps_protocols(protos);
    }
    if let Some(v) = d.get_item("record_size_limit")? {
        b = b.record_size_limit(v.extract::<u16>()?);
    }
    if let Some(v) = d.get_item("delegated_credentials")? {
        b = b.delegated_credentials(v.extract::<String>()?);
    }
    if let Some(v) = d.get_item("psk_skip_session_ticket")? {
        b = b.psk_skip_session_ticket(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("psk_dhe_ke")? {
        b = b.psk_dhe_ke(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("renegotiation")? {
        b = b.renegotiation(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("aes_hw_override")? {
        b = b.aes_hw_override(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("random_aes_hw_override")? {
        b = b.random_aes_hw_override(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("certificate_compressors")? {
        let items: Vec<String> = v.extract()?;
        let mut comps: Vec<&'static dyn CertificateCompressor> = Vec::with_capacity(items.len());
        for c in items {
            match c.trim().to_ascii_lowercase().as_str() {
                "brotli" | "br" => comps.push(&BrotliCompressor),
                "zlib" | "deflate" => comps.push(&ZlibCompressor),
                "zstd" => comps.push(&ZstdCompressor),
                other => return Err(PyValueError::new_err(format!("Unsupported certificate compressor '{other}'"))),
            }
        }
        b = b.certificate_compressors(comps);
    }
    if let Some(v) = d.get_item("extension_permutation")? {
        let ids: Vec<u16> = v.extract()?;
        let exts: Vec<ExtensionType> = ids.into_iter().map(ExtensionType::from).collect();
        b = b.extension_permutation(exts);
    }
    Ok(b.build())
}

#[cfg(feature = "python")]
fn parse_setting_id(item: &Bound<'_, PyAny>) -> PyResult<SettingId> {
    if let Ok(num) = item.extract::<u16>() {
        return parse_setting_id_num(num).map_err(Into::into);
    }
    let name = item.extract::<String>()?;
    parse_setting_id_str(&name).map_err(Into::into)
}

#[cfg(feature = "python")]
fn parse_pseudo_id(name: &str) -> PyResult<PseudoId> {
    parse_pseudo_id_core(name).map_err(Into::into)
}

#[cfg(feature = "python")]
fn parse_stream_dependency(v: &Bound<'_, PyAny>) -> PyResult<(StreamDependency, (u32, u8, bool))> {
    if let Ok(d) = v.downcast::<PyDict>() {
        let dep_id: u32 = d
            .get_item("stream_id")?
            .or(d.get_item("dependency_id")?)
            .map(|x| x.extract())
            .transpose()?
            .unwrap_or(0);
        let weight: u8 = d
            .get_item("weight")?
            .map(|x| x.extract())
            .transpose()?
            .unwrap_or(219);
        let exclusive: bool = d
            .get_item("exclusive")?
            .map(|x| x.extract())
            .transpose()?
            .unwrap_or(true);
        return Ok((
            StreamDependency::new(StreamId::from(dep_id), weight, exclusive),
            (dep_id, weight, exclusive),
        ));
    }
    let (dep_id, weight, exclusive): (u32, u8, bool) = v.extract()?;
    Ok((
        StreamDependency::new(StreamId::from(dep_id), weight, exclusive),
        (dep_id, weight, exclusive),
    ))
}

#[cfg(feature = "python")]
pub(crate) fn parse_http2_options(
    d: &Bound<'_, PyDict>,
) -> PyResult<(Http2Options, RawHttp2Config)> {
    let mut b = Http2Options::builder();
    let mut raw = RawHttp2Config::default();
    if let Some(v) = d.get_item("header_table_size")? {
        let val = v.extract::<u32>()?;
        b = b.header_table_size(val);
        raw.header_table_size = Some(val);
    }
    if let Some(v) = d.get_item("enable_push")? {
        let val = v.extract::<bool>()?;
        b = b.enable_push(val);
        raw.enable_push = Some(val);
    }
    if let Some(v) = d.get_item("max_concurrent_streams")? {
        let val = v.extract::<u32>()?;
        b = b.max_concurrent_streams(val);
        raw.max_concurrent_streams = Some(val);
    }
    if let Some(v) = d.get_item("initial_window_size")? {
        let val = v.extract::<u32>()?;
        b = b.initial_window_size(val);
        raw.initial_window_size = Some(val);
    }
    if let Some(v) = d.get_item("initial_connection_window_size")? {
        let val = v.extract::<u32>()?;
        b = b.initial_connection_window_size(val);
        raw.initial_connection_window_size = Some(val);
    }
    if let Some(v) = d.get_item("max_frame_size")? {
        let val = v.extract::<u32>()?;
        b = b.max_frame_size(val);
        raw.max_frame_size = Some(val);
    }
    if let Some(v) = d.get_item("max_header_list_size")? {
        let val = v.extract::<u32>()?;
        b = b.max_header_list_size(val);
        raw.max_header_list_size = Some(val);
    }
    if let Some(v) = d.get_item("enable_connect_protocol")? {
        let val = v.extract::<bool>()?;
        b = b.enable_connect_protocol(val);
        raw.enable_connect_protocol = Some(val);
    }
    if let Some(v) = d.get_item("no_rfc7540_priorities")? {
        let val = v.extract::<bool>()?;
        b = b.no_rfc7540_priorities(val);
        raw.no_rfc7540_priorities = Some(val);
    }
    if let Some(v) = d.get_item("initial_stream_id")? {
        let val = v.extract::<u32>()?;
        b = b.initial_stream_id(val);
        raw.initial_stream_id = Some(val);
    }
    if let Some(v) = d.get_item("adaptive_window")? {
        b = b.adaptive_window(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("max_send_buf_size")? {
        b = b.max_send_buf_size(v.extract::<usize>()?);
    }
    if let Some(v) = d.get_item("keep_alive_interval")? {
        b = b.keep_alive_interval(safe_duration(v.extract::<f64>()?, 0.1, 86_400.0));
    }
    if let Some(v) = d.get_item("keep_alive_timeout")? {
        b = b.keep_alive_timeout(safe_duration(v.extract::<f64>()?, 0.1, 86_400.0));
    }
    if let Some(v) = d.get_item("keep_alive_while_idle")? {
        b = b.keep_alive_while_idle(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("settings_order")? {
        let seq = v.downcast::<PyList>()?;
        let mut ids = Vec::with_capacity(seq.len());
        let mut raw_ids = Vec::with_capacity(seq.len());
        for item in seq.iter() {
            let sid = parse_setting_id(&item)?;
            raw_ids.push(setting_id_to_u16(sid));
            ids.push(sid);
        }
        b = b.settings_order(SettingsOrder::builder().extend(ids).build());
        raw.settings_order = Some(raw_ids);
    }
    if let Some(v) = d.get_item("headers_pseudo_order")? {
        let names: Vec<String> = v.extract()?;
        let mut ids = Vec::with_capacity(names.len());
        let mut raw_ids = Vec::with_capacity(names.len());
        for name in names {
            let pid = parse_pseudo_id(&name)?;
            raw_ids.push(pseudo_id_to_u8(pid));
            ids.push(pid);
        }
        b = b.headers_pseudo_order(PseudoOrder::builder().extend(ids).build());
        raw.headers_pseudo_order = Some(raw_ids);
    }
    if let Some(v) = d.get_item("headers_stream_dependency")? {
        let (dep, raw_dep) = parse_stream_dependency(&v)?;
        b = b.headers_stream_dependency(dep);
        raw.headers_stream_dependency = Some(raw_dep);
    }
    if let Some(v) = d.get_item("priorities")? {
        let seq = v.downcast::<PyList>()?;
        let mut pb = Priorities::builder();
        let mut raw_prios = Vec::with_capacity(seq.len());
        for item in seq.iter() {
            let pd = item.downcast::<PyDict>()?;
            let sid: u32 = pd
                .get_item("stream_id")?
                .ok_or_else(|| PyValueError::new_err("priority entry requires 'stream_id'"))?
                .extract()?;
            let dep_id: u32 = pd
                .get_item("dependency_id")?
                .map(|x| x.extract())
                .transpose()?
                .unwrap_or(0);
            let weight: u8 = pd
                .get_item("weight")?
                .map(|x| x.extract())
                .transpose()?
                .unwrap_or(0);
            let exclusive: bool = pd
                .get_item("exclusive")?
                .map(|x| x.extract())
                .transpose()?
                .unwrap_or(false);
            pb = pb.push(Priority::new(
                StreamId::from(sid),
                StreamDependency::new(StreamId::from(dep_id), weight, exclusive),
            ));
            raw_prios.push((sid, dep_id, weight, exclusive));
        }
        b = b.priorities(pb.build());
        raw.priorities = Some(raw_prios);
    }
    Ok((b.build(), raw))
}

#[cfg(feature = "python")]
pub(crate) fn parse_quic_options(d: &Bound<'_, PyDict>) -> PyResult<QuicOptions> {
    let mut q = QuicOptions::default();
    if let Some(v) = d.get_item("receive_window")? {
        let val = v.extract::<u32>()?;
        if val < 1024 {
            return Err(PyValueError::new_err("quic_options.receive_window must be >= 1024"));
        }
        q.receive_window = Some(val);
    }
    if let Some(v) = d.get_item("stream_receive_window")? {
        let val = v.extract::<u32>()?;
        if val < 1024 {
            return Err(PyValueError::new_err("quic_options.stream_receive_window must be >= 1024"));
        }
        q.stream_receive_window = Some(val);
    }
    if let Some(v) = d.get_item("send_window")? {
        let val = v.extract::<u64>()?;
        if val < 1024 {
            return Err(PyValueError::new_err("quic_options.send_window must be >= 1024"));
        }
        q.send_window = Some(val);
    }
    if let Some(v) = d.get_item("max_concurrent_bidi_streams")? {
        let val = v.extract::<u32>()?;
        if val < 1 {
            return Err(PyValueError::new_err("quic_options.max_concurrent_bidi_streams must be >= 1"));
        }
        q.max_concurrent_bidi_streams = Some(val);
    }
    if let Some(v) = d.get_item("max_concurrent_uni_streams")? {
        let val = v.extract::<u32>()?;
        if val < 1 {
            return Err(PyValueError::new_err("quic_options.max_concurrent_uni_streams must be >= 1"));
        }
        q.max_concurrent_uni_streams = Some(val);
    }
    if let Some(v) = d.get_item("max_idle_timeout")? {
        q.max_idle_timeout = Some(safe_duration(v.extract::<f64>()?, 0.5, 3600.0));
    }
    if let Some(v) = d.get_item("keep_alive_interval")? {
        q.keep_alive_interval = Some(safe_duration(v.extract::<f64>()?, 0.5, 3600.0));
    }
    if let Some(v) = d.get_item("send_grease")? {
        q.send_grease = Some(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("max_field_section_size")? {
        let val = v.extract::<u64>()?;
        if val < 1024 {
            return Err(PyValueError::new_err("quic_options.max_field_section_size must be >= 1024"));
        }
        q.max_field_section_size = Some(val);
    }
    if let Some(v) = d.get_item("enable_datagram")? {
        q.enable_datagram = Some(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("enable_extended_connect")? {
        q.enable_extended_connect = Some(v.extract::<bool>()?);
    }
    Ok(q)
}

#[cfg(feature = "python")]
pub(crate) fn parse_resolve_map(d: &Bound<'_, PyDict>) -> PyResult<Vec<(String, Vec<SocketAddr>)>> {
    let mut out = Vec::new();
    for (k, v) in d {
        let domain = k.extract::<String>()?;
        let raw_list: Vec<String> = if let Ok(s) = v.extract::<String>() {
            vec![s]
        } else {
            v.extract::<Vec<String>>()?
        };
        let mut addrs = Vec::with_capacity(raw_list.len());
        for entry in raw_list {
            let sa = if let Ok(s) = SocketAddr::from_str(&entry) {
                s
            } else if let Ok(ip) = IpAddr::from_str(&entry) {
                SocketAddr::new(ip, 0)
            } else {
                return Err(PyValueError::new_err(format!(
                    "Invalid IP/SocketAddr '{entry}' for resolve['{domain}']"
                )));
            };
            addrs.push(sa);
        }
        out.push((domain, addrs));
    }
    Ok(out)
}
