// Language: Rust 2021 | File: src/options.rs | Target: Custom BoringSSL TLS, HTTP/2, OrigHeaderMap & DNS Resolve Option Parsers
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
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

fn parse_tls_version(s: &str) -> PyResult<TlsVersion> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1.0" | "tls1.0" | "tls_1_0" => Ok(TlsVersion::TLS_1_0),
        "1.1" | "tls1.1" | "tls_1_1" => Ok(TlsVersion::TLS_1_1),
        "1.2" | "tls1.2" | "tls_1_2" => Ok(TlsVersion::TLS_1_2),
        "1.3" | "tls1.3" | "tls_1_3" => Ok(TlsVersion::TLS_1_3),
        other => Err(PyValueError::new_err(format!("Unsupported TLS version '{other}'"))),
    }
}

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

fn parse_setting_id(item: &Bound<'_, PyAny>) -> PyResult<SettingId> {
    if let Ok(num) = item.extract::<u16>() {
        return match num {
            1 => Ok(SettingId::HeaderTableSize),
            2 => Ok(SettingId::EnablePush),
            3 => Ok(SettingId::MaxConcurrentStreams),
            4 => Ok(SettingId::InitialWindowSize),
            5 => Ok(SettingId::MaxFrameSize),
            6 => Ok(SettingId::MaxHeaderListSize),
            8 => Ok(SettingId::EnableConnectProtocol),
            9 => Ok(SettingId::NoRfc7540Priorities),
            other => Err(PyValueError::new_err(format!("Unsupported HTTP/2 setting id {other}"))),
        };
    }
    let name = item.extract::<String>()?;
    match name.trim().to_ascii_lowercase().as_str() {
        "1" | "header_table_size" => Ok(SettingId::HeaderTableSize),
        "2" | "enable_push" => Ok(SettingId::EnablePush),
        "3" | "max_concurrent_streams" => Ok(SettingId::MaxConcurrentStreams),
        "4" | "initial_window_size" => Ok(SettingId::InitialWindowSize),
        "5" | "max_frame_size" => Ok(SettingId::MaxFrameSize),
        "6" | "max_header_list_size" => Ok(SettingId::MaxHeaderListSize),
        "8" | "enable_connect_protocol" => Ok(SettingId::EnableConnectProtocol),
        "9" | "no_rfc7540_priorities" => Ok(SettingId::NoRfc7540Priorities),
        other => Err(PyValueError::new_err(format!("Unsupported HTTP/2 setting '{other}'"))),
    }
}

fn parse_pseudo_id(name: &str) -> PyResult<PseudoId> {
    match name.trim().to_ascii_lowercase().as_str() {
        "m" | "method" | ":method" => Ok(PseudoId::Method),
        "a" | "authority" | ":authority" => Ok(PseudoId::Authority),
        "s" | "scheme" | ":scheme" => Ok(PseudoId::Scheme),
        "p" | "path" | ":path" => Ok(PseudoId::Path),
        other => Err(PyValueError::new_err(format!("Unsupported HTTP/2 pseudo-header '{other}'"))),
    }
}

fn parse_stream_dependency(v: &Bound<'_, PyAny>) -> PyResult<StreamDependency> {
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
        return Ok(StreamDependency::new(StreamId::from(dep_id), weight, exclusive));
    }
    let (dep_id, weight, exclusive): (u32, u8, bool) = v.extract()?;
    Ok(StreamDependency::new(StreamId::from(dep_id), weight, exclusive))
}

pub(crate) fn parse_http2_options(d: &Bound<'_, PyDict>) -> PyResult<Http2Options> {
    let mut b = Http2Options::builder();
    if let Some(v) = d.get_item("header_table_size")? {
        b = b.header_table_size(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("enable_push")? {
        b = b.enable_push(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("max_concurrent_streams")? {
        b = b.max_concurrent_streams(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("initial_window_size")? {
        b = b.initial_window_size(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("initial_connection_window_size")? {
        b = b.initial_connection_window_size(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("max_frame_size")? {
        b = b.max_frame_size(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("max_header_list_size")? {
        b = b.max_header_list_size(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("enable_connect_protocol")? {
        b = b.enable_connect_protocol(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("no_rfc7540_priorities")? {
        b = b.no_rfc7540_priorities(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("initial_stream_id")? {
        b = b.initial_stream_id(v.extract::<u32>()?);
    }
    if let Some(v) = d.get_item("adaptive_window")? {
        b = b.adaptive_window(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("max_send_buf_size")? {
        b = b.max_send_buf_size(v.extract::<usize>()?);
    }
    if let Some(v) = d.get_item("keep_alive_interval")? {
        b = b.keep_alive_interval(Duration::from_secs_f64(v.extract::<f64>()?.max(0.1)));
    }
    if let Some(v) = d.get_item("keep_alive_timeout")? {
        b = b.keep_alive_timeout(Duration::from_secs_f64(v.extract::<f64>()?.max(0.1)));
    }
    if let Some(v) = d.get_item("keep_alive_while_idle")? {
        b = b.keep_alive_while_idle(v.extract::<bool>()?);
    }
    if let Some(v) = d.get_item("settings_order")? {
        let seq = v.downcast::<PyList>()?;
        let mut ids = Vec::with_capacity(seq.len());
        for item in seq.iter() {
            ids.push(parse_setting_id(&item)?);
        }
        b = b.settings_order(SettingsOrder::builder().extend(ids).build());
    }
    if let Some(v) = d.get_item("headers_pseudo_order")? {
        let names: Vec<String> = v.extract()?;
        let mut ids = Vec::with_capacity(names.len());
        for name in names {
            ids.push(parse_pseudo_id(&name)?);
        }
        b = b.headers_pseudo_order(PseudoOrder::builder().extend(ids).build());
    }
    if let Some(v) = d.get_item("headers_stream_dependency")? {
        b = b.headers_stream_dependency(parse_stream_dependency(&v)?);
    }
    if let Some(v) = d.get_item("priorities")? {
        let seq = v.downcast::<PyList>()?;
        let mut pb = Priorities::builder();
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
        }
        b = b.priorities(pb.build());
    }
    Ok(b.build())
}

pub(crate) fn build_orig_headers(order: &[String]) -> OrigHeaderMap {
    let mut map = OrigHeaderMap::new();
    for name in order {
        map.insert(name.clone());
    }
    map
}

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
                return Err(PyValueError::new_err(format!("Invalid IP/SocketAddr '{entry}' for resolve['{domain}']")));
            };
            addrs.push(sa);
        }
        out.push((domain, addrs));
    }
    Ok(out)
}
