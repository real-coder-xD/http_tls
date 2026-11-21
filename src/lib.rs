// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 ABI3 Extension | Runtime: Tokio + wreq (BoringSSL) + quinn/h3 (UDP QUIC)
use bytes::{Buf, Bytes};
use encoding_rs::{Encoding, UTF_8};
use futures_util::{Stream, StreamExt};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap};
use wreq::http2::{
    Http2Options, Priorities, Priority, PseudoId, PseudoOrder, SettingId, SettingsOrder,
    StreamDependency, StreamId,
};
use wreq::multipart::{Form, Part};
use wreq::redirect::{History, Policy};
use wreq::tls::compress::CertificateCompressor;
use wreq::tls::keylog::KeyLog;
use wreq::tls::trust::{CertStore, Identity};
use wreq::tls::{AlpnProtocol, AlpsProtocol, ExtensionType, TlsInfo, TlsOptions, TlsVersion};
use wreq::ws::message::{CloseCode, Message};
use wreq::{Client, Method, Proxy, RequestBuilder, Version};
use wreq_util::emulate::compress::{BrotliCompressor, ZlibCompressor, ZstdCompressor};
use wreq_util::{Emulation, Platform, Profile};

type BodyStream = Pin<Box<dyn Stream<Item = wreq::Result<Bytes>> + Send + 'static>>;
type MultipartItem = (String, Option<String>, Vec<u8>, Option<String>);
type HistoryTuple = (u16, String, String, HashMap<String, String>);

// ---------------------------------------------------------------------------
// Shared Tokio runtime via pyo3-async-runtimes (used by both sync & async).
// ---------------------------------------------------------------------------
fn runtime() -> &'static tokio::runtime::Runtime {
    pyo3_async_runtimes::tokio::get_runtime()
}

// ---------------------------------------------------------------------------
// Error classification: "[kind] message" mapped to requests/httpx exceptions.
// ---------------------------------------------------------------------------
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

fn net_err(e: wreq::Error) -> PyErr {
    let chain = error_chain(&e);
    let low = chain.to_lowercase();
    let kind = if e.is_timeout() {
        if e.is_connect() { "connect_timeout" } else { "timeout" }
    } else if e.is_redirect() {
        "redirect"
    } else if e.is_tls()
        || low.contains("certificate")
        || low.contains("handshake")
        || low.contains("verify failed")
        || low.contains("ssl")
    {
        "ssl"
    } else if e.is_connect() || e.is_proxy_connect() || e.is_dns() || e.is_connection_reset() {
        "connect"
    } else {
        "request"
    };
    PyRuntimeError::new_err(format!("[{kind}] {chain}"))
}

// ---------------------------------------------------------------------------
// Preset -> BoringSSL Emulation + optional version-forward header patch.
// ---------------------------------------------------------------------------
struct ResolvedEmulation {
    emulation: Emulation,
    ua_override: Option<String>,
    sec_ch_ua_override: Option<String>,
}

fn platform_from_name(lower: &str) -> Platform {
    if lower.contains("android") {
        Platform::Android
    } else if lower.contains("ios") || lower.contains("ipad") {
        Platform::IOS
    } else if lower.contains("macos") || lower.contains("mac") || lower.starts_with("safari") {
        Platform::MacOS
    } else if lower.contains("linux") {
        Platform::Linux
    } else {
        Platform::Windows
    }
}

/// Deterministic Chromium `GetUserAgentBrandList` GREASE + brand permutation algorithm.
/// Used only when a caller explicitly requests a forward-aliased major version beyond native profiles.
fn chromium_sec_ch_ua(major: u32, brand: &str) -> String {
    const GREASE_CHARS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const GREASE_VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let seed = major as usize;
    let grease_brand = format!("Not{}A{}Brand", GREASE_CHARS[seed % 11], GREASE_CHARS[(seed + 1) % 11]);
    let grease_ver = GREASE_VERSIONS[seed % 3];
    let major_s = major.to_string();
    let brands = [
        (grease_brand.as_str(), grease_ver),
        ("Chromium", major_s.as_str()),
        (brand, major_s.as_str()),
    ];
    let order = ORDERS[seed % 6];
    let mut ordered = [("", ""); 3];
    for (i, &pos) in order.iter().enumerate() {
        ordered[pos] = brands[i];
    }
    format!(
        "\"{}\";v=\"{}\", \"{}\";v=\"{}\", \"{}\";v=\"{}\"",
        ordered[0].0, ordered[0].1, ordered[1].0, ordered[1].1, ordered[2].0, ordered[2].1
    )
}

fn resolve_emulation(preset: &str) -> ResolvedEmulation {
    let lower = preset.trim().to_lowercase().replace('-', "_");

    if lower == "random" {
        return ResolvedEmulation {
            emulation: Emulation::random(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }
    if lower == "weighted_random" || lower == "auto" {
        return ResolvedEmulation {
            emulation: Emulation::weighted_random(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }

    let platform = platform_from_name(&lower);

    if lower == "chrome" || lower == "default" {
        return ResolvedEmulation {
            emulation: Emulation::builder()
                .profile(Profile::Chrome149)
                .platform(Platform::Windows)
                .build(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }
    if lower.starts_with("chrome") {
        let digits: String = lower.chars().filter(|c| c.is_ascii_digit()).collect();
        let ver: u32 = digits.parse().unwrap_or(149);
        let profile = match ver {
            0..=100 => Profile::Chrome100,
            101..=103 => Profile::Chrome101,
            104 => Profile::Chrome104,
            105 => Profile::Chrome105,
            106 => Profile::Chrome106,
            107 => Profile::Chrome107,
            108 => Profile::Chrome108,
            109 => Profile::Chrome109,
            110..=113 => Profile::Chrome110,
            114..=115 => Profile::Chrome114,
            116 => Profile::Chrome116,
            117 => Profile::Chrome117,
            118 => Profile::Chrome118,
            119 => Profile::Chrome119,
            120..=122 => Profile::Chrome120,
            123 => Profile::Chrome123,
            124..=125 => Profile::Chrome124,
            126 => Profile::Chrome126,
            127 => Profile::Chrome127,
            128 => Profile::Chrome128,
            129 => Profile::Chrome129,
            130 => Profile::Chrome130,
            131 => Profile::Chrome131,
            132 => Profile::Chrome132,
            133 => Profile::Chrome133,
            134 => Profile::Chrome134,
            135 => Profile::Chrome135,
            136 => Profile::Chrome136,
            137 => Profile::Chrome137,
            138 => Profile::Chrome138,
            139 => Profile::Chrome139,
            140 => Profile::Chrome140,
            141 => Profile::Chrome141,
            142 => Profile::Chrome142,
            143 => Profile::Chrome143,
            144 => Profile::Chrome144,
            145 => Profile::Chrome145,
            146 => Profile::Chrome146,
            147 => Profile::Chrome147,
            148 => Profile::Chrome148,
            _ => Profile::Chrome149,
        };
        let (ua_ov, ch_ov) = if ver > 149 {
            let ua = match platform {
                Platform::MacOS => format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
                Platform::Linux => format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
                Platform::Android => format!("Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Mobile Safari/537.36"),
                _ => format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
            };
            let ch = chromium_sec_ch_ua(ver, "Google Chrome");
            (Some(ua), Some(ch))
        } else {
            (None, None)
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(platform).build(),
            ua_override: ua_ov,
            sec_ch_ua_override: ch_ov,
        };
    }

    if lower.starts_with("edge") {
        let digits: String = lower.chars().filter(|c| c.is_ascii_digit()).collect();
        let ver: u32 = digits.parse().unwrap_or(148);
        let profile = match ver {
            0..=110 => Profile::Edge101,
            111..=125 => Profile::Edge122,
            126..=129 => Profile::Edge127,
            130..=132 => Profile::Edge131,
            133..=134 => Profile::Edge134,
            135 => Profile::Edge135,
            136 => Profile::Edge136,
            137 => Profile::Edge137,
            138 => Profile::Edge138,
            139 => Profile::Edge139,
            140 => Profile::Edge140,
            141 => Profile::Edge141,
            142 => Profile::Edge142,
            143 => Profile::Edge143,
            144 => Profile::Edge144,
            145 => Profile::Edge145,
            146 => Profile::Edge146,
            147 => Profile::Edge147,
            _ => Profile::Edge148,
        };
        let (ua_ov, ch_ov) = if ver > 148 {
            let ua = format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36 Edg/{ver}.0.0.0");
            let ch = chromium_sec_ch_ua(ver, "Microsoft Edge");
            (Some(ua), Some(ch))
        } else {
            (None, None)
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(platform).build(),
            ua_override: ua_ov,
            sec_ch_ua_override: ch_ov,
        };
    }

    if lower.starts_with("firefox") || lower.starts_with("tor") {
        let digits: String = lower.chars().filter(|c| c.is_ascii_digit()).collect();
        let ver: u32 = if lower.starts_with("tor") { 128 } else { digits.parse().unwrap_or(151) };
        let profile = if lower.contains("android") {
            Profile::FirefoxAndroid135
        } else if lower.contains("private") && ver >= 136 {
            Profile::FirefoxPrivate136
        } else if lower.contains("private") {
            Profile::FirefoxPrivate135
        } else {
            match ver {
                0..=112 => Profile::Firefox109,
                113..=122 => Profile::Firefox117,
                123..=130 => Profile::Firefox128,
                131..=134 => Profile::Firefox133,
                135 => Profile::Firefox135,
                136..=138 => Profile::Firefox136,
                139..=141 => Profile::Firefox139,
                142 => Profile::Firefox142,
                143 => Profile::Firefox143,
                144 => Profile::Firefox144,
                145 => Profile::Firefox145,
                146 => Profile::Firefox146,
                147 => Profile::Firefox147,
                148 => Profile::Firefox148,
                149 => Profile::Firefox149,
                150 => Profile::Firefox150,
                _ => Profile::Firefox151,
            }
        };
        let ua_ov = if !lower.starts_with("tor") && ver > 151 {
            Some(format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"))
        } else {
            None
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(platform).build(),
            ua_override: ua_ov,
            sec_ch_ua_override: None,
        };
    }

    if lower.starts_with("safari") {
        let is_ios = lower.contains("ios");
        let is_ipad = lower.contains("ipad");
        let clean = lower
            .replace("safari", "")
            .replace("ios", "")
            .replace("ipad", "")
            .replace(['_', '.'], "");
        let profile = match (is_ios, is_ipad, clean.as_str()) {
            (true, _, s) if s.starts_with("262") => Profile::SafariIos26_2,
            (true, _, s) if s.starts_with("26") || s.starts_with("27") => Profile::SafariIos26,
            (true, _, s) if s.starts_with("18") => Profile::SafariIos18_1_1,
            (true, _, s) if s.starts_with("174") => Profile::SafariIos17_4_1,
            (true, _, s) if s.starts_with("17") => Profile::SafariIos17_2,
            (true, _, _) => Profile::SafariIos16_5,
            (_, true, s) if s.starts_with("262") => Profile::SafariIpad26_2,
            (_, true, s) if s.starts_with("26") || s.starts_with("27") => Profile::SafariIPad26,
            (_, true, _) => Profile::SafariIPad18,
            (_, _, s) if s.starts_with("153") => Profile::Safari15_3,
            (_, _, s) if s.starts_with("155") => Profile::Safari15_5,
            (_, _, s) if s.starts_with("156") => Profile::Safari15_6_1,
            (_, _, s) if s.starts_with("165") => Profile::Safari16_5,
            (_, _, s) if s.starts_with("16") => Profile::Safari16,
            (_, _, s) if s.starts_with("176") => Profile::Safari17_6,
            (_, _, s) if s.starts_with("175") => Profile::Safari17_5,
            (_, _, s) if s.starts_with("174") => Profile::Safari17_4_1,
            (_, _, s) if s.starts_with("172") => Profile::Safari17_2_1,
            (_, _, s) if s.starts_with("17") => Profile::Safari17_0,
            (_, _, s) if s.starts_with("185") || s.starts_with("184") => Profile::Safari18_5,
            (_, _, s) if s.starts_with("1831") => Profile::Safari18_3_1,
            (_, _, s) if s.starts_with("183") => Profile::Safari18_3,
            (_, _, s) if s.starts_with("182") => Profile::Safari18_2,
            (_, _, s) if s.starts_with("18") => Profile::Safari18,
            (_, _, s) if s.starts_with("261") => Profile::Safari26_1,
            (_, _, s) if s.starts_with("262") => Profile::Safari26_2,
            (_, _, s) if s.starts_with("263") => Profile::Safari26_3,
            (_, _, s) if s.starts_with("264") => Profile::Safari26_4,
            (_, _, s) if s.starts_with("26") => Profile::Safari26,
            _ => Profile::Safari26_4,
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(platform).build(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }

    if lower.starts_with("opera") {
        let digits: String = lower.chars().filter(|c| c.is_ascii_digit()).collect();
        let ver: u32 = digits.parse().unwrap_or(131);
        let profile = match ver {
            0..=116 => Profile::Opera116,
            117 => Profile::Opera117,
            118 => Profile::Opera118,
            119 => Profile::Opera119,
            120 => Profile::Opera120,
            121 => Profile::Opera121,
            122 => Profile::Opera122,
            123 => Profile::Opera123,
            124 => Profile::Opera124,
            125 => Profile::Opera125,
            126 => Profile::Opera126,
            127 => Profile::Opera127,
            128 => Profile::Opera128,
            129 => Profile::Opera129,
            130 => Profile::Opera130,
            _ => Profile::Opera131,
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(platform).build(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }

    if lower.starts_with("okhttp") {
        let clean = lower.replace("okhttp", "").replace(['_', '.'], "");
        let profile = match clean.as_str() {
            "39" => Profile::OkHttp3_9,
            "311" => Profile::OkHttp3_11,
            "313" => Profile::OkHttp3_13,
            "314" => Profile::OkHttp3_14,
            "49" => Profile::OkHttp4_9,
            "410" => Profile::OkHttp4_10,
            "412" => Profile::OkHttp4_12,
            _ => Profile::OkHttp5,
        };
        return ResolvedEmulation {
            emulation: Emulation::builder().profile(profile).platform(Platform::Android).build(),
            ua_override: None,
            sec_ch_ua_override: None,
        };
    }

    ResolvedEmulation {
        emulation: Emulation::builder()
            .profile(Profile::Chrome149)
            .platform(Platform::Windows)
            .build(),
        ua_override: None,
        sec_ch_ua_override: None,
    }
}

// ---------------------------------------------------------------------------
// Custom TLS & HTTP/2 options + OrigHeaderMap builders
// ---------------------------------------------------------------------------
fn parse_tls_version(s: &str) -> PyResult<TlsVersion> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1.0" | "tls1.0" | "tls_1_0" => Ok(TlsVersion::TLS_1_0),
        "1.1" | "tls1.1" | "tls_1_1" => Ok(TlsVersion::TLS_1_1),
        "1.2" | "tls1.2" | "tls_1_2" => Ok(TlsVersion::TLS_1_2),
        "1.3" | "tls1.3" | "tls_1_3" => Ok(TlsVersion::TLS_1_3),
        other => Err(PyValueError::new_err(format!("Unsupported TLS version '{other}'"))),
    }
}

fn parse_tls_options(d: &Bound<'_, PyDict>) -> PyResult<TlsOptions> {
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

fn parse_http2_options(d: &Bound<'_, PyDict>) -> PyResult<Http2Options> {
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

fn build_orig_headers(order: &[String]) -> OrigHeaderMap {
    let mut map = OrigHeaderMap::new();
    for name in order {
        map.insert(name.clone());
    }
    map
}

fn parse_resolve_map(d: &Bound<'_, PyDict>) -> PyResult<Vec<(String, Vec<SocketAddr>)>> {
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
fn version_str(v: Version) -> String {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
    .to_string()
}

fn collect_headers(h: &HeaderMap) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for (name, value) in h {
        let v = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match out.get_mut(name.as_str()) {
            Some(existing) => {
                existing.push_str(", ");
                existing.push_str(&v);
            }
            None => {
                out.insert(name.as_str().to_string(), v);
            }
        }
    }
    out
}

fn collect_cookies(jar: &Jar, uri_str: &str, h: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for c in jar.matches(uri_str) {
        out.insert(c.name().to_string(), c.value().to_string());
    }
    for raw in h.get_all(wreq::header::SET_COOKIE) {
        if let Ok(s) = raw.to_str() {
            if let Some((k, v)) = s.split(';').next().and_then(|p| p.split_once('=')) {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

fn collect_history(resp: &wreq::Response) -> Vec<HistoryTuple> {
    match resp.extensions().get::<History>() {
        None => Vec::new(),
        Some(h) => h
            .into_iter()
            .map(|e| {
                (
                    e.status.as_u16(),
                    e.previous.to_string(),
                    e.uri.to_string(),
                    collect_headers(&e.headers),
                )
            })
            .collect(),
    }
}

fn extract_peer_cert(resp: &wreq::Response) -> Option<Vec<u8>> {
    resp.extensions()
        .get::<TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .map(|b| b.to_vec())
}

fn charset_of(h: &HeaderMap) -> Option<&'static Encoding> {
    let ct = h.get(wreq::header::CONTENT_TYPE)?.to_str().ok()?.to_ascii_lowercase();
    let label = ct
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("charset="))?
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string();
    Encoding::for_label(label.as_bytes())
}

fn decode_body(bytes: &[u8], h: &HeaderMap) -> (String, String) {
    let enc = charset_of(h).unwrap_or(UTF_8);
    let (text, used, _) = enc.decode(bytes);
    (text.into_owned(), used.name().to_ascii_lowercase())
}

fn dict_pairs(d: Option<&Bound<'_, PyDict>>) -> PyResult<Vec<(String, String)>> {
    let mut v = Vec::new();
    if let Some(d) = d {
        for (k, val) in d {
            v.push((k.str()?.to_string(), val.str()?.to_string()));
        }
    }
    Ok(v)
}

fn parse_multipart_items(files: Option<&Bound<'_, PyList>>) -> PyResult<Vec<MultipartItem>> {
    let mut items = Vec::new();
    if let Some(list) = files {
        for entry in list.iter() {
            let tup = entry.downcast::<PyTuple>()?;
            if tup.len() != 4 {
                return Err(PyValueError::new_err("files entries must be (field, filename, bytes, content_type)"));
            }
            let field: String = tup.get_item(0)?.extract()?;
            let filename: Option<String> = tup.get_item(1)?.extract()?;
            let payload: Vec<u8> = tup.get_item(2)?.extract()?;
            let mime: Option<String> = tup.get_item(3)?.extract()?;
            items.push((field, filename, payload, mime));
        }
    }
    Ok(items)
}

fn build_cert_store(raw: &[u8]) -> PyResult<CertStore> {
    CertStore::from_pem_stack(raw)
        .or_else(|_| CertStore::from_der_certs([raw]))
        .map_err(|e| PyValueError::new_err(format!("Invalid CA bundle (expected PEM or DER): {}", error_chain(&e))))
}

fn build_identity(cert_pem: &[u8], key_pem: &[u8]) -> PyResult<Identity> {
    Identity::from_pkcs8_pem(cert_pem, key_pem)
        .map_err(|e| PyValueError::new_err(format!("Client certificate/key rejected: {}", error_chain(&e))))
}

// ---------------------------------------------------------------------------
// Native UDP QUIC / HTTP/3 Engine (quinn + h3 + h3-quinn + Chromium profile)
// ---------------------------------------------------------------------------
#[derive(Debug)]
struct NoCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
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
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Clone)]
struct H3RequestSpec {
    method: String,
    url: url::Url,
    headers: Vec<(String, String)>,
    header_order: Option<Vec<String>>,
    body: Option<Vec<u8>>,
    timeout: Duration,
    connect_timeout: Duration,
    allow_redirects: bool,
    max_redirects: usize,
    verify: bool,
    ca_bundle: Option<Vec<u8>>,
    identity_pair: Option<(Vec<u8>, Vec<u8>)>,
    resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    local_address: Option<IpAddr>,
    tls_info: bool,
    enable_keylog: bool,
    preset: String,
    ua_override: Option<String>,
    sec_ch_ua_override: Option<String>,
    alt_svc_port: Option<u16>,
    strict_h3: bool,
}

fn default_h3_browser_headers(
    preset: &str,
    ua_ov: Option<&str>,
    ch_ov: Option<&str>,
) -> Vec<(String, String)> {
    let lower = preset.trim().to_lowercase().replace('-', "_");
    let platform = platform_from_name(&lower);
    let digits: String = lower.chars().filter(|c| c.is_ascii_digit()).collect();

    if lower.starts_with("firefox") || lower.starts_with("tor") {
        let ver: u32 = if lower.starts_with("tor") { 128 } else { digits.parse().unwrap_or(151) };
        let ua = ua_ov.map(|s| s.to_string()).unwrap_or_else(|| match platform {
            Platform::MacOS => format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"),
            Platform::Linux => format!("Mozilla/5.0 (X11; Linux x86_64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"),
            Platform::Android => format!("Mozilla/5.0 (Android 14; Mobile; rv:{ver}.0) Gecko/{ver}.0 Firefox/{ver}.0"),
            _ => format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"),
        });
        return vec![
            ("user-agent".to_string(), ua),
            ("accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
            ("accept-language".to_string(), "en-US,en;q=0.5".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br, zstd".to_string()),
            ("sec-fetch-dest".to_string(), "document".to_string()),
            ("sec-fetch-mode".to_string(), "navigate".to_string()),
            ("sec-fetch-site".to_string(), "none".to_string()),
            ("sec-fetch-user".to_string(), "?1".to_string()),
            ("priority".to_string(), "u=0, i".to_string()),
        ];
    }

    if lower.starts_with("safari") {
        let ua = ua_ov.map(|s| s.to_string()).unwrap_or_else(|| {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15".to_string()
        });
        return vec![
            ("sec-fetch-dest".to_string(), "document".to_string()),
            ("user-agent".to_string(), ua),
            ("accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
            ("sec-fetch-site".to_string(), "none".to_string()),
            ("sec-fetch-mode".to_string(), "navigate".to_string()),
            ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
            ("priority".to_string(), "u=0, i".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
        ];
    }

    if lower.starts_with("okhttp") {
        let ua = ua_ov.map(|s| s.to_string()).unwrap_or_else(|| "okhttp/5.0.0".to_string());
        return vec![
            ("accept-encoding".to_string(), "gzip".to_string()),
            ("user-agent".to_string(), ua),
        ];
    }

    let (ver, brand) = if lower.starts_with("edge") {
        (digits.parse::<u32>().unwrap_or(148), "Microsoft Edge")
    } else if lower.starts_with("opera") {
        (digits.parse::<u32>().unwrap_or(131), "Opera")
    } else {
        (digits.parse::<u32>().unwrap_or(149), "Google Chrome")
    };

    let ch = ch_ov
        .map(|s| s.to_string())
        .unwrap_or_else(|| chromium_sec_ch_ua(ver, brand));
    let mobile = if matches!(platform, Platform::Android) { "?1" } else { "?0" };
    let plat_str = match platform {
        Platform::MacOS => "\"macOS\"",
        Platform::Linux => "\"Linux\"",
        Platform::Android => "\"Android\"",
        _ => "\"Windows\"",
    };
    let ua = ua_ov.map(|s| s.to_string()).unwrap_or_else(|| {
        let base = match platform {
            Platform::MacOS => format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
            Platform::Linux => format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
            Platform::Android => format!("Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Mobile Safari/537.36"),
            _ => format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"),
        };
        if brand == "Microsoft Edge" {
            format!("{base} Edg/{ver}.0.0.0")
        } else {
            base
        }
    });

    vec![
        ("sec-ch-ua".to_string(), ch),
        ("sec-ch-ua-mobile".to_string(), mobile.to_string()),
        ("sec-ch-ua-platform".to_string(), plat_str.to_string()),
        ("upgrade-insecure-requests".to_string(), "1".to_string()),
        ("user-agent".to_string(), ua),
        ("accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string()),
        ("sec-fetch-site".to_string(), "none".to_string()),
        ("sec-fetch-mode".to_string(), "navigate".to_string()),
        ("sec-fetch-user".to_string(), "?1".to_string()),
        ("sec-fetch-dest".to_string(), "document".to_string()),
        ("accept-encoding".to_string(), "gzip, deflate, br, zstd".to_string()),
        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
        ("priority".to_string(), "u=0, i".to_string()),
    ]
}

fn decompress_h3_body(raw: Vec<u8>, content_encoding: Option<&str>) -> Vec<u8> {
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

fn build_h3_client_config(
    verify: bool,
    ca_bundle: Option<&[u8]>,
    identity_pair: Option<&(Vec<u8>, Vec<u8>)>,
    enable_keylog: bool,
) -> PyResult<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| PyRuntimeError::new_err(format!("[builder] QUIC TLS 1.3 init failed: {e}")))?;

    let mut tls_config = if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca_raw) = ca_bundle {
            let mut reader = std::io::BufReader::new(ca_raw);
            let mut added = false;
            for cert in rustls_pemfile::certs(&mut reader).flatten() {
                let _ = roots.add(cert);
                added = true;
            }
            if !added {
                let _ = roots.add(rustls::pki_types::CertificateDer::from(ca_raw.to_vec()));
            }
        }
        let want_verifier = builder.with_root_certificates(roots);
        if let Some((cert_pem, key_pem)) = identity_pair {
            let mut creader = std::io::BufReader::new(&cert_pem[..]);
            let certs: Vec<_> = rustls_pemfile::certs(&mut creader).flatten().collect();
            let mut kreader = std::io::BufReader::new(&key_pem[..]);
            let key = rustls_pemfile::private_key(&mut kreader)
                .ok()
                .flatten()
                .ok_or_else(|| PyValueError::new_err("Invalid client private key PEM for HTTP/3"))?;
            want_verifier
                .with_client_auth_cert(certs, key)
                .map_err(|e| PyValueError::new_err(format!("HTTP/3 client auth rejected: {e}")))?
        } else {
            want_verifier.with_no_client_auth()
        }
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier(provider)))
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.enable_early_data = true;
    if enable_keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[builder] QUIC crypto config failed: {e}")))?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));

    // Chromium QUIC transport parameters (0x0039)
    let mut transport = quinn::TransportConfig::default();
    if let Ok(idle) = Duration::from_secs(30).try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.receive_window(15_728_640u32.into());
    transport.stream_receive_window(6_291_456u32.into());
    transport.send_window(15_728_640);
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(103u32.into());
    transport.send_fairness(false);
    client_cfg.transport_config(Arc::new(transport));

    Ok(client_cfg)
}

async fn resolve_h3_target(
    host: &str,
    port: u16,
    resolve_entries: &[(String, Vec<SocketAddr>)],
    prefer_ipv6: Option<bool>,
) -> PyResult<SocketAddr> {
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
    let lookup_target = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = lookup_host(&lookup_target)
        .await
        .map_err(|e| PyRuntimeError::new_err(format!("[connect] DNS lookup failed for '{lookup_target}': {e}")))?
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
        .ok_or_else(|| PyRuntimeError::new_err(format!("[connect] No addresses resolved for '{lookup_target}'")))
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct H3PoolKey {
    host: String,
    port: u16,
    verify: bool,
    local_address: Option<IpAddr>,
    ca_hash: Option<Vec<u8>>,
}

struct PooledH3Conn {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_handle: tokio::task::JoinHandle<()>,
    remote_addr: Option<String>,
    peer_certificate: Option<Vec<u8>>,
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

type H3Pool = Arc<tokio::sync::Mutex<HashMap<H3PoolKey, PooledH3Conn>>>;

fn clear_h3_pool_sync(h3_pool: &H3Pool) {
    if let Ok(mut guard) = h3_pool.try_lock() {
        for (_, entry) in guard.drain() {
            entry.close();
        }
        return;
    }
    let pool = Arc::clone(h3_pool);
    runtime().spawn(async move {
        let mut guard = pool.lock().await;
        for (_, entry) in guard.drain() {
            entry.close();
        }
    });
}

async fn acquire_h3_conn(
    spec: &H3RequestSpec,
    host: &str,
    port: u16,
    h3_pool: &H3Pool,
) -> PyResult<(
    H3PoolKey,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    Option<String>,
    Option<Vec<u8>>,
    bool,
)> {
    let key = H3PoolKey {
        host: host.to_ascii_lowercase(),
        port,
        verify: spec.verify,
        local_address: spec.local_address,
        ca_hash: spec.ca_bundle.clone(),
    };

    {
        let mut pool = h3_pool.lock().await;
        if let Some(entry) = pool.get(&key) {
            if entry.is_alive() {
                return Ok((
                    key,
                    entry.send_request.clone(),
                    entry.remote_addr.clone(),
                    entry.peer_certificate.clone(),
                    true,
                ));
            }
        }
        if let Some(stale) = pool.remove(&key) {
            stale.close();
        }
    }

    let prefer_v6 = spec.local_address.map(|ip| ip.is_ipv6());
    let remote_sa = resolve_h3_target(host, port, &spec.resolve_entries, prefer_v6).await?;

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

    let client_cfg = build_h3_client_config(
        spec.verify,
        spec.ca_bundle.as_deref(),
        spec.identity_pair.as_ref(),
        spec.enable_keylog,
    )?;

    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|e| PyRuntimeError::new_err(format!("[connect] UDP socket bind failed on {bind_addr}: {e}")))?;
    endpoint.set_default_client_config(client_cfg);

    let clean_sni = host.trim_matches(|c| c == '[' || c == ']');
    let connecting = endpoint
        .connect(remote_sa, clean_sni)
        .map_err(|e| PyRuntimeError::new_err(format!("[connect] QUIC connect init failed: {e}")))?;

    let conn = match tokio::time::timeout(spec.connect_timeout, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            endpoint.close(0u32.into(), b"handshake_err");
            let low = e.to_string().to_lowercase();
            let tag = if low.contains("certificate") || low.contains("tls") || low.contains("crypto") {
                "ssl"
            } else {
                "connect"
            };
            return Err(PyRuntimeError::new_err(format!("[{tag}] QUIC handshake failed: {e}")));
        }
        Err(_) => {
            endpoint.close(0u32.into(), b"timeout");
            return Err(PyRuntimeError::new_err(
                "[connect_timeout] QUIC UDP handshake timed out",
            ));
        }
    };

    let remote_addr_str = Some(conn.remote_address().to_string());
    let peer_cert_der = if spec.tls_info {
        conn.peer_identity()
            .and_then(|any| any.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.into_iter().next().map(|c| c.as_ref().to_vec()))
    } else {
        None
    };

    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, send_request) = h3::client::new(quinn_conn).await.map_err(|e| {
        endpoint.close(0u32.into(), b"h3_init_err");
        PyRuntimeError::new_err(format!("[connect] HTTP/3 session init failed: {e}"))
    })?;

    let driver_handle = tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let pooled_sr = send_request.clone();
    {
        let mut pool = h3_pool.lock().await;
        if pool.len() >= 16 {
            for (_, old) in pool.drain() {
                old.close();
            }
        }
        if let Some(prev) = pool.insert(
            key.clone(),
            PooledH3Conn {
                endpoint,
                conn,
                send_request,
                driver_handle,
                remote_addr: remote_addr_str.clone(),
                peer_certificate: peer_cert_der.clone(),
            },
        ) {
            prev.close();
        }
    }

    Ok((key, pooled_sr, remote_addr_str, peer_cert_der, false))
}

#[allow(clippy::type_complexity)]
async fn execute_h3_single_hop(
    spec: &H3RequestSpec,
    current_url: &url::Url,
    method_str: &str,
    body_opt: Option<&[u8]>,
    jar: &Arc<Jar>,
    h3_pool: &H3Pool,
    port_override: Option<u16>,
) -> PyResult<(
    u16,
    HeaderMap,
    HashMap<String, String>,
    Vec<u8>,
    Option<String>,
    Option<Vec<u8>>,
)> {
    if current_url.scheme() != "https" {
        return Err(PyRuntimeError::new_err(
            "[connect] HTTP/3 (QUIC) requires an https:// URL",
        ));
    }
    let host = current_url
        .host_str()
        .ok_or_else(|| PyValueError::new_err("HTTP/3 URL missing host"))?
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
        .map_err(|e| PyValueError::new_err(format!("Invalid HTTP/3 URI: {e}")))?;

    let method = http::Method::from_bytes(method_str.as_bytes())
        .map_err(|e| PyValueError::new_err(format!("Invalid HTTP method '{method_str}': {e}")))?;

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
        let (key, mut send_request, remote_addr_str, peer_cert_der, reused) =
            acquire_h3_conn(spec, &host, port, h3_pool).await?;

        let mut req_builder = http::Request::builder().method(method.clone()).uri(uri.clone());
        for (k, v) in &merged {
            if k.eq_ignore_ascii_case("host")
                || k.eq_ignore_ascii_case("connection")
                || k.eq_ignore_ascii_case("transfer-encoding")
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
            .map_err(|e| PyRuntimeError::new_err(format!("[request] HTTP/3 request build error: {e}")))?;

        let mut stream = match send_request.send_request(req).await {
            Ok(s) => s,
            Err(e) => {
                if reused && attempt == 0 {
                    let mut pool = h3_pool.lock().await;
                    if let Some(stale) = pool.remove(&key) {
                        stale.close();
                    }
                    continue;
                }
                return Err(PyRuntimeError::new_err(format!(
                    "[request] HTTP/3 send_request failed: {e}"
                )));
            }
        };

        if let Some(body_bytes) = body_opt {
            if !body_bytes.is_empty() {
                if let Err(e) = stream.send_data(Bytes::copy_from_slice(body_bytes)).await {
                    if reused && attempt == 0 {
                        let mut pool = h3_pool.lock().await;
                        if let Some(stale) = pool.remove(&key) {
                            stale.close();
                        }
                        continue;
                    }
                    return Err(PyRuntimeError::new_err(format!(
                        "[request] HTTP/3 send_data failed: {e}"
                    )));
                }
            }
        }
        if let Err(e) = stream.finish().await {
            if reused && attempt == 0 {
                let mut pool = h3_pool.lock().await;
                if let Some(stale) = pool.remove(&key) {
                    stale.close();
                }
                continue;
            }
            return Err(PyRuntimeError::new_err(format!(
                "[request] HTTP/3 stream finish failed: {e}"
            )));
        }

        let resp = match stream.recv_response().await {
            Ok(r) => r,
            Err(e) => {
                if reused && attempt == 0 {
                    let mut pool = h3_pool.lock().await;
                    if let Some(stale) = pool.remove(&key) {
                        stale.close();
                    }
                    continue;
                }
                return Err(PyRuntimeError::new_err(format!(
                    "[request] HTTP/3 recv_response failed: {e}"
                )));
            }
        };

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

        let mut raw_body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|e| PyRuntimeError::new_err(format!("[request] HTTP/3 recv_data failed: {e}")))?
        {
            while chunk.has_remaining() {
                let slice = chunk.chunk();
                raw_body.extend_from_slice(slice);
                let len = slice.len();
                chunk.advance(len);
            }
        }

        let decoded_bytes = decompress_h3_body(raw_body, content_encoding.as_deref());
        return Ok((
            status_code,
            wreq_headers,
            headers_map,
            decoded_bytes,
            remote_addr_str,
            peer_cert_der,
        ));
    }

    Err(PyRuntimeError::new_err("[connect] HTTP/3 connection retry exhausted"))
}

async fn execute_h3_request(
    spec: H3RequestSpec,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
) -> PyResult<NativeResponse> {
    let start = Instant::now();
    let fut = async {
        let mut current_url = spec.url.clone();
        let mut current_method = spec.method.to_uppercase();
        let mut current_body = spec.body.clone();
        let mut history: Vec<HistoryTuple> = Vec::new();
        let mut hop_port = spec.alt_svc_port;

        for hop in 0..=spec.max_redirects {
            let (status_code, wreq_hdrs, headers_map, body_bytes, remote_addr, peer_certificate) =
                execute_h3_single_hop(
                    &spec,
                    &current_url,
                    &current_method,
                    current_body.as_deref(),
                    &jar,
                    &h3_pool,
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
                        return Err(PyRuntimeError::new_err(format!(
                            "[redirect] Too many redirects (max {})",
                            spec.max_redirects
                        )));
                    }
                    let next_url = current_url.join(loc).map_err(|e| {
                        PyValueError::new_err(format!("Invalid redirect URL '{loc}': {e}"))
                    })?;
                    history.push((
                        status_code,
                        current_url.to_string(),
                        next_url.to_string(),
                        headers_map,
                    ));
                    if status_code == 303
                        || ((status_code == 301 || status_code == 302)
                            && current_method != "GET"
                            && current_method != "HEAD")
                    {
                        current_method = "GET".to_string();
                        current_body = None;
                    }
                    current_url = next_url;
                    continue;
                }
            }

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
            });
        }
        Err(PyRuntimeError::new_err("[redirect] Too many redirects"))
    };

    match tokio::time::timeout(spec.timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(PyRuntimeError::new_err("[timeout] HTTP/3 request timed out")),
    }
}


// ---------------------------------------------------------------------------
// Response & Stream & WebSocket types
// ---------------------------------------------------------------------------
#[pyclass(name = "Response")]
pub struct NativeResponse {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub url: String,
    pub content: Vec<u8>,
    #[pyo3(get)]
    pub text: String,
    #[pyo3(get)]
    pub encoding: String,
    #[pyo3(get)]
    pub elapsed: f64,
    #[pyo3(get)]
    pub cookies: HashMap<String, String>,
    #[pyo3(get)]
    pub http_version: String,
    #[pyo3(get)]
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    #[pyo3(get)]
    pub history: Vec<HistoryTuple>,
}

#[pymethods]
impl NativeResponse {
    #[getter]
    pub fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.content)
    }

    #[getter]
    pub fn peer_certificate<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.peer_certificate.as_ref().map(|b| PyBytes::new(py, b))
    }

    pub fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        py.import("json")?.getattr("loads")?.call1((&self.text,))
    }

    pub fn ok(&self) -> bool {
        self.status_code >= 200 && self.status_code < 400
    }

    pub fn __repr__(&self) -> String {
        format!("<Response [{}]>", self.status_code)
    }

    pub fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.content)
    }
}

#[pyclass(name = "StreamResponse")]
pub struct NativeStream {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub encoding: String,
    #[pyo3(get)]
    pub elapsed: f64,
    #[pyo3(get)]
    pub cookies: HashMap<String, String>,
    #[pyo3(get)]
    pub http_version: String,
    #[pyo3(get)]
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    #[pyo3(get)]
    pub history: Vec<HistoryTuple>,
    inner: Arc<tokio::sync::Mutex<Option<BodyStream>>>,
}

#[pymethods]
impl NativeStream {
    #[getter]
    pub fn peer_certificate<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.peer_certificate.as_ref().map(|b| PyBytes::new(py, b))
    }

    pub fn read_chunk(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        let rt = runtime();
        let inner = Arc::clone(&self.inner);
        let chunk = py.allow_threads(|| -> PyResult<Option<Bytes>> {
            rt.block_on(async move {
                let mut guard = inner.lock().await;
                let next = match guard.as_mut() {
                    None => return Ok(None),
                    Some(stream) => match stream.next().await {
                        None => None,
                        Some(Ok(b)) => Some(b),
                        Some(Err(e)) => return Err(net_err(e)),
                    },
                };
                if next.is_none() {
                    guard.take();
                }
                Ok(next)
            })
        })?;
        Ok(chunk.map(|b| PyBytes::new(py, &b).unbind()))
    }

    pub fn aread_chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let next = match guard.as_mut() {
                None => return Ok(None::<Vec<u8>>),
                Some(stream) => match stream.next().await {
                    None => None,
                    Some(Ok(b)) => Some(b.to_vec()),
                    Some(Err(e)) => return Err(net_err(e)),
                },
            };
            if next.is_none() {
                guard.take();
            }
            Ok(next)
        })
    }

    pub fn close(&self, py: Python<'_>) {
        let inner = Arc::clone(&self.inner);
        py.allow_threads(|| {
            runtime().block_on(async move {
                inner.lock().await.take();
            });
        });
    }

    pub fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.lock().await.take();
            Ok(())
        })
    }

    pub fn __repr__(&self) -> String {
        format!("<StreamResponse [{}]>", self.status_code)
    }
}

#[pyclass(name = "WebSocket")]
pub struct NativeWebSocket {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub protocol: Option<String>,
    inner: Arc<tokio::sync::Mutex<Option<wreq::ws::WebSocket>>>,
}

fn ws_msg_to_tuple(msg: Message) -> (String, Vec<u8>) {
    match msg {
        Message::Text(t) => ("text".to_string(), t.as_str().as_bytes().to_vec()),
        Message::Binary(b) => ("binary".to_string(), b.to_vec()),
        Message::Ping(b) => ("ping".to_string(), b.to_vec()),
        Message::Pong(b) => ("pong".to_string(), b.to_vec()),
        Message::Close(frame) => {
            let reason = frame.map(|f| f.reason.as_str().to_string()).unwrap_or_default();
            ("close".to_string(), reason.into_bytes())
        }
    }
}

#[pymethods]
impl NativeWebSocket {
    pub fn send_text(&self, py: Python<'_>, text: String) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::text(text)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::text(text)).await.map_err(net_err)
        })
    }

    pub fn send_bytes(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::binary(data)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_bytes<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::binary(data)).await.map_err(net_err)
        })
    }

    pub fn recv(&self, py: Python<'_>) -> PyResult<Option<(String, Py<PyBytes>)>> {
        let inner = Arc::clone(&self.inner);
        let res = py.allow_threads(move || -> PyResult<Option<(String, Vec<u8>)>> {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = match guard.as_mut() {
                    Some(w) => w,
                    None => return Ok(None),
                };
                match ws.recv().await {
                    None => {
                        guard.take();
                        Ok(None)
                    }
                    Some(Ok(msg)) => {
                        let out = ws_msg_to_tuple(msg);
                        if out.0 == "close" {
                            guard.take();
                        }
                        Ok(Some(out))
                    }
                    Some(Err(e)) => Err(net_err(e)),
                }
            })
        })?;
        Ok(res.map(|(k, b)| (k, PyBytes::new(py, &b).unbind())))
    }

    pub fn arecv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = match guard.as_mut() {
                Some(w) => w,
                None => return Ok(None::<(String, Vec<u8>)>),
            };
            match ws.recv().await {
                None => {
                    guard.take();
                    Ok(None)
                }
                Some(Ok(msg)) => {
                    let out = ws_msg_to_tuple(msg);
                    if out.0 == "close" {
                        guard.take();
                    }
                    Ok(Some(out))
                }
                Some(Err(e)) => Err(net_err(e)),
            }
        })
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        let reason_str = reason.to_string();
        py.allow_threads(move || {
            runtime().block_on(async move {
                if let Some(ws) = inner.lock().await.take() {
                    let _ = ws.close(CloseCode::from(code), reason_str).await;
                }
                Ok(())
            })
        })
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn aclose<'py>(&self, py: Python<'py>, code: u16, reason: &str) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let reason_str = reason.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(ws) = inner.lock().await.take() {
                let _ = ws.close(CloseCode::from(code), reason_str).await;
            }
            Ok(())
        })
    }

    pub fn __repr__(&self) -> String {
        format!("<WebSocket [{}]>", self.status_code)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
#[derive(Clone, Hash, PartialEq, Eq)]
struct ClientKey {
    verify: bool,
    ca_hash: Option<Vec<u8>>,
}

struct EmulationState {
    emulation: Emulation,
    ua_override: Option<String>,
    sec_ch_ua_override: Option<String>,
    impersonate: String,
}

#[pyclass(name = "Session")]
pub struct NativeSession {
    jar: Arc<Jar>,
    clients: Mutex<HashMap<ClientKey, Client>>,
    h3_pool: H3Pool,
    emu_state: Mutex<EmulationState>,
    default_headers: HeaderMap,
    header_order: Option<Vec<String>>,
    tls_options: Option<TlsOptions>,
    http2_options: Option<Http2Options>,
    http1_only: bool,
    http2_only: bool,
    http3: bool,
    http3_only: bool,
    resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    local_address: Option<IpAddr>,
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "ios", target_os = "linux", target_os = "macos"))]
    interface: Option<String>,
    tls_info: bool,
    keylog_file: Option<String>,
    system_dns: bool,
    timeout: Duration,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    pool_idle_timeout: Option<Duration>,
    tcp_nodelay: Option<bool>,
    tcp_keepalive: Option<Duration>,
    max_redirects: usize,
    ca_bundle: Option<Vec<u8>>,
    identity_pair: Option<(Vec<u8>, Vec<u8>)>,
    default_proxy: Option<String>,
    follow_redirects: bool,
    verify: bool,
}

impl NativeSession {
    fn client_for(&self, verify: bool, ca_override: Option<&[u8]>) -> PyResult<Client> {
        let effective_ca: Option<&[u8]> = ca_override.or(self.ca_bundle.as_deref());
        let key = ClientKey {
            verify,
            ca_hash: effective_ca.map(|b| b.to_vec()),
        };

        let mut cache = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = cache.get(&key) {
            return Ok(c.clone());
        }

        let emu = self
            .emu_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .emulation
            .clone();

        let mut b = Client::builder()
            .emulation(emu)
            .cookie_provider(Arc::clone(&self.jar))
            .timeout(self.timeout)
            .tls_cert_verification(verify)
            .tls_verify_hostname(verify)
            .tls_info(self.tls_info)
            .redirect(if self.follow_redirects {
                Policy::limited(self.max_redirects)
            } else {
                Policy::none()
            });

        if let Some(ct) = self.connect_timeout {
            b = b.connect_timeout(ct);
        }
        if let Some(rt) = self.read_timeout {
            b = b.read_timeout(rt);
        }
        if let Some(n) = self.pool_max_idle_per_host {
            b = b.pool_max_idle_per_host(n);
        }
        if let Some(it) = self.pool_idle_timeout {
            b = b.pool_idle_timeout(it);
        }
        if let Some(nd) = self.tcp_nodelay {
            b = b.tcp_nodelay(nd);
        }
        if let Some(ka) = self.tcp_keepalive {
            b = b.tcp_keepalive(ka);
        }
        if let Some(ref opts) = self.tls_options {
            b = b.tls_options(opts.clone());
        }
        if let Some(ref h2) = self.http2_options {
            b = b.http2_options(h2.clone());
        }
        if self.http1_only {
            b = b.http1_only();
        } else if self.http2_only {
            b = b.http2_only();
        }
        if let Some(ref order) = self.header_order {
            b = b.orig_headers(build_orig_headers(order));
        }
        if !self.default_headers.is_empty() {
            b = b.default_headers(self.default_headers.clone());
        }
        for (domain, addrs) in &self.resolve_entries {
            b = b.resolve_to_addrs(domain.clone(), addrs.iter().copied());
        }
        if let Some(ip) = self.local_address {
            b = b.local_address(ip);
        }
        if let Some(ref kl) = self.keylog_file {
            b = b.tls_keylog(KeyLog::from_file(kl));
        } else if std::env::var("SSLKEYLOGFILE").map(|v| !v.trim().is_empty()).unwrap_or(false) {
            b = b.tls_keylog(KeyLog::from_env());
        }
        if self.system_dns {
            b = b.no_hickory_dns();
        }
        #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "ios", target_os = "linux", target_os = "macos"))]
        if let Some(ref iface) = self.interface {
            b = b.interface(iface.clone());
        }
        if let Some(ca_raw) = effective_ca {
            b = b.tls_cert_store(build_cert_store(ca_raw)?);
        }
        if let Some((ref cert_pem, ref key_pem)) = self.identity_pair {
            b = b.tls_identity(build_identity(cert_pem, key_pem)?);
        }
        if let Some(ref p) = self.default_proxy {
            let px = Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
            b = b.proxy(px);
        }

        let client = b
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("[builder] {}", error_chain(&e))))?;
        // Bound cached sub-clients so dynamic CA bundle churn cannot grow memory unboundedly.
        if cache.len() >= 16 {
            cache.clear();
        }
        cache.insert(key, client.clone());
        Ok(client)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate_override: Option<String>,
        local_address_override: Option<String>,
    ) -> PyResult<RequestBuilder> {
        let m = Method::from_str(&method.to_uppercase())
            .map_err(|e| PyValueError::new_err(format!("Invalid HTTP method: {e}")))?;

        let mut final_url =
            url::Url::parse(url).map_err(|e| PyValueError::new_err(format!("Invalid URL '{url}': {e}")))?;

        let qp = dict_pairs(params)?;
        if !qp.is_empty() {
            let mut pairs = final_url.query_pairs_mut();
            for (k, v) in &qp {
                pairs.append_pair(k, v);
            }
        }

        let uri_str = final_url.as_str();
        for (k, v) in dict_pairs(cookies)? {
            self.jar.add(format!("{k}={v}; Path=/"), uri_str);
        }

        let use_verify = verify.unwrap_or(self.verify);
        let client = self.client_for(use_verify, ca_bundle.as_deref())?;

        let mut rb = client.request(m, uri_str);

        if let Some(t) = timeout {
            rb = rb.timeout(Duration::from_secs_f64(t.max(0.05)));
        }
        if let Some(redir) = allow_redirects {
            rb = rb.redirect(if redir {
                Policy::limited(self.max_redirects)
            } else {
                Policy::none()
            });
        }
        if let Some(p) = proxy {
            let px = Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
            rb = rb.proxy(px);
        }
        if let Some(la) = local_address_override {
            let ip = IpAddr::from_str(&la)
                .map_err(|e| PyValueError::new_err(format!("Invalid local_address '{la}': {e}")))?;
            rb = rb.local_address(ip);
        }

        let (ua_ov, ch_ov) = if let Some(ref preset) = impersonate_override {
            let res = resolve_emulation(preset);
            rb = rb.emulation(res.emulation);
            (res.ua_override, res.sec_ch_ua_override)
        } else {
            let st = self.emu_state.lock().unwrap_or_else(|p| p.into_inner());
            (st.ua_override.clone(), st.sec_ch_ua_override.clone())
        };

        if let Some(ref order) = header_order {
            rb = rb.orig_headers(build_orig_headers(order));
        }

        let caller_hdrs = dict_pairs(headers)?;
        let has_caller_ua = caller_hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
        let has_caller_ch = caller_hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("sec-ch-ua"));

        if !has_caller_ua {
            if let Some(ref ua) = ua_ov {
                if let Ok(hv) = HeaderValue::from_str(ua) {
                    rb = rb.header(wreq::header::USER_AGENT, hv);
                }
            }
        }
        if !has_caller_ch {
            if let Some(ref ch) = ch_ov {
                if let (Ok(hn), Ok(hv)) = (HeaderName::from_str("sec-ch-ua"), HeaderValue::from_str(ch)) {
                    rb = rb.header(hn, hv);
                }
            }
        }

        for (k, v) in caller_hdrs {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                rb = rb.header(hn, hv);
            }
        }

        let mp_items = parse_multipart_items(files)?;
        if !mp_items.is_empty() {
            let mut form = Form::new();
            for (field, filename, payload, mime) in mp_items {
                let mut part = Part::bytes(payload);
                if let Some(fname) = filename {
                    part = part.file_name(fname);
                }
                if let Some(ct) = mime {
                    part = part
                        .mime_str(&ct)
                        .map_err(|e| PyValueError::new_err(format!("Invalid MIME '{ct}': {e}")))?;
                }
                form = form.part(field, part);
            }
            rb = rb.multipart(form);
        } else if let Some(body) = data {
            rb = rb.body(body);
        } else if let Some(j) = json {
            rb = rb
                .header(wreq::header::CONTENT_TYPE, "application/json")
                .body(j.to_string());
        }

        Ok(rb)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_h3(
        &self,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate_override: Option<String>,
        local_address_override: Option<String>,
        http3_override: Option<bool>,
        alt_svc_port: Option<u16>,
    ) -> PyResult<Option<H3RequestSpec>> {
        let want_h3 = http3_override.unwrap_or(self.http3 || self.http3_only);
        if !want_h3 || self.http1_only || self.http2_only {
            return Ok(None);
        }
        let has_proxy = proxy.is_some() || self.default_proxy.is_some();
        if has_proxy {
            if self.http3_only {
                return Err(PyRuntimeError::new_err(
                    "[connect] http3_only=True cannot be used with an HTTP/SOCKS TCP proxy",
                ));
            }
            return Ok(None);
        }
        if files.map(|f| !f.is_empty()).unwrap_or(false) {
            return Ok(None);
        }

        let mut final_url =
            url::Url::parse(url).map_err(|e| PyValueError::new_err(format!("Invalid URL '{url}': {e}")))?;
        if final_url.scheme() != "https" {
            if self.http3_only {
                return Err(PyRuntimeError::new_err(
                    "[connect] HTTP/3 (QUIC) requires an https:// URL",
                ));
            }
            return Ok(None);
        }

        let qp = dict_pairs(params)?;
        if !qp.is_empty() {
            let mut pairs = final_url.query_pairs_mut();
            for (k, v) in &qp {
                pairs.append_pair(k, v);
            }
        }

        let uri_str = final_url.as_str();
        for (k, v) in dict_pairs(cookies)? {
            self.jar.add(format!("{k}={v}; Path=/"), uri_str);
        }

        let (preset_name, ua_ov, ch_ov) = if let Some(ref preset) = impersonate_override {
            let res = resolve_emulation(preset);
            (preset.clone(), res.ua_override, res.sec_ch_ua_override)
        } else {
            let st = self.emu_state.lock().unwrap_or_else(|p| p.into_inner());
            (
                st.impersonate.clone(),
                st.ua_override.clone(),
                st.sec_ch_ua_override.clone(),
            )
        };

        let mut merged_hdrs: Vec<(String, String)> = Vec::new();
        for (k, v) in &self.default_headers {
            merged_hdrs.push((
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            ));
        }
        for (k, v) in dict_pairs(headers)? {
            if let Some(pos) = merged_hdrs.iter().position(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
                merged_hdrs[pos] = (k, v);
            } else {
                merged_hdrs.push((k, v));
            }
        }

        let body = if let Some(b) = data {
            Some(b)
        } else if let Some(j) = json {
            if !merged_hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                merged_hdrs.push(("content-type".to_string(), "application/json".to_string()));
            }
            Some(j.as_bytes().to_vec())
        } else {
            None
        };

        if let Some(ref b) = body {
            if !merged_hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
                merged_hdrs.push(("content-length".to_string(), b.len().to_string()));
            }
        }

        let eff_local_addr = match local_address_override {
            Some(ref la) => Some(
                IpAddr::from_str(la)
                    .map_err(|e| PyValueError::new_err(format!("Invalid local_address '{la}': {e}")))?,
            ),
            None => self.local_address,
        };

        let eff_timeout = timeout
            .map(|t| Duration::from_secs_f64(t.max(0.05)))
            .unwrap_or(self.timeout);
        let eff_connect_timeout = self
            .connect_timeout
            .unwrap_or_else(|| eff_timeout.min(Duration::from_secs(10)));
        let enable_keylog = self.keylog_file.is_some()
            || std::env::var("SSLKEYLOGFILE")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);

        Ok(Some(H3RequestSpec {
            method: method.to_uppercase(),
            url: final_url,
            headers: merged_hdrs,
            header_order: header_order.or_else(|| self.header_order.clone()),
            body,
            timeout: eff_timeout,
            connect_timeout: eff_connect_timeout,
            allow_redirects: allow_redirects.unwrap_or(self.follow_redirects),
            max_redirects: self.max_redirects,
            verify: verify.unwrap_or(self.verify),
            ca_bundle: ca_bundle.or_else(|| self.ca_bundle.clone()),
            identity_pair: self.identity_pair.clone(),
            resolve_entries: self.resolve_entries.clone(),
            local_address: eff_local_addr,
            tls_info: self.tls_info,
            enable_keylog,
            preset: preset_name,
            ua_override: ua_ov,
            sec_ch_ua_override: ch_ov,
            alt_svc_port,
            strict_h3: self.http3_only,
        }))
    }
}

async fn finish_dual_response(
    rb: RequestBuilder,
    h3_spec: Option<H3RequestSpec>,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
) -> PyResult<NativeResponse> {
    if let Some(spec) = h3_spec {
        let strict = spec.strict_h3;
        match execute_h3_request(spec, Arc::clone(&jar), h3_pool).await {
            Ok(resp) => return Ok(resp),
            Err(e) if strict => return Err(e),
            Err(_) => {}
        }
    }
    finish_response(rb, jar).await
}

async fn start_dual_stream(
    rb: RequestBuilder,
    h3_spec: Option<H3RequestSpec>,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
) -> PyResult<NativeStream> {
    if let Some(spec) = h3_spec {
        let strict = spec.strict_h3;
        match execute_h3_request(spec, Arc::clone(&jar), h3_pool).await {
            Ok(resp) => {
                let body_bytes = Bytes::from(resp.content);
                let stream: BodyStream =
                    Box::pin(futures_util::stream::once(async move { Ok(body_bytes) }));
                return Ok(NativeStream {
                    status_code: resp.status_code,
                    headers: resp.headers,
                    cookies: resp.cookies,
                    encoding: resp.encoding,
                    url: resp.url,
                    elapsed: resp.elapsed,
                    http_version: resp.http_version,
                    remote_addr: resp.remote_addr,
                    peer_certificate: resp.peer_certificate,
                    history: resp.history,
                    inner: Arc::new(tokio::sync::Mutex::new(Some(stream))),
                });
            }
            Err(e) if strict => return Err(e),
            Err(_) => {}
        }
    }
    start_stream(rb, jar).await
}

async fn finish_response(rb: RequestBuilder, jar: Arc<Jar>) -> PyResult<NativeResponse> {
    let start = Instant::now();
    let resp = rb.send().await.map_err(net_err)?;
    let status_code = resp.status().as_u16();
    let http_version = version_str(resp.version());
    let final_url = resp.uri().to_string();
    let remote_addr = resp.remote_addr().map(|a| a.to_string());
    let peer_certificate = extract_peer_cert(&resp);
    let history = collect_history(&resp);
    let hdrs = resp.headers().clone();
    let bytes = resp.bytes().await.map_err(net_err)?;
    let elapsed = start.elapsed().as_secs_f64();

    let (text, encoding) = decode_body(&bytes, &hdrs);
    Ok(NativeResponse {
        status_code,
        headers: collect_headers(&hdrs),
        cookies: collect_cookies(&jar, &final_url, &hdrs),
        url: final_url,
        content: bytes.to_vec(),
        text,
        encoding,
        elapsed,
        http_version,
        remote_addr,
        peer_certificate,
        history,
    })
}

async fn start_stream(rb: RequestBuilder, jar: Arc<Jar>) -> PyResult<NativeStream> {
    let start = Instant::now();
    let resp = rb.send().await.map_err(net_err)?;
    let elapsed = start.elapsed().as_secs_f64();
    let status_code = resp.status().as_u16();
    let http_version = version_str(resp.version());
    let final_url = resp.uri().to_string();
    let remote_addr = resp.remote_addr().map(|a| a.to_string());
    let peer_certificate = extract_peer_cert(&resp);
    let history = collect_history(&resp);
    let hdrs = resp.headers().clone();
    let encoding = charset_of(&hdrs)
        .map(|e| e.name().to_ascii_lowercase())
        .unwrap_or_default();
    let cookies = collect_cookies(&jar, &final_url, &hdrs);
    let headers = collect_headers(&hdrs);
    let stream: BodyStream = Box::pin(resp.bytes_stream());
    Ok(NativeStream {
        status_code,
        headers,
        cookies,
        encoding,
        url: final_url,
        elapsed,
        http_version,
        remote_addr,
        peer_certificate,
        history,
        inner: Arc::new(tokio::sync::Mutex::new(Some(stream))),
    })
}

#[pymethods]
impl NativeSession {
    #[new]
    #[pyo3(signature = (
        impersonate = "chrome_149",
        timeout = 30.0,
        follow_redirects = true,
        max_redirects = 10,
        verify_ssl = true,
        proxy = None,
        headers = None,
        ca_bundle = None,
        client_cert = None,
        client_key = None,
        header_order = None,
        tls_options = None,
        http2_options = None,
        http1_only = false,
        http2_only = false,
        http3 = false,
        http3_only = false,
        resolve = None,
        local_address = None,
        interface = None,
        tls_info = false,
        connect_timeout = None,
        read_timeout = None,
        pool_max_idle_per_host = None,
        pool_idle_timeout = None,
        keylog_file = None,
        system_dns = false,
        tcp_nodelay = None,
        tcp_keepalive = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        impersonate: &str,
        timeout: f64,
        follow_redirects: bool,
        max_redirects: usize,
        verify_ssl: bool,
        proxy: Option<String>,
        headers: Option<&Bound<'_, PyDict>>,
        ca_bundle: Option<Vec<u8>>,
        client_cert: Option<Vec<u8>>,
        client_key: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        tls_options: Option<&Bound<'_, PyDict>>,
        http2_options: Option<&Bound<'_, PyDict>>,
        http1_only: bool,
        http2_only: bool,
        http3: bool,
        http3_only: bool,
        resolve: Option<&Bound<'_, PyDict>>,
        local_address: Option<String>,
        interface: Option<String>,
        tls_info: bool,
        connect_timeout: Option<f64>,
        read_timeout: Option<f64>,
        pool_max_idle_per_host: Option<usize>,
        pool_idle_timeout: Option<f64>,
        keylog_file: Option<String>,
        system_dns: bool,
        tcp_nodelay: Option<bool>,
        tcp_keepalive: Option<f64>,
    ) -> PyResult<Self> {
        let mut default_headers = HeaderMap::new();
        for (k, v) in dict_pairs(headers)? {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                default_headers.insert(hn, hv);
            }
        }

        if let Some(ref raw) = ca_bundle {
            build_cert_store(raw)?;
        }
        let identity_pair = match (client_cert, client_key) {
            (Some(c), Some(k)) => {
                build_identity(&c, &k)?;
                Some((c, k))
            }
            (None, None) => None,
            _ => return Err(PyValueError::new_err("Both client_cert and client_key PEM bytes are required")),
        };
        if let Some(ref p) = proxy {
            Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
        }

        let parsed_tls = match tls_options {
            Some(d) => Some(parse_tls_options(d)?),
            None => None,
        };
        let parsed_h2 = match http2_options {
            Some(d) => Some(parse_http2_options(d)?),
            None => None,
        };
        let resolve_entries = match resolve {
            Some(d) => parse_resolve_map(d)?,
            None => Vec::new(),
        };
        let parsed_local_addr = match local_address {
            Some(ref s) => Some(
                IpAddr::from_str(s)
                    .map_err(|e| PyValueError::new_err(format!("Invalid local_address '{s}': {e}")))?,
            ),
            None => None,
        };
        #[cfg(not(any(target_os = "android", target_os = "freebsd", target_os = "ios", target_os = "linux", target_os = "macos")))]
        if interface.is_some() {
            return Err(PyValueError::new_err("interface binding is supported on Linux/macOS/Android/FreeBSD; use local_address on Windows"));
        }

        let resolved = resolve_emulation(impersonate);

        Ok(NativeSession {
            jar: Arc::new(Jar::default()),
            clients: Mutex::new(HashMap::new()),
            h3_pool: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            emu_state: Mutex::new(EmulationState {
                emulation: resolved.emulation,
                ua_override: resolved.ua_override,
                sec_ch_ua_override: resolved.sec_ch_ua_override,
                impersonate: impersonate.to_string(),
            }),
            default_headers,
            header_order,
            tls_options: parsed_tls,
            http2_options: parsed_h2,
            http1_only,
            http2_only,
            http3,
            http3_only,
            resolve_entries,
            local_address: parsed_local_addr,
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "ios", target_os = "linux", target_os = "macos"))]
            interface,
            tls_info,
            keylog_file,
            system_dns,
            timeout: Duration::from_secs_f64(timeout.max(0.05)),
            connect_timeout: connect_timeout.map(|t| Duration::from_secs_f64(t.max(0.05))),
            read_timeout: read_timeout.map(|t| Duration::from_secs_f64(t.max(0.05))),
            pool_max_idle_per_host,
            pool_idle_timeout: pool_idle_timeout.map(|t| Duration::from_secs_f64(t.max(0.05))),
            tcp_nodelay,
            tcp_keepalive: tcp_keepalive.map(|t| Duration::from_secs_f64(t.max(1.0))),
            max_redirects,
            ca_bundle,
            identity_pair,
            default_proxy: proxy,
            follow_redirects,
            verify: verify_ssl,
        })
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate: Option<String>,
        local_address: Option<String>,
        http3: Option<bool>,
        alt_svc_port: Option<u16>,
    ) -> PyResult<NativeResponse> {
        let h3_spec = self.prepare_h3(
            method,
            url,
            params,
            headers,
            cookies,
            data.clone(),
            json,
            files,
            timeout,
            proxy.clone(),
            allow_redirects,
            verify,
            ca_bundle.clone(),
            header_order.clone(),
            impersonate.clone(),
            local_address.clone(),
            http3,
            alt_svc_port,
        )?;
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        py.allow_threads(move || runtime().block_on(finish_dual_response(rb, h3_spec, jar, h3_pool)))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn async_request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate: Option<String>,
        local_address: Option<String>,
        http3: Option<bool>,
        alt_svc_port: Option<u16>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let h3_spec = self.prepare_h3(
            method,
            url,
            params,
            headers,
            cookies,
            data.clone(),
            json,
            files,
            timeout,
            proxy.clone(),
            allow_redirects,
            verify,
            ca_bundle.clone(),
            header_order.clone(),
            impersonate.clone(),
            local_address.clone(),
            http3,
            alt_svc_port,
        )?;
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        pyo3_async_runtimes::tokio::future_into_py(py, finish_dual_response(rb, h3_spec, jar, h3_pool))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn request_stream(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate: Option<String>,
        local_address: Option<String>,
        http3: Option<bool>,
        alt_svc_port: Option<u16>,
    ) -> PyResult<NativeStream> {
        let h3_spec = self.prepare_h3(
            method,
            url,
            params,
            headers,
            cookies,
            data.clone(),
            json,
            files,
            timeout,
            proxy.clone(),
            allow_redirects,
            verify,
            ca_bundle.clone(),
            header_order.clone(),
            impersonate.clone(),
            local_address.clone(),
            http3,
            alt_svc_port,
        )?;
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        py.allow_threads(move || runtime().block_on(start_dual_stream(rb, h3_spec, jar, h3_pool)))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn async_request_stream<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        params: Option<&Bound<'_, PyDict>>,
        headers: Option<&Bound<'_, PyDict>>,
        cookies: Option<&Bound<'_, PyDict>>,
        data: Option<Vec<u8>>,
        json: Option<&str>,
        files: Option<&Bound<'_, PyList>>,
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
        ca_bundle: Option<Vec<u8>>,
        header_order: Option<Vec<String>>,
        impersonate: Option<String>,
        local_address: Option<String>,
        http3: Option<bool>,
        alt_svc_port: Option<u16>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let h3_spec = self.prepare_h3(
            method,
            url,
            params,
            headers,
            cookies,
            data.clone(),
            json,
            files,
            timeout,
            proxy.clone(),
            allow_redirects,
            verify,
            ca_bundle.clone(),
            header_order.clone(),
            impersonate.clone(),
            local_address.clone(),
            http3,
            alt_svc_port,
        )?;
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        pyo3_async_runtimes::tokio::future_into_py(py, start_dual_stream(rb, h3_spec, jar, h3_pool))
    }

    #[pyo3(signature = (url, headers = None, proxy = None, verify = None))]
    pub fn ws_connect(
        &self,
        py: Python<'_>,
        url: &str,
        headers: Option<&Bound<'_, PyDict>>,
        proxy: Option<String>,
        verify: Option<bool>,
    ) -> PyResult<NativeWebSocket> {
        let client = self.client_for(verify.unwrap_or(self.verify), None)?;
        let mut ws_req = client.websocket(url);
        for (k, v) in dict_pairs(headers)? {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                ws_req = ws_req.header(hn, hv);
            }
        }
        if let Some(p) = proxy {
            let px = Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
            ws_req = ws_req.proxy(px);
        }
        py.allow_threads(move || {
            runtime().block_on(async move {
                let ws_resp = ws_req.send().await.map_err(net_err)?;
                let status_code = ws_resp.status().as_u16();
                let headers = collect_headers(ws_resp.headers());
                let ws = ws_resp.into_websocket().await.map_err(net_err)?;
                let protocol = ws.protocol().and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                Ok(NativeWebSocket {
                    status_code,
                    headers,
                    protocol,
                    inner: Arc::new(tokio::sync::Mutex::new(Some(ws))),
                })
            })
        })
    }

    #[pyo3(signature = (url, headers = None, proxy = None, verify = None))]
    pub fn async_ws_connect<'py>(
        &self,
        py: Python<'py>,
        url: &str,
        headers: Option<&Bound<'_, PyDict>>,
        proxy: Option<String>,
        verify: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client_for(verify.unwrap_or(self.verify), None)?;
        let mut ws_req = client.websocket(url);
        for (k, v) in dict_pairs(headers)? {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                ws_req = ws_req.header(hn, hv);
            }
        }
        if let Some(p) = proxy {
            let px = Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
            ws_req = ws_req.proxy(px);
        }
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let ws_resp = ws_req.send().await.map_err(net_err)?;
            let status_code = ws_resp.status().as_u16();
            let headers = collect_headers(ws_resp.headers());
            let ws = ws_resp.into_websocket().await.map_err(net_err)?;
            let protocol = ws.protocol().and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            Ok(NativeWebSocket {
                status_code,
                headers,
                protocol,
                inner: Arc::new(tokio::sync::Mutex::new(Some(ws))),
            })
        })
    }

    pub fn cookies_for(&self, url: &str) -> PyResult<HashMap<String, String>> {
        Ok(collect_cookies(&self.jar, url, &HeaderMap::new()))
    }

    /// Return all cookies in the jar as (name, value, domain, path, secure, http_only).
    pub fn all_cookies(&self) -> Vec<(String, String, String, String, bool, bool)> {
        self.jar
            .get_all()
            .map(|c| {
                (
                    c.name().to_string(),
                    c.value().to_string(),
                    c.domain().unwrap_or("").to_string(),
                    c.path().unwrap_or("/").to_string(),
                    c.secure(),
                    c.http_only(),
                )
            })
            .collect()
    }

    /// Insert a raw Set-Cookie style string scoped to `url`.
    pub fn add_raw_cookie(&self, cookie_header: &str, url: &str) {
        self.jar.add(cookie_header.to_string(), url);
    }

    /// Insert a domain/path-scoped cookie directly into the RFC 6265 cookie jar.
    #[pyo3(signature = (name, value, domain = None, path = None, secure = false, http_only = false))]
    pub fn set_cookie(
        &self,
        name: &str,
        value: &str,
        domain: Option<&str>,
        path: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        let dom = domain.unwrap_or("").trim().trim_start_matches('.');
        if dom.is_empty() {
            return;
        }
        let cpath = match path {
            Some(p) if !p.trim().is_empty() => p.trim(),
            _ => "/",
        };
        let mut raw = format!("{name}={value}; Domain={dom}; Path={cpath}");
        if secure {
            raw.push_str("; Secure");
        }
        if http_only {
            raw.push_str("; HttpOnly");
        }
        let scheme = if secure { "https" } else { "http" };
        let url = format!("{scheme}://{dom}{cpath}");
        self.jar.add(raw, &url);
    }

    /// Remove cookies matching `name` (and optional `domain` / `path`) from the RFC 6265 cookie jar.
    #[pyo3(signature = (name, domain = None, path = None))]
    pub fn delete_cookie(&self, name: &str, domain: Option<&str>, path: Option<&str>) {
        let dom_filter = domain.map(|d| d.trim().trim_start_matches('.').to_ascii_lowercase());
        let path_filter = path.map(|p| p.trim().to_string());
        let survivors: Vec<(String, String, String, String, bool, bool)> = self
            .all_cookies()
            .into_iter()
            .filter(|(n, _v, d, p, _sec, _ho)| {
                if n != name {
                    return true;
                }
                if let Some(ref df) = dom_filter {
                    if !df.is_empty() && d.trim_start_matches('.').to_ascii_lowercase() != *df {
                        return true;
                    }
                }
                if let Some(ref pf) = path_filter {
                    if !pf.is_empty() && p != pf {
                        return true;
                    }
                }
                false
            })
            .collect();
        self.jar.clear();
        for (n, v, d, p, sec, ho) in survivors {
            self.set_cookie(&n, &v, Some(&d), Some(&p), sec, ho);
        }
    }

    /// Hot-swap the active browser impersonation profile (TLS, HTTP/2, and default Client Hints)
    /// and invalidate cached sub-clients so subsequent requests match the new profile 1:1.
    pub fn set_impersonate(&self, preset: &str) {
        let resolved = resolve_emulation(preset);
        {
            let mut st = self.emu_state.lock().unwrap_or_else(|p| p.into_inner());
            st.emulation = resolved.emulation;
            st.ua_override = resolved.ua_override;
            st.sec_ch_ua_override = resolved.sec_ch_ua_override;
            st.impersonate = preset.to_string();
        }
        let mut cache = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        cache.clear();
        clear_h3_pool_sync(&self.h3_pool);
    }

    /// Execute a batch of requests concurrently on the Rust Tokio multi-thread pool,
    /// releasing the GIL and returning responses in the exact input order.
    #[pyo3(signature = (specs, concurrency = 50))]
    pub fn gather(
        &self,
        py: Python<'_>,
        specs: &Bound<'_, PyList>,
        concurrency: usize,
    ) -> PyResult<Vec<NativeResponse>> {
        let mut builders = Vec::with_capacity(specs.len());
        for item in specs.iter() {
            let d = item.downcast::<PyDict>()?;
            let method: String = d
                .get_item("method")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or_else(|| "GET".to_string());
            let url: String = d
                .get_item("url")?
                .ok_or_else(|| PyValueError::new_err("gather spec missing 'url'"))?
                .extract()?;
            let params_any = d.get_item("params")?;
            let params = params_any.as_ref().and_then(|v| v.downcast::<PyDict>().ok());
            let headers_any = d.get_item("headers")?;
            let headers = headers_any.as_ref().and_then(|v| v.downcast::<PyDict>().ok());
            let cookies_any = d.get_item("cookies")?;
            let cookies = cookies_any.as_ref().and_then(|v| v.downcast::<PyDict>().ok());
            let data: Option<Vec<u8>> = d.get_item("data")?.and_then(|v| v.extract().ok());
            let json_str: Option<String> = d.get_item("json")?.and_then(|v| v.extract().ok());
            let files_any = d.get_item("files")?;
            let files = files_any.as_ref().and_then(|v| v.downcast::<PyList>().ok());
            let timeout: Option<f64> = d.get_item("timeout")?.and_then(|v| v.extract().ok());
            let proxy: Option<String> = d.get_item("proxy")?.and_then(|v| v.extract().ok());
            let allow_redirects: Option<bool> = d.get_item("allow_redirects")?.and_then(|v| v.extract().ok());
            let verify: Option<bool> = d.get_item("verify")?.and_then(|v| v.extract().ok());
            let ca_bundle: Option<Vec<u8>> = d.get_item("ca_bundle")?.and_then(|v| v.extract().ok());
            let header_order: Option<Vec<String>> = d.get_item("header_order")?.and_then(|v| v.extract().ok());
            let impersonate: Option<String> = d.get_item("impersonate")?.and_then(|v| v.extract().ok());
            let local_address: Option<String> = d.get_item("local_address")?.and_then(|v| v.extract().ok());
            let http3: Option<bool> = d.get_item("http3")?.and_then(|v| v.extract().ok());
            let alt_svc_port: Option<u16> = d.get_item("alt_svc_port")?.and_then(|v| v.extract().ok());

            let h3_spec = self.prepare_h3(
                &method,
                &url,
                params,
                headers,
                cookies,
                data.clone(),
                json_str.as_deref(),
                files,
                timeout,
                proxy.clone(),
                allow_redirects,
                verify,
                ca_bundle.clone(),
                header_order.clone(),
                impersonate.clone(),
                local_address.clone(),
                http3,
                alt_svc_port,
            )?;
            let rb = self.prepare(
                &method,
                &url,
                params,
                headers,
                cookies,
                data,
                json_str.as_deref(),
                files,
                timeout,
                proxy,
                allow_redirects,
                verify,
                ca_bundle,
                header_order,
                impersonate,
                local_address,
            )?;
            builders.push((rb, h3_spec));
        }

        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let limit = concurrency.max(1);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let results: Vec<PyResult<NativeResponse>> = futures_util::stream::iter(
                    builders
                        .into_iter()
                        .map(|(rb, h3_spec)| {
                            finish_dual_response(rb, h3_spec, Arc::clone(&jar), Arc::clone(&h3_pool))
                        }),
                )
                .buffered(limit)
                .collect()
                .await;
                results.into_iter().collect()
            })
        })
    }

    pub fn clear_cookies(&self) {
        self.jar.clear();
    }

    pub fn close(&self) {
        let mut cache = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        cache.clear();
        clear_h3_pool_sync(&self.h3_pool);
    }

    pub fn client_cache_len(&self) -> usize {
        self.clients.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn h3_pool_len(&self) -> usize {
        self.h3_pool.try_lock().map(|g| g.len()).unwrap_or(0)
    }

    #[getter]
    pub fn impersonate(&self) -> String {
        self.emu_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .impersonate
            .clone()
    }
}

#[pyfunction]
pub fn supported_presets() -> Vec<&'static str> {
    vec![
        // Verified native BoringSSL + HTTP/2 profiles from wreq-util (zero header extrapolation)
        "chrome_149", "chrome_149_macos", "chrome_148", "chrome_147", "chrome_146", "chrome_145",
        "chrome_144", "chrome_143", "chrome_142", "chrome_141", "chrome_140", "chrome_139",
        "chrome_138", "chrome_137", "chrome_136", "chrome_135", "chrome_134", "chrome_133",
        "chrome_132", "chrome_131", "chrome_131_android", "chrome_130", "chrome_129", "chrome_128",
        "chrome_127", "chrome_126", "chrome_124", "chrome_123", "chrome_120", "chrome_119",
        "chrome_116", "chrome_114", "chrome_110", "chrome_107", "chrome_104", "chrome_100",
        "edge_148", "edge_147", "edge_146", "edge_145", "edge_144", "edge_143", "edge_142",
        "edge_141", "edge_140", "edge_139", "edge_138", "edge_137", "edge_136", "edge_135",
        "edge_134", "edge_131", "edge_127", "edge_122", "edge_101",
        "safari_26_4", "safari_26_3", "safari_26_2", "safari_26_1", "safari_26",
        "safari_ios_26_2", "safari_ios_26", "safari_ipad_26_2", "safari_ipad_26",
        "safari_18_5", "safari_18_3_1", "safari_18_3", "safari_18_2", "safari_18",
        "safari_ios_18_1_1", "safari_ipad_18",
        "safari_17_6", "safari_17_5", "safari_17_4_1", "safari_17_2_1", "safari_17_0",
        "safari_ios_17_4_1", "safari_ios_17_2",
        "safari_16_5", "safari_ios_16_5", "safari_16", "safari_15_6_1", "safari_15_5", "safari_15_3",
        "firefox_151", "firefox_150", "firefox_149", "firefox_148", "firefox_147", "firefox_146",
        "firefox_145", "firefox_144", "firefox_143", "firefox_142", "firefox_139", "firefox_136",
        "firefox_private_136", "firefox_135", "firefox_private_135", "firefox_android_135",
        "firefox_133", "firefox_128", "firefox_117", "firefox_109",
        "opera_131", "opera_130", "opera_129", "opera_128", "opera_127", "opera_126",
        "opera_125", "opera_124", "opera_123", "opera_122", "opera_121", "opera_120",
        "opera_119", "opera_118", "opera_117", "opera_116",
        "okhttp_5", "okhttp_4_12", "okhttp_4_10", "okhttp_4_9", "okhttp_3_14", "okhttp_3_13",
        "okhttp_3_11", "okhttp_3_9",
        "tor_14_5", "random", "weighted_random",
    ]
}

#[pyfunction]
pub fn is_verified_preset(preset: &str) -> bool {
    let lower = preset.trim().to_lowercase().replace('-', "_");
    if matches!(lower.as_str(), "random" | "weighted_random" | "auto" | "chrome" | "default") {
        return true;
    }
    let resolved = resolve_emulation(&lower);
    resolved.ua_override.is_none()
        && resolved.sec_ch_ua_override.is_none()
        && !lower.starts_with("safari_27")
        && !lower.starts_with("safari27")
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeStream>()?;
    m.add_class::<NativeWebSocket>()?;
    m.add_class::<NativeSession>()?;
    m.add_function(wrap_pyfunction!(supported_presets, m)?)?;
    m.add_function(wrap_pyfunction!(is_verified_preset, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
