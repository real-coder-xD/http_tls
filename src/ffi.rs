// Language: Rust 2021 | File: src/ffi.rs | Target: C-ABI JSON FFI Layer for C#, Node.js, Go, C/C++, PHP, AutoIt, etc.
//! Thread-safe, zero-Python-dependency C-ABI bridge exposing the full Rust BoringSSL
//! HTTP/1.1, HTTP/2, UDP QUIC HTTP/3, Real ECH, DoH, SOCKS5 UDP, JA3/Akamai H2,
//! concurrent `gather`, Cookie Jar, WAF challenge detection, and Rust Extraction Engine.

use crate::doh::DEFAULT_DOH_URL;
use crate::error::{CoreError, CoreResult};
use crate::extract::{
    extract_between, extract_between_all, extract_css_json, extract_json_path_val,
    extract_re_first_pure, extract_re_pure, extract_xpath_json,
};
use crate::options::{
    parse_akamai_h2_to_http2_json, parse_http2_options_json, parse_ja3_to_tls_json,
    parse_resolve_map_json, parse_tls_options_json,
};
use crate::presets::supported_presets;
use crate::{
    runtime, safe_duration, MultipartItem, NativeResponse, NativeSession, NativeStream,
    RequestInput, SessionConfig,
};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::Notify;
use wreq::ws::message::{CloseCode, CloseFrame, Message};

// ---------------------------------------------------------------------------
// Thread-safe Global Session, Stream & Full-Duplex WebSocket Registries
// ---------------------------------------------------------------------------
struct StreamHandle {
    stream: Arc<NativeStream>,
    cancel: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
}

struct WsHandle {
    sink: Arc<tokio::sync::Mutex<Option<SplitSink<wreq::ws::WebSocket, Message>>>>,
    stream: Arc<tokio::sync::Mutex<Option<SplitStream<wreq::ws::WebSocket>>>>,
    cancel: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
}

fn sessions() -> &'static RwLock<HashMap<String, Arc<NativeSession>>> {
    static STORE: OnceLock<RwLock<HashMap<String, Arc<NativeSession>>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn streams() -> &'static RwLock<HashMap<String, Arc<StreamHandle>>> {
    static STORE: OnceLock<RwLock<HashMap<String, Arc<StreamHandle>>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn websockets() -> &'static RwLock<HashMap<String, Arc<WsHandle>>> {
    static STORE: OnceLock<RwLock<HashMap<String, Arc<WsHandle>>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn next_handle_id(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut rnd = [0u8; 4];
    unsafe {
        btls_sys::RAND_bytes(rnd.as_mut_ptr(), rnd.len());
    }
    format!(
        "{prefix}-{n}-{:02x}{:02x}{:02x}{:02x}",
        rnd[0], rnd[1], rnd[2], rnd[3]
    )
}

fn next_session_id() -> String {
    next_handle_id("s")
}

fn get_session(id: &str) -> CoreResult<Arc<NativeSession>> {
    let guard = sessions().read().unwrap_or_else(|p| p.into_inner());
    guard
        .get(id)
        .cloned()
        .ok_or_else(|| CoreError::runtime(format!("[session_not_found] Unknown session_id '{id}'")))
}

fn get_stream(id: &str) -> CoreResult<Arc<StreamHandle>> {
    let guard = streams().read().unwrap_or_else(|p| p.into_inner());
    guard
        .get(id)
        .cloned()
        .ok_or_else(|| CoreError::runtime(format!("[stream_not_found] Unknown stream_id '{id}'")))
}

fn get_ws(id: &str) -> CoreResult<Arc<WsHandle>> {
    let guard = websockets().read().unwrap_or_else(|p| p.into_inner());
    guard
        .get(id)
        .cloned()
        .ok_or_else(|| CoreError::runtime(format!("[ws_not_found] Unknown ws_id '{id}'")))
}

// ---------------------------------------------------------------------------
// Zero-dependency RFC 4648 Base64 Encode / Decode
// ---------------------------------------------------------------------------
const B64_ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ENC[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ENC[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ENC[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ENC[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub(crate) fn b64_decode(input: &str) -> CoreResult<Vec<u8>> {
    let mut vals: Vec<u8> = Vec::with_capacity(input.len());
    let mut pad = 0usize;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            pad += 1;
            vals.push(0);
            continue;
        }
        if pad > 0 {
            return Err(CoreError::value("Invalid base64: data after '=' padding"));
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return Err(CoreError::value(format!("Invalid base64 byte 0x{b:02x}"))),
        };
        vals.push(v);
    }
    if !vals.len().is_multiple_of(4) || pad > 2 {
        return Err(CoreError::value("Invalid base64 length or padding"));
    }
    let mut out = Vec::with_capacity((vals.len() / 4) * 3);
    for (idx, chunk) in vals.as_chunks::<4>().0.iter().enumerate() {
        let n = ((chunk[0] as u32) << 18)
            | ((chunk[1] as u32) << 12)
            | ((chunk[2] as u32) << 6)
            | (chunk[3] as u32);
        let is_last = (idx + 1) * 4 == vals.len();
        out.push(((n >> 16) & 0xff) as u8);
        if !(is_last && pad >= 2) {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if !(is_last && pad >= 1) {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// WAF / Anti-Bot Challenge Classifier (1:1 parity with python/http_tls/challenge.py)
// ---------------------------------------------------------------------------
fn header_ci<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    if let Some(v) = headers.get(key) {
        return Some(v.as_str());
    }
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

pub(crate) fn detect_challenge(
    status: u16,
    headers: &HashMap<String, String>,
    text: &str,
) -> Option<&'static str> {
    let server = header_ci(headers, "server").unwrap_or("").to_ascii_lowercase();

    if header_ci(headers, "cf-mitigated")
        .map(|v| v.eq_ignore_ascii_case("challenge"))
        .unwrap_or(false)
    {
        return Some("cloudflare");
    }
    if header_ci(headers, "x-vercel-mitigated")
        .map(|v| v.eq_ignore_ascii_case("challenge"))
        .unwrap_or(false)
    {
        return Some("vercel");
    }

    let is_chal_status = matches!(status, 403 | 429 | 503);
    if !is_chal_status && status != 200 {
        return None;
    }

    let limit = text.floor_char_boundary(text.len().min(32768));
    let low = text[..limit].to_ascii_lowercase();

    if server.contains("cloudflare")
        && is_chal_status
        && (low.contains("challenge-platform")
            || low.contains("cf_chl_opt")
            || low.contains("<title>just a moment"))
    {
        return Some("cloudflare");
    }

    if (server.contains("ddos-guard") || server.contains("ddg")) && is_chal_status {
        return Some("ddos-guard");
    }
    if low.contains("check.ddos-guard.net") || low.contains("ddos-guard/js-challenge") {
        return Some("ddos-guard");
    }

    if (header_ci(headers, "x-datadome").is_some() || header_ci(headers, "x-dd-b").is_some())
        && (is_chal_status || low.contains("captcha-delivery.com"))
    {
        return Some("datadome");
    }

    if is_chal_status && (low.contains("px-captcha") || low.contains("_pxappid")) {
        return Some("perimeterx");
    }

    if low.contains("_incapsula_resource")
        || (header_ci(headers, "x-iinfo").is_some() && is_chal_status)
    {
        return Some("imperva");
    }

    if server.contains("sucuri") && low.contains("sucuri_cloudproxy_js") {
        return Some("sucuri");
    }

    if server.contains("akamaighost") && status == 403 && low.contains("reference&#32;&#35;") {
        return Some("akamai");
    }

    None
}

// ---------------------------------------------------------------------------
// JSON Parsing Helpers
// ---------------------------------------------------------------------------
fn str_map_pairs(v: Option<&Value>) -> CoreResult<Vec<(String, String)>> {
    let Some(val) = v else {
        return Ok(Vec::new());
    };
    if val.is_null() {
        return Ok(Vec::new());
    }
    let obj = val
        .as_object()
        .ok_or_else(|| CoreError::value("Expected a JSON object for key/value map"))?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        let s = match v {
            Value::String(s) => s.clone(),
            Value::Null => continue,
            other => other.to_string(),
        };
        out.push((k.clone(), s));
    }
    Ok(out)
}

fn opt_string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn opt_str_vec(obj: &Map<String, Value>, key: &str) -> CoreResult<Option<Vec<String>>> {
    let Some(v) = obj.get(key) else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let arr = v
        .as_array()
        .ok_or_else(|| CoreError::value(format!("'{key}' must be an array of strings")))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| CoreError::value(format!("'{key}' elements must be strings")))?;
        out.push(s.to_string());
    }
    Ok(Some(out))
}

fn load_pem_bytes(
    obj: &Map<String, Value>,
    pem_key: &str,
    path_key: &str,
    b64_key: Option<&str>,
) -> CoreResult<Option<Vec<u8>>> {
    if let Some(s) = opt_string(obj, pem_key) {
        return Ok(Some(s.into_bytes()));
    }
    if let Some(bk) = b64_key {
        if let Some(s) = opt_string(obj, bk) {
            return Ok(Some(b64_decode(&s)?));
        }
    }
    if let Some(path) = opt_string(obj, path_key) {
        let bytes = std::fs::read(&path)
            .map_err(|e| CoreError::value(format!("Failed to read '{path}': {e}")))?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn parse_session_config_json(obj: &Map<String, Value>) -> CoreResult<SessionConfig> {
    let impersonate = opt_string(obj, "impersonate").unwrap_or_else(|| "chrome_149".to_string());
    let timeout = obj.get("timeout").and_then(Value::as_f64).unwrap_or(30.0);
    let follow_redirects = obj
        .get("follow_redirects")
        .or_else(|| obj.get("allow_redirects"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let max_redirects = obj
        .get("max_redirects")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .min(100) as usize;
    let verify_ssl = obj
        .get("verify")
        .or_else(|| obj.get("verify_ssl"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let proxy = opt_string(obj, "proxy");
    let headers = str_map_pairs(obj.get("headers"))?;
    let header_order = opt_str_vec(obj, "header_order")?;

    let ca_bundle = load_pem_bytes(obj, "ca_bundle_pem", "ca_bundle_path", Some("ca_bundle_base64"))?;
    let client_cert = load_pem_bytes(obj, "client_cert_pem", "client_cert_path", None)?;
    let client_key = load_pem_bytes(obj, "client_key_pem", "client_key_path", None)?;

    // Merge optional `ja3` string + explicit `tls_options` object (explicit fields win).
    let mut tls_map: Option<Map<String, Value>> = None;
    if let Some(ja3) = opt_string(obj, "ja3") {
        tls_map = Some(parse_ja3_to_tls_json(&ja3)?);
    }
    if let Some(raw_tls) = obj.get("tls_options").filter(|v| !v.is_null()) {
        let extra = raw_tls
            .as_object()
            .ok_or_else(|| CoreError::value("tls_options must be a JSON object"))?;
        let m = tls_map.get_or_insert_with(Map::new);
        for (k, v) in extra {
            m.insert(k.clone(), v.clone());
        }
    }
    let tls_options = match tls_map {
        Some(m) => Some(parse_tls_options_json(&Value::Object(m))?),
        None => None,
    };

    // Merge optional `akamai_h2` string + explicit `http2_options` object (explicit fields win).
    let mut h2_map: Option<Map<String, Value>> = None;
    if let Some(ak) = opt_string(obj, "akamai_h2") {
        h2_map = Some(parse_akamai_h2_to_http2_json(&ak)?);
    }
    if let Some(raw_h2) = obj.get("http2_options").filter(|v| !v.is_null()) {
        let extra = raw_h2
            .as_object()
            .ok_or_else(|| CoreError::value("http2_options must be a JSON object"))?;
        let m = h2_map.get_or_insert_with(Map::new);
        for (k, v) in extra {
            m.insert(k.clone(), v.clone());
        }
    }
    let http2_options = match h2_map {
        Some(m) => Some(parse_http2_options_json(&Value::Object(m))?),
        None => None,
    };

    let resolve_entries = match obj.get("resolve").filter(|v| !v.is_null()) {
        Some(v) => parse_resolve_map_json(v)?,
        None => Vec::new(),
    };

    let doh_flag = obj.get("doh").and_then(Value::as_bool).unwrap_or(false);
    let mut doh_url = opt_string(obj, "doh_url");
    if doh_flag && doh_url.as_deref().map(str::trim).unwrap_or("").is_empty() {
        doh_url = Some(DEFAULT_DOH_URL.to_string());
    }

    Ok(SessionConfig {
        impersonate,
        timeout,
        follow_redirects,
        max_redirects,
        verify_ssl,
        proxy,
        headers,
        ca_bundle,
        client_cert,
        client_key,
        header_order,
        tls_options,
        http2_options,
        http1_only: obj.get("http1_only").and_then(Value::as_bool).unwrap_or(false),
        http2_only: obj.get("http2_only").and_then(Value::as_bool).unwrap_or(false),
        http3: obj.get("http3").and_then(Value::as_bool).unwrap_or(false),
        http3_only: obj.get("http3_only").and_then(Value::as_bool).unwrap_or(false),
        ech: obj.get("ech").and_then(Value::as_bool).unwrap_or(false),
        ech_doh_url: opt_string(obj, "ech_doh_url"),
        doh_url,
        resolve_entries,
        local_address: opt_string(obj, "local_address"),
        interface: opt_string(obj, "interface"),
        tls_info: obj.get("tls_info").and_then(Value::as_bool).unwrap_or(false),
        connect_timeout: obj.get("connect_timeout").and_then(Value::as_f64),
        read_timeout: obj.get("read_timeout").and_then(Value::as_f64),
        pool_max_idle_per_host: obj
            .get("pool_max_idle_per_host")
            .and_then(Value::as_u64)
            .map(|n| n as usize),
        pool_idle_timeout: obj.get("pool_idle_timeout").and_then(Value::as_f64),
        keylog_file: opt_string(obj, "keylog_file"),
        system_dns: obj.get("system_dns").and_then(Value::as_bool).unwrap_or(false),
        tcp_nodelay: obj.get("tcp_nodelay").and_then(Value::as_bool),
        tcp_keepalive: obj.get("tcp_keepalive").and_then(Value::as_f64),
    })
}

fn parse_files_json(v: Option<&Value>) -> CoreResult<Vec<MultipartItem>> {
    let Some(val) = v.filter(|x| !x.is_null()) else {
        return Ok(Vec::new());
    };
    let arr = val
        .as_array()
        .ok_or_else(|| CoreError::value("'files' must be an array of multipart part objects"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item
            .as_object()
            .ok_or_else(|| CoreError::value("'files' entries must be JSON objects"))?;
        let field = opt_string(obj, "field")
            .or_else(|| opt_string(obj, "name"))
            .ok_or_else(|| CoreError::value("multipart file entry missing 'field'"))?;
        let filename = opt_string(obj, "filename");
        let content_type = opt_string(obj, "content_type");
        let payload = if let Some(b64) = opt_string(obj, "content_base64") {
            b64_decode(&b64)?
        } else if let Some(txt) = opt_string(obj, "content") {
            txt.into_bytes()
        } else if let Some(path) = opt_string(obj, "path") {
            std::fs::read(&path)
                .map_err(|e| CoreError::value(format!("Failed to read file '{path}': {e}")))?
        } else {
            Vec::new()
        };
        out.push((field, filename, payload, content_type));
    }
    Ok(out)
}

fn parse_request_input_json(obj: &Map<String, Value>) -> CoreResult<(RequestInput, bool)> {
    let method = opt_string(obj, "method").unwrap_or_else(|| "GET".to_string());
    let url = opt_string(obj, "url")
        .ok_or_else(|| CoreError::value("Request JSON missing required field 'url'"))?;
    let params = str_map_pairs(obj.get("params"))?;
    let mut headers = str_map_pairs(obj.get("headers"))?;
    let cookies = str_map_pairs(obj.get("cookies"))?;

    let data = if let Some(b64) = opt_string(obj, "body_base64") {
        Some(b64_decode(&b64)?)
    } else if let Some(form_val) = obj.get("form").filter(|v| !v.is_null()) {
        let pairs = str_map_pairs(Some(form_val))?;
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            ser.append_pair(&k, &v);
        }
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push((
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }
        Some(ser.finish().into_bytes())
    } else {
        opt_string(obj, "body")
            .or_else(|| opt_string(obj, "data"))
            .map(String::into_bytes)
    };

    let json_body = match obj.get("json") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    };

    let files = parse_files_json(obj.get("files"))?;
    let ca_bundle = load_pem_bytes(obj, "ca_bundle_pem", "ca_bundle_path", Some("ca_bundle_base64"))?;
    let ech_config_list = match opt_string(obj, "ech_config_base64") {
        Some(s) => Some(b64_decode(&s)?),
        None => None,
    };
    let return_body_base64 = obj
        .get("return_body_base64")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let input = RequestInput {
        method,
        url,
        params,
        headers,
        cookies,
        data,
        json: json_body,
        files,
        timeout: obj.get("timeout").and_then(Value::as_f64),
        proxy: opt_string(obj, "proxy"),
        allow_redirects: obj
            .get("allow_redirects")
            .or_else(|| obj.get("follow_redirects"))
            .and_then(Value::as_bool),
        verify: obj.get("verify").and_then(Value::as_bool),
        ca_bundle,
        header_order: opt_str_vec(obj, "header_order")?,
        impersonate: opt_string(obj, "impersonate"),
        local_address: opt_string(obj, "local_address"),
        http3: obj.get("http3").and_then(Value::as_bool),
        alt_svc_port: match obj.get("alt_svc_port").and_then(Value::as_u64) {
            Some(n) => Some(u16::try_from(n).map_err(|_| {
                CoreError::value(format!("alt_svc_port {n} out of u16 range (0..=65535)"))
            })?),
            None => None,
        },
        ech: obj.get("ech").and_then(Value::as_bool),
        ech_config_list,
    };
    Ok((input, return_body_base64))
}

fn response_to_json(resp: &NativeResponse, force_b64: bool) -> Value {
    let challenge = detect_challenge(resp.status_code, &resp.headers, &resp.text);
    let is_binary = std::str::from_utf8(&resp.content).is_err();
    let body_base64 = if force_b64 || is_binary {
        Value::String(b64_encode(&resp.content))
    } else {
        Value::Null
    };
    let history: Vec<Value> = resp
        .history
        .iter()
        .map(|(status, prev, next, hdrs)| {
            json!({
                "status_code": status,
                "from_url": prev,
                "to_url": next,
                "headers": hdrs,
            })
        })
        .collect();
    let peer_cert_b64 = resp
        .peer_certificate
        .as_deref()
        .map(b64_encode)
        .map(Value::String)
        .unwrap_or(Value::Null);

    json!({
        "ok": true,
        "status_code": resp.status_code,
        "url": resp.url,
        "http_version": resp.http_version,
        "headers": resp.headers,
        "cookies": resp.cookies,
        "body": resp.text,
        "body_base64": body_base64,
        "content_length": resp.content.len(),
        "encoding": resp.encoding,
        "elapsed": resp.elapsed,
        "remote_addr": resp.remote_addr,
        "ech_accepted": resp.ech_accepted,
        "tls_resumed": resp.tls_resumed,
        "challenge": challenge,
        "history": history,
        "peer_certificate_base64": peer_cert_b64,
    })
}

fn err_to_json(err: &CoreError) -> Value {
    let (kind, msg) = err.split_kind();
    json!({
        "ok": false,
        "error": msg,
        "error_kind": kind,
    })
}

// ---------------------------------------------------------------------------
// C-String Marshaling & Panic Guard
// ---------------------------------------------------------------------------
fn to_c_json(val: Value) -> *mut c_char {
    let s = serde_json::to_string(&val).unwrap_or_else(|_| {
        r#"{"ok":false,"error":"JSON serialization failed","error_kind":"internal"}"#.to_string()
    });
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => CString::new(
            r#"{"ok":false,"error":"Interior NUL byte in response","error_kind":"internal"}"#,
        )
        .unwrap()
        .into_raw(),
    }
}

unsafe fn read_c_str(ptr: *const c_char) -> CoreResult<Option<String>> {
    if ptr.is_null() {
        return Ok(None);
    }
    let s = CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| CoreError::value(format!("Input string is not valid UTF-8: {e}")))?;
    Ok(Some(s.to_string()))
}

fn parse_json_obj(raw: Option<String>, allow_empty: bool) -> CoreResult<Map<String, Value>> {
    let s = match raw {
        Some(ref t) if !t.trim().is_empty() => t.as_str(),
        _ if allow_empty => return Ok(Map::new()),
        _ => return Err(CoreError::value("Expected a non-empty JSON object string")),
    };
    let val: Value =
        serde_json::from_str(s).map_err(|e| CoreError::value(format!("Invalid JSON: {e}")))?;
    val.as_object()
        .cloned()
        .ok_or_else(|| CoreError::value("Expected top-level JSON object"))
}

fn ffi_guard<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> CoreResult<Value>,
{
    let outcome = catch_unwind(AssertUnwindSafe(f));
    match outcome {
        Ok(Ok(val)) => to_c_json(val),
        Ok(Err(err)) => to_c_json(err_to_json(&err)),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "Unexpected internal panic".to_string());
            to_c_json(json!({
                "ok": false,
                "error": msg,
                "error_kind": "panic",
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Public C-ABI Implementation Functions (re-exported by `ffi/src/lib.rs`)
// ---------------------------------------------------------------------------
pub fn capi_version() -> *mut c_char {
    ffi_guard(|| {
        Ok(json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "engine": "BoringSSL (wreq + quinn/h3 + dom_query)",
            "presets_count": supported_presets().len(),
            "features": [
                "http1", "http2", "http3", "real_ech_tcp", "real_ech_udp",
                "doh", "socks5_udp", "ja3", "akamai_h2", "gather",
                "streaming", "websocket",
                "challenge_detect", "extract_css", "extract_xpath",
                "extract_json_path", "extract_regex", "extract_between"
            ]
        }))
    })
}

pub fn capi_presets() -> *mut c_char {
    ffi_guard(|| {
        let presets = supported_presets();
        Ok(json!({
            "ok": true,
            "count": presets.len(),
            "presets": presets,
        }))
    })
}

/// # Safety
/// `config_json` must be either NULL or a valid NUL-terminated UTF-8 C string.
pub unsafe fn capi_create_session(config_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(config_json)? };
        let obj = parse_json_obj(raw, true)?;
        let custom_id = opt_string(&obj, "session_id").filter(|s| !s.trim().is_empty());
        let cfg = parse_session_config_json(&obj)?;
        let impersonate = cfg.impersonate.clone();
        let session = Arc::new(NativeSession::from_config(cfg)?);
        let session_id = custom_id.unwrap_or_else(next_session_id);
        let displaced = {
            let mut guard = sessions().write().unwrap_or_else(|p| p.into_inner());
            guard.insert(session_id.clone(), session)
        };
        if let Some(old) = displaced {
            old.close_core();
        }
        Ok(json!({
            "ok": true,
            "session_id": session_id,
            "impersonate": impersonate,
        }))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_request(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let (mut req, force_b64) = parse_request_input_json(&obj)?;

        let session = if let Some(sid) = opt_string(&obj, "session_id").filter(|s| !s.trim().is_empty()) {
            get_session(&sid)?
        } else {
            let mut cfg = parse_session_config_json(&obj)?;
            // One-shot request already passes headers/impersonate via `req`; keep session defaults clean.
            cfg.headers.clear();
            req.impersonate = None;
            Arc::new(NativeSession::from_config(cfg)?)
        };

        let resp = session.execute_sync_core(&req)?;
        Ok(response_to_json(&resp, force_b64))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_gather(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let concurrency = obj
            .get("concurrency")
            .and_then(Value::as_u64)
            .unwrap_or(50) as usize;
        let reqs_val = obj
            .get("requests")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::value("gather JSON requires a 'requests' array"))?;
        if reqs_val.is_empty() {
            return Ok(json!({
                "ok": true,
                "count": 0,
                "responses": [],
            }));
        }

        let session = if let Some(sid) = opt_string(&obj, "session_id").filter(|s| !s.trim().is_empty()) {
            get_session(&sid)?
        } else {
            let mut cfg = parse_session_config_json(&obj)?;
            cfg.headers.clear();
            Arc::new(NativeSession::from_config(cfg)?)
        };

        let mut inputs = Vec::with_capacity(reqs_val.len());
        let mut b64_flags = Vec::with_capacity(reqs_val.len());
        for item in reqs_val {
            let ro = item
                .as_object()
                .ok_or_else(|| CoreError::value("Each entry in 'requests' must be a JSON object"))?;
            let (inp, b64) = parse_request_input_json(ro)?;
            inputs.push(inp);
            b64_flags.push(b64);
        }

        let results = session.gather_sync_core(&inputs, concurrency)?;
        let mut out = Vec::with_capacity(results.len());
        for (res, force_b64) in results.into_iter().zip(b64_flags) {
            match res {
                Ok(resp) => out.push(response_to_json(&resp, force_b64)),
                Err(err) => out.push(err_to_json(&err)),
            }
        }
        Ok(json!({
            "ok": true,
            "count": out.len(),
            "responses": out,
        }))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_get_cookies(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let sid = opt_string(&obj, "session_id")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CoreError::value("get_cookies requires 'session_id'"))?;
        let session = get_session(&sid)?;

        if let Some(url) = opt_string(&obj, "url").filter(|s| !s.trim().is_empty()) {
            let map = session.cookies_for_core(&url);
            return Ok(json!({
                "ok": true,
                "session_id": sid,
                "url": url,
                "cookies": map,
            }));
        }

        let all: Vec<Value> = session
            .all_cookies_core()
            .into_iter()
            .map(|(name, value, domain, path, secure, http_only)| {
                json!({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": path,
                    "secure": secure,
                    "http_only": http_only,
                })
            })
            .collect();
        Ok(json!({
            "ok": true,
            "session_id": sid,
            "cookies": all,
        }))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_set_cookies(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let sid = opt_string(&obj, "session_id")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CoreError::value("set_cookies requires 'session_id'"))?;
        let session = get_session(&sid)?;

        if obj.get("clear").and_then(Value::as_bool).unwrap_or(false) {
            session.clear_cookies_core();
        }
        if let Some(del_name) = opt_string(&obj, "delete_name") {
            let dom = opt_string(&obj, "domain");
            let path = opt_string(&obj, "path");
            session.delete_cookie_core(&del_name, dom.as_deref(), path.as_deref());
        }
        let top_url = opt_string(&obj, "url").filter(|s| !s.trim().is_empty());
        if let (Some(raw_cookie), Some(ref url)) = (opt_string(&obj, "raw_cookie"), &top_url) {
            session.add_raw_cookie_core(&raw_cookie, url);
        }
        if let Some(cookies_val) = obj.get("cookies").filter(|v| !v.is_null()) {
            if let Some(arr) = cookies_val.as_array() {
                for item in arr {
                    let c = item.as_object().ok_or_else(|| {
                        CoreError::value("cookies array entries must be JSON objects")
                    })?;
                    let name = opt_string(c, "name")
                        .ok_or_else(|| CoreError::value("cookie entry missing 'name'"))?;
                    let value = opt_string(c, "value").unwrap_or_default();
                    let domain = opt_string(c, "domain").filter(|s| !s.trim().is_empty());
                    let path = opt_string(c, "path").filter(|s| !s.trim().is_empty());
                    let secure = c.get("secure").and_then(Value::as_bool).unwrap_or(false);
                    let http_only = c.get("http_only").and_then(Value::as_bool).unwrap_or(false);
                    let entry_url = opt_string(c, "url")
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| top_url.clone());

                    if let Some(ref dom) = domain {
                        let clean_dom = dom.trim().trim_start_matches('.');
                        if clean_dom.parse::<std::net::IpAddr>().is_ok() {
                            let cpath = path.as_deref().unwrap_or("/");
                            let mut raw = format!("{name}={value}; Path={cpath}");
                            if secure {
                                raw.push_str("; Secure");
                            }
                            if http_only {
                                raw.push_str("; HttpOnly");
                            }
                            let scheme = if secure { "https" } else { "http" };
                            let u = entry_url
                                .unwrap_or_else(|| format!("{scheme}://{clean_dom}{cpath}"));
                            session.add_raw_cookie_core(&raw, &u);
                        } else {
                            session.set_cookie_core(
                                &name,
                                &value,
                                Some(clean_dom),
                                path.as_deref(),
                                secure,
                                http_only,
                            );
                        }
                    } else if let Some(ref u) = entry_url {
                        let cpath = path.as_deref().unwrap_or("/");
                        let mut raw = format!("{name}={value}; Path={cpath}");
                        if secure {
                            raw.push_str("; Secure");
                        }
                        if http_only {
                            raw.push_str("; HttpOnly");
                        }
                        session.add_raw_cookie_core(&raw, u);
                    } else {
                        return Err(CoreError::value(format!(
                            "cookie '{name}' requires either 'domain' or a top-level 'url'"
                        )));
                    }
                }
            } else if let Some(map) = cookies_val.as_object() {
                let u = top_url.as_deref().ok_or_else(|| {
                    CoreError::value("cookies object map requires a top-level 'url'")
                })?;
                for (name, val) in map {
                    let value = match val {
                        Value::String(s) => s.clone(),
                        Value::Null => continue,
                        other => other.to_string(),
                    };
                    session.add_raw_cookie_core(&format!("{name}={value}; Path=/"), u);
                }
            } else {
                return Err(CoreError::value(
                    "'cookies' must be an array of cookie objects or a {name: value} object",
                ));
            }
        }
        Ok(json!({
            "ok": true,
            "session_id": sid,
            "count": session.all_cookies_core().len(),
        }))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_set_impersonate(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let sid = opt_string(&obj, "session_id")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CoreError::value("set_impersonate requires 'session_id'"))?;
        let preset = opt_string(&obj, "impersonate")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CoreError::value("set_impersonate requires 'impersonate'"))?;
        let session = get_session(&sid)?;
        session.set_impersonate_core(&preset);
        Ok(json!({
            "ok": true,
            "session_id": sid,
            "impersonate": preset,
        }))
    })
}

/// # Safety
/// `session_id` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_destroy_session(session_id: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(session_id)? }
            .ok_or_else(|| CoreError::value("session_id pointer is NULL"))?;
        let sid = if raw.trim_start().starts_with('{') {
            let obj = parse_json_obj(Some(raw), false)?;
            opt_string(&obj, "session_id")
                .ok_or_else(|| CoreError::value("Missing 'session_id'"))?
        } else {
            raw.trim().to_string()
        };
        let removed = {
            let mut guard = sessions().write().unwrap_or_else(|p| p.into_inner());
            guard.remove(&sid)
        };
        if let Some(sess) = removed {
            sess.close_core();
            Ok(json!({ "ok": true, "session_id": sid, "destroyed": true }))
        } else {
            Ok(json!({ "ok": true, "session_id": sid, "destroyed": false }))
        }
    })
}

pub fn capi_destroy_all_sessions() -> *mut c_char {
    ffi_guard(|| {
        let drained_sessions: Vec<Arc<NativeSession>> = {
            let mut guard = sessions().write().unwrap_or_else(|p| p.into_inner());
            guard.drain().map(|(_, s)| s).collect()
        };
        let drained_streams: Vec<Arc<StreamHandle>> = {
            let mut guard = streams().write().unwrap_or_else(|p| p.into_inner());
            guard.drain().map(|(_, s)| s).collect()
        };
        let drained_ws: Vec<Arc<WsHandle>> = {
            let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
            guard.drain().map(|(_, w)| w).collect()
        };

        let count = drained_sessions.len();
        let stream_count = drained_streams.len();
        let ws_count = drained_ws.len();
        for sess in drained_sessions {
            sess.close_core();
        }
        for st in &drained_streams {
            st.cancelled.store(true, Ordering::Release);
            st.cancel.notify_waiters();
        }
        for ws in &drained_ws {
            ws.cancelled.store(true, Ordering::Release);
            ws.cancel.notify_waiters();
        }
        if !drained_streams.is_empty() || !drained_ws.is_empty() {
            runtime().block_on(async move {
                for st in drained_streams {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(250),
                        async { st.stream.inner.lock().await.take(); },
                    )
                    .await;
                }
                for ws in drained_ws {
                    if let Ok(mut guard) =
                        tokio::time::timeout(Duration::from_millis(500), ws.sink.lock()).await
                    {
                        if let Some(mut s) = guard.take() {
                            let frame = CloseFrame {
                                code: CloseCode::from(1000u16),
                                reason: "".into(),
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                                let _ = s.send(Message::close(frame)).await;
                                let _ = s.close().await;
                            })
                            .await;
                        }
                    }
                }
            });
        }
        Ok(json!({
            "ok": true,
            "destroyed_count": count,
            "destroyed_streams": stream_count,
            "destroyed_websockets": ws_count,
        }))
    })
}

fn parse_id_and_opt_obj(
    raw: Option<String>,
    key: &str,
) -> CoreResult<(String, Map<String, Value>)> {
    let s = raw
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| CoreError::value(format!("Missing '{key}'")))?;
    if s.trim_start().starts_with('{') {
        let obj = parse_json_obj(Some(s), false)?;
        let id = opt_string(&obj, key)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| CoreError::value(format!("Missing '{key}'")))?;
        Ok((id, obj))
    } else {
        Ok((s.trim().to_string(), Map::new()))
    }
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_stream_open(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let (mut req, _) = parse_request_input_json(&obj)?;

        let session = if let Some(sid) =
            opt_string(&obj, "session_id").filter(|s| !s.trim().is_empty())
        {
            get_session(&sid)?
        } else {
            let mut cfg = parse_session_config_json(&obj)?;
            cfg.headers.clear();
            req.impersonate = None;
            Arc::new(NativeSession::from_config(cfg)?)
        };

        let st = Arc::new(session.execute_stream_sync_core(&req)?);
        let stream_id = next_handle_id("st");
        let history: Vec<Value> = st
            .history
            .iter()
            .map(|(status, prev, next, hdrs)| {
                json!({
                    "status_code": status,
                    "from_url": prev,
                    "to_url": next,
                    "headers": hdrs,
                })
            })
            .collect();
        let peer_cert_b64 = st
            .peer_certificate
            .as_deref()
            .map(b64_encode)
            .map(Value::String)
            .unwrap_or(Value::Null);

        let resp_json = json!({
            "ok": true,
            "stream_id": stream_id,
            "status_code": st.status_code,
            "url": st.url,
            "http_version": st.http_version,
            "headers": st.headers,
            "cookies": st.cookies,
            "encoding": st.encoding,
            "elapsed": st.elapsed,
            "remote_addr": st.remote_addr,
            "ech_accepted": st.ech_accepted,
            "tls_resumed": st.tls_resumed,
            "history": history,
            "peer_certificate_base64": peer_cert_b64,
        });
        let handle = Arc::new(StreamHandle {
            stream: st,
            cancel: Arc::new(Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        {
            let mut guard = streams().write().unwrap_or_else(|p| p.into_inner());
            guard.insert(stream_id, handle);
        }
        Ok(resp_json)
    })
}

/// # Safety
/// `request_json` must be either a raw stream_id string or a JSON object `{"stream_id": "...", "timeout": 30.0}`.
pub unsafe fn capi_stream_read(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let (stream_id, obj) = parse_id_and_opt_obj(raw, "stream_id")?;
        let read_timeout = obj
            .get("timeout")
            .and_then(Value::as_f64)
            .map(|t| safe_duration(t, 0.05, 86_400.0))
            .unwrap_or(Duration::from_secs(60));
        let handle = get_stream(&stream_id)?;
        let inner = Arc::clone(&handle.stream.inner);
        let cancel = Arc::clone(&handle.cancel);
        let cancelled = Arc::clone(&handle.cancelled);

        let outcome = runtime().block_on(async move {
            let fut = async move {
                if cancelled.load(Ordering::Acquire) {
                    return Ok(None);
                }
                let mut guard = inner.lock().await;
                if cancelled.load(Ordering::Acquire) {
                    guard.take();
                    return Ok(None);
                }
                let next = match guard.as_mut() {
                    None => return Ok(None),
                    Some(stream) => {
                        tokio::select! {
                            biased;
                            _ = cancel.notified() => None,
                            item = stream.next() => match item {
                                None => None,
                                Some(Ok(b)) => Some(b),
                                Some(Err(e)) => {
                                    guard.take();
                                    return Err(e);
                                }
                            }
                        }
                    }
                };
                if next.is_none() {
                    guard.take();
                }
                Ok(next)
            };
            tokio::time::timeout(read_timeout, fut)
                .await
                .map_err(|_| CoreError::runtime("[timeout] Stream read timed out"))?
        });

        match outcome {
            Ok(Some(chunk)) => {
                let text = String::from_utf8_lossy(&chunk).into_owned();
                let b64 = b64_encode(&chunk);
                Ok(json!({
                    "ok": true,
                    "stream_id": stream_id,
                    "eof": false,
                    "length": chunk.len(),
                    "text": text,
                    "data_base64": b64,
                }))
            }
            Ok(None) => {
                let mut guard = streams().write().unwrap_or_else(|p| p.into_inner());
                guard.remove(&stream_id);
                Ok(json!({
                    "ok": true,
                    "stream_id": stream_id,
                    "eof": true,
                    "length": 0,
                    "text": "",
                    "data_base64": Value::Null,
                }))
            }
            Err(e) => {
                if !e.message().starts_with("[timeout]") {
                    let mut guard = streams().write().unwrap_or_else(|p| p.into_inner());
                    guard.remove(&stream_id);
                }
                Err(e)
            }
        }
    })
}

/// # Safety
/// `stream_id` must be a valid NUL-terminated UTF-8 string (raw ID or `{"stream_id": "..."}`).
pub unsafe fn capi_stream_close(stream_id: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(stream_id)? };
        let (sid, _) = parse_id_and_opt_obj(raw, "stream_id")?;
        let removed = {
            let mut guard = streams().write().unwrap_or_else(|p| p.into_inner());
            guard.remove(&sid)
        };
        if let Some(handle) = removed {
            handle.cancelled.store(true, Ordering::Release);
            handle.cancel.notify_waiters();
            runtime().spawn(async move {
                handle.stream.inner.lock().await.take();
            });
            Ok(json!({ "ok": true, "stream_id": sid, "closed": true }))
        } else {
            Ok(json!({ "ok": true, "stream_id": sid, "closed": false }))
        }
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_ws_connect(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let url = opt_string(&obj, "url")
            .ok_or_else(|| CoreError::value("ws_connect requires 'url'"))?;
        let headers = str_map_pairs(obj.get("headers"))?;
        let proxy = opt_string(&obj, "proxy");
        let verify = obj.get("verify").and_then(Value::as_bool);
        let timeout = obj.get("timeout").and_then(Value::as_f64);
        let ca_bundle = load_pem_bytes(&obj, "ca_bundle_pem", "ca_bundle_path", Some("ca_bundle_base64"))?;

        let session = if let Some(sid) =
            opt_string(&obj, "session_id").filter(|s| !s.trim().is_empty())
        {
            get_session(&sid)?
        } else {
            let mut cfg = parse_session_config_json(&obj)?;
            cfg.headers.clear();
            Arc::new(NativeSession::from_config(cfg)?)
        };

        let (status_code, resp_headers, protocol, ws) = session.ws_connect_sync_core(
            &url,
            &headers,
            proxy.as_deref(),
            verify,
            ca_bundle.as_deref(),
            timeout,
        )?;
        let (sink, stream) = ws.split();
        let ws_id = next_handle_id("ws");
        let handle = Arc::new(WsHandle {
            sink: Arc::new(tokio::sync::Mutex::new(Some(sink))),
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            cancel: Arc::new(Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        {
            let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
            guard.insert(ws_id.clone(), handle);
        }
        Ok(json!({
            "ok": true,
            "ws_id": ws_id,
            "status_code": status_code,
            "headers": resp_headers,
            "protocol": protocol,
        }))
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_ws_send(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let ws_id = opt_string(&obj, "ws_id")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| CoreError::value("ws_send requires 'ws_id'"))?;
        let send_timeout = obj
            .get("timeout")
            .and_then(Value::as_f64)
            .map(|t| safe_duration(t, 0.05, 86_400.0))
            .unwrap_or(Duration::from_secs(30));

        let msg = if let Some(txt) = opt_string(&obj, "text") {
            Message::text(txt)
        } else if let Some(b64) = opt_string(&obj, "data_base64") {
            Message::binary(b64_decode(&b64)?)
        } else if let Some(pb64) = opt_string(&obj, "ping_base64") {
            Message::ping(b64_decode(&pb64)?)
        } else {
            return Err(CoreError::value(
                "ws_send requires one of 'text', 'data_base64', or 'ping_base64'",
            ));
        };

        let handle = get_ws(&ws_id)?;
        let sink = Arc::clone(&handle.sink);
        runtime().block_on(async move {
            let fut = async move {
                let mut guard = sink.lock().await;
                let ws = guard
                    .as_mut()
                    .ok_or_else(|| CoreError::runtime("[request] WebSocket closed"))?;
                ws.send(msg).await.map_err(crate::net_err)
            };
            tokio::time::timeout(send_timeout, fut)
                .await
                .map_err(|_| CoreError::runtime("[timeout] WebSocket send timed out"))?
        })?;
        Ok(json!({ "ok": true, "ws_id": ws_id }))
    })
}

/// # Safety
/// `request_json` must be a raw ws_id string or JSON object `{"ws_id": "...", "timeout": 30.0}`.
pub unsafe fn capi_ws_recv(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let (ws_id, obj) = parse_id_and_opt_obj(raw, "ws_id")?;
        let recv_timeout = obj
            .get("timeout")
            .and_then(Value::as_f64)
            .map(|t| safe_duration(t, 0.05, 86_400.0))
            .unwrap_or(Duration::from_secs(60));
        let handle = get_ws(&ws_id)?;
        let stream = Arc::clone(&handle.stream);
        let cancel = Arc::clone(&handle.cancel);
        let cancelled = Arc::clone(&handle.cancelled);

        let outcome = runtime().block_on(async move {
            let fut = async move {
                if cancelled.load(Ordering::Acquire) {
                    return Ok(None);
                }
                let mut guard = stream.lock().await;
                if cancelled.load(Ordering::Acquire) {
                    guard.take();
                    return Ok(None);
                }
                let ws = match guard.as_mut() {
                    Some(w) => w,
                    None => return Ok(None),
                };
                tokio::select! {
                    biased;
                    _ = cancel.notified() => {
                        guard.take();
                        Ok(None)
                    }
                    item = ws.next() => {
                        match item {
                            None => {
                                guard.take();
                                Ok(None)
                            }
                            Some(Ok(msg)) => {
                                if matches!(msg, Message::Close(_)) {
                                    guard.take();
                                }
                                Ok(Some(msg))
                            }
                            Some(Err(e)) => {
                                guard.take();
                                Err(crate::net_err(e))
                            }
                        }
                    }
                }
            };
            tokio::time::timeout(recv_timeout, fut)
                .await
                .map_err(|_| CoreError::runtime("[timeout] WebSocket recv timed out"))?
        });

        match outcome {
            Ok(Some(Message::Text(t))) => Ok(json!({
                "ok": true,
                "ws_id": ws_id,
                "closed": false,
                "kind": "text",
                "text": t.as_str(),
                "data_base64": Value::Null,
            })),
            Ok(Some(Message::Binary(b))) => Ok(json!({
                "ok": true,
                "ws_id": ws_id,
                "closed": false,
                "kind": "binary",
                "text": Value::Null,
                "data_base64": b64_encode(&b),
            })),
            Ok(Some(Message::Ping(b))) => Ok(json!({
                "ok": true,
                "ws_id": ws_id,
                "closed": false,
                "kind": "ping",
                "text": Value::Null,
                "data_base64": b64_encode(&b),
            })),
            Ok(Some(Message::Pong(b))) => Ok(json!({
                "ok": true,
                "ws_id": ws_id,
                "closed": false,
                "kind": "pong",
                "text": Value::Null,
                "data_base64": b64_encode(&b),
            })),
            Ok(Some(Message::Close(frame))) => {
                let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
                guard.remove(&ws_id);
                let reason = frame
                    .map(|f| f.reason.as_str().to_string())
                    .unwrap_or_default();
                Ok(json!({
                    "ok": true,
                    "ws_id": ws_id,
                    "closed": true,
                    "kind": "close",
                    "text": reason,
                    "data_base64": Value::Null,
                }))
            }
            Ok(None) => {
                let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
                guard.remove(&ws_id);
                Ok(json!({
                    "ok": true,
                    "ws_id": ws_id,
                    "closed": true,
                    "kind": "close",
                    "text": "",
                    "data_base64": Value::Null,
                }))
            }
            Err(e) => {
                if !e.message().starts_with("[timeout]") {
                    let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
                    guard.remove(&ws_id);
                }
                Err(e)
            }
        }
    })
}

/// # Safety
/// `request_json` must be a raw ws_id string or JSON object `{"ws_id": "...", "code": 1000, "reason": ""}`.
pub unsafe fn capi_ws_close(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let (ws_id, obj) = parse_id_and_opt_obj(raw, "ws_id")?;
        let code = match obj.get("code").and_then(Value::as_u64) {
            Some(n) => u16::try_from(n)
                .map_err(|_| CoreError::value(format!("Invalid WebSocket close code {n}")))?,
            None => 1000,
        };
        let reason = opt_string(&obj, "reason").unwrap_or_default();
        let removed = {
            let mut guard = websockets().write().unwrap_or_else(|p| p.into_inner());
            guard.remove(&ws_id)
        };
        if let Some(handle) = removed {
            handle.cancelled.store(true, Ordering::Release);
            handle.cancel.notify_waiters();
            let sink = Arc::clone(&handle.sink);
            runtime().block_on(async move {
                if let Ok(mut guard) =
                    tokio::time::timeout(Duration::from_secs(1), sink.lock()).await
                {
                    if let Some(mut s) = guard.take() {
                        let frame = CloseFrame {
                            code: CloseCode::from(code),
                            reason: reason.into(),
                        };
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            let _ = s.send(Message::close(frame)).await;
                            let _ = s.close().await;
                        })
                        .await;
                    }
                }
            });
            Ok(json!({ "ok": true, "ws_id": ws_id, "closed": true }))
        } else {
            Ok(json!({ "ok": true, "ws_id": ws_id, "closed": false }))
        }
    })
}

/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 C string (or NULL).
pub unsafe fn capi_extract(request_json: *const c_char) -> *mut c_char {
    ffi_guard(|| {
        let raw = unsafe { read_c_str(request_json)? };
        let obj = parse_json_obj(raw, false)?;
        let content = opt_string(&obj, "content")
            .or_else(|| opt_string(&obj, "html"))
            .or_else(|| opt_string(&obj, "text"))
            .or_else(|| opt_string(&obj, "body"))
            .ok_or_else(|| CoreError::value("extract requires 'content' (or 'html'/'text'/'body')"))?;
        let first = obj.get("first").and_then(Value::as_bool).unwrap_or(false);

        if let Some(sel) = opt_string(&obj, "css") {
            let items = extract_css_json(&content, &sel, first).map_err(CoreError::value)?;
            let result = if first {
                items.into_iter().next().unwrap_or(Value::Null)
            } else {
                Value::Array(items)
            };
            return Ok(json!({ "ok": true, "mode": "css", "result": result }));
        }

        if let Some(expr) = opt_string(&obj, "xpath") {
            let items = extract_xpath_json(&content, &expr, first).map_err(CoreError::value)?;
            let result = if first {
                items.into_iter().next().unwrap_or(Value::Null)
            } else {
                Value::Array(items)
            };
            return Ok(json!({ "ok": true, "mode": "xpath", "result": result }));
        }

        if let Some(path) = opt_string(&obj, "json_path") {
            let val = extract_json_path_val(&content, &path).map_err(CoreError::value)?;
            return Ok(json!({
                "ok": true,
                "mode": "json_path",
                "found": val.is_some(),
                "result": val.unwrap_or(Value::Null),
            }));
        }

        if let Some(pat) = opt_string(&obj, "regex").or_else(|| opt_string(&obj, "re")) {
            let result = if first {
                match extract_re_first_pure(&content, &pat).map_err(CoreError::value)? {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                }
            } else {
                let items = extract_re_pure(&content, &pat).map_err(CoreError::value)?;
                Value::Array(items.into_iter().map(Value::String).collect())
            };
            return Ok(json!({ "ok": true, "mode": "regex", "result": result }));
        }

        if let (Some(left), Some(right)) = (opt_string(&obj, "left"), opt_string(&obj, "right")) {
            let result = if first {
                match extract_between(&content, &left, &right) {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                }
            } else {
                let items = extract_between_all(&content, &left, &right);
                Value::Array(items.into_iter().map(Value::String).collect())
            };
            return Ok(json!({ "ok": true, "mode": "between", "result": result }));
        }

        Err(CoreError::value(
            "extract requires one of: 'css', 'xpath', 'json_path', 'regex'/'re', or ('left' + 'right')",
        ))
    })
}

/// Safely free a UTF-8 string returned by any `http_tls_*` C-ABI function.
///
/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by an `http_tls_*` function and not yet freed.
pub unsafe fn capi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        for raw in [
            b"".as_slice(),
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 1, 2, 254, 255],
        ] {
            let enc = b64_encode(raw);
            let dec = b64_decode(&enc).unwrap();
            assert_eq!(dec, raw);
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_challenge_detection() {
        let mut h = HashMap::new();
        h.insert("cf-mitigated".to_string(), "challenge".to_string());
        assert_eq!(detect_challenge(403, &h, ""), Some("cloudflare"));

        let mut h2 = HashMap::new();
        h2.insert("server".to_string(), "cloudflare".to_string());
        assert_eq!(
            detect_challenge(403, &h2, "<title>Just a moment...</title>"),
            Some("cloudflare")
        );
        assert_eq!(detect_challenge(200, &h2, "<h1>Hello</h1>"), None);
    }

    #[test]
    fn test_ja3_and_akamai_parsers() {
        let tls = parse_ja3_to_tls_json(
            "771,4865-4866-4867-49195-49199,0-23-65281,4588-29-23-24,0",
        )
        .unwrap();
        assert_eq!(tls.get("min_tls_version").and_then(Value::as_str), Some("1.2"));
        assert!(tls
            .get("curves_list")
            .and_then(Value::as_str)
            .unwrap()
            .contains("X25519MLKEM768"));

        let h2 = parse_akamai_h2_to_http2_json(
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        )
        .unwrap();
        assert_eq!(
            h2.get("initial_connection_window_size").and_then(Value::as_u64),
            Some(15663105 + 65535)
        );
    }

    #[test]
    fn test_ffi_extract_css_xpath_json_regex_between() {
        unsafe {
            let html = r#"<html><body><h1>Title</h1><h2>Sub</h2><a class="buy" href="/item/42">Buy $19.99</a></body></html>"#;
            let q = CString::new(
                json!({"html": html, "css": "h1::text, h2::text"}).to_string(),
            )
            .unwrap();
            let ptr = capi_extract(q.as_ptr());
            let out: Value = serde_json::from_str(CStr::from_ptr(ptr).to_str().unwrap()).unwrap();
            capi_free_string(ptr);
            assert_eq!(out["ok"], true);
            assert_eq!(out["result"], json!(["Title", "Sub"]));

            let qx = CString::new(
                json!({"html": html, "xpath": "//a[@class='buy']/@href", "first": true}).to_string(),
            )
            .unwrap();
            let ptr2 = capi_extract(qx.as_ptr());
            let out2: Value = serde_json::from_str(CStr::from_ptr(ptr2).to_str().unwrap()).unwrap();
            capi_free_string(ptr2);
            assert_eq!(out2["result"], "/item/42");

            let jdoc = r#"{"items":[{"name":"A","price":10},{"name":"B","price":30}]}"#;
            let qj = CString::new(
                json!({"content": jdoc, "json_path": "items[?(@.price > 15)].name"}).to_string(),
            )
            .unwrap();
            let ptr3 = capi_extract(qj.as_ptr());
            let out3: Value = serde_json::from_str(CStr::from_ptr(ptr3).to_str().unwrap()).unwrap();
            capi_free_string(ptr3);
            assert_eq!(out3["found"], true);
            assert_eq!(out3["result"], json!(["B"]));
        }
    }
}
