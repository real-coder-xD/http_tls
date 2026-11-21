// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 ABI3 Extension | Runtime: Tokio + wreq (BoringSSL)
use bytes::Bytes;
use encoding_rs::{Encoding, UTF_8};
use futures_util::{Stream, StreamExt};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::multipart::{Form, Part};
use wreq::redirect::Policy;
use wreq::tls::trust::{CertStore, Identity};
use wreq::ws::message::{CloseCode, Message};
use wreq::{Client, Method, Proxy, RequestBuilder, Version};
use wreq_util::{Emulation, Platform, Profile};

type BodyStream = Pin<Box<dyn Stream<Item = wreq::Result<Bytes>> + Send + 'static>>;
type MultipartItem = (String, Option<String>, Vec<u8>, Option<String>);

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

    // Chrome family (including forward versions 150-152 using Chrome149 BoringSSL + patched UA/CH)
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
            let grease = if ver % 2 == 0 { "24" } else { "99" };
            let ch = format!("\"Google Chrome\";v=\"{ver}\", \"Chromium\";v=\"{ver}\", \"Not)A;Brand\";v=\"{grease}\"");
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

    // Edge family
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
            let ch = format!("\"Microsoft Edge\";v=\"{ver}\", \"Chromium\";v=\"{ver}\", \"Not)A;Brand\";v=\"24\"");
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

    // Firefox / Tor family
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

    // Safari family
    if lower.starts_with("safari") {
        let is_ios = lower.contains("ios");
        let is_ipad = lower.contains("ipad");
        let clean = lower
            .replace("safari", "")
            .replace("ios", "")
            .replace("ipad", "")
            .replace('_', "")
            .replace('.', "");
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

    // Opera family
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

    // OkHttp family
    if lower.starts_with("okhttp") {
        let clean = lower.replace("okhttp", "").replace('_', "").replace('.', "");
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

    // Fallback: latest Chrome149
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
}

#[pymethods]
impl NativeResponse {
    #[getter]
    pub fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.content)
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
    inner: Arc<tokio::sync::Mutex<Option<BodyStream>>>,
}

#[pymethods]
impl NativeStream {
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
// Session (BoringSSL native TLS + H2 + Cookie Jar + Sync/Async + Multipart + WS)
// ---------------------------------------------------------------------------
#[derive(Clone, Hash, PartialEq, Eq)]
struct ClientKey {
    verify: bool,
    ca_hash: Option<Vec<u8>>,
}

#[pyclass(name = "Session")]
pub struct NativeSession {
    jar: Arc<Jar>,
    clients: Mutex<HashMap<ClientKey, Client>>,
    emulation: Emulation,
    ua_override: Option<String>,
    sec_ch_ua_override: Option<String>,
    default_headers: HeaderMap,
    timeout: Duration,
    max_redirects: usize,
    ca_bundle: Option<Vec<u8>>,
    identity_pair: Option<(Vec<u8>, Vec<u8>)>,
    default_proxy: Option<String>,
    follow_redirects: bool,
    verify: bool,
    impersonate: String,
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

        let mut b = Client::builder()
            .emulation(self.emulation.clone())
            .cookie_provider(Arc::clone(&self.jar))
            .timeout(self.timeout)
            .tls_cert_verification(verify)
            .tls_verify_hostname(verify)
            .redirect(if self.follow_redirects {
                Policy::limited(self.max_redirects)
            } else {
                Policy::none()
            });

        if !self.default_headers.is_empty() {
            b = b.default_headers(self.default_headers.clone());
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

        // Apply forward-version UA/Sec-CH-UA patch if preset > wreq-util's built-in cap
        if let Some(ref ua) = self.ua_override {
            if let Ok(hv) = HeaderValue::from_str(ua) {
                rb = rb.header(wreq::header::USER_AGENT, hv);
            }
        }
        if let Some(ref ch) = self.sec_ch_ua_override {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str("sec-ch-ua"), HeaderValue::from_str(ch)) {
                rb = rb.header(hn, hv);
            }
        }

        for (k, v) in dict_pairs(headers)? {
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
}

async fn finish_response(rb: RequestBuilder, jar: Arc<Jar>) -> PyResult<NativeResponse> {
    let start = Instant::now();
    let resp = rb.send().await.map_err(net_err)?;
    let status_code = resp.status().as_u16();
    let http_version = version_str(resp.version());
    let final_url = resp.uri().to_string();
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
    })
}

async fn start_stream(rb: RequestBuilder, jar: Arc<Jar>) -> PyResult<NativeStream> {
    let start = Instant::now();
    let resp = rb.send().await.map_err(net_err)?;
    let elapsed = start.elapsed().as_secs_f64();
    let status_code = resp.status().as_u16();
    let http_version = version_str(resp.version());
    let final_url = resp.uri().to_string();
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
        inner: Arc::new(tokio::sync::Mutex::new(Some(stream))),
    })
}

#[pymethods]
impl NativeSession {
    #[new]
    #[pyo3(signature = (
        impersonate = "chrome_152",
        timeout = 30.0,
        follow_redirects = true,
        max_redirects = 10,
        verify_ssl = true,
        proxy = None,
        headers = None,
        ca_bundle = None,
        client_cert = None,
        client_key = None
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

        let resolved = resolve_emulation(impersonate);

        Ok(NativeSession {
            jar: Arc::new(Jar::default()),
            clients: Mutex::new(HashMap::new()),
            emulation: resolved.emulation,
            ua_override: resolved.ua_override,
            sec_ch_ua_override: resolved.sec_ch_ua_override,
            default_headers,
            timeout: Duration::from_secs_f64(timeout.max(0.05)),
            max_redirects,
            ca_bundle,
            identity_pair,
            default_proxy: proxy,
            follow_redirects,
            verify: verify_ssl,
            impersonate: impersonate.to_string(),
        })
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None
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
    ) -> PyResult<NativeResponse> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle,
        )?;
        let jar = Arc::clone(&self.jar);
        py.allow_threads(move || runtime().block_on(finish_response(rb, jar)))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None
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
    ) -> PyResult<Bound<'py, PyAny>> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle,
        )?;
        let jar = Arc::clone(&self.jar);
        pyo3_async_runtimes::tokio::future_into_py(py, finish_response(rb, jar))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None
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
    ) -> PyResult<NativeStream> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle,
        )?;
        let jar = Arc::clone(&self.jar);
        py.allow_threads(move || runtime().block_on(start_stream(rb, jar)))
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None
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
    ) -> PyResult<Bound<'py, PyAny>> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle,
        )?;
        let jar = Arc::clone(&self.jar);
        pyo3_async_runtimes::tokio::future_into_py(py, start_stream(rb, jar))
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

    pub fn clear_cookies(&self) {
        self.jar.clear();
    }

    #[getter]
    pub fn impersonate(&self) -> String {
        self.impersonate.clone()
    }
}

#[pyfunction]
pub fn supported_presets() -> Vec<&'static str> {
    vec![
        "chrome_152", "chrome_152_macos", "chrome_151", "chrome_151_macos", "chrome_150",
        "chrome_149", "chrome_148", "chrome_147", "chrome_146", "chrome_145", "chrome_144",
        "chrome_143", "chrome_142", "chrome_141", "chrome_140", "chrome_139", "chrome_138",
        "chrome_137", "chrome_136", "chrome_135", "chrome_134", "chrome_133", "chrome_132",
        "chrome_131", "chrome_131_android", "chrome_130", "chrome_129", "chrome_128",
        "chrome_127", "chrome_126", "chrome_124", "chrome_123", "chrome_120", "chrome_119",
        "chrome_116", "chrome_114", "chrome_110", "chrome_107", "chrome_104", "chrome_100",
        "edge_152", "edge_148", "edge_147", "edge_146", "edge_145", "edge_142", "edge_136",
        "edge_134", "edge_131", "edge_127", "edge_122", "edge_101",
        "safari_27", "safari_26_4", "safari_26_3", "safari_26_2", "safari_26_1", "safari_26",
        "safari_ios_26_2", "safari_ios_26", "safari_ipad_26",
        "safari_18_5", "safari_18_4", "safari_18_3", "safari_18_2", "safari_18",
        "safari_ios_18_1_1", "safari_ipad_18",
        "safari_17_6", "safari_17_5", "safari_17_4_1", "safari_17_2_1", "safari_17",
        "safari_16_5", "safari_16", "safari_15_5", "safari_15_3",
        "firefox_155", "firefox_154", "firefox_153", "firefox_151", "firefox_150",
        "firefox_149", "firefox_148", "firefox_147", "firefox_146", "firefox_145",
        "firefox_144", "firefox_143", "firefox_142", "firefox_139", "firefox_136",
        "firefox_135", "firefox_android_135", "firefox_private_136", "firefox_133",
        "firefox_128", "firefox_117", "firefox_109",
        "opera_131", "opera_130", "opera_129", "opera_128", "opera_127", "opera_126",
        "opera_124", "opera_120", "opera_116",
        "okhttp_5", "okhttp_4_12", "okhttp_4_10", "okhttp_4_9", "okhttp_3_14", "okhttp_3_11",
        "tor_14_5", "random", "weighted_random",
    ]
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeStream>()?;
    m.add_class::<NativeWebSocket>()?;
    m.add_class::<NativeSession>()?;
    m.add_function(wrap_pyfunction!(supported_presets, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
