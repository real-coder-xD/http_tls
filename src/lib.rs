// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 ABI3 Extension & Standalone C-ABI Shared Library | Runtime: Tokio + wreq (BoringSSL) + quinn/h3 (BoringSSL UDP QUIC + ECH + SOCKS5 UDP + DoH + TCP ECH)
mod doh;
mod error;
mod extract;
#[cfg(feature = "ffi")]
pub mod ffi;
mod h3_transport;
mod options;
mod presets;
mod quic_boring;
mod socks5_udp;
mod tcp_ech;
#[cfg(feature = "python")]
mod ws;

use doh::{DohResolver, EchCache, DEFAULT_DOH_URL};
pub(crate) use error::{CoreError, CoreResult};
pub(crate) use h3_transport::H3StreamDecoder;
use h3_transport::{
    clear_h3_pool_sync, decompress_h3_body, execute_h3_request, execute_h3_stream, H3Pool,
    H3RequestSpec,
};
use options::build_orig_headers;
#[cfg(feature = "python")]
use options::{parse_http2_options, parse_resolve_map, parse_tls_options};
use presets::{default_h3_browser_headers, resolve_emulation};
#[cfg(feature = "python")]
use presets::{is_verified_preset, supported_presets};
use quic_boring::TicketCache;
#[cfg(feature = "python")]
use ws::NativeWebSocket;

use bytes::Bytes;
use encoding_rs::{Encoding, UTF_8};
use futures_util::{Stream, StreamExt};
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::http2::Http2Options;
use wreq::multipart::{Form, Part};
use wreq::redirect::{History, Policy};
use wreq::tls::keylog::KeyLog;
use wreq::tls::trust::{CertStore, Identity};
use wreq::tls::{TlsInfo, TlsOptions};
use wreq::{Client, Method, Proxy, RequestBuilder, Version};
use wreq_util::Emulation;

pub(crate) type BodyStream = Pin<Box<dyn Stream<Item = CoreResult<Bytes>> + Send + 'static>>;
pub(crate) type MultipartItem = (String, Option<String>, Vec<u8>, Option<String>);
pub(crate) type HistoryTuple = (u16, String, String, HashMap<String, String>);
pub(crate) type CookieTuple = (String, String, String, String, bool, bool);

// ---------------------------------------------------------------------------
// Shared Tokio runtime (pyo3-async-runtimes under Python, OnceLock under C-ABI).
// ---------------------------------------------------------------------------
#[cfg(feature = "python")]
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    pyo3_async_runtimes::tokio::get_runtime()
}

#[cfg(not(feature = "python"))]
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("http_tls: failed to initialize Tokio runtime")
    })
}

pub(crate) fn safe_duration(secs: f64, min_secs: f64, max_secs: f64) -> Duration {
    if secs.is_finite() {
        Duration::from_secs_f64(secs.clamp(min_secs, max_secs))
    } else if secs.is_sign_negative() {
        Duration::from_secs_f64(min_secs)
    } else {
        Duration::from_secs_f64(max_secs)
    }
}

pub(crate) fn sanitize_redirect_headers(
    headers: &mut Vec<(String, String)>,
    from_url: &url::Url,
    to_url: &url::Url,
    stripped_body: bool,
) {
    let cross_origin = from_url.scheme() != to_url.scheme()
        || from_url.host_str() != to_url.host_str()
        || from_url.port_or_known_default() != to_url.port_or_known_default();
    headers.retain(|(k, _)| {
        let low = k.to_ascii_lowercase();
        if stripped_body
            && matches!(
                low.as_str(),
                "content-length" | "content-type" | "content-encoding" | "transfer-encoding"
            )
        {
            return false;
        }
        if cross_origin
            && matches!(
                low.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            )
        {
            return false;
        }
        true
    });
}

// ---------------------------------------------------------------------------
// Error classification: "[kind] clean message" mapped to requests/httpx/FFI errors.
// ---------------------------------------------------------------------------
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut segments: Vec<String> = Vec::new();
    let mut push_clean = |raw: String| {
        let s = raw.trim().to_string();
        if s.is_empty() {
            return;
        }
        if segments
            .last()
            .map(|prev| prev.eq_ignore_ascii_case(&s) || prev.ends_with(&s))
            .unwrap_or(false)
        {
            return;
        }
        if matches!(
            s.to_ascii_lowercase().as_str(),
            "dns error" | "dns resolution error" | "client error (connect)"
        ) && segments
            .iter()
            .any(|p| p.to_ascii_lowercase().contains(&s.to_ascii_lowercase()))
        {
            return;
        }
        segments.push(s);
    };
    push_clean(e.to_string());
    let mut src = e.source();
    while let Some(s) = src {
        push_clean(s.to_string());
        src = s.source();
    }
    segments.join(": ")
}

pub(crate) fn net_err(e: wreq::Error) -> CoreError {
    let chain = error_chain(&e);
    let low = chain.to_lowercase();
    let kind = if e.is_timeout() {
        if e.is_connect() {
            "connect_timeout"
        } else {
            "timeout"
        }
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
    CoreError::runtime(format!("[{kind}] {chain}"))
}

#[cfg(feature = "python")]
pub(crate) fn net_py_err(e: wreq::Error) -> PyErr {
    net_err(e).into()
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

pub(crate) fn collect_cookies(jar: &Jar, uri_str: &str, h: &HeaderMap) -> HashMap<String, String> {
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

pub(crate) fn charset_of(h: &HeaderMap) -> Option<&'static Encoding> {
    let ct = h.get(wreq::header::CONTENT_TYPE)?.to_str().ok()?.to_ascii_lowercase();
    let label = ct
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("charset="))?
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string();
    Encoding::for_label(label.as_bytes())
}

pub(crate) fn decode_body(bytes: &[u8], h: &HeaderMap) -> (String, String) {
    let enc = charset_of(h).unwrap_or(UTF_8);
    let (text, used, _) = enc.decode(bytes);
    (text.into_owned(), used.name().to_ascii_lowercase())
}

#[cfg(feature = "python")]
fn dict_pairs(d: Option<&Bound<'_, PyDict>>) -> PyResult<Vec<(String, String)>> {
    let mut v = Vec::new();
    if let Some(d) = d {
        for (k, val) in d {
            v.push((k.str()?.to_string(), val.str()?.to_string()));
        }
    }
    Ok(v)
}

#[cfg(feature = "python")]
fn parse_multipart_items(files: Option<&Bound<'_, PyList>>) -> PyResult<Vec<MultipartItem>> {
    let mut items = Vec::new();
    if let Some(list) = files {
        for entry in list.iter() {
            let tup = entry.downcast::<PyTuple>()?;
            if tup.len() != 4 {
                return Err(PyValueError::new_err(
                    "files entries must be (field, filename, bytes, content_type)",
                ));
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

fn build_cert_store(raw: &[u8]) -> CoreResult<CertStore> {
    CertStore::from_pem_stack(raw)
        .or_else(|_| CertStore::from_der_certs([raw]))
        .map_err(|e| {
            CoreError::value(format!(
                "Invalid CA bundle (expected PEM or DER): {}",
                error_chain(&e)
            ))
        })
}

fn build_identity(cert_pem: &[u8], key_pem: &[u8]) -> CoreResult<Identity> {
    Identity::from_pkcs8_pem(cert_pem, key_pem).map_err(|e| {
        CoreError::value(format!("Client certificate/key rejected: {}", error_chain(&e)))
    })
}

fn encode_multipart_body(items: &[MultipartItem]) -> (String, Vec<u8>) {
    let mut rnd = [0u8; 12];
    unsafe {
        btls_sys::RAND_bytes(rnd.as_mut_ptr(), rnd.len());
    }
    let mut boundary = String::from("----httpTlsBoundary");
    for b in rnd {
        use std::fmt::Write as _;
        let _ = write!(&mut boundary, "{b:02x}");
    }
    let mut body = Vec::new();
    for (field, filename, payload, mime) in items {
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
        body.extend_from_slice(field.replace('"', "\\\"").as_bytes());
        body.push(b'"');
        if let Some(fname) = filename {
            body.extend_from_slice(b"; filename=\"");
            body.extend_from_slice(fname.replace('"', "\\\"").as_bytes());
            body.push(b'"');
        }
        body.extend_from_slice(b"\r\n");
        if let Some(ct) = mime {
            body.extend_from_slice(b"Content-Type: ");
            body.extend_from_slice(ct.as_bytes());
            body.extend_from_slice(b"\r\n");
        } else if filename.is_some() {
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
    (format!("multipart/form-data; boundary={boundary}"), body)
}

// ---------------------------------------------------------------------------
// Response & Stream types (pure Rust structs + optional PyO3 bindings)
// ---------------------------------------------------------------------------
#[cfg_attr(feature = "python", pyclass(name = "Response"))]
pub struct NativeResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub url: String,
    pub content: Vec<u8>,
    pub text: String,
    pub encoding: String,
    pub elapsed: f64,
    pub cookies: HashMap<String, String>,
    pub http_version: String,
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    pub history: Vec<HistoryTuple>,
    pub ech_accepted: bool,
    pub tls_resumed: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl NativeResponse {
    #[getter]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    #[getter]
    pub fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    #[getter]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[getter]
    pub fn text(&self) -> String {
        self.text.clone()
    }

    #[getter]
    pub fn encoding(&self) -> String {
        self.encoding.clone()
    }

    #[getter]
    pub fn elapsed(&self) -> f64 {
        self.elapsed
    }

    #[getter]
    pub fn cookies(&self) -> HashMap<String, String> {
        self.cookies.clone()
    }

    #[getter]
    pub fn http_version(&self) -> String {
        self.http_version.clone()
    }

    #[getter]
    pub fn remote_addr(&self) -> Option<String> {
        self.remote_addr.clone()
    }

    #[getter]
    pub fn history(&self) -> Vec<HistoryTuple> {
        self.history.clone()
    }

    #[getter]
    pub fn ech_accepted(&self) -> bool {
        self.ech_accepted
    }

    #[getter]
    pub fn tls_resumed(&self) -> bool {
        self.tls_resumed
    }

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

#[cfg_attr(feature = "python", pyclass(name = "StreamResponse"))]
#[allow(dead_code)]
pub struct NativeStream {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub url: String,
    pub encoding: String,
    pub elapsed: f64,
    pub cookies: HashMap<String, String>,
    pub http_version: String,
    pub remote_addr: Option<String>,
    pub peer_certificate: Option<Vec<u8>>,
    pub history: Vec<HistoryTuple>,
    pub ech_accepted: bool,
    pub tls_resumed: bool,
    pub(crate) inner: Arc<tokio::sync::Mutex<Option<BodyStream>>>,
}

#[cfg(feature = "python")]
#[pymethods]
impl NativeStream {
    #[getter]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    #[getter]
    pub fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    #[getter]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[getter]
    pub fn encoding(&self) -> String {
        self.encoding.clone()
    }

    #[getter]
    pub fn elapsed(&self) -> f64 {
        self.elapsed
    }

    #[getter]
    pub fn cookies(&self) -> HashMap<String, String> {
        self.cookies.clone()
    }

    #[getter]
    pub fn http_version(&self) -> String {
        self.http_version.clone()
    }

    #[getter]
    pub fn remote_addr(&self) -> Option<String> {
        self.remote_addr.clone()
    }

    #[getter]
    pub fn history(&self) -> Vec<HistoryTuple> {
        self.history.clone()
    }

    #[getter]
    pub fn ech_accepted(&self) -> bool {
        self.ech_accepted
    }

    #[getter]
    pub fn tls_resumed(&self) -> bool {
        self.tls_resumed
    }

    #[getter]
    pub fn peer_certificate<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.peer_certificate.as_ref().map(|b| PyBytes::new(py, b))
    }

    pub fn read_chunk(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        let rt = runtime();
        let inner = Arc::clone(&self.inner);
        let chunk = py.allow_threads(|| -> CoreResult<Option<Bytes>> {
            rt.block_on(async move {
                let mut guard = inner.lock().await;
                let next = match guard.as_mut() {
                    None => return Ok(None),
                    Some(stream) => match stream.next().await {
                        None => None,
                        Some(Ok(b)) => Some(b),
                        Some(Err(e)) => return Err(e),
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
                    Some(Err(e)) => return Err(PyErr::from(e)),
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

// ---------------------------------------------------------------------------
// Pure Rust Session Config & Request Input (shared by PyO3 & C-ABI FFI)
// ---------------------------------------------------------------------------
pub(crate) struct SessionConfig {
    pub impersonate: String,
    pub timeout: f64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
    pub proxy: Option<String>,
    pub headers: Vec<(String, String)>,
    pub ca_bundle: Option<Vec<u8>>,
    pub client_cert: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    pub header_order: Option<Vec<String>>,
    pub tls_options: Option<TlsOptions>,
    pub http2_options: Option<Http2Options>,
    pub http1_only: bool,
    pub http2_only: bool,
    pub http3: bool,
    pub http3_only: bool,
    pub ech: bool,
    pub ech_doh_url: Option<String>,
    pub doh_url: Option<String>,
    pub resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    pub local_address: Option<String>,
    pub interface: Option<String>,
    pub tls_info: bool,
    pub connect_timeout: Option<f64>,
    pub read_timeout: Option<f64>,
    pub pool_max_idle_per_host: Option<usize>,
    pub pool_idle_timeout: Option<f64>,
    pub keylog_file: Option<String>,
    pub system_dns: bool,
    pub tcp_nodelay: Option<bool>,
    pub tcp_keepalive: Option<f64>,
}

pub(crate) struct RequestInput {
    pub method: String,
    pub url: String,
    pub params: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub data: Option<Vec<u8>>,
    pub json: Option<String>,
    pub files: Vec<MultipartItem>,
    pub timeout: Option<f64>,
    pub proxy: Option<String>,
    pub allow_redirects: Option<bool>,
    pub verify: Option<bool>,
    pub ca_bundle: Option<Vec<u8>>,
    pub header_order: Option<Vec<String>>,
    pub impersonate: Option<String>,
    pub local_address: Option<String>,
    pub http3: Option<bool>,
    pub alt_svc_port: Option<u16>,
    pub ech: Option<bool>,
    pub ech_config_list: Option<Vec<u8>>,
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

#[cfg_attr(feature = "python", pyclass(name = "Session"))]
pub struct NativeSession {
    jar: Arc<Jar>,
    clients: Mutex<HashMap<ClientKey, Client>>,
    h3_pool: H3Pool,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    emu_state: Mutex<EmulationState>,
    default_headers: HeaderMap,
    header_order: Option<Vec<String>>,
    tls_options: Option<TlsOptions>,
    http2_options: Option<Http2Options>,
    http1_only: bool,
    http2_only: bool,
    http3: bool,
    http3_only: bool,
    ech: bool,
    ech_doh_url: String,
    resolve_entries: Vec<(String, Vec<SocketAddr>)>,
    local_address: Option<IpAddr>,
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos"
    ))]
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
    pub(crate) fn from_config(cfg: SessionConfig) -> CoreResult<Self> {
        let mut default_headers = HeaderMap::new();
        for (k, v) in cfg.headers {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                default_headers.insert(hn, hv);
            }
        }

        if let Some(ref raw) = cfg.ca_bundle {
            build_cert_store(raw)?;
        }
        let identity_pair = match (cfg.client_cert, cfg.client_key) {
            (Some(c), Some(k)) => {
                build_identity(&c, &k)?;
                Some((c, k))
            }
            (None, None) => None,
            _ => {
                return Err(CoreError::value(
                    "Both client_cert and client_key PEM bytes are required",
                ))
            }
        };
        if let Some(ref p) = cfg.proxy {
            Proxy::all(p.as_str())
                .map_err(|e| CoreError::value(format!("Invalid proxy '{p}': {}", error_chain(&e))))?;
        }

        let parsed_local_addr = match cfg.local_address {
            Some(ref s) => Some(
                IpAddr::from_str(s)
                    .map_err(|e| CoreError::value(format!("Invalid local_address '{s}': {e}")))?,
            ),
            None => None,
        };
        #[cfg(not(any(
            target_os = "android",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos"
        )))]
        if cfg.interface.is_some() {
            return Err(CoreError::value(
                "interface binding is supported on Linux/macOS/Android/FreeBSD; use local_address on Windows",
            ));
        }

        let resolved = resolve_emulation(&cfg.impersonate);
        let parsed_doh_url = cfg.doh_url.filter(|s| !s.trim().is_empty());
        let doh_resolver = match parsed_doh_url {
            Some(ref u) => Some(
                DohResolver::new(u.clone(), cfg.proxy.as_deref())
                    .map_err(|e| CoreError::value(format!("Invalid doh_url '{u}': {e}")))?,
            ),
            None => None,
        };
        let effective_ech_doh = cfg
            .ech_doh_url
            .filter(|s| !s.trim().is_empty())
            .or(parsed_doh_url)
            .unwrap_or_else(|| DEFAULT_DOH_URL.to_string());

        Ok(NativeSession {
            jar: Arc::new(Jar::default()),
            clients: Mutex::new(HashMap::new()),
            h3_pool: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ech_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ticket_cache: Arc::new(Mutex::new(HashMap::new())),
            doh_resolver,
            emu_state: Mutex::new(EmulationState {
                emulation: resolved.emulation,
                ua_override: resolved.ua_override,
                sec_ch_ua_override: resolved.sec_ch_ua_override,
                impersonate: cfg.impersonate,
            }),
            default_headers,
            header_order: cfg.header_order,
            tls_options: cfg.tls_options,
            http2_options: cfg.http2_options,
            http1_only: cfg.http1_only,
            http2_only: cfg.http2_only,
            http3: cfg.http3,
            http3_only: cfg.http3_only,
            ech: cfg.ech,
            ech_doh_url: effective_ech_doh,
            resolve_entries: cfg.resolve_entries,
            local_address: parsed_local_addr,
            #[cfg(any(
                target_os = "android",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos"
            ))]
            interface: cfg.interface,
            tls_info: cfg.tls_info,
            keylog_file: cfg.keylog_file,
            system_dns: cfg.system_dns,
            timeout: safe_duration(cfg.timeout, 0.05, 86_400.0),
            connect_timeout: cfg.connect_timeout.map(|t| safe_duration(t, 0.05, 86_400.0)),
            read_timeout: cfg.read_timeout.map(|t| safe_duration(t, 0.05, 86_400.0)),
            pool_max_idle_per_host: cfg.pool_max_idle_per_host,
            pool_idle_timeout: cfg
                .pool_idle_timeout
                .map(|t| safe_duration(t, 0.05, 86_400.0)),
            tcp_nodelay: cfg.tcp_nodelay,
            tcp_keepalive: cfg.tcp_keepalive.map(|t| safe_duration(t, 1.0, 86_400.0)),
            max_redirects: cfg.max_redirects,
            ca_bundle: cfg.ca_bundle,
            identity_pair,
            default_proxy: cfg.proxy,
            follow_redirects: cfg.follow_redirects,
            verify: cfg.verify_ssl,
        })
    }

    fn client_for(&self, verify: bool, ca_override: Option<&[u8]>) -> CoreResult<Client> {
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
        } else if std::env::var("SSLKEYLOGFILE")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
        {
            b = b.tls_keylog(KeyLog::from_env());
        }
        if let Some(ref doh) = self.doh_resolver {
            b = b.dns_resolver(doh.clone());
        } else if self.system_dns {
            b = b.no_hickory_dns();
        }
        #[cfg(any(
            target_os = "android",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos"
        ))]
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
            let px = Proxy::all(p.as_str()).map_err(|e| {
                CoreError::value(format!("Invalid proxy '{p}': {}", error_chain(&e)))
            })?;
            b = b.proxy(px);
        }

        let client = b
            .build()
            .map_err(|e| CoreError::runtime(format!("[builder] {}", error_chain(&e))))?;
        if cache.len() >= 16 {
            cache.clear();
        }
        cache.insert(key, client.clone());
        Ok(client)
    }

    fn prepare_core(&self, req: &RequestInput) -> CoreResult<RequestBuilder> {
        let m = Method::from_str(&req.method.to_uppercase())
            .map_err(|e| CoreError::value(format!("Invalid HTTP method: {e}")))?;

        let mut final_url = url::Url::parse(&req.url)
            .map_err(|e| CoreError::value(format!("Invalid URL '{}': {e}", req.url)))?;

        if !req.params.is_empty() {
            let mut pairs = final_url.query_pairs_mut();
            for (k, v) in &req.params {
                pairs.append_pair(k, v);
            }
        }

        let uri_str = final_url.as_str();
        for (k, v) in &req.cookies {
            self.jar.add(format!("{k}={v}; Path=/"), uri_str);
        }

        let use_verify = req.verify.unwrap_or(self.verify);
        let client = self.client_for(use_verify, req.ca_bundle.as_deref())?;

        let mut rb = client.request(m, uri_str);

        if let Some(t) = req.timeout {
            rb = rb.timeout(safe_duration(t, 0.05, 86_400.0));
        }
        if let Some(redir) = req.allow_redirects {
            rb = rb.redirect(if redir {
                Policy::limited(self.max_redirects)
            } else {
                Policy::none()
            });
        }
        if let Some(ref p) = req.proxy {
            let px = Proxy::all(p.as_str()).map_err(|e| {
                CoreError::value(format!("Invalid proxy '{p}': {}", error_chain(&e)))
            })?;
            rb = rb.proxy(px);
        }
        if let Some(ref la) = req.local_address {
            let ip = IpAddr::from_str(la)
                .map_err(|e| CoreError::value(format!("Invalid local_address '{la}': {e}")))?;
            rb = rb.local_address(ip);
        }

        let (ua_ov, ch_ov) = if let Some(ref preset) = req.impersonate {
            let res = resolve_emulation(preset);
            rb = rb.emulation(res.emulation);
            (res.ua_override, res.sec_ch_ua_override)
        } else {
            let st = self.emu_state.lock().unwrap_or_else(|p| p.into_inner());
            (st.ua_override.clone(), st.sec_ch_ua_override.clone())
        };

        if let Some(ref order) = req.header_order {
            rb = rb.orig_headers(build_orig_headers(order));
        }

        let has_caller_ua = req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
        let has_caller_ch = req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-ch-ua"));
        let has_caller_ct = req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            || self.default_headers.contains_key(wreq::header::CONTENT_TYPE);

        let mut req_hdrs = HeaderMap::new();
        if !has_caller_ua {
            if let Some(ref ua) = ua_ov {
                if let Ok(hv) = HeaderValue::from_str(ua) {
                    req_hdrs.insert(wreq::header::USER_AGENT, hv);
                }
            }
        }
        if !has_caller_ch {
            if let Some(ref ch) = ch_ov {
                if let (Ok(hn), Ok(hv)) =
                    (HeaderName::from_str("sec-ch-ua"), HeaderValue::from_str(ch))
                {
                    req_hdrs.insert(hn, hv);
                }
            }
        }

        for (k, v) in &req.headers {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                req_hdrs.insert(hn, hv);
            }
        }
        if !req_hdrs.is_empty() {
            // `RequestBuilder::headers()` replaces matching preset/default headers
            // instead of appending duplicates (unlike `RequestBuilder::header()`).
            rb = rb.headers(req_hdrs);
        }

        if !req.files.is_empty() {
            let mut form = Form::new();
            for (field, filename, payload, mime) in &req.files {
                let mut part = Part::bytes(payload.clone());
                if let Some(fname) = filename {
                    part = part.file_name(fname.clone());
                }
                if let Some(ct) = mime {
                    part = part
                        .mime_str(ct)
                        .map_err(|e| CoreError::value(format!("Invalid MIME '{ct}': {e}")))?;
                }
                form = form.part(field.clone(), part);
            }
            rb = rb.multipart(form);
        } else if let Some(ref body) = req.data {
            rb = rb.body(body.clone());
        } else if let Some(ref j) = req.json {
            if !has_caller_ct {
                rb = rb.header(wreq::header::CONTENT_TYPE, "application/json");
            }
            rb = rb.body(j.clone());
        }

        Ok(rb)
    }

    fn prepare_h3_core(
        &self,
        req: &RequestInput,
    ) -> CoreResult<(Option<H3RequestSpec>, Option<tcp_ech::TcpEchSpec>)> {
        let eff_ech = req.ech.unwrap_or(self.ech) || req.ech_config_list.is_some();
        let want_h3 = req.http3.unwrap_or(
            self.http3 || self.http3_only || (eff_ech && !self.http1_only && !self.http2_only),
        );
        let allow_h3 = want_h3 && !self.http1_only && !self.http2_only;
        let allow_tcp_ech = eff_ech && !self.http1_only && !self.http3_only;
        if !allow_h3 && !allow_tcp_ech {
            return Ok((None, None));
        }

        let eff_proxy = req.proxy.clone().or_else(|| self.default_proxy.clone());
        let socks5_proxy = match eff_proxy {
            Some(ref p) if socks5_udp::is_socks5_proxy(p) => Some(p.clone()),
            Some(_) => {
                if self.http3_only {
                    return Err(CoreError::runtime(
                        "[connect] http3_only=True requires direct UDP or a socks5:// / socks5h:// UDP ASSOCIATE proxy",
                    ));
                }
                return Ok((None, None));
            }
            None => None,
        };

        let mut final_url = url::Url::parse(&req.url)
            .map_err(|e| CoreError::value(format!("Invalid URL '{}': {e}", req.url)))?;
        if final_url.scheme() != "https" {
            if self.http3_only {
                return Err(CoreError::runtime(
                    "[connect] HTTP/3 (QUIC) requires an https:// URL",
                ));
            }
            return Ok((None, None));
        }

        if !req.params.is_empty() {
            let mut pairs = final_url.query_pairs_mut();
            for (k, v) in &req.params {
                pairs.append_pair(k, v);
            }
        }

        let uri_str = final_url.as_str();
        for (k, v) in &req.cookies {
            self.jar.add(format!("{k}={v}; Path=/"), uri_str);
        }

        let (preset_name, ua_ov, ch_ov) = if let Some(ref preset) = req.impersonate {
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
        for (k, v) in &req.headers {
            if let Some(pos) = merged_hdrs.iter().position(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
                merged_hdrs[pos] = (k.clone(), v.clone());
            } else {
                merged_hdrs.push((k.clone(), v.clone()));
            }
        }

        let body = if !req.files.is_empty() {
            let (ct, encoded) = encode_multipart_body(&req.files);
            if let Some(pos) = merged_hdrs
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                merged_hdrs[pos].1 = ct;
            } else {
                merged_hdrs.push(("content-type".to_string(), ct));
            }
            Some(encoded)
        } else if let Some(ref b) = req.data {
            Some(b.clone())
        } else if let Some(ref j) = req.json {
            if !merged_hdrs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                merged_hdrs.push(("content-type".to_string(), "application/json".to_string()));
            }
            Some(j.as_bytes().to_vec())
        } else {
            None
        };

        if let Some(ref b) = body {
            if !merged_hdrs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            {
                merged_hdrs.push(("content-length".to_string(), b.len().to_string()));
            }
        }

        let eff_local_addr = match req.local_address {
            Some(ref la) => Some(
                IpAddr::from_str(la)
                    .map_err(|e| CoreError::value(format!("Invalid local_address '{la}': {e}")))?,
            ),
            None => self.local_address,
        };

        let eff_timeout = req
            .timeout
            .map(|t| safe_duration(t, 0.05, 86_400.0))
            .unwrap_or(self.timeout);
        let eff_connect_timeout = self
            .connect_timeout
            .unwrap_or_else(|| eff_timeout.min(Duration::from_secs(10)));
        let eff_header_order = req.header_order.clone().or_else(|| self.header_order.clone());
        let eff_allow_redir = req.allow_redirects.unwrap_or(self.follow_redirects);
        let eff_verify = req.verify.unwrap_or(self.verify);
        let eff_ca = req.ca_bundle.clone().or_else(|| self.ca_bundle.clone());

        let tcp_ech_spec = if allow_tcp_ech {
            let defaults =
                default_h3_browser_headers(&preset_name, ua_ov.as_deref(), ch_ov.as_deref());
            let mut tcp_hdrs: Vec<(String, String)> = Vec::new();
            for (dk, dv) in defaults {
                if !merged_hdrs.iter().any(|(ck, _)| ck.eq_ignore_ascii_case(&dk)) {
                    tcp_hdrs.push((dk, dv));
                }
            }
            for (ck, cv) in &merged_hdrs {
                if let Some(pos) = tcp_hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(ck)) {
                    tcp_hdrs[pos] = (ck.clone(), cv.clone());
                } else {
                    tcp_hdrs.push((ck.clone(), cv.clone()));
                }
            }
            Some(tcp_ech::TcpEchSpec {
                method: req.method.to_uppercase(),
                url: final_url.clone(),
                headers: tcp_hdrs,
                header_order: eff_header_order.clone(),
                body: body.clone(),
                timeout: eff_timeout,
                connect_timeout: eff_connect_timeout,
                allow_redirects: eff_allow_redir,
                max_redirects: self.max_redirects,
                verify: eff_verify,
                ca_bundle: eff_ca.clone(),
                identity_pair: self.identity_pair.clone(),
                resolve_entries: self.resolve_entries.clone(),
                local_address: eff_local_addr,
                proxy: socks5_proxy.clone(),
                tls_info: self.tls_info,
                keylog_file: self.keylog_file.clone(),
                preset: preset_name.clone(),
                ech_doh_url: self.ech_doh_url.clone(),
                ech_config_list: req.ech_config_list.clone(),
            })
        } else {
            None
        };

        let h3_spec = if allow_h3 {
            Some(H3RequestSpec {
                method: req.method.to_uppercase(),
                url: final_url,
                headers: merged_hdrs,
                header_order: eff_header_order,
                body,
                timeout: eff_timeout,
                connect_timeout: eff_connect_timeout,
                allow_redirects: eff_allow_redir,
                max_redirects: self.max_redirects,
                verify: eff_verify,
                ca_bundle: eff_ca,
                identity_pair: self.identity_pair.clone(),
                resolve_entries: self.resolve_entries.clone(),
                local_address: eff_local_addr,
                proxy: socks5_proxy,
                tls_info: self.tls_info,
                keylog_file: self.keylog_file.clone(),
                preset: preset_name,
                ua_override: ua_ov,
                sec_ch_ua_override: ch_ov,
                alt_svc_port: req.alt_svc_port,
                strict_h3: self.http3_only,
                ech: eff_ech,
                ech_doh_url: self.ech_doh_url.clone(),
                ech_config_list: req.ech_config_list.clone(),
            })
        } else {
            None
        };

        Ok((h3_spec, tcp_ech_spec))
    }

    fn doh_client_for(
        &self,
        h3_spec: &Option<H3RequestSpec>,
        tcp_ech_spec: &Option<tcp_ech::TcpEchSpec>,
    ) -> CoreResult<Option<Client>> {
        let need_doh_ech = h3_spec
            .as_ref()
            .map(|s| s.ech && s.ech_config_list.is_none())
            .unwrap_or(false)
            || tcp_ech_spec
                .as_ref()
                .map(|s| s.ech_config_list.is_none())
                .unwrap_or(false);
        if need_doh_ech {
            if let Some(ref doh) = self.doh_resolver {
                Ok(Some(doh.client().clone()))
            } else {
                Ok(Some(self.client_for(true, None)?))
            }
        } else {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    pub(crate) fn execute_sync_core(&self, req: &RequestInput) -> CoreResult<NativeResponse> {
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        runtime().block_on(finish_dual_response(
            rb,
            h3_spec,
            tcp_ech_spec,
            jar,
            h3_pool,
            ech_cache,
            ticket_cache,
            doh_resolver,
            doh_client,
        ))
    }

    #[allow(dead_code)]
    pub(crate) fn execute_stream_sync_core(&self, req: &RequestInput) -> CoreResult<NativeStream> {
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        runtime().block_on(start_dual_stream(
            rb,
            h3_spec,
            tcp_ech_spec,
            jar,
            h3_pool,
            ech_cache,
            ticket_cache,
            doh_resolver,
            doh_client,
        ))
    }

    #[allow(dead_code, clippy::type_complexity)]
    pub(crate) fn ws_connect_sync_core(
        &self,
        url: &str,
        headers: &[(String, String)],
        proxy: Option<&str>,
        verify: Option<bool>,
        ca_bundle: Option<&[u8]>,
        timeout: Option<f64>,
    ) -> CoreResult<(u16, HashMap<String, String>, Option<String>, wreq::ws::WebSocket)> {
        let client = self.client_for(verify.unwrap_or(self.verify), ca_bundle)?;
        let mut ws_req = client.websocket(url);
        let mut hdr_map = HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                hdr_map.insert(hn, hv);
            }
        }
        if !hdr_map.is_empty() {
            ws_req = ws_req.headers(hdr_map);
        }
        if let Some(p) = proxy {
            let px = Proxy::all(p).map_err(|e| {
                CoreError::value(format!("Invalid proxy '{p}': {}", error_chain(&e)))
            })?;
            ws_req = ws_req.proxy(px);
        }
        let eff_timeout = timeout
            .map(|t| safe_duration(t, 0.05, 86_400.0))
            .unwrap_or(self.timeout);
        runtime().block_on(async move {
            let fut = async move {
                let ws_resp = ws_req.send().await.map_err(net_err)?;
                let status_code = ws_resp.status().as_u16();
                let resp_headers = collect_headers(ws_resp.headers());
                let ws = ws_resp.into_websocket().await.map_err(net_err)?;
                let protocol = ws
                    .protocol()
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                Ok::<_, CoreError>((status_code, resp_headers, protocol, ws))
            };
            tokio::time::timeout(eff_timeout, fut)
                .await
                .map_err(|_| CoreError::runtime("[timeout] WebSocket connect timed out"))?
        })
    }

    #[allow(dead_code)]
    pub(crate) fn gather_sync_core(
        &self,
        specs: &[RequestInput],
        concurrency: usize,
    ) -> CoreResult<Vec<CoreResult<NativeResponse>>> {
        let mut builders = Vec::with_capacity(specs.len());
        for spec in specs {
            let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(spec)?;
            let rb = self.prepare_core(spec)?;
            builders.push((rb, h3_spec, tcp_ech_spec));
        }

        let need_doh = builders.iter().any(|(_, s, ts)| {
            s.as_ref()
                .map(|sp| sp.ech && sp.ech_config_list.is_none())
                .unwrap_or(false)
                || ts.as_ref().map(|sp| sp.ech_config_list.is_none()).unwrap_or(false)
        });
        let doh_client = if need_doh {
            if let Some(ref doh) = self.doh_resolver {
                Some(doh.client().clone())
            } else {
                Some(self.client_for(true, None)?)
            }
        } else {
            None
        };
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        let limit = concurrency.clamp(1, specs.len().max(1)).min(4096);

        let results = runtime().block_on(async move {
            futures_util::stream::iter(builders.into_iter().map(|(rb, h3_spec, tcp_ech_spec)| {
                finish_dual_response(
                    rb,
                    h3_spec,
                    tcp_ech_spec,
                    Arc::clone(&jar),
                    Arc::clone(&h3_pool),
                    Arc::clone(&ech_cache),
                    Arc::clone(&ticket_cache),
                    doh_resolver.clone(),
                    doh_client.clone(),
                )
            }))
            .buffered(limit)
            .collect::<Vec<_>>()
            .await
        });
        Ok(results)
    }

    pub(crate) fn cookies_for_core(&self, url: &str) -> HashMap<String, String> {
        collect_cookies(&self.jar, url, &HeaderMap::new())
    }

    pub(crate) fn all_cookies_core(&self) -> Vec<CookieTuple> {
        self.jar
            .get_all()
            .map(|c| {
                let dom = c
                    .domain()
                    .map(ToString::to_string)
                    .or_else(|| c.host().map(|h| h.to_string()))
                    .unwrap_or_default();
                (
                    c.name().to_string(),
                    c.value().to_string(),
                    dom,
                    c.path().unwrap_or("/").to_string(),
                    c.secure(),
                    c.http_only(),
                )
            })
            .collect()
    }

    pub(crate) fn add_raw_cookie_core(&self, cookie_header: &str, url: &str) {
        self.jar.add(cookie_header.to_string(), url);
    }

    pub(crate) fn set_cookie_core(
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
        let is_ip = dom.parse::<IpAddr>().is_ok();
        let mut raw = if is_ip {
            format!("{name}={value}; Path={cpath}")
        } else {
            format!("{name}={value}; Domain={dom}; Path={cpath}")
        };
        if secure {
            raw.push_str("; Secure");
        }
        if http_only {
            raw.push_str("; HttpOnly");
        }
        let scheme = if secure { "https" } else { "http" };
        let host_part = if dom.contains(':') && !dom.starts_with('[') {
            format!("[{dom}]")
        } else {
            dom.to_string()
        };
        let url = format!("{scheme}://{host_part}{cpath}");
        self.jar.add(raw, &url);
    }

    pub(crate) fn delete_cookie_core(
        &self,
        name: &str,
        domain: Option<&str>,
        path: Option<&str>,
    ) {
        let dom_filter = domain.map(|d| d.trim().trim_start_matches('.').to_ascii_lowercase());
        let path_filter = path.map(|p| p.trim().to_string());
        let targets: Vec<(String, String, String, bool)> = self
            .jar
            .get_all()
            .filter_map(|c| {
                if c.name() != name {
                    return None;
                }
                let dom = c
                    .domain()
                    .map(ToString::to_string)
                    .or_else(|| c.host().map(|h| h.to_string()))
                    .unwrap_or_default();
                let cpath = c.path().unwrap_or("/").to_string();
                if let Some(ref df) = dom_filter {
                    if !df.is_empty() && dom.trim_start_matches('.').to_ascii_lowercase() != *df {
                        return None;
                    }
                }
                if let Some(ref pf) = path_filter {
                    if !pf.is_empty() && cpath != *pf {
                        return None;
                    }
                }
                Some((c.name().to_string(), dom, cpath, c.secure()))
            })
            .collect();

        for (cname, dom, cpath, secure) in targets {
            let clean_dom = dom.trim().trim_start_matches('.');
            if clean_dom.is_empty() {
                continue;
            }
            let scheme = if secure { "https" } else { "http" };
            let host_part = if clean_dom.contains(':') && !clean_dom.starts_with('[') {
                format!("[{clean_dom}]")
            } else {
                clean_dom.to_string()
            };
            let uri = format!("{scheme}://{host_part}{cpath}");
            self.jar.remove(cname, &uri);
        }
    }

    pub(crate) fn clear_cookies_core(&self) {
        self.jar.clear();
    }

    pub(crate) fn set_impersonate_core(&self, preset: &str) {
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
        self.ticket_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    pub(crate) fn close_core(&self) {
        let mut cache = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        cache.clear();
        clear_h3_pool_sync(&self.h3_pool);
        self.ticket_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

fn tcp_ech_outcome_to_response(out: tcp_ech::TcpEchOutcome, jar: &Arc<Jar>) -> NativeResponse {
    let body_bytes = decompress_h3_body(out.raw_body, out.content_encoding.as_deref());
    let (text, encoding) = decode_body(&body_bytes, &out.wreq_headers);
    let cookies = collect_cookies(jar, &out.final_url, &out.wreq_headers);
    NativeResponse {
        status_code: out.status_code,
        headers: out.headers_map,
        cookies,
        url: out.final_url,
        content: body_bytes,
        text,
        encoding,
        elapsed: out.elapsed,
        http_version: "HTTP/2".to_string(),
        remote_addr: out.remote_addr,
        peer_certificate: out.peer_certificate,
        history: out.history,
        ech_accepted: out.ech_accepted,
        tls_resumed: out.tls_resumed,
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_dual_response(
    rb: RequestBuilder,
    h3_spec: Option<H3RequestSpec>,
    tcp_ech_spec: Option<tcp_ech::TcpEchSpec>,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> CoreResult<NativeResponse> {
    if let Some(spec) = h3_spec {
        let strict = spec.strict_h3;
        match execute_h3_request(
            spec,
            Arc::clone(&jar),
            h3_pool,
            Arc::clone(&ech_cache),
            Arc::clone(&ticket_cache),
            doh_resolver.clone(),
            doh_client.clone(),
        )
        .await
        {
            Ok(resp) => return Ok(resp),
            Err(e) if strict => return Err(e),
            Err(_) => {}
        }
    }
    if let Some(tspec) = tcp_ech_spec {
        if let Ok(out) = tcp_ech::execute_tcp_ech_request(
            tspec,
            Arc::clone(&jar),
            ech_cache,
            ticket_cache,
            doh_resolver,
            doh_client,
        )
        .await
        {
            return Ok(tcp_ech_outcome_to_response(out, &jar));
        }
    }
    finish_response(rb, jar).await
}

#[allow(clippy::too_many_arguments)]
async fn start_dual_stream(
    rb: RequestBuilder,
    h3_spec: Option<H3RequestSpec>,
    tcp_ech_spec: Option<tcp_ech::TcpEchSpec>,
    jar: Arc<Jar>,
    h3_pool: H3Pool,
    ech_cache: EchCache,
    ticket_cache: TicketCache,
    doh_resolver: Option<DohResolver>,
    doh_client: Option<Client>,
) -> CoreResult<NativeStream> {
    if let Some(spec) = h3_spec {
        let strict = spec.strict_h3;
        match execute_h3_stream(
            spec,
            Arc::clone(&jar),
            h3_pool,
            Arc::clone(&ech_cache),
            Arc::clone(&ticket_cache),
            doh_resolver.clone(),
            doh_client.clone(),
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(e) if strict => return Err(e),
            Err(_) => {}
        }
    }
    if let Some(tspec) = tcp_ech_spec {
        if let Ok(out) = tcp_ech::execute_tcp_ech_stream(
            tspec,
            Arc::clone(&jar),
            ech_cache,
            ticket_cache,
            doh_resolver,
            doh_client,
        )
        .await
        {
            let encoding = charset_of(&out.wreq_headers)
                .map(|e| e.name().to_ascii_lowercase())
                .unwrap_or_default();
            let cookies = collect_cookies(&jar, &out.final_url, &out.wreq_headers);
            let stream: BodyStream =
                Box::pin(out.body_stream.map(|res| res.map_err(CoreError::runtime)));
            return Ok(NativeStream {
                status_code: out.status_code,
                headers: out.headers_map,
                cookies,
                encoding,
                url: out.final_url,
                elapsed: out.elapsed,
                http_version: "HTTP/2".to_string(),
                remote_addr: out.remote_addr,
                peer_certificate: out.peer_certificate,
                history: out.history,
                ech_accepted: out.ech_accepted,
                tls_resumed: out.tls_resumed,
                inner: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            });
        }
    }
    start_stream(rb, jar).await
}

async fn finish_response(rb: RequestBuilder, jar: Arc<Jar>) -> CoreResult<NativeResponse> {
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
        ech_accepted: false,
        tls_resumed: false,
    })
}

async fn start_stream(rb: RequestBuilder, jar: Arc<Jar>) -> CoreResult<NativeStream> {
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
    let stream: BodyStream = Box::pin(resp.bytes_stream().map(|res| res.map_err(net_err)));
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
        ech_accepted: false,
        tls_resumed: false,
        inner: Arc::new(tokio::sync::Mutex::new(Some(stream))),
    })
}

// ---------------------------------------------------------------------------
// PyO3 Session Methods & Module Registration
// ---------------------------------------------------------------------------
#[cfg(feature = "python")]
#[allow(clippy::too_many_arguments)]
fn build_py_request_input(
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
    ech: Option<bool>,
    ech_config_list: Option<Vec<u8>>,
) -> PyResult<RequestInput> {
    Ok(RequestInput {
        method: method.to_string(),
        url: url.to_string(),
        params: dict_pairs(params)?,
        headers: dict_pairs(headers)?,
        cookies: dict_pairs(cookies)?,
        data,
        json: json.map(ToString::to_string),
        files: parse_multipart_items(files)?,
        timeout,
        proxy,
        allow_redirects,
        verify,
        ca_bundle,
        header_order,
        impersonate,
        local_address,
        http3,
        alt_svc_port,
        ech,
        ech_config_list,
    })
}

#[cfg(feature = "python")]
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
        ech = false,
        ech_doh_url = None,
        doh_url = None,
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
        ech: bool,
        ech_doh_url: Option<String>,
        doh_url: Option<String>,
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
        let cfg = SessionConfig {
            impersonate: impersonate.to_string(),
            timeout,
            follow_redirects,
            max_redirects,
            verify_ssl,
            proxy,
            headers: dict_pairs(headers)?,
            ca_bundle,
            client_cert,
            client_key,
            header_order,
            tls_options: match tls_options {
                Some(d) => Some(parse_tls_options(d)?),
                None => None,
            },
            http2_options: match http2_options {
                Some(d) => Some(parse_http2_options(d)?),
                None => None,
            },
            http1_only,
            http2_only,
            http3,
            http3_only,
            ech,
            ech_doh_url,
            doh_url,
            resolve_entries: match resolve {
                Some(d) => parse_resolve_map(d)?,
                None => Vec::new(),
            },
            local_address,
            interface,
            tls_info,
            connect_timeout,
            read_timeout,
            pool_max_idle_per_host,
            pool_idle_timeout,
            keylog_file,
            system_dns,
            tcp_nodelay,
            tcp_keepalive,
        };
        Ok(Self::from_config(cfg)?)
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None, ech = None,
        ech_config_list = None
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
        ech: Option<bool>,
        ech_config_list: Option<Vec<u8>>,
    ) -> PyResult<NativeResponse> {
        let req = build_py_request_input(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
            http3, alt_svc_port, ech, ech_config_list,
        )?;
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(&req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(&req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        Ok(py.allow_threads(move || {
            runtime().block_on(finish_dual_response(
                rb,
                h3_spec,
                tcp_ech_spec,
                jar,
                h3_pool,
                ech_cache,
                ticket_cache,
                doh_resolver,
                doh_client,
            ))
        })?)
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None, ech = None,
        ech_config_list = None
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
        ech: Option<bool>,
        ech_config_list: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let req = build_py_request_input(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
            http3, alt_svc_port, ech, ech_config_list,
        )?;
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(&req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(&req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            finish_dual_response(
                rb,
                h3_spec,
                tcp_ech_spec,
                jar,
                h3_pool,
                ech_cache,
                ticket_cache,
                doh_resolver,
                doh_client,
            )
            .await
            .map_err(PyErr::from)
        })
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None, ech = None,
        ech_config_list = None
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
        ech: Option<bool>,
        ech_config_list: Option<Vec<u8>>,
    ) -> PyResult<NativeStream> {
        let req = build_py_request_input(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
            http3, alt_svc_port, ech, ech_config_list,
        )?;
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(&req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(&req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        Ok(py.allow_threads(move || {
            runtime().block_on(start_dual_stream(
                rb,
                h3_spec,
                tcp_ech_spec,
                jar,
                h3_pool,
                ech_cache,
                ticket_cache,
                doh_resolver,
                doh_client,
            ))
        })?)
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, files = None, timeout = None, proxy = None, allow_redirects = None,
        verify = None, ca_bundle = None, header_order = None, impersonate = None,
        local_address = None, http3 = None, alt_svc_port = None, ech = None,
        ech_config_list = None
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
        ech: Option<bool>,
        ech_config_list: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let req = build_py_request_input(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
            http3, alt_svc_port, ech, ech_config_list,
        )?;
        let (h3_spec, tcp_ech_spec) = self.prepare_h3_core(&req)?;
        let doh_client = self.doh_client_for(&h3_spec, &tcp_ech_spec)?;
        let rb = self.prepare_core(&req)?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            start_dual_stream(
                rb,
                h3_spec,
                tcp_ech_spec,
                jar,
                h3_pool,
                ech_cache,
                ticket_cache,
                doh_resolver,
                doh_client,
            )
            .await
            .map_err(PyErr::from)
        })
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
        Ok(py.allow_threads(move || {
            runtime().block_on(async move {
                let ws_resp = ws_req.send().await.map_err(net_err)?;
                let status_code = ws_resp.status().as_u16();
                let headers = collect_headers(ws_resp.headers());
                let ws = ws_resp.into_websocket().await.map_err(net_err)?;
                let protocol = ws
                    .protocol()
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                Ok::<_, CoreError>(NativeWebSocket::from_ws(
                    status_code,
                    headers,
                    protocol,
                    ws,
                ))
            })
        })?)
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
            let ws_resp = ws_req.send().await.map_err(net_py_err)?;
            let status_code = ws_resp.status().as_u16();
            let headers = collect_headers(ws_resp.headers());
            let ws = ws_resp.into_websocket().await.map_err(net_py_err)?;
            let protocol = ws
                .protocol()
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            Ok(NativeWebSocket::from_ws(status_code, headers, protocol, ws))
        })
    }

    pub fn cookies_for(&self, url: &str) -> PyResult<HashMap<String, String>> {
        Ok(self.cookies_for_core(url))
    }

    pub fn all_cookies(&self) -> Vec<CookieTuple> {
        self.all_cookies_core()
    }

    pub fn add_raw_cookie(&self, cookie_header: &str, url: &str) {
        self.add_raw_cookie_core(cookie_header, url);
    }

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
        self.set_cookie_core(name, value, domain, path, secure, http_only);
    }

    #[pyo3(signature = (name, domain = None, path = None))]
    pub fn delete_cookie(&self, name: &str, domain: Option<&str>, path: Option<&str>) {
        self.delete_cookie_core(name, domain, path);
    }

    pub fn set_impersonate(&self, preset: &str) {
        self.set_impersonate_core(preset);
    }

    #[pyo3(signature = (specs, concurrency = 50))]
    pub fn gather(
        &self,
        py: Python<'_>,
        specs: &Bound<'_, PyList>,
        concurrency: usize,
    ) -> PyResult<Vec<NativeResponse>> {
        let mut inputs = Vec::with_capacity(specs.len());
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
            let allow_redirects: Option<bool> =
                d.get_item("allow_redirects")?.and_then(|v| v.extract().ok());
            let verify: Option<bool> = d.get_item("verify")?.and_then(|v| v.extract().ok());
            let ca_bundle: Option<Vec<u8>> = d.get_item("ca_bundle")?.and_then(|v| v.extract().ok());
            let header_order: Option<Vec<String>> =
                d.get_item("header_order")?.and_then(|v| v.extract().ok());
            let impersonate: Option<String> =
                d.get_item("impersonate")?.and_then(|v| v.extract().ok());
            let local_address: Option<String> =
                d.get_item("local_address")?.and_then(|v| v.extract().ok());
            let http3: Option<bool> = d.get_item("http3")?.and_then(|v| v.extract().ok());
            let alt_svc_port: Option<u16> =
                d.get_item("alt_svc_port")?.and_then(|v| v.extract().ok());
            let ech: Option<bool> = d.get_item("ech")?.and_then(|v| v.extract().ok());
            let ech_config_list: Option<Vec<u8>> =
                d.get_item("ech_config_list")?.and_then(|v| v.extract().ok());

            inputs.push(build_py_request_input(
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
                http3,
                alt_svc_port,
                ech,
                ech_config_list,
            )?);
        }

        let results = py.allow_threads(|| self.gather_sync_core(&inputs, concurrency))?;
        let mut out = Vec::with_capacity(results.len());
        for r in results {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn clear_cookies(&self) {
        self.clear_cookies_core();
    }

    pub fn close(&self) {
        self.close_core();
    }

    pub fn clear_h3_pool(&self) {
        clear_h3_pool_sync(&self.h3_pool);
    }

    pub fn h3_ticket_cache_len(&self) -> usize {
        self.ticket_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
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

#[cfg(feature = "python")]
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeStream>()?;
    m.add_class::<NativeWebSocket>()?;
    m.add_class::<NativeSession>()?;
    m.add_class::<extract::NativeDocument>()?;
    m.add_class::<extract::NativeElement>()?;
    m.add_class::<extract::NativeJsonDoc>()?;
    m.add_function(wrap_pyfunction!(supported_presets, m)?)?;
    m.add_function(wrap_pyfunction!(is_verified_preset, m)?)?;
    m.add_function(wrap_pyfunction!(extract::parse_html, m)?)?;
    m.add_function(wrap_pyfunction!(extract::parse_json, m)?)?;
    m.add_function(wrap_pyfunction!(extract::extract_re, m)?)?;
    m.add_function(wrap_pyfunction!(extract::extract_re_first, m)?)?;
    m.add_function(wrap_pyfunction!(extract::extract_between, m)?)?;
    m.add_function(wrap_pyfunction!(extract::extract_between_all, m)?)?;
    m.add_function(wrap_pyfunction!(extract::extract_json_path, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DummyErr(&'static str, Option<Box<DummyErr>>);

    impl std::fmt::Display for DummyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for DummyErr {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn test_error_chain_deduplicates_noisy_wrappers() {
        let err = DummyErr(
            "client error (Connect)",
            Some(Box::new(DummyErr(
                "client error (Connect)",
                Some(Box::new(DummyErr(
                    "dns error",
                    Some(Box::new(DummyErr(
                        "dns resolution error",
                        Some(Box::new(DummyErr("no records found", None))),
                    ))),
                ))),
            ))),
        );
        let formatted = error_chain(&err);
        assert_eq!(
            formatted,
            "client error (Connect): dns error: dns resolution error: no records found"
        );
    }

    #[test]
    fn test_socks5_percent_decode() {
        assert_eq!(
            socks5_udp::percent_decode("user%40name%3Apass"),
            "user@name:pass"
        );
        assert_eq!(socks5_udp::percent_decode("plain123"), "plain123");
    }

    #[test]
    fn test_safe_duration_clamps_extreme_floats() {
        assert_eq!(safe_duration(1e30, 0.05, 86_400.0), Duration::from_secs(86_400));
        assert_eq!(safe_duration(f64::INFINITY, 0.05, 86_400.0), Duration::from_secs(86_400));
        assert_eq!(safe_duration(f64::NEG_INFINITY, 0.05, 86_400.0), Duration::from_millis(50));
        assert_eq!(safe_duration(f64::NAN, 0.05, 86_400.0), Duration::from_secs(86_400));
        assert_eq!(safe_duration(-5.0, 0.05, 86_400.0), Duration::from_millis(50));
        assert_eq!(safe_duration(2.5, 0.05, 86_400.0), Duration::from_millis(2500));
    }

    #[test]
    fn test_sanitize_redirect_headers_cross_origin_and_body_strip() {
        let a = url::Url::parse("https://a.example.com/login").unwrap();
        let a2 = url::Url::parse("https://a.example.com/dashboard").unwrap();
        let b = url::Url::parse("https://b.other.com/landing").unwrap();

        // Same-origin POST->GET strips body headers, preserves Authorization
        let mut h_same = vec![
            ("Authorization".to_string(), "Bearer tok".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Length".to_string(), "42".to_string()),
            ("X-Trace".to_string(), "1".to_string()),
        ];
        sanitize_redirect_headers(&mut h_same, &a, &a2, true);
        let keys_same: Vec<&str> = h_same.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys_same, vec!["Authorization", "X-Trace"]);

        // Cross-origin 307 preserves body headers, strips Authorization & manual Cookie
        let mut h_cross = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Proxy-Authorization".to_string(), "Basic abc".to_string()),
            ("Cookie".to_string(), "sid=secret".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Trace".to_string(), "1".to_string()),
        ];
        sanitize_redirect_headers(&mut h_cross, &a, &b, false);
        let keys_cross: Vec<&str> = h_cross.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys_cross, vec!["Content-Type", "X-Trace"]);
    }
}
