// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 ABI3 Extension | Runtime: Tokio + wreq (BoringSSL) + quinn/h3 (BoringSSL UDP QUIC + ECH + SOCKS5 UDP + DoH + TCP ECH)
mod doh;
mod extract;
mod h3_transport;
mod options;
mod presets;
mod quic_boring;
mod socks5_udp;
mod tcp_ech;
mod ws;

use doh::{DohResolver, EchCache, DEFAULT_DOH_URL};
pub(crate) use h3_transport::H3StreamDecoder;
use h3_transport::{
    clear_h3_pool_sync, decompress_h3_body, execute_h3_request, execute_h3_stream, H3Pool,
    H3RequestSpec,
};
use options::{build_orig_headers, parse_http2_options, parse_resolve_map, parse_tls_options};
use presets::{default_h3_browser_headers, is_verified_preset, resolve_emulation, supported_presets};
use quic_boring::TicketCache;
use ws::NativeWebSocket;

use bytes::Bytes;
use encoding_rs::{Encoding, UTF_8};
use futures_util::{Stream, StreamExt};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
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

pub(crate) type BodyStream = Pin<Box<dyn Stream<Item = PyResult<Bytes>> + Send + 'static>>;
type MultipartItem = (String, Option<String>, Vec<u8>, Option<String>);
pub(crate) type HistoryTuple = (u16, String, String, HashMap<String, String>);

// ---------------------------------------------------------------------------
// Shared Tokio runtime via pyo3-async-runtimes (used by both sync & async).
// ---------------------------------------------------------------------------
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    pyo3_async_runtimes::tokio::get_runtime()
}

// ---------------------------------------------------------------------------
// Error classification: "[kind] clean message" mapped to requests/httpx exceptions.
// ---------------------------------------------------------------------------
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut segments: Vec<String> = Vec::new();
    let mut push_clean = |raw: String| {
        let s = raw.trim().to_string();
        if s.is_empty() {
            return;
        }
        // Collapse repetitive hyper/wreq wrapper noise ("client error (Connect): client error (Connect)")
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
        ) && segments.iter().any(|p| p.to_ascii_lowercase().contains(&s.to_ascii_lowercase()))
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

pub(crate) fn net_err(e: wreq::Error) -> PyErr {
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
// Native UDP QUIC / HTTP/3 Engine (quinn + h3 + h3-quinn + BoringSSL btls-sys)
// Includes Real ECH (RFC 9460 HTTPS/SVCB DoH Type 65), TLS 1.3 Ticket Resumption,
// Per-Browser QUIC Transport Parameters, Multipart Upload & SOCKS5 UDP Associate.
// ---------------------------------------------------------------------------
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
    #[pyo3(get)]
    pub ech_accepted: bool,
    #[pyo3(get)]
    pub tls_resumed: bool,
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
    #[pyo3(get)]
    pub ech_accepted: bool,
    #[pyo3(get)]
    pub tls_resumed: bool,
    pub(crate) inner: Arc<tokio::sync::Mutex<Option<BodyStream>>>,
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
                    Some(Err(e)) => return Err(e),
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
        if let Some(ref doh) = self.doh_resolver {
            b = b.dns_resolver(doh.clone());
        } else if self.system_dns {
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

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
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
        ech_override: Option<bool>,
        ech_config_list: Option<Vec<u8>>,
    ) -> PyResult<(Option<H3RequestSpec>, Option<tcp_ech::TcpEchSpec>)> {
        let eff_ech = ech_override.unwrap_or(self.ech) || ech_config_list.is_some();
        let want_h3 = http3_override.unwrap_or(
            self.http3 || self.http3_only || (eff_ech && !self.http1_only && !self.http2_only),
        );
        let allow_h3 = want_h3 && !self.http1_only && !self.http2_only;
        let allow_tcp_ech = eff_ech && !self.http1_only && !self.http3_only;
        if !allow_h3 && !allow_tcp_ech {
            return Ok((None, None));
        }

        let eff_proxy = proxy.or_else(|| self.default_proxy.clone());
        let socks5_proxy = match eff_proxy {
            Some(ref p) if socks5_udp::is_socks5_proxy(p) => Some(p.clone()),
            Some(_) => {
                if self.http3_only {
                    return Err(PyRuntimeError::new_err(
                        "[connect] http3_only=True requires direct UDP or a socks5:// / socks5h:// UDP ASSOCIATE proxy",
                    ));
                }
                return Ok((None, None));
            }
            None => None,
        };

        let mut final_url =
            url::Url::parse(url).map_err(|e| PyValueError::new_err(format!("Invalid URL '{url}': {e}")))?;
        if final_url.scheme() != "https" {
            if self.http3_only {
                return Err(PyRuntimeError::new_err(
                    "[connect] HTTP/3 (QUIC) requires an https:// URL",
                ));
            }
            return Ok((None, None));
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

        let mp_items = parse_multipart_items(files)?;
        let body = if !mp_items.is_empty() {
            let (ct, encoded) = encode_multipart_body(&mp_items);
            if let Some(pos) = merged_hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
                merged_hdrs[pos].1 = ct;
            } else {
                merged_hdrs.push(("content-type".to_string(), ct));
            }
            Some(encoded)
        } else if let Some(b) = data {
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
        let eff_header_order = header_order.or_else(|| self.header_order.clone());
        let eff_allow_redir = allow_redirects.unwrap_or(self.follow_redirects);
        let eff_verify = verify.unwrap_or(self.verify);
        let eff_ca = ca_bundle.or_else(|| self.ca_bundle.clone());

        let tcp_ech_spec = if allow_tcp_ech {
            let defaults = default_h3_browser_headers(
                &preset_name,
                ua_ov.as_deref(),
                ch_ov.as_deref(),
            );
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
                method: method.to_uppercase(),
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
                ech_config_list: ech_config_list.clone(),
            })
        } else {
            None
        };

        let h3_spec = if allow_h3 {
            Some(H3RequestSpec {
                method: method.to_uppercase(),
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
                alt_svc_port,
                strict_h3: self.http3_only,
                ech: eff_ech,
                ech_doh_url: self.ech_doh_url.clone(),
                ech_config_list,
            })
        } else {
            None
        };

        Ok((h3_spec, tcp_ech_spec))
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
) -> PyResult<NativeResponse> {
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
) -> PyResult<NativeStream> {
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
            let stream: BodyStream = Box::pin(
                out.body_stream
                    .map(|res| res.map_err(PyRuntimeError::new_err)),
            );
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
        ech_accepted: false,
        tls_resumed: false,
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
        let parsed_doh_url = doh_url.filter(|s| !s.trim().is_empty());
        let doh_resolver = match parsed_doh_url {
            Some(ref u) => Some(
                DohResolver::new(u.clone(), proxy.as_deref())
                    .map_err(|e| PyValueError::new_err(format!("Invalid doh_url '{u}': {e}")))?,
            ),
            None => None,
        };
        let effective_ech_doh = ech_doh_url
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
            ech,
            ech_doh_url: effective_ech_doh,
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
        let (h3_spec, tcp_ech_spec) = self.prepare_h3(
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
            ech,
            ech_config_list,
        )?;
        let need_doh_ech = h3_spec.as_ref().map(|s| s.ech && s.ech_config_list.is_none()).unwrap_or(false)
            || tcp_ech_spec.as_ref().map(|s| s.ech_config_list.is_none()).unwrap_or(false);
        let doh_client = if need_doh_ech {
            if let Some(ref doh) = self.doh_resolver {
                Some(doh.client().clone())
            } else {
                Some(self.client_for(true, None)?)
            }
        } else {
            None
        };
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        py.allow_threads(move || {
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
        let (h3_spec, tcp_ech_spec) = self.prepare_h3(
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
            ech,
            ech_config_list,
        )?;
        let need_doh_ech = h3_spec.as_ref().map(|s| s.ech && s.ech_config_list.is_none()).unwrap_or(false)
            || tcp_ech_spec.as_ref().map(|s| s.ech_config_list.is_none()).unwrap_or(false);
        let doh_client = if need_doh_ech {
            if let Some(ref doh) = self.doh_resolver {
                Some(doh.client().clone())
            } else {
                Some(self.client_for(true, None)?)
            }
        } else {
            None
        };
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        pyo3_async_runtimes::tokio::future_into_py(
            py,
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
            ),
        )
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
        let (h3_spec, tcp_ech_spec) = self.prepare_h3(
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
            ech,
            ech_config_list,
        )?;
        let need_doh_ech = h3_spec.as_ref().map(|s| s.ech && s.ech_config_list.is_none()).unwrap_or(false)
            || tcp_ech_spec.as_ref().map(|s| s.ech_config_list.is_none()).unwrap_or(false);
        let doh_client = if need_doh_ech {
            if let Some(ref doh) = self.doh_resolver {
                Some(doh.client().clone())
            } else {
                Some(self.client_for(true, None)?)
            }
        } else {
            None
        };
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        py.allow_threads(move || {
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
        let (h3_spec, tcp_ech_spec) = self.prepare_h3(
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
            ech,
            ech_config_list,
        )?;
        let need_doh_ech = h3_spec.as_ref().map(|s| s.ech && s.ech_config_list.is_none()).unwrap_or(false)
            || tcp_ech_spec.as_ref().map(|s| s.ech_config_list.is_none()).unwrap_or(false);
        let doh_client = if need_doh_ech {
            if let Some(ref doh) = self.doh_resolver {
                Some(doh.client().clone())
            } else {
                Some(self.client_for(true, None)?)
            }
        } else {
            None
        };
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, files, timeout, proxy,
            allow_redirects, verify, ca_bundle, header_order, impersonate, local_address,
        )?;
        let jar = Arc::clone(&self.jar);
        let h3_pool = Arc::clone(&self.h3_pool);
        let ech_cache = Arc::clone(&self.ech_cache);
        let ticket_cache = Arc::clone(&self.ticket_cache);
        let doh_resolver = self.doh_resolver.clone();
        pyo3_async_runtimes::tokio::future_into_py(
            py,
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
            ),
        )
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
        self.ticket_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
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
            let ech: Option<bool> = d.get_item("ech")?.and_then(|v| v.extract().ok());
            let ech_config_list: Option<Vec<u8>> =
                d.get_item("ech_config_list")?.and_then(|v| v.extract().ok());

            let (h3_spec, tcp_ech_spec) = self.prepare_h3(
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
                ech,
                ech_config_list,
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
        let limit = concurrency.max(1);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let results: Vec<PyResult<NativeResponse>> = futures_util::stream::iter(
                    builders.into_iter().map(|(rb, h3_spec, tcp_ech_spec)| {
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
        self.ticket_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
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
        assert_eq!(formatted, "client error (Connect): dns error: dns resolution error: no records found");
    }

    #[test]
    fn test_socks5_percent_decode() {
        assert_eq!(socks5_udp::percent_decode("user%40name%3Apass"), "user@name:pass");
        assert_eq!(socks5_udp::percent_decode("plain123"), "plain123");
    }
}
