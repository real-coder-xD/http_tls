// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 Extension | Runtime: Tokio + Reqwest
use encoding_rs::{Encoding, UTF_8};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Identity, Method, Proxy, RequestBuilder};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub name: String,
    pub user_agent: String,
    pub accept: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_mobile: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub sec_fetch_dest: Option<String>,
    pub sec_fetch_mode: Option<String>,
    pub sec_fetch_site: Option<String>,
    pub sec_fetch_user: Option<String>,
    pub upgrade_insecure_requests: Option<String>,
    pub priority: Option<String>,
}

fn build_chrome_profile(ver: u32, is_macos: bool, is_android: bool) -> BrowserProfile {
    let (ua, platform, mobile) = if is_android {
        (
            format!(
                "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Mobile Safari/537.36"
            ),
            "\"Android\"".to_string(),
            "?1".to_string(),
        )
    } else if is_macos {
        (
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
            ),
            "\"macOS\"".to_string(),
            "?0".to_string(),
        )
    } else {
        (
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
            ),
            "\"Windows\"".to_string(),
            "?0".to_string(),
        )
    };

    let grease = if ver % 2 == 0 { "24" } else { "99" };
    let sec_ch_ua = format!(
        "\"Chromium\";v=\"{ver}\", \"Not?A_Brand\";v=\"{grease}\", \"Google Chrome\";v=\"{ver}\""
    );

    BrowserProfile {
        name: format!("chrome_{ver}"),
        user_agent: ua,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_ch_ua: Some(sec_ch_ua),
        sec_ch_ua_mobile: Some(mobile),
        sec_ch_ua_platform: Some(platform),
        sec_fetch_dest: Some("document".to_string()),
        sec_fetch_mode: Some("navigate".to_string()),
        sec_fetch_site: Some("none".to_string()),
        sec_fetch_user: Some("?1".to_string()),
        upgrade_insecure_requests: Some("1".to_string()),
        priority: Some("u=0, i".to_string()),
    }
}

fn build_edge_profile(ver: u32) -> BrowserProfile {
    let grease = if ver % 2 == 0 { "24" } else { "99" };
    let sec_ch_ua = format!(
        "\"Chromium\";v=\"{ver}\", \"Not?A_Brand\";v=\"{grease}\", \"Microsoft Edge\";v=\"{ver}\""
    );

    BrowserProfile {
        name: format!("edge_{ver}"),
        user_agent: format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36 Edg/{ver}.0.0.0"
        ),
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_ch_ua: Some(sec_ch_ua),
        sec_ch_ua_mobile: Some("?0".to_string()),
        sec_ch_ua_platform: Some("\"Windows\"".to_string()),
        sec_fetch_dest: Some("document".to_string()),
        sec_fetch_mode: Some("navigate".to_string()),
        sec_fetch_site: Some("none".to_string()),
        sec_fetch_user: Some("?1".to_string()),
        upgrade_insecure_requests: Some("1".to_string()),
        priority: Some("u=0, i".to_string()),
    }
}

fn build_firefox_profile(ver: u32) -> BrowserProfile {
    BrowserProfile {
        name: format!("firefox_{ver}"),
        user_agent: format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0"
        ),
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
        sec_fetch_dest: Some("document".to_string()),
        sec_fetch_mode: Some("navigate".to_string()),
        sec_fetch_site: Some("none".to_string()),
        sec_fetch_user: Some("?1".to_string()),
        upgrade_insecure_requests: Some("1".to_string()),
        priority: Some("u=0, i".to_string()),
    }
}

fn build_safari_profile(ver: &str) -> BrowserProfile {
    BrowserProfile {
        name: format!("safari_{ver}"),
        user_agent: format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Safari/605.1.15"
        ),
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
        accept_language: "en-US,en;q=0.9".to_string(),
        accept_encoding: "gzip, deflate, br, zstd".to_string(),
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
        sec_fetch_dest: Some("document".to_string()),
        sec_fetch_mode: Some("navigate".to_string()),
        sec_fetch_site: Some("none".to_string()),
        sec_fetch_user: None,
        upgrade_insecure_requests: None,
        priority: Some("u=0, i".to_string()),
    }
}

fn get_browser_profile(preset: &str) -> Option<BrowserProfile> {
    let lower = preset.to_lowercase().replace('-', "_");

    // Default alias "chrome" -> Chrome 152 (phiÃªn báº£n má»›i nháº¥t tÃ­nh Ä‘áº¿n 15/11/2026)
    if lower == "chrome" || lower == "default" {
        return Some(build_chrome_profile(152, false, false));
    }
    if lower == "safari" {
        return Some(build_safari_profile("27.0"));
    }
    if lower == "firefox" {
        return Some(build_firefox_profile(155));
    }
    if lower == "edge" {
        return Some(build_edge_profile(152));
    }

    // Chrome presets
    if lower.starts_with("chrome") {
        let is_macos = lower.contains("macos") || lower.contains("mac");
        let is_android = lower.contains("android");
        let clean = lower
            .replace("chrome_", "")
            .replace("chrome", "")
            .replace("_macos", "")
            .replace("_android", "")
            .replace('a', "");

        if let Ok(ver) = clean.parse::<u32>() {
            return Some(build_chrome_profile(ver, is_macos, is_android));
        }
    }

    // Edge presets
    if lower.starts_with("edge") {
        let clean = lower.replace("edge_", "").replace("edge", "");
        if let Ok(ver) = clean.parse::<u32>() {
            return Some(build_edge_profile(ver));
        }
    }

    // Firefox presets
    if lower.starts_with("firefox") {
        let clean = lower.replace("firefox_", "").replace("firefox", "");
        if let Ok(ver) = clean.parse::<u32>() {
            return Some(build_firefox_profile(ver));
        }
    }

    // Safari presets
    if lower.starts_with("safari") {
        let clean = lower.replace("safari_", "").replace("safari", "");
        let ver = match clean.as_str() {
            "27" | "270" | "27_0" => "27.0",
            "26" | "260" | "26_0" => "26.0",
            "2601" | "26_0_1" => "26.0.1",
            "184" | "18_4" => "18.4",
            "18" | "180" | "18_0" => "18.0",
            "172" | "17_2" => "17.2",
            "17" | "170" | "17_0" => "17.0",
            "155" | "15_5" => "15.5",
            "153" | "15_3" => "15.3",
            _ => "27.0",
        };
        return Some(build_safari_profile(ver));
    }

    if lower.starts_with("tor") {
        return Some(BrowserProfile {
            name: "tor_14_5".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
            accept_language: "en-US,en;q=0.5".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            sec_ch_ua: None,
            sec_ch_ua_mobile: None,
            sec_ch_ua_platform: None,
            sec_fetch_dest: Some("document".to_string()),
            sec_fetch_mode: Some("navigate".to_string()),
            sec_fetch_site: Some("none".to_string()),
            sec_fetch_user: Some("?1".to_string()),
            upgrade_insecure_requests: Some("1".to_string()),
            priority: Some("u=0, i".to_string()),
        });
    }

    None
}

fn apply_profile_headers(headers: &mut HeaderMap, profile: &BrowserProfile) {
    let insert = |hdrs: &mut HeaderMap, key: &'static str, val: &str| {
        if let (Ok(k), Ok(v)) = (HeaderName::from_str(key), HeaderValue::from_str(val)) {
            hdrs.insert(k, v);
        }
    };

    insert(headers, "user-agent", &profile.user_agent);
    insert(headers, "accept", &profile.accept);
    insert(headers, "accept-language", &profile.accept_language);
    insert(headers, "accept-encoding", &profile.accept_encoding);

    if let Some(ref v) = profile.sec_ch_ua {
        insert(headers, "sec-ch-ua", v);
    }
    if let Some(ref v) = profile.sec_ch_ua_mobile {
        insert(headers, "sec-ch-ua-mobile", v);
    }
    if let Some(ref v) = profile.sec_ch_ua_platform {
        insert(headers, "sec-ch-ua-platform", v);
    }
    if let Some(ref v) = profile.sec_fetch_dest {
        insert(headers, "sec-fetch-dest", v);
    }
    if let Some(ref v) = profile.sec_fetch_mode {
        insert(headers, "sec-fetch-mode", v);
    }
    if let Some(ref v) = profile.sec_fetch_site {
        insert(headers, "sec-fetch-site", v);
    }
    if let Some(ref v) = profile.sec_fetch_user {
        insert(headers, "sec-fetch-user", v);
    }
    if let Some(ref v) = profile.upgrade_insecure_requests {
        insert(headers, "upgrade-insecure-requests", v);
    }
    if let Some(ref v) = profile.priority {
        insert(headers, "priority", v);
    }
}

// ---------------------------------------------------------------------------
// Shared runtime: one multi-thread Tokio runtime per process, not per Session.
// ---------------------------------------------------------------------------
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> PyResult<&'static tokio::runtime::Runtime> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("http_tls-rt")
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("[runtime] failed to start Tokio: {e}")))?;
    // A racing thread may have won; its runtime is kept, ours is dropped.
    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .ok_or_else(|| PyRuntimeError::new_err("[runtime] Tokio runtime unavailable"))
}

// ---------------------------------------------------------------------------
// Error classification: "[kind] message" prefix, mapped to requests-style
// exceptions on the Python side (http_tls.requests._raise_native).
// ---------------------------------------------------------------------------
fn error_chain(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

fn net_err(e: reqwest::Error) -> PyErr {
    let chain = error_chain(&e);
    let low = chain.to_lowercase();
    let kind = if e.is_timeout() {
        if e.is_connect() { "connect_timeout" } else { "timeout" }
    } else if e.is_redirect() {
        "redirect"
    } else if low.contains("certificate")
        || low.contains("handshake")
        || low.contains("invalid peer")
        || low.contains("tls")
    {
        "ssl"
    } else if e.is_connect() {
        "connect"
    } else {
        "request"
    };
    PyRuntimeError::new_err(format!("[{kind}] {chain}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
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

fn collect_cookies(jar: &Jar, url: &url::Url, h: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(hv) = jar.cookies(url) {
        if let Ok(s) = hv.to_str() {
            for part in s.split(';') {
                if let Some((k, v)) = part.split_once('=') {
                    out.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
    }
    // Cookies scoped to other paths/domains are not returned by the jar for
    // this URL; surface them from the final response anyway.
    for raw in h.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(s) = raw.to_str() {
            if let Some((k, v)) = s.split(';').next().and_then(|p| p.split_once('=')) {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

fn charset_of(h: &HeaderMap) -> Option<&'static Encoding> {
    let ct = h.get(reqwest::header::CONTENT_TYPE)?.to_str().ok()?.to_ascii_lowercase();
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

// ---------------------------------------------------------------------------
// Response types
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

/// Response whose body is pulled chunk-by-chunk from the socket (stream=True).
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
    inner: Mutex<Option<reqwest::Response>>,
}

#[pymethods]
impl NativeStream {
    /// Next body chunk, or None at EOF. The connection is released at EOF.
    pub fn read_chunk(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        let rt = runtime()?;
        let chunk = py.allow_threads(|| -> PyResult<Option<bytes::Bytes>> {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let next = match guard.as_mut() {
                None => return Ok(None),
                Some(resp) => rt.block_on(resp.chunk()).map_err(net_err)?,
            };
            if next.is_none() {
                guard.take();
            }
            Ok(next)
        })?;
        Ok(chunk.map(|b| PyBytes::new(py, &b).unbind()))
    }

    /// Drop the body without reading it; returns the connection to the pool state.
    pub fn close(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).take();
    }

    #[getter]
    pub fn closed(&self) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).is_none()
    }

    pub fn __repr__(&self) -> String {
        format!("<StreamResponse [{}]>", self.status_code)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
/// (proxy, follow_redirects, verify) -> dedicated reqwest Client.
/// reqwest fixes these at build time, so per-request overrides get their own
/// client; all clients share one cookie jar.
type ClientKey = (Option<String>, bool, bool);

#[pyclass(name = "Session")]
pub struct NativeSession {
    jar: Arc<Jar>,
    clients: Mutex<HashMap<ClientKey, Client>>,
    default_headers: HeaderMap,
    timeout: Duration,
    max_redirects: usize,
    ca_certs: Vec<Certificate>,
    identity: Option<Identity>,
    default_proxy: Option<String>,
    follow_redirects: bool,
    verify: bool,
    impersonate: String,
}

impl NativeSession {
    fn client_for(&self, key: ClientKey) -> PyResult<Client> {
        let mut cache = self.clients.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = cache.get(&key) {
            return Ok(c.clone());
        }
        let (proxy, follow, verify) = &key;

        let mut b = Client::builder()
            .cookie_provider(Arc::clone(&self.jar))
            .default_headers(self.default_headers.clone())
            .timeout(self.timeout)
            .tls_danger_accept_invalid_certs(!*verify)
            .redirect(if *follow {
                Policy::limited(self.max_redirects)
            } else {
                Policy::none()
            });

        if !self.ca_certs.is_empty() {
            b = b.tls_certs_merge(self.ca_certs.clone());
        }
        if let Some(id) = &self.identity {
            b = b.identity(id.clone());
        }
        if let Some(p) = proxy {
            let px = Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {e}")))?;
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
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
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

        // Caller cookies go into the shared jar, scoped to this host and "/",
        // so redirects and later requests carry them exactly once.
        for (k, v) in dict_pairs(cookies)? {
            self.jar.add_cookie_str(&format!("{k}={v}; Path=/"), &final_url);
        }

        let key: ClientKey = (
            proxy.or_else(|| self.default_proxy.clone()),
            allow_redirects.unwrap_or(self.follow_redirects),
            verify.unwrap_or(self.verify),
        );
        let client = self.client_for(key)?;

        let mut rb = client.request(m, final_url);
        if let Some(t) = timeout {
            rb = rb.timeout(Duration::from_secs_f64(t.max(0.1)));
        }
        for (k, v) in dict_pairs(headers)? {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                rb = rb.header(hn, hv);
            }
        }
        if let Some(body) = data {
            rb = rb.body(body);
        } else if let Some(j) = json {
            rb = rb
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(j.to_string());
        }
        Ok(rb)
    }
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
        client_identity = None
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
        client_identity: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut default_headers = HeaderMap::new();
        if let Some(profile) = get_browser_profile(impersonate) {
            apply_profile_headers(&mut default_headers, &profile);
        }
        for (k, v) in dict_pairs(headers)? {
            if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                default_headers.insert(hn, hv);
            }
        }

        // CA bundle: PEM (one or many certs) or a single DER certificate.
        let ca_certs = match ca_bundle {
            None => Vec::new(),
            Some(raw) => {
                let pem = Certificate::from_pem_bundle(&raw).unwrap_or_default();
                if !pem.is_empty() {
                    pem
                } else {
                    vec![Certificate::from_der(&raw).map_err(|e| {
                        PyValueError::new_err(format!("CA bundle is neither PEM nor DER: {e}"))
                    })?]
                }
            }
        };

        // Client identity: PEM containing certificate chain + private key.
        let identity = match client_identity {
            None => None,
            Some(raw) => Some(Identity::from_pem(&raw).map_err(|e| {
                PyValueError::new_err(format!("Client certificate/key PEM rejected: {e}"))
            })?),
        };

        // Fail fast on a bad proxy string instead of at first request.
        if let Some(p) = &proxy {
            Proxy::all(p.as_str())
                .map_err(|e| PyValueError::new_err(format!("Invalid proxy '{p}': {e}")))?;
        }

        runtime()?;

        Ok(NativeSession {
            jar: Arc::new(Jar::default()),
            clients: Mutex::new(HashMap::new()),
            default_headers,
            timeout: Duration::from_secs_f64(timeout.max(0.1)),
            max_redirects,
            ca_certs,
            identity,
            default_proxy: proxy,
            follow_redirects,
            verify: verify_ssl,
            impersonate: impersonate.to_string(),
        })
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, timeout = None, proxy = None, allow_redirects = None, verify = None
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
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
    ) -> PyResult<NativeResponse> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, timeout, proxy, allow_redirects, verify,
        )?;
        let rt = runtime()?;
        let jar = Arc::clone(&self.jar);

        py.allow_threads(move || {
            rt.block_on(async move {
                let start = Instant::now();
                let resp = rb.send().await.map_err(net_err)?;
                let status_code = resp.status().as_u16();
                let final_url = resp.url().clone();
                let hdrs = resp.headers().clone();
                let bytes = resp.bytes().await.map_err(net_err)?;
                let elapsed = start.elapsed().as_secs_f64();

                let (text, encoding) = decode_body(&bytes, &hdrs);
                Ok(NativeResponse {
                    status_code,
                    headers: collect_headers(&hdrs),
                    cookies: collect_cookies(&jar, &final_url, &hdrs),
                    url: final_url.to_string(),
                    content: bytes.to_vec(),
                    text,
                    encoding,
                    elapsed,
                })
            })
        })
    }

    #[pyo3(signature = (
        method, url, params = None, headers = None, cookies = None, data = None,
        json = None, timeout = None, proxy = None, allow_redirects = None, verify = None
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
        timeout: Option<f64>,
        proxy: Option<String>,
        allow_redirects: Option<bool>,
        verify: Option<bool>,
    ) -> PyResult<NativeStream> {
        let rb = self.prepare(
            method, url, params, headers, cookies, data, json, timeout, proxy, allow_redirects, verify,
        )?;
        let rt = runtime()?;
        let jar = Arc::clone(&self.jar);

        py.allow_threads(move || {
            rt.block_on(async move {
                let start = Instant::now();
                let resp = rb.send().await.map_err(net_err)?;
                let elapsed = start.elapsed().as_secs_f64();
                let final_url = resp.url().clone();
                let hdrs = resp.headers();
                Ok(NativeStream {
                    status_code: resp.status().as_u16(),
                    headers: collect_headers(hdrs),
                    cookies: collect_cookies(&jar, &final_url, hdrs),
                    encoding: charset_of(hdrs)
                        .map(|e| e.name().to_ascii_lowercase())
                        .unwrap_or_default(),
                    url: final_url.to_string(),
                    elapsed,
                    inner: Mutex::new(Some(resp)),
                })
            })
        })
    }

    /// All cookies the jar would send to `url`.
    pub fn cookies_for(&self, url: &str) -> PyResult<HashMap<String, String>> {
        let u = url::Url::parse(url).map_err(|e| PyValueError::new_err(format!("Invalid URL: {e}")))?;
        Ok(collect_cookies(&self.jar, &u, &HeaderMap::new()))
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
        "chrome_146", "chrome_145", "chrome_142", "chrome_136", "chrome_133", "chrome_131",
        "chrome_131_android", "chrome_130", "chrome_128", "chrome_126", "chrome_124",
        "edge_152", "edge_142", "edge_131", "edge_128", "edge_124",
        "safari_27", "safari_26", "safari_18_4", "safari_18", "safari_17",
        "firefox_155", "firefox_154", "firefox_153", "firefox_147", "firefox_144",
        "firefox_135", "firefox_133", "firefox_130",
        "tor_14_5",
    ]
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeStream>()?;
    m.add_class::<NativeSession>()?;
    m.add_function(wrap_pyfunction!(supported_presets, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
