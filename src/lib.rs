// Language: Rust 2021 | File: src/lib.rs | Target: Python PyO3 Extension | Runtime: Tokio + Reqwest
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Method, Proxy};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
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

    // Default alias "chrome" -> Chrome 152 (phiên bản mới nhất tính đến 15/11/2026)
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

#[pyclass(name = "Response")]
pub struct NativeResponse {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
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
    pub fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let json_mod = py.import("json")?;
        let loads = json_mod.getattr("loads")?;
        loads.call1((&self.text,))
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

#[pyclass(name = "Session")]
pub struct NativeSession {
    client: Arc<Client>,
    runtime: Arc<tokio::runtime::Runtime>,
    impersonate: String,
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
        headers = None
    ))]
    pub fn new(
        impersonate: &str,
        timeout: f64,
        follow_redirects: bool,
        max_redirects: usize,
        verify_ssl: bool,
        proxy: Option<&str>,
        headers: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to start async runtime: {}", e)))?;

        let mut builder = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs_f64(timeout.max(0.1)));

        if follow_redirects {
            builder = builder.redirect(Policy::limited(max_redirects));
        } else {
            builder = builder.redirect(Policy::none());
        }

        if let Some(proxy_str) = proxy {
            let p = Proxy::all(proxy_str)
                .map_err(|e| PyRuntimeError::new_err(format!("Invalid proxy: {}", e)))?;
            builder = builder.proxy(p);
        }

        let mut default_hdrs = HeaderMap::new();
        if let Some(profile) = get_browser_profile(impersonate) {
            apply_profile_headers(&mut default_hdrs, &profile);
        }

        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                let key_str = k.extract::<String>()?;
                let val_str = v.extract::<String>()?;
                if let (Ok(hn), Ok(hv)) = (
                    HeaderName::from_str(&key_str),
                    HeaderValue::from_str(&val_str),
                ) {
                    default_hdrs.insert(hn, hv);
                }
            }
        }

        builder = builder.default_headers(default_hdrs);

        let client = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to build HTTP client: {}", e)))?;

        Ok(NativeSession {
            client: Arc::new(client),
            runtime: Arc::new(rt),
            impersonate: impersonate.to_string(),
        })
    }

    #[pyo3(signature = (
        method,
        url,
        params = None,
        headers = None,
        cookies = None,
        data = None,
        json = None,
        timeout = None,
        _proxy = None
    ))]
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
        _proxy: Option<&str>,
    ) -> PyResult<NativeResponse> {
        let req_method = Method::from_str(&method.to_uppercase())
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid HTTP method: {}", e)))?;

        let mut final_url = url::Url::parse(url)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid URL: {}", e)))?;

        if let Some(p) = params {
            let mut pairs = final_url.query_pairs_mut();
            for (k, v) in p {
                let ks = k.extract::<String>()?;
                let vs = v.extract::<String>()?;
                pairs.append_pair(&ks, &vs);
            }
        }

        let mut req_builder = self.client.request(req_method, final_url);

        if let Some(t) = timeout {
            req_builder = req_builder.timeout(Duration::from_secs_f64(t.max(0.1)));
        }

        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                let ks = k.extract::<String>()?;
                let vs = v.extract::<String>()?;
                if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&ks), HeaderValue::from_str(&vs)) {
                    req_builder = req_builder.header(hn, hv);
                }
            }
        }

        if let Some(c) = cookies {
            let mut cookie_parts = Vec::new();
            for (k, v) in c {
                let ks = k.extract::<String>()?;
                let vs = v.extract::<String>()?;
                cookie_parts.push(format!("{}={}", ks, vs));
            }
            if !cookie_parts.is_empty() {
                let cookie_header = cookie_parts.join("; ");
                if let Ok(hv) = HeaderValue::from_str(&cookie_header) {
                    req_builder = req_builder.header(reqwest::header::COOKIE, hv);
                }
            }
        }

        if let Some(body_bytes) = data {
            req_builder = req_builder.body(body_bytes);
        } else if let Some(json_text) = json {
            req_builder = req_builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(json_text.to_string());
        }

        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(move || {
            runtime.block_on(async move {
                let start_time = Instant::now();
                let resp = req_builder
                    .send()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("Request failed: {}", e)))?;

                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let status_code = resp.status().as_u16();
                let resp_url = resp.url().to_string();

                let mut out_headers = HashMap::new();
                let mut out_cookies = HashMap::new();

                for (name, value) in resp.headers() {
                    let key = name.as_str().to_lowercase();
                    let val = value.to_str().unwrap_or("").to_string();
                    if key == "set-cookie" {
                        if let Some(first) = val.split(';').next() {
                            if let Some((ck, cv)) = first.split_once('=') {
                                out_cookies.insert(ck.trim().to_string(), cv.trim().to_string());
                            }
                        }
                    }
                    out_headers.insert(key, val);
                }

                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("Failed reading response bytes: {}", e)))?;

                let (decoded_text, encoding_used, _) = encoding_rs::UTF_8.decode(&bytes);
                let text = decoded_text.into_owned();
                let encoding = encoding_used.name().to_string();

                Ok(NativeResponse {
                    status_code,
                    headers: out_headers,
                    url: resp_url,
                    content: bytes.to_vec(),
                    text,
                    encoding,
                    elapsed: elapsed_secs,
                    cookies: out_cookies,
                })
            })
        })
    }

    #[getter]
    pub fn impersonate(&self) -> String {
        self.impersonate.clone()
    }
}

#[pyfunction]
pub fn supported_presets() -> Vec<&'static str> {
    vec![
        // Chrome (124 -> 152 hiện tại 15/11/2026)
        "chrome_152", // Default hiện tại
        "chrome_152_macos",
        "chrome_151",
        "chrome_151_macos",
        "chrome_150",
        "chrome_146",
        "chrome_145",
        "chrome_142",
        "chrome_136",
        "chrome_133",
        "chrome_131",
        "chrome_131_android",
        "chrome_130",
        "chrome_128",
        "chrome_126",
        "chrome_124",
        // Edge
        "edge_152",
        "edge_142",
        "edge_131",
        "edge_128",
        "edge_124",
        // Safari
        "safari_27",
        "safari_26",
        "safari_18_4",
        "safari_18",
        "safari_17",
        // Firefox
        "firefox_155",
        "firefox_154",
        "firefox_153",
        "firefox_147",
        "firefox_144",
        "firefox_135",
        "firefox_133",
        "firefox_130",
        // Tor
        "tor_14_5",
    ]
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeResponse>()?;
    m.add_class::<NativeSession>()?;
    m.add_function(wrap_pyfunction!(supported_presets, m)?)?;
    m.add("__version__", "0.2.0")?;
    Ok(())
}
