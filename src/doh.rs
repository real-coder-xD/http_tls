// Language: Rust 2021 | File: src/doh.rs | Target: Session-wide DNS-over-HTTPS (RFC 8484 JSON) A/AAAA & HTTPS(Type 65) ECH Resolver
//! Native DNS-over-HTTPS (DoH) resolver for both `wreq::dns::Resolve` (TCP HTTP/1.1, HTTP/2, WS)
//! and UDP QUIC HTTP/3 / TCP ECH, plus RFC 9460 Type 65 (`HTTPS` / SVCB) ECHConfigList fetching.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use wreq::dns::{Addrs, Name, Resolve, Resolving};
use wreq::{Client, Proxy};

pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

pub type EchCache = Arc<Mutex<HashMap<String, (Vec<u8>, Instant)>>>;
type AddrCache = Arc<Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>>;

pub fn decode_base64_ech(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    if out.len() >= 4 {
        Some(out)
    } else {
        None
    }
}

/// Extract `(ech_config_list_bytes, ttl_secs)` from a DoH JSON Type 65 (`HTTPS`) response.
pub fn extract_ech_from_doh_json(body: &str) -> Option<(Vec<u8>, u64)> {
    let mut ttl_secs: u64 = 300;
    if let Some(ttl_pos) = body.find("\"TTL\":") {
        let rest = body[ttl_pos + 6..].trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(parsed) = digits.parse::<u64>() {
            ttl_secs = parsed.clamp(30, 3600);
        }
    }
    let mut search_from = 0;
    while let Some(rel) = body[search_from..].find("ech=") {
        let start = search_from + rel + 4;
        let rest = &body[start..];
        let trimmed = rest
            .strip_prefix("\\\"")
            .or_else(|| rest.strip_prefix('"'))
            .unwrap_or(rest);
        let b64: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
            .collect();
        if b64.len() >= 16 {
            if let Some(decoded) = decode_base64_ech(&b64) {
                return Some((decoded, ttl_secs));
            }
        }
        search_from = start;
    }
    None
}

/// Extract `(ips, min_ttl)` from a DoH JSON `A` (type 1) or `AAAA` (type 28) response.
fn extract_ips_from_doh_json(body: &str) -> (Vec<IpAddr>, u64) {
    let mut ips = Vec::new();
    let mut min_ttl: u64 = 300;

    let after_answer = match body.find("\"Answer\"") {
        Some(pos) => &body[pos..],
        None => return (ips, min_ttl),
    };
    let answer_slice = match (after_answer.find('['), after_answer.find(']')) {
        (Some(l), Some(r)) if r > l => &after_answer[l..=r],
        _ => after_answer,
    };

    if let Some(ttl_pos) = answer_slice.find("\"TTL\":") {
        let rest = answer_slice[ttl_pos + 6..].trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(parsed) = digits.parse::<u64>() {
            min_ttl = parsed.clamp(30, 3600);
        }
    }

    let mut search_from = 0;
    while let Some(rel) = answer_slice[search_from..].find("\"data\":") {
        let start = search_from + rel + 7;
        let rest = answer_slice[start..].trim_start();
        if let Some(after_q) = rest.strip_prefix('"') {
            if let Some(end_q) = after_q.find('"') {
                let candidate = after_q[..end_q].trim();
                if let Ok(ip) = IpAddr::from_str(candidate) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
        search_from = start;
    }

    (ips, min_ttl)
}

pub async fn fetch_ech_config_list(
    host: &str,
    doh_url: &str,
    ech_cache: &EchCache,
    doh_client: &Client,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let key = host.trim().to_ascii_lowercase();
    if key.is_empty() || IpAddr::from_str(&key).is_ok() {
        return None;
    }
    {
        let cache = ech_cache.lock().await;
        if let Some((bytes, exp)) = cache.get(&key) {
            if Instant::now() < *exp {
                return Some(bytes.clone());
            }
        }
    }

    let mut url = url::Url::parse(doh_url).ok()?;
    url.query_pairs_mut()
        .append_pair("name", &key)
        .append_pair("type", "HTTPS");

    let resp = doh_client
        .get(url.as_str())
        .header(wreq::header::ACCEPT, "application/dns-json")
        .timeout(timeout.min(Duration::from_secs(5)))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    let (decoded, ttl) = extract_ech_from_doh_json(&body)?;
    {
        let mut cache = ech_cache.lock().await;
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(
            key,
            (decoded.clone(), Instant::now() + Duration::from_secs(ttl)),
        );
    }
    Some(decoded)
}

/// Session-wide DNS-over-HTTPS resolver plugging directly into `wreq::ClientBuilder::dns_resolver`
/// and shared with the UDP QUIC HTTP/3 and TCP ECH engines.
#[derive(Clone)]
pub struct DohResolver {
    doh_url: String,
    client: Client,
    cache: AddrCache,
}

impl DohResolver {
    pub fn new(doh_url: String, proxy: Option<&str>) -> Result<Self, String> {
        let mut b = Client::builder()
            .timeout(Duration::from_secs(6))
            .connect_timeout(Duration::from_secs(4));
        if let Some(p) = proxy {
            let px = Proxy::all(p).map_err(|e| format!("Invalid proxy '{p}' for DoH: {e}"))?;
            b = b.proxy(px);
        }
        let client = b
            .build()
            .map_err(|e| format!("Failed to initialize DoH client: {e}"))?;
        Ok(Self {
            doh_url,
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn resolve_ips(&self, host: &str) -> Result<Vec<IpAddr>, io::Error> {
        let clean = host.trim().trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
        if let Ok(ip) = IpAddr::from_str(&clean) {
            return Ok(vec![ip]);
        }
        if clean == "localhost" {
            return Ok(vec![IpAddr::from([127, 0, 0, 1])]);
        }
        {
            let guard = self.cache.lock().await;
            if let Some((ips, exp)) = guard.get(&clean) {
                if Instant::now() < *exp {
                    return Ok(ips.clone());
                }
            }
        }

        let (a_res, aaaa_res) = tokio::join!(
            self.query_type(&clean, "A"),
            self.query_type(&clean, "AAAA")
        );
        let mut resolved_ips = Vec::new();
        let mut ttl: u64 = 300;
        let mut got_ttl = false;
        if let Some((ips_v4, t4)) = a_res {
            for ip in ips_v4 {
                if !resolved_ips.contains(&ip) {
                    resolved_ips.push(ip);
                }
            }
            ttl = t4;
            got_ttl = true;
        }
        if let Some((ips_v6, t6)) = aaaa_res {
            for ip in ips_v6 {
                if !resolved_ips.contains(&ip) {
                    resolved_ips.push(ip);
                }
            }
            ttl = if got_ttl { ttl.min(t6) } else { t6 };
        }
        if resolved_ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DoH returned no A/AAAA records for '{clean}' via {}", self.doh_url),
            ));
        }
        {
            let mut guard = self.cache.lock().await;
            if guard.len() >= 512 {
                guard.clear();
            }
            guard.insert(
                clean,
                (resolved_ips.clone(), Instant::now() + Duration::from_secs(ttl)),
            );
        }
        Ok(resolved_ips)
    }

    async fn query_type(&self, host: &str, rr_type: &str) -> Option<(Vec<IpAddr>, u64)> {
        let mut url = url::Url::parse(&self.doh_url).ok()?;
        url.query_pairs_mut()
            .append_pair("name", host)
            .append_pair("type", rr_type);
        let resp = self
            .client
            .get(url.as_str())
            .header(wreq::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        let (ips, ttl) = extract_ips_from_doh_json(&body);
        if ips.is_empty() {
            None
        } else {
            Some((ips, ttl))
        }
    }

    pub async fn resolve_socket_addr(
        &self,
        host: &str,
        port: u16,
        prefer_ipv6: Option<bool>,
    ) -> Result<SocketAddr, io::Error> {
        let ips = self.resolve_ips(host).await?;
        if let Some(want_v6) = prefer_ipv6 {
            if let Some(&ip) = ips.iter().find(|i| i.is_ipv6() == want_v6) {
                return Ok(SocketAddr::new(ip, port));
            }
        }
        if let Some(&v4) = ips.iter().find(|i| i.is_ipv4()) {
            return Ok(SocketAddr::new(v4, port));
        }
        ips.into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("DoH returned no usable address for '{host}:{port}'"),
                )
            })
    }
}

impl Resolve for DohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = this.resolve_ips(&host).await?;
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}
