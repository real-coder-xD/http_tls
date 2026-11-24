// Language: Rust 2021 | File: src/presets.rs | Target: Browser Emulation Presets, Chromium GREASE Brand Lists & H3 Default Headers
#[cfg(feature = "python")]
use pyo3::prelude::*;
use wreq_util::{Emulation, Platform, Profile};

pub(crate) struct ResolvedEmulation {
    pub emulation: Emulation,
    pub ua_override: Option<String>,
    pub sec_ch_ua_override: Option<String>,
}

pub(crate) fn platform_from_name(lower: &str) -> Platform {
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
pub(crate) fn chromium_sec_ch_ua(major: u32, brand: &str) -> String {
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

pub(crate) fn resolve_emulation(preset: &str) -> ResolvedEmulation {
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

pub(crate) fn default_h3_browser_headers(
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

#[cfg_attr(feature = "python", pyfunction)]
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

#[allow(dead_code)]
#[cfg_attr(feature = "python", pyfunction)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chromium_grease_deterministic_and_verified_presets() {
        let ch = chromium_sec_ch_ua(152, "Google Chrome");
        assert!(ch.contains("\"Chromium\";v=\"152\""));
        assert!(ch.contains("\"Google Chrome\";v=\"152\""));
        assert!(ch.contains("Not"));
        assert!(is_verified_preset("chrome_149"));
        assert!(is_verified_preset("firefox_151"));
        assert!(is_verified_preset("safari_26_4"));
        assert!(!is_verified_preset("chrome_160"));
        assert!(supported_presets().len() >= 100);
    }
}
