use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// NVD API 2.0 vulnerability response (subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdResponse {
    pub results_per_page: u32,
    pub total_results: u32,
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCve {
    pub id: String,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    #[serde(default)]
    pub cvss_metric_v31: Vec<NvdCvssMetric>,
    #[serde(rename = "cvssMetricV2")]
    #[serde(default)]
    pub cvss_metric_v2: Vec<NvdCvssMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdNode {
    #[serde(default)]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
}

/// NVD API 2.0 client with built-in rate limiting.
pub struct NvdClient {
    api_key: Option<String>,
    base_url: String,
    last_request: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            last_request: std::sync::Mutex::new(None),
        }
    }

    /// Rate limit: 6s without API key, 2s with API key.
    async fn rate_limit(&self) {
        let min_interval = if self.api_key.is_some() {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(6)
        };

        let now = tokio::time::Instant::now();
        let mut last = self.last_request.lock().unwrap();
        if let Some(prev) = *last {
            let elapsed = now - prev;
            if elapsed < min_interval {
                let remaining = min_interval - elapsed;
                sleep(remaining).await;
            }
        }
        *last = Some(tokio::time::Instant::now());
    }

    /// Query NVD by CPE name.
    pub async fn query_cpe(&self, cpe: &str) -> Result<NvdResponse, Box<dyn std::error::Error>> {
        self.rate_limit().await;

        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let mut req = client.get(&self.base_url).query(&[("cpeName", cpe)]);

        if let Some(ref key) = self.api_key {
            req = req.header("apiKey", key);
        }

        let resp = req
            .send()
            .await?
            .error_for_status()?
            .json::<NvdResponse>()
            .await?;
        Ok(resp)
    }

    /// Query NVD by keyword search (e.g. product name).
    pub async fn query_keyword(
        &self,
        keyword: &str,
    ) -> Result<NvdResponse, Box<dyn std::error::Error>> {
        self.rate_limit().await;

        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let mut req = client
            .get(&self.base_url)
            .query(&[("keywordSearch", keyword)]);

        if let Some(ref key) = self.api_key {
            req = req.header("apiKey", key);
        }

        let resp = req
            .send()
            .await?
            .error_for_status()?
            .json::<NvdResponse>()
            .await?;
        Ok(resp)
    }

    /// Build a CPE 2.3 formatted string from vendor, product, and version.
    pub fn build_cpe(vendor: &str, product: &str, version: &str) -> String {
        format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, version)
    }

    /// Attempt to match a software name to a CPE vendor/product pair.
    /// Returns (vendor, product) if a known mapping exists.
    pub fn lookup_cpe_mapping(name: &str) -> Option<(&'static str, &'static str)> {
        let lower = name.to_lowercase();
        let mappings: &[(&str, &str, &str)] = &[
            ("google chrome", "google", "chrome"),
            ("chrome", "google", "chrome"),
            ("mozilla firefox", "mozilla", "firefox"),
            ("firefox", "mozilla", "firefox"),
            ("microsoft edge", "microsoft", "edge"),
            ("edge", "microsoft", "edge"),
            ("adobe acrobat", "adobe", "acrobat"),
            ("acrobat", "adobe", "acrobat"),
            ("adobe reader", "adobe", "acrobat_reader"),
            ("java", "oracle", "jdk"),
            ("jdk", "oracle", "jdk"),
            ("jre", "oracle", "jre"),
            ("python", "python", "python"),
            ("node", "nodejs", "node"),
            ("node.js", "nodejs", "node"),
            ("npm", "npm", "npm"),
            ("git", "git", "git"),
            ("openssh", "openbsd", "openssh"),
            ("openssl", "openssl", "openssl"),
            ("apache", "apache", "http_server"),
            ("nginx", "nginx", "nginx"),
            ("mysql", "oracle", "mysql"),
            ("postgresql", "postgresql", "postgresql"),
            ("redis", "redis", "redis"),
            ("mongodb", "mongodb", "mongodb"),
            ("7-zip", "7-zip", "7-zip"),
            ("7zip", "7-zip", "7-zip"),
            ("vlc", "videolan", "vlc"),
            ("notepad++", "notepad-plus-plus", "notepad++"),
            ("winrar", "winrar", "winrar"),
            ("zoom", "zoom", "zoom"),
            ("slack", "slack", "slack"),
            ("docker", "docker", "docker"),
            ("visual studio code", "microsoft", "visual_studio_code"),
            ("vscode", "microsoft", "visual_studio_code"),
            ("curl", "haxx", "curl"),
            ("wget", "gnu", "wget"),
            ("putty", "simon_tatham", "putty"),
            ("wireshark", "wireshark", "wireshark"),
            ("filezilla", "filezilla", "filezilla"),
        ];

        for (pattern, vendor, product) in mappings {
            if lower.contains(pattern) {
                return Some((vendor, product));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cpe() {
        let cpe = NvdClient::build_cpe("google", "chrome", "120.0.6099.71");
        assert_eq!(cpe, "cpe:2.3:a:google:chrome:120.0.6099.71:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_build_cpe_special_chars() {
        let cpe = NvdClient::build_cpe("7-zip", "7-zip", "23.01");
        assert_eq!(cpe, "cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_lookup_cpe_mapping_chrome() {
        let result = NvdClient::lookup_cpe_mapping("Google Chrome");
        assert_eq!(result, Some(("google", "chrome")));
    }

    #[test]
    fn test_lookup_cpe_mapping_firefox() {
        let result = NvdClient::lookup_cpe_mapping("Mozilla Firefox");
        assert_eq!(result, Some(("mozilla", "firefox")));
    }

    #[test]
    fn test_lookup_cpe_mapping_case_insensitive() {
        let result = NvdClient::lookup_cpe_mapping("CHROME");
        assert_eq!(result, Some(("google", "chrome")));
    }

    #[test]
    fn test_lookup_cpe_mapping_no_match() {
        let result = NvdClient::lookup_cpe_mapping("unknown-software");
        assert_eq!(result, None);
    }

    #[test]
    fn test_lookup_cpe_mapping_partial_match() {
        let result = NvdClient::lookup_cpe_mapping("Visual Studio Code");
        assert_eq!(result, Some(("microsoft", "visual_studio_code")));
    }

    #[test]
    fn test_lookup_cpe_mapping_openssl() {
        let result = NvdClient::lookup_cpe_mapping("openssl");
        assert_eq!(result, Some(("openssl", "openssl")));
    }

    #[test]
    fn test_nvd_client_new_no_key() {
        let client = NvdClient::new(None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_nvd_client_new_with_key() {
        let client = NvdClient::new(Some("test-key".to_string()));
        assert!(client.api_key.is_some());
    }
}
