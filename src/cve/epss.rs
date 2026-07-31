use serde::{Deserialize, Serialize};

/// EPSS API response (subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssResponse {
    #[serde(rename = "epss")]
    pub epss_score: f64,
    pub percentile: f64,
    pub cve: String,
}

/// EPSS API top-level response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct EpssApiResponse {
    pub data: Vec<EpssResponse>,
}

/// EPSS API client — exploit prediction scoring for prioritization.
pub struct EpssClient {
    base_url: String,
}

impl EpssClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://api.first.org/data/v1/epss".to_string(),
        }
    }

    /// Get EPSS score for a single CVE.
    pub async fn get_score(&self, cve: &str) -> Result<EpssResponse, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let resp = client
            .get(&self.base_url)
            .query(&[("cve", cve)])
            .send()
            .await?
            .error_for_status()?
            .json::<EpssApiResponse>()
            .await?;

        resp.data
            .into_iter()
            .next()
            .ok_or_else(|| format!("No EPSS data for {}", cve).into())
    }
}
