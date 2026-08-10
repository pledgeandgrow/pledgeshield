use serde::{Deserialize, Serialize};

/// GitHub Security Advisory (subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhsaAdvisory {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub summary: String,
    pub severity: String,
    pub cvss: Option<GhsaCvss>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhsaCvss {
    pub score: f64,
    pub severity: String,
}

/// GitHub Security Advisories API client.
pub struct GhsaClient {
    token: Option<String>,
    base_url: String,
}

impl GhsaClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            token,
            base_url: "https://api.github.com/advisories".to_string(),
        }
    }

    /// Query GHSA by ecosystem and package name.
    pub async fn query(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Vec<GhsaAdvisory>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let mut req = client
            .get(&self.base_url)
            .query(&[("type", ecosystem), ("ecosystem_package", package)]);

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<GhsaAdvisory>>()
            .await?;

        Ok(resp)
    }

    /// Query GHSA by CVE ID.
    pub async fn query_by_cve(
        &self,
        cve_id: &str,
    ) -> Result<Vec<GhsaAdvisory>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let mut req = client.get(&self.base_url).query(&[("cve_id", cve_id)]);

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<GhsaAdvisory>>()
            .await?;

        Ok(resp)
    }
}
