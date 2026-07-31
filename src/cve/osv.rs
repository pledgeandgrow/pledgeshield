use serde::{Deserialize, Serialize};

/// OSV.dev query request.
#[derive(Debug, Clone, Serialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

/// OSV.dev batch query request.
#[derive(Debug, Clone, Serialize)]
pub struct OsvBatchQuery {
    pub queries: Vec<OsvQuery>,
}

/// OSV.dev vulnerability response (subset).
#[derive(Debug, Clone, Deserialize)]
pub struct OsvResponse {
    pub vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub summary: String,
    pub severity: Vec<OsvSeverity>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

/// OSV.dev API client.
pub struct OsvClient {
    base_url: String,
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://api.osv.dev/v1".to_string(),
        }
    }

    /// Query OSV.dev for a single package.
    pub async fn query(&self, query: &OsvQuery) -> Result<OsvResponse, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let resp = client
            .post(format!("{}/query", self.base_url))
            .json(query)
            .send()
            .await?
            .error_for_status()?
            .json::<OsvResponse>()
            .await?;

        Ok(resp)
    }

    /// Batch query OSV.dev for multiple packages at once.
    pub async fn query_batch(
        &self,
        batch: &OsvBatchQuery,
    ) -> Result<Vec<OsvResponse>, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .user_agent("PledgeShield/0.1")
            .build()?;

        let resp = client
            .post(format!("{}/querybatch", self.base_url))
            .json(batch)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<OsvResponse>>()
            .await?;

        Ok(resp)
    }
}
