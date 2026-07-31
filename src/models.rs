use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels ordered from most to least critical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[31m", // red
            Severity::High => "\x1b[91m",     // bright red
            Severity::Medium => "\x1b[33m",   // yellow
            Severity::Low => "\x1b[36m",      // cyan
            Severity::Info => "\x1b[37m",     // white
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A category that identifies which module produced a finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Config,
    Services,
    Cve,
    Privileges,
    Persistence,
    Credentials,
    Shares,
    Patches,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Config => write!(f, "config"),
            Category::Services => write!(f, "services"),
            Category::Cve => write!(f, "cve"),
            Category::Privileges => write!(f, "privileges"),
            Category::Persistence => write!(f, "persistence"),
            Category::Credentials => write!(f, "credentials"),
            Category::Shares => write!(f, "shares"),
            Category::Patches => write!(f, "patches"),
        }
    }
}

/// A single security finding produced by a scan module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding type
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description of the issue
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Module category that produced this finding
    pub category: Category,
    /// Recommended remediation action
    pub recommendation: String,
    /// Whether this finding can be auto-fixed
    #[serde(default)]
    pub fixable: bool,
    /// Additional structured metadata (e.g. port numbers, CVE IDs, registry keys)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl Finding {
    pub fn new(id: impl Into<String>, title: impl Into<String>, severity: Severity, category: Category) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            category,
            recommendation: String::new(),
            fixable: false,
            metadata: HashMap::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }

    pub fn fixable(mut self, fixable: bool) -> Self {
        self.fixable = fixable;
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// The complete result of a scan run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    /// Hostname of the scanned machine
    pub hostname: String,
    /// Operating system name
    pub os: String,
    /// OS version string
    pub os_version: String,
    /// Scan start timestamp
    pub scan_started: DateTime<Utc>,
    /// Scan end timestamp
    pub scan_completed: DateTime<Utc>,
    /// All findings collected during the scan
    pub findings: Vec<Finding>,
    /// Summary counts by severity
    pub summary: SeveritySummary,
}

impl ScanResult {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string()),
            os: std::env::consts::OS.to_string(),
            os_version: String::new(),
            scan_started: now,
            scan_completed: now,
            findings: Vec::new(),
            summary: SeveritySummary::default(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn finalize(&mut self) {
        self.scan_completed = Utc::now();
        self.summary = SeveritySummary::from_findings(&self.findings);
    }

    pub fn filter_by_severity(&mut self, min: Severity) {
        self.findings.retain(|f| f.severity <= min);
        self.summary = SeveritySummary::from_findings(&self.findings);
    }
}

/// Aggregated counts of findings by severity.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl SeveritySummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = SeveritySummary::default();
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
            summary.total += 1;
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str("low"), Some(Severity::Low));
        assert_eq!(Severity::from_str("info"), Some(Severity::Info));
        assert_eq!(Severity::from_str("invalid"), None);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Info.as_str(), "info");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "critical");
        assert_eq!(format!("{}", Severity::High), "high");
    }

    #[test]
    fn test_finding_builder() {
        let f = Finding::new("test-1", "Test Finding", Severity::High, Category::Config)
            .description("A test description")
            .recommendation("Fix it")
            .fixable(true)
            .metadata("key", "value");

        assert_eq!(f.id, "test-1");
        assert_eq!(f.title, "Test Finding");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, Category::Config);
        assert_eq!(f.description, "A test description");
        assert_eq!(f.recommendation, "Fix it");
        assert!(f.fixable);
        assert_eq!(f.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_finding_metadata_multiple() {
        let f = Finding::new("test-2", "Test", Severity::Low, Category::Services)
            .metadata("port", "22")
            .metadata("protocol", "tcp");

        assert_eq!(f.metadata.len(), 2);
        assert_eq!(f.metadata.get("port"), Some(&"22".to_string()));
        assert_eq!(f.metadata.get("protocol"), Some(&"tcp".to_string()));
    }

    #[test]
    fn test_scan_result_add_finding() {
        let mut result = ScanResult::new();
        assert_eq!(result.findings.len(), 0);

        result.add_finding(Finding::new("test-1", "Test", Severity::High, Category::Config));
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_scan_result_finalize() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("c-1", "Critical", Severity::Critical, Category::Config));
        result.add_finding(Finding::new("h-1", "High", Severity::High, Category::Services));
        result.add_finding(Finding::new("m-1", "Medium", Severity::Medium, Category::Patches));

        result.finalize();

        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.medium, 1);
        assert_eq!(result.summary.low, 0);
        assert_eq!(result.summary.info, 0);
        assert_eq!(result.summary.total, 3);
    }

    #[test]
    fn test_scan_result_filter_by_severity() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("c-1", "Critical", Severity::Critical, Category::Config));
        result.add_finding(Finding::new("h-1", "High", Severity::High, Category::Services));
        result.add_finding(Finding::new("l-1", "Low", Severity::Low, Category::Patches));

        result.filter_by_severity(Severity::High);

        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().all(|f| f.severity <= Severity::High));
    }

    #[test]
    fn test_severity_summary_from_findings() {
        let findings = vec![
            Finding::new("1", "A", Severity::Critical, Category::Config),
            Finding::new("2", "B", Severity::Critical, Category::Config),
            Finding::new("3", "C", Severity::High, Category::Services),
            Finding::new("4", "D", Severity::Info, Category::Patches),
        ];

        let summary = SeveritySummary::from_findings(&findings);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.total, 4);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", Category::Config), "config");
        assert_eq!(format!("{}", Category::Services), "services");
        assert_eq!(format!("{}", Category::Cve), "cve");
        assert_eq!(format!("{}", Category::Privileges), "privileges");
        assert_eq!(format!("{}", Category::Persistence), "persistence");
        assert_eq!(format!("{}", Category::Credentials), "credentials");
        assert_eq!(format!("{}", Category::Shares), "shares");
        assert_eq!(format!("{}", Category::Patches), "patches");
    }

    #[test]
    fn test_severity_serde() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");

        let sev: Severity = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(sev, Severity::High);
    }
}
