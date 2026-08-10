use crate::models::Severity;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// PledgeShield configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PledgeShieldConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub cve: CveConfig,
    #[serde(default)]
    pub exclusions: ExclusionConfig,
    #[serde(default)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub history: HistoryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Modules to enable (empty = all)
    #[serde(default)]
    pub modules: Vec<String>,
    /// Minimum severity to report
    #[serde(default)]
    pub min_severity: Option<String>,
    /// Enable CVE scanning
    #[serde(default)]
    pub cve: bool,
    /// Offline mode
    #[serde(default)]
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveConfig {
    /// NVD API key
    #[serde(default)]
    pub nvd_api_key: Option<String>,
    /// GitHub token for GHSA
    #[serde(default)]
    pub github_token: Option<String>,
    /// Cache TTL in hours (default: 24)
    #[serde(default)]
    pub cache_ttl_hours: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExclusionConfig {
    /// Finding IDs to exclude from results
    #[serde(default)]
    pub finding_ids: Vec<String>,
    /// Categories to exclude
    #[serde(default)]
    pub categories: Vec<String>,
    /// Metadata key=value pairs to exclude (e.g. port=23)
    #[serde(default)]
    pub metadata: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThresholdConfig {
    /// Max number of info findings to show
    #[serde(default)]
    pub max_info: Option<usize>,
    /// Max number of low findings to show
    #[serde(default)]
    pub max_low: Option<usize>,
    /// Fail exit code if findings at or above this severity
    #[serde(default)]
    pub fail_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotifyConfig {
    /// Webhook URL (Slack/Discord/Teams/generic). Empty = disabled.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Email notification settings
    #[serde(default)]
    pub email: Option<EmailNotifyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailNotifyConfig {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: u16,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoryConfig {
    /// Record each scan to the local SQLite history database
    #[serde(default)]
    pub enabled: bool,
    /// Optional explicit path to the history database
    #[serde(default)]
    pub path: Option<String>,
}

impl PledgeShieldConfig {
    /// Load config from a file. Supports TOML (.toml) and YAML (.yaml/.yml).
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let config = match ext {
            "toml" => toml::from_str::<PledgeShieldConfig>(&content)?,
            "yaml" | "yml" => serde_yaml::from_str::<PledgeShieldConfig>(&content)?,
            _ => {
                // Try TOML first, then YAML
                toml::from_str::<PledgeShieldConfig>(&content)
                    .or_else(|_| serde_yaml::from_str::<PledgeShieldConfig>(&content))?
            }
        };

        Ok(config)
    }

    /// Try to load from default locations.
    pub fn load_default() -> Option<Self> {
        let candidates = [
            "pledgeshield.toml",
            "pledgeshield.yaml",
            "pledgeshield.yml",
            ".pledgeshield.toml",
            ".pledgeshield.yaml",
            ".pledgeshield.yml",
        ];

        for candidate in &candidates {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                if let Ok(config) = Self::load(path) {
                    log::info!("Loaded config from {}", candidate);
                    return Some(config);
                }
            }
        }

        // Check config directory
        if let Some(config_dir) = dirs::config_dir() {
            let path = config_dir.join("pledgeshield").join("config.toml");
            if path.exists() {
                if let Ok(config) = Self::load(&path) {
                    log::info!("Loaded config from {}", path.display());
                    return Some(config);
                }
            }
        }

        None
    }

    /// Check if a finding should be excluded based on config.
    pub fn is_excluded(&self, finding: &crate::models::Finding) -> bool {
        // Check finding ID exclusions
        if self
            .exclusions
            .finding_ids
            .iter()
            .any(|id| finding.id == *id)
        {
            return true;
        }

        // Check category exclusions
        let cat_str = finding.category.to_string();
        if self.exclusions.categories.iter().any(|c| *c == cat_str) {
            return true;
        }

        // Check metadata exclusions (format: key=value)
        for excl in &self.exclusions.metadata {
            if let Some((key, value)) = excl.split_once('=') {
                if finding.metadata.get(key).map(|v| v.as_str()) == Some(value) {
                    return true;
                }
            }
        }

        false
    }

    /// Get the minimum severity from config.
    pub fn min_severity(&self) -> Option<Severity> {
        self.scan
            .min_severity
            .as_deref()
            .and_then(Severity::from_str)
            .or_else(|| {
                self.thresholds
                    .fail_on
                    .as_deref()
                    .and_then(Severity::from_str)
            })
    }

    /// Generate a sample config file.
    pub fn sample_toml() -> String {
        let sample = PledgeShieldConfig {
            scan: ScanConfig {
                modules: vec![],
                min_severity: Some("low".to_string()),
                cve: false,
                offline: false,
            },
            cve: CveConfig {
                nvd_api_key: Some("your-nvd-api-key-here".to_string()),
                github_token: Some("your-github-token-here".to_string()),
                cache_ttl_hours: Some(24),
            },
            exclusions: ExclusionConfig {
                finding_ids: vec!["win-clipboard-history-enabled".to_string()],
                categories: vec![],
                metadata: vec!["port=139".to_string()],
            },
            thresholds: ThresholdConfig {
                max_info: Some(50),
                max_low: Some(100),
                fail_on: Some("high".to_string()),
            },
            notify: NotifyConfig {
                webhook_url: Some("https://hooks.slack.com/services/XXX/YYY/ZZZ".to_string()),
                email: None,
            },
            history: HistoryConfig {
                enabled: false,
                path: None,
            },
        };

        toml::to_string_pretty(&sample).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Finding, Severity};

    #[test]
    fn test_config_default() {
        let config = PledgeShieldConfig::default();
        assert!(config.scan.modules.is_empty());
        assert!(!config.scan.cve);
    }

    #[test]
    fn test_config_load_toml() {
        let toml_content = r#"
[scan]
cve = true
offline = false
min_severity = "high"

[cve]
nvd_api_key = "test-key"
github_token = "test-token"
cache_ttl_hours = 12

[exclusions]
finding_ids = ["test-1", "test-2"]
categories = ["info"]
metadata = ["port=23"]

[thresholds]
max_info = 10
max_low = 20
fail_on = "critical"
"#;
        let path = std::env::temp_dir().join("pledgeshield_test_config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let config = PledgeShieldConfig::load(&path).unwrap();
        assert!(config.scan.cve);
        assert_eq!(config.scan.min_severity, Some("high".to_string()));
        assert_eq!(config.cve.nvd_api_key, Some("test-key".to_string()));
        assert_eq!(config.cve.github_token, Some("test-token".to_string()));
        assert_eq!(config.cve.cache_ttl_hours, Some(12));
        assert_eq!(config.exclusions.finding_ids, vec!["test-1", "test-2"]);
        assert_eq!(config.exclusions.categories, vec!["info"]);
        assert_eq!(config.exclusions.metadata, vec!["port=23"]);
        assert_eq!(config.thresholds.max_info, Some(10));
        assert_eq!(config.thresholds.max_low, Some(20));
        assert_eq!(config.thresholds.fail_on, Some("critical".to_string()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_config_load_yaml() {
        let yaml_content = r#"
scan:
  cve: true
  offline: false
  min_severity: medium
cve:
  nvd_api_key: yaml-key
exclusions:
  finding_ids:
    - yaml-1
thresholds:
  fail_on: high
"#;
        let path = std::env::temp_dir().join("pledgeshield_test_config.yaml");
        std::fs::write(&path, yaml_content).unwrap();

        let config = PledgeShieldConfig::load(&path).unwrap();
        assert!(config.scan.cve);
        assert_eq!(config.scan.min_severity, Some("medium".to_string()));
        assert_eq!(config.cve.nvd_api_key, Some("yaml-key".to_string()));
        assert_eq!(config.exclusions.finding_ids, vec!["yaml-1"]);
        assert_eq!(config.thresholds.fail_on, Some("high".to_string()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_is_excluded_by_id() {
        let config = PledgeShieldConfig {
            exclusions: ExclusionConfig {
                finding_ids: vec!["win-uac-disabled".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let f = Finding::new(
            "win-uac-disabled",
            "UAC Disabled",
            Severity::High,
            Category::Config,
        );
        assert!(config.is_excluded(&f));

        let f2 = Finding::new("other-finding", "Other", Severity::Low, Category::Config);
        assert!(!config.is_excluded(&f2));
    }

    #[test]
    fn test_is_excluded_by_category() {
        let config = PledgeShieldConfig {
            exclusions: ExclusionConfig {
                categories: vec!["info".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let f = Finding::new("test-1", "Test", Severity::Info, Category::Config);
        assert!(!config.is_excluded(&f)); // Category::Config != "info"

        // Category string should match the category name
        let config2 = PledgeShieldConfig {
            exclusions: ExclusionConfig {
                categories: vec!["config".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config2.is_excluded(&f));
    }

    #[test]
    fn test_is_excluded_by_metadata() {
        let config = PledgeShieldConfig {
            exclusions: ExclusionConfig {
                metadata: vec!["port=23".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let f = Finding::new("test-1", "Test", Severity::Medium, Category::Services)
            .metadata("port", "23");
        assert!(config.is_excluded(&f));

        let f2 = Finding::new("test-2", "Test", Severity::Medium, Category::Services)
            .metadata("port", "22");
        assert!(!config.is_excluded(&f2));
    }

    #[test]
    fn test_is_not_excluded() {
        let config = PledgeShieldConfig::default();
        let f = Finding::new("test-1", "Test", Severity::High, Category::Config);
        assert!(!config.is_excluded(&f));
    }

    #[test]
    fn test_min_severity_from_scan() {
        let config = PledgeShieldConfig {
            scan: ScanConfig {
                min_severity: Some("high".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(config.min_severity(), Some(Severity::High));
    }

    #[test]
    fn test_min_severity_none() {
        let config = PledgeShieldConfig::default();
        assert_eq!(config.min_severity(), None);
    }

    #[test]
    fn test_sample_toml() {
        let sample = PledgeShieldConfig::sample_toml();
        assert!(sample.contains("[scan]"));
        assert!(sample.contains("[cve]"));
        assert!(sample.contains("[exclusions]"));
        assert!(sample.contains("[thresholds]"));
        assert!(sample.contains("nvd_api_key"));
        assert!(sample.contains("github_token"));
    }
}
