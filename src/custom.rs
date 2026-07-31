use crate::models::{Category, Finding, Severity};

/// A user-defined custom audit check loaded from a config file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomCheck {
    /// Unique identifier for this check
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Description of what the check does
    pub description: String,
    /// Severity if the check fails
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Category for the finding
    #[serde(default = "default_category")]
    pub category: String,
    /// Recommendation if the check fails
    #[serde(default)]
    pub recommendation: String,
    /// Check type: command, file_exists, file_not_exists, registry
    #[serde(default = "default_check_type")]
    pub check_type: String,
    /// Command to run (exit 0 = pass, non-zero = fail) — for command type
    #[serde(default)]
    pub command: Option<String>,
    /// File path to check — for file_exists/file_not_exists types
    #[serde(default)]
    pub path: Option<String>,
    /// Registry path (Windows) — for registry type
    #[serde(default)]
    pub registry_key: Option<String>,
    /// Registry value name — for registry type
    #[serde(default)]
    pub registry_value: Option<String>,
    /// Expected registry value — for registry type
    #[serde(default)]
    pub registry_expected: Option<String>,
}

fn default_severity() -> String { "medium".to_string() }
fn default_category() -> String { "config".to_string() }
fn default_check_type() -> String { "command".to_string() }

/// Configuration for custom audit checks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomAuditConfig {
    /// List of custom checks
    pub checks: Vec<CustomCheck>,
}

/// Run all custom audit checks and return findings.
pub fn run_custom_checks(config: &CustomAuditConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    for check in &config.checks {
        if run_check(check) {
            // Check failed (condition met = finding)
            let severity = Severity::from_str(&check.severity).unwrap_or(Severity::Medium);
            let category = parse_category(&check.category);

            let mut finding = Finding::new(
                &check.id,
                &check.title,
                severity,
                category,
            )
            .description(&check.description);

            if !check.recommendation.is_empty() {
                finding = finding.recommendation(&check.recommendation);
            }

            findings.push(finding);
        }
    }

    findings
}

/// Run a single check. Returns true if the check "fails" (finding should be reported).
fn run_check(check: &CustomCheck) -> bool {
    match check.check_type.as_str() {
        "command" => {
            if let Some(cmd) = &check.command {
                #[cfg(windows)]
                {
                    let output = std::process::Command::new("cmd")
                        .args(["/C", cmd])
                        .output();
                    match output {
                        Ok(o) => !o.status.success(),
                        Err(_) => false,
                    }
                }
                #[cfg(not(windows))]
                {
                    let output = std::process::Command::new("sh")
                        .args(["-c", cmd])
                        .output();
                    match output {
                        Ok(o) => !o.status.success(),
                        Err(_) => false,
                    }
                }
            } else {
                false
            }
        }
        "file_exists" => {
            if let Some(path) = &check.path {
                std::path::Path::new(path).exists()
            } else {
                false
            }
        }
        "file_not_exists" => {
            if let Some(path) = &check.path {
                !std::path::Path::new(path).exists()
            } else {
                false
            }
        }
        "registry" => {
            #[cfg(windows)]
            {
                if let (Some(key), Some(value)) = (&check.registry_key, &check.registry_value) {
                    check_registry_value(key, value, check.registry_expected.as_deref())
                } else {
                    false
                }
            }
            #[cfg(not(windows))]
            {
                false
            }
        }
        _ => false,
    }
}

#[cfg(windows)]
fn check_registry_value(key: &str, value: &str, expected: Option<&str>) -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    // Parse HKLM\...\key format
    let (root, subpath) = if key.starts_with("HKLM\\") {
        (HKEY_LOCAL_MACHINE, &key[5..])
    } else if key.starts_with("HKCU\\") {
        (HKEY_CURRENT_USER, &key[5..])
    } else if key.starts_with("HKCR\\") {
        (HKEY_CLASSES_ROOT, &key[5..])
    } else {
        return false;
    };

    let hk = RegKey::predef(root);
    if let Ok(subkey) = hk.open_subkey(subpath) {
        match subkey.get_value::<String, _>(value) {
            Ok(val) => {
                if let Some(exp) = expected {
                    val != exp
                } else {
                    false
                }
            }
            Err(_) => true, // Value doesn't exist = check fails
        }
    } else {
        true // Key doesn't exist = check fails
    }
}

fn parse_category(s: &str) -> Category {
    match s.to_lowercase().as_str() {
        "config" => Category::Config,
        "services" => Category::Services,
        "cve" => Category::Cve,
        "privileges" => Category::Privileges,
        "persistence" => Category::Persistence,
        "credentials" => Category::Credentials,
        "shares" => Category::Shares,
        "patches" => Category::Patches,
        _ => Category::Config,
    }
}

/// Load custom checks from a TOML file.
pub fn load_custom_checks(path: &std::path::Path) -> Result<CustomAuditConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: CustomAuditConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Load custom checks from a YAML file.
pub fn load_custom_checks_yaml(path: &std::path::Path) -> Result<CustomAuditConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: CustomAuditConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_category() {
        assert_eq!(parse_category("config"), Category::Config);
        assert_eq!(parse_category("Services"), Category::Services);
        assert_eq!(parse_category("CVE"), Category::Cve);
        assert_eq!(parse_category("unknown"), Category::Config);
    }

    #[test]
    fn test_run_check_file_not_exists() {
        let check = CustomCheck {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test check".to_string(),
            severity: "high".to_string(),
            category: "config".to_string(),
            recommendation: String::new(),
            check_type: "file_not_exists".to_string(),
            command: None,
            path: Some("/nonexistent/path/12345".to_string()),
            registry_key: None,
            registry_value: None,
            registry_expected: None,
        };

        // File doesn't exist → check fails (returns true)
        assert!(run_check(&check));
    }

    #[test]
    fn test_run_check_file_exists() {
        let check = CustomCheck {
            id: "test-2".to_string(),
            title: "Test".to_string(),
            description: "Test check".to_string(),
            severity: "high".to_string(),
            category: "config".to_string(),
            recommendation: String::new(),
            check_type: "file_exists".to_string(),
            command: None,
            path: Some("/nonexistent/path/12345".to_string()),
            registry_key: None,
            registry_value: None,
            registry_expected: None,
        };

        // File doesn't exist → check passes (returns false)
        assert!(!run_check(&check));
    }

    #[test]
    fn test_load_custom_checks_toml() {
        let toml_content = r#"
[[checks]]
id = "custom-test"
title = "Custom Test Check"
description = "A test check"
severity = "high"
category = "config"
check_type = "file_not_exists"
path = "/nonexistent/path"
recommendation = "Create the file"
"#;
        let path = std::env::temp_dir().join("pledgeshield_custom_checks.toml");
        std::fs::write(&path, toml_content).unwrap();

        let config = load_custom_checks(&path).unwrap();
        assert_eq!(config.checks.len(), 1);
        assert_eq!(config.checks[0].id, "custom-test");
        assert_eq!(config.checks[0].severity, "high");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_custom_checks() {
        let config = CustomAuditConfig {
            checks: vec![CustomCheck {
                id: "test-check".to_string(),
                title: "Test Check".to_string(),
                description: "Test".to_string(),
                severity: "high".to_string(),
                category: "config".to_string(),
                recommendation: "Fix it".to_string(),
                check_type: "file_not_exists".to_string(),
                command: None,
                path: Some("/nonexistent/path/12345".to_string()),
                registry_key: None,
                registry_value: None,
                registry_expected: None,
            }],
        };

        let findings = run_custom_checks(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "test-check");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].recommendation, "Fix it");
    }

    #[test]
    fn test_default_severity() {
        assert_eq!(default_severity(), "medium");
    }

    #[test]
    fn test_default_category() {
        assert_eq!(default_category(), "config");
    }
}
