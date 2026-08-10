pub mod cache;
pub mod epss;
pub mod ghsa;
pub mod nvd;
pub mod osv;

use crate::models::{Category, Finding, Severity};
use std::collections::HashSet;

/// Context passed to the CVE scan subsystem.
pub struct CveContext {
    pub offline: bool,
    pub refresh: bool,
    pub nvd_api_key: Option<String>,
    pub github_token: Option<String>,
}

/// Installed software entry.
#[derive(Debug, Clone)]
pub struct InstalledSoftware {
    pub name: String,
    pub version: String,
    pub publisher: String,
}

/// Detect the OSV ecosystem for a given software package.
fn detect_ecosystem(sw: &InstalledSoftware) -> Option<String> {
    let name_lower = sw.name.to_lowercase();
    let publisher_lower = sw.publisher.to_lowercase();

    // Linux package managers
    if publisher_lower == "dpkg" || publisher_lower == "apt" {
        return Some("Debian".to_string());
    }
    if publisher_lower == "rpm"
        || publisher_lower.contains("redhat")
        || publisher_lower.contains("fedora")
    {
        return Some("AlmaLinux".to_string());
    }
    if publisher_lower == "pacman" || publisher_lower.contains("arch") {
        return Some("Arch Linux".to_string());
    }

    // macOS
    if publisher_lower == "homebrew" {
        return Some("Homebrew".to_string());
    }

    // Language ecosystems
    if name_lower.starts_with("python") || name_lower == "pip" || name_lower == "pip3" {
        return Some("PyPI".to_string());
    }
    if name_lower == "node"
        || name_lower == "node.js"
        || name_lower == "npm"
        || name_lower == "yarn"
    {
        return Some("npm".to_string());
    }
    if name_lower == "go" || name_lower.starts_with("golang") {
        return Some("Go".to_string());
    }
    if name_lower == "cargo" || name_lower == "rustc" {
        return Some("crates.io".to_string());
    }
    if name_lower == "gem" || name_lower == "ruby" || name_lower == "bundler" {
        return Some("RubyGems".to_string());
    }
    if name_lower == "composer" || name_lower == "php" {
        return Some("Packagist".to_string());
    }
    if name_lower == "mvn" || name_lower == "maven" || name_lower == "gradle" {
        return Some("Maven".to_string());
    }
    if name_lower == "nuget" {
        return Some("NuGet".to_string());
    }

    // Common package prefixes
    if name_lower.starts_with("lib") && publisher_lower == "dpkg" {
        return Some("Debian".to_string());
    }

    None
}

/// Orchestrate the full CVE scan: enumerate software, query APIs, deduplicate, rank.
pub async fn run_cve_scan(ctx: &CveContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    log::info!(
        "CVE scan started (offline={}, refresh={})",
        ctx.offline,
        ctx.refresh
    );

    if ctx.offline {
        log::info!("CVE scan skipped (offline mode)");
        return Ok(vec![]);
    }

    // 1. Enumerate installed software
    let software = enumerate_software();
    log::info!("Found {} installed packages", software.len());

    if software.is_empty() {
        return Ok(vec![]);
    }

    // 2. Initialize cache
    let cache = if ctx.refresh {
        let c = cache::CveCache::new();
        let _ = c.clear();
        c
    } else {
        cache::CveCache::new()
    };

    // 3. Initialize API clients
    let nvd_client = nvd::NvdClient::new(ctx.nvd_api_key.clone());
    let osv_client = osv::OsvClient::new();
    let epss_client = epss::EpssClient::new();
    let ghsa_client = ghsa::GhsaClient::new(ctx.github_token.clone());

    // 4. Build OSV batch query for all packages with detected ecosystems
    let osv_queries: Vec<osv::OsvQuery> = software
        .iter()
        .filter_map(|sw| {
            detect_ecosystem(sw).map(|eco| osv::OsvQuery {
                package: osv::OsvPackage {
                    name: sw.name.clone(),
                    ecosystem: eco,
                },
                version: sw.version.clone(),
            })
        })
        .collect();

    // 5. Execute OSV batch query if we have ecosystem-matched packages
    let mut osv_results: std::collections::HashMap<String, osv::OsvResponse> =
        std::collections::HashMap::new();
    if !osv_queries.is_empty() {
        log::info!("Querying OSV batch for {} packages", osv_queries.len());
        let batch = osv::OsvBatchQuery {
            queries: osv_queries.clone(),
        };
        match osv_client.query_batch(&batch).await {
            Ok(responses) => {
                for (i, resp) in responses.iter().enumerate() {
                    if let Some(q) = osv_queries.get(i) {
                        osv_results.insert(q.package.name.clone(), resp.clone());
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "OSV batch query failed: {}, falling back to individual queries",
                    e
                );
                // Fallback: query individually
                for q in &osv_queries {
                    if let Ok(resp) = osv_client.query(q).await {
                        osv_results.insert(q.package.name.clone(), resp);
                    }
                }
            }
        }
    }

    // 6. Query NVD and GHSA for each software package
    let mut seen_cves: HashSet<String> = HashSet::new();
    let mut findings = Vec::new();

    for sw in &software {
        log::debug!("Checking: {} {}", sw.name, sw.version);

        // Try CPE-based NVD query first (more precise)
        let mut nvd_resp = None;
        if let Some((vendor, product)) = nvd::NvdClient::lookup_cpe_mapping(&sw.name) {
            let cpe = nvd::NvdClient::build_cpe(vendor, product, &sw.version);
            let cpe_cache_key = format!("nvd-cpe:{}", cpe);
            if let Some(entry) = cache.get(&cpe_cache_key) {
                if let Ok(parsed) = serde_json::from_str::<nvd::NvdResponse>(&entry.data) {
                    nvd_resp = Some(parsed);
                }
            }
            if nvd_resp.is_none() {
                match nvd_client.query_cpe(&cpe).await {
                    Ok(resp) => {
                        if let Ok(json) = serde_json::to_string(&resp) {
                            let _ = cache.set(&cpe_cache_key, &json);
                        }
                        nvd_resp = Some(resp);
                    }
                    Err(e) => {
                        log::debug!("NVD CPE query failed for {}: {}", cpe, e);
                    }
                }
            }
        }

        // Fall back to keyword search if no CPE match or CPE query returned nothing
        if nvd_resp.is_none()
            || nvd_resp
                .as_ref()
                .map(|r| r.vulnerabilities.is_empty())
                .unwrap_or(true)
        {
            let cache_key = format!("nvd:{}", sw.name);
            let cached = if let Some(entry) = cache.get(&cache_key) {
                serde_json::from_str::<nvd::NvdResponse>(&entry.data).ok()
            } else {
                None
            };

            nvd_resp = match cached {
                Some(r) => Some(r),
                None => match nvd_client.query_keyword(&sw.name).await {
                    Ok(resp) => {
                        if let Ok(json) = serde_json::to_string(&resp) {
                            let _ = cache.set(&cache_key, &json);
                        }
                        Some(resp)
                    }
                    Err(e) => {
                        log::warn!("NVD keyword query failed for {}: {}", sw.name, e);
                        None
                    }
                },
            };
        }

        // Process NVD vulnerabilities
        if let Some(nvd_resp) = nvd_resp {
            for vuln in &nvd_resp.vulnerabilities {
                let cve_id = &vuln.cve.id;

                if seen_cves.contains(cve_id) {
                    continue;
                }
                seen_cves.insert(cve_id.clone());

                let description = vuln
                    .cve
                    .descriptions
                    .iter()
                    .find(|d| d.lang == "en")
                    .map(|d| d.value.clone())
                    .unwrap_or_else(|| "No description available".to_string());

                let (cvss_score, cvss_severity) = vuln
                    .cve
                    .metrics
                    .as_ref()
                    .and_then(|m| m.cvss_metric_v31.first().or(m.cvss_metric_v2.first()))
                    .map(|m| (m.cvss_data.base_score, m.cvss_data.base_severity.clone()))
                    .unwrap_or((0.0, "UNKNOWN".to_string()));

                let epss_score = match epss_client.get_score(cve_id).await {
                    Ok(resp) => resp.epss_score,
                    Err(_) => 0.0,
                };

                let epss_percentile = match epss_client.get_score(cve_id).await {
                    Ok(resp) => resp.percentile,
                    Err(_) => 0.0,
                };

                let severity = map_cvss_severity(&cvss_severity, epss_score);

                findings.push(
                    Finding::new(
                        &format!("cve-{}", cve_id.to_lowercase()),
                        &format!("{}: {} ({})", cve_id, sw.name, sw.version),
                        severity,
                        Category::Cve,
                    )
                    .description(&description)
                    .recommendation(&format!(
                        "Update {} to the latest version or apply the vendor patch.",
                        sw.name
                    ))
                    .metadata("cve_id", cve_id)
                    .metadata("software", &sw.name)
                    .metadata("installed_version", &sw.version)
                    .metadata("cvss_score", &format!("{:.1}", cvss_score))
                    .metadata("cvss_severity", &cvss_severity)
                    .metadata("epss_score", &format!("{:.4}", epss_score))
                    .metadata("epss_percentile", &format!("{:.2}", epss_percentile))
                    .metadata("source", "NVD"),
                );
            }
        }

        // Process OSV results (from batch query)
        if let Some(osv_resp) = osv_results.get(&sw.name) {
            for vuln in &osv_resp.vulns {
                if seen_cves.contains(&vuln.id) {
                    continue;
                }
                seen_cves.insert(vuln.id.clone());

                let severity = if let Some(sev) = vuln.severity.first() {
                    let score_str = &sev.score;
                    let cvss_score: f64 = score_str
                        .split('/')
                        .next()
                        .and_then(|s| s.split(':').last())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0.0);
                    map_cvss_score(cvss_score)
                } else {
                    Severity::Medium
                };

                findings.push(
                    Finding::new(
                        &format!("cve-{}", vuln.id.to_lowercase()),
                        &format!("{}: {} ({})", vuln.id, sw.name, sw.version),
                        severity,
                        Category::Cve,
                    )
                    .description(&vuln.summary)
                    .recommendation(&format!("Update {} to the latest version.", sw.name))
                    .metadata("cve_id", &vuln.id)
                    .metadata("software", &sw.name)
                    .metadata("installed_version", &sw.version)
                    .metadata("source", "OSV"),
                );
            }
        }

        // Query GHSA for packages in known ecosystems
        if let Some(eco) = detect_ecosystem(sw) {
            let ghsa_ecosystem = match eco.as_str() {
                "npm" => "npm",
                "PyPI" => "pip",
                "Go" => "go",
                "crates.io" => "rust",
                "RubyGems" => "rubygems",
                "Packagist" => "composer",
                "Maven" => "maven",
                "NuGet" => "nuget",
                _ => "",
            };

            if !ghsa_ecosystem.is_empty() {
                match ghsa_client.query(ghsa_ecosystem, &sw.name).await {
                    Ok(advisories) => {
                        for adv in &advisories {
                            let adv_id = adv.cve_id.as_ref().unwrap_or(&adv.ghsa_id);
                            if seen_cves.contains(adv_id) {
                                continue;
                            }
                            seen_cves.insert(adv_id.clone());

                            let cvss_score = adv.cvss.as_ref().map(|c| c.score).unwrap_or(0.0);
                            let severity = map_cvss_score(cvss_score);

                            findings.push(
                                Finding::new(
                                    &format!("cve-{}", adv_id.to_lowercase()),
                                    &format!("{}: {} ({})", adv_id, sw.name, sw.version),
                                    severity,
                                    Category::Cve,
                                )
                                .description(&adv.summary)
                                .recommendation(&format!(
                                    "Update {} to the latest version.",
                                    sw.name
                                ))
                                .metadata("cve_id", adv_id)
                                .metadata("ghsa_id", &adv.ghsa_id)
                                .metadata("software", &sw.name)
                                .metadata("installed_version", &sw.version)
                                .metadata("source", "GHSA"),
                            );
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "GHSA query failed for {} ({}): {}",
                            sw.name,
                            ghsa_ecosystem,
                            e
                        );
                    }
                }
            }
        }
    }

    // 7. Sort by severity (critical first)
    findings.sort_by(|a, b| {
        let order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        order(&a.severity).cmp(&order(&b.severity))
    });

    log::info!("CVE scan complete: {} findings", findings.len());
    Ok(findings)
}

/// Map CVSS severity string + EPSS score to PledgeShield severity.
fn map_cvss_severity(cvss_severity: &str, epss_score: f64) -> Severity {
    let sev_lower = cvss_severity.to_lowercase();
    let base = match sev_lower.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    };
    // Elevate if EPSS score is very high (>0.5 means >50% chance of exploitation)
    if epss_score > 0.5 && matches!(base, Severity::High | Severity::Medium) {
        return Severity::Critical;
    }
    if epss_score > 0.2 && matches!(base, Severity::Medium) {
        return Severity::High;
    }
    base
}

/// Map raw CVSS score to PledgeShield severity.
fn map_cvss_score(score: f64) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Enumerate installed software on Windows using PowerShell + registry.
#[cfg(target_os = "windows")]
fn enumerate_software() -> Vec<InstalledSoftware> {
    let mut software = Vec::new();

    // Method 1: PowerShell Get-Package
    let ps_output = std::process::Command::new("powershell")
        .args(["-Command", r#"Get-Package | Select-Object Name, Version, ProviderName | Format-Table -HideTableHeaders"#])
        .output();

    if let Ok(output) = ps_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let publisher = parts.get(2).unwrap_or(&"").to_string();
                software.push(InstalledSoftware {
                    name,
                    version,
                    publisher,
                });
            }
        }
    }

    // Method 2: Registry uninstall keys (more reliable)
    use winreg::RegKey;
    const UNINSTALL_PATHS: &[(isize, &str)] = &[
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    for (hive, path) in UNINSTALL_PATHS {
        if let Ok(key) = RegKey::predef(*hive).open_subkey(path) {
            for subkey_name in key.enum_keys().filter_map(|r| r.ok()) {
                if let Ok(subkey) = key.open_subkey(&subkey_name) {
                    let name: Option<String> = subkey.get_value("DisplayName").ok();
                    let version: Option<String> = subkey.get_value("DisplayVersion").ok();
                    let publisher: Option<String> = subkey.get_value("Publisher").ok();

                    if let (Some(n), Some(v)) = (name, version) {
                        // Avoid duplicates
                        if !software.iter().any(|s| s.name == n) {
                            software.push(InstalledSoftware {
                                name: n,
                                version: v,
                                publisher: publisher.unwrap_or_default(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Method 3: winget list
    let winget_output = std::process::Command::new("winget")
        .args(["list", "--format", "json"])
        .output();

    if let Ok(output) = winget_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(arr) = json.as_array() {
                for pkg in arr {
                    let name = pkg.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                    let version = pkg.get("Version").and_then(|v| v.as_str()).unwrap_or("");
                    let source = pkg.get("Source").and_then(|v| v.as_str()).unwrap_or("");
                    if !name.is_empty() && !version.is_empty() {
                        if !software.iter().any(|s| s.name == name) {
                            software.push(InstalledSoftware {
                                name: name.to_string(),
                                version: version.to_string(),
                                publisher: source.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Filter out Windows updates and system components
    software.retain(|s| {
        !s.name.starts_with("Security Update")
            && !s.name.starts_with("Update for")
            && !s.name.starts_with("Hotfix")
            && !s.name.is_empty()
    });

    software
}

/// Enumerate installed software on macOS.
#[cfg(target_os = "macos")]
fn enumerate_software() -> Vec<InstalledSoftware> {
    let mut software = Vec::new();

    // Homebrew
    let output = std::process::Command::new("brew")
        .args(["list", "--versions"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                software.push(InstalledSoftware {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    publisher: "Homebrew".to_string(),
                });
            }
        }
    }

    // System profiler for .app bundles
    let output = std::process::Command::new("system_profiler")
        .args(["SPApplicationsDataType", "-json"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(items) = json
                .get("SPApplicationsDataType")
                .and_then(|v| v.as_array())
            {
                for app in items {
                    let name = app.get("_name").and_then(|v| v.as_str()).unwrap_or("");
                    let version = app.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    let publisher = app
                        .get("obtained_from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !name.is_empty() {
                        software.push(InstalledSoftware {
                            name: name.to_string(),
                            version: version.to_string(),
                            publisher: publisher.to_string(),
                        });
                    }
                }
            }
        }
    }

    software
}

/// Enumerate installed software on Linux.
#[cfg(target_os = "linux")]
fn enumerate_software() -> Vec<InstalledSoftware> {
    let mut software = Vec::new();

    // dpkg (Debian/Ubuntu)
    let output = std::process::Command::new("dpkg").args(["-l"]).output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(5) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                software.push(InstalledSoftware {
                    name: parts[1].to_string(),
                    version: parts[2].to_string(),
                    publisher: "dpkg".to_string(),
                });
            }
        }
    }

    // rpm (RHEL/Fedora)
    if software.is_empty() {
        let output = std::process::Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    software.push(InstalledSoftware {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        publisher: parts.get(2).unwrap_or(&"").to_string(),
                    });
                }
            }
        }
    }

    // pacman (Arch)
    if software.is_empty() {
        let output = std::process::Command::new("pacman").args(["-Q"]).output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    software.push(InstalledSoftware {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        publisher: "pacman".to_string(),
                    });
                }
            }
        }
    }

    // Filter out libraries and system packages
    software.retain(|s| {
        !s.name.starts_with("lib")
            && !s.name.contains("-dev")
            && !s.name.contains("-doc")
            && !s.name.contains("-common")
            && !s.name.contains("-data")
    });

    software
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn enumerate_software() -> Vec<InstalledSoftware> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_cvss_severity_basic() {
        assert_eq!(map_cvss_severity("CRITICAL", 0.0), Severity::Critical);
        assert_eq!(map_cvss_severity("high", 0.0), Severity::High);
        assert_eq!(map_cvss_severity("medium", 0.0), Severity::Medium);
        assert_eq!(map_cvss_severity("low", 0.0), Severity::Low);
    }

    #[test]
    fn test_map_cvss_severity_epss_elevation() {
        // High + EPSS > 0.5 → Critical
        assert_eq!(map_cvss_severity("high", 0.6), Severity::Critical);
        // Medium + EPSS > 0.5 → Critical
        assert_eq!(map_cvss_severity("medium", 0.6), Severity::Critical);
        // Medium + EPSS > 0.2 → High
        assert_eq!(map_cvss_severity("medium", 0.3), Severity::High);
        // Low + high EPSS → still Low (no elevation for Low)
        assert_eq!(map_cvss_severity("low", 0.9), Severity::Low);
    }

    #[test]
    fn test_map_cvss_severity_unknown() {
        assert_eq!(map_cvss_severity("unknown", 0.0), Severity::Medium);
        assert_eq!(map_cvss_severity("", 0.0), Severity::Medium);
    }

    #[test]
    fn test_map_cvss_score() {
        assert_eq!(map_cvss_score(9.5), Severity::Critical);
        assert_eq!(map_cvss_score(9.0), Severity::Critical);
        assert_eq!(map_cvss_score(8.9), Severity::High);
        assert_eq!(map_cvss_score(7.0), Severity::High);
        assert_eq!(map_cvss_score(6.9), Severity::Medium);
        assert_eq!(map_cvss_score(4.0), Severity::Medium);
        assert_eq!(map_cvss_score(3.9), Severity::Low);
        assert_eq!(map_cvss_score(0.1), Severity::Low);
        assert_eq!(map_cvss_score(0.0), Severity::Info);
    }

    #[test]
    fn test_detect_ecosystem_npm() {
        let sw = InstalledSoftware {
            name: "node".to_string(),
            version: "20.0.0".to_string(),
            publisher: "manual".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("npm".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_pypi() {
        let sw = InstalledSoftware {
            name: "python3".to_string(),
            version: "3.12.0".to_string(),
            publisher: "manual".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("PyPI".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_debian() {
        let sw = InstalledSoftware {
            name: "htop".to_string(),
            version: "3.2.1".to_string(),
            publisher: "dpkg".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("Debian".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_homebrew() {
        let sw = InstalledSoftware {
            name: "wget".to_string(),
            version: "1.21.4".to_string(),
            publisher: "Homebrew".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("Homebrew".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_none() {
        let sw = InstalledSoftware {
            name: "custom-app".to_string(),
            version: "1.0".to_string(),
            publisher: "Unknown".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), None);
    }

    #[test]
    fn test_detect_ecosystem_go() {
        let sw = InstalledSoftware {
            name: "go".to_string(),
            version: "1.22.0".to_string(),
            publisher: "manual".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("Go".to_string()));
    }

    #[test]
    fn test_detect_ecosystem_crates_io() {
        let sw = InstalledSoftware {
            name: "rustc".to_string(),
            version: "1.75.0".to_string(),
            publisher: "manual".to_string(),
        };
        assert_eq!(detect_ecosystem(&sw), Some("crates.io".to_string()));
    }
}
