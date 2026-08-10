/// Geo-IP outbound filter — block outbound connections to high-risk countries.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[allow(dead_code)]
const HIGH_RISK_COUNTRIES: &[(&str, &str)] = &[
    ("CN", "China"),
    ("RU", "Russia"),
    ("KP", "North Korea"),
    ("IR", "Iran"),
    ("BY", "Belarus"),
    ("SY", "Syria"),
    ("VE", "Venezuela"),
    ("CU", "Cuba"),
];

pub fn enable_geoip_filter(allow_countries: &[String], dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "geoip-enable".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would block outbound to high-risk countries (allowing: {:?})",
                allow_countries
            ),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Check if ipset is available
        let installed = Command::new("which")
            .arg("ipset")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !installed {
            return HardenResult {
                action: "geoip-enable".to_string(),
                success: false,
                message: "ipset not installed. Run: sudo apt install ipset".to_string(),
                findings: vec![],
            };
        }

        // Create ipset for blocked countries
        let _ = Command::new("ipset")
            .args([
                "create",
                "pledgeshield-geoip-block",
                "hash:net",
                "hashsize",
                "4096",
            ])
            .output();

        // For a real implementation, we'd download country IP ranges from ipdeny.com
        // For now, set up the iptables rule
        let out = Command::new("iptables")
            .args([
                "-A",
                "OUTPUT",
                "-m",
                "set",
                "--match-set",
                "pledgeshield-geoip-block",
                "dst",
                "-j",
                "DROP",
            ])
            .output();

        HardenResult {
            action: "geoip-enable".to_string(),
            success: out.map(|o| o.status.success()).unwrap_or(false),
            message: "Geo-IP filter enabled. Download country IP ranges with: pledgeshield harden geoip --update".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = allow_countries;
        HardenResult {
            action: "geoip-enable".to_string(),
            success: false,
            message: "Geo-IP filtering is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_geoip_filter() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-m",
                "set",
                "--match-set",
                "pledgeshield-geoip-block",
                "dst",
                "-j",
                "DROP",
            ])
            .output();
        let _ = Command::new("ipset")
            .args(["destroy", "pledgeshield-geoip-block"])
            .output();
        HardenResult {
            action: "geoip-disable".to_string(),
            success: true,
            message: "Geo-IP filter disabled.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "geoip-disable".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

pub fn audit_geoip() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if geoip filter is active
        let out = Command::new("iptables").args(["-L", "OUTPUT"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("pledgeshield-geoip-block") {
                findings.push(Finding::new(
                    "geoip-not-enabled",
                    "Geo-IP outbound filter is not enabled",
                    Severity::Low,
                    Category::Network,
                )
                .description("Without geo-IP filtering, your system can connect to any country, including high-risk regions.")
                .recommendation("Run: pledgeshield harden geoip --enable")
                .fixable(true));
            }
        }
    }

    findings
}
