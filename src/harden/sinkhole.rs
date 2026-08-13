/// DNS sinkhole — block known malicious domains at the local DNS level.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[cfg(target_os = "linux")]
const MALICIOUS_DOMAINS: &[&str] = &[
    "malware.example.com",
    "c2-server.example.com",
    "phishing-example.com",
];

pub fn audit_sinkhole() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/dnsmasq.d/sinkhole.conf") {
            let blocked_count = content
                .lines()
                .filter(|l| l.starts_with("address=/"))
                .count();
            if blocked_count == 0 {
                findings.push(Finding::new(
                    "sinkhole-not-configured",
                    "DNS sinkhole is not configured",
                    Severity::Medium,
                    Category::Network,
                ).description("No DNS sinkhole is active. Malicious domains are not being blocked at the DNS level."));
            }
        } else {
            findings.push(
                Finding::new(
                    "sinkhole-not-installed",
                    "dnsmasq sinkhole not found",
                    Severity::Low,
                    Category::Network,
                )
                .description(
                    "Install dnsmasq and configure a sinkhole to block malicious domains locally.",
                ),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(
            Finding::new(
                "sinkhole-unsupported",
                "DNS sinkhole is Linux-only",
                Severity::Info,
                Category::Network,
            )
            .description("DNS sinkhole via dnsmasq is only supported on Linux."),
        );
    }

    findings
}

pub fn enable_sinkhole(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "sinkhole-enable".to_string(),
                success: true,
                message: format!(
                    "Would configure dnsmasq sinkhole for {} domains (dry run)",
                    MALICIOUS_DOMAINS.len()
                ),
                findings: vec![],
            };
        }

        let conf_dir = "/etc/dnsmasq.d";
        if std::fs::create_dir_all(conf_dir).is_err() {
            return HardenResult {
                action: "sinkhole-enable".to_string(),
                success: false,
                message: "Failed to create dnsmasq config directory".to_string(),
                findings: vec![],
            };
        }

        let mut conf = String::new();
        conf.push_str("# PledgeShield DNS sinkhole\n");
        conf.push_str("no-resolv\n");
        conf.push_str("server=1.1.1.1\n");
        conf.push_str("server=8.8.8.8\n");
        for domain in MALICIOUS_DOMAINS {
            conf.push_str(&format!("address=/{}/0.0.0.0\n", domain));
        }

        let conf_path = format!("{}/sinkhole.conf", conf_dir);
        if std::fs::write(&conf_path, conf).is_err() {
            return HardenResult {
                action: "sinkhole-enable".to_string(),
                success: false,
                message: "Failed to write sinkhole config".to_string(),
                findings: vec![],
            };
        }

        let _ = Command::new("systemctl")
            .args(["restart", "dnsmasq"])
            .output();

        HardenResult {
            action: "sinkhole-enable".to_string(),
            success: true,
            message: format!(
                "DNS sinkhole configured with {} blocked domains",
                MALICIOUS_DOMAINS.len()
            ),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "sinkhole-enable".to_string(),
            success: false,
            message: "DNS sinkhole is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_sinkhole() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let conf_path = "/etc/dnsmasq.d/sinkhole.conf";
        let _ = std::fs::remove_file(conf_path);
        let _ = Command::new("systemctl")
            .args(["restart", "dnsmasq"])
            .output();
        HardenResult {
            action: "sinkhole-disable".to_string(),
            success: true,
            message: "DNS sinkhole disabled".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "sinkhole-disable".to_string(),
            success: false,
            message: "DNS sinkhole is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
