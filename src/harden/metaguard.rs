/// Cloud metadata guard — block SSRF access to cloud metadata endpoints via local firewall.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[cfg(target_os = "linux")]
const METADATA_ENDPOINTS: &[&str] = &["169.254.169.254", "fd00:ec2::254"];

pub fn audit_metaguard() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("iptables")
            .args(["-L", "OUTPUT", "-n"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let blocking = METADATA_ENDPOINTS.iter().any(|ip| s.contains(ip));
            if !blocking {
                findings.push(Finding::new(
                    "metaguard-not-blocking",
                    "Cloud metadata endpoint not blocked",
                    Severity::High,
                    Category::Network,
                ).description("Outbound traffic to cloud metadata endpoints (169.254.169.254) is not blocked. SSRF attacks can steal credentials."));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(
            Finding::new(
                "metaguard-unsupported",
                "Cloud metadata guard is Linux-only",
                Severity::Info,
                Category::Network,
            )
            .description("Cloud metadata blocking via iptables is only supported on Linux."),
        );
    }

    findings
}

pub fn enable_metaguard(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "metaguard-enable".to_string(),
                success: true,
                message: "Would block outbound traffic to 169.254.169.254 (dry run)".to_string(),
                findings: vec![],
            };
        }

        let mut success = true;
        let mut msgs = Vec::new();

        for ip in METADATA_ENDPOINTS {
            let out = Command::new("iptables")
                .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
                .output();
            if out.is_err() {
                success = false;
                msgs.push(format!("Failed to block {}", ip));
            } else {
                msgs.push(format!("Blocked {}", ip));
            }
        }

        HardenResult {
            action: "metaguard-enable".to_string(),
            success,
            message: msgs.join(", "),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        HardenResult {
            action: "metaguard-enable".to_string(),
            success: false,
            message: "Cloud metadata guard is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_metaguard() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        for ip in METADATA_ENDPOINTS {
            let _ = Command::new("iptables")
                .args(["-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                .output();
        }
        HardenResult {
            action: "metaguard-disable".to_string(),
            success: true,
            message: "Cloud metadata endpoint blocking removed".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "metaguard-disable".to_string(),
            success: false,
            message: "Cloud metadata guard is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
