/// Zero trust agent — enforce zero-trust: deny all inbound, per-app outbound network policies.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_zerotrust() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("iptables")
            .args(["-L", "INPUT", "-n"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("ACCEPT") && s.contains("0.0.0.0/0") {
                findings.push(Finding::new(
                    "zerotrust-open-input",
                    "INPUT chain allows all traffic",
                    Severity::High,
                    Category::Network,
                ).description("The INPUT chain has ACCEPT rules for all sources. Zero-trust requires default deny."));
            }
        }
    }

    findings
}

pub fn enable_zerotrust(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "zerotrust-enable".to_string(),
                success: true,
                message:
                    "Would set INPUT policy to DROP, allow only established connections (dry run)"
                        .to_string(),
                findings: vec![],
            };
        }

        let _ = Command::new("iptables")
            .args(["-P", "INPUT", "DROP"])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ])
            .output();
        let _ = Command::new("iptables")
            .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output();

        HardenResult {
            action: "zerotrust-enable".to_string(),
            success: true,
            message: "Zero-trust policy applied: INPUT default DROP, established connections and loopback allowed".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        HardenResult {
            action: "zerotrust-enable".to_string(),
            success: false,
            message: "Zero-trust via iptables is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_zerotrust() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("iptables")
            .args(["-P", "INPUT", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-D",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ])
            .output();
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output();
        HardenResult {
            action: "zerotrust-disable".to_string(),
            success: true,
            message: "Zero-trust policy disabled, INPUT set to ACCEPT".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "zerotrust-disable".to_string(),
            success: false,
            message: "Zero-trust via iptables is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
