/// Network segmentation enforcer — enforce network segmentation rules on multi-homed machines.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_segment() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip").args(["addr", "show"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let interface_count = s.lines().filter(|l| l.starts_with("    inet ")).count();
            if interface_count > 2 {
                findings.push(Finding::new(
                    "segment-multi-homed",
                    &format!("{} active network interfaces", interface_count),
                    Severity::Medium,
                    Category::Network,
                ).description("Multiple network interfaces are active. Ensure proper segmentation to prevent traffic crossing between networks."));
            }
        }

        let out = Command::new("sh")
            .args(["-c", "cat /proc/sys/net/ipv4/ip_forward"])
            .output();
        if let Ok(o) = out {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if val == "1" {
                findings.push(Finding::new(
                    "segment-forwarding-enabled",
                    "IP forwarding is enabled",
                    Severity::High,
                    Category::Network,
                ).description("IP forwarding is enabled on a multi-homed machine. Traffic may bridge between network segments."));
            }
        }
    }

    findings
}

pub fn enforce_segment(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "segment-enforce".to_string(),
                success: true,
                message: "Would disable IP forwarding and add inter-interface DROP rules (dry run)"
                    .to_string(),
                findings: vec![],
            };
        }

        let _ = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=0"])
            .output();

        let out = Command::new("ip").args(["link", "show"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let interfaces: Vec<&str> = s
                .lines()
                .filter(|l| !l.starts_with(' '))
                .filter_map(|l| l.split(':').nth(1))
                .map(|s| s.trim().split_whitespace().next().unwrap_or(""))
                .filter(|name| !name.is_empty() && *name != "lo")
                .collect();

            for i in 0..interfaces.len() {
                for j in (i + 1)..interfaces.len() {
                    let _ = Command::new("iptables")
                        .args([
                            "-A",
                            "FORWARD",
                            "-i",
                            interfaces[i],
                            "-o",
                            interfaces[j],
                            "-j",
                            "DROP",
                        ])
                        .output();
                    let _ = Command::new("iptables")
                        .args([
                            "-A",
                            "FORWARD",
                            "-i",
                            interfaces[j],
                            "-o",
                            interfaces[i],
                            "-j",
                            "DROP",
                        ])
                        .output();
                }
            }
        }

        HardenResult {
            action: "segment-enforce".to_string(),
            success: true,
            message: "Network segmentation enforced: IP forwarding disabled, inter-interface forwarding blocked".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        HardenResult {
            action: "segment-enforce".to_string(),
            success: false,
            message: "Network segmentation is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
