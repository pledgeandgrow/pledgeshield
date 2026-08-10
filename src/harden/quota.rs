/// Quota enforcer — set disk quotas to prevent single user/process from filling disk.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_quotas() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if quota is installed
        let installed = Command::new("which").arg("quotaon").output()
            .map(|o| o.status.success()).unwrap_or(false);

        if !installed {
            findings.push(Finding::new(
                "quota-not-installed",
                "Disk quota tools not installed",
                Severity::Low,
                Category::HostConfig,
            )
            .description("Disk quotas prevent a single user or process (like ransomware) from filling the disk.")
            .recommendation("Run: sudo apt install quota")
            .fixable(true));
            return findings;
        }

        // Check if quotas are enabled
        let out = Command::new("quotaon").args(["-p"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim().is_empty() {
                findings.push(Finding::new(
                    "quota-not-enabled",
                    "Disk quotas are not enabled",
                    Severity::Low,
                    Category::HostConfig,
                )
                .description("No disk quotas are active. Ransomware could fill your disk quickly.")
                .recommendation("Run: pledgeshield harden quota --enable")
                .fixable(true));
            }
        }

        // Check if quota is set for current user
        let out = Command::new("quota").args(["-s"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("none") || s.trim().is_empty() {
                findings.push(Finding::new(
                    "quota-none-set",
                    "No quota set for current user",
                    Severity::Low,
                    Category::HostConfig,
                )
                .fixable(true));
            }
        }
    }

    findings
}

pub fn enable_quotas(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "quota-enable".to_string(),
            success: true,
            message: "[dry-run] Would enable disk quotas with 80% soft limit.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Check if quota is installed
        let installed = Command::new("which").arg("quotaon").output()
            .map(|o| o.status.success()).unwrap_or(false);

        if !installed {
            let _ = Command::new("apt").args(["install", "-y", "quota"]).output();
        }

        // Enable quotas on root filesystem
        let out = Command::new("quotaon").args(["-vug", "/"]).output();
        let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        HardenResult {
            action: "quota-enable".to_string(),
            success: ok,
            message: if ok {
                "Quotas enabled. Use 'edquota -u <user>' to set limits.".to_string()
            } else {
                "Failed to enable quotas (need root? add usrquota,grpquota to /etc/fstab)".to_string()
            },
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "quota-enable".to_string(),
            success: false,
            message: "Disk quotas are only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
