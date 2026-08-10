/// AppArmor/SELinux enforcer — check if MAC is enabled and enforcing.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_mac() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check SELinux
        let selinux_enforce = "/sys/fs/selinux/enforce";
        let selinux_enabled = "/sys/fs/selinux";

        if Path::new(selinux_enabled).exists() {
            if let Ok(content) = std::fs::read_to_string(selinux_enforce) {
                if content.trim() == "0" {
                    findings.push(Finding::new(
                        "mac-selinux-permissive",
                        "SELinux is in permissive mode (not enforcing)",
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("SELinux is running in permissive mode — it logs violations but doesn't block them.")
                    .recommendation("Run: sudo setenforce 1  (and edit /etc/selinux/config for persistence)")
                    .fixable(true));
                }
            }
        } else {
            // No SELinux — check AppArmor
            let aa_status = Command::new("apparmor_status").output();
            if let Ok(o) = aa_status {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("apparmor module is loaded") {
                    // AppArmor is loaded — check profiles
                    if s.contains("0 profiles are loaded")
                        || s.contains("0 profiles in enforce mode")
                    {
                        findings.push(Finding::new(
                            "mac-apparmor-no-profiles",
                            "AppArmor is loaded but has no enforcing profiles",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("AppArmor is running but not enforcing any profiles. Enable profiles for better security.")
                        .recommendation("Run: sudo aa-enforce /etc/apparmor.d/*")
                        .fixable(true));
                    }

                    // Check for complain mode profiles
                    if s.contains("profiles in complain mode") {
                        let count = s
                            .lines()
                            .find(|l| l.contains("profiles in complain mode"))
                            .and_then(|l| l.split_whitespace().next())
                            .and_then(|n| n.parse::<usize>().ok())
                            .unwrap_or(0);
                        if count > 0 {
                            findings.push(Finding::new(
                                "mac-apparmor-complain",
                                &format!("{} AppArmor profiles in complain mode", count),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("Profiles in complain mode log violations but don't block them. Switch to enforce mode.")
                            .fixable(true));
                        }
                    }
                } else {
                    findings.push(Finding::new(
                        "mac-none",
                        "No Mandatory Access Control (SELinux or AppArmor) is active",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("Without MAC, a compromised process has full access to the system. Enable AppArmor or SELinux.")
                    .recommendation("Run: sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor")
                    .fixable(true));
                }
            } else {
                // Neither SELinux nor AppArmor
                findings.push(Finding::new(
                    "mac-none",
                    "No Mandatory Access Control system detected",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Neither SELinux nor AppArmor is active. MAC provides important defense-in-depth.")
                .fixable(true));
            }
        }
    }

    findings
}

use std::path::Path;
