/// Mount option hardener — enforce secure mount options.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const SECURE_MOUNTS: &[(&str, &[&str])] = &[
    // (mount point, required options)
    ("/tmp", &["nosuid", "nodev", "noexec"]),
    ("/var/tmp", &["nosuid", "nodev", "noexec"]),
    ("/dev/shm", &["nosuid", "nodev", "noexec"]),
    ("/home", &["nosuid", "nodev"]),
    ("/var", &["nosuid"]),
    ("/boot", &["nosuid", "nodev", "noexec", "ro"]),
];

pub fn audit_mounts() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
            for (mount_point, required_opts) in SECURE_MOUNTS {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 4 {
                        continue;
                    }
                    if parts[1] == *mount_point {
                        let opts = parts[3];
                        for req in *required_opts {
                            if !opts.contains(req) {
                                findings.push(
                                    Finding::new(
                                        &format!("mount-{}-{}", mount_point.replace('/', "_"), req),
                                        &format!("{} is missing {} option", mount_point, req),
                                        Severity::Medium,
                                        Category::HostConfig,
                                    )
                                    .description(&format!(
                                        "Mount point {} should have the {} option for security.",
                                        mount_point, req
                                    ))
                                    .recommendation(&format!(
                                        "Add {} to {} in /etc/fstab",
                                        req, mount_point
                                    ))
                                    .fixable(true),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

pub fn harden_mounts(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Remount with secure options (for /tmp, /dev/shm, /var/tmp)
        let remounts = [
            ("/tmp", "nosuid,nodev,noexec"),
            ("/dev/shm", "nosuid,nodev,noexec"),
            ("/var/tmp", "nosuid,nodev,noexec"),
        ];

        for (mount, opts) in &remounts {
            if dry_run {
                results.push(HardenResult {
                    action: format!("mount-{}", mount),
                    success: true,
                    message: format!("[dry-run] Would remount {} with {}", mount, opts),
                    findings: vec![],
                });
                continue;
            }
            let out = Command::new("mount")
                .args(["-o", &format!("remount,{}", opts), mount])
                .output();
            let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
            results.push(HardenResult {
                action: format!("mount-{}", mount),
                success: ok,
                message: if ok {
                    format!("Remounted {} with {}", mount, opts)
                } else {
                    format!("Failed to remount {} (need root?)", mount)
                },
                findings: vec![],
            });
        }

        if !dry_run {
            results.push(HardenResult {
                action: "mount-fstab".to_string(),
                success: true,
                message: "Note: Add these options to /etc/fstab for persistence across reboots."
                    .to_string(),
                findings: vec![],
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        results.push(HardenResult {
            action: "mount".to_string(),
            success: false,
            message: "Mount hardening is only supported on Linux.".to_string(),
            findings: vec![],
        });
    }

    results
}
