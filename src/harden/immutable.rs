/// Immutable file setter — set chattr +i on critical system files.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const CRITICAL_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/boot/grub/grub.cfg",
];

pub fn audit_immutable() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for file in CRITICAL_FILES {
            if !std::path::Path::new(file).exists() {
                continue;
            }
            let out = Command::new("lsattr").arg(file).output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                // lsattr output: ----i--------e-- /etc/passwd
                if !s.contains("i") {
                    findings.push(Finding::new(
                        &format!("immutable-not-set-{}", file.replace('/', "_")),
                        &format!("{} is not immutable", file),
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("Critical system files should have the immutable attribute (chattr +i) to prevent modification even by root.")
                    .recommendation(&format!("Run: sudo chattr +i {}", file))
                    .fixable(true));
                }
            }
        }
    }

    findings
}

pub fn set_immutable(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for file in CRITICAL_FILES {
            if !std::path::Path::new(file).exists() {
                continue;
            }
            if dry_run {
                results.push(HardenResult {
                    action: format!("immutable-{}", file),
                    success: true,
                    message: format!("[dry-run] Would set immutable on {}", file),
                    findings: vec![],
                });
                continue;
            }
            let out = Command::new("chattr").args(["+i", file]).output();
            let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
            results.push(HardenResult {
                action: format!("immutable-{}", file),
                success: ok,
                message: if ok {
                    format!("Set immutable: {}", file)
                } else {
                    format!("Failed to set immutable on {} (need root?)", file)
                },
                findings: vec![],
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        results.push(HardenResult {
            action: "immutable".to_string(),
            success: false,
            message: "Immutable attribute is only supported on Linux.".to_string(),
            findings: vec![],
        });
    }

    results
}

pub fn unset_immutable() -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for file in CRITICAL_FILES {
            if !std::path::Path::new(file).exists() {
                continue;
            }
            let out = Command::new("chattr").args(["-i", file]).output();
            results.push(HardenResult {
                action: format!("immutable-unset-{}", file),
                success: out.map(|o| o.status.success()).unwrap_or(false),
                message: format!("Removed immutable: {}", file),
                findings: vec![],
            });
        }
    }

    results
}
