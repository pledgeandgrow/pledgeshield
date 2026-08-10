/// SSH config hardener — disable root login, password auth, enforce key-only.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

const SECURE_SETTINGS: &[(&str, &str, &str)] = &[
    ("PermitRootLogin", "no", "Disable root login via SSH"),
    (
        "PasswordAuthentication",
        "no",
        "Disable password authentication (key-only)",
    ),
    ("PermitEmptyPasswords", "no", "Reject empty passwords"),
    ("X11Forwarding", "no", "Disable X11 forwarding"),
    ("AllowTcpForwarding", "no", "Disable TCP forwarding"),
    ("AllowAgentForwarding", "no", "Disable agent forwarding"),
    ("MaxAuthTries", "3", "Limit authentication attempts"),
    ("LoginGraceTime", "30", "Short login grace period"),
    ("ClientAliveInterval", "300", "Client alive check interval"),
    ("ClientAliveCountMax", "2", "Max missed alive checks"),
    ("Protocol", "2", "Use SSH protocol 2 only"),
    ("AllowUsers", "", "Restrict to specific users (empty = all)"),
];

pub fn audit_ssh() -> Vec<Finding> {
    let mut findings = Vec::new();

    if !std::path::Path::new(SSHD_CONFIG).exists() {
        return findings; // SSH server not installed
    }

    let content = match std::fs::read_to_string(SSHD_CONFIG) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    for (key, secure_val, desc) in SECURE_SETTINGS {
        // Find the setting in the config
        let current = get_sshd_value(&content, key);
        match current {
            Some(val) => {
                if val != *secure_val && !secure_val.is_empty() {
                    findings.push(
                        Finding::new(
                            &format!("ssh-{}", key.to_lowercase()),
                            &format!("{} = {} (should be {})", key, val, secure_val),
                            Severity::High,
                            Category::HostConfig,
                        )
                        .description(*desc)
                        .recommendation(&format!(
                            "Run: pledgeshield harden ssh --harden  (or edit {})",
                            SSHD_CONFIG
                        ))
                        .fixable(true),
                    );
                }
            }
            None => {
                // Setting not present — use default
                if key == &"PermitRootLogin" {
                    findings.push(
                        Finding::new(
                            "ssh-permitrootlogin-default",
                            "PermitRootLogin not explicitly set (may default to yes)",
                            Severity::High,
                            Category::HostConfig,
                        )
                        .description("Root login via SSH is not explicitly disabled.")
                        .recommendation("Run: pledgeshield harden ssh --harden")
                        .fixable(true),
                    );
                }
                if key == &"PasswordAuthentication" {
                    // Default is usually yes
                    findings.push(
                        Finding::new(
                            "ssh-passwordauth-default",
                            "PasswordAuthentication not explicitly disabled",
                            Severity::High,
                            Category::HostConfig,
                        )
                        .description("Password authentication may be enabled by default.")
                        .recommendation("Run: pledgeshield harden ssh --harden")
                        .fixable(true),
                    );
                }
            }
        }
    }

    // Check if SSH is even running
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("systemctl")
            .args(["is-active", "sshd"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "inactive" || s == "disabled" {
                // SSH not running — no findings needed
                return findings;
            }
        }
    }

    findings
}

fn get_sshd_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.to_lowercase().starts_with(&key.to_lowercase()) {
            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            if parts.len() >= 2 {
                return Some(parts[1].trim().to_string());
            }
        }
    }
    None
}

pub fn harden_ssh(dry_run: bool) -> HardenResult {
    if !std::path::Path::new(SSHD_CONFIG).exists() {
        return HardenResult {
            action: "ssh-harden".to_string(),
            success: false,
            message: "SSH server config not found. Is openssh-server installed?".to_string(),
            findings: vec![],
        };
    }

    let content = std::fs::read_to_string(SSHD_CONFIG).unwrap_or_default();

    if dry_run {
        return HardenResult {
            action: "ssh-harden".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would harden {} with {} secure settings",
                SSHD_CONFIG,
                SECURE_SETTINGS.len()
            ),
            findings: vec![],
        };
    }

    // Backup
    let backup = format!("{}.pledgeshield-backup", SSHD_CONFIG);
    let _ = std::fs::copy(SSHD_CONFIG, &backup);

    // Apply settings
    let mut new_content = content.clone();
    for (key, secure_val, _) in SECURE_SETTINGS {
        if secure_val.is_empty() {
            continue;
        }

        let _pattern = format!("{} {}", key, secure_val);
        // Remove existing setting (commented or not)
        new_content = new_content
            .lines()
            .filter(|l| {
                let ll = l.trim().to_lowercase();
                !ll.starts_with(&key.to_lowercase()) || ll.starts_with('#')
            })
            .map(String::from)
            .collect::<Vec<_>>()
            .join("\n");

        // Add our setting
        new_content.push_str(&format!("\n{} {}", key, secure_val));
    }

    // Add marker
    if !new_content.contains("# PledgeShield SSH hardening") {
        new_content.push_str("\n# PledgeShield SSH hardening\n");
    }

    match std::fs::write(SSHD_CONFIG, &new_content) {
        Ok(()) => {
            // Restart SSH
            #[cfg(target_os = "linux")]
            {
                let _ = Command::new("systemctl").args(["restart", "sshd"]).output();
                let _ = Command::new("systemctl").args(["restart", "ssh"]).output();
            }
            HardenResult {
                action: "ssh-harden".to_string(),
                success: true,
                message: format!(
                    "SSH hardened (backup at {}). Restart sshd to apply.",
                    backup
                ),
                findings: vec![],
            }
        }
        Err(e) => HardenResult {
            action: "ssh-harden".to_string(),
            success: false,
            message: format!("Failed to write config (need root?): {}", e),
            findings: vec![],
        },
    }
}

pub fn restore_ssh() -> HardenResult {
    let backup = format!("{}.pledgeshield-backup", SSHD_CONFIG);
    if std::path::Path::new(&backup).exists() {
        let _ = std::fs::copy(&backup, SSHD_CONFIG);
        HardenResult {
            action: "ssh-restore".to_string(),
            success: true,
            message: "SSH config restored from backup.".to_string(),
            findings: vec![],
        }
    } else {
        HardenResult {
            action: "ssh-restore".to_string(),
            success: false,
            message: "No backup found.".to_string(),
            findings: vec![],
        }
    }
}
