/// Fail2ban auto-configurator — install and configure fail2ban with optimal jails.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_fail2ban() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let installed = Command::new("which")
            .arg("fail2ban-client")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !installed {
            findings.push(
                Finding::new(
                    "fail2ban-not-installed",
                    "fail2ban is not installed",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description(
                    "fail2ban automatically blocks IPs with repeated failed login attempts.",
                )
                .recommendation("Run: pledgeshield harden fail2ban --install")
                .fixable(true),
            );
            return findings;
        }

        // Check if it's running
        let out = Command::new("systemctl")
            .args(["is-active", "fail2ban"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s != "active" {
                findings.push(
                    Finding::new(
                        "fail2ban-not-running",
                        "fail2ban is not running",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .recommendation("Run: sudo systemctl enable --now fail2ban")
                    .fixable(true),
                );
            }
        }

        // Check which jails are active
        let out = Command::new("fail2ban-client").arg("status").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("sshd") && !s.contains("ssh") {
                findings.push(
                    Finding::new(
                        "fail2ban-no-ssh-jail",
                        "fail2ban SSH jail is not active",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("fail2ban is running but not protecting SSH.")
                    .recommendation("Run: pledgeshield harden fail2ban --configure")
                    .fixable(true),
                );
            }
        }
    }

    findings
}

pub fn install_fail2ban(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "fail2ban-install".to_string(),
            success: true,
            message: "[dry-run] Would install and configure fail2ban.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Install
        let out = Command::new("apt")
            .args(["install", "-y", "fail2ban"])
            .output();
        if !out.map(|o| o.status.success()).unwrap_or(false) {
            return HardenResult {
                action: "fail2ban-install".to_string(),
                success: false,
                message: "Failed to install fail2ban (need root? run with sudo).".to_string(),
                findings: vec![],
            };
        }

        // Configure
        configure_fail2ban(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "fail2ban-install".to_string(),
            success: false,
            message: "fail2ban is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn configure_fail2ban(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "fail2ban-configure".to_string(),
            success: true,
            message: "[dry-run] Would configure fail2ban with SSH jail (10 retries, 1h ban)."
                .to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let config = r#"[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = iptables-allports
bantime = 86400
findtime = 86400
maxretry = 3
"#;
        let config_path = "/etc/fail2ban/jail.local";
        match std::fs::write(config_path, config) {
            Ok(()) => {
                let _ = Command::new("systemctl")
                    .args(["enable", "--now", "fail2ban"])
                    .output();
                let _ = Command::new("fail2ban-client").arg("reload").output();
                HardenResult {
                    action: "fail2ban-configure".to_string(),
                    success: true,
                    message: "fail2ban configured: SSH jail (3 retries, 1h ban) + recidive jail (repeat offenders, 24h ban).".to_string(),
                    findings: vec![],
                }
            }
            Err(e) => HardenResult {
                action: "fail2ban-configure".to_string(),
                success: false,
                message: format!("Failed to write config (need root?): {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "fail2ban-configure".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

pub fn fail2ban_status() -> String {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("fail2ban-client").arg("status").output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).to_string();
        }
        "fail2ban not running or not installed.".to_string()
    }

    #[cfg(not(target_os = "linux"))]
    {
        "Not supported on this platform.".to_string()
    }
}
