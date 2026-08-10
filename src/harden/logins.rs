/// Login attempt monitor — track failed SSH/RDP/login attempts, alert on brute force.
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
use std::process::Command;

pub fn audit_login_attempts() -> Vec<Finding> {
    let mut findings = Vec::new();
    let failed = get_failed_logins();

    // Count failures per IP
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    for entry in &failed {
        *ip_counts.entry(entry.ip.clone()).or_default() += 1;
    }

    // Flag IPs with many failures (brute force)
    for (ip, count) in &ip_counts {
        if *count >= 10 {
            findings.push(
                Finding::new(
                    &format!("brute-force-{}", ip.replace('.', "_")),
                    &format!("{} failed login attempts from {}", count, ip),
                    if *count >= 50 {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    Category::HostConfig,
                )
                .description(
                    "Multiple failed login attempts from this IP — likely a brute force attack.",
                )
                .recommendation(&format!(
                    "Block this IP: sudo iptables -A INPUT -s {} -j DROP",
                    ip
                ))
                .fixable(true)
                .metadata("ip", ip)
                .metadata("attempts", &count.to_string()),
            );
        }
    }

    // Check if fail2ban is installed
    #[cfg(target_os = "linux")]
    {
        let f2b = Command::new("which")
            .arg("fail2ban-client")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !f2b {
            findings.push(Finding::new(
                "no-fail2ban",
                "fail2ban is not installed",
                Severity::Medium,
                Category::HostConfig,
            )
            .description("fail2ban automatically blocks IPs with repeated failed logins. Install it for brute force protection.")
            .recommendation("Run: sudo apt install fail2ban")
            .fixable(true));
        } else {
            // Check if it's running
            let out = Command::new("fail2ban-client").arg("status").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if !s.contains("ssh") && !s.contains("sshd") {
                    findings.push(
                        Finding::new(
                            "fail2ban-no-ssh",
                            "fail2ban is not protecting SSH",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("fail2ban is installed but SSH protection is not enabled.")
                        .recommendation("Enable: sudo fail2ban-client start sshd"),
                    );
                }
            }
        }
    }

    findings
}

#[derive(Debug, Clone)]
pub struct LoginAttempt {
    pub ip: String,
    pub user: String,
    pub timestamp: String,
}

fn get_failed_logins() -> Vec<LoginAttempt> {
    let mut attempts = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check auth log
        let log_paths = ["/var/log/auth.log", "/var/log/secure"];
        for log_path in &log_paths {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                for line in content.lines() {
                    if line.contains("Failed password") || line.contains("authentication failure") {
                        // Extract IP
                        let ip = extract_ip(line);
                        let user = extract_user(line);
                        if let Some(ip) = ip {
                            attempts.push(LoginAttempt {
                                ip,
                                user: user.unwrap_or_default(),
                                timestamp: line
                                    .split_whitespace()
                                    .take(3)
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            });
                        }
                    }
                }
            }
        }

        // Also check journalctl
        let out = Command::new("journalctl")
            .args([
                "-u",
                "ssh",
                "--no-pager",
                "-n",
                "1000",
                "-g",
                "Failed password",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("Failed password") {
                    let ip = extract_ip(line);
                    let user = extract_user(line);
                    if let Some(ip) = ip {
                        attempts.push(LoginAttempt {
                            ip,
                            user: user.unwrap_or_default(),
                            timestamp: line
                                .split_whitespace()
                                .take(3)
                                .collect::<Vec<_>>()
                                .join(" "),
                        });
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Check Windows Event Log for failed logins (Event ID 4625)
        let out = Command::new("wevtutil")
            .args([
                "qe",
                "Security",
                "/q:*[System[(EventID=4625)]]",
                "/c:100",
                "/f:text",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut current_ip = String::new();
            for line in s.lines() {
                if line.contains("Source Network Address:") {
                    current_ip = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
                if line.contains("Event ID:") && line.contains("4625") && !current_ip.is_empty() {
                    attempts.push(LoginAttempt {
                        ip: current_ip.clone(),
                        user: String::new(),
                        timestamp: String::new(),
                    });
                    current_ip.clear();
                }
            }
        }
    }

    attempts
}

fn extract_ip(line: &str) -> Option<String> {
    // Look for IP address pattern
    for word in line.split_whitespace() {
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() == 4 {
            if parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                return Some(word.trim_start_matches("from").trim().to_string());
            }
        }
    }
    None
}

fn extract_user(line: &str) -> Option<String> {
    if let Some(idx) = line.find("user ") {
        let rest = &line[idx + 5..];
        let user = rest.split_whitespace().next().unwrap_or("");
        if !user.is_empty() {
            return Some(user.to_string());
        }
    }
    None
}

/// Block an IP address (Linux only).
pub fn block_ip(ip: &str, dry_run: bool) -> Result<String, String> {
    if dry_run {
        return Ok(format!("[dry-run] Would block IP: {}", ip));
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output();
        match out {
            Ok(o) if o.status.success() => Ok(format!("Blocked IP: {} (iptables DROP)", ip)),
            Ok(o) => Err(format!("Failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => Err(format!("iptables not available: {}", e)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ip;
        Err("Only supported on Linux.".to_string())
    }
}
