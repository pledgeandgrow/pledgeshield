/// Log tampering detector — monitor system logs for truncation, deletion, timestamp gaps.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_log_tampering() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if auth log exists and has content
        let log_paths = [
            ("/var/log/auth.log", "auth"),
            ("/var/log/syslog", "syslog"),
            ("/var/log/messages", "messages"),
            ("/var/log/secure", "secure"),
        ];

        for (path, name) in &log_paths {
            let p = std::path::Path::new(path);
            if !p.exists() {
                continue;
            }

            if let Ok(meta) = std::fs::metadata(p) {
                // Check for zero-size log (truncated)
                if meta.len() == 0 {
                    findings.push(Finding::new(
                        &format!("log-empty-{}", name),
                        &format!("Log file is empty: {}", path),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A system log file is empty — it may have been truncated by an attacker to hide their tracks."));
                }

                // Check modification time
                if let Ok(time) = meta.modified() {
                    if let Ok(elapsed) = time.elapsed() {
                        // If log hasn't been modified in 24h but system is running
                        if elapsed.as_secs() > 86400 {
                            findings.push(Finding::new(
                                &format!("log-stale-{}", name),
                                &format!("Log not modified in {} days: {}", elapsed.as_secs() / 86400, path),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("A system log hasn't been written to in over a day. Logging may be broken or logs are being redirected."));
                        }
                    }
                }
            }
        }

        // Check for gaps in auth log timestamps
        if let Ok(content) = std::fs::read_to_string("/var/log/auth.log") {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() > 10 {
                // Look for large time gaps between consecutive entries
                let mut prev_time: Option<chrono::NaiveDateTime> = None;
                for line in lines.iter().rev().take(100) {
                    // Parse timestamp (format: "Jan  1 12:00:00")
                    let parts: Vec<&str> = line.split_whitespace().take(3).collect();
                    if parts.len() >= 3 {
                        let time_str = format!("2024 {} {}", parts[0], parts[1]);
                        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(&format!("{} 0 00:00:00", parts[0]), "%b %d %H:%M:%S") {
                            if let Some(prev) = prev_time {
                                let gap = prev.signed_duration_since(t).num_hours();
                                if gap > 24 {
                                    findings.push(Finding::new(
                                        "log-time-gap",
                                        &format!("{} hour gap in auth log", gap),
                                        Severity::Medium,
                                        Category::HostConfig,
                                    )
                                    .description("There's a large time gap in the auth log. Entries may have been deleted."));
                                    break;
                                }
                            }
                            prev_time = Some(t);
                        }
                    }
                }
            }
        }

        // Check if journald is persistent
        let journal_dir = "/var/log/journal";
        if !std::path::Path::new(journal_dir).exists() {
            findings.push(Finding::new(
                "log-journal-volatile",
                "journald logs are not persistent",
                Severity::Low,
                Category::HostConfig,
            )
            .description("Journal logs are stored in /run (volatile) and lost on reboot. Enable persistence: sudo mkdir /var/log/journal && sudo systemctl restart systemd-journald"));
        }

        // Check for rotated logs (normal) vs deleted logs (suspicious)
        let out = Command::new("ls").args(["-la", "/var/log/"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("auth.log") && !s.contains("auth.log.1") {
                // No rotated auth log — either fresh install or logs were deleted
                if let Ok(content) = std::fs::read_to_string("/var/log/auth.log") {
                    if content.lines().count() > 1000 {
                        findings.push(Finding::new(
                            "log-no-rotation",
                            "Auth log has no rotated copies",
                            Severity::Low,
                            Category::HostConfig,
                        )
                        .description("The auth log is large but has no rotated copies. Either logrotate is misconfigured or old logs were deleted."));
                    }
                }
            }
        }
    }

    findings
}
