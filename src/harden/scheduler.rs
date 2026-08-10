/// Cron/systemd timer auditor — deep scan all scheduled tasks for suspicious entries.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_schedulers() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check user crontabs
        let cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];
        for dir in &cron_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        audit_cron_content(&content, &path.to_string_lossy(), &mut findings);
                    }
                }
            }
        }

        // Check /etc/crontab
        if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
            audit_cron_content(&content, "/etc/crontab", &mut findings);
        }

        // Check user crontabs
        if let Ok(entries) = std::fs::read_dir("/var/spool/cron/crontabs") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let user = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    audit_cron_content(
                        &content,
                        &format!("/var/spool/cron/crontabs/{}", user),
                        &mut findings,
                    );
                }
            }
        }

        // Check systemd timers
        let out = Command::new("systemctl")
            .args(["list-timers", "--all", "--no-pager"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                // Look for suspicious timer names
                if line.contains("update") || line.contains("backup") || line.contains("sync") {
                    // Common — skip
                } else if line.contains("http")
                    || line.contains("download")
                    || line.contains("fetch")
                {
                    findings.push(Finding::new(
                        "systemd-timer-suspicious",
                        &format!("Suspicious systemd timer: {}", line.trim()),
                        Severity::Medium,
                        Category::Persistence,
                    )
                    .description("A systemd timer with a network-related name was found. Verify this is expected."));
                }
            }
        }

        // Check systemd timer unit files for suspicious content
        let unit_dirs = ["/etc/systemd/system", "/lib/systemd/system"];
        for dir in &unit_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if name.ends_with(".timer") || name.ends_with(".service") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if content.contains("curl")
                                || content.contains("wget")
                                || content.contains("nc ")
                                || content.contains("bash -i")
                            {
                                findings.push(Finding::new(
                                    "systemd-suspicious-unit",
                                    &format!("Suspicious systemd unit: {}", name),
                                    Severity::High,
                                    Category::Persistence,
                                )
                                .description("A systemd unit file contains network or shell commands — possible persistence mechanism.")
                                .recommendation(&format!("Inspect: cat {}", path.display())));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check launchd agents
        let dirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "~/Library/LaunchAgents",
        ];
        for dir in &dirs {
            let expanded = if dir.starts_with("~") {
                dirs::home_dir()
                    .map(|h| h.join(&dir[2..]))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default()
            } else {
                dir.to_string()
            };
            if let Ok(entries) = std::fs::read_dir(&expanded) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if content.contains("curl")
                            || content.contains("wget")
                            || content.contains("nc ")
                        {
                            findings.push(Finding::new(
                                "launchd-suspicious",
                                &format!("Suspicious launchd agent: {}", path.display()),
                                Severity::High,
                                Category::Persistence,
                            )
                            .description("A launchd agent contains network commands — possible persistence."));
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Check scheduled tasks
        let out = Command::new("schtasks")
            .args(["/query", "/fo", "CSV", "/v"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let lower = line.to_lowercase();
                if lower.contains("powershell") && lower.contains("downloadstring") {
                    findings.push(Finding::new(
                        "schtask-powershell-download",
                        "Scheduled task with PowerShell download",
                        Severity::Critical,
                        Category::Persistence,
                    )
                    .description("A scheduled task runs PowerShell with a download command — likely malware."));
                }
            }
        }
    }

    findings
}

fn audit_cron_content(content: &str, source: &str, findings: &mut Vec<Finding>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Suspicious patterns
        let lower = line.to_lowercase();
        if lower.contains("curl") || lower.contains("wget") {
            if lower.contains("http")
                && (lower.contains("|") || lower.contains("bash") || lower.contains("sh"))
            {
                findings.push(Finding::new(
                    "cron-download-exec",
                    &format!("Cron entry downloads and executes: {}", source),
                    Severity::Critical,
                    Category::Persistence,
                )
                .description("A cron job downloads and executes code from the internet — likely malware persistence.")
                .recommendation(&format!("Remove this entry from {}", source)));
            }
        }
        if lower.contains("nc ") || lower.contains("ncat") || lower.contains("netcat") {
            if lower.contains("-l") || lower.contains("listen") {
                findings.push(
                    Finding::new(
                        "cron-netcat-listener",
                        &format!("Cron entry starts a netcat listener: {}", source),
                        Severity::Critical,
                        Category::Persistence,
                    )
                    .description("A cron job starts a network listener — likely a backdoor."),
                );
            }
        }
        if lower.contains("bash -i") || lower.contains("/dev/tcp") {
            findings.push(
                Finding::new(
                    "cron-reverse-shell",
                    &format!("Cron entry contains reverse shell: {}", source),
                    Severity::Critical,
                    Category::Persistence,
                )
                .description("A cron job contains a reverse shell command — this is a backdoor."),
            );
        }
    }
}
