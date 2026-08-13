/// Real-time FIM — real-time file integrity monitoring via inotify/FSEvents/ReadDirectoryChangesW.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[cfg(target_os = "linux")]
const WATCH_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
];

pub fn audit_rtfim() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "pgrep -f inotifywait 2>/dev/null"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.is_empty() {
                findings.push(Finding::new(
                    "rtfim-not-running",
                    "No real-time file integrity monitor running",
                    Severity::Medium,
                    Category::System,
                ).description("No inotify-based file integrity monitor is running. Critical system files are not being watched in real-time."));
            }
        }
    }

    findings
}

pub fn start_rtfim() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let watch_list = WATCH_PATHS.join(",");
        let out = Command::new("sh")
            .args(["-c", &format!("nohup inotifywait -m -e modify,attrib,create,delete {} > /tmp/pledgeshield-fim.log 2>&1 &", watch_list)])
            .output();

        if out.is_ok() {
            HardenResult {
                action: "rtfim-start".to_string(),
                success: true,
                message: format!(
                    "Real-time FIM started on {} paths. Log: /tmp/pledgeshield-fim.log",
                    WATCH_PATHS.len()
                ),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "rtfim-start".to_string(),
                success: false,
                message:
                    "Failed to start FIM. Install inotify-tools: sudo apt install inotify-tools"
                        .to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "rtfim-start".to_string(),
            success: false,
            message: "Real-time FIM via inotify is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
