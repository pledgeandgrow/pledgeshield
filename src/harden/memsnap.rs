/// Memory forensics snapshot — capture process memory snapshots for forensic analysis.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_memsnap() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            let mut suspicious = 0;
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    let maps_path = format!("/proc/{}/maps", name);
                    if let Ok(content) = std::fs::read_to_string(&maps_path) {
                        if content.contains("rwxp") {
                            suspicious += 1;
                        }
                    }
                }
            }
            if suspicious > 5 {
                findings.push(Finding::new(
                    "memsnap-writable-exec",
                    &format!("{} processes with RWX memory regions", suspicious),
                    Severity::Medium,
                    Category::System,
                ).description("Multiple processes have writable and executable memory regions, which can indicate code injection or malware."));
            }
        }
    }

    findings
}

pub fn capture_snapshot(pid: &str) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let mem_path = format!("/proc/{}/mem", pid);
        let out_path = format!("/tmp/pledgeshield-memsnap-{}.bin", pid);

        let out = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "dd if={} of={} bs=4096 count=1024 2>/dev/null",
                    mem_path, out_path
                ),
            ])
            .output();

        if out.is_ok() {
            HardenResult {
                action: "memsnap-capture".to_string(),
                success: true,
                message: format!("Memory snapshot of PID {} saved to {}", pid, out_path),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "memsnap-capture".to_string(),
                success: false,
                message: format!("Failed to capture memory of PID {}", pid),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        HardenResult {
            action: "memsnap-capture".to_string(),
            success: false,
            message: "Memory snapshot is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
