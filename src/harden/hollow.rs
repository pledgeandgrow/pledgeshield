/// Hollow process detector — detect process hollowing (name doesn't match binary).
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_hollow() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let pid = &name;

                // Get process name from /proc/[pid]/comm
                let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // Get executable path from /proc/[pid]/exe
                let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if comm.is_empty() || exe_path.is_empty() { continue; }

                // Compare comm name with exe basename
                let exe_basename = exe_path.rsplit('/').next().unwrap_or("");
                if !exe_basename.is_empty() {
                    // comm is truncated to 15 chars, so compare first 15 chars
                    let comm_truncated = &comm[..comm.len().min(15)];
                    let exe_truncated = &exe_basename[..exe_basename.len().min(15)];

                    if comm_truncated != exe_truncated {
                        // Mismatch — could be process hollowing or just a renamed binary
                        // Only flag if the exe path is unusual
                        let known_safe = ["python", "bash", "sh", "dash", "node", "ruby",
                            "perl", "java", "sleep", "watch", "timeout", "xargs",
                            "find", "grep", "awk", "sed", "sort", "head", "tail",
                            "cat", "ls", "ps", "ss", "systemd", "dbus", "cron"];

                        if !known_safe.contains(&comm.as_str()) && !known_safe.contains(&exe_basename) {
                            findings.push(Finding::new(
                                &format!("hollow-{}-{}", pid, comm),
                                &format!("Process name mismatch: comm='{}' exe='{}' (pid {})", comm, exe_basename, pid),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("The process name doesn't match its executable path. This can indicate process hollowing or a renamed binary."));
                        }
                    }
                }

                // Check if exe path is in /tmp or /dev/shm
                if exe_path.starts_with("/tmp/") || exe_path.starts_with("/dev/shm/") {
                    findings.push(Finding::new(
                        &format!("hollow-tmp-{}-{}", pid, comm),
                        &format!("Process running from temp directory: {} (pid {})", exe_path, pid),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A process is running from a temporary directory. Legitimate programs rarely run from /tmp."));
                }
            }
        }
    }

    findings
}
