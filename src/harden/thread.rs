/// Thread anomaly detector — flag processes with suspicious thread counts.
use crate::models::{Category, Finding, Severity};

pub fn audit_threads() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let pid = &name;

                // Count threads via /proc/[pid]/task
                let task_dir = format!("/proc/{}/task", pid);
                let thread_count = std::fs::read_dir(&task_dir)
                    .map(|d| d.count())
                    .unwrap_or(0);

                if thread_count == 0 { continue; }

                let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // Flag processes with very high thread counts
                // (some injection techniques create many threads)
                if thread_count > 100 {
                    findings.push(Finding::new(
                        &format!("thread-high-{}-{}", pid, comm),
                        &format!("Process {} (pid {}) has {} threads", comm, pid, thread_count),
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("A process with an unusually high thread count may indicate a thread-based injection or a resource exhaustion attack."));
                }

                // Flag single-threaded processes that suddenly have many threads
                let single_thread_procs = ["bash", "sh", "dash", "cat", "ls", "cp", "mv", "rm", "grep", "find"];
                if single_thread_procs.contains(&comm.as_str()) && thread_count > 5 {
                    findings.push(Finding::new(
                        &format!("thread-anomaly-{}-{}", pid, comm),
                        &format!("{} (pid {}) has {} threads (normally 1)", comm, pid, thread_count),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A normally single-threaded process has multiple threads. This strongly suggests code injection."));
                }
            }
        }
    }

    findings
}
