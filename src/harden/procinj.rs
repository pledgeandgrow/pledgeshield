/// Process injection detector — scan running processes for suspicious injected libraries.
use crate::models::{Category, Finding, Severity};

pub fn audit_injections() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Read /proc/[pid]/maps for each process, look for suspicious library loads
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let pid = &name;

                // Get process name
                let comm_path = format!("/proc/{}/comm", pid);
                let proc_name = std::fs::read_to_string(&comm_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // Read maps
                let maps_path = format!("/proc/{}/maps", pid);
                if let Ok(maps) = std::fs::read_to_string(&maps_path) {
                    for line in maps.lines() {
                        // Look for .so files loaded from suspicious locations
                        if line.contains(".so") {
                            // Extract the path
                            let path = line.split_whitespace().last().unwrap_or("");
                            if path.starts_with("/tmp/")
                                || path.starts_with("/dev/shm/")
                                || path.starts_with("/var/tmp/")
                                || path.starts_with("/home/")
                            {
                                findings.push(Finding::new(
                                    &format!("procinj-{}-{}", pid, path.replace('/', "_")),
                                    &format!("Process {} (pid {}) loaded library from suspicious path: {}", proc_name, pid, path),
                                    Severity::High,
                                    Category::HostConfig,
                                )
                                .description("A shared library was loaded from a temporary or user directory. This is a common process injection technique."));
                            }
                        }

                        // Look for anonymous executable mappings (could be shellcode)
                        if line.contains("r-xp") && line.contains("[anon") {
                            // Anonymous executable mapping — potential shellcode
                            // Only flag if process is not a known JIT runtime
                            let jit_procs = [
                                "java", "node", "python", "ruby", "v8", "chromium", "chrome",
                                "firefox",
                            ];
                            if !jit_procs.iter().any(|p| proc_name.contains(p)) {
                                findings.push(Finding::new(
                                    &format!("procinj-anon-{}-{}", pid, proc_name),
                                    &format!("Process {} (pid {}) has anonymous executable memory", proc_name, pid),
                                    Severity::Medium,
                                    Category::HostConfig,
                                )
                                .description("Anonymous executable memory in a non-JIT process may indicate injected shellcode."));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
