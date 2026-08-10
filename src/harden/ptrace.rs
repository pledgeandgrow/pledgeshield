/// Debugger/ptrace detector — alert if any process is being debugged or ptraced.
use crate::models::{Category, Finding, Severity};

pub fn audit_ptrace() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check ptrace_scope setting
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            let scope = content.trim();
            if scope == "0" {
                findings.push(Finding::new(
                    "ptrace-scope-0",
                    "ptrace_scope is 0 (any process can ptrace any other)",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("ptrace_scope=0 allows any process to inspect/modify any other process's memory. Set to 2 for better security.")
                .recommendation("Run: pledgeshield harden sysctl --harden")
                .fixable(true));
            }
        }

        // Check if any process is currently being ptraced
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let pid = &name;

                // Read status file to check TracerPid
                if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                    let comm = status
                        .lines()
                        .find(|l| l.starts_with("Name:"))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();

                    let tracer_pid = status
                        .lines()
                        .find(|l| l.starts_with("TracerPid:"))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or("0".to_string());

                    if tracer_pid != "0" {
                        // Get tracer name
                        let tracer_name =
                            std::fs::read_to_string(format!("/proc/{}/comm", tracer_pid))
                                .map(|s| s.trim().to_string())
                                .unwrap_or("unknown".to_string());

                        // Known debuggers
                        let _debuggers = [
                            "gdb", "lldb", "strace", "ltrace", "frida", "x64dbg", "radare2", "r2",
                            "ida",
                        ];
                        let tracers = [
                            "gdb", "lldb", "strace", "ltrace", "frida", "radare2", "r2", "ida",
                            "py-spy", "perf",
                        ];

                        let severity = if tracers.contains(&tracer_name.as_str()) {
                            Severity::Low
                        } else {
                            Severity::Medium
                        };

                        findings.push(Finding::new(
                            &format!("ptrace-{}-{}", pid, comm),
                            &format!("Process {} (pid {}) is being traced by {} (pid {})", comm, pid, tracer_name, tracer_pid),
                            severity,
                            Category::HostConfig,
                        )
                        .description("A process is being traced/debugged. If you didn't start a debugger, this could be malware analyzing your processes."));
                    }
                }
            }
        }
    }

    findings
}
