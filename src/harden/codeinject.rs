/// Code injection blocker — set ptrace_scope and disable cross-process memory access.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_code_injection() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check ptrace_scope
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            let scope = content.trim();
            if scope == "0" || scope == "1" {
                findings.push(Finding::new(
                    "codeinject-ptrace-weak",
                    &format!("ptrace_scope is {} (should be 2 or 3)", scope),
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Weak ptrace scope allows processes to read/write other processes' memory.")
                .recommendation("Run: pledgeshield harden codeinject --block")
                .fixable(true));
            }
        }

        // Check if process_vm_readv/writev are available (they always are, but we can check usage)
        // Check for unprivileged_bpf_disabled
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
            if content.trim() == "0" {
                findings.push(Finding::new(
                    "codeinject-bpf-enabled",
                    "Unprivileged BPF is enabled",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Unprivileged BPF can be used for code injection and kernel exploitation.")
                .fixable(true));
            }
        }

        // Check if dmesg is restricted (info leak that aids injection)
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/dmesg_restrict") {
            if content.trim() == "0" {
                findings.push(Finding::new(
                    "codeinject-dmesg-unrestricted",
                    "dmesg is not restricted",
                    Severity::Low,
                    Category::HostConfig,
                )
                .description("Unrestricted dmesg leaks kernel addresses that can aid code injection attacks.")
                .fixable(true));
            }
        }
    }

    findings
}

pub fn block_injection(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "codeinject-block".to_string(),
            success: true,
            message: "[dry-run] Would harden ptrace_scope, disable unprivileged BPF, restrict dmesg.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let mut fixed = 0;
        let settings = [
            ("kernel.yama.ptrace_scope", "2"),
            ("kernel.unprivileged_bpf_disabled", "1"),
            ("kernel.dmesg_restrict", "1"),
            ("kernel.perf_event_paranoid", "2"),
        ];

        for (key, val) in &settings {
            let out = Command::new("sysctl").args(["-w", &format!("{}={}", key, val)]).output();
            if out.map(|o| o.status.success()).unwrap_or(false) {
                fixed += 1;
            }
        }

        // Persist
        let conf: String = settings.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
        let _ = std::fs::write("/etc/sysctl.d/99-pledgeshield-injection.conf", conf + "\n");

        HardenResult {
            action: "codeinject-block".to_string(),
            success: true,
            message: format!("Set {} anti-injection parameters (ptrace_scope=2, BPF disabled, dmesg restricted).", fixed),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "codeinject-block".to_string(),
            success: false,
            message: "Code injection blocking is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
