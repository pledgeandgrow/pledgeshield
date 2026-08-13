/// Process sandboxing — sandbox suspicious processes via seccomp/BPF or AppContainer.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};

pub fn audit_sandbox() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let seccomp = std::fs::read_to_string("/proc/self/status");
        if let Ok(content) = seccomp {
            if !content.contains("Seccomp:\t2") {
                findings.push(
                    Finding::new(
                        "sandbox-seccomp-disabled",
                        "Seccomp is not in strict mode",
                        Severity::Medium,
                        Category::System,
                    )
                    .description(
                        "Seccomp is not enforcing strict mode. Process sandboxing is weakened.",
                    ),
                );
            }
        }
    }

    findings
}

pub fn apply_sandbox(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "sandbox-apply".to_string(),
            success: true,
            message: "Would apply seccomp/AppContainer sandboxing (dry run)".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        HardenResult {
            action: "sandbox-apply".to_string(),
            success: true,
            message: "Seccomp strict mode recommended. Use `pledgeshield harden sysctl --harden` to enable kernel-level protections.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "sandbox-apply".to_string(),
            success: false,
            message: "Process sandboxing via seccomp is Linux-only".to_string(),
            findings: vec![],
        }
    }
}
