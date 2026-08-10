/// Kernel module lockdown — restrict which kernel modules can be loaded (Linux), block unsigned drivers (Windows).
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_kernel_modules() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if module signing is enforced
        let out = std::fs::read_to_string("/proc/sys/kernel/modules_disabled");
        if let Ok(s) = out {
            if s.trim() == "0" {
                findings.push(Finding::new(
                    "kernel-modules-not-locked",
                    "Kernel module loading is not locked down",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Any root process can load kernel modules, which can hook the kernel and hide processes.")
                .recommendation("Run: pledgeshield harden kernel --lockdown  (after all needed modules are loaded)")
                .fixable(true));
            }
        }

        // Check for suspicious loaded modules
        if let Ok(o) = Command::new("lsmod").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            let suspicious = ["rootkit", "hide", "stealth", "backdoor"];
            for line in s.lines().skip(1) {
                let name = line.split_whitespace().next().unwrap_or("");
                for sus in &suspicious {
                    if name.to_lowercase().contains(sus) {
                        findings.push(Finding::new(
                            "kernel-suspicious-module",
                            &format!("Suspicious kernel module loaded: {}", name),
                            Severity::Critical,
                            Category::HostConfig,
                        )
                        .description("A kernel module with a suspicious name is loaded. This could be a rootkit.")
                        .recommendation(&format!("Investigate: modinfo {} && rmmod {}", name, name)));
                    }
                }
            }
        }

        // Check dmesg for module load failures (could indicate attack attempts)
        if let Ok(o) = Command::new("dmesg").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            let failures = s
                .lines()
                .filter(|l| {
                    l.contains("module verification failed") || l.contains("module signature")
                })
                .count();
            if failures > 0 {
                findings.push(Finding::new(
                    "kernel-module-sign-fail",
                    &format!("{} module signature failures in dmesg", failures),
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Some kernel modules failed signature verification. This could indicate tampering."));
            }
        }
    }

    #[cfg(windows)]
    {
        // Check if driver signature enforcement is on
        let out = Command::new("bcdedit")
            .args(["/enum", "{current}"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("testsigning") && s.contains("Yes") {
                findings.push(
                    Finding::new(
                        "kernel-testsigning",
                        "Windows test signing is enabled",
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description(
                        "Test signing allows unsigned drivers to load. This is a security risk.",
                    )
                    .recommendation("Run: bcdedit /set testsigning off  (reboot required)")
                    .fixable(true),
                );
            }
        }
    }

    findings
}

/// Lock down kernel module loading (Linux only).
/// Once locked, no new kernel modules can be loaded — even by root.
pub fn lockdown_kernel(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "kernel-lockdown".to_string(),
            success: true,
            message: "[dry-run] Would lock kernel module loading (irreversible until reboot)."
                .to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Set /proc/sys/kernel/modules_disabled = 1
        // This is irreversible until reboot!
        let out = Command::new("sysctl")
            .args(["-w", "kernel.modules_disabled=1"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "kernel-lockdown".to_string(),
                success: true,
                message: "Kernel module loading locked. No new modules can be loaded until reboot."
                    .to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "kernel-lockdown".to_string(),
                success: false,
                message: format!(
                    "Failed (need root?): {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "kernel-lockdown".to_string(),
                success: false,
                message: format!("sysctl not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "kernel-lockdown".to_string(),
            success: false,
            message: "Kernel module lockdown is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

/// List currently loaded kernel modules (Linux).
pub fn list_modules() -> Vec<String> {
    let mut modules = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = Command::new("lsmod").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                modules.push(line.to_string());
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(o) = Command::new("driverquery").args(["/v"]).output() {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().take(50) {
                modules.push(line.to_string());
            }
        }
    }

    modules
}
