/// Boot log analyzer — parse dmesg/journalctl/Event Viewer for boot-time anomalies.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_bootlog() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Get recent boot log via journalctl
        let out = Command::new("journalctl")
            .args(["-b", "--no-pager", "-p", "err"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("module verification failed") || line.contains("module signature")
                {
                    findings.push(Finding::new(
                        "bootlog-module-sig",
                        "Kernel module signature failure at boot",
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A kernel module failed signature verification at boot — possible tampering."));
                }
                if line.contains("tainted") {
                    findings.push(
                        Finding::new(
                            "bootlog-tainted",
                            "Kernel is tainted",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("The kernel is tainted — non-GPL modules or firmware issues."),
                    );
                }
                if line.contains("IOMMU") && line.contains("disabled") {
                    findings.push(Finding::new(
                        "bootlog-iommu-off",
                        "IOMMU is disabled",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("IOMMU provides DMA protection. Without it, malicious PCIe/Thunderbolt devices can access all RAM."));
                }
                if line.contains("rootkit") || line.contains("backdoor") {
                    findings.push(
                        Finding::new(
                            "bootlog-rootkit",
                            "Rootkit indicator in boot log",
                            Severity::Critical,
                            Category::HostConfig,
                        )
                        .description("Boot log contains rootkit-related messages!"),
                    );
                }
            }
        }

        // Check dmesg for warnings
        let out = Command::new("dmesg")
            .args(["--level=err,crit,emerg"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let error_count = s.lines().count();
            if error_count > 20 {
                findings.push(
                    Finding::new(
                        "bootlog-many-errors",
                        &format!("{} critical/error messages in dmesg", error_count),
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description(
                        "Many boot errors may indicate hardware failure, driver issues, or attack.",
                    ),
                );
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell")
            .args(["-Command", "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} | Measure-Object"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Count") {
                let count_str = s
                    .lines()
                    .find(|l| l.contains("Count"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if count_str > 10 {
                    findings.push(Finding::new(
                        "bootlog-many-errors",
                        &format!("{} critical system events in last 24h", count_str),
                        Severity::Medium,
                        Category::HostConfig,
                    ));
                }
            }
        }
    }

    findings
}
