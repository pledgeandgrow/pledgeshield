/// WSL security audit — audit Windows Subsystem for Linux configurations.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_wsl() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("wsl").args(["-l", "-v"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Running") {
                findings.push(Finding::new(
                    "wsl-running",
                    "WSL distribution is running",
                    Severity::Low,
                    Category::HostConfig,
                ).description("A WSL distribution is running. Ensure it is properly configured and not exposing network services."));

                if s.contains("Version: 1") {
                    findings.push(Finding::new(
                        "wsl-v1",
                        "WSL version 1 detected",
                        Severity::Medium,
                        Category::HostConfig,
                    ).description("WSL v1 lacks a true Linux kernel and has weaker isolation. Upgrade to WSL v2."));
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("C:\\Users\\Default\\.wslconfig") {
            if !content.contains("localhostForwarding") {
                findings.push(
                    Finding::new(
                        "wsl-localhost-forwarding",
                        "WSL localhost forwarding not configured",
                        Severity::Low,
                        Category::Network,
                    )
                    .description("WSL localhost forwarding setting is not explicitly configured."),
                );
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        findings.push(
            Finding::new(
                "wsl-not-applicable",
                "WSL audit is Windows-only",
                Severity::Info,
                Category::HostConfig,
            )
            .description("WSL security audit is only applicable on Windows."),
        );
    }

    findings
}
