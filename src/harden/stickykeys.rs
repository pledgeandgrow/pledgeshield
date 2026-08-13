/// Sticky keys bypass detector — detect accessibility tool replacement for privilege escalation.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_stickykeys() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let targets = [
            (
                "C:\\Windows\\System32\\sethc.exe",
                "sethc.exe (Sticky Keys)",
            ),
            (
                "C:\\Windows\\System32\\utilman.exe",
                "utilman.exe (Utility Manager)",
            ),
            (
                "C:\\Windows\\System32\\osk.exe",
                "osk.exe (On-Screen Keyboard)",
            ),
            (
                "C:\\Windows\\System32\\Magnify.exe",
                "Magnify.exe (Magnifier)",
            ),
            (
                "C:\\Windows\\System32\\Narrator.exe",
                "Narrator.exe (Narrator)",
            ),
            (
                "C:\\Windows\\System32\\DisplaySwitch.exe",
                "DisplaySwitch.exe (Display Switch)",
            ),
        ];

        for (path, name) in &targets {
            if let Ok(meta) = std::fs::metadata(path) {
                let size = meta.len();
                if size < 1024 || size > 5_000_000 {
                    findings.push(Finding::new(
                        &format!("stickykeys-replaced-{}", name),
                        &format!("{} has unusual file size ({} bytes)", name, size),
                        Severity::Critical,
                        Category::HostConfig,
                    ).description(&format!("{} may have been replaced with cmd.exe or another binary for privilege escalation via accessibility tools.", name)));
                }
            }
        }

        let out = Command::new("reg")
            .args([
                "query",
                "HKCU\\Control Panel\\Accessibility\\StickyKeys",
                "/v",
                "Flags",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("510") {
                findings.push(Finding::new(
                    "stickykeys-enabled",
                    "Sticky Keys is enabled",
                    Severity::Low,
                    Category::HostConfig,
                ).description("Sticky Keys is enabled. Ensure accessibility binaries have not been replaced."));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        findings.push(
            Finding::new(
                "stickykeys-not-applicable",
                "Sticky Keys bypass is Windows-only",
                Severity::Info,
                Category::HostConfig,
            )
            .description("Sticky Keys privilege escalation is only applicable on Windows."),
        );
    }

    findings
}
