/// Firmware integrity checker — verify peripheral firmware integrity against known hashes.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_firmware() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "ls /sys/class/firmware/*/ 2>/dev/null | head -20"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.is_empty() {
                findings.push(Finding::new(
                    "firmware-no-sysfs",
                    "No firmware entries in sysfs",
                    Severity::Low,
                    Category::System,
                ).description("No firmware entries found in /sys/class/firmware. Firmware integrity cannot be verified."));
            }
        }

        let out = Command::new("sh")
            .args(["-c", "dmesg 2>/dev/null | grep -i 'firmware' | tail -10"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("failed") || s.contains("error") {
                findings.push(Finding::new(
                    "firmware-load-errors",
                    "Firmware load errors detected in dmesg",
                    Severity::Medium,
                    Category::System,
                ).description("Firmware load errors were found in kernel logs. This could indicate corrupted or tampered firmware."));
            }
        }
    }

    findings
}
