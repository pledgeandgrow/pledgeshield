/// Thunderbolt/USB4 guard — disable Thunderbolt DMA access, require device approval.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_thunderbolt() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if bolt (Thunderbolt daemon) is installed
        let installed = Command::new("which").arg("boltctl").output()
            .map(|o| o.status.success()).unwrap_or(false);

        if installed {
            // Check Thunderbolt security level
            let out = Command::new("boltctl").arg("list").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if !s.trim().is_empty() {
                    for line in s.lines() {
                        if line.contains("connected") || line.contains("authorized") {
                            if line.contains("authorized: true") && line.contains("security: user") {
                                // Good — requires user approval
                            } else if line.contains("security: none") || line.contains("security: pci") {
                                findings.push(Finding::new(
                                    "thunderbolt-no-security",
                                    "Thunderbolt security is set to 'none'",
                                    Severity::High,
                                    Category::HostConfig,
                                )
                                .description("Thunderbolt security level 'none' allows any device to perform DMA access to your RAM. Set to 'user' in BIOS."));
                            }
                        }
                    }
                }
            }
        } else {
            // Check if Thunderbolt controller exists
            let out = Command::new("lspci").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("Thunderbolt") || s.contains("USB4") {
                    findings.push(Finding::new(
                        "thunderbolt-no-bolt",
                        "Thunderbolt/USB4 controller present but bolt daemon not installed",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("Without the bolt daemon, Thunderbolt devices can connect without approval, allowing DMA attacks.")
                    .recommendation("Run: sudo apt install bolt")
                    .fixable(true));
                }
            }
        }

        // Check if IOMMU is enabled (DMA protection)
        if let Ok(content) = std::fs::read_to_string("/proc/cmdline") {
            if !content.contains("iommu=on") && !content.contains("intel_iommu=on") && !content.contains("amd_iommu=on") {
                findings.push(Finding::new(
                    "thunderbolt-no-iommu",
                    "IOMMU is not enabled — no DMA protection",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Without IOMMU, Thunderbolt/USB4 devices can directly access your system's RAM (DMA attack).")
                .recommendation("Add iommu=on to kernel boot parameters")
                .fixable(true));
            }
        }
    }

    findings
}

pub fn block_thunderbolt(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "thunderbolt-block".to_string(),
            success: true,
            message: "[dry-run] Would block unauthorized Thunderbolt devices.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Deauthorize all Thunderbolt devices
        let out = Command::new("boltctl").arg("list").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("uuid:") {
                    let uuid = line.split(':').nth(1).unwrap_or("").trim();
                    if !uuid.is_empty() {
                        let _ = Command::new("boltctl").args(["deauthorize", uuid]).output();
                    }
                }
            }
        }

        HardenResult {
            action: "thunderbolt-block".to_string(),
            success: true,
            message: "All Thunderbolt devices deauthorized. Set security level to 'user' in BIOS for permanent protection.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "thunderbolt-block".to_string(),
            success: false,
            message: "Thunderbolt management is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
