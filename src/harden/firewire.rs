/// Firewire/PCMCIA DMA guard — disable FireWire and PCMCIA DMA access.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_firewire() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check for FireWire controller
        let out = Command::new("lspci").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("FireWire") || s.contains("IEEE 1394") {
                // Check if firewire modules are loaded
                let out2 = Command::new("lsmod").output();
                if let Ok(o2) = out2 {
                    let s2 = String::from_utf8_lossy(&o2.stdout);
                    let fw_modules = ["firewire_core", "firewire_ohci", "firewire_sbp2", "raw1394"];
                    for mod_name in &fw_modules {
                        if s2.contains(mod_name) {
                            findings.push(Finding::new(
                                &format!("firewire-module-{}", mod_name),
                                &format!("FireWire module loaded: {}", mod_name),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("FireWire allows direct memory access (DMA). An attacker with physical access could read/write your RAM.")
                            .recommendation("Run: pledgeshield harden firewire --block")
                            .fixable(true));
                        }
                    }
                }
            }

            // Check for PCMCIA/CardBus
            if s.contains("CardBus") || s.contains("PCMCIA") {
                let out2 = Command::new("lsmod").output();
                if let Ok(o2) = out2 {
                    let s2 = String::from_utf8_lossy(&o2.stdout);
                    if s2.contains("pcmcia") {
                        findings.push(Finding::new(
                            "firewire-pcmcia",
                            "PCMCIA/CardBus modules loaded",
                            Severity::Low,
                            Category::HostConfig,
                        )
                        .description("PCMCIA/CardBus can allow DMA access. Disable if not needed.")
                        .fixable(true));
                    }
                }
            }
        }

        // Check IOMMU status (protects against DMA attacks)
        if let Ok(content) = std::fs::read_to_string("/proc/cmdline") {
            if !content.contains("iommu=on") && !content.contains("intel_iommu=on") {
                findings.push(Finding::new(
                    "firewire-no-iommu",
                    "IOMMU not enabled — no DMA protection for FireWire",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .fixable(true));
            }
        }
    }

    findings
}

pub fn block_firewire(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "firewire-block".to_string(),
            success: true,
            message: "[dry-run] Would unload FireWire kernel modules.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let modules = ["firewire_sbp2", "firewire_ohci", "firewire_core", "raw1394"];
        let mut unloaded = 0;
        for mod_name in &modules {
            let out = Command::new("modprobe").args(["-r", mod_name]).output();
            if out.map(|o| o.status.success()).unwrap_or(false) {
                unloaded += 1;
            }
        }

        // Blacklist to prevent loading on boot
        let blacklist: String = modules.iter().map(|m| format!("blacklist {}", m)).collect::<Vec<_>>().join("\n");
        let _ = std::fs::write("/etc/modprobe.d/pledgeshield-firewire.conf", blacklist + "\n");

        HardenResult {
            action: "firewire-block".to_string(),
            success: true,
            message: format!("Unloaded {} FireWire modules and blacklisted them.", unloaded),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "firewire-block".to_string(),
            success: false,
            message: "FireWire blocking is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn restore_firewire() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file("/etc/modprobe.d/pledgeshield-firewire.conf");
        let _ = Command::new("modprobe").arg("firewire_ohci").output();
        HardenResult {
            action: "firewire-restore".to_string(),
            success: true,
            message: "FireWire modules restored.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "firewire-restore".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
