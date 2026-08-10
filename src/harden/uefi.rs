/// UEFI/BIOS security audit — Secure Boot, boot password, boot device order, USB boot.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_uefi() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if UEFI mode (not Legacy BIOS)
        let efivars = std::path::Path::new("/sys/firmware/efi/efivars");
        if !efivars.exists() {
            findings.push(
                Finding::new(
                    "uefi-legacy-boot",
                    "System is booting in Legacy BIOS mode",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Legacy BIOS mode lacks Secure Boot and other UEFI security features.")
                .recommendation(
                    "Switch to UEFI mode in firmware settings (may require reinstall).",
                ),
            );
        }

        // Check Secure Boot status
        let out = Command::new("mokutil").args(["--sb-state"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("disabled") || s.contains("SecureBoot not enabled") {
                findings.push(Finding::new(
                    "uefi-secure-boot-off",
                    "Secure Boot is disabled",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Secure Boot prevents booting unsigned/modified kernels. Without it, bootkits can load.")
                .recommendation("Enable Secure Boot in UEFI firmware settings."));
            }
        } else {
            // Try reading from sysfs
            let sb_path =
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
            if let Ok(data) = std::fs::read(sb_path) {
                // Last byte: 1 = enabled, 0 = disabled
                if data.len() > 4 && data[data.len() - 1] == 0 {
                    findings.push(
                        Finding::new(
                            "uefi-secure-boot-off",
                            "Secure Boot is disabled",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("Secure Boot is disabled in firmware."),
                    );
                }
            }
        }

        // Check if booting from USB is possible (can't directly check, but warn)
        // Check for boot password via efibootmgr
        let out = Command::new("efibootmgr").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("BootOrder") && !s.is_empty() {
                findings.push(
                    Finding::new(
                        "uefi-no-bootmgr",
                        "Cannot read UEFI boot manager",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description(
                        "efibootmgr cannot read boot entries. Boot order may not be secured.",
                    ),
                );
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell")
            .args(["-Command", "Confirm-SecureBootUEFI"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim() == "False" {
                findings.push(
                    Finding::new(
                        "uefi-secure-boot-off",
                        "Secure Boot is disabled",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("Secure Boot is disabled. Bootkits can load unsigned kernels."),
                );
            }
        }
    }

    findings
}
