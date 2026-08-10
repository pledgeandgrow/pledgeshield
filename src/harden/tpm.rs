/// TPM status checker — check if TPM is present, enabled, and used for encryption.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_tpm() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if TPM device exists
        let tpm0 = std::path::Path::new("/dev/tpm0");
        let tpmrm0 = std::path::Path::new("/dev/tpmrm0");

        if !tpm0.exists() && !tpmrm0.exists() {
            findings.push(Finding::new(
                "tpm-not-found",
                "No TPM device detected",
                Severity::Low,
                Category::HostConfig,
            )
            .description("No Trusted Platform Module found. TPM enables disk encryption with hardware-backed keys and measured boot."));
        } else {
            // TPM exists — check if it's being used
            let out = Command::new("systemctl")
                .args(["is-active", "tpm2-abrmd"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s != "active" {
                    findings.push(Finding::new(
                        "tpm-not-active",
                        "TPM resource manager is not running",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("TPM hardware is present but the resource manager service is not active."));
                }
            }

            // Check TPM version
            let out = Command::new("cat")
                .arg("/sys/class/tpm/tpm0/tpm_version_major")
                .output();
            if let Ok(o) = out {
                let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if ver == "1" {
                    findings.push(Finding::new(
                        "tpm-v1",
                        "TPM 1.2 (legacy version)",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("TPM 1.2 is legacy. TPM 2.0 provides better algorithms and is required for Windows 11."));
                }
            }

            // Check if disk encryption uses TPM
            let out = Command::new("cryptsetup")
                .args(["luksDump", "/dev/sda1"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if !s.contains("tpm2") && !s.contains("systemd-tpm2") {
                    findings.push(Finding::new(
                        "tpm-not-used-encryption",
                        "TPM is not bound to disk encryption",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("TPM is present but not used for disk encryption key sealing. Enable for auto-unlock with hardware security."));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell")
            .args([
                "-Command",
                "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("False") {
                if s.lines().any(|l| l.contains("False")) {
                    findings.push(Finding::new(
                        "tpm-not-ready",
                        "TPM is not present or not enabled",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("TPM is not ready. Enable in BIOS/UEFI for BitLocker hardware encryption."));
                }
            }
        }
    }

    findings
}
