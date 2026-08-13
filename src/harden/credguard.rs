/// Credential guard — enable Windows Credential Guard or configure PAM to prevent credential theft.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_credguard() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args(["-Command", "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesConfigured"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("1") && !s.contains("2") {
                findings.push(Finding::new(
                    "credguard-not-enabled",
                    "Windows Credential Guard is not enabled",
                    Severity::High,
                    Category::Credentials,
                ).description("Credential Guard is not enabled. Pass-the-hash and credential theft attacks are possible."));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/pam.d/su") {
            if !content.contains("pam_wheel.so") {
                findings.push(Finding::new(
                    "credguard-no-pam-wheel",
                    "pam_wheel not configured for su",
                    Severity::Medium,
                    Category::Credentials,
                ).description("pam_wheel.so is not configured. Any user can attempt su to escalate privileges."));
            }
        }
    }

    findings
}

pub fn enable_credguard(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "credguard-enable".to_string(),
            success: true,
            message: "Would enable Credential Guard / PAM hardening (dry run)".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args(["-Command", "Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-Default-Definitions -All -NoRestart"])
            .output();
        let _ = out;
        HardenResult {
            action: "credguard-enable".to_string(),
            success: true,
            message: "Credential Guard requires reboot and UEFI. Run: bcdedit /set vsagentlaunchtype Auto".to_string(),
            findings: vec![],
        }
    }

    #[cfg(target_os = "linux")]
    {
        HardenResult {
            action: "credguard-enable".to_string(),
            success: true,
            message: "Configure pam_wheel.so in /etc/pam.d/su to restrict su access to wheel group"
                .to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        HardenResult {
            action: "credguard-enable".to_string(),
            success: false,
            message: "Credential guard is only supported on Windows and Linux".to_string(),
            findings: vec![],
        }
    }
}
