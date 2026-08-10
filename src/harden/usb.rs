/// USB device guard — whitelist USB devices, block unauthorized USB (BadUSB protection).
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_usb() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // List connected USB devices
        let out = Command::new("lsusb").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let count = s.lines().count();
            if count > 5 {
                findings.push(Finding::new(
                    "usb-many-devices",
                    &format!("{} USB devices connected", count),
                    Severity::Low,
                    Category::HostConfig,
                )
                .description("Many USB devices are connected. Each is a potential attack vector (BadUSB, data exfiltration).")
                .recommendation("Run: pledgeshield harden usb --list to review devices"));
            }
        }

        // Check if USBGuard is installed
        let guard = Command::new("which")
            .arg("usbguard")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !guard {
            findings.push(Finding::new(
                "usb-no-guard",
                "No USB device authorization tool installed",
                Severity::Medium,
                Category::HostConfig,
            )
            .description("Without USBGuard, any USB device can be plugged in and used immediately (BadUSB risk).")
            .recommendation("Install usbguard: sudo apt install usbguard  |  then: pledgeshield harden usb --lockdown")
            .fixable(true));
        }
    }

    findings
}

pub fn list_usb() -> Vec<String> {
    let mut devices = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = Command::new("lsusb").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                devices.push(line.to_string());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = Command::new("system_profiler")
            .args(["SPUSBDataType"])
            .output()
        {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let l = line.trim();
                if l.contains("Vendor ID:")
                    || l.contains("Product ID:")
                    || (l.contains(":") && !l.starts_with(" "))
                {
                    devices.push(l.to_string());
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(o) = Command::new("powershell")
            .args(["-Command", "Get-PnpDevice -Class USB | Where-Object {$_.Status -eq 'OK'} | Select-Object FriendlyName"])
            .output()
        {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let l = line.trim();
                if !l.is_empty() {
                    devices.push(l.to_string());
                }
            }
        }
    }

    devices
}

/// Lock down USB — only allow currently connected devices, block all new ones.
pub fn lockdown_usb(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "usb-lockdown".to_string(),
            success: true,
            message: "[dry-run] Would install USBGuard with current devices whitelisted."
                .to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Check if usbguard is installed
        let installed = Command::new("which")
            .arg("usbguard")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !installed {
            return HardenResult {
                action: "usb-lockdown".to_string(),
                success: false,
                message: "usbguard not installed. Run: sudo apt install usbguard".to_string(),
                findings: vec![],
            };
        }

        // Generate policy from current devices
        let out = Command::new("usbguard").args(["generate-policy"]).output();
        if let Ok(o) = out {
            let policy = String::from_utf8_lossy(&o.stdout);
            let _ = std::fs::write("/etc/usbguard/rules.conf", policy.as_ref());
            let _ = Command::new("systemctl")
                .args(["enable", "--now", "usbguard"])
                .output();
            return HardenResult {
                action: "usb-lockdown".to_string(),
                success: true,
                message: "USBGuard enabled. Only currently connected devices are allowed."
                    .to_string(),
                findings: vec![],
            };
        }
        HardenResult {
            action: "usb-lockdown".to_string(),
            success: false,
            message: "Failed to generate USBGuard policy.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "usb-lockdown".to_string(),
            success: false,
            message: "USB lockdown is only supported on Linux (via usbguard).".to_string(),
            findings: vec![],
        }
    }
}

/// Remove USB lockdown.
pub fn restore_usb() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "usbguard"])
            .output();
        HardenResult {
            action: "usb-restore".to_string(),
            success: true,
            message: "USBGuard disabled. All USB devices allowed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "usb-restore".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
