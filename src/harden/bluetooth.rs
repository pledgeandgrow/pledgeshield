/// Bluetooth privacy — disable discoverability, randomize BT MAC, audit paired devices.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_bluetooth() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if Bluetooth is on
        let out = Command::new("bluetoothctl").arg("show").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Powered: yes") {
                if s.contains("Discoverable: yes") {
                    findings.push(Finding::new(
                        "bt-discoverable",
                        "Bluetooth is discoverable",
                        Severity::Medium,
                        Category::Network,
                    )
                    .description("Your device is visible to all nearby Bluetooth devices.")
                    .recommendation("Run: pledgeshield harden bluetooth --hide")
                    .fixable(true));
                }
                // Check paired devices
                let out2 = Command::new("bluetoothctl").args(["devices", "Paired"]).output();
                if let Ok(o2) = out2 {
                    let s2 = String::from_utf8_lossy(&o2.stdout);
                    let count = s2.lines().filter(|l| l.starts_with("Device")).count();
                    if count > 5 {
                        findings.push(Finding::new(
                            "bt-many-paired",
                            &format!("{} paired Bluetooth devices", count),
                            Severity::Low,
                            Category::Network,
                        )
                        .description("Many paired devices increases attack surface. Remove devices you no longer use.")
                        .recommendation("Run: pledgeshield harden bluetooth --list to see paired devices"));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("blueutil").arg("--power").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim() == "1" {
                findings.push(Finding::new(
                    "bt-on",
                    "Bluetooth is powered on",
                    Severity::Low,
                    Category::Network,
                )
                .description("Bluetooth is active. Disable if not in use.")
                .recommendation("Run: pledgeshield harden bluetooth --disable")
                .fixable(true));
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell")
            .args(["-Command", "Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK'} | Measure-Object"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Count") {
                findings.push(Finding::new(
                    "bt-active",
                    "Bluetooth devices are active",
                    Severity::Low,
                    Category::Network,
                )
                .description("Bluetooth is active on this system.")
                .fixable(true));
            }
        }
    }

    findings
}

pub fn list_paired() -> Vec<String> {
    let mut devices = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(o) = Command::new("bluetoothctl").args(["devices", "Paired"]).output() {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.starts_with("Device ") {
                    devices.push(line.trim_start_matches("Device ").to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = Command::new("blueutil").args(["--paired"]).output() {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                devices.push(line.to_string());
            }
        }
    }

    devices
}

pub fn hide_discoverable(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "bt-hide".to_string(),
            success: true,
            message: "[dry-run] Would disable Bluetooth discoverability.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("bluetoothctl").args(["discoverable", "off"]).output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "bt-hide".to_string(),
                success: true,
                message: "Bluetooth discoverability disabled.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "bt-hide".to_string(),
                success: false,
                message: "Failed to disable discoverability.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "bt-hide".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_bluetooth(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "bt-disable".to_string(),
            success: true,
            message: "[dry-run] Would power off Bluetooth.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("bluetoothctl").args(["power", "off"]).output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "bt-disable".to_string(),
                success: true,
                message: "Bluetooth powered off.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "bt-disable".to_string(),
                success: false,
                message: "Failed to power off Bluetooth.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("blueutil").args(["--power", "0"]).output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "bt-disable".to_string(),
                success: true,
                message: "Bluetooth powered off.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "bt-disable".to_string(),
                success: false,
                message: "Failed (blueutil not installed?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "bt-disable".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

pub fn remove_device(mac: &str) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("bluetoothctl").args(["remove", mac]).output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "bt-remove".to_string(),
                success: true,
                message: format!("Removed paired device: {}", mac),
                findings: vec![],
            },
            _ => HardenResult {
                action: "bt-remove".to_string(),
                success: false,
                message: format!("Failed to remove {}.", mac),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = mac;
        HardenResult {
            action: "bt-remove".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
