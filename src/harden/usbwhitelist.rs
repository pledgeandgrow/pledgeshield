/// USB device whitelist — only allow whitelisted USB devices by vendor/product ID.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_usbwhitelist() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args([
                "-c",
                "ls /etc/udev/rules.d/*usb* 2>/dev/null || echo 'no-usb-rules'",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("no-usb-rules") {
                findings.push(Finding::new(
                    "usbwhitelist-not-configured",
                    "No USB device whitelist configured",
                    Severity::Medium,
                    Category::System,
                ).description("No USB device whitelisting udev rules found. Any USB device can be connected."));
            }
        }
    }

    findings
}

pub fn add_device(vendor_id: &str, product_id: &str) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let rule = format!(
            "ACTION==\"add\", SUBSYSTEM==\"usb\", ATTR{{idVendor}}!=\"{}\", ATTR{{idProduct}}!=\"{}\", RUN+=\"/bin/sh -c 'echo 0 > /sys$DEVPATH/authorized'\"\n",
            vendor_id, product_id
        );

        let rules_path = "/etc/udev/rules.d/99-pledgeshield-usb.rules";
        let existing = std::fs::read_to_string(rules_path).unwrap_or_default();
        let new_content = format!("{}{}", existing, rule);

        if std::fs::write(rules_path, new_content).is_ok() {
            let _ = Command::new("udevadm")
                .args(["control", "--reload-rules"])
                .output();
            HardenResult {
                action: "usbwhitelist-add".to_string(),
                success: true,
                message: format!("USB device {}/{} added to whitelist", vendor_id, product_id),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "usbwhitelist-add".to_string(),
                success: false,
                message: "Failed to write udev rules (need root)".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (vendor_id, product_id);
        HardenResult {
            action: "usbwhitelist-add".to_string(),
            success: false,
            message: "USB whitelisting via udev is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}

pub fn clear_whitelist() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file("/etc/udev/rules.d/99-pledgeshield-usb.rules");
        let _ = Command::new("udevadm")
            .args(["control", "--reload-rules"])
            .output();
        HardenResult {
            action: "usbwhitelist-clear".to_string(),
            success: true,
            message: "USB whitelist cleared".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "usbwhitelist-clear".to_string(),
            success: false,
            message: "USB whitelisting via udev is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
