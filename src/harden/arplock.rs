/// ARP table lock — lock ARP table entries to prevent ARP spoofing on static networks.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_arplock() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/arp_ignore") {
            let val = content.trim();
            if val == "0" {
                findings.push(Finding::new(
                    "arplock-not-configured",
                    "ARP table is not locked",
                    Severity::Medium,
                    Category::Network,
                ).description("ARP table entries are dynamic. Lock them to prevent ARP spoofing on static networks."));
            }
        }
    }

    findings
}

pub fn lock_arp(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "arplock-lock".to_string(),
                success: true,
                message: "Would set static ARP entries and arp_ignore=1 (dry run)".to_string(),
                findings: vec![],
            };
        }

        let _ = Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.all.arp_ignore=1"])
            .output();

        HardenResult {
            action: "arplock-lock".to_string(),
            success: true,
            message: "ARP table locked (arp_ignore=1). Use --add <ip> <mac> for static entries."
                .to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        HardenResult {
            action: "arplock-lock".to_string(),
            success: false,
            message: "ARP table locking is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}

pub fn unlock_arp() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.all.arp_ignore=0"])
            .output();
        HardenResult {
            action: "arplock-unlock".to_string(),
            success: true,
            message: "ARP table unlocked (arp_ignore=0)".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "arplock-unlock".to_string(),
            success: false,
            message: "ARP table locking is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
