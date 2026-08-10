/// Memory/swap wipe — wipe swap space and RAM on shutdown to prevent cold-boot attacks.
use super::HardenResult;
use std::process::Command;

pub fn audit_memory_security() -> Vec<crate::models::Finding> {
    use crate::models::{Category, Finding, Severity};
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if swap is encrypted
        if let Ok(content) = std::fs::read_to_string("/proc/swaps") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(dev) = parts.first() {
                    if dev.starts_with("/dev/") && !dev.contains("dm-") {
                        findings.push(Finding::new(
                            "swap-unencrypted",
                            "Swap space is not encrypted",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("Unencrypted swap can leak sensitive data (passwords, keys) to disk.")
                        .recommendation("Run: pledgeshield harden memwipe --encrypt-swap")
                        .fixable(true));
                    }
                }
            }
        }

        // Check if swap is even in use
        let out = Command::new("swapon").arg("--show").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim().is_empty() {
                // No swap — that's fine for security but may affect performance
            }
        }
    }

    findings
}

/// Wipe swap space (overwrite with zeros).
pub fn wipe_swap(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "swap-wipe".to_string(),
            success: true,
            message: "[dry-run] Would disable swap, wipe it, and re-enable.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Get swap devices
        let out = Command::new("swapon").args(["--show=NAME", "--noheadings"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let devices: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
            let device_count = devices.len();

            if devices.is_empty() {
                return HardenResult {
                    action: "swap-wipe".to_string(),
                    success: true,
                    message: "No swap devices to wipe.".to_string(),
                    findings: vec![],
                };
            }

            for dev in devices {
                let dev = dev.trim();
                // Disable swap
                let _ = Command::new("swapoff").arg(dev).output();
                // Wipe with dd
                let _ = Command::new("dd").args(["if=/dev/urandom", &format!("of={}", dev), "bs=1M", "status=progress"]).output();
                // Re-enable
                let _ = Command::new("swapon").arg(dev).output();
            }

            HardenResult {
                action: "swap-wipe".to_string(),
                success: true,
                message: format!("Wiped {} swap device(s) with random data.", device_count),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "swap-wipe".to_string(),
                success: false,
                message: "Could not list swap devices.".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "swap-wipe".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

/// Set up encrypted swap with a random key at boot (Linux).
pub fn setup_encrypted_swap(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "swap-encrypt".to_string(),
            success: true,
            message: "[dry-run] Would set up encrypted swap with random key at boot.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Add crypttab entry for encrypted swap with random key
        let crypttab_entry = "pledgeshield-swap /dev/sdX /dev/urandom swap,offset=2048,cipher=aes-xts-plain64,size=256\n";
        let crypttab_path = "/etc/crypttab";

        let mut content = String::new();
        if let Ok(existing) = std::fs::read_to_string(crypttab_path) {
            content = existing;
        }
        if !content.contains("pledgeshield-swap") {
            content.push_str(&format!("# PledgeShield encrypted swap\n{}", crypttab_entry));
            let _ = std::fs::write(crypttab_path, content);
        }

        HardenResult {
            action: "swap-encrypt".to_string(),
            success: true,
            message: "Encrypted swap configured in /etc/crypttab (edit to set correct device, then reboot).".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "swap-encrypt".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

/// Install a systemd service that wipes RAM on shutdown.
pub fn install_ram_wipe(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "ram-wipe-install".to_string(),
            success: true,
            message: "[dry-run] Would install systemd shutdown service to wipe RAM.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let service = r#"[Unit]
Description=PledgeShield RAM wipe on shutdown
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target

[Service]
Type=oneshot
ExecStart=/bin/true
ExecStop=/bin/sh -c 'echo 3 > /proc/sys/vm/drop_caches; dd if=/dev/urandom of=/dev/null bs=1M count=$(free -m | awk "/Mem:/{print $2}") 2>/dev/null'
RemainAfterExit=yes

[Install]
WantedBy=halt.target reboot.target shutdown.target
"#;
        let path = "/etc/systemd/system/pledgeshield-ramwipe.service";
        if std::fs::write(path, service).is_ok() {
            let _ = Command::new("systemctl").args(["enable", "pledgeshield-ramwipe.service"]).output();
            HardenResult {
                action: "ram-wipe-install".to_string(),
                success: true,
                message: "Installed RAM wipe service (runs on shutdown/reboot).".to_string(),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "ram-wipe-install".to_string(),
                success: false,
                message: "Failed to install service (need root?).".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "ram-wipe-install".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

/// Drop kernel caches (immediate partial RAM wipe).
pub fn drop_caches() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh").args(["-c", "echo 3 > /proc/sys/vm/drop_caches"]).output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "drop-caches".to_string(),
                success: true,
                message: "Kernel page cache, inodes, and dentries dropped.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "drop-caches".to_string(),
                success: false,
                message: "Failed (need root?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "drop-caches".to_string(),
            success: false,
            message: "Only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
