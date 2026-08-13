/// Disk encryption enabler — detect unencrypted disks, offer to enable BitLocker/LUKS/FileVault.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_encryption() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check for LUKS-encrypted partitions
        let out = Command::new("lsblk")
            .args(["-o", "NAME,FSTYPE,TYPE,MOUNTPOINT", "-J"])
            .output();
        let mut encrypted_count = 0;
        let mut total_count = 0;

        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                if let Some(blockdevices) = v.get("blockdevices").and_then(|v| v.as_array()) {
                    for dev in blockdevices {
                        check_block_device(dev, &mut encrypted_count, &mut total_count);
                    }
                }
            }
        }

        // Check /proc/mounts for encrypted filesystems
        if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let dev = parts[0];
                    let fstype = parts[2];
                    if dev.starts_with("/dev/") && fstype != "swap" {
                        // Check if it's on an encrypted device
                        let is_crypto = dev.contains("dm-crypt") || dev.contains("LUKS");
                        if !is_crypto {
                            // Check if the underlying device is encrypted
                            let out = Command::new("lsblk")
                                .args(["-o", "TYPE", "-n", dev])
                                .output();
                            let is_luks = out
                                .map(|o| String::from_utf8_lossy(&o.stdout).contains("crypt"))
                                .unwrap_or(false);
                            if !is_luks && !dev.contains("dm-") {
                                findings.push(Finding::new(
                                    &format!("disk-unencrypted-{}", dev.replace('/', "_")),
                                    &format!("Unencrypted disk: {}", dev),
                                    Severity::High,
                                    Category::HostConfig,
                                )
                                .description("This disk/partition is not encrypted. If stolen, data can be read without your password.")
                                .recommendation(&format!("Encrypt with LUKS: sudo cryptsetup luksFormat {}", dev))
                                .fixable(true));
                            }
                        }
                    }
                }
            }
        }

        // Check if swap is encrypted
        if let Ok(content) = std::fs::read_to_string("/proc/swaps") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(dev) = parts.first() {
                    if !dev.contains("dm-") && dev.starts_with("/dev/") {
                        findings.push(
                            Finding::new(
                                "swap-unencrypted",
                                "Swap space is not encrypted",
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("Unencrypted swap can leak sensitive data to disk.")
                            .recommendation(
                                "Encrypt swap with cryptsetup or use random key at boot.",
                            )
                            .fixable(true),
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("fdesetup").arg("status").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Off") || s.contains("off") {
                findings.push(Finding::new(
                    "filevault-off",
                    "FileVault is disabled",
                    Severity::High,
                    Category::HostConfig,
                )
                .description("FileVault disk encryption is not enabled. Your data is accessible if the disk is removed.")
                .recommendation("Run: sudo fdesetup enable")
                .fixable(true));
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell")
            .args([
                "-Command",
                "Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Off") {
                findings.push(Finding::new(
                    "bitlocker-off",
                    "BitLocker is not protecting one or more drives",
                    Severity::High,
                    Category::HostConfig,
                )
                .description("BitLocker is disabled for at least one drive. Data is accessible without authentication.")
                .recommendation("Run: pledgeshield harden encryption --enable")
                .fixable(true));
            }
        }
    }

    findings
}

#[cfg(target_os = "linux")]
fn check_block_device(dev: &serde_json::Value, encrypted: &mut usize, total: &mut usize) {
    if let Some(fstype) = dev.get("fstype").and_then(|v| v.as_str()) {
        if fstype == "crypto_LUKS" {
            *encrypted += 1;
        }
    }
    if let Some(children) = dev.get("children").and_then(|v| v.as_array()) {
        for child in children {
            check_block_device(child, encrypted, total);
        }
    }
}

/// Enable disk encryption (guided).
pub fn enable_encryption(dry_run: bool) -> Vec<String> {
    let mut results = Vec::new();

    if dry_run {
        results.push("[dry-run] Would guide through disk encryption setup.".to_string());
        return results;
    }

    #[cfg(target_os = "linux")]
    {
        results.push("To encrypt your disk with LUKS:".to_string());
        results.push("  1. Backup your data!".to_string());
        results.push("  2. Create LUKS partition: sudo cryptsetup luksFormat /dev/sdX".to_string());
        results.push("  3. Open it: sudo cryptsetup luksOpen /dev/sdX encrypted".to_string());
        results.push("  4. Format: sudo mkfs.ext4 /dev/mapper/encrypted".to_string());
        results.push("  5. Mount: sudo mount /dev/mapper/encrypted /mnt".to_string());
        results.push("  6. Add to /etc/crypttab and /etc/fstab for boot".to_string());
        results.push("".to_string());
        results.push(
            "For full-disk encryption on a fresh install, use your distro's installer.".to_string(),
        );
    }

    #[cfg(target_os = "macos")]
    {
        results.push("To enable FileVault:".to_string());
        results.push("  sudo fdesetup enable".to_string());
        results.push("  (Save the recovery key in a safe place!)".to_string());
    }

    #[cfg(windows)]
    {
        results.push("To enable BitLocker:".to_string());
        results.push("  1. Enable TPM in BIOS".to_string());
        results.push(
            "  2. Run as admin: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256"
                .to_string(),
        );
        results.push("  3. Save recovery key to AD or file".to_string());
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        results.push("Not supported on this platform.".to_string());
    }

    results
}
