/// Autorun/AutoPlay disabler — prevent malware auto-execution from inserted media.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_autorun() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(windows)]
    {
        // Check AutoRun registry keys
        let out = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "/v",
                "NoDriveTypeAutoRun",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            // 0xFF = all drives disabled, 0x91 = default (CD enabled)
            if !s.contains("0xff") && !s.contains("0xFF") {
                findings.push(
                    Finding::new(
                        "autorun-enabled",
                        "AutoRun is not fully disabled",
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description(
                        "AutoRun allows malware on USB/CD to execute automatically when inserted.",
                    )
                    .recommendation("Run: pledgeshield harden autorun --disable")
                    .fixable(true),
                );
            }
        } else {
            // Key doesn't exist — AutoRun is at default (enabled for CDs)
            findings.push(
                Finding::new(
                    "autorun-default",
                    "AutoRun is at default settings (enabled for some drives)",
                    Severity::High,
                    Category::HostConfig,
                )
                .recommendation("Run: pledgeshield harden autorun --disable")
                .fixable(true),
            );
        }

        // Check AutoPlay
        let out = Command::new("powershell")
            .args([
                "-Command",
                "Get-CimInstance -ClassName Win32_AutochkSetting | Select-Object SettingID",
            ])
            .output();
        // Also check via registry
        let out = Command::new("reg")
            .args([
                "query",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers",
                "/v",
                "DisableAutoplay",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("0x1") {
                findings.push(Finding::new(
                    "autoplay-enabled",
                    "AutoPlay is enabled",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("AutoPlay prompts to run programs on inserted media. Disable to prevent malware execution.")
                .recommendation("Run: pledgeshield harden autorun --disable")
                .fixable(true));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Check if automount is enabled
        let out = Command::new("gsettings")
            .args(["get", "org.gnome.desktop.media-handling", "automount"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("true") {
                findings.push(Finding::new(
                    "autorun-automount",
                    "GNOME auto-mounts inserted media",
                    Severity::Low,
                    Category::HostConfig,
                )
                .description("Auto-mounting USB media is enabled. While less risky than Windows AutoRun, it can still trigger exploits in file managers.")
                .recommendation("Run: gsettings set org.gnome.desktop.media-handling automount false"));
            }
        }

        // Check if autorun is enabled
        let out = Command::new("gsettings")
            .args(["get", "org.gnome.desktop.media-handling", "autorun-never"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("false") {
                findings.push(
                    Finding::new(
                        "autorun-gnome-enabled",
                        "GNOME autorun is not disabled",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("GNOME may auto-open applications on inserted media.")
                    .recommendation(
                        "Run: gsettings set org.gnome.desktop.media-handling autorun-never true",
                    )
                    .fixable(true),
                );
            }
        }
    }

    findings
}

pub fn disable_autorun(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "autorun-disable".to_string(),
            success: true,
            message: "[dry-run] Would disable AutoRun and AutoPlay.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(windows)]
    {
        // Disable AutoRun for all drive types
        let out1 = Command::new("reg")
            .args([
                "add",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "/v",
                "NoDriveTypeAutoRun",
                "/t",
                "REG_DWORD",
                "/d",
                "255",
                "/f",
            ])
            .output();

        // Disable AutoPlay
        let out2 = Command::new("reg")
            .args([
                "add",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers",
                "/v",
                "DisableAutoplay",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        let success = out1.map(|o| o.status.success()).unwrap_or(false)
            && out2.map(|o| o.status.success()).unwrap_or(false);

        HardenResult {
            action: "autorun-disable".to_string(),
            success,
            message: if success {
                "AutoRun and AutoPlay disabled for all drives.".to_string()
            } else {
                "Failed to disable AutoRun (need admin?)".to_string()
            },
            findings: vec![],
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("gsettings")
            .args([
                "set",
                "org.gnome.desktop.media-handling",
                "automount",
                "false",
            ])
            .output();
        let _ = Command::new("gsettings")
            .args([
                "set",
                "org.gnome.desktop.media-handling",
                "autorun-never",
                "true",
            ])
            .output();
        HardenResult {
            action: "autorun-disable".to_string(),
            success: true,
            message: "GNOME auto-mount and autorun disabled.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        HardenResult {
            action: "autorun-disable".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}
