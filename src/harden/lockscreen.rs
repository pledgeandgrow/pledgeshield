/// Auto-login & lock screen enforcer — force screen lock timeout, disable auto-login.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_lockscreen() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check GNOME settings
        let out = Command::new("gsettings").args(["get", "org.gnome.desktop.session", "idle-delay"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "0" || s == "uint32 0" {
                findings.push(Finding::new(
                    "lockscreen-no-timeout",
                    "Screen lock timeout is disabled",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("The screen will never auto-lock. Anyone can access your session if you step away.")
                .recommendation("Run: pledgeshield harden lockscreen --enable")
                .fixable(true));
            }
        }

        // Check if auto-login is enabled
        let gdm_path = "/etc/gdm3/custom.conf";
        if let Ok(content) = std::fs::read_to_string(gdm_path) {
            if content.contains("AutomaticLoginEnable=true") {
                findings.push(Finding::new(
                    "auto-login-enabled",
                    "Auto-login is enabled",
                    Severity::High,
                    Category::Privileges,
                )
                .description("Auto-login bypasses the login screen, giving anyone physical access full access.")
                .recommendation("Run: pledgeshield harden lockscreen --disable-autologin")
                .fixable(true));
            }
        }

        // Check lightdm
        let lightdm_path = "/etc/lightdm/lightdm.conf";
        if let Ok(content) = std::fs::read_to_string(lightdm_path) {
            if content.contains("autologin-user=") && !content.contains("autologin-user=#") {
                findings.push(Finding::new(
                    "lightdm-auto-login",
                    "LightDM auto-login is enabled",
                    Severity::High,
                    Category::Privileges,
                )
                .description("LightDM is configured to auto-login a user.")
                .recommendation("Run: pledgeshield harden lockscreen --disable-autologin")
                .fixable(true));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("defaults").args(["read", "com.apple.screensaver", "idleTime"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "0" || s.is_empty() {
                findings.push(Finding::new(
                    "lockscreen-no-timeout",
                    "Screen saver is disabled",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("The screen saver/lock is disabled.")
                .recommendation("Run: pledgeshield harden lockscreen --enable")
                .fixable(true));
            }
        }

        // Check auto-login
        let out = Command::new("defaults").args(["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() && s != "0" {
                findings.push(Finding::new(
                    "mac-auto-login",
                    "macOS auto-login is enabled",
                    Severity::High,
                    Category::Privileges,
                )
                .description("macOS is configured to auto-login a user.")
                .fixable(true));
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("reg").args(["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "AutoAdminLogon"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("1") {
                findings.push(Finding::new(
                    "win-auto-login",
                    "Windows auto-login is enabled",
                    Severity::High,
                    Category::Privileges,
                )
                .description("Windows is configured to auto-login without a password.")
                .recommendation("Run: pledgeshield harden lockscreen --disable-autologin")
                .fixable(true));
            }
        }
    }

    findings
}

pub fn enable_lockscreen(timeout_secs: u32, dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "lockscreen-enable".to_string(),
            success: true,
            message: format!("[dry-run] Would set screen lock timeout to {}s.", timeout_secs),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // GNOME
        let _ = Command::new("gsettings").args(["set", "org.gnome.desktop.session", "idle-delay", &format!("uint32 {}", timeout_secs)]).output();
        let _ = Command::new("gsettings").args(["set", "org.gnome.desktop.screensaver", "lock-enabled", "true"]).output();
        let _ = Command::new("gsettings").args(["set", "org.gnome.desktop.screensaver", "lock-delay", "uint32 0"]).output();

        HardenResult {
            action: "lockscreen-enable".to_string(),
            success: true,
            message: format!("Screen lock enabled (timeout: {}s).", timeout_secs),
            findings: vec![],
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("defaults").args(["write", "com.apple.screensaver", "idleTime", "-int", &timeout_secs.to_string()]).output();
        HardenResult {
            action: "lockscreen-enable".to_string(),
            success: true,
            message: format!("Screen saver enabled (timeout: {}s).", timeout_secs),
            findings: vec![],
        }
    }

    #[cfg(windows)]
    {
        let _ = Command::new("powercfg").args(["/change", "standby-timeout-ac", &((timeout_secs / 60).to_string())]).output();
        HardenResult {
            action: "lockscreen-enable".to_string(),
            success: true,
            message: format!("Screen timeout set to {} minutes.", timeout_secs / 60),
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = timeout_secs;
        HardenResult {
            action: "lockscreen-enable".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_autologin(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "disable-autologin".to_string(),
            success: true,
            message: "[dry-run] Would disable auto-login.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // GDM
        if let Ok(content) = std::fs::read_to_string("/etc/gdm3/custom.conf") {
            let new = content.replace("AutomaticLoginEnable=true", "AutomaticLoginEnable=false");
            let _ = std::fs::write("/etc/gdm3/custom.conf", new);
        }
        // LightDM
        if let Ok(content) = std::fs::read_to_string("/etc/lightdm/lightdm.conf") {
            let new = content.replace("autologin-user=", "#autologin-user=");
            let _ = std::fs::write("/etc/lightdm/lightdm.conf", new);
        }
        HardenResult {
            action: "disable-autologin".to_string(),
            success: true,
            message: "Auto-login disabled for GDM and LightDM.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("defaults").args(["delete", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]).output();
        HardenResult {
            action: "disable-autologin".to_string(),
            success: true,
            message: "macOS auto-login disabled.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(windows)]
    {
        let _ = Command::new("reg").args(["add", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "AutoAdminLogon", "/t", "REG_SZ", "/d", "0", "/f"]).output();
        HardenResult {
            action: "disable-autologin".to_string(),
            success: true,
            message: "Windows auto-login disabled.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "disable-autologin".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
