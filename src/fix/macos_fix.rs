use std::process::Command;

type FixResult = Result<(), Box<dyn std::error::Error>>;

/// Enable Gatekeeper (only allow apps from identified developers).
pub fn enable_gatekeeper() -> FixResult {
    let output = Command::new("sudo")
        .args(["spctl", "--master-enable"])
        .output()?;
    if !output.status.success() {
        return Err(format!("spctl failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

/// Enable the macOS application firewall.
pub fn enable_firewall() -> FixResult {
    let output = Command::new("sudo")
        .args(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalfirewall", "on"])
        .output()?;
    if !output.status.success() {
        return Err(format!("socketfilterfw failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

/// Enable stealth mode (drop ping requests).
pub fn enable_stealth_mode() -> FixResult {
    let output = Command::new("sudo")
        .args(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"])
        .output()?;
    if !output.status.success() {
        return Err(format!("stealth mode failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

/// Enable FileVault disk encryption (requires user interaction for recovery key).
pub fn enable_filevault() -> FixResult {
    println!("  → FileVault encryption requires user interaction.");
    println!("  → A recovery key will be generated. Please store it safely.");
    let output = Command::new("sudo")
        .args(["fdesetup", "enable"])
        .status()?;
    if !output.success() {
        return Err("fdesetup enable failed".into());
    }
    Ok(())
}

/// Require password immediately after screensaver starts.
pub fn require_screensaver_password() -> FixResult {
    Command::new("defaults")
        .args(["write", "com.apple.screensaver", "askForPassword", "-int", "1"])
        .output()?;
    Command::new("defaults")
        .args(["write", "com.apple.screensaver", "askForPasswordDelay", "-int", "0"])
        .output()?;
    Ok(())
}

/// Disable guest user access to the system.
pub fn disable_guest_access() -> FixResult {
    Command::new("sudo")
        .args(["defaults", "write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false"])
        .output()?;
    Ok(())
}

/// Disable SSH root login (PermitRootLogin no).
pub fn disable_ssh_root_login() -> FixResult {
    let sshd_config = std::fs::read_to_string("/etc/ssh/sshd_config")
        .or_else(|_| std::fs::read_to_string("/etc/ssh/sshd_config.default"))?;

    let updated = sshd_config
        .lines()
        .map(|line| {
            if line.starts_with("#PermitRootLogin") || line.starts_with("PermitRootLogin") {
                "PermitRootLogin no".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write("/etc/ssh/sshd_config", &updated)?;
    Command::new("sudo").args(["launchctl", "unload", "/System/Library/LaunchDaemons/ssh.plist"]).output()?;
    Command::new("sudo").args(["launchctl", "load", "/System/Library/LaunchDaemons/ssh.plist"]).output()?;
    Ok(())
}

/// Disable Bluetooth discoverability when not in use.
pub fn disable_bluetooth_discoverable() -> FixResult {
    Command::new("defaults")
        .args(["write", "com.apple.Bluetooth", "DiscoverableState", "-bool", "false"])
        .output()?;
    Ok(())
}
