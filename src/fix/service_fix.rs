/// Service disable/enable fixes (platform-specific).

pub fn disable_service(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Disabling service: {}", name);

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("sc")
            .args(["config", name, "start=", "disabled"])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to disable service '{}': {}", name, err).into());
        }

        // Also stop the service if running
        let _ = std::process::Command::new("sc")
            .args(["stop", name])
            .output();

        println!("  ✓ Service '{}' disabled", name);
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("systemctl")
            .args(["disable", "--now", name])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to disable service '{}': {}", name, err).into());
        }

        println!("  ✓ Service '{}' disabled", name);
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("launchctl")
            .args(["bootout", &format!("system/{}", name)])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to disable service '{}': {}", name, err).into());
        }

        println!("  ✓ Service '{}' disabled", name);
    }

    Ok(())
}

pub fn enable_service(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Enabling service: {}", name);

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("sc")
            .args(["config", name, "start=", "auto"])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to enable service '{}': {}", name, err).into());
        }

        let _ = std::process::Command::new("sc")
            .args(["start", name])
            .output();

        println!("  ✓ Service '{}' enabled", name);
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("systemctl")
            .args(["enable", "--now", name])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to enable service '{}': {}", name, err).into());
        }

        println!("  ✓ Service '{}' enabled", name);
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("launchctl")
            .args([
                "bootstrap",
                "system",
                &format!("/System/Library/LaunchDaemons/{}.plist", name),
            ])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to enable service '{}': {}", name, err).into());
        }

        println!("  ✓ Service '{}' enabled", name);
    }

    Ok(())
}
