/// Share permission fixes.

pub fn fix_share_permissions(share: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Fixing share permissions for: {}", share);

    #[cfg(target_os = "windows")]
    {
        // Remove "Everyone" from the share and grant Administrators full control
        let output = std::process::Command::new("net")
            .args([
                "share",
                share,
                "/grant:Administrators,FULL",
                "/remove:Everyone",
            ])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            // Try alternative approach: just remove Everyone
            let output2 = std::process::Command::new("net")
                .args(["share", share, "/remove:Everyone"])
                .output();

            if output2.map(|o| !o.status.success()).unwrap_or(true) {
                return Err(format!("Failed to fix share '{}': {}", share, err).into());
            }
        }

        println!("  ✓ Removed 'Everyone' from share '{}' permissions", share);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = share;
        Err("Share fixes are only supported on Windows".into())
    }
}

pub fn disable_admin_share(share: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Disabling admin share: {}", share);

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("net")
            .args(["share", share, "/delete"])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to delete admin share '{}': {}", share, err).into());
        }

        println!("  ✓ Admin share '{}' deleted", share);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = share;
        Err("Share fixes are only supported on Windows".into())
    }
}

pub fn disable_smbv1() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Disabling SMBv1");

    #[cfg(target_os = "windows")]
    {
        // Set registry key
        crate::fix::registry_fix::apply_registry_fix(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "SMB1",
            "0",
        )?;

        // Also try PowerShell to disable the feature
        let _ = std::process::Command::new("powershell")
            .args([
                "-Command",
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
            ])
            .output();

        println!("  ✓ SMBv1 disabled (reboot required for full effect)");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("SMBv1 fixes are only supported on Windows".into())
    }
}
