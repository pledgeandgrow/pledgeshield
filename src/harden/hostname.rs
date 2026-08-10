/// Hostname randomizer — randomize the machine hostname to prevent tracking on networks.
use super::HardenResult;
use std::process::Command;

pub fn get_hostname() -> String {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "?".to_string())
    }
    #[cfg(windows)]
    {
        Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "?".to_string())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        "?".to_string()
    }
}

pub fn randomize_hostname(dry_run: bool) -> HardenResult {
    let new_name = generate_random_hostname();

    if dry_run {
        return HardenResult {
            action: "hostname-randomize".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would change hostname from '{}' to '{}'",
                get_hostname(),
                new_name
            ),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // hostnamectl
        let out = Command::new("hostnamectl")
            .args(["set-hostname", &new_name])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "hostname-randomize".to_string(),
                success: true,
                message: format!("Hostname changed to '{}' (via hostnamectl)", new_name),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "hostname-randomize".to_string(),
                success: false,
                message: format!("hostnamectl failed: {}", String::from_utf8_lossy(&o.stderr)),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "hostname-randomize".to_string(),
                success: false,
                message: format!("hostnamectl not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("scutil")
            .args(["--set", "HostName", &new_name])
            .output();
        let _ = Command::new("scutil")
            .args(["--set", "LocalHostName", &new_name])
            .output();
        let _ = Command::new("scutil")
            .args(["--set", "ComputerName", &new_name])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "hostname-randomize".to_string(),
                success: true,
                message: format!("Hostname changed to '{}'", new_name),
                findings: vec![],
            },
            _ => HardenResult {
                action: "hostname-randomize".to_string(),
                success: false,
                message: "Failed to set hostname.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("wmic")
            .args([
                "computersystem",
                "where",
                "name='%COMPUTERNAME%'",
                "rename",
                &new_name,
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "hostname-randomize".to_string(),
                success: true,
                message: format!("Computer name changed to '{}' (reboot required)", new_name),
                findings: vec![],
            },
            _ => HardenResult {
                action: "hostname-randomize".to_string(),
                success: false,
                message: "Failed to rename computer (need admin?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = new_name;
        HardenResult {
            action: "hostname-randomize".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

fn generate_random_hostname() -> String {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(42) as u64;
    // Simple LCG for random chars
    let mut state = seed;
    let mut name = String::from("ps-");
    for _ in 0..8 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let c = ((state >> 33) % 36) as u8;
        let ch = if c < 10 { b'0' + c } else { b'a' + c - 10 };
        name.push(ch as char);
    }
    name
}

/// Install a systemd service that randomizes hostname on every boot.
pub fn install_boot_randomizer(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "hostname-boot-install".to_string(),
            success: true,
            message: "[dry-run] Would install systemd service to randomize hostname on boot."
                .to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let service = r#"[Unit]
Description=PledgeShield hostname randomizer
After=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'hostnamectl set-hostname ps-$(head -c 4 /dev/urandom | xxd -p)'

[Install]
WantedBy=multi-user.target
"#;
        let path = "/etc/systemd/system/pledgeshield-hostname.service";
        if std::fs::write(path, service).is_ok() {
            let _ = Command::new("systemctl")
                .args(["enable", "pledgeshield-hostname.service"])
                .output();
            HardenResult {
                action: "hostname-boot-install".to_string(),
                success: true,
                message: "Installed systemd service to randomize hostname on every boot."
                    .to_string(),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "hostname-boot-install".to_string(),
                success: false,
                message: "Failed to write service file (need root?).".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "hostname-boot-install".to_string(),
            success: false,
            message: "Boot-time hostname randomization is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
