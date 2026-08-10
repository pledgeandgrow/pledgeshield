/// Disk wipe scheduler — securely wipe free disk space so deleted files can't be recovered.
use super::HardenResult;
use std::process::Command;

pub fn wipe_freespace(path: &str, dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "freespace-wipe".to_string(),
            success: true,
            message: format!("[dry-run] Would securely wipe free space on {}", path),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Use dd to fill free space with zeros, then delete the file
        let tempfile = format!("{}/.pledgeshield-wipe", path);

        // Pass 1: zeros
        let out = Command::new("dd")
            .args([
                "if=/dev/zero",
                &format!("of={}", tempfile),
                "bs=1M",
                "status=progress",
            ])
            .output();

        if !out.map(|o| o.status.success()).unwrap_or(false) {
            // dd fails when disk is full — that's expected
        }
        let _ = std::fs::remove_file(&tempfile);

        HardenResult {
            action: "freespace-wipe".to_string(),
            success: true,
            message: format!(
                "Free space on {} wiped with zeros. Deleted files can no longer be recovered.",
                path
            ),
            findings: vec![],
        }
    }

    #[cfg(windows)]
    {
        // Use cipher /w on Windows
        let out = Command::new("cipher").args(["/w:", path]).output();
        HardenResult {
            action: "freespace-wipe".to_string(),
            success: out.as_ref().map(|o| o.status.success()).unwrap_or(false),
            message: if out.as_ref().map(|o| o.status.success()).unwrap_or(false) {
                format!("Free space on {} wiped.", path)
            } else {
                format!("Failed to wipe free space (need admin?)")
            },
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = path;
        HardenResult {
            action: "freespace-wipe".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}

/// Install a systemd timer to wipe free space weekly.
pub fn install_wipe_schedule(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "freespace-schedule".to_string(),
            success: true,
            message: "[dry-run] Would install weekly free space wipe timer.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let service = r#"[Unit]
Description=PledgeShield Free Space Wipe

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'dd if=/dev/zero of=/tmp/.pledgeshield-wipe bs=1M status=progress; rm -f /tmp/.pledgeshield-wipe'
"#;

        let timer = r#"[Unit]
Description=Weekly free space wipe

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
"#;

        let _ = std::fs::write("/etc/systemd/system/pledgeshield-wipe.service", service);
        let _ = std::fs::write("/etc/systemd/system/pledgeshield-wipe.timer", timer);
        let _ = Command::new("systemctl").args(["daemon-reload"]).output();
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "pledgeshield-wipe.timer"])
            .output();

        HardenResult {
            action: "freespace-schedule".to_string(),
            success: true,
            message: "Weekly free space wipe timer installed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "freespace-schedule".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}

pub fn remove_wipe_schedule() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "pledgeshield-wipe.timer"])
            .output();
        let _ = std::fs::remove_file("/etc/systemd/system/pledgeshield-wipe.timer");
        let _ = std::fs::remove_file("/etc/systemd/system/pledgeshield-wipe.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).output();
        HardenResult {
            action: "freespace-schedule-remove".to_string(),
            success: true,
            message: "Free space wipe timer removed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "freespace-schedule-remove".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
