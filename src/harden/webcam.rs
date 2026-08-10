/// Webcam indicator enforcer — force webcam LED, disable webcam when not in use.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_webcam() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if webcam device exists
        let video_devices = std::fs::read_dir("/dev")
            .map(|d| {
                d.filter_map(|e| {
                    let name = e.ok()?.file_name().to_string_lossy().to_string();
                    if name.starts_with("video") {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !video_devices.is_empty() {
            // Check which processes are using the webcam
            for dev in &video_devices {
                let path = format!("/dev/{}", dev);
                let out = Command::new("fuser").arg(&path).output();
                if let Ok(o) = out {
                    let s = String::from_utf8_lossy(&o.stdout);
                    let pids: Vec<&str> = s.split_whitespace().collect();
                    if !pids.is_empty() {
                        for pid in &pids {
                            let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                .map(|s| s.trim().to_string())
                                .unwrap_or("unknown".to_string());
                            findings.push(
                                Finding::new(
                                    &format!("webcam-in-use-{}-{}", dev, comm),
                                    &format!("Webcam {} is in use by {} (pid {})", dev, comm, pid),
                                    Severity::Medium,
                                    Category::HostConfig,
                                )
                                .description(
                                    "A process is accessing your webcam. Verify this is expected.",
                                ),
                            );
                        }
                    }
                }
            }

            // Check if the webcam kernel module is loaded
            let out = Command::new("lsmod").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                let webcam_modules = ["uvcvideo", "snd_usb_audio"];
                for mod_name in &webcam_modules {
                    if s.contains(mod_name) {
                        // Module is loaded — webcam is available
                        // Check if it should be blocked
                    }
                }
            }
        }
    }

    findings
}

pub fn block_webcam(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "webcam-block".to_string(),
            success: true,
            message: "[dry-run] Would unload webcam kernel module.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Unload the webcam kernel module
        let out = Command::new("modprobe").args(["-r", "uvcvideo"]).output();
        let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        HardenResult {
            action: "webcam-block".to_string(),
            success: ok,
            message: if ok {
                "Webcam kernel module unloaded. Webcam is now disabled.".to_string()
            } else {
                "Failed to unload webcam module (need root?)".to_string()
            },
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "webcam-block".to_string(),
            success: false,
            message: "Webcam blocking via kernel modules is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn restore_webcam() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("modprobe").arg("uvcvideo").output();
        HardenResult {
            action: "webcam-restore".to_string(),
            success: out.map(|o| o.status.success()).unwrap_or(false),
            message: "Webcam kernel module reloaded.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "webcam-restore".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
