/// Camera/mic guard — audit which apps have camera/mic access, block unauthorized access.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_devices() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check which processes have camera (/dev/video*) open
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    // Check /proc/<pid>/fd for video devices
                    let fd_dir = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                        for fd in fds.flatten() {
                            if let Ok(target) = std::fs::read_link(fd.path()) {
                                let t = target.to_string_lossy();
                                if t.starts_with("/dev/video") {
                                    let comm =
                                        std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                            .map(|s| s.trim().to_string())
                                            .unwrap_or_else(|_| "?".to_string());
                                    findings.push(Finding::new(
                                        "camera-in-use",
                                        &format!("Camera accessed by: {} (pid {})", comm, pid),
                                        Severity::High,
                                        Category::HostConfig,
                                    )
                                    .description("A process is currently accessing the camera. Verify this is expected."));
                                }
                                // Check for mic (sound devices)
                                if t.contains("/dev/snd/")
                                    && (t.contains("pcm") || t.contains("capture"))
                                {
                                    let comm =
                                        std::fs::read_to_string(format!("/proc/{}/comm", pid))
                                            .map(|s| s.trim().to_string())
                                            .unwrap_or_else(|_| "?".to_string());
                                    findings.push(Finding::new(
                                        "mic-in-use",
                                        &format!("Microphone accessed by: {} (pid {})", comm, pid),
                                        Severity::Medium,
                                        Category::HostConfig,
                                    )
                                    .description("A process is currently accessing the microphone. Verify this is expected."));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check TCC database for camera/mic permissions
        let out = Command::new("sqlite3")
            .args([
                "/Library/Application Support/com.apple.TCC/TCC.db",
                "SELECT client, service FROM access WHERE service IN ('kTCCServiceCamera', 'kTCCServiceMicrophone');",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 2 {
                    let client = parts[0];
                    let service = parts[1];
                    let dev = if service.contains("Camera") {
                        "camera"
                    } else {
                        "microphone"
                    };
                    findings.push(
                        Finding::new(
                            &format!("{}-permission-{}", dev, client),
                            &format!("{} has {} access", client, dev),
                            Severity::Low,
                            Category::HostConfig,
                        )
                        .description(format!("App '{}' has been granted {} access.", client, dev))
                        .recommendation(
                            "Review in System Preferences > Security & Privacy > Privacy",
                        ),
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Check camera/mic access via registry/settings
        let out = Command::new("powershell")
            .args(["-Command", "Get-PnpDevice -Class Camera,AudioEndpoint | Where-Object {$_.Status -eq 'OK'} | Select-Object FriendlyName"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.trim().is_empty() && s.lines().count() > 1 {
                findings.push(
                    Finding::new(
                        "devices-active",
                        "Camera and/or microphone devices are active",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("Camera/microphone devices are present and enabled.")
                    .recommendation("Review app permissions in Windows Settings > Privacy."),
                );
            }
        }
    }

    findings
}

/// Block camera access by disabling the video devices.
pub fn block_camera(dry_run: bool) -> Vec<String> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("video") {
                    let path = format!("/dev/{}", name_str);
                    if dry_run {
                        results.push(format!("[dry-run] Would remove permissions on {}", path));
                    } else {
                        // Remove read/write permissions
                        let _ = Command::new("chmod").args(["000", &path]).output();
                        results.push(format!("Blocked camera device: {}", path));
                    }
                }
            }
        }
        if results.is_empty() {
            results.push("No camera devices found.".to_string());
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if dry_run {
            results.push("[dry-run] Would block camera access.".to_string());
        } else {
            results.push(
                "Camera blocking requires manual configuration on this platform.".to_string(),
            );
        }
    }

    results
}

/// Restore camera access.
pub fn restore_camera() -> Vec<String> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("video") {
                    let path = format!("/dev/{}", name_str);
                    let _ = Command::new("chmod").args(["666", &path]).output();
                    results.push(format!("Restored camera device: {}", path));
                }
            }
        }
        if results.is_empty() {
            results.push("No camera devices found.".to_string());
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        results.push("Not supported on this platform.".to_string());
    }

    results
}
