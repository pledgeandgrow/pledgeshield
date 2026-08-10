/// Data exfiltration guard — monitor for large file copies to USB/network/cloud.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_exfiltration() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check for recently mounted USB/storage devices
        if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 { continue; }
                let dev = parts[0];
                let mount = parts[1];

                // Check for USB mounts
                if dev.contains("/dev/sd") || dev.contains("/dev/usb") || mount.contains("/media") || mount.contains("/mnt") {
                    // Check if large files were recently copied
                    if let Ok(entries) = std::fs::read_dir(mount) {
                        for entry in entries.flatten() {
                            if let Ok(meta) = std::fs::metadata(entry.path()) {
                                if meta.is_file() && meta.len() > 100 * 1024 * 1024 {
                                    if let Ok(time) = meta.modified() {
                                        if let Ok(elapsed) = time.elapsed() {
                                            if elapsed.as_secs() < 3600 {
                                                findings.push(Finding::new(
                                                    "exfil-large-file-usb",
                                                    &format!("Large file on USB: {} ({:.1} MB, modified {}min ago)",
                                                        entry.path().display(),
                                                        meta.len() as f64 / 1048576.0,
                                                        elapsed.as_secs() / 60),
                                                    Severity::Medium,
                                                    Category::HostConfig,
                                                )
                                                .description("A large file was recently copied to a USB device. Verify this is expected."));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for active network transfers (scp, rsync)
        let out = Command::new("ps").args(["-eo", "comm,args"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let lower = line.to_lowercase();
                if lower.contains("scp ") || lower.contains("rsync ") {
                    let comm = line.split_whitespace().next().unwrap_or("");
                    findings.push(Finding::new(
                        "exfil-network-transfer",
                        &format!("Active network transfer: {}", comm),
                        Severity::Low,
                        Category::Network,
                    )
                    .description("An active file transfer (scp/rsync) was detected. Verify this is authorized."));
                }
            }
        }

        // Check for cloud sync tools
        let cloud_tools = ["dropbox", "rclone", "gdrive", "onedrive", "mega"];
        let out = Command::new("ps").args(["-eo", "comm"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for tool in &cloud_tools {
                if s.contains(tool) {
                    findings.push(Finding::new(
                        &format!("exfil-cloud-{}", tool),
                        &format!("Cloud sync tool running: {}", tool),
                        Severity::Low,
                        Category::Network,
                    )
                    .description("A cloud sync tool is running. Files may be uploaded to cloud storage."));
                }
            }
        }
    }

    findings
}

/// Monitor for data exfiltration in real-time.
pub fn monitor_exfiltration(max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Exfiltration Monitor                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for large file copies, USB transfers, cloud sync");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    loop {
        let findings = audit_exfiltration();
        let now = chrono::Utc::now().format("%H:%M:%S");
        for f in &findings {
            println!("  {} [{}] {}", now, f.severity, f.title);
        }
        if findings.is_empty() {
            // Silent if nothing happening
        }

        std::thread::sleep(std::time::Duration::from_secs(10));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
