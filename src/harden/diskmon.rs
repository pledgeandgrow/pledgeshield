/// Disk usage anomaly detector — flag sudden disk space changes.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_disk_usage() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check disk usage of all mounted filesystems
        let out = Command::new("df").args(["-h", "--output=pcent,target"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 { continue; }
                let pct_str = parts[0].trim_end_matches('%');
                let mount = parts[1];
                if let Ok(pct) = pct_str.parse::<u32>() {
                    if pct > 95 {
                        findings.push(Finding::new(
                            &format!("disk-full-{}", mount.replace('/', "_")),
                            &format!("Disk {} is {}% full", mount, pct),
                            Severity::Critical,
                            Category::HostConfig,
                        )
                        .description("Disk is almost full. This can cause system instability, data corruption, and may indicate ransomware encryption or log flooding."));
                    } else if pct > 90 {
                        findings.push(Finding::new(
                            &format!("disk-near-full-{}", mount.replace('/', "_")),
                            &format!("Disk {} is {}% full", mount, pct),
                            Severity::High,
                            Category::HostConfig,
                        )
                        .description("Disk is nearly full. Clean up unnecessary files."));
                    }
                }
            }
        }

        // Check for sudden large directories
        let cache_path = dirs::cache_dir();
        if let Some(cache) = cache_path {
            if let Ok(out) = Command::new("du").args(["-sh", cache.to_str().unwrap_or(".")]).output() {
                let s = String::from_utf8_lossy(&out.stdout);
                if s.contains("G") {
                    // Cache is multiple GB
                    let size_str = s.split_whitespace().next().unwrap_or("");
                    findings.push(Finding::new(
                        "disk-large-cache",
                        &format!("Cache directory is large: {}", size_str),
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("Your cache directory is using significant disk space. Consider cleaning it.")
                    .recommendation("Run: pledgeshield harden cleaner  (or manually clear cache)"));
                }
            }
        }

        // Check /var/log size
        if let Ok(out) = Command::new("du").args(["-sh", "/var/log"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(size) = s.split_whitespace().next() {
                if size.contains("G") {
                    findings.push(Finding::new(
                        "disk-large-logs",
                        &format!("/var/log is large: {}", size),
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .description("Log directory is using significant space. Consider log rotation."));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("wmic").args(["logicaldisk", "get", "size,freespace,caption"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(free), Ok(total)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
                        if total > 0 {
                            let used_pct = ((total - free) * 100 / total) as u32;
                            if used_pct > 95 {
                                findings.push(Finding::new(
                                    &format!("disk-full-{}", parts[0]),
                                    &format!("Disk {} is {}% full", parts[0], used_pct),
                                    Severity::Critical,
                                    Category::HostConfig,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Monitor disk usage for sudden changes (ransomware encryption indicator).
pub fn monitor_disk_usage(interval: u64, max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Disk Usage Monitor                     ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for sudden disk space changes (ransomware indicator)");
    println!("  Press Ctrl+C to stop.\n");

    let mut prev_free = get_disk_free();
    println!("  [baseline] Free space: {:.1} GB", prev_free as f64 / 1073741824.0);

    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }

        let current_free = get_disk_free();
        let delta = current_free as i64 - prev_free as i64;
        let now = chrono::Utc::now().format("%H:%M:%S");

        if delta < -1073741824 { // > 1GB decrease
            println!("  {} [HIGH] Disk space dropped by {:.1} GB — possible mass encryption!", now, (-delta as f64) / 1073741824.0);
        } else if delta < -104857600 { // > 100MB decrease
            println!("  {} [medium] Disk space decreased by {:.0} MB", now, (-delta as f64) / 1048576.0);
        }

        prev_free = current_free;
    }
}

fn get_disk_free() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh").args(["-c", "df -B1 --output=avail / | tail -1"]).output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).trim().parse().unwrap_or(0);
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
