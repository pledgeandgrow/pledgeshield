/// Crontab modification monitor — alert when cron jobs or systemd timers are added/modified.
use crate::models::{Category, Finding, Severity};
use std::collections::HashSet;
use std::process::Command;

pub fn audit_cron_changes() -> Vec<Finding> {
    let mut findings = Vec::new();

    let baseline = load_baseline();
    let current = get_current_cron_state();

    // Compare
    let base_set: HashSet<&str> = baseline.iter().map(|s| s.as_str()).collect();
    let curr_set: HashSet<&str> = current.iter().map(|s| s.as_str()).collect();

    // New entries
    for entry in curr_set.difference(&base_set) {
        if entry.is_empty() { continue; }
        findings.push(Finding::new(
            &format!("cronmon-new-{}", entry.split_whitespace().next().unwrap_or("entry")),
            &format!("New scheduled task: {}", entry),
            Severity::High,
            Category::Persistence,
        )
        .description("A new cron job or systemd timer was added since last check. Verify this is legitimate."));
    }

    // Removed entries (less suspicious but worth noting)
    for entry in base_set.difference(&curr_set) {
        if entry.is_empty() { continue; }
        findings.push(Finding::new(
            &format!("cronmon-removed-{}", entry.split_whitespace().next().unwrap_or("entry")),
            &format!("Scheduled task removed: {}", entry),
            Severity::Info,
            Category::Persistence,
        ));
    }

    // Save current state
    save_baseline(&current);

    findings
}

fn get_current_cron_state() -> Vec<String> {
    let mut entries = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // User crontabs
        let out = Command::new("sh").args(["-c", "crontab -l 2>/dev/null"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if !line.starts_with('#') && !line.trim().is_empty() {
                    entries.push(format!("user-cron: {}", line));
                }
            }
        }

        // System crontabs
        let cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
        for dir in &cron_dirs {
            if let Ok(files) = std::fs::read_dir(dir) {
                for file in files.flatten() {
                    entries.push(format!("{}: {}", dir, file.file_name().to_string_lossy()));
                }
            }
        }

        // /etc/crontab
        if let Ok(content) = std::fs::read_to_string("/etc/crontab") {
            for line in content.lines() {
                if !line.starts_with('#') && !line.trim().is_empty() {
                    entries.push(format!("/etc/crontab: {}", line));
                }
            }
        }

        // systemd timers
        let out = Command::new("systemctl").args(["list-timers", "--all", "--no-pager"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                if !line.trim().is_empty() {
                    entries.push(format!("systemd-timer: {}", line));
                }
            }
        }
    }

    entries
}

fn baseline_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    home.join(".local/share/pledgeshield/cronmon-baseline.txt")
}

fn load_baseline() -> Vec<String> {
    let path = baseline_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        content.lines().map(String::from).collect()
    } else {
        Vec::new()
    }
}

fn save_baseline(entries: &[String]) {
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, entries.join("\n"));
}

/// Create initial baseline.
pub fn create_baseline() -> String {
    let current = get_current_cron_state();
    save_baseline(&current);
    format!("Cron baseline created with {} entries.", current.len())
}

/// Monitor cron changes in real-time.
pub fn monitor_cron(interval: u64, max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Cron Modification Monitor              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for new/modified cron jobs and systemd timers");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    loop {
        let findings = audit_cron_changes();
        let now = chrono::Utc::now().format("%H:%M:%S");
        for f in &findings {
            println!("  {} [{}] {}", now, f.severity, f.title);
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
