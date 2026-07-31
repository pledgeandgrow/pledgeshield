use std::process::Command;
#[cfg(target_os = "linux")]
use std::io::Write;

/// Schedule configuration for recurring scans.
#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    /// Cron expression (Linux/macOS) or task name (Windows)
    pub cron: String,
    /// The PledgeShield command to run
    pub command: String,
}

/// Install a scheduled scan on the current platform.
pub fn install_schedule(config: &ScheduleConfig) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        install_windows_task(config)
    }
    #[cfg(target_os = "macos")]
    {
        install_macos_launchd(config)
    }
    #[cfg(target_os = "linux")]
    {
        install_linux_crontab(config)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("Scheduling not supported on this platform".into())
    }
}

/// Remove a scheduled scan.
pub fn remove_schedule(task_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let output = Command::new("schtasks")
            .args(["/Delete", "/TN", task_name, "/F"])
            .output()?;
        if !output.status.success() {
            return Err(format!("schtasks delete failed: {}", String::from_utf8_lossy(&output.stderr)).into());
        }
        log::info!("Removed scheduled task: {}", task_name);
    }
    #[cfg(target_os = "macos")]
    {
        let plist_path = format!("/Library/LaunchAgents/com.pledgeshield.{}.plist", task_name);
        std::fs::remove_file(&plist_path)?;
        Command::new("launchctl").args(["unload", &plist_path]).output()?;
    }
    #[cfg(target_os = "linux")]
    {
        let crontab = Command::new("crontab").args(["-l"]).output()?;
        let current = String::from_utf8_lossy(&crontab.stdout);
        let updated = current
            .lines()
            .filter(|line| !line.contains("pledgeshield"))
            .collect::<Vec<_>>()
            .join("\n");
        Command::new("crontab")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?
            .stdin
            .take()
            .unwrap()
            .write_all(updated.as_bytes())?;
    }
    Ok(())
}

#[cfg(windows)]
fn install_windows_task(config: &ScheduleConfig) -> Result<(), Box<dyn std::error::Error>> {
    let task_name = "PledgeShieldScheduledScan";
    let exe_path = std::env::current_exe()?
        .to_str()
        .ok_or("Failed to get exe path")?
        .to_string();

    // Convert cron to schtasks schedule (simplified: daily, weekly, or on-startup)
    let schedule = if config.cron.contains("reboot") || config.cron.contains("@reboot") {
        "ONSTART"
    } else if config.cron.contains("daily") || config.cron == "0 0 * * *" {
        "DAILY"
    } else if config.cron.contains("weekly") || config.cron == "0 0 * * 0" {
        "WEEKLY"
    } else {
        "DAILY" // Default to daily
    };

    let output = Command::new("schtasks")
        .args([
            "/Create",
            "/TN", task_name,
            "/TR", &format!("\"{}\" {}", exe_path, config.command),
            "/SC", schedule,
            "/F",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!("schtasks failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    log::info!("Scheduled task '{}' created successfully", task_name);
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launchd(config: &ScheduleConfig) -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?
        .to_str()
        .ok_or("Failed to get exe path")?
        .to_string();

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pledgeshield.scheduled</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>{}</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>0</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>"#,
        exe_path, config.command
    );

    let plist_path = "/Library/LaunchAgents/com.pledgeshield.scheduled.plist";
    std::fs::write(plist_path, &plist)?;
    Command::new("launchctl").args(["load", plist_path]).output()?;
    log::info!("LaunchAgent installed at {}", plist_path);
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_crontab(config: &ScheduleConfig) -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?
        .to_str()
        .ok_or("Failed to get exe path")?
        .to_string();

    let cron_line = format!("{} {} # pledgeshield", config.cron, exe_path);

    let current = Command::new("crontab")
        .args(["-l"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut updated = current;
    if !updated.ends_with('\n') && !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(&cron_line);
    updated.push('\n');

    let child = Command::new("crontab")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(updated.as_bytes())?;
    child.wait_with_output()?;

    log::info!("Crontab entry added: {}", cron_line);
    Ok(())
}
