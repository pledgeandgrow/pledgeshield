/// Bluetooth beacon scanner — detect Bluetooth tracking beacons (AirTags, Tile, Galaxy SmartTag).
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_beacon() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("bluetoothctl").args(["devices"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("Device") {
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() >= 3 {
                        let name = parts[2];
                        let known_trackers = ["AirTag", "Tile", "SmartTag", "Nutale"];
                        for tracker in &known_trackers {
                            if name.contains(tracker) {
                                findings.push(Finding::new(
                                    &format!("beacon-{}-detected", tracker.to_lowercase()),
                                    &format!("{} tracking device detected: {}", tracker, name),
                                    Severity::Medium,
                                    Category::Browser,
                                ).description(&format!("A {} Bluetooth tracker was found nearby. If you don't own it, someone may be tracking your location.", tracker)));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        findings.push(Finding::new(
            "beacon-macos-manual",
            "Check for AirTags via Find My app",
            Severity::Info,
            Category::Browser,
        ).description("On macOS, use System Settings > Bluetooth or the Find My app to detect nearby AirTags."));
    }

    #[cfg(target_os = "windows")]
    {
        findings.push(
            Finding::new(
                "beacon-windows-manual",
                "Check for trackers via Bluetooth settings",
                Severity::Info,
                Category::Browser,
            )
            .description(
                "On Windows, check Settings > Bluetooth & devices for unknown tracker devices.",
            ),
        );
    }

    findings
}
