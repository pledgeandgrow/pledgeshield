/// WiFi deauth detector — detect WiFi deauthentication attacks.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_deauth() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if we're connected to WiFi
        let out = Command::new("nmcli").args(["-t", "-f", "ACTIVE,SSID,STATE", "dev", "wifi"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let connected = s.lines().any(|l| l.starts_with("yes:") && l.contains(":connected"));
            if !connected {
                return findings; // Not on WiFi — no deauth risk
            }

            // Check dmesg for deauth events
            let out = Command::new("dmesg").args(["--since", "1 hour ago"]).output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                let mut deauth_count = 0;
                for line in s.lines() {
                    if line.contains("deauth") || line.contains("deauthenticated") || line.contains("disassoc") {
                        deauth_count += 1;
                    }
                }
                if deauth_count > 3 {
                    findings.push(Finding::new(
                        "deauth-multiple",
                        &format!("{} WiFi deauth/disassoc events in last hour", deauth_count),
                        Severity::High,
                        Category::Network,
                    )
                    .description("Multiple WiFi deauthentication events detected. This could be a deauth attack trying to force you off your network (for evil twin or capture)."));
                } else if deauth_count > 0 {
                    findings.push(Finding::new(
                        "deauth-few",
                        &format!("{} WiFi deauth event(s) in last hour", deauth_count),
                        Severity::Low,
                        Category::Network,
                    )
                    .description("A few deauth events are normal. Monitor for increases."));
                }
            }

            // Check journalctl for NetworkManager deauth logs
            let out = Command::new("journalctl")
                .args(["-u", "NetworkManager", "--since", "1 hour ago", "--no-pager"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                let deauth_count = s.lines().filter(|l| {
                    l.contains("deauth") || l.contains("DEAUTH") || l.contains("reason=7")
                }).count();
                if deauth_count > 5 {
                    findings.push(Finding::new(
                        "deauth-nm-multiple",
                        &format!("NetworkManager logged {} deauth events", deauth_count),
                        Severity::High,
                        Category::Network,
                    )
                    .description("NetworkManager has logged many deauth events. Reason code 7 (Class 3 frame from non-associated station) often indicates a deauth attack."));
                }
            }
        }
    }

    findings
}

/// Monitor for deauth attacks in real-time.
pub fn monitor_deauth(max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield WiFi Deauth Monitor                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for WiFi deauthentication attacks");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    let mut last_count = 0;

    loop {
        #[cfg(target_os = "linux")]
        {
            let out = Command::new("dmesg").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                let current_count = s.lines().filter(|l| {
                    l.contains("deauth") || l.contains("deauthenticated")
                }).count();

                if current_count > last_count {
                    let new_events = current_count - last_count;
                    let now = chrono::Utc::now().format("%H:%M:%S");
                    println!("  {} [HIGH] {} new deauth event(s) detected!", now, new_events);
                    last_count = current_count;
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
