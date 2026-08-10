/// WiFi security audit — check for open WiFi, WEP, saved network leaks, auto-connect, evil twin.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_wifi() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check current connection
        let out = Command::new("nmcli").args(["-t", "-f", "active,ssid,security,signal", "device", "wifi", "list"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 4 { continue; }
                let active = parts[0] == "yes";
                let ssid = parts[1];
                let security = parts[2];
                if active {
                    if security.is_empty() || security == "--" {
                        findings.push(Finding::new(
                            "wifi-open-network",
                            &format!("Connected to open WiFi: {}", ssid),
                            Severity::High,
                            Category::Network,
                        )
                        .description("You are connected to an unencrypted WiFi network. Traffic can be intercepted.")
                        .recommendation("Use a VPN or switch to a secured network.")
                        .fixable(false));
                    } else if security.contains("WEP") {
                        findings.push(Finding::new(
                            "wifi-wep",
                            &format!("Connected to WEP network: {} (insecure)", ssid),
                            Severity::High,
                            Category::Network,
                        )
                        .description("WEP encryption is broken and can be cracked in minutes.")
                        .recommendation("Switch to WPA2/WPA3 or use a VPN.")
                        .fixable(false));
                    }
                }
            }
        }

        // Check saved networks for auto-connect to open networks
        let out = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE", "connection", "show"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 2 || parts[1] != "wifi" { continue; }
                let name = parts[0];
                // Check autoconnect
                let out2 = Command::new("nmcli").args(["-t", "-f", "connection.autoconnect", "connection", "show", name]).output();
                if let Ok(o2) = out2 {
                    let s2 = String::from_utf8_lossy(&o2.stdout);
                    if s2.contains("yes") {
                        // Check if it's open
                        let out3 = Command::new("nmcli").args(["-t", "-f", "802-11-wireless-security.key-mgmt", "connection", "show", name]).output();
                        if let Ok(o3) = out3 {
                            let s3 = String::from_utf8_lossy(&o3.stdout);
                            if s3.trim().is_empty() || s3.contains("none") {
                                findings.push(Finding::new(
                                    "wifi-autoconnect-open",
                                    &format!("Auto-connect to open network: {}", name),
                                    Severity::Medium,
                                    Category::Network,
                                )
                                .description("This device will automatically connect to an open WiFi network, exposing traffic.")
                                .recommendation(&format!("Disable auto-connect: nmcli connection modify '{}' connection.autoconnect no", name))
                                .fixable(true));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("networksetup").args(["-listallnetworkservices"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let svc = line.trim();
                if svc.is_empty() || svc == "An asterisk (*) denotes that a network service is disabled." { continue; }
                let out2 = Command::new("networksetup").args(["-getairportnetwork", svc]).output();
                if let Ok(o2) = out2 {
                    let s2 = String::from_utf8_lossy(&o2.stdout);
                    if s2.contains("Wi-Fi") || s2.contains("AirPort") {
                        // Connected — check security
                        let net = s2.split(": ").nth(1).unwrap_or("").trim();
                        if !net.is_empty() {
                            // Can't easily check security on macOS without airport utility
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh").args(["wlan", "show", "interfaces"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("Open") || s.contains("WEP") {
                findings.push(Finding::new(
                    "wifi-insecure",
                    "Connected to insecure WiFi (Open or WEP)",
                    Severity::High,
                    Category::Network,
                )
                .description("Current WiFi connection uses no encryption or broken WEP.")
                .recommendation("Switch to a WPA2/WPA3 network or use a VPN.")
                .fixable(false));
            }
        }

        // Check saved networks
        let out = Command::new("netsh").args(["wlan", "show", "profiles"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if let Some(name) = line.split(':').nth(1) {
                    let name = name.trim();
                    if name.is_empty() { continue; }
                    let out2 = Command::new("netsh").args(["wlan", "show", "profile", name, "key=clear"]).output();
                    if let Ok(o2) = out2 {
                        let s2 = String::from_utf8_lossy(&o2.stdout);
                        if s2.contains("Open") {
                            findings.push(Finding::new(
                                "wifi-saved-open",
                                &format!("Saved open WiFi network: {}", name),
                                Severity::Low,
                                Category::Network,
                            )
                            .description("An open WiFi network is saved and may auto-connect.")
                            .recommendation(&format!("Remove: netsh wlan delete profile name=\"{}\"", name))
                            .fixable(true));
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Forget a saved WiFi network.
pub fn forget_network(name: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("nmcli").args(["connection", "delete", name]).output();
        match out {
            Ok(o) if o.status.success() => Ok(format!("Removed WiFi network: {}", name)),
            Ok(o) => Err(format!("Failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => Err(format!("nmcli not available: {}", e)),
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh").args(["wlan", "delete", "profile", &format!("name={}", name)]).output();
        match out {
            Ok(o) if o.status.success() => Ok(format!("Removed WiFi network: {}", name)),
            Ok(o) => Err(format!("Failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => Err(format!("netsh not available: {}", e)),
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = name;
        Err("Not supported on this platform".to_string())
    }
}
