/// ARP spoofing detector — monitor ARP table for changes, detect MITM attempts.
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

/// ARP entry: IP -> MAC mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
}

/// Get the current ARP table.
pub fn get_arp_table() -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let out = Command::new("arp")
            .args(["-a"])
            .output()
            .or_else(|_| Command::new("ip").args(["neigh"]).output());

        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                // arp -a format: hostname (ip) at mac [ether] on iface
                // ip neigh format: ip lladdr mac dev iface
                if line.contains('(') {
                    // arp -a format
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let ip = parts[1].trim_matches(|c| c == '(' || c == ')');
                        let mac = parts[3];
                        let iface = parts
                            .iter()
                            .rposition(|p| *p != "")
                            .map(|i| parts[i])
                            .unwrap_or("?");
                        if !mac.contains("incomplete") {
                            entries.push(ArpEntry {
                                ip: ip.to_string(),
                                mac: mac.to_string(),
                                interface: iface.to_string(),
                            });
                        }
                    }
                } else {
                    // ip neigh format
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 && parts[1] == "lladdr" {
                        entries.push(ArpEntry {
                            ip: parts[0].to_string(),
                            mac: parts[2].to_string(),
                            interface: parts[4].to_string(),
                        });
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("arp").args(["-a"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0].contains('.') {
                    entries.push(ArpEntry {
                        ip: parts[0].to_string(),
                        mac: parts[1].to_string(),
                        interface: parts[2].to_string(),
                    });
                }
            }
        }
    }

    entries
}

/// Detect ARP spoofing: check if the gateway MAC has changed or if multiple IPs share a MAC.
pub fn detect_arp_spoof() -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = get_arp_table();

    // Check for MAC conflicts — multiple IPs with same MAC (could be MITM)
    let mut mac_to_ips: HashMap<String, Vec<String>> = HashMap::new();
    for e in &entries {
        mac_to_ips
            .entry(e.mac.clone())
            .or_default()
            .push(e.ip.clone());
    }

    for (mac, ips) in &mac_to_ips {
        if ips.len() > 2 {
            // Many IPs sharing one MAC — could be a router (normal) or MITM
            // Flag only if it's not the gateway
            findings.push(
                Finding::new(
                    "arp-mac-shared",
                    &format!("MAC {} has {} IPs (possible ARP spoofing)", mac, ips.len()),
                    Severity::Medium,
                    Category::Network,
                )
                .description(format!("IPs: {}", ips.join(", "))),
            );
        }
    }

    // Check gateway MAC consistency
    let gateway = get_gateway();
    if let Some(gw_ip) = gateway {
        let gw_mac = entries
            .iter()
            .find(|e| e.ip == gw_ip)
            .map(|e| e.mac.clone());
        if let Some(mac) = gw_mac {
            // Store in a known-good file for comparison
            let cache_path = "/tmp/pledgeshield-arp-gateway";
            if let Ok(cached) = std::fs::read_to_string(cache_path) {
                let cached = cached.trim();
                if cached != mac {
                    findings.push(Finding::new(
                        "arp-gateway-changed",
                        &format!("Gateway MAC changed: {} -> {}", cached, mac),
                        Severity::High,
                        Category::Network,
                    )
                    .description("The gateway's MAC address has changed since last check. This is a strong indicator of ARP spoofing / MITM attack.")
                    .recommendation("Verify you're on the correct network. Run: pledgeshield harden arp --monitor to watch in real-time."));
                }
            }
            let _ = std::fs::write(cache_path, &mac);
        }
    }

    findings
}

fn get_gateway() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip")
            .args(["route", "show", "default"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.starts_with("default") {
                    return line.split_whitespace().nth(2).map(String::from);
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let l = line.trim();
                if l.starts_with("gateway:") {
                    return l.split(':').nth(1).map(|s| s.trim().to_string());
                }
            }
        }
        None
    }

    #[cfg(windows)]
    {
        let out = Command::new("route").args(["print", "0.0.0.0"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.trim_start().starts_with("0.0.0.0") {
                    return line.split_whitespace().nth(2).map(String::from);
                }
            }
        }
        None
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Monitor ARP table in real-time for changes. Runs until max_runtime seconds.
pub fn monitor_arp(interval: u64, max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield ARP Spoofing Monitor                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!(
        "  Polling every {}s | max runtime: {}s",
        interval,
        if max_runtime == 0 {
            "∞".to_string()
        } else {
            max_runtime.to_string()
        }
    );
    println!();

    let mut known: HashMap<String, ArpEntry> = HashMap::new();
    for e in get_arp_table() {
        known.insert(e.ip.clone(), e);
    }
    println!("  [baseline] {} ARP entries", known.len());

    let start = Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }

        let now = chrono::Utc::now().format("%H:%M:%S");
        let current = get_arp_table();
        let current_map: HashMap<String, ArpEntry> =
            current.into_iter().map(|e| (e.ip.clone(), e)).collect();

        // Check for MAC changes
        for (ip, entry) in &current_map {
            if let Some(old) = known.get(ip) {
                if old.mac != entry.mac {
                    println!(
                        "  {} [HIGH] {} MAC changed: {} -> {}",
                        now, ip, old.mac, entry.mac
                    );
                }
            } else {
                println!("  {} [info] New ARP entry: {} ({})", now, ip, entry.mac);
            }
        }

        // Check for removed entries
        for ip in known.keys() {
            if !current_map.contains_key(ip) {
                println!("  {} [info] ARP entry removed: {}", now, ip);
            }
        }

        known = current_map;
    }
}
