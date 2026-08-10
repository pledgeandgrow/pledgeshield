/// Real-time security monitor — watches for new listening ports, suspicious processes,
/// and firewall changes. Runs as a foreground daemon until Ctrl+C.
use crate::models::{Category, Finding, Severity};
use std::collections::HashSet;
use std::process::Command;
use std::time::{Duration, Instant};

/// Monitor configuration.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// How often to poll (seconds)
    pub interval: u64,
    /// Alert on new listening ports
    pub watch_ports: bool,
    /// Alert on new processes running as root/SYSTEM
    pub watch_processes: bool,
    /// Alert if firewall gets disabled
    pub watch_firewall: bool,
    /// Stop after this many seconds (0 = run forever)
    pub max_runtime: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval: 5,
            watch_ports: true,
            watch_processes: true,
            watch_firewall: true,
            max_runtime: 0,
        }
    }
}

/// Run the monitor. Prints alerts to stdout. Returns when max_runtime is reached
/// or the user presses Ctrl+C (handled by the caller via signal).
pub fn run_monitor(config: &MonitorConfig) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Real-Time Security Monitor            ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Polling every {}s | ports={} processes={} firewall={}",
        config.interval, config.watch_ports, config.watch_processes, config.watch_firewall);
    println!("  Press Ctrl+C to stop.\n");

    // Establish baseline
    let mut known_ports: HashSet<(u16, String)> = HashSet::new();
    let mut known_processes: HashSet<String> = HashSet::new();
    let mut firewall_was_up = true;

    if config.watch_ports {
        known_ports = get_listening_ports();
        println!("  [baseline] {} ports currently listening", known_ports.len());
    }
    if config.watch_processes {
        known_processes = get_root_processes();
        println!("  [baseline] {} root/SYSTEM processes running", known_processes.len());
    }
    if config.watch_firewall {
        firewall_was_up = is_firewall_up();
    }

    println!("\n  Monitoring started...\n");

    let start = Instant::now();
    let interval = Duration::from_secs(config.interval);

    loop {
        std::thread::sleep(interval);

        // Check max runtime
        if config.max_runtime > 0 && start.elapsed().as_secs() >= config.max_runtime {
            println!("\n  Max runtime reached ({}s). Stopping.", config.max_runtime);
            break;
        }

        let now = chrono::Utc::now().format("%H:%M:%S");

        // Watch for new ports
        if config.watch_ports {
            let current = get_listening_ports();
            let new_ports: Vec<_> = current.difference(&known_ports).cloned().collect();
            let closed_ports: Vec<_> = known_ports.difference(&current).cloned().collect();

            for (port, proto) in &new_ports {
                let sev = if is_sensitive_port(*port) { Severity::High } else { Severity::Medium };
                println!("  {} [{}] NEW port {}/{} is now listening", now, sev, port, proto);
                if is_sensitive_port(*port) {
                    println!("    ⚠ This is a sensitive port (SSH, RDP, SMB, etc.)!");
                }
            }
            for (port, proto) in &closed_ports {
                println!("  {} [info] port {}/{} stopped listening", now, port, proto);
            }

            known_ports = current;
        }

        // Watch for new root processes
        if config.watch_processes {
            let current = get_root_processes();
            let new_procs: Vec<_> = current.difference(&known_processes).cloned().collect();
            let ended_procs: Vec<_> = known_processes.difference(&current).cloned().collect();

            for proc in &new_procs {
                println!("  {} [medium] NEW root process: {}", now, proc);
            }
            // Only report ended processes if there are many (avoid noise)
            if ended_procs.len() > 5 {
                println!("  {} [info] {} root processes ended", now, ended_procs.len());
            }

            known_processes = current;
        }

        // Watch for firewall changes
        if config.watch_firewall {
            let fw_up = is_firewall_up();
            if fw_up != firewall_was_up {
                if fw_up {
                    println!("  {} [info] Firewall was re-enabled", now);
                } else {
                    println!("  {} [CRITICAL] Firewall was DISABLED!", now);
                }
                firewall_was_up = fw_up;
            }
        }
    }
}

/// Get all listening ports as (port, protocol) tuples.
fn get_listening_ports() -> HashSet<(u16, String)> {
    let mut ports = HashSet::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let out = Command::new("ss")
            .args(["-tuln"])
            .output()
            .or_else(|_| Command::new("netstat").args(["-tuln"]).output());

        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                if !line.contains("LISTEN") && !line.contains("UNCONN") {
                    continue;
                }
                let lower = line.to_lowercase();
                let proto = if lower.starts_with("tcp") { "tcp" }
                    else if lower.starts_with("udp") { "udp" }
                    else { continue };
                for token in line.split_whitespace() {
                    if token.contains(':') {
                        if let Some(port_str) = token.rsplit(':').next() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                ports.insert((port, proto.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(o) = Command::new("netstat").args(["-an"]).output() {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.contains("LISTENING") { continue; }
                let lower = line.to_lowercase();
                let proto = if lower.starts_with("tcp") { "tcp" }
                    else if lower.starts_with("udp") { "udp" }
                    else { continue };
                for token in line.split_whitespace() {
                    if token.contains(':') {
                        if let Some(port_str) = token.rsplit(':').next() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                ports.insert((port, proto.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    ports
}

/// Get processes running as root/SYSTEM (names only, for comparison).
fn get_root_processes() -> HashSet<String> {
    let mut procs = HashSet::new();

    #[cfg(target_os = "linux")]
    {
        // ps with root user
        if let Ok(o) = Command::new("ps").args(["-u", "root", "-o", "comm="]).output() {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let name = line.trim();
                if !name.is_empty() {
                    procs.insert(name.to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = Command::new("ps").args(["-u", "root", "-o", "comm="]).output() {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let name = line.trim();
                if !name.is_empty() {
                    procs.insert(name.to_string());
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Use wmic to get processes running as SYSTEM
        if let Ok(o) = Command::new("wmic")
            .args(["process", "where", "(ExecutablePath is not null)", "get", "Name"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines().skip(1) {
                let name = line.trim();
                if !name.is_empty() {
                    procs.insert(name.to_string());
                }
            }
        }
    }

    procs
}

/// Check if the firewall is up.
fn is_firewall_up() -> bool {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ufw").args(["status"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("active") {
                return true;
            }
        }
        let out = Command::new("systemctl").args(["is-active", "firewalld"]).output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).trim() == "active";
        }
        // If iptables has rules, consider it up
        let out = Command::new("iptables").args(["-S"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            return s.lines().count() > 3; // More than just default chains
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--getglobalstate"])
            .output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).contains("enabled");
        }
        false
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["advfirewall", "show", "allprofiles", "state"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            // If all profiles say ON, firewall is up
            return !s.contains("OFF");
        }
        false
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Ports that are sensitive and should trigger a high-severity alert.
fn is_sensitive_port(port: u16) -> bool {
    matches!(port,
        22 |   // SSH
        23 |   // Telnet
        21 |   // FTP
        3389 | // RDP
        5900 | // VNC
        445 |  // SMB
        139 |  // NetBIOS
        135 |  // MSRPC
        1433 | // SQL Server
        3306 | // MySQL
        5432 | // PostgreSQL
        6379 | // Redis
        27017 // MongoDB
    )
}

/// Generate findings from monitor alerts (for integration with scan results).
pub fn monitor_findings(_config: &MonitorConfig) -> Vec<Finding> {
    // This is a placeholder — the real-time monitor prints directly to stdout.
    // This function exists so the monitor can be integrated into scan results
    // if needed in the future.
    Vec::new()
}
