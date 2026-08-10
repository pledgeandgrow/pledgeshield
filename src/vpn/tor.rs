/// Tor proxy management — start/stop Tor, route traffic, check status.
use std::process::Command;

/// Tor proxy status.
#[derive(Debug, Clone)]
pub struct TorStatus {
    pub running: bool,
    pub socks_port: u16,
    pub control_port: u16,
    /// Whether system traffic is routed through Tor
    pub routed: bool,
}

impl std::fmt::Display for TorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.running {
            return write!(f, "Tor: Not running");
        }
        write!(
            f,
            "Tor: Running (SOCKS on 127.0.0.1:{}, control on 127.0.0.1:{}){}",
            self.socks_port,
            self.control_port,
            if self.routed { " [traffic routed through Tor]" } else { "" },
        )
    }
}

/// Check if Tor is running and get its status.
pub fn status() -> TorStatus {
    let running = is_tor_running();
    let routed = is_traffic_routed();

    TorStatus {
        running,
        socks_port: 9050,
        control_port: 9051,
        routed,
    }
}

pub fn is_tor_running() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Check if tor process is running
        let out = Command::new("pgrep").args(["-x", "tor"]).output();
        if let Ok(o) = out {
            return o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty();
        }
        // Fallback: check if SOCKS port 9050 is listening
        let out = Command::new("ss").args(["-tlnp"]).output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).contains(":9050");
        }
        false
    }

    #[cfg(windows)]
    {
        let out = Command::new("tasklist").args(["/FI", "IMAGENAME eq tor.exe"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            return s.contains("tor.exe");
        }
        false
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

fn is_traffic_routed() -> bool {
    // Check if there's a torsocks/torify wrapper active or if iptables redirects to Tor
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "iptables -t nat -S OUTPUT 2>/dev/null | grep -i tor"])
            .output();
        if let Ok(o) = out {
            return String::from_utf8_lossy(&o.stdout).contains("tor");
        }
    }
    let _ = is_tor_running(); // just to have a reference
    false
}

/// Start the Tor daemon.
pub fn start() -> Result<String, String> {
    if is_tor_running() {
        return Ok("Tor is already running.".to_string());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Try systemctl first (Linux), then direct tor binary
        let out = Command::new("systemctl").args(["start", "tor"]).output();
        if let Ok(o) = out {
            if o.status.success() {
                return Ok("Tor started via systemctl.".to_string());
            }
        }
        // Direct launch
        let out = Command::new("tor")
            .args(["--RunAsDaemon", "1"])
            .output();
        match out {
            Ok(o) if o.status.success() => Ok("Tor daemon started.".to_string()),
            Ok(o) => Err(format!(
                "tor failed to start: {} (is it installed?)",
                String::from_utf8_lossy(&o.stderr)
            )),
            Err(e) => Err(format!("tor binary not found: {}", e)),
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("tor").spawn();
        match out {
            Ok(_) => Ok("Tor process started.".to_string()),
            Err(e) => Err(format!("tor.exe not found: {}", e)),
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}

/// Stop the Tor daemon.
pub fn stop() -> Result<String, String> {
    if !is_tor_running() {
        return Ok("Tor is not running.".to_string());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let out = Command::new("systemctl").args(["stop", "tor"]).output();
        if let Ok(o) = out {
            if o.status.success() {
                return Ok("Tor stopped via systemctl.".to_string());
            }
        }
        // Fallback: kill the process
        let out = Command::new("pkill").args(["-x", "tor"]).output();
        match out {
            Ok(o) if o.status.success() => Ok("Tor process killed.".to_string()),
            _ => Ok("No Tor process found.".to_string()),
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("taskkill").args(["/IM", "tor.exe", "/F"]).output();
        match out {
            Ok(o) if o.status.success() => Ok("Tor process killed.".to_string()),
            _ => Ok("No Tor process found.".to_string()),
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}

/// Route all outbound traffic through Tor using iptables (Linux only).
/// This sets up transparent proxying — all TCP traffic goes through Tor.
pub fn route_traffic() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        // Check if tor is running first
        if !is_tor_running() {
            return Err("Tor is not running. Start it first with: pledgeshield vpn tor start".to_string());
        }

        // Set up iptables NAT rules to redirect traffic through Tor
        // This is a simplified version of the Tor transparent proxy setup.
        let rules = [
            ("iptables -t nat -A OUTPUT -o lo -j RETURN", "skip loopback"),
            ("iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN", "skip localhost"),
            ("iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040", "redirect TCP to Tor"),
            ("iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353", "redirect DNS to Tor"),
        ];

        for (cmd, label) in &rules {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let out = Command::new(parts[0]).args(&parts[1..]).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => return Err(format!("route step '{}' failed: {}", label, String::from_utf8_lossy(&o.stderr))),
                Err(e) => return Err(format!("route step '{}' failed (need root?): {}", label, e)),
            }
        }
        Ok("Traffic routed through Tor (transparent proxy on ports 9040/5353).".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err("Traffic routing through Tor is only supported on Linux. Use torsocks <command> manually on macOS.".to_string())
    }
}

/// Remove Tor traffic routing rules.
pub fn unroute_traffic() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "iptables -t nat -D OUTPUT -o lo -j RETURN 2>/dev/null",
            "iptables -t nat -D OUTPUT -d 127.0.0.0/8 -j RETURN 2>/dev/null",
            "iptables -t nat -D OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040 2>/dev/null",
            "iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null",
        ];
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let _ = Command::new(parts[0]).args(&parts[1..]).output();
        }
        Ok("Tor traffic routing removed.".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err("Not applicable on this platform.".to_string())
    }
}

/// Get the current exit IP (as seen through Tor) to verify the circuit.
pub fn check_exit_ip() -> Option<String> {
    let out = Command::new("curl")
        .args(["-s", "--max-time", "10", "--socks5-hostname", "127.0.0.1:9050", "https://check.torproject.org/api/ip"])
        .output()
        .ok()?;
    let body = String::from_utf8_lossy(&out.stdout);
    // Response: {"IsTor":true,"IP":"x.x.x.x"}
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        v.get("IP").and_then(|ip| ip.as_str()).map(String::from)
    } else {
        None
    }
}

/// Check if Tor is installed.
pub fn is_installed() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Command::new("which").arg("tor").output()
            .map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(windows)]
    {
        Command::new("where").arg("tor").output()
            .map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
