/// VPN / proxy connection management.
/// Supports WireGuard (wg-quick) and OpenVPN.
pub mod tor;

use std::process::Command;

/// VPN provider type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnType {
    WireGuard,
    OpenVpn,
    None,
}

impl std::fmt::Display for VpnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnType::WireGuard => write!(f, "WireGuard"),
            VpnType::OpenVpn => write!(f, "OpenVPN"),
            VpnType::None => write!(f, "None"),
        }
    }
}

/// Current VPN status.
#[derive(Debug, Clone)]
pub struct VpnStatus {
    pub active: bool,
    pub vpn_type: VpnType,
    pub interface: Option<String>,
    pub config: Option<String>,
    /// Public IP if detectable
    pub public_ip: Option<String>,
}

impl std::fmt::Display for VpnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.active {
            return write!(f, "VPN: Inactive (no tunnel detected)");
        }
        write!(
            f,
            "VPN: Active [{}] iface={} config={} ip={}",
            self.vpn_type,
            self.interface.as_deref().unwrap_or("?"),
            self.config.as_deref().unwrap_or("?"),
            self.public_ip.as_deref().unwrap_or("?"),
        )
    }
}

/// Detect the current VPN status by checking for WireGuard/OpenVPN interfaces.
pub fn status() -> VpnStatus {
    // Check WireGuard
    let wg = Command::new("wg").arg("show").output();
    if let Ok(o) = wg {
        if o.status.success() {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.trim().is_empty() {
                // First line is the interface name: "interface: wg0"
                let iface = stdout
                    .lines()
                    .next()
                    .and_then(|l| l.strip_prefix("interface: "))
                    .map(String::from);
                return VpnStatus {
                    active: true,
                    vpn_type: VpnType::WireGuard,
                    interface: iface,
                    config: None,
                    public_ip: detect_public_ip(),
                };
            }
        }
    }

    // Check OpenVPN (look for tun* interfaces or the openvpn process)
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let out = Command::new("pgrep").args(["-a", "openvpn"]).output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.trim().is_empty() {
                // Extract config path from the process args
                let config = stdout
                    .lines()
                    .next()
                    .and_then(|l| l.split("--config ").nth(1))
                    .map(|s| s.trim().to_string());
                return VpnStatus {
                    active: true,
                    vpn_type: VpnType::OpenVpn,
                    interface: Some("tun0".to_string()),
                    config,
                    public_ip: detect_public_ip(),
                };
            }
        }
    }

    VpnStatus {
        active: false,
        vpn_type: VpnType::None,
        interface: None,
        config: None,
        public_ip: None,
    }
}

/// List available WireGuard configs (in /etc/wireguard/*.conf).
pub fn list_wireguard_configs() -> Vec<String> {
    let mut configs = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/etc/wireguard") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".conf") {
                    configs.push(name.trim_end_matches(".conf").to_string());
                }
            }
        }
    }
    configs
}

/// Connect to a WireGuard VPN by config name (requires root).
pub fn connect_wireguard(config: &str) -> Result<String, String> {
    let out = Command::new("wg-quick").args(["up", config]).output();
    match out {
        Ok(o) if o.status.success() => Ok(format!("WireGuard '{}' connected.", config)),
        Ok(o) => Err(format!(
            "wg-quick up failed: {} (need root?)",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("wg-quick not installed: {}", e)),
    }
}

/// Disconnect a WireGuard VPN.
pub fn disconnect_wireguard(config: &str) -> Result<String, String> {
    let out = Command::new("wg-quick").args(["down", config]).output();
    match out {
        Ok(o) if o.status.success() => Ok(format!("WireGuard '{}' disconnected.", config)),
        Ok(o) => Err(format!(
            "wg-quick down failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("wg-quick not installed: {}", e)),
    }
}

/// Connect to an OpenVPN config file.
pub fn connect_openvpn(config_path: &str) -> Result<String, String> {
    let out = Command::new("openvpn")
        .args(["--config", config_path, "--daemon"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            Ok(format!("OpenVPN '{}' started (daemonized).", config_path))
        }
        Ok(o) => Err(format!(
            "openvpn failed: {} (need root?)",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("openvpn not installed: {}", e)),
    }
}

/// Disconnect OpenVPN (kills the daemon).
pub fn disconnect_openvpn() -> Result<String, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let out = Command::new("pkill").args(["-x", "openvpn"]).output();
        match out {
            Ok(o) if o.status.success() => Ok("OpenVPN daemon stopped.".to_string()),
            _ => Ok("No OpenVPN process found.".to_string()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("OpenVPN disconnect not supported on this platform".to_string())
    }
}

/// Detect the public IP by querying an external service.
/// Returns None if offline or the request fails.
fn detect_public_ip() -> Option<String> {
    // Synchronous-ish: spawn curl (avoid pulling in a sync HTTP client).
    let out = Command::new("curl")
        .args(["-s", "--max-time", "3", "https://api.ipify.org"])
        .output()
        .ok()?;
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if ip.is_empty() || ip.contains('<') {
        None
    } else {
        Some(ip)
    }
}

/// A kill switch: if the VPN goes down, block all traffic until it's back up.
/// Implemented as a simple firewall rule set on Linux (iptables).
pub fn enable_kill_switch() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        // Block all traffic except loopback and the WireGuard interface.
        // This is a simplified kill switch.
        let rules = [
            ("iptables -A OUTPUT -o lo -j ACCEPT", "allow loopback out"),
            ("iptables -A OUTPUT -o wg+ -j ACCEPT", "allow wg out"),
            ("iptables -A OUTPUT -j DROP", "drop everything else out"),
        ];
        for (cmd, label) in &rules {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let out = Command::new(parts[0]).args(&parts[1..]).output();
            match out {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    return Err(format!(
                        "kill-switch step '{}' failed: {}",
                        label,
                        String::from_utf8_lossy(&o.stderr)
                    ))
                }
                Err(e) => return Err(format!("kill-switch step '{}' failed to run: {}", label, e)),
            }
        }
        Ok("Kill switch enabled: all non-VPN outbound traffic blocked.".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Kill switch currently only supported on Linux.".to_string())
    }
}

pub fn disable_kill_switch() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "iptables -D OUTPUT -j DROP 2>/dev/null; iptables -D OUTPUT -o wg+ -j ACCEPT 2>/dev/null; iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null"])
            .output();
        match out {
            Ok(_) => Ok("Kill switch disabled.".to_string()),
            Err(e) => Err(format!("Failed to remove kill switch rules: {}", e)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Kill switch currently only supported on Linux.".to_string())
    }
}
