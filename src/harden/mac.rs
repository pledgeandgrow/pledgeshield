/// MAC address spoofer — randomize or set a network interface's MAC address.
use std::process::Command;

/// List available network interfaces (non-loopback, up or down).
pub fn list_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name != "lo" {
                        ifaces.push(name.to_string());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("ifconfig").arg("-l").output() {
            let list = String::from_utf8_lossy(&out.stdout);
            for name in list.split_whitespace() {
                if name != "lo0" {
                    ifaces.push(name.to_string());
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = Command::new("ipconfig"); // suppress unused warning
    }

    ifaces
}

/// Get the current MAC address of an interface.
pub fn get_mac(iface: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/sys/class/net/{}/address", iface);
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read MAC for {}: {}", iface, e))
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("ifconfig").arg(iface).output();
        match out {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ether ") {
                        return Ok(trimmed[6..].trim().to_string());
                    }
                }
                Err(format!("No MAC address found for {}", iface))
            }
            Err(e) => Err(format!("ifconfig failed: {}", e)),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = iface;
        Err("MAC address retrieval is only supported on Linux and macOS.".to_string())
    }
}

/// Generate a random locally-administered MAC address.
fn random_mac() -> String {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;

    // Simple LCG for pseudo-random bytes
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((state >> 33) & 0xFF) as u8
    };

    let b: [u8; 6] = [next(), next(), next(), next(), next(), next()];
    // Set locally-administered bit (bit 1 of first byte) and clear multicast bit (bit 0)
    let first = (b[0] & 0xFC) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        first, b[1], b[2], b[3], b[4], b[5]
    )
}

/// Spoof the MAC address of an interface. If `new_mac` is None, a random one is generated.
pub fn spoof_mac(iface: &str, new_mac: Option<&str>) -> String {
    let mac = new_mac.map(|m| m.to_string()).unwrap_or_else(random_mac);

    #[cfg(target_os = "linux")]
    {
        // Bring interface down, set MAC, bring back up
        let _down = Command::new("ip").args(["link", "set", iface, "down"]).output();
        let out = Command::new("ip").args(["link", "set", iface, "address", &mac]).output();
        let _up = Command::new("ip").args(["link", "set", iface, "up"]).output();

        let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if ok {
            format!("  ✓ {} MAC set to {}", iface, mac)
        } else {
            format!("  ✗ Failed to set MAC on {} (need root?)", iface)
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("ifconfig").args([iface, "ether", &mac]).output();
        let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if ok {
            format!("  ✓ {} MAC set to {}", iface, mac)
        } else {
            format!("  ✗ Failed to set MAC on {} (need root?)", iface)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (iface, mac);
        "  ✗ MAC spoofing is only supported on Linux and macOS.".to_string()
    }
}

/// Restore the original (permanent) MAC address of an interface.
pub fn restore_mac(iface: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        // On Linux, the permanent MAC can often be read from /sys/class/net/<iface>/address
        // before spoofing, but we don't store it. Best effort: reload the driver.
        let _down = Command::new("ip").args(["link", "set", iface, "down"]).output();

        // Try to read the permanent address from ethtool
        let perm = Command::new("ethtool")
            .args(["-P", iface])
            .output()
            .ok()
            .and_then(|o| {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines() {
                    if line.contains("Permanent address:") {
                        return Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                    }
                }
                None
            });

        if let Some(p) = perm {
            let out = Command::new("ip").args(["link", "set", iface, "address", &p]).output();
            let _up = Command::new("ip").args(["link", "set", iface, "up"]).output();
            let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
            if ok {
                return format!("  ✓ {} MAC restored to {}", iface, p);
            }
        }

        let _up = Command::new("ip").args(["link", "set", iface, "up"]).output();
        format!("  ⚠ Could not determine permanent MAC for {}. A reboot may fully restore it.", iface)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = iface;
        "  ⚠ On macOS, a full reboot restores the original MAC address.".to_string()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = iface;
        "  ✗ MAC restoration is only supported on Linux and macOS.".to_string()
    }
}
