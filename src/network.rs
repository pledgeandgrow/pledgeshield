use crate::models::{Category, Finding, Severity};

/// Check network interface exposure: public IP, UPnP, open ports.
pub fn audit_network_exposure() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for UPnP enabled
    if let Some(upnp_finding) = check_upnp() {
        findings.push(upnp_finding);
    }

    // Check for public IP exposure
    if let Some(public_ip_finding) = check_public_ip_exposure() {
        findings.push(public_ip_finding);
    }

    // Check for listening on all interfaces
    if let Some(wildcard_finding) = check_wildcard_listening() {
        findings.push(wildcard_finding);
    }

    findings
}

/// Check if UPnP (Universal Plug and Play) is enabled.
fn check_upnp() -> Option<Finding> {
    #[cfg(windows)]
    {
        // Check Windows UPnP service
        let output = std::process::Command::new("sc")
            .args(["query", "upnphost"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("RUNNING") {
            return Some(Finding::new(
                "net-upnp-enabled",
                "UPnP Service Running",
                Severity::Medium,
                Category::Network,
            )
            .description("Universal Plug and Play (UPnP) service is running. UPnP can allow automatic port forwarding without user consent, potentially exposing services to the internet.")
            .recommendation("Disable the UPnP Device Host service if not needed.")
            .fixable(true)
            .metadata("service", "upnphost"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Check for miniupnpd or linux-igd
        let output = std::process::Command::new("systemctl")
            .args(["is-active", "miniupnpd"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim() == "active" {
            return Some(Finding::new(
                "net-upnp-enabled",
                "UPnP Service Running",
                Severity::Medium,
                Category::Network,
            )
            .description("UPnP daemon (miniupnpd) is active. UPnP can allow automatic port forwarding without user consent.")
            .recommendation("Disable miniupnpd if not required: sudo systemctl disable miniupnpd")
            .fixable(true)
            .metadata("service", "miniupnpd"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check for UPnP on macOS (usually via mDNSResponder)
        let output = std::process::Command::new("launchctl")
            .args(["list", "com.apple.mDNSResponder"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("PID") {
            // mDNSResponder is running — check if NAT/UPnP is enabled
            let nat_output = std::process::Command::new("defaults")
                .args(["read", "/Library/Preferences/com.apple.nat", "NatUpnpEnabled"])
                .output()
                .ok()?;

            let nat_stdout = String::from_utf8_lossy(&nat_output.stdout);
            if nat_stdout.trim() == "1" {
                return Some(Finding::new(
                    "net-upnp-enabled",
                    "UPnP Enabled on macOS",
                    Severity::Medium,
                    Category::Network,
                )
                .description("UPnP is enabled via macOS NAT settings. This can allow automatic port forwarding.")
                .recommendation("Disable UPnP in System Settings > Sharing > Internet Sharing.")
                .metadata("service", "mDNSResponder"));
            }
        }
    }

    None
}

/// Check if the machine has a public IP address exposed.
fn check_public_ip_exposure() -> Option<Finding> {
    // Check if any network interface has a public (non-RFC1918) IP
    #[cfg(windows)]
    {
        let output = std::process::Command::new("ipconfig")
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("IPv4 Address") || line.contains("IPv6 Address") {
                if let Some(ip) = line.split(':').nth(1) {
                    let ip = ip.trim();
                    if is_public_ip(ip) {
                        return Some(Finding::new(
                            "net-public-ip-exposed",
                            "Public IP Address Detected",
                            Severity::Low,
                            Category::Network,
                        )
                        .description(&format!("Interface has public IP address: {}. This machine is directly accessible from the internet.", ip))
                        .recommendation("Ensure firewall is enabled and only necessary ports are open.")
                        .metadata("ip", ip));
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let output = std::process::Command::new("ifconfig")
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("inet ") || line.starts_with("inet6 ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[1];
                    if is_public_ip(ip) {
                        return Some(Finding::new(
                            "net-public-ip-exposed",
                            "Public IP Address Detected",
                            Severity::Low,
                            Category::Network,
                        )
                        .description(&format!("Interface has public IP address: {}. This machine is directly accessible from the internet.", ip))
                        .recommendation("Ensure firewall is enabled and only necessary ports are open.")
                        .metadata("ip", ip));
                    }
                }
            }
        }
    }

    None
}

/// Check if any services are listening on 0.0.0.0 (all interfaces).
fn check_wildcard_listening() -> Option<Finding> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("netstat")
            .args(["-an"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let wildcard_count = stdout
            .lines()
            .filter(|l| l.contains("0.0.0.0:") && l.contains("LISTENING"))
            .count();

        if wildcard_count > 0 {
            return Some(Finding::new(
                "net-wildcard-listening",
                "Services Listening on All Interfaces",
                Severity::Medium,
                Category::Network,
            )
            .description(&format!("{} service(s) are listening on 0.0.0.0 (all interfaces). This exposes them to network access.", wildcard_count))
            .recommendation("Bind services to localhost (127.0.0.1) when remote access is not needed.")
            .metadata("count", &wildcard_count.to_string()));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let output = std::process::Command::new("ss")
            .args(["-tlnp"])
            .output()
            .or_else(|_| std::process::Command::new("netstat").args(["-tlnp"]).output())
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let wildcard_count = stdout
            .lines()
            .filter(|l| l.contains("0.0.0.0:") || l.contains(":::"))
            .filter(|l| l.contains("LISTEN"))
            .count();

        if wildcard_count > 0 {
            return Some(Finding::new(
                "net-wildcard-listening",
                "Services Listening on All Interfaces",
                Severity::Medium,
                Category::Network,
            )
            .description(&format!("{} service(s) are listening on 0.0.0.0 or [::] (all interfaces).", wildcard_count))
            .recommendation("Bind services to localhost (127.0.0.1) when remote access is not needed.")
            .metadata("count", &wildcard_count.to_string()));
        }
    }

    None
}

/// Check if an IP address is public (not RFC1918 private).
fn is_public_ip(ip: &str) -> bool {
    let ip = ip.split('%').next().unwrap_or(ip); // Remove zone ID

    // IPv4 checks
    if let Some(ipv4) = ip.strip_prefix("::ffff:") {
        return is_public_ipv4(ipv4);
    }
    if !ip.contains(':') {
        return is_public_ipv4(ip);
    }

    // IPv6: check for link-local, unique local, loopback
    if ip.starts_with("fe80::") || ip.starts_with("fc00::") || ip.starts_with("fd00::") || ip == "::1" {
        return false;
    }

    // Assume public for other IPv6
    true
}

fn is_public_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }

    // RFC1918 private ranges
    if octets[0] == 10 { return false; }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return false; }
    if octets[0] == 192 && octets[1] == 168 { return false; }

    // Loopback
    if octets[0] == 127 { return false; }

    // Link-local
    if octets[0] == 169 && octets[1] == 254 { return false; }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_public_ipv4_private() {
        assert!(!is_public_ipv4("10.0.0.1"));
        assert!(!is_public_ipv4("172.16.0.1"));
        assert!(!is_public_ipv4("172.31.255.255"));
        assert!(!is_public_ipv4("192.168.1.1"));
        assert!(!is_public_ipv4("127.0.0.1"));
        assert!(!is_public_ipv4("169.254.1.1"));
    }

    #[test]
    fn test_is_public_ipv4_public() {
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(is_public_ipv4("1.1.1.1"));
        assert!(is_public_ipv4("203.0.113.1"));
    }

    #[test]
    fn test_is_public_ip_ipv6() {
        assert!(!is_public_ip("::1"));
        assert!(!is_public_ip("fe80::1"));
        assert!(!is_public_ip("fc00::1"));
        assert!(!is_public_ip("fd00::1"));
        assert!(is_public_ip("2001:db8::1"));
    }

    #[test]
    fn test_is_public_ip_ipv4_mapped() {
        assert!(!is_public_ip("::ffff:192.168.1.1"));
        assert!(is_public_ip("::ffff:8.8.8.8"));
    }
}
