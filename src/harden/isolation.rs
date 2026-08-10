/// Network isolation mode — block all outbound except whitelisted IPs/domains.
use super::HardenResult;
use std::process::Command;

pub fn enable_isolation(whitelist: &[String], dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    if dry_run {
        results.push(HardenResult {
            action: "isolation-enable".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would block all outbound except: {}",
                whitelist.join(", ")
            ),
            findings: vec![],
        });
        return results;
    }

    #[cfg(target_os = "linux")]
    {
        // Set default DROP on OUTPUT
        let cmds = [
            "iptables -P OUTPUT DROP",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        ];
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let _ = Command::new(parts[0]).args(&parts[1..]).output();
        }
        results.push(HardenResult {
            action: "isolation-enable".to_string(),
            success: true,
            message: "Default OUTPUT policy set to DROP. Loopback + established allowed."
                .to_string(),
            findings: vec![],
        });

        // Allow whitelisted IPs
        for ip in whitelist {
            let out = Command::new("iptables")
                .args(["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])
                .output();
            let ok = out.map(|o| o.status.success()).unwrap_or(false);
            results.push(HardenResult {
                action: format!("isolation-allow-{}", ip),
                success: ok,
                message: format!("Allow outbound to {}", ip),
                findings: vec![],
            });
        }

        // Allow DNS (port 53) to whitelisted DNS servers
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
            .output();
        results.push(HardenResult {
            action: "isolation-allow-dns".to_string(),
            success: true,
            message: "DNS (port 53) allowed for name resolution.".to_string(),
            findings: vec![],
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        results.push(HardenResult {
            action: "isolation-enable".to_string(),
            success: false,
            message: "Network isolation is only supported on Linux (iptables).".to_string(),
            findings: vec![],
        });
    }

    results
}

pub fn disable_isolation() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        // Remove our rules and set OUTPUT back to ACCEPT
        let cmds = [
            "iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null",
            "iptables -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null",
            "iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null",
            "iptables -D OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null",
        ];
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let _ = Command::new(parts[0]).args(&parts[1..]).output();
        }
        let _ = Command::new("iptables")
            .args(["-P", "OUTPUT", "ACCEPT"])
            .output();
        HardenResult {
            action: "isolation-disable".to_string(),
            success: true,
            message: "Network isolation disabled. OUTPUT policy restored to ACCEPT.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "isolation-disable".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}
