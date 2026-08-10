/// Rogue DHCP detector — monitor for DHCP responses from non-router sources.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_rogue_dhcp() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check current DHCP lease info
        let lease_files = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/NetworkManager/dhclient-*.lease",
        ];
        for pattern in &lease_files {
            let out = Command::new("sh")
                .args(["-c", &format!("cat {} 2>/dev/null", pattern)])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                // Look for DHCP server IP
                for line in s.lines() {
                    if line.contains("dhcp-server-identifier") {
                        let server_ip = line
                            .split(' ')
                            .nth(2)
                            .unwrap_or("")
                            .trim_end_matches(';')
                            .trim_end_matches('"');
                        if !server_ip.is_empty() {
                            // Check if this is the expected gateway
                            let gateway = get_default_gateway();
                            if let Some(gw) = gateway {
                                if server_ip != gw {
                                    findings.push(Finding::new(
                                        "rogue-dhcp-server",
                                        &format!("DHCP server {} doesn't match gateway {}", server_ip, gw),
                                        Severity::High,
                                        Category::Network,
                                    )
                                    .description("A DHCP server that doesn't match your gateway may be a rogue DHCP server trying to redirect your traffic (MITM attack)."));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for multiple DHCP offers (would indicate a rogue server)
        // This requires active monitoring — just note if monitoring is needed
        let out = Command::new("which").arg("dhcpdump").output();
        if !out.map(|o| o.status.success()).unwrap_or(false) {
            findings.push(Finding::new(
                "rogue-dhcp-no-monitor",
                "No DHCP monitoring tool installed",
                Severity::Low,
                Category::Network,
            )
            .description("Install dhcpdump or dhcpstarved to actively monitor for rogue DHCP servers: sudo apt install dhcpdump"));
        }
    }

    findings
}

fn get_default_gateway() -> Option<String> {
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
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
