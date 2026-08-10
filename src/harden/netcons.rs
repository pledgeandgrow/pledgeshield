/// Network connection auditor — list all outbound connections with process names.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_connections() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Use ss to get all connections with process info
        let out = Command::new("ss").args(["-tunp"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }

                let state = parts.get(0).unwrap_or(&"");
                let _local = parts.get(4).unwrap_or(&"");
                let peer = parts.get(5).unwrap_or(&"");

                // Only look at ESTAB connections
                if state != &"ESTAB" {
                    continue;
                }

                // Extract peer IP and port
                if let Some((ip, port)) = peer.rsplit_once(':') {
                    // Flag connections to unusual ports
                    if let Ok(p) = port.parse::<u16>() {
                        let suspicious_ports =
                            [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 1234, 4321];
                        if suspicious_ports.contains(&p) {
                            findings.push(Finding::new(
                                &format!("netconn-suspicious-port-{}", p),
                                &format!("Connection to {}:{} (suspicious port)", ip, p),
                                Severity::High,
                                Category::Network,
                            )
                            .description("An established connection to a suspicious port commonly used by malware/reverse shells."));
                        }
                    }

                    // Flag connections to private IP ranges that aren't local
                    if ip.starts_with("10.") || ip.starts_with("192.168.") {
                        // Normal for LAN — skip
                    } else if !ip.starts_with("127.") && !ip.starts_with("::1") {
                        // External connection — note it
                        // Only flag if we can identify the process
                        if line.contains("users:") {
                            let proc_name = line
                                .split("users:")
                                .nth(1)
                                .and_then(|s| s.split('"').nth(1))
                                .unwrap_or("unknown");
                            // Flag if it's an unusual process making external connections
                            let unusual = [
                                "nc", "ncat", "netcat", "socat", "python", "perl", "ruby", "bash",
                                "sh",
                            ];
                            if unusual.contains(&proc_name) {
                                findings.push(Finding::new(
                                    &format!("netconn-unusual-proc-{}", proc_name),
                                    &format!("{} has external connection to {}:{}", proc_name, ip, port),
                                    Severity::Medium,
                                    Category::Network,
                                )
                                .description("An unusual process is making external network connections. This could be a reverse shell or data exfiltration."));
                            }
                        }
                    }
                }
            }
        }

        // Check for listening on all interfaces (0.0.0.0)
        let out = Command::new("ss").args(["-tlnp"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let local = parts[3];
                if local.starts_with("0.0.0.0:")
                    || local.starts_with("*:")
                    || local.starts_with("[::]:")
                {
                    let port = local.rsplit(':').next().unwrap_or("?");
                    // Skip common safe ports
                    let safe_ports = ["22", "80", "443", "53"];
                    if !safe_ports.contains(&port) {
                        findings.push(Finding::new(
                            &format!("netconn-listen-all-{}", port),
                            &format!("Service listening on all interfaces: port {}", port),
                            Severity::Low,
                            Category::Network,
                        )
                        .description("A service is listening on all interfaces (0.0.0.0). If it doesn't need external access, bind to 127.0.0.1."));
                    }
                }
            }
        }
    }

    findings
}

/// Print a table of all current connections.
pub fn list_connections() -> Vec<String> {
    let mut lines = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ss").args(["-tunp"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            lines.push(format!(
                "{:<8} {:<22} {:<22} {}",
                "PROTO", "LOCAL", "PEER", "PROCESS"
            ));
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }
                let proto = parts[0];
                let _state = parts[1];
                let local = parts.get(4).unwrap_or(&"");
                let peer = parts.get(5).unwrap_or(&"");
                let proc = line
                    .split("users:")
                    .nth(1)
                    .and_then(|s| s.split('"').nth(1))
                    .unwrap_or("-");
                lines.push(format!("{:<8} {:<22} {:<22} {}", proto, local, peer, proc));
            }
        }
    }

    lines
}
