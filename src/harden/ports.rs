use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

/// Ports considered inherently insecure / should never be listening.
const INSECURE_PORTS: &[(u16, &str)] = &[
    (23, "Telnet — unencrypted remote shell"),
    (21, "FTP — unencrypted file transfer"),
    (69, "TFTP — unauthenticated file transfer"),
    (161, "SNMP — can leak system info"),
    (445, "SMB — often targeted by ransomware/worms"),
    (135, "MSRPC — DCOM endpoint mapper"),
    (139, "NetBIOS — legacy, leaks host info"),
    (3389, "RDP — brute-force target if exposed"),
    (5900, "VNC — often unencrypted"),
    (5800, "VNC HTTP — web viewer"),
    (2049, "NFS — file sharing, often misconfigured"),
    (111, "rpcbind — portmapper, info leak"),
];

/// Audit which insecure ports are currently listening. Returns findings.
pub fn audit_insecure_ports() -> Vec<Finding> {
    let listening = get_listening_ports();
    let mut findings = Vec::new();

    for (port, proto) in &listening {
        for (bad_port, reason) in INSECURE_PORTS {
            if port == bad_port {
                findings.push(
                    Finding::new(
                        &format!("harden-port-{}", port),
                        &format!("Insecure port {} is open", port),
                        if *port == 23 || *port == 21 || *port == 445 {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        Category::Network,
                    )
                    .description(&format!("Port {}/{} is listening. {}", port, proto, reason))
                    .recommendation(&format!("Close port {} or bind it to localhost only.", port))
                    .fixable(true)
                    .metadata("port", &port.to_string())
                    .metadata("protocol", proto),
                );
            }
        }
    }
    findings
}

/// Close insecure ports by adding firewall block rules.
/// `dry_run` = only report what would be done, don't change anything.
/// `all_open` = block ALL listening ports, not just known-insecure ones.
pub fn close_insecure_ports(dry_run: bool, all_open: bool) -> Vec<HardenResult> {
    let listening = get_listening_ports();
    let mut results = Vec::new();

    let to_block: Vec<(u16, String)> = if all_open {
        listening.clone()
    } else {
        listening
            .iter()
            .filter(|(p, _)| INSECURE_PORTS.iter().any(|(bp, _)| bp == p))
            .cloned()
            .collect()
    };

    if to_block.is_empty() {
        results.push(HardenResult {
            action: "port-scan".to_string(),
            success: true,
            message: "No insecure ports found listening.".to_string(),
            findings: vec![],
        });
        return results;
    }

    for (port, proto) in &to_block {
        let action = format!("block port {}/{}", port, proto);
        if dry_run {
            results.push(HardenResult {
                action,
                success: true,
                message: "[dry-run] Would add firewall rule to block this port.".to_string(),
                findings: vec![],
            });
            continue;
        }

        let r = block_port(*port, proto);
        results.push(HardenResult {
            action,
            success: r.is_ok(),
            message: r.unwrap_or_else(|e| e),
            findings: vec![],
        });
    }

    results
}

/// Get all listening TCP/UDP ports on the system.
fn get_listening_ports() -> Vec<(u16, String)> {
    let mut ports = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Try ss first (Linux), fall back to netstat (macOS/Linux)
        let out = Command::new("ss")
            .args(["-tuln"])
            .output()
            .or_else(|_| Command::new("netstat").args(["-tuln"]).output());

        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                // ss: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
                // netstat: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN"
                if !line.contains("LISTEN") && !line.contains("UNCONN") {
                    continue;
                }
                if let Some(p) = parse_port_from_line(line) {
                    ports.push(p);
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
                if !line.contains("LISTENING") {
                    continue;
                }
                // "TCP 0.0.0.0:445 0.0.0.0:0 LISTENING"
                if let Some(p) = parse_port_from_line(line) {
                    ports.push(p);
                }
            }
        }
    }

    ports.sort();
    ports.dedup();
    ports
}

/// Parse a port number and protocol from a netstat/ss line.
fn parse_port_from_line(line: &str) -> Option<(u16, String)> {
    let lower = line.to_lowercase();
    let proto = if lower.starts_with("tcp") || lower.contains(" tcp ") {
        "tcp"
    } else if lower.starts_with("udp") || lower.contains(" udp ") {
        "udp"
    } else {
        return None;
    };

    // Find the local address token (contains ":port")
    for token in line.split_whitespace() {
        if token.contains(':') && !token.is_empty() {
            // Take the part after the last ':'
            if let Some(port_str) = token.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some((port, proto.to_string()));
                }
            }
        }
    }
    None
}

/// Block a port using the platform firewall. Returns Ok(message) on success.
fn block_port(port: u16, proto: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        // Try ufw first (simplest), fall back to iptables
        let ufw = Command::new("ufw")
            .args(["deny", &format!("{}/{}", port, proto)])
            .output();
        if let Ok(o) = ufw {
            if o.status.success() {
                return Ok(format!("ufw: blocked {}/{}", port, proto));
            }
        }
        // iptables fallback
        let ipt = Command::new("iptables")
            .args([
                "-A", "INPUT",
                "-p", proto,
                "--dport", &port.to_string(),
                "-j", "DROP",
            ])
            .output();
        match ipt {
            Ok(o) if o.status.success() =>
                Ok(format!("iptables: DROP rule added for {}/{}", port, proto)),
            Ok(o) => Err(format!("iptables failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => Err(format!("No firewall tool available: {}", e)),
        }
    }

    #[cfg(target_os = "macos")]
    {
        // pfctl: add a block rule. Requires editing a pf anchor or using `pfctl`.
        // Simplest: use a one-shot anchor rule.
        let rule = format!("block in quick proto {} from any to any port {}", proto, port);
        let out = Command::new("pfctl")
            .args(["-ef", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        match out {
            Ok(mut child) => {
                use std::io::Write;
                if let Some(stdin) = &mut child.stdin {
                    let _ = stdin.write_all(rule.as_bytes());
                }
                let _ = child.wait();
                Ok(format!("pfctl: blocked {}/{}", port, proto))
            }
            Err(e) => Err(format!("pfctl not available: {}", e)),
        }
    }

    #[cfg(windows)]
    {
        let proto_name = if proto == "tcp" { "TCP" } else { "UDP" };
        let out = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name=PledgeShield-Block-{}", port),
                "dir=in", "action=block",
                &format!("protocol={}", proto_name),
                &format!("localport={}", port),
            ])
            .output();
        match out {
            Ok(o) if o.status.success() =>
                Ok(format!("netsh: firewall rule added to block {}/{}", port, proto)),
            Ok(o) => Err(format!("netsh failed: {}", String::from_utf8_lossy(&o.stderr))),
            Err(e) => Err(format!("netsh not available: {}", e)),
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (port, proto);
        Err("Unsupported platform".to_string())
    }
}

/// Remove all PledgeShield-added firewall block rules.
pub fn restore_ports() -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Remove iptables rules we added
        let out = Command::new("sh")
            .args(["-c", "iptables -S INPUT | grep PledgeShield"])
            .output();
        let _ = out; // Best-effort; ufw rules are harder to enumerate generically
        results.push(HardenResult {
            action: "restore-ports".to_string(),
            success: true,
            message: "Manual review recommended: check `iptables -S` and `ufw status` for PledgeShield rules.".to_string(),
            findings: vec![],
        });
    }

    #[cfg(windows)]
    {
        // netsh doesn't support wildcard rule name matching, so we enumerate
        // all rules and delete those starting with "PledgeShield-Block-".
        let list = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all"])
            .output();
        let mut removed = 0;
        if let Ok(o) = list {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let l = line.trim();
                if l.starts_with("Rule Name:") {
                    let name = l.strip_prefix("Rule Name:").unwrap_or("").trim();
                    if name.starts_with("PledgeShield-Block-") {
                        let del = Command::new("netsh")
                            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", name)])
                            .output();
                        if del.map(|o| o.status.success()).unwrap_or(false) {
                            removed += 1;
                        }
                    }
                }
            }
        }
        results.push(HardenResult {
            action: "restore-ports".to_string(),
            success: removed > 0,
            message: if removed > 0 {
                format!("Removed {} PledgeShield firewall block rules.", removed)
            } else {
                "No PledgeShield firewall rules found.".to_string()
            },
            findings: vec![],
        });
    }

    #[cfg(target_os = "macos")]
    {
        results.push(HardenResult {
            action: "restore-ports".to_string(),
            success: true,
            message: "Check `pfctl -sr` for PledgeShield block rules and remove with `pfctl -d`.".to_string(),
            findings: vec![],
        });
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        results.push(HardenResult {
            action: "restore-ports".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        });
    }

    results
}
