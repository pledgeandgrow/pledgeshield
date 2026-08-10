use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

/// Audit firewall state — is it on, what's the default policy, what's open.
pub fn audit_firewall() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // UFW
        let ufw = Command::new("ufw").args(["status", "verbose"]).output();
        if let Ok(o) = ufw {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("inactive") || s.contains("Status: inactive") {
                findings.push(
                    Finding::new(
                        "fw-linux-ufw-off",
                        "UFW firewall is disabled",
                        Severity::Critical,
                        Category::Network,
                    )
                    .description("No firewall is active. All incoming connections are allowed.")
                    .recommendation("Run: pledgeshield harden firewall --enable")
                    .fixable(true),
                );
            } else if s.contains("Status: active") {
                // Check default policy
                if s.contains("Default:") {
                    if s.contains("deny (incoming)") {
                        // Good
                    } else if s.contains("allow (incoming)") {
                        findings.push(Finding::new(
                            "fw-linux-ufw-default-allow",
                            "UFW default incoming policy is ALLOW",
                            Severity::High,
                            Category::Network,
                        )
                        .description("UFW is active but allows all incoming traffic by default — effectively no protection.")
                        .recommendation("Run: pledgeshield harden firewall --harden")
                        .fixable(true));
                    }
                }
            }
        } else {
            // No UFW — check firewalld
            let fd = Command::new("systemctl")
                .args(["is-active", "firewalld"])
                .output();
            if let Ok(o) = fd {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.trim() == "inactive" || s.trim() == "failed" {
                    findings.push(
                        Finding::new(
                            "fw-linux-firewalld-off",
                            "firewalld is disabled",
                            Severity::Critical,
                            Category::Network,
                        )
                        .description("No firewall service is active (neither UFW nor firewalld).")
                        .recommendation("Run: pledgeshield harden firewall --enable")
                        .fixable(true),
                    );
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--getglobalstate"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("disabled") {
                findings.push(
                    Finding::new(
                        "fw-mac-off",
                        "macOS Application Firewall is disabled",
                        Severity::High,
                        Category::Network,
                    )
                    .description("The macOS built-in firewall is not enabled.")
                    .recommendation("Run: pledgeshield harden firewall --enable")
                    .fixable(true),
                );
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["advfirewall", "show", "allprofiles", "state"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let l = line.trim();
                if l.contains("OFF") {
                    findings.push(
                        Finding::new(
                            "fw-win-off",
                            "Windows Firewall is disabled for one or more profiles",
                            Severity::Critical,
                            Category::Network,
                        )
                        .description("Windows Firewall is OFF for at least one network profile.")
                        .recommendation("Run: pledgeshield harden firewall --enable")
                        .fixable(true),
                    );
                    break;
                }
            }
        }
    }

    findings
}

/// Enable the firewall on the current platform.
pub fn enable_firewall() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        // Try UFW first
        let out = Command::new("ufw").args(["--force", "enable"]).output();
        if let Ok(o) = out {
            if o.status.success() {
                return HardenResult {
                    action: "firewall-enable".to_string(),
                    success: true,
                    message: "UFW firewall enabled.".to_string(),
                    findings: vec![],
                };
            }
        }
        // Fall back to firewalld
        let out = Command::new("systemctl")
            .args(["enable", "--now", "firewalld"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-enable".to_string(),
                success: true,
                message: "firewalld enabled and started.".to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!(
                    "Failed to enable firewall: {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!("No firewall tool available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--setglobalstate", "on"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-enable".to_string(),
                success: true,
                message: "macOS Application Firewall enabled.".to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!(
                    "socketfilterfw failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!("socketfilterfw not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "state", "on"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-enable".to_string(),
                success: true,
                message: "Windows Firewall enabled for all profiles.".to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!("netsh failed: {}", String::from_utf8_lossy(&o.stderr)),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "firewall-enable".to_string(),
                success: false,
                message: format!("netsh not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "firewall-enable".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        }
    }
}

/// Harden the firewall: set default DROP/deny for inbound, allow only SSH (if running).
pub fn harden_firewall(dry_run: bool, allow_ssh: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    if dry_run {
        results.push(HardenResult {
            action: "firewall-harden".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would set default inbound policy to DROP/deny{}.",
                if allow_ssh {
                    ", allow SSH (port 22)"
                } else {
                    ""
                }
            ),
            findings: vec![],
        });
        return results;
    }

    #[cfg(target_os = "linux")]
    {
        // UFW approach
        let ufw_available = Command::new("ufw")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if ufw_available {
            // Default deny incoming, allow outgoing
            let _ = Command::new("ufw")
                .args(["default", "deny", "incoming"])
                .output();
            let _ = Command::new("ufw")
                .args(["default", "allow", "outgoing"])
                .output();

            if allow_ssh {
                let _ = Command::new("ufw").args(["allow", "22/tcp"]).output();
                results.push(HardenResult {
                    action: "firewall-allow-ssh".to_string(),
                    success: true,
                    message: "SSH (port 22/tcp) allowed through firewall.".to_string(),
                    findings: vec![],
                });
            }

            // Enable (in case it wasn't)
            let _ = Command::new("ufw").args(["--force", "enable"]).output();

            results.push(HardenResult {
                action: "firewall-harden".to_string(),
                success: true,
                message: "UFW: default incoming=deny, outgoing=allow.".to_string(),
                findings: vec![],
            });
        } else {
            // iptables approach
            let cmds = [
                ("iptables -P INPUT DROP", "set INPUT policy DROP"),
                ("iptables -P FORWARD DROP", "set FORWARD policy DROP"),
                ("iptables -P OUTPUT ACCEPT", "set OUTPUT policy ACCEPT"),
                (
                    "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "allow established connections",
                ),
                ("iptables -A INPUT -i lo -j ACCEPT", "allow loopback"),
            ];
            for (cmd, label) in &cmds {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                let out = Command::new(parts[0]).args(&parts[1..]).output();
                match out {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        results.push(HardenResult {
                            action: "firewall-harden".to_string(),
                            success: false,
                            message: format!(
                                "Failed: {} — {}",
                                label,
                                String::from_utf8_lossy(&o.stderr)
                            ),
                            findings: vec![],
                        });
                        return results;
                    }
                    Err(e) => {
                        results.push(HardenResult {
                            action: "firewall-harden".to_string(),
                            success: false,
                            message: format!("Failed to run iptables (need root?): {}", e),
                            findings: vec![],
                        });
                        return results;
                    }
                }
            }
            if allow_ssh {
                let _ = Command::new("iptables")
                    .args(["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
                    .output();
                results.push(HardenResult {
                    action: "firewall-allow-ssh".to_string(),
                    success: true,
                    message: "SSH (port 22/tcp) allowed.".to_string(),
                    findings: vec![],
                });
            }
            results.push(HardenResult {
                action: "firewall-harden".to_string(),
                success: true,
                message: "iptables: INPUT=DROP, FORWARD=DROP, OUTPUT=ACCEPT, established+loopback allowed.".to_string(),
                findings: vec![],
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Enable stealth mode + firewall
        let _ = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--setglobalstate", "on"])
            .output();
        let _ = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--setstealthmode", "on"])
            .output();
        results.push(HardenResult {
            action: "firewall-harden".to_string(),
            success: true,
            message: "macOS firewall enabled + stealth mode on (no ping response).".to_string(),
            findings: vec![],
        });
    }

    #[cfg(windows)]
    {
        // Enable all profiles + set default inbound to block
        let _ = Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "state", "on"])
            .output();
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,allowoutbound",
            ])
            .output();
        results.push(HardenResult {
            action: "firewall-harden".to_string(),
            success: true,
            message: "Windows Firewall: all profiles on, inbound=block, outbound=allow."
                .to_string(),
            findings: vec![],
        });
        if allow_ssh {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=PledgeShield-SSH",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=22",
                ])
                .output();
            results.push(HardenResult {
                action: "firewall-allow-ssh".to_string(),
                success: true,
                message: "SSH (port 22/tcp) allowed.".to_string(),
                findings: vec![],
            });
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        results.push(HardenResult {
            action: "firewall-harden".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        });
    }

    results
}

/// Disable the firewall entirely (restore to no filtering).
pub fn disable_firewall() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ufw").args(["--force", "disable"]).output();
        if let Ok(o) = out {
            if o.status.success() {
                return HardenResult {
                    action: "firewall-disable".to_string(),
                    success: true,
                    message: "UFW firewall disabled.".to_string(),
                    findings: vec![],
                };
            }
        }
        let out = Command::new("systemctl")
            .args(["disable", "--now", "firewalld"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-disable".to_string(),
                success: true,
                message: "firewalld disabled.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "firewall-disable".to_string(),
                success: false,
                message: "Could not disable firewall (no tool found?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--setglobalstate", "off"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-disable".to_string(),
                success: true,
                message: "macOS firewall disabled.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "firewall-disable".to_string(),
                success: false,
                message: "Failed to disable macOS firewall.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "state", "off"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "firewall-disable".to_string(),
                success: true,
                message: "Windows Firewall disabled for all profiles.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "firewall-disable".to_string(),
                success: false,
                message: "Failed to disable Windows Firewall.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "firewall-disable".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        }
    }
}
