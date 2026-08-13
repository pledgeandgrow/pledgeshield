use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

/// Audit identity/privacy exposure — things that leak who you are.
pub fn audit_identity_exposure() -> Vec<Finding> {
    let mut findings = Vec::new();

    audit_dns(findings.as_mut());
    audit_telemetry(findings.as_mut());
    audit_hostname(findings.as_mut());

    findings
}

fn audit_dns(findings: &mut Vec<Finding>) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let l = line.trim();
                if l.starts_with("nameserver ") {
                    let ns = l.strip_prefix("nameserver ").unwrap_or("").trim();
                    // Flag well-known ISP/default DNS that may log queries
                    let risky = matches!(
                        ns,
                        "192.168.0.1"
                            | "192.168.1.1"
                            | "10.0.0.1"
                            | "208.67.222.222"
                            | "208.67.220.220" // OpenDNS (logs)
                    );
                    let is_isp = ns.starts_with("192.168.")
                        || ns.starts_with("10.")
                        || ns.starts_with("172.");
                    if risky || is_isp {
                        findings.push(
                            Finding::new(
                                "identity-dns-default",
                                "Default/local DNS server in use",
                                Severity::Medium,
                                Category::Network,
                            )
                            .description(&format!(
                                "DNS queries go to {} (a local or logging resolver). \
                                 Your ISP or this resolver can see and log every domain you visit.",
                                ns
                            ))
                            .recommendation("Use a privacy-respecting DNS: 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9), or enable DNS-over-HTTPS.")
                            .fixable(true)
                            .metadata("dns_server", ns),
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("scutil").args(["--dns"]).output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let l = line.trim();
                if l.starts_with("nameserver[") {
                    if let Some(ns) = l.split(']').nth(1).map(|s| s.trim()) {
                        if ns.starts_with("192.168.") || ns.starts_with("10.") {
                            findings.push(
                                Finding::new(
                                    "identity-dns-default",
                                    "Local DNS server in use",
                                    Severity::Medium,
                                    Category::Network,
                                )
                                .description("macOS DNS queries go to a local resolver that can log your browsing.")
                                .recommendation("Set DNS to 1.1.1.1 or 9.9.9.9 via System Settings > Network.")
                                .fixable(true)
                                .metadata("dns_server", ns),
                            );
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output();
        if let Ok(o) = out {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Just flag that DNS should be checked; full enumeration is complex
            if stdout.contains("Connected") {
                findings.push(
                    Finding::new(
                        "identity-dns-check",
                        "Verify DNS resolver privacy",
                        Severity::Low,
                        Category::Network,
                    )
                    .description("DNS resolver settings were not automatically verified on Windows. Check via: netsh interface ip show dnsservers")
                    .recommendation("Set DNS to 1.1.1.1 and 1.0.0.1 for privacy."),
                );
            }
        }
    }
}

fn audit_telemetry(findings: &mut Vec<Finding>) {
    #[cfg(target_os = "linux")]
    {
        // Check for Ubuntu popularity-contest (phones home with installed packages)
        if std::path::Path::new("/etc/cron.d/popularity-contest").exists()
            || Command::new("systemctl")
                .args(["is-enabled", "popularity-contest"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
                .unwrap_or(false)
        {
            findings.push(
                Finding::new(
                    "identity-telemetry-popcon",
                    "Ubuntu popularity-contest is enabled",
                    Severity::Low,
                    Category::Config,
                )
                .description("popularity-contest sends installed package lists to Ubuntu weekly, leaking software inventory.")
                .recommendation("Disable: sudo systemctl disable --now popularity-contest")
                .fixable(true),
            );
        }
    }

    #[cfg(windows)]
    {
        // Check telemetry level via registry
        use winreg::RegKey;
        let val = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Policies\Microsoft\Windows\DataCollection")
            .ok()
            .and_then(|k| k.get_value::<u32, _>("AllowTelemetry").ok());
        match val {
            Some(3) | None => findings.push(
                Finding::new(
                    "identity-telemetry-full",
                    "Windows telemetry is set to Full",
                    Severity::Medium,
                    Category::Config,
                )
                .description("Full telemetry sends detailed usage and diagnostic data to Microsoft, including browsing history and search queries.")
                .recommendation("Set AllowTelemetry=1 (Required) or 0 (Security) in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection")
                .fixable(true),
            ),
            _ => {}
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Check Siri analytics / iCloud analytics
        let out = Command::new("defaults")
            .args([
                "read",
                "/Library/Preferences/com.apple.assistant.support",
                "Siri Data Sharing",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim() == "1" {
                findings.push(
                    Finding::new(
                        "identity-siri-analytics",
                        "Siri data sharing is enabled",
                        Severity::Low,
                        Category::Config,
                    )
                    .description("Siri analytics data is shared with Apple.")
                    .recommendation("Disable in System Settings > Siri & Spotlight > Privacy.")
                    .fixable(true),
                );
            }
        }
    }
}

fn audit_hostname(findings: &mut Vec<Finding>) {
    // A hostname that includes your real name or username is an identity leak.
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    if !user.is_empty()
        && !host.is_empty()
        && host.to_lowercase().contains(&user.to_lowercase())
        && host.to_lowercase() != user.to_lowercase()
    {
        findings.push(
            Finding::new(
                "identity-hostname-leak",
                "Hostname contains your username",
                Severity::Low,
                Category::Config,
            )
            .description(&format!(
                "Hostname '{}' contains your username '{}'. This is broadcast on the local network and in DHCP requests.",
                host, user
            ))
            .recommendation(&format!("Rename the host: sudo hostnamectl set-hostname <neutral-name>"))
            .fixable(true)
            .metadata("hostname", &host),
        );
    }
}

/// Apply identity hardening: set privacy DNS, disable telemetry.
pub fn harden_identity(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    // 1. Set DNS to privacy resolvers
    results.push(set_privacy_dns(dry_run));

    // 2. Disable telemetry
    results.push(disable_telemetry(dry_run));

    results
}

fn set_privacy_dns(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "set-dns".to_string(),
            success: true,
            message: "[dry-run] Would set DNS to 1.1.1.1 / 9.9.9.9 (privacy resolvers)."
                .to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Write a new resolv.conf (simplest; NetworkManager may override)
        let content = "# PledgeShield: privacy DNS\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n";
        let resolv = "/etc/resolv.conf";
        // Backup original
        let _ = std::fs::copy(resolv, "/etc/resolv.conf.pledgeshield.bak");
        match std::fs::write(resolv, content) {
            Ok(()) => HardenResult {
                action: "set-dns".to_string(),
                success: true,
                message:
                    "DNS set to 1.1.1.1 + 9.9.9.9 (backup at /etc/resolv.conf.pledgeshield.bak)."
                        .to_string(),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "set-dns".to_string(),
                success: false,
                message: format!("Failed to write /etc/resolv.conf (need root?): {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("networksetup")
            .args(["-setdnsservers", "Wi-Fi", "1.1.1.1", "9.9.9.9"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "set-dns".to_string(),
                success: true,
                message: "DNS set to 1.1.1.1 + 9.9.9.9 for Wi-Fi.".to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "set-dns".to_string(),
                success: false,
                message: format!(
                    "networksetup failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "set-dns".to_string(),
                success: false,
                message: format!("networksetup not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                "name=Wi-Fi",
                "static",
                "1.1.1.1",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "set-dns".to_string(),
                success: true,
                message: "DNS set to 1.1.1.1 for Wi-Fi (run again for other adapters).".to_string(),
                findings: vec![],
            },
            Ok(o) => HardenResult {
                action: "set-dns".to_string(),
                success: false,
                message: format!(
                    "netsh failed: {} (try with adapter name from `netsh interface show interface`)",
                    String::from_utf8_lossy(&o.stderr)
                ),
                findings: vec![],
            },
            Err(e) => HardenResult {
                action: "set-dns".to_string(),
                success: false,
                message: format!("netsh not available: {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "set-dns".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        }
    }
}

fn disable_telemetry(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "disable-telemetry".to_string(),
            success: true,
            message: "[dry-run] Would disable OS telemetry/analytics.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("systemctl")
            .args(["disable", "--now", "popularity-contest"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "disable-telemetry".to_string(),
                success: true,
                message: "Disabled popularity-contest.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "disable-telemetry".to_string(),
                success: true,
                message: "No popularity-contest found or already disabled.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(windows)]
    {
        use winreg::RegKey;
        let r = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            winreg::enums::KEY_WRITE,
        );
        match r {
            Ok(key) => {
                let res = key.set_value("AllowTelemetry", &1u32); // Required (minimal)
                match res {
                    Ok(()) => HardenResult {
                        action: "disable-telemetry".to_string(),
                        success: true,
                        message: "Windows telemetry set to Required (minimal).".to_string(),
                        findings: vec![],
                    },
                    Err(e) => HardenResult {
                        action: "disable-telemetry".to_string(),
                        success: false,
                        message: format!("Failed to set registry value: {}", e),
                        findings: vec![],
                    },
                }
            }
            Err(_) => HardenResult {
                action: "disable-telemetry".to_string(),
                success: false,
                message: "Could not open registry key (need admin?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("defaults")
            .args([
                "write",
                "/Library/Preferences/com.apple.assistant.support",
                "Siri Data Sharing",
                "-bool",
                "false",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "disable-telemetry".to_string(),
                success: true,
                message: "Siri data sharing disabled.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "disable-telemetry".to_string(),
                success: false,
                message: "Failed to disable Siri data sharing (need root?).".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "disable-telemetry".to_string(),
            success: false,
            message: "Unsupported platform".to_string(),
            findings: vec![],
        }
    }
}
