/// IPv6 leak guard — disable or firewall IPv6 to prevent VPN/DNS leaks over IPv6.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_ipv6() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if IPv6 is enabled
        let out = Command::new("cat").arg("/proc/sys/net/ipv6/conf/all/disable_ipv6").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "0" {
                // IPv6 is enabled — check if there's a VPN that might leak
                findings.push(Finding::new(
                    "ipv6-enabled",
                    "IPv6 is enabled (potential VPN leak)",
                    Severity::Medium,
                    Category::Network,
                )
                .description("IPv6 traffic may bypass your VPN, leaking your real IP address.")
                .recommendation("Run: pledgeshield harden ipv6 --disable  (or --firewall to just block traffic)")
                .fixable(true));
            }
        }

        // Check for global IPv6 address
        let out = Command::new("ip").args(["-6", "addr", "show", "scope", "global"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.trim().is_empty() {
                findings.push(Finding::new(
                    "ipv6-global-address",
                    "Device has a global IPv6 address",
                    Severity::Low,
                    Category::Network,
                )
                .description("Your device has a public IPv6 address, which can be used for tracking and may bypass VPN.")
                .fixable(true));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("ifconfig").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("inet6") && s.contains("scope") {
                findings.push(Finding::new(
                    "ipv6-enabled",
                    "IPv6 is enabled (potential VPN leak)",
                    Severity::Medium,
                    Category::Network,
                )
                .description("IPv6 traffic may bypass your VPN.")
                .recommendation("Run: pledgeshield harden ipv6 --disable")
                .fixable(true));
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("powershell").args(["-Command", "Get-NetIPv6Protocol | Select-Object -ExpandProperty DefaultHopLimit"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("0") {
                findings.push(Finding::new(
                    "ipv6-enabled",
                    "IPv6 is enabled (potential VPN leak)",
                    Severity::Medium,
                    Category::Network,
                )
                .description("IPv6 traffic may bypass your VPN.")
                .recommendation("Run: pledgeshield harden ipv6 --disable")
                .fixable(true));
            }
        }
    }

    findings
}

pub fn disable_ipv6(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "ipv6-disable".to_string(),
            success: true,
            message: "[dry-run] Would disable IPv6 system-wide.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=1",
            "sysctl -w net.ipv6.conf.lo.disable_ipv6=1",
        ];
        let mut ok = true;
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let out = Command::new(parts[0]).args(&parts[1..]).output();
            if !out.map(|o| o.status.success()).unwrap_or(false) {
                ok = false;
            }
        }
        // Persist
        let _ = std::fs::write("/etc/sysctl.d/99-disable-ipv6.conf",
            "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv6.conf.lo.disable_ipv6=1\n");
        HardenResult {
            action: "ipv6-disable".to_string(),
            success: ok,
            message: "IPv6 disabled system-wide (persisted to /etc/sysctl.d/).".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "ipv6-disable".to_string(),
            success: false,
            message: "IPv6 disable is only supported on Linux. Use --firewall for other platforms.".to_string(),
            findings: vec![],
        }
    }
}

pub fn firewall_ipv6(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "ipv6-firewall".to_string(),
            success: true,
            message: "[dry-run] Would block all IPv6 traffic via ip6tables.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "ip6tables -P INPUT DROP",
            "ip6tables -P OUTPUT DROP",
            "ip6tables -P FORWARD DROP",
        ];
        let mut ok = true;
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let out = Command::new(parts[0]).args(&parts[1..]).output();
            if !out.map(|o| o.status.success()).unwrap_or(false) {
                ok = false;
            }
        }
        HardenResult {
            action: "ipv6-firewall".to_string(),
            success: ok,
            message: "IPv6 traffic blocked via ip6tables (INPUT/OUTPUT/FORWARD = DROP).".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "ipv6-firewall".to_string(),
            success: false,
            message: "IPv6 firewall is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn restore_ipv6() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "sysctl -w net.ipv6.conf.all.disable_ipv6=0",
            "sysctl -w net.ipv6.conf.default.disable_ipv6=0",
            "sysctl -w net.ipv6.conf.lo.disable_ipv6=0",
        ];
        for cmd in &cmds {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let _ = Command::new(parts[0]).args(&parts[1..]).output();
        }
        let _ = std::fs::remove_file("/etc/sysctl.d/99-disable-ipv6.conf");
        // Restore ip6tables
        let _ = Command::new("ip6tables").args(["-P", "INPUT", "ACCEPT"]).output();
        let _ = Command::new("ip6tables").args(["-P", "OUTPUT", "ACCEPT"]).output();
        let _ = Command::new("ip6tables").args(["-P", "FORWARD", "ACCEPT"]).output();
        HardenResult {
            action: "ipv6-restore".to_string(),
            success: true,
            message: "IPv6 re-enabled and firewall rules removed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "ipv6-restore".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}
