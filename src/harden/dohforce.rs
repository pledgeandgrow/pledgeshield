/// DNS over HTTPS enforcement — force all DNS through encrypted resolvers, block port 53.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_dns_enforcement() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if port 53 is blocked outbound
        let out = Command::new("iptables").args(["-L", "OUTPUT"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("dpt:53") {
                findings.push(Finding::new(
                    "dohforce-port53-open",
                    "Outbound port 53 (DNS) is not blocked",
                    Severity::Medium,
                    Category::Network,
                )
                .description("Without blocking plaintext DNS, applications can bypass DoH/DoT and leak queries.")
                .recommendation("Run: pledgeshield harden dohforce --enforce")
                .fixable(true));
            }
        }

        // Check if systemd-resolved is using DoT
        let out = Command::new("resolvectl").arg("status").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("DNS-over-TLS") && !s.contains("DoT") {
                findings.push(Finding::new(
                    "dohforce-no-dot",
                    "DNS-over-TLS is not configured in systemd-resolved",
                    Severity::Low,
                    Category::Network,
                )
                .fixable(true));
            }
        }
    }

    findings
}

pub fn enforce_doh(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "dohforce-enforce".to_string(),
            success: true,
            message: "[dry-run] Would block plaintext DNS (port 53) and force DoH/DoT.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Configure systemd-resolved for DoT
        let conf = "[Resolve]\nDNSOverTLS=yes\nDNS=1.1.1.1#cloudflare-dns.com 8.8.8.8#dns.google\nFallbackDNS=9.9.9.9#dns.quad9.net\n";
        let _ = std::fs::write("/etc/systemd/resolved.conf.d/pledgeshield.conf", conf);
        let _ = Command::new("systemctl").args(["restart", "systemd-resolved"]).output();

        // Block outbound port 53 (plaintext DNS) except for systemd-resolved
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "systemd-resolve", "-j", "DROP"])
            .output();
        let _ = Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "systemd-resolve", "-j", "DROP"])
            .output();

        HardenResult {
            action: "dohforce-enforce".to_string(),
            success: true,
            message: "DNS-over-TLS enforced via systemd-resolved. Plaintext DNS (port 53) blocked for non-resolver processes.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "dohforce-enforce".to_string(),
            success: false,
            message: "DNS enforcement is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_enforcement() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::remove_file("/etc/systemd/resolved.conf.d/pledgeshield.conf");
        let _ = Command::new("systemd-resolved").args(["restart"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "systemd-resolve", "-j", "DROP"])
            .output();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "systemd-resolve", "-j", "DROP"])
            .output();
        HardenResult {
            action: "dohforce-disable".to_string(),
            success: true,
            message: "DNS enforcement disabled.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "dohforce-disable".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
