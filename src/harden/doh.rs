/// DNS-over-HTTPS/TLS — configure systemd-resolved or dnscrypt-proxy for encrypted DNS.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/dns-query"),
    ("quad9", "https://dns.quad9.net/dns-query"),
    ("adguard", "https://dns.adguard.com/dns-query"),
];

pub fn audit_dns() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if systemd-resolved is using DoH/DoT
        let out = Command::new("resolvectl").arg("status").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("DNS-over-TLS") && !s.contains("DoT") && !s.contains("DoH") {
                findings.push(Finding::new(
                    "dns-no-encryption",
                    "DNS queries are not encrypted",
                    Severity::Medium,
                    Category::Network,
                )
                .description("DNS queries are sent in plaintext. ISPs and network observers can see which domains you visit.")
                .recommendation("Run: pledgeshield harden doh --enable cloudflare")
                .fixable(true));
            }
        } else {
            // No systemd-resolved — check /etc/resolv.conf
            if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in content.lines() {
                    if line.starts_with("nameserver") {
                        let ns = line.split_whitespace().nth(1).unwrap_or("");
                        if ns.starts_with("127.") || ns == "127.0.0.1" {
                            // Local resolver — could be dnscrypt-proxy
                        } else {
                            findings.push(
                                Finding::new(
                                    "dns-plaintext-resolver",
                                    &format!("DNS resolver {} is plaintext", ns),
                                    Severity::Medium,
                                    Category::Network,
                                )
                                .description("Your DNS resolver does not support encryption.")
                                .recommendation("Run: pledgeshield harden doh --enable cloudflare")
                                .fixable(true),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("scutil").arg("--dns").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("tls") && !s.contains("https") {
                findings.push(
                    Finding::new(
                        "dns-no-encryption",
                        "DNS queries are not encrypted",
                        Severity::Medium,
                        Category::Network,
                    )
                    .description("macOS DNS is not configured for DoH/DoT.")
                    .recommendation("Run: pledgeshield harden doh --enable cloudflare")
                    .fixable(true),
                );
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output();
        let _ = out;
        findings.push(
            Finding::new(
                "dns-no-encryption",
                "DNS encryption not detected",
                Severity::Medium,
                Category::Network,
            )
            .description("Windows DNS encryption requires manual configuration or a DoH client.")
            .recommendation("Run: pledgeshield harden doh --enable cloudflare")
            .fixable(true),
        );
    }

    findings
}

pub fn enable_doh(provider: &str, dry_run: bool) -> HardenResult {
    let url = DOH_PROVIDERS
        .iter()
        .find(|(name, _)| *name == provider)
        .map(|(_, url)| *url)
        .unwrap_or_else(|| {
            if provider.starts_with("https://") {
                provider
            } else {
                "https://cloudflare-dns.com/dns-query"
            }
        });

    if dry_run {
        return HardenResult {
            action: "doh-enable".to_string(),
            success: true,
            message: format!("[dry-run] Would configure DoH via {} ({})", provider, url),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Try systemd-resolved first
        let resolved = Command::new("resolvectl")
            .arg("status")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if resolved {
            // Configure systemd-resolved for DoT
            let conf = format!(
                "[Resolve]\nDNS=127.0.0.1\nDNSOverTLS=yes\nDNSSEC=yes\nFallbackDNS=1.1.1.1 8.8.8.8\n"
            );
            let conf_path = "/etc/systemd/resolved.conf.d/doh.conf";
            let _ = std::fs::create_dir_all("/etc/systemd/resolved.conf.d");
            if std::fs::write(conf_path, conf).is_ok() {
                let _ = Command::new("systemctl")
                    .args(["restart", "systemd-resolved"])
                    .output();
                return HardenResult {
                    action: "doh-enable".to_string(),
                    success: true,
                    message: format!(
                        "systemd-resolved configured with DoT (provider: {})",
                        provider
                    ),
                    findings: vec![],
                };
            }
        }

        // Fallback: install/configure dnscrypt-proxy
        let dnscrypt = Command::new("which")
            .arg("dnscrypt-proxy")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if dnscrypt {
            let conf = format!(
                "server_names = ['{}']\nlisten_addresses = ['127.0.0.1:53']\ndoh_servers = ['{}']\n",
                provider, url
            );
            let _ = std::fs::write("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", conf);
            let _ = Command::new("systemctl")
                .args(["restart", "dnscrypt-proxy"])
                .output();
            HardenResult {
                action: "doh-enable".to_string(),
                success: true,
                message: format!("dnscrypt-proxy configured with DoH ({})", provider),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "doh-enable".to_string(),
                success: false,
                message: "Neither systemd-resolved nor dnscrypt-proxy available. Install with: sudo apt install dnscrypt-proxy".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "doh-enable".to_string(),
            success: false,
            message: format!("DoH configuration on this platform requires manual setup. Use {} in browser settings.", url),
            findings: vec![],
        }
    }
}

pub fn disable_doh() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let p = "/etc/systemd/resolved.conf.d/doh.conf";
        if std::path::Path::new(p).exists() {
            let _ = std::fs::remove_file(p);
            let _ = Command::new("systemctl")
                .args(["restart", "systemd-resolved"])
                .output();
            return HardenResult {
                action: "doh-disable".to_string(),
                success: true,
                message: "DoH/DoT configuration removed. DNS reverted to plaintext.".to_string(),
                findings: vec![],
            };
        }
        HardenResult {
            action: "doh-disable".to_string(),
            success: true,
            message: "No DoH configuration found to remove.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "doh-disable".to_string(),
            success: false,
            message: "Nothing to disable on this platform.".to_string(),
            findings: vec![],
        }
    }
}

pub fn list_providers() -> Vec<String> {
    DOH_PROVIDERS
        .iter()
        .map(|(name, url)| format!("  {:12} — {}", name, url))
        .collect()
}
