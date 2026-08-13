/// Anomalous DNS query detector — monitor DNS queries for fast flux, DGA patterns, known C2 domains.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

/// Known suspicious TLDs commonly used by malware.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz",
    ".top",
    ".click",
    ".loan",
    ".work",
    ".men",
    ".racing",
    ".download",
    ".stream",
    ".review",
];

/// Known C2 domains (small sample — real deployments would use a larger list).
const KNOWN_C2: &[&str] = &["malicious-c2.com", "botnet-cc.net", "trojan-c2.org"];

pub fn audit_dns_queries() -> Vec<Finding> {
    let mut findings = Vec::new();
    let queries = get_recent_dns_queries();

    for query in &queries {
        let domain = &query.domain;

        // Check against known C2
        for c2 in KNOWN_C2 {
            if domain.contains(c2) {
                findings.push(
                    Finding::new(
                        &format!("dns-c2-{}", domain.replace('.', "_")),
                        &format!("DNS query to known C2: {}", domain),
                        Severity::Critical,
                        Category::Network,
                    )
                    .description("This domain is a known command-and-control server for malware.")
                    .recommendation("Investigate the process making this query immediately."),
                );
            }
        }

        // Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS {
            if domain.ends_with(tld) {
                findings.push(
                    Finding::new(
                        &format!("dns-suspicious-tld-{}", domain.replace('.', "_")),
                        &format!("DNS query to suspicious TLD: {}", domain),
                        Severity::Low,
                        Category::Network,
                    )
                    .description(&format!(
                        "Domain uses .{} TLD, commonly abused by malware.",
                        tld.trim_start_matches('.')
                    )),
                );
                break;
            }
        }

        // Check for DGA patterns (random-looking domains)
        if is_dga_like(domain) {
            findings.push(Finding::new(
                &format!("dns-dga-{}", domain.replace('.', "_")),
                &format!("Possible DGA domain: {}", domain),
                Severity::Medium,
                Category::Network,
            )
            .description("This domain name looks randomly generated — possible DGA (Domain Generation Algorithm) used by malware."));
        }

        // Check for fast flux (many IPs for one domain)
        if query.ips.len() > 5 {
            findings.push(
                Finding::new(
                    &format!("dns-fast-flux-{}", domain.replace('.', "_")),
                    &format!("Fast flux detected: {} has {} IPs", domain, query.ips.len()),
                    Severity::Medium,
                    Category::Network,
                )
                .description(
                    "This domain resolves to many IP addresses — possible fast flux botnet.",
                ),
            );
        }
    }

    findings
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: String,
    pub ips: Vec<String>,
}

fn get_recent_dns_queries() -> Vec<DnsQuery> {
    let mut queries = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Try to read from systemd-resolved or dnsmasq logs
        let out = Command::new("journalctl")
            .args([
                "-u",
                "systemd-resolved",
                "--no-pager",
                "-n",
                "500",
                "-g",
                "query",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if let Some(domain) = extract_domain_from_journal(line) {
                    queries.push(DnsQuery {
                        domain,
                        ips: vec![],
                    });
                }
            }
        }

        // Also check /var/log/dnsmasq.log
        if let Ok(content) = std::fs::read_to_string("/var/log/dnsmasq.log") {
            for line in content.lines() {
                if line.contains("query[A]") {
                    if let Some(domain) = line.split("query[A] ").nth(1) {
                        let domain = domain.split_whitespace().next().unwrap_or("").to_string();
                        if !domain.is_empty() {
                            queries.push(DnsQuery {
                                domain,
                                ips: vec![],
                            });
                        }
                    }
                }
            }
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    queries.retain(|q: &DnsQuery| seen.insert(q.domain.clone()));

    queries
}

#[cfg(target_os = "linux")]
fn extract_domain_from_journal(line: &str) -> Option<String> {
    // Format: "query[AAAA] example.com"
    if let Some(idx) = line.find("query[") {
        let rest = &line[idx..];
        if let Some(end) = rest.find(']') {
            let after = &rest[end + 1..].trim();
            let domain = after.split_whitespace().next().unwrap_or("");
            if !domain.is_empty() && domain.contains('.') {
                return Some(domain.to_string());
            }
        }
    }
    None
}

/// Check if a domain looks like it was generated by a DGA.
fn is_dga_like(domain: &str) -> bool {
    // Get the main domain (without TLD)
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let main = parts[parts.len() - 2];

    // DGA characteristics:
    // 1. All consonants or all vowels (unnatural)
    // 2. Very long random-looking string
    // 3. High entropy

    if main.len() > 15 {
        return true;
    }

    // Check consonant ratio
    let consonants = main
        .chars()
        .filter(|c| "bcdfghjklmnpqrstvwxyz".contains(*c))
        .count();
    let vowels = main.chars().filter(|c| "aeiou".contains(*c)).count();
    if main.len() > 6 && (consonants == 0 || vowels == 0) {
        return true;
    }

    // Check for no repeated characters (random)
    let mut chars: Vec<char> = main.chars().collect();
    chars.sort();
    let unique = chars.iter().collect::<std::collections::HashSet<_>>().len();
    if main.len() > 8 && unique as f64 / main.len() as f64 > 0.8 {
        return true;
    }

    false
}

/// Monitor DNS queries in real-time (Linux, requires systemd-resolved).
pub fn monitor_dns(max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield DNS Query Monitor                      ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Monitoring DNS queries for anomalies...");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    let mut seen = std::collections::HashSet::new();

    loop {
        let queries = get_recent_dns_queries();
        for q in &queries {
            if !seen.contains(&q.domain) {
                let now = chrono::Utc::now().format("%H:%M:%S");
                let flag = if is_dga_like(&q.domain) {
                    " [DGA?]"
                } else if KNOWN_C2.iter().any(|c2| q.domain.contains(c2)) {
                    " [C2!]"
                } else if SUSPICIOUS_TLDS.iter().any(|tld| q.domain.ends_with(tld)) {
                    " [SUSP]"
                } else {
                    ""
                };
                println!("  {} {}{}", now, q.domain, flag);
                seen.insert(q.domain.clone());
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
