/// Hosts file hardener — block ad/tracker/malware domains via the hosts file.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const BLOCKLIST_URLS: &[(&str, &str)] = &[
    (
        "StevenBlack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    ("adaway", "https://adaway.org/hosts.txt"),
    (
        "malware",
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
    ),
];

pub fn audit_hosts() -> Vec<Finding> {
    let mut findings = Vec::new();

    let hosts_path = get_hosts_path();
    if let Ok(content) = std::fs::read_to_string(&hosts_path) {
        let blocked = content
            .lines()
            .filter(|l| l.contains("0.0.0.0") || l.contains("127.0.0.1"))
            .count();
        if blocked < 10 {
            findings.push(Finding::new(
                "hosts-no-blocking",
                "Hosts file has minimal or no domain blocking",
                Severity::Low,
                Category::Network,
            )
            .description(format!("Only {} blocked domains in hosts file. Ad/tracker/malware domains are not being blocked.", blocked))
            .recommendation("Run: pledgeshield harden hosts --update  to add blocklists")
            .fixable(true));
        } else {
            // Good — lots of blocked domains
        }
    }

    findings
}

fn get_hosts_path() -> String {
    #[cfg(windows)]
    {
        r"C:\Windows\System32\drivers\etc\hosts".to_string()
    }
    #[cfg(not(windows))]
    {
        "/etc/hosts".to_string()
    }
}

pub fn update_hosts(dry_run: bool) -> HardenResult {
    let hosts_path = get_hosts_path();

    if dry_run {
        return HardenResult {
            action: "hosts-update".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would download blocklists and add to {}",
                hosts_path
            ),
            findings: vec![],
        };
    }

    // Backup current hosts file
    let backup = format!("{}.pledgeshield-backup", hosts_path);
    let _ = std::fs::copy(&hosts_path, &backup);

    // Read current hosts
    let mut content = std::fs::read_to_string(&hosts_path).unwrap_or_default();

    // Add marker if not present
    if !content.contains("# PledgeShield blocklist") {
        content.push_str("\n# PledgeShield blocklist — do not edit below this line\n");
    }

    // Download and append blocklists
    let mut total_blocked = 0;
    for (name, url) in BLOCKLIST_URLS {
        if let Ok(out) = Command::new("curl")
            .args(["-s", "--max-time", "30", url])
            .output()
        {
            let list = String::from_utf8_lossy(&out.stdout);
            let count = list
                .lines()
                .filter(|l| {
                    let l = l.trim();
                    !l.is_empty()
                        && !l.starts_with('#')
                        && (l.contains("0.0.0.0") || l.contains("127.0.0.1"))
                })
                .count();
            content.push_str(&format!("# --- {} ({} entries) ---\n", name, count));
            for line in list.lines() {
                let l = line.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    // Normalize: ensure it's "0.0.0.0 domain"
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() >= 2 {
                        content.push_str(&format!("0.0.0.0 {}\n", parts[1]));
                        total_blocked += 1;
                    } else if parts.len() == 1 && parts[0].contains('.') {
                        content.push_str(&format!("0.0.0.0 {}\n", parts[0]));
                        total_blocked += 1;
                    }
                }
            }
        }
    }

    match std::fs::write(&hosts_path, content) {
        Ok(()) => HardenResult {
            action: "hosts-update".to_string(),
            success: true,
            message: format!(
                "Added {} blocked domains to {} (backup at {})",
                total_blocked, hosts_path, backup
            ),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "hosts-update".to_string(),
            success: false,
            message: format!("Failed to write hosts file (need root?): {}", e),
            findings: vec![],
        },
    }
}

pub fn restore_hosts() -> HardenResult {
    let hosts_path = get_hosts_path();
    let backup = format!("{}.pledgeshield-backup", hosts_path);

    if !std::path::Path::new(&backup).exists() {
        return HardenResult {
            action: "hosts-restore".to_string(),
            success: false,
            message: "No backup found. Nothing to restore.".to_string(),
            findings: vec![],
        };
    }

    match std::fs::copy(&backup, &hosts_path) {
        Ok(_) => {
            let _ = std::fs::remove_file(&backup);
            HardenResult {
                action: "hosts-restore".to_string(),
                success: true,
                message: "Hosts file restored from backup.".to_string(),
                findings: vec![],
            }
        }
        Err(e) => HardenResult {
            action: "hosts-restore".to_string(),
            success: false,
            message: format!("Failed to restore: {}", e),
            findings: vec![],
        },
    }
}

pub fn add_custom_block(domain: &str) -> HardenResult {
    let hosts_path = get_hosts_path();
    let mut content = std::fs::read_to_string(&hosts_path).unwrap_or_default();
    let entry = format!("0.0.0.0 {}\n", domain);
    if content.contains(&entry) {
        return HardenResult {
            action: "hosts-block".to_string(),
            success: true,
            message: format!("{} is already blocked.", domain),
            findings: vec![],
        };
    }
    content.push_str(&entry);
    match std::fs::write(&hosts_path, content) {
        Ok(()) => HardenResult {
            action: "hosts-block".to_string(),
            success: true,
            message: format!("Blocked domain: {}", domain),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "hosts-block".to_string(),
            success: false,
            message: format!("Failed (need root?): {}", e),
            findings: vec![],
        },
    }
}

pub fn count_blocked() -> usize {
    let hosts_path = get_hosts_path();
    std::fs::read_to_string(&hosts_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            l.trim_start().starts_with("0.0.0.0") || l.trim_start().starts_with("127.0.0.1")
        })
        .count()
}
