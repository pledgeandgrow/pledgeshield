/// SSH key auditor — check key sizes, passphrases, permissions, authorized_keys hygiene.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_ssh_keys() -> Vec<Finding> {
    let mut findings = Vec::new();

    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return findings,
    };

    let ssh_dir = home.join(".ssh");
    if !ssh_dir.exists() {
        return findings;
    }

    // Check all private keys
    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip public keys and known_hosts
            if name.ends_with(".pub") || name == "known_hosts" || name == "known_hosts2" {
                continue;
            }
            if name.starts_with('.') {
                continue;
            }

            // Check if it's a private key
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("PRIVATE KEY") {
                    // Check key type and size
                    if content.contains("BEGIN RSA PRIVATE KEY") {
                        // Check key size
                        let out = Command::new("ssh-keygen")
                            .args(["-l", "-f", path.to_str().unwrap_or("")])
                            .output();
                        if let Ok(o) = out {
                            let s = String::from_utf8_lossy(&o.stdout);
                            if s.contains("1024") || s.contains("2048") {
                                findings.push(Finding::new(
                                    &format!("sshkey-weak-{}", name),
                                    &format!("RSA key {} is too small ({})", name, s.split_whitespace().next().unwrap_or("?")),
                                    Severity::High,
                                    Category::Credentials,
                                )
                                .description("RSA keys < 3072 bits are considered weak. Use ed25519 or RSA 4096.")
                                .recommendation(&format!("Generate new key: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new")));
                            }
                        }
                    }

                    // Check if key has a passphrase
                    let out = Command::new("ssh-keygen")
                        .args(["-y", "-P", "", "-f", path.to_str().unwrap_or("")])
                        .output();
                    if let Ok(o) = out {
                        if o.status.success() {
                            // Key could be read with empty passphrase — no passphrase set
                            findings.push(Finding::new(
                                &format!("sshkey-no-passphrase-{}", name),
                                &format!("SSH key {} has no passphrase", name),
                                Severity::High,
                                Category::Credentials,
                            )
                            .description("Your private key has no passphrase. If stolen, it can be used immediately.")
                            .recommendation(&format!("Add passphrase: ssh-keygen -p -f {}", path.display()))
                            .fixable(true));
                        }
                    }
                }
            }
        }
    }

    // Check authorized_keys
    let auth_keys = ssh_dir.join("authorized_keys");
    if auth_keys.exists() {
        if let Ok(content) = std::fs::read_to_string(&auth_keys) {
            let key_count = content
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .count();
            if key_count > 10 {
                findings.push(Finding::new(
                    "sshkey-many-authorized",
                    &format!("{} keys in authorized_keys", key_count),
                    Severity::Low,
                    Category::Credentials,
                )
                .description("Many authorized keys increase the attack surface. Remove keys you no longer use."));
            }

            // Check for key comments that reveal usernames
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                if line.contains("root@") || line.contains("admin@") {
                    findings.push(Finding::new(
                        "sshkey-suspicious-key",
                        "Authorized key appears to be from root/admin account",
                        Severity::Medium,
                        Category::Credentials,
                    )
                    .description("An authorized key has a comment suggesting it's from a root or admin account. Verify this is expected."));
                }
            }
        }
    }

    // Check known_hosts for too many entries
    let known_hosts = ssh_dir.join("known_hosts");
    if known_hosts.exists() {
        if let Ok(content) = std::fs::read_to_string(&known_hosts) {
            let count = content
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .count();
            if count > 50 {
                findings.push(Finding::new(
                    "sshkey-many-known-hosts",
                    &format!("{} entries in known_hosts", count),
                    Severity::Info,
                    Category::Credentials,
                )
                .description("Many known_hosts entries. Consider pruning hosts you no longer connect to."));
            }
        }
    }

    findings
}
