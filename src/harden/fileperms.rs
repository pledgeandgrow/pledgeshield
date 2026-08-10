/// File permission auditor — find world-readable/writable files in home, config, SSH keys.
use crate::models::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn audit_file_permissions() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(unix)]
    {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return findings,
        };

        // Check SSH directory and keys
        let ssh_dir = home.join(".ssh");
        if ssh_dir.exists() {
            // .ssh dir should be 700
            if let Ok(meta) = std::fs::metadata(&ssh_dir) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    findings.push(Finding::new(
                        "fileperm-ssh-dir",
                        &format!(".ssh directory is {} (should be 700)", format_mode(mode)),
                        Severity::High,
                        Category::Credentials,
                    )
                    .description("Your .ssh directory is accessible by other users. They could read your private keys or modify authorized_keys.")
                    .recommendation("Run: chmod 700 ~/.ssh")
                    .fixable(true));
                }
            }

            // Check individual key files
            if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') { continue; }

                    if let Ok(meta) = std::fs::metadata(&path) {
                        let mode = meta.permissions().mode();
                        if meta.is_file() {
                            // Private keys should be 600
                            if name.contains("id_") && !name.ends_with(".pub") {
                                if mode & 0o077 != 0 {
                                    findings.push(Finding::new(
                                        &format!("fileperm-ssh-key-{}", name),
                                        &format!("SSH private key {} is {} (should be 600)", name, format_mode(mode)),
                                        Severity::Critical,
                                        Category::Credentials,
                                    )
                                    .description("Your SSH private key is readable by other users!")
                                    .recommendation(&format!("Run: chmod 600 {}", path.display()))
                                    .fixable(true));
                                }
                            }
                            // authorized_keys should be 600
                            if name == "authorized_keys" || name == "authorized_keys2" {
                                if mode & 0o077 != 0 {
                                    findings.push(Finding::new(
                                        "fileperm-authorized-keys",
                                        &format!("{} is {} (should be 600)", name, format_mode(mode)),
                                        Severity::High,
                                        Category::Credentials,
                                    )
                                    .recommendation(&format!("Run: chmod 600 {}", path.display()))
                                    .fixable(true));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check .gnupg directory
        let gnupg = home.join(".gnupg");
        if gnupg.exists() {
            if let Ok(meta) = std::fs::metadata(&gnupg) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    findings.push(Finding::new(
                        "fileperm-gnupg",
                        &format!(".gnupg directory is {} (should be 700)", format_mode(mode)),
                        Severity::High,
                        Category::Credentials,
                    )
                    .recommendation("Run: chmod 700 ~/.gnupg")
                    .fixable(true));
                }
            }
        }

        // Check .env files in home
        if let Ok(entries) = std::fs::read_dir(&home) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".env") || name == ".netrc" || name == ".my.cnf" || name == ".pgpass" {
                    if let Ok(meta) = std::fs::metadata(entry.path()) {
                        let mode = meta.permissions().mode();
                        if mode & 0o077 != 0 {
                            findings.push(Finding::new(
                                &format!("fileperm-{}", name.replace('.', "_")),
                                &format!("{} is {} (should be 600)", name, format_mode(mode)),
                                Severity::High,
                                Category::Credentials,
                            )
                            .description("This file may contain credentials and is readable by other users.")
                            .recommendation(&format!("Run: chmod 600 ~/'{}'", name))
                            .fixable(true));
                        }
                    }
                }
            }
        }

        // Check home directory itself (should not be 777)
        if let Ok(meta) = std::fs::metadata(&home) {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                findings.push(Finding::new(
                    "fileperm-home-writable",
                    "Home directory is world-writable",
                    Severity::High,
                    Category::HostConfig,
                )
                .description("Your home directory is writable by any user. They could modify your files.")
                .recommendation(&format!("Run: chmod 755 ~  (or chmod 700 ~ for stricter)"))
                .fixable(true));
            }
        }
    }

    findings
}

fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// Fix permissions on sensitive files.
pub fn fix_permissions(dry_run: bool) -> Vec<String> {
    let mut results = Vec::new();

    #[cfg(unix)]
    {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return results,
        };

        let fixes = [
            (home.join(".ssh"), 0o700),
            (home.join(".gnupg"), 0o700),
        ];

        for (path, mode) in &fixes {
            if path.exists() {
                if dry_run {
                    results.push(format!("[dry-run] Would chmod {:o} {}", mode, path.display()));
                } else {
                    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(*mode));
                    results.push(format!("Set {:o} on {}", mode, path.display()));
                }
            }
        }

        // Fix SSH keys
        let ssh_dir = home.join(".ssh");
        if ssh_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') { continue; }
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if meta.is_file() {
                            let mode = if name.contains("id_") && !name.ends_with(".pub") { 0o600 }
                                else if name == "authorized_keys" || name == "authorized_keys2" { 0o600 }
                                else if name.ends_with(".pub") { 0o644 }
                                else { 0o600 };
                            if dry_run {
                                results.push(format!("[dry-run] Would chmod {:o} {}", mode, path.display()));
                            } else {
                                let _ = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode));
                                results.push(format!("Set {:o} on {}", mode, path.display()));
                            }
                        }
                    }
                }
            }
        }
    }

    results
}
