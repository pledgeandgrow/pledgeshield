/// Backup integrity checker — verify backups exist, are recent, match expected size/hash.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::path::Path;

pub fn audit_backups(backup_dir: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dir = Path::new(backup_dir);

    if !dir.exists() {
        findings.push(
            Finding::new(
                "backup-dir-missing",
                &format!("Backup directory not found: {}", backup_dir),
                Severity::High,
                Category::HostConfig,
            )
            .description(
                "The specified backup directory does not exist. Backups may not be running.",
            )
            .recommendation(
                "Verify your backup configuration and ensure backups are being created.",
            ),
        );
        return findings;
    }

    // Count backup files
    let mut backup_files: Vec<(std::path::PathBuf, std::fs::Metadata)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    backup_files.push((entry.path(), meta));
                }
            }
        }
    }

    if backup_files.is_empty() {
        findings.push(
            Finding::new(
                "backup-empty",
                &format!("No backup files in {}", backup_dir),
                Severity::High,
                Category::HostConfig,
            )
            .description("The backup directory is empty. No backups have been created."),
        );
        return findings;
    }

    // Sort by modification time (newest first)
    backup_files.sort_by(|a, b| b.1.modified().ok().cmp(&a.1.modified().ok()));

    // Check most recent backup
    let (newest_path, newest_meta) = &backup_files[0];
    if let Ok(time) = newest_meta.modified() {
        if let Ok(elapsed) = time.elapsed() {
            let age_days = elapsed.as_secs() / 86400;
            if age_days > 7 {
                findings.push(Finding::new(
                    "backup-stale",
                    &format!("Newest backup is {} days old: {}", age_days, newest_path.display()),
                    Severity::High,
                    Category::HostConfig,
                )
                .description("Your most recent backup is more than a week old. Backups should be more frequent."));
            } else if age_days > 1 {
                findings.push(Finding::new(
                    "backup-aging",
                    &format!("Newest backup is {} days old", age_days),
                    Severity::Low,
                    Category::HostConfig,
                ));
            }
        }
    }

    // Check for zero-size backups (corrupt)
    for (path, meta) in &backup_files {
        if meta.len() == 0 {
            findings.push(
                Finding::new(
                    "backup-empty-file",
                    &format!("Empty backup file: {}", path.display()),
                    Severity::High,
                    Category::HostConfig,
                )
                .description(
                    "This backup file is 0 bytes — it's corrupt or was never written properly.",
                ),
            );
        }
    }

    // Check backup size trend (is it growing or shrinking?)
    if backup_files.len() >= 2 {
        let newest_size = backup_files[0].1.len();
        let oldest_size = backup_files[backup_files.len() - 1].1.len();
        if oldest_size > 0 {
            let ratio = newest_size as f64 / oldest_size as f64;
            if ratio < 0.5 {
                findings.push(Finding::new(
                    "backup-size-shrunk",
                    &format!("Backup size shrank to {:.0}% of oldest", ratio * 100.0),
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Recent backups are much smaller than older ones. This could indicate data loss or backup configuration changes."));
            }
        }
    }

    findings
}

/// Verify a backup file's hash matches an expected value.
pub fn verify_backup_hash(path: &str, expected_hash: &str) -> HardenResult {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return HardenResult {
                action: "backup-verify".to_string(),
                success: false,
                message: format!("Cannot read {}: {}", path, e),
                findings: vec![],
            }
        }
    };

    let actual_hash = simple_hash(&data);
    let match_result = actual_hash == expected_hash;

    HardenResult {
        action: "backup-verify".to_string(),
        success: match_result,
        message: if match_result {
            format!("Hash matches: {}", expected_hash)
        } else {
            format!(
                "Hash mismatch! Expected: {}, got: {}",
                expected_hash, actual_hash
            )
        },
        findings: vec![],
    }
}

fn simple_hash(data: &[u8]) -> String {
    // Simple hash for verification (not crypto, but sufficient for integrity check)
    let mut hash: u64 = 5381;
    for byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    format!("{:016x}", hash)
}
