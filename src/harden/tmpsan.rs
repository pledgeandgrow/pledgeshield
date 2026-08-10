/// Temp directory sanitizer — clean /tmp, /var/tmp, /dev/shm of stale and dangerous files.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

const TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

pub fn audit_temp() -> Vec<Finding> {
    let mut findings = Vec::new();

    for dir in TEMP_DIRS {
        if !Path::new(dir).exists() { continue; }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                if let Ok(meta) = entry.metadata() {
                    // Check for executables in temp
                    if meta.is_file() {
                        let mode = meta.permissions().mode();
                        if mode & 0o111 != 0 {
                            findings.push(Finding::new(
                                &format!("temp-exec-{}-{}", dir.replace('/', "_"), name),
                                &format!("Executable in {}: {}", dir, name),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("Executables in temp directories are suspicious — they may be dropped by malware."));
                        }

                        // Check for stale files (older than 7 days)
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = SystemTime::now().duration_since(modified) {
                                if age > Duration::from_secs(7 * 86400) {
                                    findings.push(Finding::new(
                                        &format!("temp-stale-{}-{}", dir.replace('/', "_"), name),
                                        &format!("Stale file in {} ({} days old): {}", dir, age.as_secs() / 86400, name),
                                        Severity::Low,
                                        Category::HostConfig,
                                    ));
                                }
                            }
                        }
                    }

                    // Check for symlinks pointing outside temp
                    if meta.is_symlink() {
                        if let Ok(target) = std::fs::read_link(&path) {
                            if !target.starts_with(dir) && !target.is_absolute() {
                                findings.push(Finding::new(
                                    &format!("temp-symlink-{}-{}", dir.replace('/', "_"), name),
                                    &format!("Symlink in {} points outside: {} -> {}", dir, name, target.display()),
                                    Severity::Medium,
                                    Category::HostConfig,
                                )
                                .description("Symlinks in temp directories pointing outside can be used for privilege escalation (TOCTOU attacks)."));
                            }
                        }
                    }

                    // Check for world-writable non-sticky directories
                    if meta.is_dir() {
                        let mode = meta.permissions().mode();
                        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
                            findings.push(Finding::new(
                                &format!("temp-worldwrite-{}-{}", dir.replace('/', "_"), name),
                                &format!("World-writable directory without sticky bit in {}: {}", dir, name),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("World-writable directories without the sticky bit allow any user to delete/modify files placed by others."));
                        }
                    }
                }
            }
        }
    }

    findings
}

pub fn clean_temp(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    for dir in TEMP_DIRS {
        if !Path::new(dir).exists() { continue; }
        let mut cleaned = 0;

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        // Only clean files older than 7 days
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = SystemTime::now().duration_since(modified) {
                                if age > Duration::from_secs(7 * 86400) {
                                    if dry_run {
                                        cleaned += 1;
                                    } else {
                                        if std::fs::remove_file(&path).is_ok() {
                                            cleaned += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results.push(HardenResult {
            action: format!("temp-clean-{}", dir),
            success: true,
            message: if dry_run {
                format!("[dry-run] Would clean {} stale files from {}", cleaned, dir)
            } else {
                format!("Cleaned {} stale files from {}", cleaned, dir)
            },
            findings: vec![],
        });
    }

    results
}
