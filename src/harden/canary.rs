/// Ransomware canary — plant decoy files and monitor for mass encryption/modification.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::path::PathBuf;
use std::time::SystemTime;

/// Plant canary files in common user directories.
pub fn plant_canaries(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![HardenResult {
            action: "canary-plant".to_string(),
            success: false,
            message: "Could not determine home directory.".to_string(),
            findings: vec![],
        }],
    };

    let canary_dirs = ["Documents", "Desktop", "Downloads", "Pictures"];
    let canary_content = "This is a PledgeShield ransomware canary file. Do not modify. \
If this file has been encrypted or modified, you may be under a ransomware attack. \
Contact your security team immediately.";

    for dir in &canary_dirs {
        let path = home.join(dir);
        if path.exists() {
            let canary_path = path.join("PLEDGESHIELD_CANARY.txt");
            if dry_run {
                results.push(HardenResult {
                    action: "canary-plant".to_string(),
                    success: true,
                    message: format!("[dry-run] Would plant canary at {}", canary_path.display()),
                    findings: vec![],
                });
            } else {
                match std::fs::write(&canary_path, canary_content) {
                    Ok(()) => {
                        // Record the hash and timestamp
                        results.push(HardenResult {
                            action: "canary-plant".to_string(),
                            success: true,
                            message: format!("Planted canary: {}", canary_path.display()),
                            findings: vec![],
                        });
                    }
                    Err(e) => results.push(HardenResult {
                        action: "canary-plant".to_string(),
                        success: false,
                        message: format!("Failed to plant at {}: {}", canary_path.display(), e),
                        findings: vec![],
                    }),
                }
            }
        }
    }

    // Store canary metadata
    if !dry_run && !results.is_empty() {
        let meta_path = get_canary_meta_path();
        let meta = serde_json::json!({
            "planted_at": chrono::Utc::now().to_rfc3339(),
            "content_hash": simple_hash(canary_content),
        });
        if let Some(parent) = PathBuf::from(&meta_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&meta_path, meta.to_string());
    }

    results
}

/// Check canary files for modification/encryption.
pub fn check_canaries() -> Vec<Finding> {
    let mut findings = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return findings,
    };

    let canary_dirs = ["Documents", "Desktop", "Downloads", "Pictures"];
    let expected_content = "This is a PledgeShield ransomware canary file. Do not modify. \
If this file has been encrypted or modified, you may be under a ransomware attack. \
Contact your security team immediately.";

    let mut canaries_found = 0;
    let mut canaries_modified = 0;

    for dir in &canary_dirs {
        let canary_path = home.join(dir).join("PLEDGESHIELD_CANARY.txt");
        if canary_path.exists() {
            canaries_found += 1;
            match std::fs::read_to_string(&canary_path) {
                Ok(content) => {
                    if content != expected_content {
                        canaries_modified += 1;
                        // Check if it looks encrypted (high entropy / unreadable)
                        let is_encrypted = content.bytes().all(|b| b > 127) || content.contains('\0');
                        let severity = if is_encrypted { Severity::Critical } else { Severity::High };
                        let desc = if is_encrypted {
                            "A canary file has been encrypted! You are likely under an active ransomware attack. Disconnect from network immediately!"
                        } else {
                            "A canary file has been modified. This could indicate ransomware activity or tampering."
                        };
                        findings.push(Finding::new(
                            "canary-modified",
                            &format!("Canary file modified: {}", canary_path.display()),
                            severity,
                            Category::HostConfig,
                        )
                        .description(desc)
                        .recommendation("1. Disconnect from network  2. Do not pay ransom  3. Contact security team  4. Check backups"));
                    }
                }
                Err(e) => {
                    findings.push(Finding::new(
                        "canary-unreadable",
                        &format!("Cannot read canary: {} ({})", canary_path.display(), e),
                        Severity::Critical,
                        Category::HostConfig,
                    )
                    .description("A canary file exists but cannot be read — it may have been encrypted."));
                }
            }
        }
    }

    if canaries_found == 0 {
        findings.push(Finding::new(
            "canary-none",
            "No ransomware canaries planted",
            Severity::Low,
            Category::HostConfig,
        )
        .description("Plant canary files to get early warning of ransomware attacks.")
        .recommendation("Run: pledgeshield harden canary --plant")
        .fixable(true));
    }

    findings
}

/// Remove all canary files.
pub fn remove_canaries() -> HardenResult {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return HardenResult {
            action: "canary-remove".to_string(),
            success: false,
            message: "No home directory.".to_string(),
            findings: vec![],
        },
    };

    let canary_dirs = ["Documents", "Desktop", "Downloads", "Pictures"];
    let mut removed = 0;
    for dir in &canary_dirs {
        let path = home.join(dir).join("PLEDGESHIELD_CANARY.txt");
        if path.exists() {
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }

    let meta_path = get_canary_meta_path();
    let _ = std::fs::remove_file(&meta_path);

    HardenResult {
        action: "canary-remove".to_string(),
        success: true,
        message: format!("Removed {} canary files.", removed),
        findings: vec![],
    }
}

fn get_canary_meta_path() -> String {
    dirs::data_dir()
        .map(|d| d.join("pledgeshield/canary.json").to_string_lossy().to_string())
        .unwrap_or_else(|| "/tmp/pledgeshield-canary.json".to_string())
}

fn simple_hash(s: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{:016x}", hash)
}
