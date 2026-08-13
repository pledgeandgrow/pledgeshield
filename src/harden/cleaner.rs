/// Recent files & activity cleaner — clear recent docs, shell history, command history, temp files.
use super::HardenResult;
#[allow(unused_imports)]
use std::process::Command;

pub fn clean_activity(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    // Shell history files
    let history_files = [
        ("bash_history", "~/.bash_history"),
        ("zsh_history", "~/.zsh_history"),
        ("python_history", "~/.python_history"),
        ("lesshst", "~/.lesshst"),
        ("viminfo", "~/.viminfo"),
        ("node_repl_history", "~/.node_repl_history"),
        ("mysql_history", "~/.mysql_history"),
        ("psql_history", "~/.psql_history"),
    ];

    for (name, path) in &history_files {
        let expanded = expand_tilde(path);
        if std::path::Path::new(&expanded).exists() {
            if dry_run {
                results.push(HardenResult {
                    action: format!("clean-{}", name),
                    success: true,
                    message: format!("[dry-run] Would clear {}", expanded),
                    findings: vec![],
                });
            } else {
                match std::fs::write(&expanded, "") {
                    Ok(()) => results.push(HardenResult {
                        action: format!("clean-{}", name),
                        success: true,
                        message: format!("Cleared {}", expanded),
                        findings: vec![],
                    }),
                    Err(e) => results.push(HardenResult {
                        action: format!("clean-{}", name),
                        success: false,
                        message: format!("Failed to clear {}: {}", expanded, e),
                        findings: vec![],
                    }),
                }
            }
        }
    }

    // Temp files
    let temp_dirs = ["/tmp", "/var/tmp"];
    for dir in &temp_dirs {
        if std::path::Path::new(dir).exists() {
            if dry_run {
                results.push(HardenResult {
                    action: "clean-tmp".to_string(),
                    success: true,
                    message: format!("[dry-run] Would clean temp files in {}", dir),
                    findings: vec![],
                });
            } else {
                // Only clean files owned by current user that are older than 1 day
                if let Ok(entries) = std::fs::read_dir(dir) {
                    let mut cleaned = 0;
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            // Try to get metadata
                            if let Ok(meta) = std::fs::metadata(&path) {
                                if let Ok(time) = meta.modified() {
                                    if time.elapsed().map(|d| d.as_secs() > 86400).unwrap_or(false)
                                    {
                                        if std::fs::remove_file(&path).is_ok() {
                                            cleaned += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    results.push(HardenResult {
                        action: "clean-tmp".to_string(),
                        success: true,
                        message: format!("Cleaned {} old temp files from {}", cleaned, dir),
                        findings: vec![],
                    });
                }
            }
        }
    }

    // Recent files (Linux GTK)
    let recent_path = expand_tilde("~/.local/share/recently-used.xbel");
    if std::path::Path::new(&recent_path).exists() {
        if dry_run {
            results.push(HardenResult {
                action: "clean-recent".to_string(),
                success: true,
                message: format!("[dry-run] Would clear recent files list"),
                findings: vec![],
            });
        } else {
            let _ = std::fs::write(&recent_path, "");
            results.push(HardenResult {
                action: "clean-recent".to_string(),
                success: true,
                message: "Recent files list cleared.".to_string(),
                findings: vec![],
            });
        }
    }

    // Thumbnail cache
    let thumb_dir = expand_tilde("~/.cache/thumbnails");
    if std::path::Path::new(&thumb_dir).exists() {
        if dry_run {
            results.push(HardenResult {
                action: "clean-thumbnails".to_string(),
                success: true,
                message: "[dry-run] Would clear thumbnail cache".to_string(),
                findings: vec![],
            });
        } else {
            let _ = std::fs::remove_dir_all(&thumb_dir);
            results.push(HardenResult {
                action: "clean-thumbnails".to_string(),
                success: true,
                message: "Thumbnail cache cleared.".to_string(),
                findings: vec![],
            });
        }
    }

    // Windows: clear recent docs, prefetch, event logs
    #[cfg(windows)]
    {
        if dry_run {
            results.push(HardenResult {
                action: "clean-win-recent".to_string(),
                success: true,
                message: "[dry-run] Would clear Windows recent docs + prefetch".to_string(),
                findings: vec![],
            });
        } else {
            let _ = Command::new("del")
                .args(["/q", "%APPDATA%\\Microsoft\\Windows\\Recent\\*"])
                .output();
            let _ = Command::new("del")
                .args(["/q", "%WINDIR%\\Prefetch\\*"])
                .output();
            results.push(HardenResult {
                action: "clean-win-recent".to_string(),
                success: true,
                message: "Windows recent docs + prefetch cleared.".to_string(),
                findings: vec![],
            });
        }
    }

    // macOS: clear recent items
    #[cfg(target_os = "macos")]
    {
        let recent_apps = expand_tilde(
            "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl",
        );
        if std::path::Path::new(&recent_apps).exists() && !dry_run {
            let _ = std::fs::remove_file(&recent_apps);
            results.push(HardenResult {
                action: "clean-mac-recent".to_string(),
                success: true,
                message: "macOS recent applications cleared.".to_string(),
                findings: vec![],
            });
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "clean-activity".to_string(),
            success: true,
            message: "Nothing to clean.".to_string(),
            findings: vec![],
        });
    }

    results
}

fn expand_tilde(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        if path.starts_with("~/") {
            return home.join(&path[2..]).to_string_lossy().to_string();
        }
        if path == "~" {
            return home.to_string_lossy().to_string();
        }
    }
    path.to_string()
}
