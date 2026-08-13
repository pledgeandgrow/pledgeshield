/// User agent spoofer — normalize/spoof browser user-agent strings to prevent fingerprinting.
use super::HardenResult;
use std::path::PathBuf;

const COMMON_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

pub fn get_chromium_prefs_path(browser: &str) -> Option<PathBuf> {
    let path = crate::harden::browser::audit_browser_privacy(); // just to reference the module
    let _ = path;
    #[cfg(target_os = "linux")]
    {
        let config = dirs::config_dir()?;
        let base = match browser {
            "chrome" => config.join("google-chrome").join("Default"),
            "edge" => config.join("microsoft-edge").join("Default"),
            "brave" => config
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("Default"),
            "chromium" => config.join("chromium").join("Default"),
            _ => return None,
        };
        Some(base)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = browser;
        None
    }
}

pub fn spoof_user_agent(ua: Option<&str>, dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();
    let target_ua = ua.unwrap_or(COMMON_UA);

    // Chromium-based browsers: set via Preferences
    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(base) = get_chromium_prefs_path(browser) {
            let prefs_path = base.join("Preferences");
            if prefs_path.exists() {
                if dry_run {
                    results.push(HardenResult {
                        action: format!("ua-spoof-{}", browser),
                        success: true,
                        message: format!("[dry-run] Would set {} UA to: {}", browser, target_ua),
                        findings: vec![],
                    });
                } else {
                    let r = set_chromium_ua(&prefs_path, browser, target_ua);
                    results.push(r);
                }
            }
        }
    }

    // Firefox: set via prefs.js
    if let Some(ff_dir) = get_firefox_profile_dir() {
        let prefs_path = ff_dir.join("prefs.js");
        if prefs_path.exists() {
            if dry_run {
                results.push(HardenResult {
                    action: "ua-spoof-firefox".to_string(),
                    success: true,
                    message: format!("[dry-run] Would set Firefox UA to: {}", target_ua),
                    findings: vec![],
                });
            } else {
                results.push(set_firefox_ua(&prefs_path, target_ua));
            }
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "ua-spoof".to_string(),
            success: true,
            message: "No browser profiles found.".to_string(),
            findings: vec![],
        });
    }

    results
}

fn get_firefox_profile_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir()?;
        let profiles = home.join(".mozilla").join("firefox");
        if let Ok(entries) = std::fs::read_dir(&profiles) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.join("prefs.js").exists() {
                    return Some(path);
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn set_chromium_ua(prefs_path: &std::path::Path, browser: &str, ua: &str) -> HardenResult {
    let content = match std::fs::read_to_string(prefs_path) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: format!("ua-spoof-{}", browser),
                success: false,
                message: format!("Failed to read prefs: {}", e),
                findings: vec![],
            };
        }
    };

    let mut prefs: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return HardenResult {
                action: format!("ua-spoof-{}", browser),
                success: false,
                message: format!("Failed to parse prefs: {}", e),
                findings: vec![],
            };
        }
    };

    if let Some(obj) = prefs.as_object_mut() {
        let ua_settings = obj
            .entry("user_agent")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(u) = ua_settings.as_object_mut() {
            u.insert("ua_override".to_string(), serde_json::json!(ua));
        }
    }

    let new_content = serde_json::to_string_pretty(&prefs).unwrap_or_default();
    match std::fs::write(prefs_path, new_content) {
        Ok(()) => HardenResult {
            action: format!("ua-spoof-{}", browser),
            success: true,
            message: format!("{} UA set to: {}", browser, ua),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: format!("ua-spoof-{}", browser),
            success: false,
            message: format!("Failed to write: {}", e),
            findings: vec![],
        },
    }
}

fn set_firefox_ua(prefs_path: &std::path::Path, ua: &str) -> HardenResult {
    let content = match std::fs::read_to_string(prefs_path) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: "ua-spoof-firefox".to_string(),
                success: false,
                message: format!("Failed to read: {}", e),
                findings: vec![],
            };
        }
    };

    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let prefix = "user_pref(\"general.useragent.override\"";
    lines.retain(|l| !l.starts_with(prefix));
    lines.push(format!(
        "user_pref(\"general.useragent.override\", \"{}\");",
        ua
    ));

    match std::fs::write(prefs_path, lines.join("\n") + "\n") {
        Ok(()) => HardenResult {
            action: "ua-spoof-firefox".to_string(),
            success: true,
            message: format!("Firefox UA set to: {}", ua),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "ua-spoof-firefox".to_string(),
            success: false,
            message: format!("Failed to write: {}", e),
            findings: vec![],
        },
    }
}

pub fn reset_user_agent() -> Vec<HardenResult> {
    let mut results = Vec::new();

    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(base) = get_chromium_prefs_path(browser) {
            let prefs_path = base.join("Preferences");
            if prefs_path.exists() {
                let content = std::fs::read_to_string(&prefs_path).unwrap_or_default();
                if let Ok(mut prefs) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = prefs.as_object_mut() {
                        obj.remove("user_agent");
                    }
                    let _ = std::fs::write(
                        &prefs_path,
                        serde_json::to_string_pretty(&prefs).unwrap_or_default(),
                    );
                }
                results.push(HardenResult {
                    action: format!("ua-reset-{}", browser),
                    success: true,
                    message: format!("{} UA override removed.", browser),
                    findings: vec![],
                });
            }
        }
    }

    if let Some(ff_dir) = get_firefox_profile_dir() {
        let prefs_path = ff_dir.join("prefs.js");
        if prefs_path.exists() {
            let content = std::fs::read_to_string(&prefs_path).unwrap_or_default();
            let lines: Vec<String> = content
                .lines()
                .filter(|l| !l.starts_with("user_pref(\"general.useragent.override\""))
                .map(String::from)
                .collect();
            let _ = std::fs::write(&prefs_path, lines.join("\n") + "\n");
            results.push(HardenResult {
                action: "ua-reset-firefox".to_string(),
                success: true,
                message: "Firefox UA override removed.".to_string(),
                findings: vec![],
            });
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "ua-reset".to_string(),
            success: true,
            message: "No UA overrides found.".to_string(),
            findings: vec![],
        });
    }

    results
}
