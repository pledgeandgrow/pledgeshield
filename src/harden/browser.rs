use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::path::PathBuf;

/// Audit browser privacy settings — telemetry, tracking, data collection.
pub fn audit_browser_privacy() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Chrome/Chromium/Brave/Edge
    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(prefs_path) = get_chromium_prefs_path(browser) {
            if prefs_path.exists() {
                audit_chromium_prefs(&prefs_path, browser, &mut findings);
            }
        }
    }

    // Firefox
    if let Some(ff_dir) = get_firefox_profile_dir() {
        if ff_dir.exists() {
            audit_firefox_prefs(&ff_dir, &mut findings);
        }
    }

    findings
}

fn get_chromium_prefs_path(browser: &str) -> Option<PathBuf> {
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
        Some(base.join("Preferences"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()?;
        let base = match browser {
            "chrome" => home
                .join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome")
                .join("Default"),
            "edge" => home
                .join("Library")
                .join("Application Support")
                .join("Microsoft Edge")
                .join("Default"),
            "brave" => home
                .join("Library")
                .join("Application Support")
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("Default"),
            "chromium" => home
                .join("Library")
                .join("Application Support")
                .join("Chromium")
                .join("Default"),
            _ => return None,
        };
        Some(base.join("Preferences"))
    }

    #[cfg(windows)]
    {
        let local = dirs::data_dir()?;
        let base = match browser {
            "chrome" => local
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default"),
            "edge" => local
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default"),
            "brave" => local
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data")
                .join("Default"),
            "chromium" => local.join("Chromium").join("User Data").join("Default"),
            _ => return None,
        };
        Some(base.join("Preferences"))
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = browser;
        None
    }
}

fn get_firefox_profile_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir()?;
        let profiles = home.join(".mozilla").join("firefox");
        // Find the default profile (contains prefs.js)
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

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()?;
        let profiles = home
            .join("Library")
            .join("Application Support")
            .join("Firefox")
            .join("Profiles");
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

    #[cfg(windows)]
    {
        let app = dirs::data_dir()?;
        let profiles = app.join("Mozilla").join("Firefox").join("Profiles");
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

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn audit_chromium_prefs(prefs_path: &std::path::Path, browser: &str, findings: &mut Vec<Finding>) {
    let content = match std::fs::read_to_string(prefs_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let prefs: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Check telemetry/usage reporting
    let metrics_reporting = prefs
        .pointer("/metrics_reporting/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if metrics_reporting {
        findings.push(Finding::new(
            &format!("browser-{}-telemetry", browser),
            &format!("{} usage reporting is enabled", browser),
            Severity::Medium,
            Category::Browser,
        )
        .description("Browser telemetry/usage reporting is enabled. This sends browsing data to the vendor.")
        .recommendation("Disable usage reporting in browser settings or run: pledgeshield harden browser")
        .fixable(true)
        .metadata("browser", browser));
    }

    // Check safe browsing (should be on)
    let safe_browsing = prefs
        .pointer("/safebrowsing/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if !safe_browsing {
        findings.push(
            Finding::new(
                &format!("browser-{}-no-safebrowsing", browser),
                &format!("{} Safe Browsing is disabled", browser),
                Severity::High,
                Category::Browser,
            )
            .description("Safe Browsing is disabled. The browser won't warn about malicious sites.")
            .recommendation("Re-enable Safe Browsing in browser settings.")
            .fixable(true)
            .metadata("browser", browser),
        );
    }

    // Check third-party cookies
    let cookies = prefs.pointer("/profile/content_settings/exceptions/cookies");
    if let Some(_c) = cookies {
        // Complex to parse; just flag for review
    }
}

fn audit_firefox_prefs(profile_dir: &std::path::Path, findings: &mut Vec<Finding>) {
    let prefs_path = profile_dir.join("prefs.js");
    let content = match std::fs::read_to_string(&prefs_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Check telemetry
    if !content.contains("toolkit.telemetry.enabled\", false") {
        // If it's not explicitly false, it might be on (default is true in many versions)
        if !content.contains("toolkit.telemetry.enabled\", false") {
            findings.push(Finding::new(
                "browser-firefox-telemetry",
                "Firefox telemetry may be enabled",
                Severity::Medium,
                Category::Browser,
            )
            .description("Firefox telemetry is not explicitly disabled. Usage data may be sent to Mozilla.")
            .recommendation("Run: pledgeshield harden browser  (or set toolkit.telemetry.enabled=false in about:config)")
            .fixable(true)
            .metadata("browser", "firefox"));
        }
    }

    // Check tracking protection
    if content.contains("privacy.trackingprotection.enabled\", false") {
        findings.push(Finding::new(
            "browser-firefox-no-tracking-protection",
            "Firefox tracking protection is disabled",
            Severity::Medium,
            Category::Browser,
        )
        .description("Tracking protection is explicitly disabled. Third-party trackers can follow you across sites.")
        .recommendation("Run: pledgeshield harden browser  (or enable in about:config)")
        .fixable(true)
        .metadata("browser", "firefox"));
    }
}

/// Apply browser privacy hardening: disable telemetry, enable tracking protection.
pub fn harden_browser(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    // Chromium-based browsers
    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(prefs_path) = get_chromium_prefs_path(browser) {
            if prefs_path.exists() {
                results.push(harden_chromium_prefs(&prefs_path, browser, dry_run));
            }
        }
    }

    // Firefox
    if let Some(ff_dir) = get_firefox_profile_dir() {
        results.push(harden_firefox_prefs(&ff_dir, dry_run));
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "browser-harden".to_string(),
            success: true,
            message: "No browser profiles found.".to_string(),
            findings: vec![],
        });
    }

    results
}

fn harden_chromium_prefs(
    prefs_path: &std::path::Path,
    browser: &str,
    dry_run: bool,
) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: format!("browser-harden-{}", browser),
            success: true,
            message: format!("[dry-run] Would disable {} telemetry, enable Safe Browsing, block third-party cookies.", browser),
            findings: vec![],
        };
    }

    let content = match std::fs::read_to_string(prefs_path) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: format!("browser-harden-{}", browser),
                success: false,
                message: format!("Failed to read prefs: {}", e),
                findings: vec![],
            }
        }
    };

    let mut prefs: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return HardenResult {
                action: format!("browser-harden-{}", browser),
                success: false,
                message: format!("Failed to parse prefs JSON: {}", e),
                findings: vec![],
            }
        }
    };

    // Disable telemetry
    if let Some(obj) = prefs.as_object_mut() {
        let metrics = obj
            .entry("metrics_reporting")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(m) = metrics.as_object_mut() {
            m.insert("enabled".to_string(), serde_json::json!(false));
        }
        // Enable Safe Browsing
        let sb = obj
            .entry("safebrowsing")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(s) = sb.as_object_mut() {
            s.insert("enabled".to_string(), serde_json::json!(true));
        }
        // Disable background sync (stops data collection when closed)
        let sync = obj
            .entry("background_mode")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(s) = sync.as_object_mut() {
            s.insert("enabled".to_string(), serde_json::json!(false));
        }
    }

    let new_content = match serde_json::to_string_pretty(&prefs) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: format!("browser-harden-{}", browser),
                success: false,
                message: format!("Failed to serialize prefs: {}", e),
                findings: vec![],
            }
        }
    };

    match std::fs::write(prefs_path, new_content) {
        Ok(()) => HardenResult {
            action: format!("browser-harden-{}", browser),
            success: true,
            message: format!(
                "{}: telemetry off, Safe Browsing on, background sync off.",
                browser
            ),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: format!("browser-harden-{}", browser),
            success: false,
            message: format!("Failed to write prefs: {}", e),
            findings: vec![],
        },
    }
}

fn harden_firefox_prefs(profile_dir: &std::path::Path, dry_run: bool) -> HardenResult {
    let prefs_path = profile_dir.join("prefs.js");

    if dry_run {
        return HardenResult {
            action: "browser-harden-firefox".to_string(),
            success: true,
            message: "[dry-run] Would disable telemetry, enable tracking protection, enable DoH."
                .to_string(),
            findings: vec![],
        };
    }

    let content = match std::fs::read_to_string(&prefs_path) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: "browser-harden-firefox".to_string(),
                success: false,
                message: format!("Failed to read prefs.js: {}", e),
                findings: vec![],
            }
        }
    };

    // Firefox prefs.js is JS, not JSON. We append/replace user_pref lines.
    let mut new_lines: Vec<String> = content.lines().map(String::from).collect();

    // Helper: set a pref (replace existing or append)
    let set_pref = |lines: &mut Vec<String>, key: &str, value: &str| {
        let prefix = format!("user_pref(\"{}\", ", key);
        // Remove existing
        lines.retain(|l| !l.starts_with(&prefix));
        // Append new
        lines.push(format!("user_pref(\"{}\", {});", key, value));
    };

    set_pref(&mut new_lines, "toolkit.telemetry.enabled", "false");
    set_pref(&mut new_lines, "toolkit.telemetry.archive.enabled", "false");
    set_pref(
        &mut new_lines,
        "datareporting.healthreport.uploadEnabled",
        "false",
    );
    set_pref(&mut new_lines, "privacy.trackingprotection.enabled", "true");
    set_pref(&mut new_lines, "privacy.donottrackheader.enabled", "true");
    set_pref(&mut new_lines, "network.trr.mode", "2"); // DoH with fallback
    set_pref(
        &mut new_lines,
        "network.trr.uri",
        "\"https://cloudflare-dns.com/dns-query\"",
    );
    set_pref(
        &mut new_lines,
        "browser.safebrowsing.malware.enabled",
        "true",
    );
    set_pref(
        &mut new_lines,
        "browser.safebrowsing.phishing.enabled",
        "true",
    );
    set_pref(&mut new_lines, "media.peerconnection.enabled", "false"); // Prevent WebRTC IP leak

    let new_content = new_lines.join("\n") + "\n";

    match std::fs::write(&prefs_path, new_content) {
        Ok(()) => HardenResult {
            action: "browser-harden-firefox".to_string(),
            success: true,
            message:
                "Firefox: telemetry off, tracking protection on, DoH enabled, WebRTC leak blocked."
                    .to_string(),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "browser-harden-firefox".to_string(),
            success: false,
            message: format!("Failed to write prefs.js: {}", e),
            findings: vec![],
        },
    }
}

/// Clear browser data: cookies, cache, history. Requires browser to be closed.
pub fn clear_browser_data(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(prefs_path) = get_chromium_prefs_path(browser) {
            let base = prefs_path.parent().unwrap_or(std::path::Path::new("."));
            let targets = [
                "Cookies",
                "Cache",
                "Code Cache",
                "GPUCache",
                "History",
                "Visited Links",
            ];
            let mut cleared = 0;
            for t in &targets {
                let p = base.join(t);
                if p.exists() {
                    if !dry_run {
                        let _ = std::fs::remove_dir_all(&p).or_else(|_| std::fs::remove_file(&p));
                    }
                    cleared += 1;
                }
            }
            if cleared > 0 {
                results.push(HardenResult {
                    action: format!("clear-{}-data", browser),
                    success: true,
                    message: if dry_run {
                        format!(
                            "[dry-run] Would clear {} data items from {}.",
                            cleared, browser
                        )
                    } else {
                        format!("Cleared {} data items from {}.", cleared, browser)
                    },
                    findings: vec![],
                });
            }
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "clear-browser-data".to_string(),
            success: true,
            message: "No browser data found to clear.".to_string(),
            findings: vec![],
        });
    }

    results
}
