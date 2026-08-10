/// WebRTC leak blocker — disable WebRTC in all browsers to prevent real IP leaks behind VPN.
use super::HardenResult;
use std::path::PathBuf;

pub fn audit_webrtc() -> Vec<crate::models::Finding> {
    use crate::models::{Category, Finding, Severity};
    let mut findings = Vec::new();

    // Check Firefox prefs for WebRTC
    if let Some(ff_dir) = get_firefox_profile_dir() {
        let prefs_path = ff_dir.join("prefs.js");
        if let Ok(content) = std::fs::read_to_string(&prefs_path) {
            if !content.contains("media.peerconnection.enabled\", false") {
                findings.push(Finding::new(
                    "webrtc-firefox-enabled",
                    "Firefox WebRTC is enabled (IP leak risk)",
                    Severity::Medium,
                    Category::Browser,
                )
                .description("WebRTC can leak your real IP address even when using a VPN.")
                .recommendation("Run: pledgeshield harden webrtc --block")
                .fixable(true)
                .metadata("browser", "firefox"));
            }
        }
    }

    // Chromium-based browsers don't have a simple prefs toggle for WebRTC,
    // but we can check if the policy is set
    for browser in &["chrome", "chromium", "brave", "edge"] {
        if get_chromium_prefs_path(browser).is_some() {
            findings.push(Finding::new(
                &format!("webrtc-{}-check", browser),
                &format!("{} WebRTC status unknown (check via browser)", browser),
                Severity::Low,
                Category::Browser,
            )
            .description("Chromium-based browsers need a WebRTC blocking extension or policy.")
            .recommendation("Run: pledgeshield harden webrtc --block  (sets policy to block WebRTC)")
            .fixable(true)
            .metadata("browser", browser.to_string()));
        }
    }

    findings
}

pub fn block_webrtc(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    // Firefox: set media.peerconnection.enabled = false
    if let Some(ff_dir) = get_firefox_profile_dir() {
        let prefs_path = ff_dir.join("prefs.js");
        if prefs_path.exists() {
            if dry_run {
                results.push(HardenResult {
                    action: "webrtc-block-firefox".to_string(),
                    success: true,
                    message: "[dry-run] Would disable WebRTC in Firefox.".to_string(),
                    findings: vec![],
                });
            } else {
                let content = std::fs::read_to_string(&prefs_path).unwrap_or_default();
                let mut lines: Vec<String> = content.lines()
                    .filter(|l| !l.starts_with("user_pref(\"media.peerconnection"))
                    .map(String::from)
                    .collect();
                lines.push("user_pref(\"media.peerconnection.enabled\", false);".to_string());
                lines.push("user_pref(\"media.peerconnection.turn.disable\", true);".to_string());
                lines.push("user_pref(\"media.peerconnection.use_document_iceservers\", false);".to_string());
                lines.push("user_pref(\"media.peerconnection.video.enabled\", false);".to_string());
                lines.push("user_pref(\"media.peerconnection.identity.enabled\", false);".to_string());
                lines.push("user_pref(\"media.peerconnection.ice.default_address_only\", true);".to_string());
                let _ = std::fs::write(&prefs_path, lines.join("\n") + "\n");
                results.push(HardenResult {
                    action: "webrtc-block-firefox".to_string(),
                    success: true,
                    message: "Firefox WebRTC disabled + ICE restricted to default address only.".to_string(),
                    findings: vec![],
                });
            }
        }
    }

    // Chromium: set policy to block WebRTC
    #[cfg(target_os = "linux")]
    {
        for browser in &["chrome", "chromium", "brave", "edge"] {
            let policy_dir = match *browser {
                "chrome" => "/etc/opt/chrome/policies/managed",
                "chromium" => "/etc/chromium/policies/managed",
                "brave" => "/etc/brave/policies/managed",
                "edge" => "/etc/opt/edge/policies/managed",
                _ => continue,
            };
            if dry_run {
                results.push(HardenResult {
                    action: format!("webrtc-block-{}", browser),
                    success: true,
                    message: format!("[dry-run] Would set {} WebRTC policy to block.", browser),
                    findings: vec![],
                });
            } else {
                let _ = std::fs::create_dir_all(policy_dir);
                let policy = r#"{"WebRtcIPHandling": {"Default": "disable_non_proxied_udp"}}"#;
                let policy_path = format!("{}/pledgeshield-webrtc.json", policy_dir);
                match std::fs::write(&policy_path, policy) {
                    Ok(()) => results.push(HardenResult {
                        action: format!("webrtc-block-{}", browser),
                        success: true,
                        message: format!("{} WebRTC policy set (disable_non_proxied_udp).", browser),
                        findings: vec![],
                    }),
                    Err(e) => results.push(HardenResult {
                        action: format!("webrtc-block-{}", browser),
                        success: false,
                        message: format!("Failed: {}", e),
                        findings: vec![],
                    }),
                }
            }
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "webrtc-block".to_string(),
            success: true,
            message: "No browser profiles found.".to_string(),
            findings: vec![],
        });
    }

    results
}

pub fn restore_webrtc() -> Vec<HardenResult> {
    let mut results = Vec::new();

    // Firefox
    if let Some(ff_dir) = get_firefox_profile_dir() {
        let prefs_path = ff_dir.join("prefs.js");
        if prefs_path.exists() {
            let content = std::fs::read_to_string(&prefs_path).unwrap_or_default();
            let lines: Vec<String> = content.lines()
                .filter(|l| !l.starts_with("user_pref(\"media.peerconnection"))
                .map(String::from)
                .collect();
            let _ = std::fs::write(&prefs_path, lines.join("\n") + "\n");
            results.push(HardenResult {
                action: "webrtc-restore-firefox".to_string(),
                success: true,
                message: "Firefox WebRTC settings restored.".to_string(),
                findings: vec![],
            });
        }
    }

    // Chromium policies
    #[cfg(target_os = "linux")]
    {
        for path in &[
            "/etc/opt/chrome/policies/managed/pledgeshield-webrtc.json",
            "/etc/chromium/policies/managed/pledgeshield-webrtc.json",
            "/etc/brave/policies/managed/pledgeshield-webrtc.json",
            "/etc/opt/edge/policies/managed/pledgeshield-webrtc.json",
        ] {
            if std::path::Path::new(path).exists() {
                let _ = std::fs::remove_file(path);
                results.push(HardenResult {
                    action: "webrtc-restore".to_string(),
                    success: true,
                    message: format!("Removed {}", path),
                    findings: vec![],
                });
            }
        }
    }

    if results.is_empty() {
        results.push(HardenResult {
            action: "webrtc-restore".to_string(),
            success: true,
            message: "No WebRTC blocks found to remove.".to_string(),
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

fn get_chromium_prefs_path(browser: &str) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let config = dirs::config_dir()?;
        let base = match browser {
            "chrome" => config.join("google-chrome").join("Default"),
            "edge" => config.join("microsoft-edge").join("Default"),
            "brave" => config.join("BraveSoftware").join("Brave-Browser").join("Default"),
            "chromium" => config.join("chromium").join("Default"),
            _ => return None,
        };
        Some(base.join("Preferences"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = browser;
        None
    }
}
