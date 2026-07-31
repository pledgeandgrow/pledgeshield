use crate::models::{Category, Finding, Severity};
use std::path::PathBuf;

/// Audit browser extensions for risky permissions and known-bad extensions.
pub fn audit_browser_extensions() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Chrome/Chromium/Brave/Edge extensions
    for browser in &["chrome", "chromium", "brave", "edge"] {
        if let Some(ext_dir) = get_extension_dir(browser) {
            if ext_dir.exists() {
                findings.extend(audit_chromium_extensions(&ext_dir, browser));
            }
        }
    }

    // Firefox extensions
    if let Some(firefox_dir) = get_firefox_profile_dir() {
        if firefox_dir.exists() {
            findings.extend(audit_firefox_extensions(&firefox_dir));
        }
    }

    findings
}

/// Get the extension directory for Chromium-based browsers.
fn get_extension_dir(browser: &str) -> Option<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let home = dirs::home_dir()?;

    #[cfg(windows)]
    {
        let local_app = dirs::data_dir()?;
        match browser {
            "chrome" => Some(local_app.join("Google").join("Chrome").join("User Data").join("Default").join("Extensions")),
            "edge" => Some(local_app.join("Microsoft").join("Edge").join("User Data").join("Default").join("Extensions")),
            "brave" => Some(local_app.join("BraveSoftware").join("Brave-Browser").join("User Data").join("Default").join("Extensions")),
            "chromium" => Some(local_app.join("Chromium").join("User Data").join("Default").join("Extensions")),
            _ => None,
        }
    }

    #[cfg(target_os = "macos")]
    {
        match browser {
            "chrome" => Some(home.join("Library").join("Application Support").join("Google").join("Chrome").join("Default").join("Extensions")),
            "edge" => Some(home.join("Library").join("Application Support").join("Microsoft Edge").join("Default").join("Extensions")),
            "brave" => Some(home.join("Library").join("Application Support").join("BraveSoftware").join("Brave-Browser").join("Default").join("Extensions")),
            "chromium" => Some(home.join("Library").join("Application Support").join("Chromium").join("Default").join("Extensions")),
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let config = dirs::config_dir()?;
        match browser {
            "chrome" => Some(config.join("google-chrome").join("Default").join("Extensions")),
            "edge" => Some(config.join("microsoft-edge").join("Default").join("Extensions")),
            "brave" => Some(config.join("BraveSoftware").join("Brave-Browser").join("Default").join("Extensions")),
            "chromium" => Some(config.join("chromium").join("Default").join("Extensions")),
            _ => None,
        }
    }
}

/// Get Firefox profile directory.
fn get_firefox_profile_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let app = dirs::data_dir()?;
        Some(app.join("Mozilla").join("Firefox").join("Profiles"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()?;
        Some(home.join("Library").join("Application Support").join("Firefox").join("Profiles"))
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir()?;
        Some(home.join(".mozilla").join("firefox"))
    }
}

/// Audit Chromium-based browser extensions.
fn audit_chromium_extensions(ext_dir: &std::path::Path, browser: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Known risky extension IDs (malware/adware)
    let risky_extensions = [
        ("cooliris", "Cooliris (known adware)"),
        ("speedbit", "Speedbit (known adware)"),
    ];

    // Extensions with dangerous permissions
    let dangerous_permissions = [
        "<all_urls>",
        "webRequest",
        "webRequestBlocking",
        "tabs",
        "cookies",
        "history",
        "downloads",
        "management",
        "nativeMessaging",
    ];

    if let Ok(entries) = std::fs::read_dir(ext_dir) {
        for entry in entries.flatten() {
            let ext_id = entry.file_name().to_string_lossy().to_string();

            // Check for known risky extensions
            for (risk_id, risk_desc) in &risky_extensions {
                if ext_id.to_lowercase().contains(risk_id) {
                    findings.push(
                        Finding::new(
                            &format!("browser-{}-risky-{}", browser, ext_id),
                            &format!("Risky Browser Extension: {}", risk_desc),
                            Severity::High,
                            Category::Services,
                        )
                        .description(&format!("Extension '{}' in {} browser is flagged as risky/adware.", ext_id, browser))
                        .recommendation("Remove this extension from your browser.")
                        .metadata("browser", browser)
                        .metadata("extension_id", &ext_id)
                    );
                }
            }

            // Check manifest for dangerous permissions
            let manifest_path = entry.path().join("manifest.json");
            if let Ok(manifest_content) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&manifest_content) {
                    let ext_name = manifest.get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or(&ext_id);

                    if let Some(perms) = manifest.get("permissions").and_then(|p| p.as_array()) {
                        let perm_count = perms.len();
                        let dangerous_count = perms.iter()
                            .filter(|p| {
                                p.as_str().map(|s| dangerous_permissions.contains(&s)).unwrap_or(false)
                            })
                            .count();

                        if dangerous_count >= 3 {
                            findings.push(
                                Finding::new(
                                    &format!("browser-{}-perms-{}", browser, ext_id),
                                    &format!("Browser Extension with Broad Permissions: {}", ext_name),
                                    Severity::Medium,
                                    Category::Services,
                                )
                                .description(&format!(
                                    "Extension '{}' in {} browser has {} permission(s), including {} dangerous one(s). Broad permissions can be abused for data theft.",
                                    ext_name, browser, perm_count, dangerous_count
                                ))
                                .recommendation("Review if this extension truly needs all these permissions. Consider removing if not essential.")
                                .metadata("browser", browser)
                                .metadata("extension_id", &ext_id)
                                .metadata("permission_count", &perm_count.to_string())
                                .metadata("dangerous_count", &dangerous_count.to_string())
                            );
                        }

                        // Check for <all_urls> specifically
                        if perms.iter().any(|p| p.as_str() == Some("<all_urls>")) {
                            findings.push(
                                Finding::new(
                                    &format!("browser-{}-allurls-{}", browser, ext_id),
                                    &format!("Extension Can Access All Sites: {}", ext_name),
                                    Severity::Medium,
                                    Category::Services,
                                )
                                .description(&format!(
                                    "Extension '{}' in {} browser has <all_urls> permission, allowing it to read and modify all websites you visit.",
                                    ext_name, browser
                                ))
                                .recommendation("Consider restricting the extension to specific sites or removing it if not trusted.")
                                .metadata("browser", browser)
                                .metadata("extension_id", &ext_id)
                            );
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Audit Firefox browser extensions.
fn audit_firefox_extensions(profile_dir: &std::path::Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(entries) = std::fs::read_dir(profile_dir) {
        for entry in entries.flatten() {
            let extensions_json = entry.path().join("extensions.json");
            if let Ok(content) = std::fs::read_to_string(&extensions_json) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(addons) = json.get("addons").and_then(|a| a.as_array()) {
                        for addon in addons {
                            let name = addon.get("defaultLocale")
                                .and_then(|l| l.get("name"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown");
                            let addon_id = addon.get("id").and_then(|i| i.as_str()).unwrap_or("unknown");

                            // Check for broad permissions
                            if let Some(perms) = addon.get("userPermissions").and_then(|p| p.get("permissions")).and_then(|p| p.as_array()) {
                                if perms.iter().any(|p| p.as_str() == Some("<all_urls>")) {
                                    findings.push(
                                        Finding::new(
                                            &format!("browser-firefox-allurls-{}", addon_id),
                                            &format!("Firefox Extension Can Access All Sites: {}", name),
                                            Severity::Medium,
                                            Category::Services,
                                        )
                                        .description(&format!("Firefox extension '{}' has <all_urls> permission.", name))
                                        .recommendation("Review if this extension needs access to all sites.")
                                        .metadata("browser", "firefox")
                                        .metadata("extension_id", addon_id)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_browser_extensions_no_crash() {
        // Should not crash even if no browsers are installed
        let findings = audit_browser_extensions();
        // On CI without browsers, this returns empty. With browsers, may return findings.
        let _ = findings.len();
    }
}
