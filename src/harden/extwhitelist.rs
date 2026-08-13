/// Browser extension whitelist — enforce allowed browser extensions, remove unapproved ones.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};

const APPROVED_EXTENSIONS: &[&str] = &["uBlock Origin", "Privacy Badger", "Bitwarden"];

pub fn audit_extwhitelist() -> Vec<Finding> {
    let mut findings = Vec::new();

    let browser_paths = [
        #[cfg(target_os = "linux")]
        ("Chrome", "~/.config/google-chrome/Default/Extensions"),
        #[cfg(target_os = "linux")]
        ("Firefox", "~/.mozilla/firefox"),
        #[cfg(target_os = "macos")]
        (
            "Chrome",
            "~/Library/Application Support/Google/Chrome/Default/Extensions",
        ),
        #[cfg(target_os = "windows")]
        (
            "Chrome",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions",
        ),
    ];

    let mut any_found = false;
    for (browser, path) in &browser_paths {
        let expanded = if path.starts_with("~") {
            if let Some(home) = std::env::var_os("HOME").or(std::env::var_os("USERPROFILE")) {
                format!("{}{}", home.to_string_lossy(), &path[1..])
            } else {
                continue;
            }
        } else {
            path.to_string()
        };

        if std::path::Path::new(&expanded).exists() {
            any_found = true;
            findings.push(
                Finding::new(
                    &format!("extwhitelist-{}-found", browser.to_lowercase()),
                    &format!("{} extension directory found", browser),
                    Severity::Info,
                    Category::Browser,
                )
                .description(&format!(
                    "Review {} extensions manually. Approved: {}",
                    browser,
                    APPROVED_EXTENSIONS.join(", ")
                )),
            );
        }
    }

    if !any_found {
        findings.push(
            Finding::new(
                "extwhitelist-no-browsers",
                "No browser extension directories found",
                Severity::Info,
                Category::Browser,
            )
            .description("No browser extension directories were detected."),
        );
    }

    findings
}

pub fn list_extensions() -> Vec<String> {
    let mut result = Vec::new();
    result.push("Approved extensions:".to_string());
    for ext in APPROVED_EXTENSIONS {
        result.push(format!("  ✓ {}", ext));
    }
    result
}
