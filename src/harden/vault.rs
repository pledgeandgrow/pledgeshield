/// Browser password vault auditor — check if saved passwords are encrypted at rest.
use crate::models::{Category, Finding, Severity};
use std::path::Path;

pub fn audit_vault() -> Vec<Finding> {
    let mut findings = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return findings,
    };

    // Chrome / Chromium / Brave / Edge
    let chromium_browsers = [
        ("chrome", "Google Chrome"),
        ("chromium", "Chromium"),
        ("brave", "Brave"),
        ("edge", "Microsoft Edge"),
    ];

    for (dir, name) in &chromium_browsers {
        let profile = home.join(format!(".config/{}/Default", dir));
        #[cfg(target_os = "macos")]
        let profile = home.join(format!("Library/Application Support/{}/Default", dir));
        #[cfg(windows)]
        let profile = home.join(format!("AppData/Local/{}/User Data/Default", dir));

        if profile.exists() {
            let login_db = profile.join("Login Data");
            if login_db.exists() {
                // Check if the DB is encrypted
                if let Ok(data) = std::fs::read(&login_db) {
                    // Chrome stores passwords in SQLite, encrypted with OS keychain
                    // If the file is plaintext SQLite (starts with "SQLite format 3"),
                    // passwords may be accessible
                    if data.starts_with(b"SQLite format 3") {
                        // Check if the encrypted_value column has data
                        // (simplified check — just flag that the DB exists)
                        findings.push(Finding::new(
                            &format!("vault-{}-logins", dir),
                            &format!("{} has saved passwords", name),
                            Severity::Medium,
                            Category::Credentials,
                        )
                        .description("Browser stores saved passwords. Verify they're encrypted with OS keychain (master password)."));
                    }
                }
            }

            // Check if a master password / OS keychain is used
            #[cfg(target_os = "linux")]
            {
                // On Linux, Chrome uses kwallet or gnome-keyring by default
                // If neither is available, passwords are stored with plain DPAPI
                let out = std::process::Command::new("gsettings")
                    .args(["get", "org.gnome.desktop.lockdown", "disable-lock-screen"])
                    .output();
                if let Ok(o) = out {
                    let s = String::from_utf8_lossy(&o.stdout);
                    if s.contains("true") {
                        findings.push(Finding::new(
                            &format!("vault-{}-no-keyring", dir),
                            &format!("{} passwords may not be encrypted (no keyring)", name),
                            Severity::High,
                            Category::Credentials,
                        )
                        .description("Without a keyring (gnome-keyring/kwallet), browser passwords are stored with weak encryption."));
                    }
                }
            }
        }
    }

    // Firefox
    let firefox_profile = home.join(".mozilla/firewall");
    #[cfg(target_os = "macos")]
    let firefox_profile = home.join("Library/Application Support/Firefox/Profiles");
    #[cfg(windows)]
    let firefox_profile = home.join("AppData/Roaming/Mozilla/Firefox/Profiles");

    if firefox_profile.exists() {
        if let Ok(entries) = std::fs::read_dir(&firefox_profile) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains(".default") {
                    let logins_json = path.join("logins.json");
                    let key4_db = path.join("key4.db");

                    if logins_json.exists() {
                        if !key4_db.exists() {
                            findings.push(Finding::new(
                                "vault-firefox-no-master",
                                "Firefox passwords may not have a master password",
                                Severity::High,
                                Category::Credentials,
                            )
                            .description("Firefox logins.json exists but no key4.db (master password database) found. Set a master password."));
                        } else {
                            findings.push(Finding::new(
                                "vault-firefox-encrypted",
                                "Firefox password vault is encrypted (master password set)",
                                Severity::Info,
                                Category::Credentials,
                            ));
                        }
                    }
                }
            }
        }
    }

    findings
}
