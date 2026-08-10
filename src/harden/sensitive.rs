/// Sensitive file finder — locate private keys, certificates, password files, .env files.
use crate::models::{Category, Finding, Severity};
use std::path::Path;

const SENSITIVE_PATTERNS: &[&str] = &[
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".pem", ".key", ".pfx", ".p12",
    ".env", ".env.local", ".env.production",
    ".netrc", ".my.cnf", ".pgpass", ".ldaprc",
    "credentials", "passwords.txt", "secrets.json",
    "keystore.jks", "keystore.p12",
    ".htpasswd", ".htpasswd",
    "oauth.json", "service-account.json",
    ".aws/credentials", ".aws/config",
    ".kube/config",
    ".docker/config.json",
    ".gnupg/secring.gpg",
];

pub fn find_sensitive_files() -> Vec<Finding> {
    let mut findings = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return findings,
    };

    // Scan home directory (1 level deep for common locations)
    scan_for_sensitive(&home, &mut findings, 0, 3);

    // Scan common config directories
    let config_dirs = [".config", ".local/share", ".aws", ".kube", ".docker", ".gnupg", ".ssh"];
    for dir in &config_dirs {
        let path = home.join(dir);
        if path.exists() {
            scan_for_sensitive(&path, &mut findings, 0, 2);
        }
    }

    findings
}

fn scan_for_sensitive(dir: &Path, findings: &mut Vec<Finding>, depth: usize, max_depth: usize) {
    if depth > max_depth { return; }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('.') && depth == 0 && name == "." { continue; }

            // Check if name matches sensitive patterns
            let name_lower = name.to_lowercase();
            let is_sensitive = SENSITIVE_PATTERNS.iter().any(|p| {
                name_lower.contains(p) || name_lower == p.trim_start_matches('.')
            });

            if is_sensitive {
                let severity = if name_lower.contains("id_rsa") || name_lower.contains("id_ed25519")
                    || name_lower.contains(".pem") || name_lower.contains(".key") { Severity::High }
                    else { Severity::Medium };

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&path) {
                        let mode = meta.permissions().mode();
                        if mode & 0o044 != 0 {
                            findings.push(Finding::new(
                                &format!("sensitive-{}", name.replace('.', "_")),
                                &format!("Sensitive file is world-readable: {}", path.display()),
                                severity,
                                Category::Credentials,
                            )
                            .description("This file likely contains secrets and is readable by all users.")
                            .recommendation(&format!("Run: chmod 600 {}", path.display()))
                            .fixable(true));
                        } else {
                            // File exists but permissions are OK — still note it
                            findings.push(Finding::new(
                                &format!("sensitive-found-{}", name.replace('.', "_")),
                                &format!("Sensitive file found: {}", path.display()),
                                Severity::Info,
                                Category::Credentials,
                            )
                            .description("This file may contain secrets. Verify it's properly secured and not committed to any repository."));
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                findings.push(Finding::new(
                    &format!("sensitive-found-{}", name.replace('.', "_")),
                    &format!("Sensitive file found: {}", path.display()),
                    severity,
                    Category::Credentials,
                ));
                }
            }

            // Recurse into directories
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() && !name.starts_with(".cache") && name != "node_modules" && name != "target" {
                    scan_for_sensitive(&path, findings, depth + 1, max_depth);
                }
            }
        }
    }
}
