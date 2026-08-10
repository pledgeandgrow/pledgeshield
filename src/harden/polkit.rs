/// Polkit/pkexec auditor — check polkit rules for overly permissive actions.
use crate::models::{Category, Finding, Severity};
use std::path::Path;
use std::process::Command;

pub fn audit_polkit() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check polkit rules directory
        let rules_dirs = ["/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"];
        for dir in &rules_dirs {
            if !Path::new(dir).exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        // Check for overly permissive rules
                        if content.contains("auth_yes") && content.contains("any") {
                            findings.push(Finding::new(
                                &format!("polkit-permissive-{}", path.file_name().unwrap_or_default().to_string_lossy()),
                                &format!("Permissive polkit rule: {}", path.display()),
                                Severity::Medium,
                                Category::Privileges,
                            )
                            .description("A polkit rule allows any user to perform privileged actions without authentication."));
                        }

                        // Check for rules that allow admin actions without password
                        if content.contains("auth_admin_keep") || content.contains("auth_yes_keep")
                        {
                            findings.push(Finding::new(
                                &format!("polkit-keep-auth-{}", path.file_name().unwrap_or_default().to_string_lossy()),
                                &format!("Polkit rule keeps authentication: {}", path.display()),
                                Severity::Low,
                                Category::Privileges,
                            )
                            .description("This polkit rule keeps authentication alive, which could be abused if the session is compromised."));
                        }
                    }
                }
            }
        }

        // Check pkexec permissions
        let pkexec = "/usr/bin/pkexec";
        if Path::new(pkexec).exists() {
            if let Ok(meta) = std::fs::metadata(pkexec) {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o4000 != 0 {
                    // SUID
                    // pkexec with SUID is normal, but check for known CVEs
                    findings.push(Finding::new(
                        "polkit-pkexec-suid",
                        "pkexec has SUID bit (check for CVE-2021-4034 PwnKit)",
                        Severity::Medium,
                        Category::Privileges,
                    )
                    .description("pkexec with SUID is normal but was vulnerable to PwnKit (CVE-2021-4034). Ensure your system is patched."));
                }
            }
        }

        // Check if polkit service is running
        let out = Command::new("systemctl")
            .args(["is-active", "polkit"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "inactive" || s == "failed" {
                findings.push(Finding::new(
                    "polkit-not-running",
                    "polkit service is not running",
                    Severity::Low,
                    Category::Services,
                ));
            }
        }
    }

    findings
}
