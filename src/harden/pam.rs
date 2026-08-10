/// PAM module auditor — check PAM config for weak/backdoored modules.
use crate::models::{Category, Finding, Severity};
use std::path::Path;

pub fn audit_pam() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let pam_files = [
            "/etc/pam.d/common-auth",
            "/etc/pam.d/common-password",
            "/etc/pam.d/common-account",
            "/etc/pam.d/common-session",
            "/etc/pam.d/su",
            "/etc/pam.d/sudo",
            "/etc/pam.d/login",
            "/etc/pam.d/sshd",
        ];

        for file in &pam_files {
            if !Path::new(file).exists() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(file) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }

                    // Check for modules loaded from non-standard paths
                    if line.contains(".so")
                        && !line.contains("lib/security/")
                        && !line.contains("lib64/security/")
                    {
                        let so_path = line
                            .split_whitespace()
                            .find(|w| w.ends_with(".so"))
                            .unwrap_or("");
                        if so_path.starts_with("/tmp/")
                            || so_path.starts_with("/home/")
                            || so_path.starts_with("/var/")
                        {
                            findings.push(Finding::new(
                                &format!("pam-backdoor-{}", file.replace('/', "_")),
                                &format!("PAM module from suspicious path in {}: {}", file, so_path),
                                Severity::Critical,
                                Category::HostConfig,
                            )
                            .description("A PAM module is being loaded from a non-standard path. This is a common backdoor technique to capture passwords."));
                        }
                    }

                    // Check for missing password quality controls
                    if file.ends_with("common-password") && line.contains("pam_unix.so") {
                        if !content.contains("pam_pwquality") && !content.contains("pam_cracklib") {
                            findings.push(
                                Finding::new(
                                    "pam-no-quality",
                                    "No password quality module in PAM config",
                                    Severity::Medium,
                                    Category::HostConfig,
                                )
                                .description(
                                    "Password quality is not enforced. Weak passwords can be set.",
                                )
                                .recommendation(
                                    "Install libpam-pwquality and add to common-password",
                                )
                                .fixable(true),
                            );
                        }
                    }

                    // Check for sufficient password hashing rounds
                    if line.contains("pam_unix.so") && line.contains("sha512") {
                        if !line.contains("rounds=") {
                            findings.push(Finding::new(
                                "pam-low-rounds",
                                "Password hashing uses default rounds",
                                Severity::Low,
                                Category::HostConfig,
                            )
                            .description("Adding rounds=10000 to pam_unix.so increases password hash strength."));
                        }
                    }

                    // Check for pam_tally2/pam_faillock (account lockout)
                    if file.ends_with("common-auth") {
                        if !content.contains("pam_faillock") && !content.contains("pam_tally2") {
                            findings.push(Finding::new(
                                "pam-no-lockout",
                                "No account lockout after failed logins",
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("Without pam_faillock, brute force attacks can proceed without lockout.")
                            .fixable(true));
                        }
                    }
                }
            }
        }
    }

    findings
}
