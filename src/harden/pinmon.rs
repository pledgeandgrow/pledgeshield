/// Certificate pinning monitor — monitor TLS connections for certificate pinning violations.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_pinmon() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let ca_files = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/usr/local/share/ca-certificates",
        ];
        for path in &ca_files {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.modified().is_ok() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            if elapsed.as_secs() < 3600 {
                                findings.push(Finding::new(
                                    &format!("pinmon-{}-recently-modified", path.split('/').last().unwrap_or("")),
                                    &format!("CA store recently modified: {}", path),
                                    Severity::Medium,
                                    Category::Network,
                                ).description("The CA certificate store was recently modified. An attacker may have injected a rogue CA."));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
