/// Supply chain verifier — verify checksums/signatures of downloaded packages.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_verify() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "which apt 2>/dev/null"])
            .output();
        if let Ok(o) = out {
            if !String::from_utf8_lossy(&o.stdout).is_empty() {
                let out2 = Command::new("apt").args(["-v"]).output();
                if let Ok(o2) = out2 {
                    let ver = String::from_utf8_lossy(&o2.stdout);
                    if !ver.contains("signed-by") && !ver.contains("Signed-By") {
                        findings.push(Finding::new(
                            "verify-apt-no-signing",
                            "APT repositories may lack signing",
                            Severity::Low,
                            Category::System,
                        ).description("Verify that all APT repositories use signed-by for GPG verification."));
                    }
                }
            }
        }
    }

    findings
}

pub fn verify_package(name: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", &format!("dpkg -V {} 2>/dev/null", name)])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.is_empty() {
                findings.push(Finding::new(
                    &format!("verify-{}-modified", name),
                    &format!("Package {} has been modified from installed version", name),
                    Severity::High,
                    Category::System,
                ).description(&format!("dpkg -V reports modifications to {}. Files may have been tampered with.\n{}", name, s)));
            }
        }
    }

    findings
}
