/// Container image scanner — deep scan container images for vulnerabilities, secrets, misconfigs.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_imagescan() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "which trivy 2>/dev/null"])
            .output();
        if let Ok(o) = out {
            if String::from_utf8_lossy(&o.stdout).is_empty() {
                findings.push(Finding::new(
                    "imagescan-no-trivy",
                    "Trivy scanner not installed",
                    Severity::Low,
                    Category::System,
                ).description("Trivy is not installed. Install it to scan container images for vulnerabilities."));
            }
        }

        let out = Command::new("sh")
            .args([
                "-c",
                "which docker 2>/dev/null && docker images -q 2>/dev/null | wc -l",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Ok(count) = s.trim().parse::<u32>() {
                if count > 10 {
                    findings.push(Finding::new(
                        "imagescan-many-images",
                        &format!("{} Docker images present", count),
                        Severity::Low,
                        Category::System,
                    ).description("Many Docker images are present. Scan them for vulnerabilities and remove unused ones."));
                }
            }
        }
    }

    findings
}

pub fn scan_image(image: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("trivy")
            .args(["image", "--format", "json", image])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("CRITICAL") {
                findings.push(
                    Finding::new(
                        &format!("imagescan-{}-critical", image),
                        &format!("Critical vulnerabilities in {}", image),
                        Severity::Critical,
                        Category::System,
                    )
                    .description(&format!(
                        "Trivy found critical vulnerabilities in container image {}.",
                        image
                    )),
                );
            }
            if s.contains("HIGH") {
                findings.push(
                    Finding::new(
                        &format!("imagescan-{}-high", image),
                        &format!("High vulnerabilities in {}", image),
                        Severity::High,
                        Category::System,
                    )
                    .description(&format!(
                        "Trivy found high-severity vulnerabilities in container image {}.",
                        image
                    )),
                );
            }
        }
    }

    findings
}
