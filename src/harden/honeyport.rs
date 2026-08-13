/// Network honeytoken — deploy fake network services to detect lateral movement.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[cfg(target_os = "linux")]
const HONEYPORTS: &[u16] = &[22, 80, 443, 3389, 8080];

pub fn audit_honeyport() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ss").args(["-tlnp"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let deployed = HONEYPORTS.iter().any(|p| s.contains(&format!(":{}", p)));
            if !deployed {
                findings.push(Finding::new(
                    "honeyport-not-deployed",
                    "No honeyport services detected",
                    Severity::Low,
                    Category::Network,
                ).description("No honeyport services are running. Deploy fake services to detect unauthorized scanning and lateral movement."));
            }
        }
    }

    findings
}

pub fn deploy_honeyport(port: u16, dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "honeyport-deploy".to_string(),
            success: true,
            message: format!("Would deploy honeyport on port {} (dry run)", port),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "nohup nc -l -p {} -k > /tmp/honeyport-{}.log 2>&1 &",
                    port, port
                ),
            ])
            .output();

        if out.is_ok() {
            HardenResult {
                action: "honeyport-deploy".to_string(),
                success: true,
                message: format!(
                    "Honeyport deployed on port {}. Connections logged to /tmp/honeyport-{}.log",
                    port, port
                ),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "honeyport-deploy".to_string(),
                success: false,
                message: format!("Failed to deploy honeyport on port {}", port),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = port;
        HardenResult {
            action: "honeyport-deploy".to_string(),
            success: false,
            message: "Honeyport deployment is only supported on Linux".to_string(),
            findings: vec![],
        }
    }
}
