/// SMB relay protection — enforce SMB signing and detect relay attack indicators.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_smbrelay() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/samba/smb.conf") {
            let mut signing_enabled = false;
            let mut min_protocol = String::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("client signing") || trimmed.starts_with("server signing") {
                    if trimmed.contains("mandatory") || trimmed.contains("true") {
                        signing_enabled = true;
                    }
                }
                if trimmed.starts_with("server min protocol") {
                    min_protocol = trimmed.split('=').nth(1).unwrap_or("").trim().to_string();
                }
            }
            if !signing_enabled {
                findings.push(Finding::new(
                    "smbrelay-no-signing",
                    "SMB signing is not enforced",
                    Severity::High,
                    Category::Network,
                ).description("SMB signing is not mandatory. SMB relay attacks can intercept and modify traffic."));
            }
            if min_protocol.is_empty() || min_protocol == "SMB1" || min_protocol == "NT1" {
                findings.push(Finding::new(
                    "smbrelay-smb1",
                    "SMBv1 is allowed",
                    Severity::Critical,
                    Category::Network,
                ).description("SMBv1 is enabled, which is vulnerable to relay attacks and was exploited by EternalBlue."));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args([
                "-Command",
                "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("True") {
                findings.push(Finding::new(
                    "smbrelay-no-signing",
                    "SMB signing is not required",
                    Severity::High,
                    Category::Network,
                ).description("SMB signing is not required on the server. Enable it to prevent relay attacks."));
            }
        }
    }

    findings
}
