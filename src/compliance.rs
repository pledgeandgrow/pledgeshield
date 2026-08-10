use crate::models::Finding;

/// Compliance framework mapping for a finding.
#[derive(Debug, Clone)]
pub struct ComplianceMapping {
    pub finding_id: String,
    pub cis_control: Option<String>,
    pub nist_control: Option<String>,
}

/// Map a finding to compliance frameworks (CIS Benchmarks, NIST SP 800-53).
pub fn map_finding(finding: &Finding) -> ComplianceMapping {
    let id = &finding.id;

    let (cis, nist) = match id.as_str() {
        // Windows config
        "win-uac-disabled" => (Some("CIS 1.1"), Some("AC-3")),
        "win-firewall-disabled" => (Some("CIS 9.1"), Some("SC-7")),
        "win-defender-disabled" => (Some("CIS 18.1"), Some("SI-3")),
        "win-defender-realtime-disabled" => (Some("CIS 18.3"), Some("SI-3")),
        "win-smartscreen-disabled" => (Some("CIS 18.9"), Some("SC-44")),
        "win-autologin-enabled" => (Some("CIS 2.3"), Some("AC-11")),
        "win-clipboard-history-enabled" => (Some("CIS 2.4"), Some("AC-11")),
        "win-wifi-sense-enabled" => (Some("CIS 19.1"), Some("SC-8")),
        "win-telemetry-full" => (Some("CIS 18.9.2"), Some("AU-14")),
        "win-rdp-nla-disabled" => (Some("CIS 18.9.3"), Some("SC-13")),
        "win-smbv1-enabled" => (Some("CIS 18.9.4.1"), Some("SC-7")),
        "win-share-everyone" => (Some("CIS 18.9.4.2"), Some("AC-5")),
        "win-admin-share" => (Some("CIS 18.9.4.3"), Some("AC-5")),
        "win-guest-enabled" => (Some("CIS 2.1"), Some("AC-2")),
        "win-password-length-weak" => (Some("CIS 1.2"), Some("IA-5")),
        "win-lockout-disabled" => (Some("CIS 1.3"), Some("AC-7")),
        "win-smb-signing-not-required" => (Some("CIS 18.9.4.4"), Some("SC-8")),
        "win-rdp-encryption-low" => (Some("CIS 18.9.4.5"), Some("SC-13")),
        "win-rdp-security-rdp" => (Some("CIS 18.9.4.6"), Some("SC-13")),

        // macOS
        "mac-gatekeeper-disabled" => (Some("CIS 2.6"), Some("CM-7")),
        "mac-firewall-disabled" => (Some("CIS 14.1"), Some("SC-7")),
        "mac-firewall-stealth-disabled" => (Some("CIS 14.2"), Some("SC-7")),
        "mac-filevault-disabled" => (Some("CIS 5.1"), Some("SC-28")),
        "mac-screensaver-insecure" => (Some("CIS 1.6"), Some("AC-11")),
        "mac-guest-access" => (Some("CIS 2.5"), Some("AC-2")),
        "mac-ssh-root-login" => (Some("CIS 5.10"), Some("AC-6")),
        "mac-bluetooth-discoverable" => (Some("CIS 2.7"), Some("AC-18")),

        // Linux
        "linux-ufw-disabled" => (Some("CIS 3.5.1"), Some("SC-7")),
        "linux-ssh-root-login" => (Some("CIS 5.2.6"), Some("AC-6")),
        "linux-ssh-password-auth" => (Some("CIS 5.2.7"), Some("IA-5")),
        "linux-ssh-port-default" => (Some("CIS 5.2.2"), Some("SC-7")),
        "linux-fail2ban-disabled" => (Some("CIS 5.3"), Some("AC-7")),
        "linux-ipv6-enabled" => (Some("CIS 3.1.2"), Some("SC-7")),
        "linux-unattended-upgrades-disabled" => (Some("CIS 1.8"), Some("SI-2")),

        // CVE
        _ if id.starts_with("cve-") => (Some("CIS 3.4"), Some("SI-2")),

        // Default
        _ => (None, None),
    };

    ComplianceMapping {
        finding_id: id.clone(),
        cis_control: cis.map(String::from),
        nist_control: nist.map(String::from),
    }
}

/// Generate a compliance report for all findings.
pub fn generate_compliance_report(findings: &[Finding]) -> String {
    let mut buf = String::new();

    buf.push_str("── Compliance Mapping ─────────────────────────────────\n");
    buf.push_str(&format!(
        "{:<30} {:<15} {:<15} {:<10}\n",
        "Finding ID", "CIS Control", "NIST 800-53", "Severity"
    ));
    buf.push_str(&"─".repeat(75));
    buf.push('\n');

    for f in findings {
        let mapping = map_finding(f);
        let cis = mapping.cis_control.as_deref().unwrap_or("—");
        let nist = mapping.nist_control.as_deref().unwrap_or("—");
        buf.push_str(&format!(
            "{:<30} {:<15} {:<15} {:<10}\n",
            f.id, cis, nist, f.severity
        ));
    }

    buf
}

/// Get compliance summary statistics.
pub fn compliance_summary(findings: &[Finding]) -> (usize, usize, usize) {
    let mut mapped = 0;
    let mut cis_mapped = 0;
    let mut nist_mapped = 0;

    for f in findings {
        let mapping = map_finding(f);
        if mapping.cis_control.is_some() || mapping.nist_control.is_some() {
            mapped += 1;
        }
        if mapping.cis_control.is_some() {
            cis_mapped += 1;
        }
        if mapping.nist_control.is_some() {
            nist_mapped += 1;
        }
    }

    (mapped, cis_mapped, nist_mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Severity};

    #[test]
    fn test_map_finding_uac() {
        let finding = Finding::new(
            "win-uac-disabled",
            "UAC Disabled",
            Severity::High,
            Category::Config,
        );
        let mapping = map_finding(&finding);
        assert_eq!(mapping.cis_control, Some("CIS 1.1".to_string()));
        assert_eq!(mapping.nist_control, Some("AC-3".to_string()));
    }

    #[test]
    fn test_map_finding_firewall() {
        let finding = Finding::new(
            "win-firewall-disabled",
            "Firewall Disabled",
            Severity::High,
            Category::Config,
        );
        let mapping = map_finding(&finding);
        assert_eq!(mapping.cis_control, Some("CIS 9.1".to_string()));
        assert_eq!(mapping.nist_control, Some("SC-7".to_string()));
    }

    #[test]
    fn test_map_finding_macos_filevault() {
        let finding = Finding::new(
            "mac-filevault-disabled",
            "FileVault Disabled",
            Severity::High,
            Category::Config,
        );
        let mapping = map_finding(&finding);
        assert_eq!(mapping.cis_control, Some("CIS 5.1".to_string()));
        assert_eq!(mapping.nist_control, Some("SC-28".to_string()));
    }

    #[test]
    fn test_map_finding_linux_ufw() {
        let finding = Finding::new(
            "linux-ufw-disabled",
            "UFW Disabled",
            Severity::High,
            Category::Config,
        );
        let mapping = map_finding(&finding);
        assert_eq!(mapping.cis_control, Some("CIS 3.5.1".to_string()));
        assert_eq!(mapping.nist_control, Some("SC-7".to_string()));
    }

    #[test]
    fn test_map_finding_cve() {
        let finding = Finding::new(
            "cve-2024-1234",
            "CVE 2024-1234",
            Severity::Critical,
            Category::Cve,
        );
        let mapping = map_finding(&finding);
        assert_eq!(mapping.cis_control, Some("CIS 3.4".to_string()));
        assert_eq!(mapping.nist_control, Some("SI-2".to_string()));
    }

    #[test]
    fn test_map_finding_unknown() {
        let finding = Finding::new(
            "unknown-finding",
            "Unknown",
            Severity::Low,
            Category::Config,
        );
        let mapping = map_finding(&finding);
        assert!(mapping.cis_control.is_none());
        assert!(mapping.nist_control.is_none());
    }

    #[test]
    fn test_compliance_summary() {
        let findings = vec![
            Finding::new("win-uac-disabled", "UAC", Severity::High, Category::Config),
            Finding::new(
                "win-firewall-disabled",
                "Firewall",
                Severity::High,
                Category::Config,
            ),
            Finding::new(
                "unknown-finding",
                "Unknown",
                Severity::Low,
                Category::Config,
            ),
        ];

        let (mapped, cis, nist) = compliance_summary(&findings);
        assert_eq!(mapped, 2);
        assert_eq!(cis, 2);
        assert_eq!(nist, 2);
    }

    #[test]
    fn test_generate_compliance_report() {
        let findings = vec![Finding::new(
            "win-uac-disabled",
            "UAC",
            Severity::High,
            Category::Config,
        )];

        let report = generate_compliance_report(&findings);
        assert!(report.contains("Compliance Mapping"));
        assert!(report.contains("CIS 1.1"));
        assert!(report.contains("AC-3"));
    }
}
