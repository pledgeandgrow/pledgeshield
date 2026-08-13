/// Kerberos ticket monitor — monitor for golden ticket indicators.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_kerberos() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("klist").args(["sessions"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("krbtgt") {
                    findings.push(Finding::new(
                        "kerberos-krbtgt-active",
                        "krbtgt ticket detected in session",
                        Severity::High,
                        Category::Credentials,
                    ).description("A krbtgt ticket-granting ticket was found. Monitor for golden ticket attacks if unexpected."));
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        findings.push(
            Finding::new(
                "kerberos-not-applicable",
                "Kerberos monitoring is Windows/AD-only",
                Severity::Info,
                Category::Credentials,
            )
            .description(
                "Kerberos ticket monitoring is only applicable on Windows with Active Directory.",
            ),
        );
    }

    findings
}
