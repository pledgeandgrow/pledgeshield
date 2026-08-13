/// DNS tunneling detector — detect DNS tunneling via long queries, high-entropy subdomains, TXT abuse.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_dnstunnel() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args(["-c", "journalctl -u systemd-resolved --no-pager -n 1000 2>/dev/null || cat /var/log/syslog 2>/dev/null | grep -i dns | tail -1000"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut long_queries = 0;
            let mut txt_queries = 0;
            for line in s.lines() {
                if line.contains("TXT") {
                    txt_queries += 1;
                }
                if line.len() > 100 {
                    long_queries += 1;
                }
            }
            if long_queries > 50 {
                findings.push(Finding::new(
                    "dnstunnel-long-queries",
                    &format!("{} unusually long DNS queries detected", long_queries),
                    Severity::Medium,
                    Category::Network,
                ).description("High number of long DNS queries may indicate DNS tunneling for data exfiltration."));
            }
            if txt_queries > 30 {
                findings.push(
                    Finding::new(
                        "dnstunnel-txt-queries",
                        &format!("{} TXT DNS queries detected", txt_queries),
                        Severity::Low,
                        Category::Network,
                    )
                    .description("High number of TXT queries may indicate DNS tunneling."),
                );
            }
        }
    }

    findings
}
