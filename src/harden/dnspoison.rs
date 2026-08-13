/// DNS cache poisoning detector — monitor local DNS cache for signs of poisoning.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_dnspoison() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("systemd-resolve")
            .args(["--statistics"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("Transactions") {
                    if let Some(current) = line.split_whitespace().last() {
                        if let Ok(n) = current.parse::<u32>() {
                            if n > 100 {
                                findings.push(Finding::new(
                                    "dnspoison-high-transactions",
                                    "Unusually high DNS transaction count",
                                    Severity::Medium,
                                    Category::Network,
                                ).description(&format!("{} DNS transactions detected. High volume may indicate cache poisoning attempts.", n)));
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("ipconfig").args(["/displaydns"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let entry_count = s.matches("Record Name").count();
            if entry_count > 200 {
                findings.push(Finding::new(
                    "dnspoison-large-cache",
                    "DNS cache is unusually large",
                    Severity::Low,
                    Category::Network,
                ).description(&format!("{} DNS cache entries detected. An unusually large cache may indicate poisoning.", entry_count)));
            }
        }
    }

    findings
}
