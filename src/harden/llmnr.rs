/// LLMNR/NBT-NS poisoning detector — detect name resolution poisoning attacks.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_llmnr() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("sh")
            .args([
                "-c",
                "cat /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null",
            ])
            .output();
        if let Ok(o) = out {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if val != "0" {
                findings.push(Finding::new(
                    "llmnr-source-routing",
                    "Source routing is enabled",
                    Severity::High,
                    Category::Network,
                ).description("Source routing is enabled, which can facilitate LLMNR/NBT-NS poisoning relay attacks."));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                "/v",
                "EnableMulticast",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("0x0") {
                findings.push(Finding::new(
                    "llmnr-enabled",
                    "LLMNR is enabled on Windows",
                    Severity::High,
                    Category::Network,
                ).description("Link-Local Multicast Name Resolution (LLMNR) is enabled. Disable it to prevent poisoning attacks."));
            }
        }
    }

    findings
}
