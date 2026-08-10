/// Packet capture detector — detect if your machine is being sniffed.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_pcap() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check for promiscuous mode interfaces
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "lo" { continue; }

                // Check flags for PROMISC
                let flags_path = format!("/sys/class/net/{}/flags", name);
                if let Ok(content) = std::fs::read_to_string(&flags_path) {
                    let flags = u32::from_str_radix(content.trim().trim_start_matches("0x"), 16).unwrap_or(0);
                    if flags & 0x100 != 0 { // IFF_PROMISC
                        findings.push(Finding::new(
                            &format!("pcap-promisc-{}", name),
                            &format!("Interface {} is in promiscuous mode", name),
                            Severity::High,
                            Category::Network,
                        )
                        .description("An interface is in promiscuous mode, capturing all network traffic. This could be a packet sniffer (tcpdump, wireshark) or malware."));
                    }
                }
            }
        }

        // Check for running packet capture tools
        let out = Command::new("ps").args(["-eo", "comm"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let sniffers = ["tcpdump", "tshark", "wireshark", "dumpcap", "ettercap", "bettercap", "kismet", "airsnort"];
            for sniffer in &sniffers {
                if s.contains(sniffer) {
                    findings.push(Finding::new(
                        &format!("pcap-tool-{}", sniffer),
                        &format!("Packet capture tool running: {}", sniffer),
                        Severity::Medium,
                        Category::Network,
                    )
                    .description("A packet capture tool is running. If you didn't start it, someone may be sniffing your traffic."));
                }
            }
        }

        // Check for raw socket processes
        let out = Command::new("ss").args(["-tunlp"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("raw") {
                // Check which process has raw sockets
                let out2 = Command::new("sh").args(["-c", "cat /proc/net/raw 2>/dev/null | tail -n +2"]).output();
                if let Ok(o2) = out2 {
                    let raw_count = String::from_utf8_lossy(&o2.stdout).lines().count();
                    if raw_count > 0 {
                        findings.push(Finding::new(
                            "pcap-raw-sockets",
                            &format!("{} raw socket(s) active", raw_count),
                            Severity::Low,
                            Category::Network,
                        )
                        .description("Raw sockets can be used for packet sniffing. Check which process owns them."));
                    }
                }
            }
        }
    }

    findings
}
