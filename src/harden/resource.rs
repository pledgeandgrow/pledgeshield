/// System resource anomaly detector — monitor CPU/RAM for spikes (crypto miners, malware).
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_resources() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check top CPU consumers
        let out = Command::new("ps").args(["-eo", "pid,pcpu,pmem,comm", "--sort=-pcpu"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut count = 0;
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }
                if let Ok(cpu) = parts[1].parse::<f64>() {
                    if cpu > 80.0 {
                        let pid = parts[0];
                        let name = parts[3];
                        findings.push(Finding::new(
                            &format!("resource-cpu-{}-{}", pid, name),
                            &format!("Process {} using {:.0}% CPU: {}", pid, cpu, name),
                            if cpu > 95.0 { Severity::High } else { Severity::Medium },
                            Category::HostConfig,
                        )
                        .description("A process is consuming very high CPU. This could be a crypto miner or runaway process."));
                    }
                    count += 1;
                    if count >= 10 { break; }
                }
            }
        }

        // Check memory usage
        let out = Command::new("free").args(["-m"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.starts_with("Mem:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let (Ok(total), Ok(used)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>()) {
                            if total > 0 {
                                let pct = used * 100 / total;
                                if pct > 90 {
                                    findings.push(Finding::new(
                                        "resource-ram-high",
                                        &format!("RAM usage: {}% ({}MB / {}MB)", pct, used, total),
                                        Severity::High,
                                        Category::HostConfig,
                                    )
                                    .description("RAM is almost full. This can cause swapping and system instability."));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for known crypto miner process names
        let out = Command::new("ps").args(["-eo", "comm"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let miners = ["xmrig", "cpuminer", "minerd", "ethminer", "phoenixminer",
                         "t-rex", "lolminer", "nbminer", "teamredminer", "cryptonight",
                         "stratum", "nicehash"];
            for miner in &miners {
                if s.contains(miner) {
                    findings.push(Finding::new(
                        &format!("resource-miner-{}", miner),
                        &format!("Crypto miner process detected: {}", miner),
                        Severity::Critical,
                        Category::HostConfig,
                    )
                    .description("A cryptocurrency mining process is running! This may be malware using your system to mine crypto."));
                }
            }
        }

        // Check load average
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if let Some(first) = parts.first() {
                if let Ok(load1) = first.parse::<f64>() {
                    // Get CPU count
                    let cpus = num_cpus();
                    if load1 > cpus as f64 * 2.0 {
                        findings.push(Finding::new(
                            "resource-load-high",
                            &format!("Load average {:.1} with {} CPUs", load1, cpus),
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .description("System load is very high relative to CPU count."));
                    }
                }
            }
        }
    }

    findings
}

fn num_cpus() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
            .unwrap_or(1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        1
    }
}

/// Monitor system resources in real-time.
pub fn monitor_resources(interval: u64, max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Resource Monitor                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for CPU/RAM spikes and crypto miners");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    loop {
        let findings = audit_resources();
        let now = chrono::Utc::now().format("%H:%M:%S");
        if findings.is_empty() {
            // Print a heartbeat every 10 intervals
        } else {
            for f in &findings {
                println!("  {} [{}] {}", now, f.severity, f.title);
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
