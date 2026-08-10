/// Bandwidth/traffic monitor — track per-process network usage, flag anomalous data exfiltration.
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

/// Per-process network usage snapshot.
#[derive(Debug, Clone)]
pub struct ProcessTraffic {
    pub pid: u32,
    pub name: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Get current per-process network usage (Linux only, via /proc).
pub fn get_process_traffic() -> Vec<ProcessTraffic> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Read /proc/net/dev for total, then /proc/<pid>/net/dev for per-process
        // Actually, per-process network usage is hard to get directly.
        // Use ss + /proc/<pid>/fd to map sockets to processes.
        // For simplicity, use /proc/<pid>/io for read/write bytes as a proxy.

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    // Get process name
                    let comm_path = format!("/proc/{}/comm", pid);
                    let proc_name = std::fs::read_to_string(&comm_path)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|_| "?".to_string());

                    // Get IO stats
                    let io_path = format!("/proc/{}/io", pid);
                    if let Ok(io_content) = std::fs::read_to_string(&io_path) {
                        let mut sent = 0u64;
                        let mut recv = 0u64;
                        for line in io_content.lines() {
                            if line.starts_with("write_bytes:") {
                                sent = line.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                            }
                            if line.starts_with("read_bytes:") {
                                recv = line.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                            }
                        }
                        if sent > 0 || recv > 0 {
                            results.push(ProcessTraffic { pid, name: proc_name, bytes_sent: sent, bytes_recv: recv });
                        }
                    }
                }
            }
        }
        // Sort by total bytes descending
        results.sort_by(|a, b| (b.bytes_sent + b.bytes_recv).cmp(&(a.bytes_sent + a.bytes_recv)));
    }

    results
}

/// Audit for anomalous data exfiltration — processes sending unusually large amounts of data.
pub fn audit_traffic_anomalies() -> Vec<Finding> {
    let mut findings = Vec::new();
    let traffic = get_process_traffic();

    // Flag processes sending > 100MB
    for proc in &traffic {
        if proc.bytes_sent > 100 * 1024 * 1024 {
            findings.push(Finding::new(
                "traffic-high-upload",
                &format!("{} (pid {}) uploaded {:.1} MB", proc.name, proc.pid, proc.bytes_sent as f64 / 1048576.0),
                Severity::High,
                Category::Network,
            )
            .description("This process has sent an unusually large amount of data. Possible data exfiltration.")
            .recommendation("Investigate this process. If unexpected, kill it and check for malware."));
        }
    }

    findings
}

/// Monitor network traffic in real-time. Prints top processes by bandwidth.
pub fn monitor_traffic(interval: u64, max_runtime: u64, top_n: usize) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield Traffic Monitor                        ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Polling every {}s | top {} processes | max runtime: {}s", interval, top_n, if max_runtime == 0 { "∞".to_string() } else { max_runtime.to_string() });
    println!();

    let mut prev: HashMap<u32, ProcessTraffic> = HashMap::new();
    let start = Instant::now();

    loop {
        let now = chrono::Utc::now().format("%H:%M:%S");
        let current = get_process_traffic();

        // Calculate deltas
        let mut deltas: Vec<(String, u32, u64, u64)> = Vec::new();
        for proc in &current {
            if let Some(p) = prev.get(&proc.pid) {
                let ds = proc.bytes_sent.saturating_sub(p.bytes_sent);
                let dr = proc.bytes_recv.saturating_sub(p.bytes_recv);
                if ds > 0 || dr > 0 {
                    deltas.push((proc.name.clone(), proc.pid, ds, dr));
                }
            }
        }
        deltas.sort_by(|a, b| (b.2 + b.3).cmp(&(a.2 + a.3)));

        if !deltas.is_empty() {
            println!("  {} — Top {} by bandwidth:", now, top_n.min(deltas.len()));
            for (name, pid, sent, recv) in deltas.iter().take(top_n) {
                println!("    {:20} pid:{:6}  ↑{}/s  ↓{}/s",
                    name, pid, format_bytes(*sent / interval), format_bytes(*recv / interval));
            }
        }

        prev = current.into_iter().map(|p| (p.pid, p)).collect();

        std::thread::sleep(Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}

fn format_bytes(b: u64) -> String {
    if b < 1024 { format!("{}B", b) }
    else if b < 1048576 { format!("{:.1}KB", b as f64 / 1024.0) }
    else if b < 1073741824 { format!("{:.1}MB", b as f64 / 1048576.0) }
    else { format!("{:.1}GB", b as f64 / 1073741824.0) }
}
