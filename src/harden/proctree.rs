/// Process tree analyzer — detect suspicious process trees (browser spawning shells, etc.).
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
use std::process::Command;

pub fn audit_process_tree() -> Vec<Finding> {
    let mut findings = Vec::new();
    let tree = get_process_tree();

    // Suspicious parent-child relationships
    // (parent_name, child_name, severity, description)
    let suspicious_pairs: &[(&str, &str, Severity, &str)] = &[
        ("chrome", "bash", Severity::High, "Browser spawning shell — possible exploit"),
        ("chrome", "sh", Severity::High, "Browser spawning shell — possible exploit"),
        ("chrome", "powershell", Severity::High, "Browser spawning PowerShell — possible exploit"),
        ("firefox", "bash", Severity::High, "Browser spawning shell — possible exploit"),
        ("firefox", "sh", Severity::High, "Browser spawning shell — possible exploit"),
        ("firefox", "cmd", Severity::High, "Browser spawning cmd — possible exploit"),
        ("office", "powershell", Severity::Critical, "Office app spawning PowerShell — likely macro malware"),
        ("soffice", "bash", Severity::Critical, "LibreOffice spawning shell — likely macro malware"),
        ("soffice", "powershell", Severity::Critical, "LibreOffice spawning PowerShell — likely macro malware"),
        ("winword", "cmd", Severity::Critical, "Word spawning cmd — likely macro malware"),
        ("winword", "powershell", Severity::Critical, "Word spawning PowerShell — likely macro malware"),
        ("excel", "cmd", Severity::Critical, "Excel spawning cmd — likely macro malware"),
        ("outlook", "powershell", Severity::Critical, "Outlook spawning PowerShell — likely email malware"),
        ("nginx", "bash", Severity::High, "Web server spawning shell — possible web shell"),
        ("apache", "bash", Severity::High, "Web server spawning shell — possible web shell"),
        ("httpd", "bash", Severity::High, "Web server spawning shell — possible web shell"),
        ("vsftpd", "bash", Severity::High, "FTP server spawning shell — possible backdoor"),
        ("sshd", "bash", Severity::Low, "SSH session shell (normal)"),
    ];

    for (pid, proc_info) in &tree {
        if let Some(parent_info) = tree.get(&proc_info.ppid) {
            let parent_name = parent_info.name.to_lowercase();
            let child_name = proc_info.name.to_lowercase();

            for (p, c, sev, desc) in suspicious_pairs {
                if parent_name.contains(p) && child_name.contains(c) {
                    // Skip sshd -> bash (normal)
                    if *p == "sshd" && *sev == Severity::Low { continue; }

                    findings.push(Finding::new(
                        &format!("proctree-{}-{}-{}", p, c, pid),
                        &format!("{} -> {} (pid {})", parent_info.name, proc_info.name, pid),
                        *sev,
                        Category::HostConfig,
                    )
                    .description(*desc)
                    .recommendation(&format!("Investigate: ps aux | grep {}", proc_info.name)));
                }
            }
        }
    }

    // Check for processes with no parent (orphaned/hidden)
    for (pid, proc_info) in &tree {
        if proc_info.ppid == 0 && proc_info.name != "kernel" && proc_info.name != "systemd"
            && proc_info.name != "launchd" && proc_info.name != "idle"
        {
            // Could be a kernel thread or hidden process
        }
    }

    findings
}

#[derive(Debug, Clone)]
struct ProcInfo {
    pid: u32,
    ppid: u32,
    name: String,
}

fn get_process_tree() -> HashMap<u32, ProcInfo> {
    let mut tree: HashMap<u32, ProcInfo> = HashMap::new();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // ps -eo pid,ppid,comm
        let out = Command::new("ps").args(["-eo", "pid,ppid,comm"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                        let name = parts[2..].join(" ");
                        tree.insert(pid, ProcInfo { pid, ppid, name });
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let out = Command::new("wmic")
            .args(["process", "get", "ProcessId,ParentProcessId,Name"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let name = parts[..parts.len()-2].join(" ");
                    if let (Ok(pid), Ok(ppid)) = (parts[parts.len()-2].parse::<u32>(), parts[parts.len()-1].parse::<u32>()) {
                        tree.insert(pid, ProcInfo { pid, ppid, name });
                    }
                }
            }
        }
    }

    tree
}
