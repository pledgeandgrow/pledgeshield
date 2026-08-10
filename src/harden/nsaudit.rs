/// Namespace isolation auditor — check if sensitive processes are in isolated namespaces.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_namespaces() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check if user namespaces are enabled (security risk if so)
        if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
            let max = content.trim();
            if max != "0" {
                findings.push(Finding::new(
                    "ns-user-namespaces-enabled",
                    &format!("User namespaces enabled (max: {})", max),
                    Severity::Low,
                    Category::HostConfig,
                )
                .description("User namespaces allow unprivileged users to create isolated environments. While useful for containers, they've been the source of many kernel exploits.")
                .recommendation("If not needed: sudo sysctl -w user.max_user_namespaces=0")
                .fixable(true));
            }
        }

        // Check if any process is running in isolated namespaces
        let mut isolated_count = 0;
        let mut total_count = 0;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let pid = &name;
                total_count += 1;

                // Check namespace isolation via /proc/[pid]/ns
                let ns_path = format!("/proc/{}/ns", pid);
                if let Ok(ns_entries) = std::fs::read_dir(&ns_path) {
                    let mut has_own_ns = false;
                    for ns in ns_entries.flatten() {
                        let ns_name = ns.file_name().to_string_lossy().to_string();
                        let ns_link = format!("/proc/{}/ns/{}", pid, ns_name);
                        if let Ok(target) = std::fs::read_link(&ns_link) {
                            // If the namespace inode differs from init's, it's isolated
                            let init_ns = format!("/proc/1/ns/{}", ns_name);
                            if let Ok(init_target) = std::fs::read_link(&init_ns) {
                                if target != init_target {
                                    has_own_ns = true;
                                    break;
                                }
                            }
                        }
                    }
                    if has_own_ns {
                        isolated_count += 1;
                    }
                }
            }
        }

        // Check for processes that SHOULD be isolated but aren't
        // (e.g., web servers, databases)
        let out = Command::new("ps").args(["-eo", "comm"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let should_isolate = ["nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server", "mongod"];
            for proc_name in &should_isolate {
                if s.contains(proc_name) {
                    // Check if it's in its own namespace
                    let out2 = Command::new("sh")
                        .args(["-c", &format!("pgrep -f {} | head -1", proc_name)])
                        .output();
                    if let Ok(o2) = out2 {
                        let pid = String::from_utf8_lossy(&o2.stdout).trim().to_string();
                        if !pid.is_empty() {
                            let mnt_ns = format!("/proc/{}/ns/mnt", pid);
                            let init_mnt = "/proc/1/ns/mnt";
                            if let (Ok(t1), Ok(t2)) = (std::fs::read_link(&mnt_ns), std::fs::read_link(init_mnt)) {
                                if t1 == t2 {
                                    findings.push(Finding::new(
                                        &format!("ns-not-isolated-{}", proc_name),
                                        &format!("{} (pid {}) is not in an isolated mount namespace", proc_name, pid),
                                        Severity::Low,
                                        Category::HostConfig,
                                    )
                                    .description("This service should run in an isolated namespace for defense-in-depth."));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
