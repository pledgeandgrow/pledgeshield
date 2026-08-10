/// Systemd unit auditor — deep scan for suspicious units (ExecStart in /tmp, no sandboxing).
use crate::models::{Category, Finding, Severity};
use std::path::Path;
use std::process::Command;

pub fn audit_systemd() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Get all unit files
        let unit_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ];
        for dir in &unit_dirs {
            if !Path::new(dir).exists() {
                continue;
            }
            scan_systemd_dir(dir, &mut findings);
        }

        // Check running services for sandboxing
        let out = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let unit = line.split_whitespace().next().unwrap_or("");
                if unit.is_empty() {
                    continue;
                }

                // Get unit properties
                let out2 = Command::new("systemctl")
                    .args(["show", unit, "--property=ExecStart,User,Group,PrivateTmp,ProtectSystem,ProtectHome,NoNewPrivileges"])
                    .output();
                if let Ok(o2) = out2 {
                    let props = String::from_utf8_lossy(&o2.stdout);

                    // Check if running as root without sandboxing
                    if props.contains("User=root") || props.contains("User=") == false {
                        if !props.contains("PrivateTmp=yes") && !props.contains("ProtectSystem=") {
                            // Only flag non-essential services
                            let essential = [
                                "systemd", "dbus", "networkd", "resolved", "logind", "journal",
                                "udev", "init",
                            ];
                            if !essential.iter().any(|e| unit.contains(e)) {
                                findings.push(Finding::new(
                                    &format!("systemd-no-sandbox-{}", unit.replace('.', "_")),
                                    &format!("Service {} runs as root without sandboxing", unit),
                                    Severity::Low,
                                    Category::Services,
                                )
                                .description("This service runs as root without systemd sandboxing directives. Add ProtectSystem, PrivateTmp, etc."));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

fn scan_systemd_dir(dir: &str, findings: &mut Vec<Finding>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_systemd_dir(path.to_str().unwrap_or(""), findings);
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".service") {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                // Check ExecStart for suspicious paths
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("ExecStart=") {
                        let exec = line.strip_prefix("ExecStart=").unwrap_or("");
                        // Remove quotes and arguments
                        let exec_path = exec
                            .trim_start_matches('"')
                            .split_whitespace()
                            .next()
                            .unwrap_or("");

                        if exec_path.starts_with("/tmp/")
                            || exec_path.starts_with("/dev/shm/")
                            || exec_path.starts_with("/var/tmp/")
                        {
                            findings.push(Finding::new(
                                &format!("systemd-tmp-exec-{}", name.replace('.', "_")),
                                &format!("Unit {} executes from temp: {}", name, exec_path),
                                Severity::High,
                                Category::Persistence,
                            )
                            .description("A systemd service executes a binary from a temp directory. This is a common persistence mechanism for malware."));
                        }

                        // Check for download-and-exec patterns
                        if exec.contains("curl") || exec.contains("wget") {
                            if exec.contains("|") || exec.contains("bash") || exec.contains("sh") {
                                findings.push(Finding::new(
                                    &format!("systemd-download-exec-{}", name.replace('.', "_")),
                                    &format!("Unit {} downloads and executes code", name),
                                    Severity::Critical,
                                    Category::Persistence,
                                )
                                .description("This systemd unit downloads and executes remote code — classic malware persistence."));
                            }
                        }
                    }

                    // Check for User=root with no hardening
                    if line.starts_with("User=root")
                        || (line.starts_with("User=") && !content.contains("ProtectSystem"))
                    {
                        // Flag only if the service is not a known system service
                    }
                }
            }
        }
    }
}
