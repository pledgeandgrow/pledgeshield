/// Capability auditor — scan all binaries for dangerous Linux capabilities.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

#[cfg(target_os = "linux")]
const DANGEROUS_CAPS: &[(&str, &str)] = &[
    (
        "cap_setuid",
        "Can change process UID (privilege escalation)",
    ),
    ("cap_setgid", "Can change process GID"),
    ("cap_sys_admin", "Broad admin capability (near-root)"),
    (
        "cap_sys_ptrace",
        "Can inspect/modify other processes' memory",
    ),
    ("cap_sys_module", "Can load/unload kernel modules"),
    ("cap_sys_rawio", "Can perform raw I/O operations"),
    (
        "cap_net_admin",
        "Can configure network interfaces and firewall",
    ),
    ("cap_net_raw", "Can create raw sockets (packet sniffing)"),
    ("cap_dac_override", "Can bypass file permission checks"),
    (
        "cap_dac_read_search",
        "Can bypass file read permission checks",
    ),
    ("cap_linux_immutable", "Can set immutable flag on files"),
    ("cap_bpf", "Can load BPF programs"),
    ("cap_perfmon", "Can access performance monitoring"),
    ("cap_wake_alarm", "Can set wake alarms"),
    ("cap_block_suspend", "Can block system suspend"),
];

pub fn audit_capabilities() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Scan all SUID/capability-enabled binaries
        let out = Command::new("sh")
            .args(["-c", "getcap -r / 2>/dev/null | head -100"])
            .output();

        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    continue;
                }
                let path = parts[0];
                let caps = parts[1];

                for (cap, desc) in DANGEROUS_CAPS {
                    if caps.contains(cap) {
                        // Check if this is a known-safe binary
                        let known_safe = [
                            "/usr/bin/ping",
                            "/usr/bin/gpasswd",
                            "/usr/bin/passwd",
                            "/usr/bin/newgrp",
                            "/usr/bin/chage",
                            "/usr/bin/chfn",
                            "/usr/bin/chsh",
                            "/usr/bin/su",
                            "/usr/bin/sudo",
                            "/usr/lib/policykit-1/polkit-agent-helper-1",
                            "/usr/bin/fusermount3",
                            "/usr/bin/fusermount",
                        ];
                        let severity = if known_safe.contains(&path) {
                            Severity::Low
                        } else {
                            Severity::Medium
                        };

                        if !known_safe.contains(&path) {
                            findings.push(Finding::new(
                                &format!("caps-{}-{}", cap, path.replace('/', "_")),
                                &format!("{} has {} — {}", path, cap, desc),
                                severity,
                                Category::Privileges,
                            )
                            .description("This binary has a dangerous Linux capability. If exploited, it can be used for privilege escalation.")
                            .recommendation(&format!("If not needed: sudo setcap -r {}", path))
                            .fixable(true));
                        }
                    }
                }
            }
        }

        // Also check for SUID binaries that have capabilities (double risk)
        let out = Command::new("sh")
            .args([
                "-c",
                "find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let path = line.trim();
                if path.is_empty() {
                    continue;
                }
                let out2 = Command::new("getcap").arg(path).output();
                if let Ok(o2) = out2 {
                    let caps = String::from_utf8_lossy(&o2.stdout);
                    if !caps.trim().is_empty() {
                        findings.push(Finding::new(
                            &format!("caps-suid-plus-{}", path.replace('/', "_")),
                            &format!("{} has both SUID and capabilities: {}", path, caps.trim()),
                            Severity::High,
                            Category::Privileges,
                        )
                        .description("This binary has both SUID and capabilities — double privilege escalation risk."));
                    }
                }
            }
        }
    }

    findings
}
