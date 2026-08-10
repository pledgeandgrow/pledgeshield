/// Kernel parameter hardener — toggle sysctl security params.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

const SECURITY_SYSCALLS: &[(&str, &str, &str)] = &[
    // (param, secure_value, description)
    ("net.ipv4.conf.all.send_redirects", "0", "Disable ICMP redirect sending"),
    ("net.ipv4.conf.default.send_redirects", "0", "Disable ICMP redirect sending (default)"),
    ("net.ipv4.conf.all.accept_redirects", "0", "Don't accept ICMP redirects"),
    ("net.ipv4.conf.default.accept_redirects", "0", "Don't accept ICMP redirects (default)"),
    ("net.ipv4.conf.all.accept_source_route", "0", "Reject source-routed packets"),
    ("net.ipv4.conf.default.accept_source_route", "0", "Reject source-routed packets (default)"),
    ("net.ipv4.tcp_syncookies", "1", "Enable SYN flood protection"),
    ("net.ipv4.conf.all.log_martians", "1", "Log spoofed/martian packets"),
    ("kernel.randomize_va_space", "2", "Full ASLR"),
    ("kernel.kptr_restrict", "2", "Hide kernel pointers"),
    ("kernel.dmesg_restrict", "1", "Restrict dmesg to root"),
    ("kernel.perf_event_paranoid", "2", "Restrict perf events"),
    ("kernel.yama.ptrace_scope", "2", "Restrict ptrace"),
    ("kernel.kexec_load_disabled", "1", "Disable kexec (prevent kernel replacement)"),
    ("user.max_user_namespaces", "0", "Disable user namespaces (reduces attack surface)"),
    ("dev.tty.ldisc_autoload", "0", "Disable TTY line discipline autoload"),
    ("fs.protected_hardlinks", "1", "Protect against hardlink attacks"),
    ("fs.protected_symlinks", "1", "Protect against symlink attacks"),
    ("fs.protected_fifos", "2", "Protect against FIFO attacks"),
    ("fs.protected_regular", "2", "Protect against regular file attacks"),
    ("fs.suid_dumpable", "0", "Disable SUID core dumps"),
    ("kernel.unprivileged_bpf_disabled", "1", "Disable unprivileged BPF"),
];

pub fn audit_sysctl() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for (param, secure_val, desc) in SECURITY_SYSCALLS {
            let out = Command::new("sysctl").args(["-n", param]).output();
            if let Ok(o) = out {
                let current = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if current != *secure_val && !current.is_empty() {
                    findings.push(Finding::new(
                        &format!("sysctl-{}", param.replace('.', "_")),
                        &format!("{} = {} (should be {})", param, current, secure_val),
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description(*desc)
                    .recommendation(&format!("Run: pledgeshield harden sysctl --harden  (or: sudo sysctl -w {}={})", param, secure_val))
                    .fixable(true));
                }
            }
        }
    }

    findings
}

pub fn harden_sysctl(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let mut fixed = 0;
        for (param, secure_val, _) in SECURITY_SYSCALLS {
            if dry_run {
                results.push(HardenResult {
                    action: format!("sysctl-{}", param),
                    success: true,
                    message: format!("[dry-run] Would set {} = {}", param, secure_val),
                    findings: vec![],
                });
                continue;
            }
            let out = Command::new("sysctl").args(["-w", &format!("{}={}", param, secure_val)]).output();
            if out.map(|o| o.status.success()).unwrap_or(false) {
                fixed += 1;
            }
        }

        if !dry_run && fixed > 0 {
            // Persist to /etc/sysctl.d/
            let conf: String = SECURITY_SYSCALLS.iter()
                .map(|(p, v, _)| format!("{}={}", p, v))
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write("/etc/sysctl.d/99-pledgeshield.conf", conf + "\n");
            results.push(HardenResult {
                action: "sysctl-harden".to_string(),
                success: true,
                message: format!("Set {} kernel parameters (persisted to /etc/sysctl.d/99-pledgeshield.conf)", fixed),
                findings: vec![],
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        results.push(HardenResult {
            action: "sysctl-harden".to_string(),
            success: false,
            message: "Sysctl hardening is only supported on Linux.".to_string(),
            findings: vec![],
        });
    }

    results
}

pub fn restore_sysctl() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let path = "/etc/sysctl.d/99-pledgeshield.conf";
        if std::path::Path::new(path).exists() {
            let _ = std::fs::remove_file(path);
            HardenResult {
                action: "sysctl-restore".to_string(),
                success: true,
                message: "Removed PledgeShield sysctl config (reboot to fully restore defaults).".to_string(),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "sysctl-restore".to_string(),
                success: true,
                message: "No PledgeShield sysctl config found.".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "sysctl-restore".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
