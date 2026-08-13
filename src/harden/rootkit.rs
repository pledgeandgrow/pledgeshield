/// Rootkit scanner — check for common rootkit indicators.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn scan_rootkits() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check 1: Compare /proc ps output vs ps command (hidden processes)
        let proc_pids = get_proc_pids();
        let ps_pids = get_ps_pids();
        let hidden: Vec<_> = ps_pids
            .iter()
            .filter(|pid| !proc_pids.contains(pid))
            .collect();
        if !hidden.is_empty() {
            findings.push(Finding::new(
                "rootkit-hidden-pids",
                &format!("{} PIDs visible to ps but not in /proc", hidden.len()),
                Severity::Critical,
                Category::HostConfig,
            )
            .description("Some processes are visible to ps but not in /proc — this can indicate a rootkit hiding processes.")
            .recommendation("Run a dedicated rootkit scanner: sudo rkhunter --check"));
        }

        // Check 2: LD_PRELOAD in environment
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
            if !content.trim().is_empty() {
                findings.push(Finding::new(
                    "rootkit-ld-preload",
                    &format!("/etc/ld.so.preload contains: {}", content.trim()),
                    Severity::Critical,
                    Category::HostConfig,
                )
                .description("/etc/ld.so.preload forces a library to be loaded into every process. This is a common rootkit technique.")
                .recommendation("Inspect and remove unexpected entries from /etc/ld.so.preload"));
            }
        }

        // Check 3: Check for hidden kernel modules
        let lsmod_modules = get_lsmod_modules();
        let proc_modules = get_proc_modules();
        let hidden_modules: Vec<_> = lsmod_modules
            .iter()
            .filter(|m| !proc_modules.contains(m))
            .collect();
        if !hidden_modules.is_empty() {
            findings.push(Finding::new(
                "rootkit-hidden-module",
                &format!("Hidden kernel module(s): {}", hidden_modules.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")),
                Severity::Critical,
                Category::HostConfig,
            )
            .description("A kernel module is listed by lsmod but not in /proc/modules — possible rootkit."));
        }

        // Check 4: Check /proc/modules for modules not in lsmod
        let extra_modules: Vec<_> = proc_modules
            .iter()
            .filter(|m| !lsmod_modules.contains(m))
            .collect();
        if !extra_modules.is_empty() {
            findings.push(Finding::new(
                "rootkit-extra-module",
                &format!("Module(s) in /proc but not lsmod: {}", extra_modules.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")),
                Severity::High,
                Category::HostConfig,
            )
            .description("Modules in /proc/modules but not shown by lsmod — possible rootkit hiding from lsmod."));
        }

        // Check 5: Check for suspicious files in /dev that aren't devices
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Regular files in /dev are suspicious
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() && !name_str.starts_with(".") {
                        // Some files are normal (like /dev/MAKEDEV)
                        if name_str != "MAKEDEV" && name_str != "README" {
                            findings.push(Finding::new(
                                "rootkit-dev-file",
                                &format!("Regular file in /dev: {}", path.display()),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("A regular file in /dev is unusual and could be a rootkit hiding data."));
                        }
                    }
                }
            }
        }

        // Check 6: Check for modified system binaries
        // (Quick check: compare /bin/su and /bin/login timestamps)
        for bin in &["/bin/su", "/usr/bin/sudo", "/bin/login", "/usr/bin/passwd"] {
            if let Ok(meta) = std::fs::metadata(bin) {
                if let Ok(time) = meta.modified() {
                    if let Ok(elapsed) = time.elapsed() {
                        // If modified in the last 24 hours, flag it
                        if elapsed.as_secs() < 86400 {
                            findings.push(Finding::new(
                                "rootkit-modified-binary",
                                &format!("Recently modified: {}", bin),
                                Severity::High,
                                Category::HostConfig,
                            )
                            .description("A critical system binary was modified recently. This could be a rootkit replacing it.")
                            .recommendation(&format!("Verify: dpkg -V $(dpkg -S {} | cut -d: -f1)", bin)));
                        }
                    }
                }
            }
        }

        // Check 7: Check if rkhunter/chkrootkit are available
        let rkhunter = Command::new("which")
            .arg("rkhunter")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if rkhunter {
            findings.push(
                Finding::new(
                    "rootkit-scanner-available",
                    "rkhunter is installed — run a full scan",
                    Severity::Info,
                    Category::HostConfig,
                )
                .description("Run: sudo rkhunter --check  for a comprehensive rootkit scan."),
            );
        }
    }

    findings
}

#[cfg(target_os = "linux")]
fn get_proc_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids
}

#[cfg(target_os = "linux")]
fn get_ps_pids() -> Vec<u32> {
    if let Ok(o) = Command::new("ps").args(["-eo", "pid"]).output() {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    } else {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn get_lsmod_modules() -> Vec<String> {
    if let Ok(o) = Command::new("lsmod").output() {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next().map(String::from))
            .collect()
    } else {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn get_proc_modules() -> Vec<String> {
    std::fs::read_to_string("/proc/modules")
        .map(|s| {
            s.lines()
                .filter_map(|l| l.split_whitespace().next().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
