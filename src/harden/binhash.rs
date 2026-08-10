/// Binary hash verifier — hash executables and compare against package manager's expected hashes.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_binary_hashes() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Use dpkg to verify installed package files
        let out = Command::new("dpkg").args(["-V"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                // dpkg -V output format: "??5?????? /path/to/file"
                // ? = not checked, 5 = md5 checksum changed
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    continue;
                }
                let status = parts[0];
                let path = parts[1].trim();

                if status.contains('5') {
                    // MD5 checksum mismatch
                    let severity = if path.starts_with("/bin/")
                        || path.starts_with("/sbin/")
                        || path.starts_with("/usr/bin/")
                        || path.starts_with("/usr/sbin/")
                    {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    findings.push(Finding::new(
                        &format!("binhash-mismatch-{}", path.replace('/', "_")),
                        &format!("Binary modified: {} (checksum mismatch)", path),
                        severity,
                        Category::HostConfig,
                    )
                    .description("A system binary's checksum doesn't match what the package manager expects. It may have been replaced by an attacker."));
                }

                if status.contains('M') {
                    // Mode changed
                    findings.push(Finding::new(
                        &format!("binhash-mode-{}", path.replace('/', "_")),
                        &format!("File mode changed: {}", path),
                        Severity::Medium,
                        Category::HostConfig,
                    ));
                }
            }
        }

        // Also check with rpm if available (Fedora/RHEL)
        let out = Command::new("rpm").args(["-Va"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.starts_with("S.5") || line.starts_with("5") {
                    let path = line.split_whitespace().last().unwrap_or("");
                    if !path.is_empty() {
                        findings.push(
                            Finding::new(
                                &format!("binhash-rpm-{}", path.replace('/', "_")),
                                &format!("Binary modified (rpm): {}", path),
                                Severity::Critical,
                                Category::HostConfig,
                            )
                            .description("RPM verification detected a modified binary."),
                        );
                    }
                }
            }
        }

        // Check for binaries not owned by any package (orphaned)
        let out = Command::new("sh")
            .args(["-c", "find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null | while read f; do dpkg -S \"$f\" 2>/dev/null | grep -q . || echo \"$f\"; done | head -20"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let path = line.trim();
                if !path.is_empty() && !path.starts_with("dpkg-query:") {
                    findings.push(Finding::new(
                        &format!("binhash-orphan-{}", path.replace('/', "_")),
                        &format!("Executable not owned by any package: {}", path),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("An executable in a system directory is not owned by any installed package. It may have been planted by an attacker."));
                }
            }
        }
    }

    findings
}
