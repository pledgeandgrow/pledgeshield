/// Shared library auditor — check LD_LIBRARY_PATH, RPATH, scan for unusual library paths.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_libraries() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check global LD_LIBRARY_PATH
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() { continue; }
                if line.starts_with("/tmp/") || line.starts_with("/home/") || line.starts_with("/var/tmp/") {
                    findings.push(Finding::new(
                        &format!("libaudit-ldconf-{}", line.replace('/', "_")),
                        &format!("Suspicious library path in ld.so.conf: {}", line),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A library search path in /etc/ld.so.conf points to a non-standard directory. This could be used for library hijacking."));
                }
            }
        }

        // Check for binaries with RPATH/RUNPATH pointing to writable directories
        let out = Command::new("sh")
            .args(["-c", "find /usr/bin /usr/sbin /usr/local/bin -type f -executable 2>/dev/null | head -200"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let path = line.trim();
                if path.is_empty() { continue; }

                let out2 = Command::new("readelf").args(["-d", path]).output();
                if let Ok(o2) = out2 {
                    let elf = String::from_utf8_lossy(&o2.stdout);
                    for line in elf.lines() {
                        if line.contains("RPATH") || line.contains("RUNPATH") {
                            let rpath = line.split('[').nth(1).and_then(|s| s.trim_end_matches(']').trim().strip_prefix("Path:")).unwrap_or("");
                            let rpath = line.split('[').nth(1).and_then(|s| s.split(']').next()).unwrap_or("");
                            if rpath.starts_with("/tmp/") || rpath.starts_with("/home/") || rpath.starts_with("/var/tmp/") || rpath == "." {
                                findings.push(Finding::new(
                                    &format!("libaudit-rpath-{}", path.replace('/', "_")),
                                    &format!("{} has RPATH/RUNPATH pointing to writable dir: {}", path, rpath),
                                    Severity::High,
                                    Category::HostConfig,
                                )
                                .description("This binary searches for libraries in a writable directory. An attacker could place a malicious library there."));
                            }
                        }
                    }
                }
            }
        }

        // Check for world-writable library directories
        let lib_dirs = ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/local/lib"];
        for dir in &lib_dirs {
            if !std::path::Path::new(dir).exists() { continue; }
            if let Ok(meta) = std::fs::metadata(dir) {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o022 != 0 { // group or world writable
                    findings.push(Finding::new(
                        &format!("libaudit-writable-{}", dir.replace('/', "_")),
                        &format!("Library directory {} is writable", dir),
                        Severity::Critical,
                        Category::HostConfig,
                    )
                    .description("A system library directory is writable by non-root. An attacker could replace system libraries."));
                }
            }
        }

        // Check for libraries in /tmp or /dev/shm
        let out = Command::new("sh")
            .args(["-c", "find /tmp /dev/shm /var/tmp -name '*.so*' -type f 2>/dev/null"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    findings.push(Finding::new(
                        &format!("libaudit-tmp-so-{}", line.replace('/', "_")),
                        &format!("Shared library in temp directory: {}", line),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("A shared library was found in a temp directory. This is suspicious and could be used for library injection."));
                }
            }
        }
    }

    findings
}
