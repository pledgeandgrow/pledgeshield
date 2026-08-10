/// SUID/SGID scanner — find all SUID/SGID binaries, flag suspicious ones, remove unnecessary bits.
use crate::models::{Category, Finding, Severity};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Known-safe SUID binaries (common on Linux).
const KNOWN_SUID: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/bwrap",
    "/usr/bin/snap-confine",
];

pub fn audit_suid() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let suid_bins = find_suid_binaries("/usr");
        for bin in &suid_bins {
            if !KNOWN_SUID.contains(&bin.as_str()) {
                let severity = if is_suspicious_suid(bin) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding::new(
                    &format!("suid-{}", bin.replace('/', "_")),
                    &format!("SUID binary: {}", bin),
                    severity,
                    Category::Privileges,
                )
                .description("This binary has the SUID bit set, allowing it to run as root. If it's not a known system utility, it could be a privilege escalation vector.")
                .recommendation(&format!("If unexpected: sudo chmod u-s {}", bin))
                .fixable(true));
            }
        }

        // Also check /opt and /home for SUID binaries (very suspicious)
        for dir in &["/opt", "/home", "/tmp", "/var/tmp"] {
            let extra = find_suid_binaries(dir);
            for bin in &extra {
                findings.push(
                    Finding::new(
                        &format!("suid-unusual-{}", bin.replace('/', "_")),
                        &format!("SUID binary in unusual location: {}", bin),
                        Severity::High,
                        Category::Privileges,
                    )
                    .description(
                        "SUID binaries outside standard system directories are highly suspicious.",
                    )
                    .recommendation(&format!(
                        "Investigate and remove SUID: sudo chmod u-s {}",
                        bin
                    ))
                    .fixable(true),
                );
            }
        }
    }

    findings
}

fn find_suid_binaries(root: &str) -> Vec<String> {
    let mut results = Vec::new();
    let root_path = Path::new(root);
    if !root_path.exists() {
        return results;
    }

    walk_dir(root_path, &mut |path| {
        if let Ok(meta) = std::fs::metadata(path) {
            #[cfg(unix)]
            {
                let mode = meta.permissions().mode();
                // SUID = 0o4000, SGID = 0o2000
                if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                    if meta.is_file() {
                        results.push(path.to_string_lossy().to_string());
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = meta;
            }
        }
    });

    results
}

fn walk_dir(dir: &Path, callback: &mut impl FnMut(&Path)) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    // Skip proc, sys, dev
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if name == "proc"
                        || name == "sys"
                        || name == "dev"
                        || name == "run"
                        || name == "snap"
                    {
                        continue;
                    }
                    walk_dir(&path, callback);
                } else if meta.is_file() {
                    callback(&path);
                }
            }
        }
    }
}

fn is_suspicious_suid(path: &str) -> bool {
    // SUID binaries in /tmp, /home, /var/tmp are always suspicious
    path.starts_with("/tmp/")
        || path.starts_with("/home/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
}

/// Remove SUID bit from a binary.
pub fn remove_suid(path: &str, dry_run: bool) -> Result<String, String> {
    if dry_run {
        return Ok(format!("[dry-run] Would remove SUID bit from {}", path));
    }

    #[cfg(target_os = "linux")]
    {
        let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let mut mode = meta.permissions().mode();
        mode &= !0o4000; // Remove SUID
        mode &= !0o2000; // Remove SGID
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(|e| e.to_string())?;
        Ok(format!("Removed SUID/SGID from {}", path))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("Only supported on Linux.".to_string())
    }
}
