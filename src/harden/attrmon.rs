/// File attribute monitor — watch for changes to file attributes (immutable, permissions).
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const WATCH_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/fstab",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/bin/su",
    "/bin/sudo",
    "/usr/bin/sudo",
    "/bin/mount",
    "/bin/umount",
];

pub fn audit_attr_changes() -> Vec<Finding> {
    let mut findings = Vec::new();
    let baseline = load_baseline();
    let current = get_current_attrs();

    for (file, (mode, immutable)) in &current {
        if let Some((base_mode, base_imm)) = baseline.get(file) {
            if mode != base_mode {
                findings.push(Finding::new(
                    &format!("attrmon-perm-{}", file.replace('/', "_")),
                    &format!("{} permissions changed: {:04o} -> {:04o}", file, base_mode, mode),
                    Severity::High,
                    Category::HostConfig,
                )
                .description("A critical file's permissions have changed. This could indicate tampering."));
            }
            if immutable != base_imm {
                findings.push(Finding::new(
                    &format!("attrmon-immutable-{}", file.replace('/', "_")),
                    &format!("{} immutable flag changed: {} -> {}", file, base_imm, immutable),
                    Severity::High,
                    Category::HostConfig,
                )
                .description("The immutable flag on a critical file was changed. If it was removed, someone may be trying to modify it."));
            }
        }
    }

    save_baseline(&current);
    findings
}

fn get_current_attrs() -> Vec<(String, (u32, bool))> {
    let mut attrs = Vec::new();

    for file in WATCH_FILES {
        if !Path::new(file).exists() {
            continue;
        }

        let mode = if let Ok(meta) = std::fs::metadata(file) {
            #[cfg(unix)]
            {
                meta.permissions().mode() & 0o7777
            }
            #[cfg(not(unix))]
            {
                let _ = meta;
                0
            }
        } else {
            0
        };

        let immutable = check_immutable(file);

        attrs.push((file.to_string(), (mode, immutable)));
    }

    attrs
}

fn baseline_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    home.join(".local/share/pledgeshield/attrmon-baseline.txt")
}

fn load_baseline() -> HashMap<String, (u32, bool)> {
    let path = baseline_path();
    let mut result = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() == 3 {
                let file = parts[0].to_string();
                let mode = parts[1].parse::<u32>().unwrap_or(0);
                let immutable = parts[2] == "true";
                result.insert(file, (mode, immutable));
            }
        }
    }
    result
}

fn save_baseline(attrs: &[(String, (u32, bool))]) {
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content: Vec<String> = attrs
        .iter()
        .map(|(f, (m, i))| format!("{},{},{}", f, m, i))
        .collect();
    let _ = std::fs::write(&path, content.join("\n"));
}

pub fn create_baseline() -> String {
    let current = get_current_attrs();
    save_baseline(&current);
    format!("Attribute baseline created with {} files.", current.len())
}

#[cfg(target_os = "linux")]
fn check_immutable(file: &str) -> bool {
    Command::new("lsattr")
        .arg(file)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("i"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn check_immutable(_file: &str) -> bool {
    false
}
