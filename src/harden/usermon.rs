/// User account change monitor — alert on new users, UID changes, sudoers modifications.
use crate::models::{Category, Finding, Severity};
use std::collections::HashMap;
use std::process::Command;

pub fn audit_user_changes() -> Vec<Finding> {
    let mut findings = Vec::new();

    let baseline = load_baseline();
    let current = get_current_state();

    // Check for new users
    if let Some(base_users) = baseline.get("users") {
        let base_set: HashSet<&str> = base_users.split(',').collect();
        let empty = String::new();
        let curr_users = current.get("users").unwrap_or(&empty);
        let curr_set: HashSet<&str> = curr_users.split(',').collect();
        for user in curr_set.difference(&base_set) {
            if user.is_empty() { continue; }
            findings.push(Finding::new(
                &format!("usermon-new-{}", user),
                &format!("New user account: {}", user),
                Severity::High,
                Category::Privileges,
            )
            .description("A new user account was created since last check. Verify this is authorized."));
        }
    }

    // Check for UID 0 accounts (root-equivalent)
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        if uid == 0 && parts[0] != "root" {
                            findings.push(Finding::new(
                                &format!("usermon-uid0-{}", parts[0]),
                                &format!("Non-root user with UID 0: {}", parts[0]),
                                Severity::Critical,
                                Category::Privileges,
                            )
                            .description("A non-root user has UID 0, giving them full root privileges!"));
                        }
                    }
                }
            }
        }
    }

    // Check sudoers modifications
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ls").args(["-la", "/etc/sudoers.d/"]).output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Some(base_sudoers) = baseline.get("sudoers") {
                // Compare current sudoers.d listing with baseline
                let base_count = base_sudoers.matches('\n').count();
                let curr_count = s.matches('\n').count();
                if curr_count > base_count {
                    findings.push(Finding::new(
                        "usermon-sudoers-added",
                        "New sudoers rule file detected",
                        Severity::High,
                        Category::Privileges,
                    )
                    .description("A new file was added to /etc/sudoers.d/. Check who now has sudo access."));
                }
            }
        }
    }

    // Check for users without passwords
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/shadow") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let user = parts[0];
                    let hash = parts[1];
                    if hash.is_empty() {
                        findings.push(Finding::new(
                            &format!("usermon-no-password-{}", user),
                            &format!("User {} has no password", user),
                            Severity::High,
                            Category::Credentials,
                        )
                        .description("This user account has no password set. Anyone can log in without authentication."));
                    }
                    if hash == "*" || hash == "!" {
                        // Locked account — normal for system accounts
                    }
                }
            }
        }
    }

    // Save current state
    save_baseline(&current);

    findings
}

fn get_current_state() -> HashMap<String, String> {
    let mut state = HashMap::new();

    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            let users: Vec<String> = content.lines()
                .filter_map(|l| l.split(':').next().map(String::from))
                .collect();
            state.insert("users".to_string(), users.join(","));
        }

        #[cfg(target_os = "linux")]
        {
            let out = Command::new("ls").args(["-la", "/etc/sudoers.d/"]).output();
            if let Ok(o) = out {
                state.insert("sudoers".to_string(), String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
    }

    state
}

fn baseline_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    home.join(".local/share/pledgeshield/usermon-baseline.txt")
}

fn load_baseline() -> HashMap<String, String> {
    let path = baseline_path();
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

fn save_baseline(state: &HashMap<String, String>) {
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content: Vec<String> = state.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    let _ = std::fs::write(&path, content.join("\n"));
}

use std::collections::HashSet;
