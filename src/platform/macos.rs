#![allow(unused_imports, unused_mut, unused_variables)]

use crate::models::{Category, Finding, Severity};
use std::process::Command;

// ─── Helpers ───────────────────────────────────────────────────────────

fn run_cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}

fn run_cmd_lossy(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            let e = String::from_utf8_lossy(&o.stderr).to_string();
            if s.is_empty() {
                e
            } else {
                s
            }
        })
        .unwrap_or_default()
}

fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

// ─── Config Audit ──────────────────────────────────────────────────────

pub fn audit_config() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_gatekeeper(&mut findings);
    audit_sip(&mut findings);
    audit_filevault(&mut findings);
    audit_firewall(&mut findings);
    audit_xprotect(&mut findings);
    audit_telemetry(&mut findings);
    audit_autologin(&mut findings);
    audit_ssh_config(&mut findings);

    Ok(findings)
}

fn audit_gatekeeper(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("spctl", &["--status"]);
    if output.contains("disabled") {
        findings.push(Finding::new(
            "mac-gatekeeper-disabled",
            "Gatekeeper is disabled",
            Severity::High,
            Category::Config,
        )
        .description("Gatekeeper (spctl) is disabled. Unsigned or unnotarized applications can be executed without any verification, increasing the risk of malware infection.")
        .recommendation("Enable Gatekeeper: sudo spctl --master-enable")
        .fixable(true));
    }
}

fn audit_sip(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("csrutil", &["status"]);
    if output.contains("disabled") {
        findings.push(Finding::new(
            "mac-sip-disabled",
            "System Integrity Protection (SIP) is disabled",
            Severity::Critical,
            Category::Config,
        )
        .description("SIP is disabled. Without SIP, root-level processes can modify protected system files, making the system vulnerable to deep persistence and rootkit installation.")
        .recommendation("Enable SIP: boot into Recovery Mode, run csrutil enable"));
    }
}

fn audit_filevault(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("fdesetup", &["status"]);
    if output.contains("Off") || output.contains("off") {
        findings.push(Finding::new(
            "mac-filevault-off",
            "FileVault disk encryption is disabled",
            Severity::High,
            Category::Config,
        )
        .description("FileVault is disabled. Disk data is unencrypted, meaning it can be read by anyone with physical access to the storage device.")
        .recommendation("Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On")
        .metadata("encryption", "FileVault"));
    }
}

fn audit_firewall(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    );
    if output.contains("off") || output.contains("Off") {
        findings.push(Finding::new(
            "mac-firewall-off",
            "macOS Application Firewall is disabled",
            Severity::High,
            Category::Config,
        )
        .description("The macOS application firewall is disabled. All incoming connections are allowed by default.")
        .recommendation("Enable firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")
        .fixable(true));
    }

    let stealth = run_cmd_lossy(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["getstealthmode"],
    );
    if stealth.contains("off") || stealth.contains("Off") {
        findings.push(Finding::new(
            "mac-firewall-stealth-off",
            "Firewall stealth mode is disabled",
            Severity::Low,
            Category::Config,
        )
        .description("Stealth mode is off. The system responds to ping and port scans, making it discoverable on the network.")
        .recommendation("Enable stealth mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"));
    }
}

fn audit_xprotect(findings: &mut Vec<Finding>) {
    let xprotect_plist =
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";
    if !file_exists(xprotect_plist) {
        findings.push(Finding::new(
            "mac-xprotect-missing",
            "XProtect malware protection files not found",
            Severity::High,
            Category::Config,
        )
        .description("XProtect, macOS's built-in malware detection system, appears to be missing or disabled."));
    }
}

fn audit_telemetry(findings: &mut Vec<Finding>) {
    let _output = run_cmd_lossy(
        "defaults",
        &["read", "/Library/Preferences/com.apple.alf", "globalstate"],
    );
    // Check analytics submission
    let analytics = run_cmd_lossy(
        "defaults",
        &["read", "com.apple.alf", "allowdownloadsignedenabled"],
    );
    if analytics.contains("0") {
        findings.push(
            Finding::new(
                "mac-analytics-disabled",
                "Diagnostic data submission appears restricted",
                Severity::Info,
                Category::Config,
            )
            .description("Diagnostic and usage data submission is restricted."),
        );
    }
}

fn audit_autologin(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "autoLoginUser",
        ],
    );
    if !output.is_empty() && !output.contains("does not exist") {
        findings.push(Finding::new(
            "mac-autologin-enabled",
            "Auto-login is enabled",
            Severity::Medium,
            Category::Config,
        )
        .description(&format!("Auto-login is configured for user: {}. This bypasses the login screen, allowing anyone with physical access to boot directly into the user session.", output.trim()))
        .recommendation("Disable auto-login: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"));
    }
}

fn audit_ssh_config(findings: &mut Vec<Finding>) {
    let sshd_config = read_file("/etc/ssh/sshd_config");
    if let Some(config) = sshd_config {
        for line in config.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with("PermitRootLogin") && (line.contains("yes") || !line.contains("no"))
            {
                findings.push(Finding::new(
                    "mac-ssh-root-login",
                    "SSH root login is permitted",
                    Severity::High,
                    Category::Config,
                )
                .description("SSH PermitRootLogin is enabled. Direct root SSH access is a major security risk.")
                .recommendation("Set PermitRootLogin no in /etc/ssh/sshd_config"));
            }
            if line.starts_with("PasswordAuthentication") && line.contains("yes") {
                findings.push(Finding::new(
                    "mac-ssh-password-auth",
                    "SSH password authentication is enabled",
                    Severity::Medium,
                    Category::Config,
                )
                .description("SSH password authentication is enabled. Key-based authentication is more secure.")
                .recommendation("Set PasswordAuthentication no in /etc/ssh/sshd_config"));
            }
            if line.starts_with("PermitEmptyPasswords") && line.contains("yes") {
                findings.push(Finding::new(
                    "mac-ssh-empty-passwords",
                    "SSH permits empty passwords",
                    Severity::Critical,
                    Category::Config,
                )
                .description("SSH PermitEmptyPasswords is enabled, allowing accounts with no password to log in remotely."));
            }
        }
    }
}

// ─── Services Audit ────────────────────────────────────────────────────

pub fn audit_services() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_listening_ports(&mut findings);
    audit_launchd_services(&mut findings);
    audit_exposed_services(&mut findings);

    Ok(findings)
}

fn audit_listening_ports(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("lsof", &["-i", "-P", "-n"]);

    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let name = parts[0];
        let user = parts[2];
        let addr = parts[8];
        let state = parts.get(9).unwrap_or(&"");

        if !state.contains("LISTEN") {
            continue;
        }

        // Parse address:port
        if let Some(colon) = addr.rfind(':') {
            let ip = &addr[..colon];
            let port_str = &addr[colon + 1..];
            let port: u16 = port_str.parse().unwrap_or(0);
            if port == 0 {
                continue;
            }

            let is_public = ip == "*" || ip == "0.0.0.0" || ip == "::";
            let is_loopback = ip == "127.0.0.1" || ip == "::1" || ip == "localhost";

            if is_public {
                let service_name = identify_service_by_port(port);
                let severity = if is_dangerous_port(port) {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(Finding::new(
                    &format!("mac-port-public-{}", port),
                    &format!("Port {} ({}) listening on all interfaces", port, service_name),
                    severity,
                    Category::Services,
                )
                .description(&format!("Port {} is listening on {} (all interfaces), accessible from any network. Process: {}, User: {}", port, ip, name, user))
                .metadata("port", port.to_string())
                .metadata("process", name)
                .metadata("user", user)
                .metadata("address", ip.to_string()));
            } else if !is_loopback {
                findings.push(
                    Finding::new(
                        &format!("mac-port-bound-{}", port),
                        &format!("Port {} listening on {}", port, ip),
                        Severity::Low,
                        Category::Services,
                    )
                    .metadata("port", port.to_string())
                    .metadata("address", ip.to_string()),
                );
            }
        }
    }
}

fn identify_service_by_port(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        21 => "FTP",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB",
        3389 => "RDP",
        5900 => "VNC",
        5901 => "VNC",
        631 => "IPP/CUPS",
        88 => "Kerberos",
        389 => "LDAP",
        636 => "LDAPS",
        139 => "NetBIOS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        27017 => "MongoDB",
        6379 => "Redis",
        9200 => "Elasticsearch",
        _ => "unknown",
    }
}

fn is_dangerous_port(port: u16) -> bool {
    matches!(
        port,
        23 | 21 | 139 | 445 | 3389 | 5900 | 5901 | 27017 | 6379 | 9200 | 11211
    )
}

fn audit_launchd_services(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("launchctl", &["list"]);

    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let label = parts[2];
        let pid = parts[0];

        // Check for suspicious labels
        if label.contains("com.apple") {
            continue; // Apple system service
        }

        if pid != "-" {
            // Running non-Apple service
            findings.push(
                Finding::new(
                    &format!("mac-launchd-service-{}", label),
                    &format!("Third-party launchd service running: {}", label),
                    Severity::Info,
                    Category::Services,
                )
                .metadata("label", label)
                .metadata("pid", pid.to_string()),
            );
        }
    }
}

fn audit_exposed_services(findings: &mut Vec<Finding>) {
    // Check for remote management (VNC/ARD)
    let ard = run_cmd_lossy(
        "sudo",
        &[
            "defaults",
            "read",
            "/var/db/launchd.db/com.apple.launchd/overrides.plist",
            "com.apple.screensharing",
        ],
    );
    if ard.contains("1") || ard.contains("true") {
        findings.push(
            Finding::new(
                "mac-remote-management-on",
                "Remote Management (Screen Sharing/VNC) is enabled",
                Severity::High,
                Category::Services,
            )
            .description("Remote Management is enabled, allowing VNC/ARD connections to this Mac.")
            .recommendation(
                "Disable if not needed: System Settings > Sharing > Screen Sharing > Off",
            ),
        );
    }

    // Check for SSH
    let ssh = run_cmd_lossy("systemsetup", &["-getremotelogin"]);
    if ssh.contains("On") {
        findings.push(
            Finding::new(
                "mac-ssh-enabled",
                "Remote Login (SSH) is enabled",
                Severity::Medium,
                Category::Services,
            )
            .description(
                "SSH remote login is enabled. If not needed, disable to reduce attack surface.",
            )
            .recommendation("Disable: sudo systemsetup -setremotelogin off"),
        );
    }

    // Check for file sharing
    let afp = run_cmd_lossy("sudo", &["launchctl", "list", "com.apple.AppleFileServer"]);
    if !afp.contains("Could not find") {
        findings.push(
            Finding::new(
                "mac-afp-sharing",
                "AFP file sharing is active",
                Severity::Medium,
                Category::Services,
            )
            .description("Apple Filing Protocol (AFP) sharing is active."),
        );
    }
}

// ─── Privileges Audit ──────────────────────────────────────────────────

pub fn audit_privileges() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_admin_users(&mut findings);
    audit_sudoers(&mut findings);
    audit_password_policy(&mut findings);
    audit_guest_account(&mut findings);

    Ok(findings)
}

fn audit_admin_users(findings: &mut Vec<Finding>) {
    let output = run_cmd("dscl", &[".", &"-list", "/Groups/admin", "GroupMembership"]);
    let members = output.trim();
    if !members.is_empty() {
        let user_list: Vec<&str> = members.split_whitespace().collect();
        for user in &user_list {
            findings.push(
                Finding::new(
                    &format!("mac-admin-user-{}", user),
                    &format!("User '{}' is an administrator", user),
                    Severity::Info,
                    Category::Privileges,
                )
                .metadata("user", user)
                .metadata("group", "admin"),
            );
        }

        if user_list.len() > 3 {
            findings.push(Finding::new(
                "mac-too-many-admins",
                &format!("{} users have admin privileges", user_list.len()),
                Severity::Medium,
                Category::Privileges,
            )
            .description(&format!("{} users are members of the admin group. Each admin account is a potential privilege escalation vector.", user_list.len()))
            .recommendation("Reduce admin users to only those who need it."));
        }
    }
}

fn audit_sudoers(findings: &mut Vec<Finding>) {
    // Check /etc/sudoers for insecure configs
    if let Some(content) = read_file("/etc/sudoers") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.contains("NOPASSWD") {
                findings.push(Finding::new(
                    "mac-sudo-nopasswd",
                    "NOPASSWD entry found in sudoers",
                    Severity::High,
                    Category::Privileges,
                )
                .description(&format!("Sudoers contains a NOPASSWD entry: '{}'. This allows running commands as root without password, making privilege escalation trivial.", line))
                .recommendation("Remove NOPASSWD entries or restrict to specific commands."));
            }
            if line.contains("ALL=(ALL) ALL")
                && !line.starts_with("root")
                && !line.starts_with("%admin")
                && !line.starts_with("%wheel")
            {
                findings.push(
                    Finding::new(
                        "mac-sudo-all-user",
                        "Non-standard user has full sudo access",
                        Severity::Medium,
                        Category::Privileges,
                    )
                    .description(&format!(
                        "Sudoers entry: '{}'. This user has unrestricted sudo access.",
                        line
                    )),
                );
            }
        }
    }

    // Check sudoers.d directory
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(content) = std::fs::read_to_string(&path).ok() {
                for line in content.lines() {
                    let line = line.trim();
                    if line.contains("NOPASSWD") {
                        findings.push(
                            Finding::new(
                                &format!("mac-sudo-nopasswd-{}", path.display()),
                                &format!("NOPASSWD in {}", path.display()),
                                Severity::High,
                                Category::Privileges,
                            )
                            .description(&format!(
                                "NOPASSWD entry in {}: '{}'",
                                path.display(),
                                line
                            )),
                        );
                    }
                }
            }
        }
    }
}

fn audit_password_policy(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("pwpolicy", &["getglobalpolicy"]);
    if output.contains("disabled") || output.is_empty() {
        // Check individual policies
        let acct_flags = run_cmd_lossy("pwpolicy", &["-u", "root", "-getglobalpolicy"]);
        if !acct_flags.contains("minChars") {
            findings.push(Finding::new(
                "mac-password-policy-weak",
                "Password policy may be weak or not enforced",
                Severity::Medium,
                Category::Privileges,
            )
            .description("No minimum password length policy detected. Short passwords are vulnerable to brute-force attacks.")
            .recommendation("Set password policy: pwpolicy setglobalpolicy minChars>=12"));
        }
    }
}

fn audit_guest_account(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "GuestEnabled",
        ],
    );
    if output.contains("1") || output.contains("true") {
        findings.push(Finding::new(
            "mac-guest-enabled",
            "Guest account is enabled",
            Severity::Medium,
            Category::Privileges,
        )
        .description("The guest account is enabled, allowing unauthenticated local access.")
        .recommendation("Disable guest: sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"));
    }
}

// ─── Persistence Audit ─────────────────────────────────────────────────

pub fn audit_persistence() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_launch_agents(&mut findings);
    audit_login_items(&mut findings);
    audit_cron_jobs(&mut findings);
    audit_startup_items(&mut findings);

    Ok(findings)
}

fn audit_launch_agents(findings: &mut Vec<Finding>) {
    let launch_paths = [
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        &format!(
            "{}/Library/LaunchAgents",
            std::env::var("HOME").unwrap_or_default()
        ),
    ];

    for path in &launch_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if file_path.extension().map_or(false, |e| e == "plist") {
                    if let Some(content) = std::fs::read_to_string(&file_path).ok() {
                        let is_suspicious =
                            is_suspicious_persistence(&content, &file_path.display().to_string());

                        if is_suspicious {
                            findings.push(
                                Finding::new(
                                    &format!(
                                        "mac-launch-{}",
                                        file_path.file_name().unwrap().to_string_lossy()
                                    ),
                                    &format!("Suspicious launch agent: {}", file_path.display()),
                                    Severity::High,
                                    Category::Persistence,
                                )
                                .description(&format!(
                                    "Launch agent at {} has suspicious characteristics.",
                                    file_path.display()
                                ))
                                .metadata("path", file_path.display().to_string()),
                            );
                        } else if !path.starts_with("/System/Library") {
                            // Third-party launch agent
                            findings.push(
                                Finding::new(
                                    &format!(
                                        "mac-launch-{}",
                                        file_path.file_name().unwrap().to_string_lossy()
                                    ),
                                    &format!("Third-party launch agent: {}", file_path.display()),
                                    Severity::Info,
                                    Category::Persistence,
                                )
                                .metadata("path", file_path.display().to_string()),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn is_suspicious_persistence(content: &str, path: &str) -> bool {
    let lower = content.to_lowercase();
    let path_lower = path.to_lowercase();

    // Suspicious indicators
    (lower.contains("/tmp/") || lower.contains("/var/tmp/"))
        || (lower.contains("curl") || lower.contains("wget") || lower.contains("nc "))
        || (lower.contains("base64") && lower.contains("-d"))
        || (lower.contains("python") && (lower.contains("-c") || lower.contains("eval")))
        || (path_lower.contains("temp") || path_lower.contains("appdata"))
        || (lower.contains("powershell") && lower.contains("hidden"))
}

fn audit_login_items(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_items_path = format!("{}/Library/Application Support/com.apple.backgroundtaskmanagementagent/BackgroundItems.btm", home);

    if file_exists(&login_items_path) {
        // Parse the BTM file - it's a binary plist
        let output = run_cmd_lossy("plutil", &["-p", &login_items_path]);
        if !output.is_empty() {
            for line in output.lines() {
                if line.contains("URL") || line.contains("Path") {
                    let trimmed = line.trim();
                    if trimmed.contains("tmp") || trimmed.contains("Downloads") {
                        findings.push(
                            Finding::new(
                                "mac-login-item-suspicious",
                                "Suspicious login item detected",
                                Severity::Medium,
                                Category::Persistence,
                            )
                            .description(&format!(
                                "Login item from suspicious location: {}",
                                trimmed
                            )),
                        );
                    }
                }
            }
        }
    }
}

fn audit_cron_jobs(findings: &mut Vec<Finding>) {
    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];

    for path in &cron_paths {
        let p = std::path::Path::new(path);
        if p.is_file() {
            if let Some(content) = read_file(path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    findings.push(
                        Finding::new(
                            &format!("mac-cron-{}", path),
                            &format!("Cron job in {}", path),
                            Severity::Info,
                            Category::Persistence,
                        )
                        .metadata("path", path.to_string())
                        .metadata("entry", line.to_string()),
                    );
                }
            }
        } else if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let file_path = entry.path();
                    if let Some(content) = std::fs::read_to_string(&file_path).ok() {
                        for line in content.lines() {
                            let line = line.trim();
                            if !line.is_empty() && !line.starts_with('#') {
                                findings.push(
                                    Finding::new(
                                        &format!("mac-cron-{}", file_path.display()),
                                        &format!("Cron job: {}", file_path.display()),
                                        Severity::Info,
                                        Category::Persistence,
                                    )
                                    .metadata("path", file_path.display().to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // User crontab
    let user_cron = run_cmd("crontab", &["-l"]);
    for line in user_cron.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            findings.push(
                Finding::new(
                    "mac-cron-user",
                    "User crontab entry",
                    Severity::Info,
                    Category::Persistence,
                )
                .metadata("entry", line.to_string()),
            );
        }
    }
}

fn audit_startup_items(findings: &mut Vec<Finding>) {
    let startup_paths = ["/Library/StartupItems", "/System/Library/StartupItems"];

    for path in &startup_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(|e| e.ok()) {
                let dir_path = entry.path();
                if dir_path.is_dir() {
                    findings.push(
                        Finding::new(
                            &format!("mac-startup-{}", dir_path.display()),
                            &format!("Startup item: {}", dir_path.display()),
                            Severity::Info,
                            Category::Persistence,
                        )
                        .metadata("path", dir_path.display().to_string()),
                    );
                }
            }
        }
    }
}

// ─── Credentials Audit ─────────────────────────────────────────────────

pub fn audit_credentials() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_keychain(&mut findings);
    audit_browser_passwords(&mut findings);
    audit_ssh_keys(&mut findings);
    audit_wifi_passwords(&mut findings);

    Ok(findings)
}

fn audit_keychain(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("security", &["list-keychains"]);
    for line in output.lines() {
        let keychain = line.trim().trim_matches('"');
        if !keychain.is_empty() {
            // Check if keychain is unlocked
            let locked = run_cmd_lossy("security", &["show-keychain-info", keychain]);
            if locked.contains("locked") {
                findings.push(
                    Finding::new(
                        &format!("mac-keychain-locked-{}", keychain),
                        &format!("Keychain '{}' is locked", keychain),
                        Severity::Info,
                        Category::Credentials,
                    )
                    .metadata("keychain", keychain.to_string()),
                );
            }
        }
    }

    // Check for default keychain items count
    let items = run_cmd_lossy("security", &["dump-keychain"]);
    let count = items.lines().filter(|l| l.contains("password")).count();
    if count > 0 {
        findings.push(Finding::new(
            "mac-keychain-items",
            &format!("{} password items in keychain", count),
            Severity::Info,
            Category::Credentials,
        )
        .description(&format!("Found {} password entries in the default keychain. These are encrypted but accessible to processes running as the user.", count))
        .metadata("count", count.to_string()));
    }
}

fn audit_browser_passwords(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();

    // Chrome
    let chrome_login = format!(
        "{}/Library/Application Support/Google/Chrome/Default/Login Data",
        home
    );
    if file_exists(&chrome_login) {
        findings.push(Finding::new(
            "mac-browser-chrome-passwords",
            "Google Chrome has saved passwords",
            Severity::Medium,
            Category::Credentials,
        )
        .description("Chrome's Login Data database exists, indicating saved passwords. These are encrypted with Keychain but can be accessed by processes running as the user."));
    }

    // Firefox
    let firefox_dir = format!("{}/Library/Application Support/Firefox/Profiles", home);
    if let Ok(entries) = std::fs::read_dir(&firefox_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let profile = entry.path();
            let logins = profile.join("logins.json");
            if logins.exists() {
                findings.push(
                    Finding::new(
                        "mac-browser-firefox-passwords",
                        "Firefox has saved passwords",
                        Severity::Medium,
                        Category::Credentials,
                    )
                    .description("Firefox logins.json exists, indicating saved passwords.")
                    .metadata("path", logins.display().to_string()),
                );
                break;
            }
        }
    }

    // Safari
    let safari_cookies = format!("{}/Library/Cookies/Cookies.binarycookies", home);
    if file_exists(&safari_cookies) {
        findings.push(
            Finding::new(
                "mac-browser-safari-cookies",
                "Safari has stored cookies",
                Severity::Low,
                Category::Credentials,
            )
            .description("Safari cookie database exists. Cookies may contain session tokens."),
        );
    }

    // Edge
    let edge_login = format!(
        "{}/Library/Application Support/Microsoft Edge/Default/Login Data",
        home
    );
    if file_exists(&edge_login) {
        findings.push(
            Finding::new(
                "mac-browser-edge-passwords",
                "Microsoft Edge has saved passwords",
                Severity::Medium,
                Category::Credentials,
            )
            .description("Edge's Login Data database exists, indicating saved passwords."),
        );
    }

    // Brave
    let brave_login = format!(
        "{}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
        home
    );
    if file_exists(&brave_login) {
        findings.push(
            Finding::new(
                "mac-browser-brave-passwords",
                "Brave browser has saved passwords",
                Severity::Medium,
                Category::Credentials,
            )
            .description("Brave's Login Data database exists, indicating saved passwords."),
        );
    }
}

fn audit_ssh_keys(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let ssh_dir = format!("{}/.ssh", home);

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            if file_name.ends_with(".pub")
                || file_name.starts_with("known_hosts")
                || file_name.starts_with("config")
            {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("PRIVATE KEY") {
                    let is_encrypted = content.contains("ENCRYPTED");
                    if !is_encrypted {
                        findings.push(Finding::new(
                            &format!("mac-ssh-key-nopass-{}", file_name),
                            &format!("SSH private key '{}' has no passphrase", file_name),
                            Severity::High,
                            Category::Credentials,
                        )
                        .description("Unencrypted SSH private key found. Anyone with file access can use it for authentication.")
                        .metadata("key_file", file_name));
                    }
                }
            }
        }
    }
}

fn audit_wifi_passwords(findings: &mut Vec<Finding>) {
    // macOS stores Wi-Fi passwords in Keychain
    let output = run_cmd_lossy("networksetup", &["-listallhardwareports"]);

    for line in output.lines() {
        if line.contains("Wi-Fi") || line.contains("AirPort") {
            // Get the device name
            let _next_lines: Vec<&str> = output.lines().collect();
            // Try to list known networks
            let networks =
                run_cmd_lossy("networksetup", &["-listpreferredwirelessnetworks", "en0"]);
            let count = networks
                .lines()
                .filter(|l| !l.is_empty() && !l.contains("Preferred"))
                .count();
            if count > 0 {
                findings.push(Finding::new(
                    "mac-wifi-profiles",
                    &format!("{} saved Wi-Fi networks", count),
                    Severity::Low,
                    Category::Credentials,
                )
                .description(&format!("{} Wi-Fi network profiles found. Passwords are stored in Keychain and accessible via `security find-generic-password`.", count))
                .metadata("count", count.to_string()));
            }
            break;
        }
    }
}

// ─── Shares Audit ──────────────────────────────────────────────────────

pub fn audit_shares() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_smb_shares(&mut findings);
    audit_afp_shares(&mut findings);
    audit_guest_access(&mut findings);
    audit_screen_sharing(&mut findings);

    Ok(findings)
}

fn audit_smb_shares(findings: &mut Vec<Finding>) {
    // Check if SMB sharing is enabled
    let output = run_cmd_lossy("launchctl", &["list", "com.apple.smbd"]);
    if !output.contains("Could not find") {
        findings.push(Finding::new(
            "mac-smb-sharing",
            "SMB file sharing is enabled",
            Severity::Medium,
            Category::Shares,
        )
        .description("SMB file sharing is active. Ensure shares are not accessible to unauthorized users."));
    }

    // List shared directories
    let sharing = run_cmd_lossy("sharing", &["-l"]);
    for line in sharing.lines() {
        let line = line.trim();
        if line.starts_with("name:") || line.starts_with("path:") {
            findings.push(
                Finding::new(
                    "mac-smb-share",
                    &format!("Shared folder: {}", line),
                    Severity::Info,
                    Category::Shares,
                )
                .metadata("share", line.to_string()),
            );
        }
    }
}

fn audit_afp_shares(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("launchctl", &["list", "com.apple.AppleFileServer"]);
    if !output.contains("Could not find") {
        findings.push(Finding::new(
            "mac-afp-sharing",
            "AFP file sharing is enabled",
            Severity::Medium,
            Category::Shares,
        )
        .description("AFP (Apple Filing Protocol) sharing is active. AFP is deprecated; consider using SMB instead."));
    }
}

fn audit_guest_access(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.AppleFileServer",
            "guest_access",
        ],
    );
    if output.contains("1") || output.contains("true") {
        findings.push(Finding::new(
            "mac-afp-guest",
            "AFP guest access is enabled",
            Severity::High,
            Category::Shares,
        )
        .description("AFP guest access is enabled, allowing unauthenticated file access.")
        .recommendation("Disable guest access: sudo defaults write /Library/Preferences/com.apple.AppleFileServer guest_access -bool false"));
    }

    let smb_guest = run_cmd_lossy(
        "defaults",
        &[
            "read",
            "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
            "GuestEnabled",
        ],
    );
    if smb_guest.contains("1") || smb_guest.contains("true") {
        findings.push(Finding::new(
            "mac-smb-guest",
            "SMB guest access is enabled",
            Severity::High,
            Category::Shares,
        )
        .description("SMB guest access is enabled, allowing unauthenticated file access.")
        .recommendation("Disable: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server GuestEnabled -bool false"));
    }
}

fn audit_screen_sharing(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("launchctl", &["list", "com.apple.screensharing"]);
    if !output.contains("Could not find") {
        findings.push(Finding::new(
            "mac-screen-sharing",
            "Screen Sharing (VNC) is enabled",
            Severity::High,
            Category::Shares,
        )
        .description("Screen Sharing is enabled. If VNC is accessible externally, an attacker could view and control the desktop.")
        .recommendation("Disable if not needed: sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist"));
    }
}

// ─── Patches Audit ─────────────────────────────────────────────────────

pub fn audit_patches() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_software_update(&mut findings);
    audit_brew_outdated(&mut findings);
    audit_last_update(&mut findings);

    Ok(findings)
}

fn audit_software_update(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("softwareupdate", &["-l"]);

    let mut count = 0;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("* Label:") {
            count += 1;
        }
    }

    if count > 0 {
        findings.push(Finding::new(
            "mac-updates-pending",
            &format!("{} macOS updates pending", count),
            Severity::High,
            Category::Patches,
        )
        .description(&format!("{} software updates are available. Unpatched systems are vulnerable to known exploits.", count))
        .recommendation("Install updates: sudo softwareupdate -i -a")
        .metadata("count", count.to_string()));
    }
}

fn audit_brew_outdated(findings: &mut Vec<Finding>) {
    let output = run_cmd("brew", &["outdated"]);

    let count = output.lines().filter(|l| !l.is_empty()).count();
    if count > 0 {
        findings.push(
            Finding::new(
                "mac-brew-outdated",
                &format!("{} Homebrew packages outdated", count),
                Severity::Medium,
                Category::Patches,
            )
            .description(&format!(
                "{} Homebrew packages have updates available.",
                count
            ))
            .recommendation("Update: brew upgrade")
            .metadata("count", count.to_string()),
        );

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                findings.push(
                    Finding::new(
                        &format!("mac-brew-outdated-{}", parts[0]),
                        &format!(
                            "{} is outdated ({} -> {})",
                            parts[0],
                            parts[1],
                            parts.get(3).unwrap_or(&"?")
                        ),
                        Severity::Low,
                        Category::Patches,
                    )
                    .metadata("package", parts[0].to_string())
                    .metadata("current", parts[1].to_string()),
                );
            }
        }
    }
}

fn audit_last_update(findings: &mut Vec<Finding>) {
    // Check last successful software update via system_profiler
    let output = run_cmd_lossy("system_profiler", &["SPSoftwareDataType"]);
    for line in output.lines() {
        let line = line.trim();
        if line.contains("Last Update") || line.contains("last update") {
            findings.push(
                Finding::new(
                    "mac-last-update",
                    "Last system update info",
                    Severity::Info,
                    Category::Patches,
                )
                .metadata("info", line.to_string()),
            );
        }
    }

    // Check if automatic updates are enabled
    let auto = run_cmd_lossy(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        ],
    );
    if auto.contains("0") || auto.contains("false") {
        findings.push(Finding::new(
            "mac-auto-update-off",
            "Automatic software updates are disabled",
            Severity::Medium,
            Category::Patches,
        )
        .description("Automatic update checking is disabled. Security patches may be missed.")
        .recommendation("Enable: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"));
    }
}
