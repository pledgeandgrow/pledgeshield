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
            if s.is_empty() { e } else { s }
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

    audit_firewall(&mut findings);
    audit_selinux_apparmor(&mut findings);
    audit_kernel_hardening(&mut findings);
    audit_ssh_config(&mut findings);
    audit_disk_encryption(&mut findings);
    audit_auto_updates(&mut findings);

    Ok(findings)
}

fn audit_firewall(findings: &mut Vec<Finding>) {
    // Check UFW
    let ufw = run_cmd_lossy("ufw", &["status"]);
    if ufw.contains("inactive") || ufw.contains("disabled") {
        findings.push(Finding::new(
            "linux-ufw-inactive",
            "UFW firewall is inactive",
            Severity::High,
            Category::Config,
        )
        .description("UFW (Uncomplicated Firewall) is inactive. All incoming connections are allowed by default.")
        .recommendation("Enable: sudo ufw enable")
        .fixable(true));
    } else if ufw.is_empty() {
        // UFW not found, check firewalld
        let firewalld = run_cmd_lossy("systemctl", &["is-active", "firewalld"]);
        if firewalld.contains("inactive") || firewalld.contains("failed") {
            findings.push(Finding::new(
                "linux-firewalld-inactive",
                "firewalld is inactive",
                Severity::High,
                Category::Config,
            )
            .description("firewalld is not running. No host-level firewall is active.")
            .recommendation("Enable: sudo systemctl enable --now firewalld"));
        } else if firewalld.is_empty() {
            // Check iptables
            let iptables = run_cmd_lossy("iptables", &["-L"]);
            if iptables.contains("Chain INPUT (policy ACCEPT)") {
                findings.push(Finding::new(
                    "linux-iptables-open",
                    "iptables INPUT chain has default ACCEPT policy",
                    Severity::Medium,
                    Category::Config,
                )
                .description("The iptables INPUT chain default policy is ACCEPT, allowing all incoming traffic.")
                .recommendation("Set default policy to DROP: sudo iptables -P INPUT DROP"));
            }
        }
    }
}

fn audit_selinux_apparmor(findings: &mut Vec<Finding>) {
    // Check SELinux
    let sestatus = run_cmd_lossy("sestatus", &[]);
    if !sestatus.is_empty() {
        if sestatus.contains("disabled") {
            findings.push(Finding::new(
                "linux-selinux-disabled",
                "SELinux is disabled",
                Severity::High,
                Category::Config,
            )
            .description("SELinux is disabled. Mandatory access control is not enforced, increasing the risk of privilege escalation and lateral movement.")
            .recommendation("Enable SELinux: edit /etc/selinux/config, set SELINUX=enforcing, reboot"));
        } else if sestatus.contains("permissive") {
            findings.push(Finding::new(
                "linux-selinux-permissive",
                "SELinux is in permissive mode",
                Severity::Medium,
                Category::Config,
            )
            .description("SELinux is in permissive mode. Violations are logged but not enforced.")
            .recommendation("Set to enforcing: sudo setenforce 1"));
        }
    } else {
        // Check AppArmor
        let apparmor = run_cmd_lossy("aa-status", &[]);
        if apparmor.is_empty() {
            // Try systemctl
            let aa_service = run_cmd_lossy("systemctl", &["is-active", "apparmor"]);
            if aa_service.contains("inactive") || aa_service.contains("failed") {
                findings.push(Finding::new(
                    "linux-apparmor-inactive",
                    "AppArmor is not active",
                    Severity::Medium,
                    Category::Config,
                )
                .description("AppArmor is not active. No mandatory access control is enforced."));
            }
        } else if apparmor.contains("0 profiles loaded") {
            findings.push(Finding::new(
                "linux-apparmor-no-profiles",
                "AppArmor has no loaded profiles",
                Severity::Medium,
                Category::Config,
            )
            .description("AppArmor is running but has no profiles loaded, providing no MAC protection."));
        }
    }
}

fn audit_kernel_hardening(findings: &mut Vec<Finding>) {
    let sysctl_checks = [
        ("kernel.randomize_va_space", "2", "ASLR is disabled", "linux-aslr-disabled", Severity::High),
        ("kernel.dmesg_restrict", "1", "dmesg is not restricted", "linux-dmesg-unrestricted", Severity::Medium),
        ("kernel.kptr_restrict", "2", "Kernel pointer addresses are not restricted", "linux-kptr-unrestricted", Severity::Medium),
        ("net.ipv4.tcp_syncookies", "1", "TCP SYN cookies are disabled", "linux-syncookies-off", Severity::Medium),
        ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects are accepted", "linux-icmp-redirects", Severity::Medium),
        ("net.ipv4.conf.all.send_redirects", "0", "ICMP redirects are sent", "linux-icmp-send-redirects", Severity::Low),
        ("net.ipv4.conf.all.accept_source_route", "0", "Source routing is accepted", "linux-source-routing", Severity::Medium),
        ("net.ipv4.conf.all.log_martians", "1", "Martian packets are not logged", "linux-no-martian-log", Severity::Low),
        ("kernel.yama.ptrace_scope", "2", "ptrace scope is not restricted", "linux-ptrace-unrestricted", Severity::Medium),
        ("fs.suid_dumpable", "0", "SUID dumps are enabled", "linux-suid-dumpable", Severity::Medium),
        ("net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering is disabled", "linux-rp-filter-off", Severity::Low),
    ];

    for (key, expected, desc, finding_id, severity) in sysctl_checks {
        let output = run_cmd_lossy("sysctl", &["-n", key]);
        let actual = output.trim();
        if actual != expected {
            findings.push(Finding::new(
                finding_id,
                desc,
                severity,
                Category::Config,
            )
            .description(&format!("sysctl {} = {} (expected: {}). {}", key, actual, expected, desc))
            .recommendation(&format!("Set: sudo sysctl -w {}={}", key, expected))
            .metadata("key", key)
            .metadata("current", actual.to_string())
            .metadata("expected", expected.to_string()));
        }
    }
}

fn audit_ssh_config(findings: &mut Vec<Finding>) {
    if let Some(config) = read_file("/etc/ssh/sshd_config") {
        for line in config.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with("PermitRootLogin") && (line.contains("yes") || !line.contains("no")) {
                findings.push(Finding::new(
                    "linux-ssh-root-login",
                    "SSH root login is permitted",
                    Severity::High,
                    Category::Config,
                )
                .description("SSH PermitRootLogin is enabled. Direct root SSH access is a major security risk.")
                .recommendation("Set PermitRootLogin no in /etc/ssh/sshd_config"));
            }
            if line.starts_with("PasswordAuthentication") && line.contains("yes") {
                findings.push(Finding::new(
                    "linux-ssh-password-auth",
                    "SSH password authentication is enabled",
                    Severity::Medium,
                    Category::Config,
                )
                .description("SSH password authentication is enabled. Key-based authentication is more secure.")
                .recommendation("Set PasswordAuthentication no in /etc/ssh/sshd_config"));
            }
            if line.starts_with("PermitEmptyPasswords") && line.contains("yes") {
                findings.push(Finding::new(
                    "linux-ssh-empty-passwords",
                    "SSH permits empty passwords",
                    Severity::Critical,
                    Category::Config,
                )
                .description("SSH PermitEmptyPasswords is enabled."));
            }
            if line.starts_with("X11Forwarding") && line.contains("yes") {
                findings.push(Finding::new(
                    "linux-ssh-x11-forward",
                    "SSH X11 forwarding is enabled",
                    Severity::Low,
                    Category::Config,
                )
                .description("X11 forwarding is enabled, which can be used for keylogging and clipboard attacks."));
            }
            if line.starts_with("Protocol") && !line.contains("2") {
                findings.push(Finding::new(
                    "linux-ssh-protocol-1",
                    "SSH protocol 1 is allowed",
                    Severity::Critical,
                    Category::Config,
                )
                .description("SSH protocol 1 is allowed. Protocol 1 has known vulnerabilities."));
            }
            if line.starts_with("MaxAuthTries") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    if val.parse::<u32>().unwrap_or(6) > 3 {
                        findings.push(Finding::new(
                            "linux-ssh-high-auth-tries",
                            "SSH MaxAuthTries is high",
                            Severity::Low,
                            Category::Config,
                        )
                        .description(&format!("MaxAuthTries is {}, allowing many brute-force attempts.", val)));
                    }
                }
            }
        }
    }
}

fn audit_disk_encryption(findings: &mut Vec<Finding>) {
    // Check for LUKS
    let luks = run_cmd_lossy("lsblk", &["-o", "NAME,FSTYPE,SIZE,MOUNTPOINT"]);
    let has_crypt = luks.contains("crypto_LUKS") || luks.contains("crypt");
    if !has_crypt {
        // Check if root is on LVM without encryption
        let mounts = read_file("/proc/mounts");
        if let Some(mounts) = mounts {
            if mounts.contains(" / ") && !luks.contains("crypt") {
                findings.push(Finding::new(
                    "linux-no-disk-encryption",
                    "Root filesystem appears unencrypted",
                    Severity::Medium,
                    Category::Config,
                )
                .description("No LUKS encryption detected on any block device. Data at rest is readable by anyone with physical access.")
                .recommendation("Consider encrypting with LUKS: cryptsetup luksFormat /dev/sdX"));
            }
        }
    }
}

fn audit_auto_updates(findings: &mut Vec<Finding>) {
    // Check unattended-upgrades (Debian/Ubuntu)
    if file_exists("/etc/apt/apt.conf.d/20auto-upgrades") {
        if let Some(content) = read_file("/etc/apt/apt.conf.d/20auto-upgrades") {
            if !content.contains("APT::Periodic::Update-Package-Lists \"1\"") || !content.contains("APT::Periodic::Unattended-Upgrade \"1\"") {
                findings.push(Finding::new(
                    "linux-auto-updates-off",
                    "Automatic security updates are disabled",
                    Severity::Medium,
                    Category::Config,
                )
                .description("unattended-upgrades is not configured for automatic security updates.")
                .recommendation("Enable: sudo dpkg-reconfigure -plow unattended-upgrades"));
            }
        }
    } else {
        // Check dnf-automatic (RHEL/Fedora)
        let dnf_auto = run_cmd_lossy("systemctl", &["is-enabled", "dnf-automatic.timer"]);
        if dnf_auto.contains("disabled") || dnf_auto.contains("inactive") {
            // Check cron-apt as fallback
            if !file_exists("/etc/cron-apt/action.d") {
                findings.push(Finding::new(
                    "linux-auto-updates-unknown",
                    "Automatic updates may not be configured",
                    Severity::Low,
                    Category::Config,
                )
                .description("No automatic update mechanism detected. Security patches may be missed."));
            }
        }
    }
}

// ─── Services Audit ────────────────────────────────────────────────────

pub fn audit_services() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_listening_ports(&mut findings);
    audit_systemd_services(&mut findings);
    audit_root_services(&mut findings);

    Ok(findings)
}

fn audit_listening_ports(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("ss", &["-tlnp"]);
    if output.is_empty() {
        // Fallback to netstat
        let _ = run_cmd_lossy("netstat", &["-tlnp"]);
    }

    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let local_addr = parts[3];
        let state = parts.get(4).unwrap_or(&"");

        if !state.contains("LISTEN") {
            continue;
        }

        // Parse address:port
        if let Some(colon) = local_addr.rfind(':') {
            let ip = &local_addr[..colon];
            let port_str = &local_addr[colon + 1..];
            let port: u16 = port_str.parse().unwrap_or(0);
            if port == 0 {
                continue;
            }

            let is_public = ip == "*" || ip == "0.0.0.0" || ip == "[::]" || ip == "::";
            let is_loopback = ip == "127.0.0.1" || ip == "::1" || ip == "[::1]";

            if is_public {
                let service_name = identify_service_by_port(port);
                let severity = if is_dangerous_port(port) { Severity::Critical } else { Severity::High };

                findings.push(Finding::new(
                    &format!("linux-port-public-{}", port),
                    &format!("Port {} ({}) listening on all interfaces", port, service_name),
                    severity,
                    Category::Services,
                )
                .description(&format!("Port {} is listening on {} (all interfaces), accessible from any network.", port, ip))
                .metadata("port", port.to_string())
                .metadata("address", ip.to_string()));
            } else if !is_loopback {
                findings.push(Finding::new(
                    &format!("linux-port-bound-{}", port),
                    &format!("Port {} listening on {}", port, ip),
                    Severity::Low,
                    Category::Services,
                )
                .metadata("port", port.to_string())
                .metadata("address", ip.to_string()));
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
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        5900 => "VNC",
        3389 => "RDP",
        139 => "NetBIOS",
        631 => "IPP/CUPS",
        2049 => "NFS",
        111 => "rpcbind",
        _ => "unknown",
    }
}

fn is_dangerous_port(port: u16) -> bool {
    matches!(port, 23 | 21 | 139 | 445 | 3389 | 5900 | 27017 | 6379 | 9200 | 11211 | 2049 | 111)
}

fn audit_systemd_services(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("systemctl", &["list-units", "--type=service", "--state=running"]);

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("UNIT") || line.starts_with("LOAD") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let unit = parts[0];
        if unit.ends_with(".service") {
            findings.push(Finding::new(
                &format!("linux-service-{}", unit),
                &format!("Running service: {}", unit),
                Severity::Info,
                Category::Services,
            )
            .metadata("unit", unit.to_string()));
        }
    }
}

fn audit_root_services(findings: &mut Vec<Finding>) {
    // Check for services running as root that shouldn't
    let output = run_cmd_lossy("ps", &["aux"]);
    let root_services = ["nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server", "mongod"];

    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 11 {
            continue;
        }

        let user = parts[0];
        let cmd = parts[10];

        if user == "root" {
            for svc in &root_services {
                if cmd.contains(svc) {
                    findings.push(Finding::new(
                        &format!("linux-root-service-{}", svc),
                        &format!("{} is running as root", svc),
                        Severity::Medium,
                        Category::Services,
                    )
                    .description(&format!("{} is running as root. If compromised, the attacker gains root access.", svc))
                    .recommendation(&format!("Run {} as a dedicated unprivileged user.", svc))
                    .metadata("service", svc.to_string())
                    .metadata("user", "root"));
                }
            }
        }
    }
}

// ─── Privileges Audit ──────────────────────────────────────────────────

pub fn audit_privileges() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_passwd(&mut findings);
    audit_sudoers(&mut findings);
    audit_password_policy(&mut findings);
    audit_shadow_file(&mut findings);

    Ok(findings)
}

fn audit_passwd(findings: &mut Vec<Finding>) {
    if let Some(content) = read_file("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }

            let username = parts[0];
            let uid = parts[2];
            let shell = parts[6];

            // Check for UID 0 accounts other than root
            if uid == "0" && username != "root" {
                findings.push(Finding::new(
                    &format!("linux-uid0-{}", username),
                    &format!("User '{}' has UID 0 (root equivalent)", username),
                    Severity::Critical,
                    Category::Privileges,
                )
                .description(&format!("User '{}' has UID 0, granting full root privileges.", username))
                .metadata("user", username));
            }

            // Check for accounts with login shells but no password
            if shell != "/bin/false" && shell != "/usr/sbin/nologin" && shell != "/bin/nologin" && shell != "/dev/null" {
                if uid.parse::<u32>().unwrap_or(1000) < 1000 && username != "root" && username != "sync" {
                    findings.push(Finding::new(
                        &format!("linux-system-account-shell-{}", username),
                        &format!("System account '{}' has a login shell", username),
                        Severity::Medium,
                        Category::Privileges,
                    )
                    .description(&format!("System account '{}' has shell '{}'. System accounts should not have login shells.", username, shell))
                    .metadata("user", username)
                    .metadata("shell", shell.to_string()));
                }
            }
        }
    }
}

fn audit_sudoers(findings: &mut Vec<Finding>) {
    if let Some(content) = read_file("/etc/sudoers") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line.starts_with("Defaults") {
                continue;
            }
            if line.contains("NOPASSWD") {
                findings.push(Finding::new(
                    "linux-sudo-nopasswd",
                    "NOPASSWD entry found in sudoers",
                    Severity::High,
                    Category::Privileges,
                )
                .description(&format!("Sudoers contains NOPASSWD: '{}'. This allows running commands as root without password.", line))
                .recommendation("Remove NOPASSWD entries or restrict to specific commands."));
            }
            if line.contains("ALL=(ALL:ALL) ALL") && !line.starts_with("root") && !line.starts_with("%admin") && !line.starts_with("%sudo") && !line.starts_with("%wheel") {
                findings.push(Finding::new(
                    "linux-sudo-all-user",
                    "Non-standard user has full sudo access",
                    Severity::Medium,
                    Category::Privileges,
                )
                .description(&format!("Sudoers entry: '{}'. Unrestricted sudo access.", line)));
            }
        }
    }

    // Check sudoers.d
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(content) = std::fs::read_to_string(&path).ok() {
                for line in content.lines() {
                    let line = line.trim();
                    if line.contains("NOPASSWD") {
                        findings.push(Finding::new(
                            &format!("linux-sudo-nopasswd-{}", path.display()),
                            &format!("NOPASSWD in {}", path.display()),
                            Severity::High,
                            Category::Privileges,
                        )
                        .description(&format!("NOPASSWD in {}: '{}'", path.display(), line)));
                    }
                }
            }
        }
    }
}

fn audit_password_policy(findings: &mut Vec<Finding>) {
    // Check PAM config for password quality
    if let Some(content) = read_file("/etc/pam.d/common-password") {
        if !content.contains("pam_pwquality") && !content.contains("pam_cracklib") {
            findings.push(Finding::new(
                "linux-password-quality-none",
                "No PAM password quality module configured",
                Severity::Medium,
                Category::Privileges,
            )
            .description("No pam_pwquality or pam_cracklib module found in PAM config. Passwords are not checked for complexity.")
            .recommendation("Install and configure pam_pwquality"));
        }
    }

    // Check login.defs for password aging
    if let Some(content) = read_file("/etc/login.defs") {
        let mut min_len = 0u32;
        let mut max_days = 99999u32;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "PASS_MIN_LEN" | "PASS_MIN_DAYS" => {
                    min_len = parts[1].parse().unwrap_or(0);
                }
                "PASS_MAX_DAYS" => {
                    max_days = parts[1].parse().unwrap_or(99999);
                }
                _ => {}
            }
        }
        if min_len < 12 {
            findings.push(Finding::new(
                "linux-password-length-weak",
                &format!("Minimum password length is {} (recommended: 12)", min_len),
                Severity::Medium,
                Category::Privileges,
            )
            .description(&format!("PASS_MIN_LEN is {}. Short passwords are vulnerable to brute-force.", min_len))
            .recommendation("Set PASS_MIN_LEN 12 in /etc/login.defs"));
        }
        if max_days > 90 {
            findings.push(Finding::new(
                "linux-password-max-age",
                &format!("Password max age is {} days (recommended: 90)", max_days),
                Severity::Low,
                Category::Privileges,
            )
            .description(&format!("PASS_MAX_DAYS is {}. Passwords rarely expire.", max_days)));
        }
    }
}

fn audit_shadow_file(findings: &mut Vec<Finding>) {
    if let Some(content) = read_file("/etc/shadow") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 2 {
                continue;
            }

            let username = parts[0];
            let hash = parts[1];

            if hash == "*" || hash == "!" {
                continue; // Locked or no password
            }

            if hash.is_empty() {
                findings.push(Finding::new(
                    &format!("linux-empty-password-{}", username),
                    &format!("User '{}' has an empty password", username),
                    Severity::Critical,
                    Category::Privileges,
                )
                .description(&format!("User '{}' has an empty password in /etc/shadow.", username))
                .recommendation(&format!("Lock account: sudo passwd -l {}", username)));
            }

            // Check for weak hash algorithms
            if hash.starts_with("$1$") {
                findings.push(Finding::new(
                    &format!("linux-weak-hash-{}", username),
                    &format!("User '{}' uses MD5 password hashing", username),
                    Severity::Medium,
                    Category::Privileges,
                )
                .description("MD5 password hashing is used. MD5 is cryptographically broken and vulnerable to GPU cracking.")
                .recommendation("Use SHA-512 ($6$) or yescrypt ($y$) hashing."));
            }
            if hash.starts_with("$5$") {
                findings.push(Finding::new(
                    &format!("linux-sha256-hash-{}", username),
                    &format!("User '{}' uses SHA-256 hashing", username),
                    Severity::Low,
                    Category::Privileges,
                )
                .description("SHA-256 hashing is used. SHA-512 or yescrypt is recommended."));
            }
        }
    }
}

// ─── Persistence Audit ─────────────────────────────────────────────────

pub fn audit_persistence() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_cron_jobs(&mut findings);
    audit_systemd_timers(&mut findings);
    audit_init_scripts(&mut findings);
    audit_shell_profiles(&mut findings);
    audit_rc_local(&mut findings);

    Ok(findings)
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
                    findings.push(Finding::new(
                        &format!("linux-cron-{}", path),
                        &format!("Cron job in {}", path),
                        Severity::Info,
                        Category::Persistence,
                    )
                    .metadata("path", path.to_string())
                    .metadata("entry", line.to_string()));
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
                                findings.push(Finding::new(
                                    &format!("linux-cron-{}", file_path.display()),
                                    &format!("Cron job: {}", file_path.display()),
                                    Severity::Info,
                                    Category::Persistence,
                                )
                                .metadata("path", file_path.display().to_string()));
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
            findings.push(Finding::new(
                "linux-cron-user",
                "User crontab entry",
                Severity::Info,
                Category::Persistence,
            )
            .metadata("entry", line.to_string()));
        }
    }
}

fn audit_systemd_timers(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("systemctl", &["list-timers", "--all"]);

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("NEXT") || line.starts_with("n/a") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Find the .timer unit
        for part in &parts {
            if part.ends_with(".timer") {
                findings.push(Finding::new(
                    &format!("linux-timer-{}", part),
                    &format!("Systemd timer: {}", part),
                    Severity::Info,
                    Category::Persistence,
                )
                .metadata("timer", part.to_string()));
            }
        }
    }
}

fn audit_init_scripts(findings: &mut Vec<Finding>) {
    let init_paths = ["/etc/init.d", "/etc/rc.d/init.d"];

    for path in &init_paths {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if file_path.is_file() {
                    let name = file_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    findings.push(Finding::new(
                        &format!("linux-initd-{}", name),
                        &format!("Init script: {}", name),
                        Severity::Info,
                        Category::Persistence,
                    )
                    .metadata("path", file_path.display().to_string()));
                }
            }
        }
    }
}

fn audit_shell_profiles(findings: &mut Vec<Finding>) {
    let profile_paths = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/profile.d",
    ];

    for path in &profile_paths {
        let p = std::path::Path::new(path);
        if p.is_file() {
            if let Some(content) = read_file(path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    // Check for suspicious commands in system profiles
                    let lower = line.to_lowercase();
                    if lower.contains("curl") || lower.contains("wget") || lower.contains("nc ") || lower.contains("base64 -d") {
                        findings.push(Finding::new(
                            &format!("linux-profile-suspicious-{}", path),
                            &format!("Suspicious entry in {}", path),
                            Severity::High,
                            Category::Persistence,
                        )
                        .description(&format!("Suspicious command in {}: '{}'", path, line))
                        .metadata("path", path.to_string())
                        .metadata("entry", line.to_string()));
                    }
                }
            }
        } else if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let file_path = entry.path();
                    if let Some(content) = std::fs::read_to_string(&file_path).ok() {
                        for line in content.lines() {
                            let line = line.trim();
                            let lower = line.to_lowercase();
                            if lower.contains("curl") || lower.contains("wget") || lower.contains("nc ") || lower.contains("base64 -d") {
                                findings.push(Finding::new(
                                    &format!("linux-profile-suspicious-{}", file_path.display()),
                                    &format!("Suspicious entry in {}", file_path.display()),
                                    Severity::High,
                                    Category::Persistence,
                                )
                                .description(&format!("Suspicious command in {}: '{}'", file_path.display(), line))
                                .metadata("path", file_path.display().to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn audit_rc_local(findings: &mut Vec<Finding>) {
    if let Some(content) = read_file("/etc/rc.local") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line == "exit 0" {
                continue;
            }
            findings.push(Finding::new(
                "linux-rc-local",
                "Entry in /etc/rc.local",
                Severity::Info,
                Category::Persistence,
            )
            .metadata("entry", line.to_string()));
        }
    }
}

// ─── Credentials Audit ─────────────────────────────────────────────────

pub fn audit_credentials() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_browser_passwords(&mut findings);
    audit_ssh_keys(&mut findings);
    audit_wifi_passwords(&mut findings);
    audit_keyring(&mut findings);

    Ok(findings)
}

fn audit_browser_passwords(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();

    // Chrome
    let chrome_login = format!("{}/.config/google-chrome/Default/Login Data", home);
    if file_exists(&chrome_login) {
        findings.push(Finding::new(
            "linux-browser-chrome-passwords",
            "Google Chrome has saved passwords",
            Severity::Medium,
            Category::Credentials,
        )
        .description("Chrome's Login Data database exists, indicating saved passwords."));
    }

    // Chromium
    let chromium_login = format!("{}/.config/chromium/Default/Login Data", home);
    if file_exists(&chromium_login) {
        findings.push(Finding::new(
            "linux-browser-chromium-passwords",
            "Chromium has saved passwords",
            Severity::Medium,
            Category::Credentials,
        )
        .description("Chromium's Login Data database exists, indicating saved passwords."));
    }

    // Firefox
    let firefox_dir = format!("{}/.mozilla/firefox", home);
    if let Ok(entries) = std::fs::read_dir(&firefox_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let profile = entry.path();
            let logins = profile.join("logins.json");
            if logins.exists() {
                findings.push(Finding::new(
                    "linux-browser-firefox-passwords",
                    "Firefox has saved passwords",
                    Severity::Medium,
                    Category::Credentials,
                )
                .description("Firefox logins.json exists, indicating saved passwords.")
                .metadata("path", logins.display().to_string()));
                break;
            }
        }
    }

    // Brave
    let brave_login = format!("{}/.config/BraveSoftware/Brave-Browser/Default/Login Data", home);
    if file_exists(&brave_login) {
        findings.push(Finding::new(
            "linux-browser-brave-passwords",
            "Brave browser has saved passwords",
            Severity::Medium,
            Category::Credentials,
        )
        .description("Brave's Login Data database exists, indicating saved passwords."));
    }
}

fn audit_ssh_keys(findings: &mut Vec<Finding>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let ssh_dir = format!("{}/.ssh", home);

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

            if file_name.ends_with(".pub") || file_name.starts_with("known_hosts") || file_name.starts_with("config") {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("PRIVATE KEY") {
                    let is_encrypted = content.contains("ENCRYPTED");
                    if !is_encrypted {
                        findings.push(Finding::new(
                            &format!("linux-ssh-key-nopass-{}", file_name),
                            &format!("SSH private key '{}' has no passphrase", file_name),
                            Severity::High,
                            Category::Credentials,
                        )
                        .description("Unencrypted SSH private key found.")
                        .metadata("key_file", file_name));
                    }

                    // Check file permissions
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        use std::os::unix::fs::PermissionsExt;
                        let perms = metadata.permissions().mode();
                        if perms & 0o077 != 0 {
                            findings.push(Finding::new(
                                &format!("linux-ssh-key-perms-{}", file_name),
                                &format!("SSH key '{}' has overly permissive file permissions", file_name),
                                Severity::Medium,
                                Category::Credentials,
                            )
                            .description(&format!("SSH key '{}' is readable by other users (mode {:o}). SSH may refuse to use it.", file_name, perms & 0o777))
                            .recommendation(&format!("Fix: chmod 600 {}", path.display())));
                        }
                    }
                }
            }
        }
    }
}

fn audit_wifi_passwords(findings: &mut Vec<Finding>) {
    // NetworkManager stores Wi-Fi passwords in /etc/NetworkManager/system-connections/
    let nm_dir = "/etc/NetworkManager/system-connections";
    if let Ok(entries) = std::fs::read_dir(nm_dir) {
        let count = entries.filter_map(|e| e.ok()).count();
        if count > 0 {
            findings.push(Finding::new(
                "linux-wifi-profiles",
                &format!("{} saved Wi-Fi networks (NetworkManager)", count),
                Severity::Low,
                Category::Credentials,
            )
            .description(&format!("{} Wi-Fi network profiles found in {}. Passwords are stored in plaintext config files.", count, nm_dir))
            .metadata("count", count.to_string()));
        }
    }

    // wpa_supplicant
    let wpa_conf = "/etc/wpa_supplicant/wpa_supplicant.conf";
    if let Some(content) = read_file(wpa_conf) {
        if content.contains("psk=") {
            let count = content.lines().filter(|l| l.contains("psk=")).count();
            findings.push(Finding::new(
                "linux-wifi-wpa-supplicant",
                &format!("{} Wi-Fi passwords in wpa_supplicant.conf", count),
                Severity::Low,
                Category::Credentials,
            )
            .description(&format!("{} Wi-Fi PSKs found in {}.", count, wpa_conf))
            .metadata("count", count.to_string()));
        }
    }
}

fn audit_keyring(findings: &mut Vec<Finding>) {
    // Check for GNOME Keyring
    let keyring_dir = format!("{}/.local/share/keyrings", std::env::var("HOME").unwrap_or_default());
    if let Ok(entries) = std::fs::read_dir(&keyring_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.ends_with(".keyring") {
                findings.push(Finding::new(
                    &format!("linux-keyring-{}", name),
                    &format!("GNOME Keyring file: {}", name),
                    Severity::Info,
                    Category::Credentials,
                )
                .description("GNOME Keyring file found. Stored credentials are encrypted with the user's login password."));
            }
        }
    }

    // Check for KDE Wallet
    let kwallet_dir = format!("{}/.local/share/kwalletd", std::env::var("HOME").unwrap_or_default());
    if let Ok(entries) = std::fs::read_dir(&kwallet_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if name.ends_with(".kwl") {
                findings.push(Finding::new(
                    &format!("linux-kwallet-{}", name),
                    &format!("KDE Wallet file: {}", name),
                    Severity::Info,
                    Category::Credentials,
                )
                .description("KDE Wallet file found."));
            }
        }
    }
}

// ─── Shares Audit ──────────────────────────────────────────────────────

pub fn audit_shares() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_nfs_exports(&mut findings);
    audit_samba_shares(&mut findings);

    Ok(findings)
}

fn audit_nfs_exports(findings: &mut Vec<Finding>) {
    if let Some(content) = read_file("/etc/exports") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let export_path = parts[0];
            let options = line.to_string();

            // Check for no_root_squash
            if line.contains("no_root_squash") {
                findings.push(Finding::new(
                    &format!("linux-nfs-no-root-squash-{}", export_path),
                    &format!("NFS export '{}' has no_root_squash", export_path),
                    Severity::High,
                    Category::Shares,
                )
                .description(&format!("NFS export '{}' is configured with no_root_squash. Remote root users retain root privileges on the exported filesystem.", export_path))
                .recommendation("Remove no_root_squash or use root_squash")
                .metadata("export", export_path.to_string())
                .metadata("options", options.clone()));
            }

            // Check for * export
            if line.contains("*") {
                findings.push(Finding::new(
                    &format!("linux-nfs-wildcard-{}", export_path),
                    &format!("NFS export '{}' allows wildcard access", export_path),
                    Severity::High,
                    Category::Shares,
                )
                .description(&format!("NFS export '{}' is accessible from any host (*).", export_path))
                .metadata("export", export_path.to_string())
                .metadata("options", options.clone()));
            }

            // General info
            findings.push(Finding::new(
                &format!("linux-nfs-export-{}", export_path),
                &format!("NFS export: {}", export_path),
                Severity::Info,
                Category::Shares,
            )
            .metadata("export", export_path.to_string())
            .metadata("options", options));
        }
    }
}

fn audit_samba_shares(findings: &mut Vec<Finding>) {
    let smb_conf_paths = ["/etc/samba/smb.conf", "/usr/local/etc/smb.conf"];

    for conf_path in &smb_conf_paths {
        if let Some(content) = read_file(conf_path) {
            let mut in_share = false;
            let mut current_share = String::new();
            let mut has_guest = false;
            let mut is_writable = false;

            for line in content.lines() {
                let line = line.trim();

                // New share section
                if line.starts_with('[') && line.ends_with(']') {
                    // Report previous share
                    if in_share && !current_share.is_empty() {
                        if has_guest {
                            findings.push(Finding::new(
                                &format!("linux-smb-guest-{}", current_share),
                                &format!("SMB share '{}' allows guest access", current_share),
                                Severity::High,
                                Category::Shares,
                            )
                            .description(&format!("SMB share '{}' has guest ok = yes, allowing unauthenticated access.", current_share))
                            .metadata("share", current_share.clone()));
                        }
                        if is_writable && has_guest {
                            findings.push(Finding::new(
                                &format!("linux-smb-guest-writable-{}", current_share),
                                &format!("SMB share '{}' is writable and allows guest", current_share),
                                Severity::Critical,
                                Category::Shares,
                            )
                            .description(&format!("SMB share '{}' is both writable and guest-accessible.", current_share))
                            .metadata("share", current_share.clone()));
                        }
                    }

                    current_share = line.trim_matches(|c| c == '[' || c == ']').to_string();
                    in_share = current_share != "global";
                    has_guest = false;
                    is_writable = false;
                    continue;
                }

                if !in_share || line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                    continue;
                }

                let lower = line.to_lowercase();
                if lower.contains("guest ok") && lower.contains("yes") {
                    has_guest = true;
                }
                if lower.contains("writable") && lower.contains("yes") {
                    is_writable = true;
                }
                if lower.contains("writeable") && lower.contains("yes") {
                    is_writable = true;
                }
            }

            // Report last share
            if in_share && !current_share.is_empty() && has_guest {
                findings.push(Finding::new(
                    &format!("linux-smb-guest-{}", current_share),
                    &format!("SMB share '{}' allows guest access", current_share),
                    Severity::High,
                    Category::Shares,
                )
                .metadata("share", current_share.clone()));
            }

            // Check global settings
            if content.contains("server signing") && !content.contains("mandatory") {
                findings.push(Finding::new(
                    "linux-smb-signing-optional",
                    "SMB signing is not mandatory",
                    Severity::Medium,
                    Category::Shares,
                )
                .description("SMB server signing is not set to mandatory. Relay attacks are possible.")
                .recommendation("Set 'server signing = mandatory' in [global] section"));
            }

            if content.contains("min protocol") {
                // Check for SMBv1
                if content.contains("min protocol = NT1") || content.contains("client min protocol = NT1") {
                    findings.push(Finding::new(
                        "linux-smbv1-enabled",
                        "SMBv1 protocol is enabled",
                        Severity::Critical,
                        Category::Shares,
                    )
                    .description("SMBv1 is enabled in Samba config. SMBv1 is vulnerable to EternalBlue (MS17-010).")
                    .recommendation("Set 'min protocol = SMB2' or higher"));
                }
            }
        }
    }
}

// ─── Patches Audit ─────────────────────────────────────────────────────

pub fn audit_patches() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_apt_updates(&mut findings);
    audit_dnf_updates(&mut findings);
    audit_pacman_updates(&mut findings);
    audit_pending_reboot(&mut findings);

    Ok(findings)
}

fn audit_apt_updates(findings: &mut Vec<Finding>) {
    if !file_exists("/usr/bin/apt") && !file_exists("/usr/bin/apt-get") {
        return;
    }

    let output = run_cmd_lossy("apt", &["list", "--upgradable"]);

    let mut count = 0;
    let mut security_count = 0;

    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        count += 1;

        if line.contains("security") {
            security_count += 1;
        }
    }

    if count > 0 {
        findings.push(Finding::new(
            "linux-apt-updates",
            &format!("{} packages can be upgraded ({} security)", count, security_count),
            if security_count > 0 { Severity::High } else { Severity::Medium },
            Category::Patches,
        )
        .description(&format!("{} packages have updates available, {} of which are security updates.", count, security_count))
        .recommendation("Update: sudo apt update && sudo apt upgrade")
        .metadata("total", count.to_string())
        .metadata("security", security_count.to_string()));
    }
}

fn audit_dnf_updates(findings: &mut Vec<Finding>) {
    if !file_exists("/usr/bin/dnf") && !file_exists("/usr/bin/yum") {
        return;
    }

    let cmd = if file_exists("/usr/bin/dnf") { "dnf" } else { "yum" };
    let output = run_cmd_lossy(cmd, &["check-update"]);

    let count = output.lines().filter(|l| {
        !l.is_empty() && !l.starts_with("Last metadata") && !l.contains(".repo")
    }).count();

    if count > 0 {
        // Check security updates
        let sec_output = run_cmd_lossy(cmd, &["check-update", "--security"]);
        let sec_count = sec_output.lines().filter(|l| {
            !l.is_empty() && !l.starts_with("Last metadata") && !l.contains(".repo")
        }).count();

        findings.push(Finding::new(
            "linux-dnf-updates",
            &format!("{} packages can be updated ({} security)", count, sec_count),
            if sec_count > 0 { Severity::High } else { Severity::Medium },
            Category::Patches,
        )
        .description(&format!("{} packages have updates available, {} security.", count, sec_count))
        .recommendation(&format!("Update: sudo {} upgrade", cmd))
        .metadata("total", count.to_string())
        .metadata("security", sec_count.to_string()));
    }
}

fn audit_pacman_updates(findings: &mut Vec<Finding>) {
    if !file_exists("/usr/bin/pacman") {
        return;
    }

    let output = run_cmd_lossy("pacman", &["-Qu"]);

    let count = output.lines().filter(|l| !l.is_empty()).count();
    if count > 0 {
        findings.push(Finding::new(
            "linux-pacman-updates",
            &format!("{} packages can be updated", count),
            Severity::Medium,
            Category::Patches,
        )
        .description(&format!("{} Arch Linux packages have updates available.", count))
        .recommendation("Update: sudo pacman -Syu")
        .metadata("count", count.to_string()));
    }
}

fn audit_pending_reboot(findings: &mut Vec<Finding>) {
    // Check if a reboot is needed (Debian/Ubuntu)
    if file_exists("/var/run/reboot-required") {
        findings.push(Finding::new(
            "linux-reboot-required",
            "System reboot is required",
            Severity::Medium,
            Category::Patches,
        )
        .description("A reboot is required to complete pending updates (kernel or security patches).")
        .recommendation("Reboot the system to apply pending updates"));
    }

    // Check for updated kernel not yet booted (RHEL/Fedora)
    let running_kernel = run_cmd_lossy("uname", &["-r"]);
    let installed_kernels = run_cmd_lossy("rpm", &["-q", "kernel", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}\n"]);

    if !running_kernel.is_empty() && !installed_kernels.is_empty() {
        let running = running_kernel.trim();
        for line in installed_kernels.lines() {
            let installed = line.trim();
            if !installed.is_empty() && installed != running && !installed.contains("not installed") {
                findings.push(Finding::new(
                    "linux-kernel-reboot",
                    "Updated kernel is installed but not running",
                    Severity::Medium,
                    Category::Patches,
                )
                .description(&format!("Running kernel: {}, installed: {}. A reboot is needed to use the updated kernel.", running, installed))
                .metadata("running", running.to_string())
                .metadata("installed", installed.to_string()));
                break;
            }
        }
    }
}
