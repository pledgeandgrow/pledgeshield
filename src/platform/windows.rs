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

fn reg_read(hive: isize, path: &str, value: &str) -> Option<String> {
    use winreg::RegKey;
    RegKey::predef(hive)
        .open_subkey(path)
        .ok()
        .and_then(|key| key.get_value::<String, _>(value).ok())
}

fn reg_read_u32(hive: isize, path: &str, value: &str) -> Option<u32> {
    use winreg::RegKey;
    RegKey::predef(hive)
        .open_subkey(path)
        .ok()
        .and_then(|key| key.get_value::<u32, _>(value).ok())
}

fn reg_subkeys(hive: isize, path: &str) -> Vec<String> {
    use winreg::RegKey;
    RegKey::predef(hive)
        .open_subkey(path)
        .map(|key| key.enum_keys().filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
}

const POLICIES_SYSTEM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

// ─── Config Audit ──────────────────────────────────────────────────────

pub fn audit_config() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_uac(&mut findings);
    audit_smartscreen(&mut findings);
    audit_firewall(&mut findings);
    audit_defender(&mut findings);
    audit_bitlocker(&mut findings);
    audit_telemetry(&mut findings);
    audit_clipboard_history(&mut findings);
    audit_wifi_sense(&mut findings);
    audit_autologin(&mut findings);

    Ok(findings)
}

fn audit_uac(findings: &mut Vec<Finding>) {
    let enable_lua = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        POLICIES_SYSTEM,
        "EnableLUA",
    );
    let consent_prompt = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        POLICIES_SYSTEM,
        "ConsentPromptBehaviorAdmin",
    );

    match enable_lua {
        Some(0) => {
            findings.push(Finding::new(
                "win-uac-disabled",
                "UAC (User Account Control) is disabled",
                Severity::High,
                Category::Config,
            )
            .description("User Account Control is disabled. All programs run with full administrator privileges without consent prompts, making privilege escalation trivial.")
            .recommendation("Enable UAC: Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1")
            .fixable(true)
            .metadata("registry_key", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
            .metadata("registry_value", "EnableLUA")
            .metadata("current_value", "0")
            .metadata("recommended_value", "1"));
        }
        Some(1) => {
            // Check UAC level
            if let Some(level) = consent_prompt {
                if level == 0 {
                    findings.push(Finding::new(
                        "win-uac-no-prompt",
                        "UAC configured to not prompt (elevate without prompting)",
                        Severity::High,
                        Category::Config,
                    )
                    .description("UAC is enabled but configured to elevate without prompting (ConsentPromptBehaviorAdmin=0). This effectively bypasses UAC consent.")
                    .recommendation("Set ConsentPromptBehaviorAdmin to 5 (default) or higher."));
                }
            }
        }
        _ => {
            findings.push(
                Finding::new(
                    "win-uac-unknown",
                    "UAC status could not be determined",
                    Severity::Info,
                    Category::Config,
                )
                .description("Unable to read UAC configuration from registry."),
            );
        }
    }
}

fn audit_smartscreen(findings: &mut Vec<Finding>) {
    let enable_smartscreen = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
    );

    match enable_smartscreen {
        Some(0) => {
            findings.push(Finding::new(
                "win-smartscreen-disabled",
                "SmartScreen is disabled",
                Severity::Medium,
                Category::Config,
            )
            .description("Windows SmartScreen is disabled. Downloaded files and unrecognized apps won't be checked against Microsoft's reputation service.")
            .recommendation("Enable SmartScreen: Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreenEnabled = \"RequireAdmin\""));
        }
        _ => {}
    }

    // Edge SmartScreen
    let edge_smartscreen = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Edge",
        "SmartScreenEnabled",
    );
    if let Some(0) = edge_smartscreen {
        findings.push(Finding::new(
            "win-edge-smartscreen-disabled",
            "Microsoft Edge SmartScreen is disabled",
            Severity::Low,
            Category::Config,
        )
        .description("Edge SmartScreen is disabled via policy, allowing downloads of potentially malicious files without warning."));
    }
}

fn audit_firewall(findings: &mut Vec<Finding>) {
    // Check registry for each profile
    let firewall_key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    for profile_name in &["DomainProfile", "StandardProfile", "PublicProfile"] {
        let path = format!("{}\\{}", firewall_key, profile_name);
        let enabled = reg_read_u32(winreg::enums::HKEY_LOCAL_MACHINE, &path, "EnableFirewall");
        match enabled {
            Some(0) => {
                findings.push(Finding::new(
                    &format!("win-firewall-disabled-{}", profile_name.to_lowercase()),
                    &format!("Windows Firewall is disabled for {}", profile_name),
                    Severity::Critical,
                    Category::Config,
                )
                .description(&format!("The Windows Firewall is disabled for the {} profile. All incoming connections are allowed.", profile_name))
                .recommendation(&format!("Enable firewall: netsh advfirewall set {} state on", profile_name))
                .fixable(true)
                .metadata("profile", *profile_name));
            }
            Some(1) => {} // Enabled, good
            _ => {}       // Can't read or unknown, skip
        }
    }
}

fn audit_defender(findings: &mut Vec<Finding>) {
    // Check if Defender is disabled via registry
    let disable_anti_spyware = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    );

    if let Some(1) = disable_anti_spyware {
        findings.push(Finding::new(
            "win-defender-disabled",
            "Windows Defender is disabled via policy",
            Severity::High,
            Category::Config,
        )
        .description("Windows Defender (anti-spyware) is disabled via Group Policy. Real-time protection against malware is not active.")
        .recommendation("Remove DisableAntiSpyware=1 from HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender")
        .fixable(true));
    }

    // Check real-time protection
    let realtime_disabled = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    );
    if let Some(1) = realtime_disabled {
        findings.push(Finding::new(
            "win-defender-realtime-disabled",
            "Windows Defender real-time monitoring is disabled",
            Severity::High,
            Category::Config,
        )
        .description("Real-time monitoring is disabled. Files are not scanned as they are accessed, allowing malware to execute undetected.")
        .recommendation("Set DisableRealtimeMonitoring=0 or remove the policy key"));
    }

    // Check Defender exclusions
    let exclusions = reg_subkeys(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
    );
    if !exclusions.is_empty() {
        findings.push(Finding::new(
            "win-defender-exclusions",
            &format!("Windows Defender has {} exclusion(s) configured", exclusions.len()),
            Severity::Medium,
            Category::Config,
        )
        .description("Defender exclusions allow files/paths/processes to bypass scanning. Excessive exclusions can be abused by malware to avoid detection.")
        .metadata("exclusion_types", &exclusions.join(", ")));
    }
}

fn audit_bitlocker(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("manage-bde", &["-status"]);

    if output.is_empty() {
        // manage-bde not available or not found
        return;
    }

    let mut found_encrypted = false;
    let mut found_unencrypted = false;

    for line in output.lines() {
        let line = line.trim();
        if line.contains("Protection Status:") {
            if line.contains("Protection On") || line.contains("On") {
                found_encrypted = true;
            } else if line.contains("Protection Off") || line.contains("Off") {
                found_unencrypted = true;
            }
        }
    }

    if found_unencrypted && !found_encrypted {
        findings.push(Finding::new(
            "win-bitlocker-off",
            "BitLocker encryption is not active",
            Severity::High,
            Category::Config,
        )
        .description("BitLocker drive encryption is not protecting the system drive. If the device is stolen, data can be accessed by mounting the drive on another machine.")
        .recommendation("Enable BitLocker: manage-bde -on C: -UsedSpaceOnly"));
    }
}

fn audit_telemetry(findings: &mut Vec<Finding>) {
    let telemetry_level = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "AllowTelemetry",
    );

    match telemetry_level {
        Some(3) => {
            findings.push(Finding::new(
                "win-telemetry-full",
                "Windows telemetry is set to Full (level 3)",
                Severity::Low,
                Category::Config,
            )
            .description("Full telemetry sends extensive diagnostic data to Microsoft, including system activity and app usage patterns.")
            .recommendation("Set AllowTelemetry=1 (Security) or 0 (Diagnostic Off) for reduced data sharing."));
        }
        Some(0) | Some(1) => {} // Good
        Some(_) | None => {
            // No policy set - check commercial data opt-in
            let opt_in = reg_read_u32(
                winreg::enums::HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                "CommercialDataOptIn",
            );
            if let Some(1) = opt_in {
                findings.push(Finding::new(
                    "win-telemetry-commercial-optin",
                    "Commercial telemetry data opt-in is enabled",
                    Severity::Low,
                    Category::Config,
                )
                .description("Commercial data collection is opted in, sending diagnostic data to Microsoft."));
            }
        }
    }
}

fn audit_clipboard_history(findings: &mut Vec<Finding>) {
    let allow_clipboard = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\System",
        "AllowClipboardHistory",
    );

    if let Some(1) = allow_clipboard {
        findings.push(Finding::new(
            "win-clipboard-history-enabled",
            "Clipboard history is enabled",
            Severity::Low,
            Category::Config,
        )
        .description("Clipboard history stores copied text (passwords, tokens, sensitive data) in plaintext, accessible across applications and after reboot.")
        .recommendation("Disable via Group Policy: Set AllowClipboardHistory=0"));
    }
}

fn audit_wifi_sense(findings: &mut Vec<Finding>) {
    let allow_wifi_sense = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config",
        "AutoConnectAllowedOEM",
    );

    if let Some(1) = allow_wifi_sense {
        findings.push(Finding::new(
            "win-wifi-sense-enabled",
            "Wi-Fi Sense is enabled",
            Severity::Medium,
            Category::Config,
        )
        .description("Wi-Fi Sense may share Wi-Fi network credentials with contacts, potentially exposing network access to unintended parties.")
        .recommendation("Disable Wi-Fi Sense: Set AutoConnectAllowedOEM=0"));
    }
}

fn audit_autologin(findings: &mut Vec<Finding>) {
    let auto_admin_logon = reg_read(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
    );

    if let Some(ref val) = auto_admin_logon {
        if val == "1" {
            let username = reg_read(
                winreg::enums::HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "DefaultUserName",
            )
            .unwrap_or_default();

            findings.push(Finding::new(
                "win-autologin-enabled",
                "Automatic login is enabled",
                Severity::Medium,
                Category::Config,
            )
            .description(&format!("Auto-login is configured for user '{}'. The system boots directly to desktop without requiring a password, bypassing physical security.", username))
            .recommendation("Set AutoAdminLogon=0 in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"));
        }
    }
}

pub fn audit_services() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_listening_ports(&mut findings);
    audit_high_priv_services(&mut findings);
    audit_rdp_exposure(&mut findings);
    audit_smb_exposure(&mut findings);
    audit_winrm_exposure(&mut findings);
    audit_ssh_exposure(&mut findings);
    audit_vnc_exposure(&mut findings);

    Ok(findings)
}

fn audit_listening_ports(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);

    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with("TCP") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let local_addr = parts[1];
        let state = parts[3];

        if !state.eq_ignore_ascii_case("LISTENING") {
            continue;
        }

        // Parse address:port
        if let Some(colon_pos) = local_addr.rfind(':') {
            let addr = &local_addr[..colon_pos];
            let port_str = &local_addr[colon_pos + 1..];
            let pid = parts.get(4).unwrap_or(&"?");

            let port: u16 = port_str.parse().unwrap_or(0);
            if port == 0 {
                continue;
            }

            // Check if exposed to public
            let is_public = addr == "0.0.0.0" || addr == "::";
            let is_loopback = addr == "127.0.0.1" || addr == "::1";

            if is_public {
                let service_name = identify_service_by_port(port);
                let severity = if is_dangerous_port(port) {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(Finding::new(
                    &format!("win-port-public-{}", port),
                    &format!("Port {} ({}) exposed to 0.0.0.0 — accessible from any network", port, service_name),
                    severity,
                    Category::Services,
                )
                .description(&format!("Port {} is listening on 0.0.0.0, meaning it accepts connections from any network interface. PID: {}. This may expose the service to the internet.", port, pid))
                .recommendation(&format!("Bind {} to 127.0.0.1 if remote access is not needed, or restrict via firewall rules.", service_name))
                .metadata("port", &port.to_string())
                .metadata("address", addr)
                .metadata("pid", *pid)
                .metadata("service", service_name));
            } else if is_loopback {
                // Good - only listening on localhost
            }
        }
    }
}

fn identify_service_by_port(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 | 8080 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        1433 | 1434 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 | 5901 | 5902 => "VNC",
        5985 | 5986 => "WinRM",
        6379 => "Redis",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

fn is_dangerous_port(port: u16) -> bool {
    matches!(
        port,
        22 | 23 | 3389 | 445 | 5985 | 5986 | 5900 | 5901 | 5902 | 139 | 135
    )
}

fn audit_high_priv_services(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("sc", &["query", "type=", "service", "state=", "active"]);

    let mut service_names = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("SERVICE_NAME:") {
            let name = line.trim_start_matches("SERVICE_NAME:").trim();
            service_names.push(name.to_string());
        }
    }

    // Check services running as LocalSystem
    for name in service_names.iter().take(50) {
        let qc_output = run_cmd_lossy("sc", &["qc", name]);
        for line in qc_output.lines() {
            let line = line.trim();
            if line.contains("SERVICE_START_NAME") {
                if line.contains("LocalSystem") || line.contains("NT AUTHORITY\\SYSTEM") {
                    // Report services running as SYSTEM that are non-standard
                    let is_standard = is_standard_system_service(name);
                    if !is_standard {
                        findings.push(Finding::new(
                            &format!("win-service-system-{}", name),
                            &format!("Non-standard service '{}' runs as LocalSystem", name),
                            Severity::Medium,
                            Category::Services,
                        )
                        .description(&format!("Service '{}' is running with LocalSystem privileges. If compromised, it provides full system access.", name))
                        .metadata("service", name)
                        .metadata("account", "LocalSystem"));
                    }
                }
            }
        }
    }
}

fn is_standard_system_service(name: &str) -> bool {
    const STANDARD: &[&str] = &[
        "Audiosrv",
        "AudioEndpointBuilder",
        "BFE",
        "BITS",
        "BrokerInfrastructure",
        "CryptSvc",
        "DcomLaunch",
        "Dhcp",
        "Dnscache",
        "DPS",
        "EventLog",
        "EventSystem",
        "FontCache",
        "gpsvc",
        "LanmanServer",
        "LanmanWorkstation",
        "LSM",
        "MpsSvc",
        "Netman",
        "nsi",
        "PlugPlay",
        "Power",
        "ProfSvc",
        "RpcSs",
        "RpcEptMapper",
        "SamSs",
        "Schedule",
        "SENS",
        "SessionEnv",
        "Spooler",
        "SystemEventsBroker",
        "Themes",
        "TrkWks",
        "TrustedInstaller",
        "UserManager",
        "UsoSvc",
        "Winmgmt",
        "WinDefend",
        "wuauserv",
        "WpnService",
        "wuauserv",
        "StateRepository",
        "ShellHWDetection",
        "DoSvc",
        "DiagTrack",
        "WSearch",
        "SysMain",
        "WdiSystemHost",
    ];
    STANDARD.contains(&name)
}

fn audit_rdp_exposure(findings: &mut Vec<Finding>) {
    // Check if RDP is enabled
    let rdp_enabled = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
    );

    if let Some(0) = rdp_enabled {
        // RDP is enabled - check NLA requirement
        let nla_required = reg_read_u32(
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication",
        );

        if let Some(0) = nla_required {
            findings.push(Finding::new(
                "win-rdp-nla-disabled",
                "RDP is enabled without Network Level Authentication (NLA)",
                Severity::High,
                Category::Services,
            )
            .description("RDP is enabled but NLA is not required. Without NLA, the server is vulnerable to credential relay attacks and brute-force attempts before authentication.")
            .recommendation("Enable NLA: Set UserAuthentication=1 in Terminal Server\\WinStations\\RDP-Tcp")
            .fixable(true));
        }

        // Check if RDP port is exposed
        let netstat = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);
        for line in netstat.lines() {
            let line = line.trim();
            if line.contains("0.0.0.0:3389") && line.contains("LISTENING") {
                findings.push(Finding::new(
                    "win-rdp-public",
                    "RDP (port 3389) is exposed to 0.0.0.0",
                    Severity::Critical,
                    Category::Services,
                )
                .description("RDP is listening on all interfaces (0.0.0.0:3389). This exposes the remote desktop service to any network, including the internet if not firewalled.")
                .recommendation("Restrict RDP to specific IPs via firewall, or use a VPN. At minimum, enable NLA."));
                break;
            }
        }
    }
}

fn audit_smb_exposure(findings: &mut Vec<Finding>) {
    let netstat = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);
    for line in netstat.lines() {
        let line = line.trim();
        if (line.contains("0.0.0.0:445") || line.contains("0.0.0.0:139"))
            && line.contains("LISTENING")
        {
            findings.push(Finding::new(
                "win-smb-public",
                "SMB (port 445/139) is exposed to 0.0.0.0",
                Severity::High,
                Category::Services,
            )
            .description("SMB is listening on all interfaces. If connected to untrusted networks, file sharing services may be accessible remotely.")
            .recommendation("Restrict SMB access via firewall rules to trusted networks only."));
            break;
        }
    }
}

fn audit_winrm_exposure(findings: &mut Vec<Finding>) {
    let netstat = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);
    for line in netstat.lines() {
        let line = line.trim();
        if (line.contains("0.0.0.0:5985") || line.contains("0.0.0.0:5986"))
            && line.contains("LISTENING")
        {
            findings.push(Finding::new(
                "win-winrm-public",
                "WinRM (port 5985/5986) is exposed to 0.0.0.0",
                Severity::High,
                Category::Services,
            )
            .description("Windows Remote Management is listening on all interfaces, allowing remote command execution from any network.")
            .recommendation("Restrict WinRM to trusted IPs via firewall or disable if not needed."));
            break;
        }
    }
}

fn audit_ssh_exposure(findings: &mut Vec<Finding>) {
    let netstat = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);
    for line in netstat.lines() {
        let line = line.trim();
        if line.contains("0.0.0.0:22") && line.contains("LISTENING") {
            findings.push(Finding::new(
                "win-ssh-public",
                "SSH (port 22) is exposed to 0.0.0.0",
                Severity::Critical,
                Category::Services,
            )
            .description("SSH server is listening on all interfaces. If exposed to the internet, it is a common target for brute-force attacks.")
            .recommendation("Restrict SSH to specific IPs, use key-based auth, and consider changing the default port."));
            break;
        }
    }
}

fn audit_vnc_exposure(findings: &mut Vec<Finding>) {
    let netstat = run_cmd_lossy("netstat", &["-ano", "-p", "TCP"]);
    for line in netstat.lines() {
        let line = line.trim();
        if (line.contains("0.0.0.0:5900") || line.contains("0.0.0.0:5901"))
            && line.contains("LISTENING")
        {
            findings.push(Finding::new(
                "win-vnc-public",
                "VNC (port 5900/5901) is exposed to 0.0.0.0",
                Severity::Critical,
                Category::Services,
            )
            .description("VNC remote desktop is listening on all interfaces. VNC often transmits credentials insecurely and is a common attack target.")
            .recommendation("Restrict VNC to localhost and use SSH tunneling for remote access."));
            break;
        }
    }
}

pub fn audit_privileges() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_local_users(&mut findings);
    audit_admin_group(&mut findings);
    audit_guest_account(&mut findings);
    audit_password_policy(&mut findings);

    Ok(findings)
}

fn audit_local_users(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("net", &["user"]);

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("User accounts")
            || line.starts_with("The command")
            || line.starts_with("---")
        {
            continue;
        }

        // Each line may contain multiple usernames separated by spaces
        for name in line.split_whitespace() {
            // Check if account is disabled/expired
            let user_info = run_cmd_lossy("net", &["user", name]);

            let mut is_admin = false;
            let mut never_expires = false;
            let mut active = true;

            for info_line in user_info.lines() {
                let info_line = info_line.trim();
                if info_line.contains("Account active") {
                    if info_line.contains("No") {
                        active = false;
                    }
                }
                if info_line.contains("Account expires") && info_line.contains("Never") {
                    never_expires = true;
                }
                if info_line.contains("Local Group Memberships")
                    && info_line.contains("Administrators")
                {
                    is_admin = true;
                }
            }

            if active && is_admin {
                findings.push(
                    Finding::new(
                        &format!("win-user-admin-{}", name),
                        &format!("User '{}' has administrator privileges", name),
                        Severity::Info,
                        Category::Privileges,
                    )
                    .description(&format!(
                        "User '{}' is a member of the Administrators group.",
                        name
                    ))
                    .metadata("user", name)
                    .metadata("group", "Administrators"),
                );
            }

            if never_expires && active {
                findings.push(Finding::new(
                    &format!("win-user-no-expire-{}", name),
                    &format!("User '{}' has 'Password never expires' set", name),
                    Severity::Low,
                    Category::Privileges,
                )
                .description(&format!("User '{}' password is set to never expire, which may allow compromised credentials to remain valid indefinitely.", name))
                .metadata("user", name));
            }
        }
    }
}

fn audit_admin_group(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("net", &["localgroup", "Administrators"]);

    let mut members = Vec::new();
    let mut in_members = false;

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Members") {
            in_members = true;
            continue;
        }
        if in_members {
            if line.is_empty() || line.starts_with("The command") || line.starts_with("---") {
                in_members = false;
                continue;
            }
            members.push(line.to_string());
        }
    }

    if members.is_empty() {
        findings.push(
            Finding::new(
                "win-admin-group-empty",
                "Administrators group has no visible members",
                Severity::Info,
                Category::Privileges,
            )
            .description("Could not enumerate Administrators group members or the group is empty."),
        );
    } else if members.len() > 3 {
        findings.push(Finding::new(
            "win-admin-group-large",
            &format!("Administrators group has {} members", members.len()),
            Severity::Medium,
            Category::Privileges,
        )
        .description(&format!("The Administrators group has {} members: {}. Each admin account is an attack surface for privilege escalation.", members.len(), members.join(", ")))
        .metadata("members", &members.join(", ")));
    }
}

fn audit_guest_account(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("net", &["user", "Guest"]);

    for line in output.lines() {
        let line = line.trim();
        if line.contains("Account active") && line.contains("Yes") {
            findings.push(Finding::new(
                "win-guest-enabled",
                "Guest account is enabled",
                Severity::High,
                Category::Privileges,
            )
            .description("The Guest account is active. It provides unauthenticated access to the system and should be disabled.")
            .recommendation("Disable Guest: net user Guest /active:no")
            .fixable(true));
            break;
        }
    }
}

fn audit_password_policy(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("net", &["accounts"]);

    let mut min_len: Option<u32> = None;
    let mut max_age: Option<u32> = None;
    let mut lockout_threshold: Option<u32> = None;

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Minimum password length") {
            min_len = line.split_whitespace().last().and_then(|s| s.parse().ok());
        }
        if line.starts_with("Maximum password age") {
            max_age = line.split_whitespace().last().and_then(|s| s.parse().ok());
        }
        if line.starts_with("Lockout threshold") {
            lockout_threshold = line.split_whitespace().last().and_then(|s| s.parse().ok());
        }
    }

    if let Some(len) = min_len {
        if len < 12 {
            findings.push(Finding::new(
                "win-password-length-weak",
                &format!("Minimum password length is {} (recommended: 12+)", len),
                Severity::Medium,
                Category::Privileges,
            )
            .description(&format!("Minimum password length is only {} characters. Short passwords are vulnerable to brute-force attacks.", len))
            .recommendation("Set minimum password length to at least 12: net accounts /minpwlen:12")
            .fixable(true)
            .metadata("current_min_length", &len.to_string())
            .metadata("recommended_min_length", "12"));
        }
    }

    if let Some(threshold) = lockout_threshold {
        if threshold == 0 {
            findings.push(Finding::new(
                "win-lockout-disabled",
                "Account lockout threshold is 0 (never locks out)",
                Severity::High,
                Category::Privileges,
            )
            .description("Account lockout is disabled. Attackers can attempt unlimited password guesses without being locked out.")
            .recommendation("Set lockout threshold: net accounts /lockoutthreshold:5")
            .fixable(true)
            .metadata("current_threshold", "0")
            .metadata("recommended_threshold", "5"));
        }
    }

    if let Some(age) = max_age {
        if age == 0 || age > 90 {
            findings.push(Finding::new(
                "win-password-max-age",
                &format!("Maximum password age is {} days", if age == 0 { "unlimited".to_string() } else { age.to_string() }),
                Severity::Low,
                Category::Privileges,
            )
            .description("Passwords never expire or expire after a very long period. Regular password rotation reduces the window for compromised credentials."));
        }
    }
}

pub fn audit_persistence() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_run_keys(&mut findings);
    audit_startup_folder(&mut findings);
    audit_scheduled_tasks(&mut findings);
    audit_suspicious_services(&mut findings);

    Ok(findings)
}

fn audit_run_keys(findings: &mut Vec<Finding>) {
    const RUN_KEYS: &[(isize, &str, &str)] = &[
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM",
        ),
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU",
        ),
        (
            winreg::enums::HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU",
        ),
        (
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM WOW64",
        ),
    ];

    for (hive, path, label) in RUN_KEYS {
        use winreg::RegKey;
        if let Ok(key) = RegKey::predef(*hive).open_subkey(path) {
            for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
                let val_str = value.to_string();
                let is_suspicious = is_suspicious_persistence_path(&val_str);

                if is_suspicious {
                    findings.push(Finding::new(
                        &format!("win-runkey-suspicious-{}-{}", label.replace(' ', ""), name),
                        &format!("Suspicious startup entry: {} ({}\\Run)", name, label),
                        Severity::High,
                        Category::Persistence,
                    )
                    .description(&format!("Registry Run key entry '{}' points to: {}. This path has characteristics of malicious persistence (temp directory, script, or unusual executable).", name, val_str))
                    .metadata("registry_path", &format!("{}\\{}", label, path))
                    .metadata("entry_name", &name)
                    .metadata("entry_value", &val_str));
                } else {
                    findings.push(
                        Finding::new(
                            &format!("win-runkey-{}-{}", label.replace(' ', ""), name),
                            &format!("Startup entry: {} ({}\\Run)", name, label),
                            Severity::Info,
                            Category::Persistence,
                        )
                        .description(&format!(
                            "Program '{}' starts automatically via registry: {}",
                            name, val_str
                        ))
                        .metadata("registry_path", &format!("{}\\{}", label, path))
                        .metadata("entry_name", &name)
                        .metadata("entry_value", &val_str),
                    );
                }
            }
        }
    }
}

fn is_suspicious_persistence_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("wscript")
        || lower.contains("cscript")
        || lower.contains("rundll32")
        || lower.contains("regsvr32")
        || lower.contains("mshta")
        || lower.contains("bitsadmin")
        || lower.contains(".bat")
        || lower.contains(".vbs")
        || lower.contains(".ps1")
}

fn audit_startup_folder(findings: &mut Vec<Finding>) {
    let startup_paths = [
        dirs::data_dir().map(|d| d.join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
        dirs::config_dir().map(|d| d.join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ];

    for path_opt in &startup_paths {
        if let Some(path) = path_opt {
            if path.exists() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let file_path = entry.path();
                        let path_str = file_path.to_string_lossy().to_string();

                        let is_suspicious = is_suspicious_persistence_path(&path_str);

                        if is_suspicious {
                            findings.push(Finding::new(
                                &format!("win-startup-suspicious-{}", file_name),
                                &format!("Suspicious startup folder entry: {}", file_name),
                                Severity::High,
                                Category::Persistence,
                            )
                            .description(&format!("File '{}' in the Startup folder has suspicious characteristics.", path_str))
                            .metadata("path", &path_str));
                        } else {
                            findings.push(
                                Finding::new(
                                    &format!("win-startup-{}", file_name),
                                    &format!("Startup folder entry: {}", file_name),
                                    Severity::Info,
                                    Category::Persistence,
                                )
                                .metadata("path", &path_str),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn audit_scheduled_tasks(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("schtasks", &["/query", "/fo", "CSV", "/v"]);

    // Skip header line
    for line in output.lines().skip(1) {
        // CSV format: "TaskName","Next Run Time","Status","Logon Mode","Last Run Time",...
        // We're interested in TaskName and the task to run
        let fields: Vec<&str> = line.split("\",\"").collect();
        if fields.len() < 8 {
            continue;
        }

        let task_name = fields[0].trim_start_matches('"');
        let task_to_run = fields.get(7).unwrap_or(&"").trim_end_matches('"');

        if is_suspicious_persistence_path(task_to_run) {
            findings.push(Finding::new(
                &format!("win-schtask-suspicious-{}", task_name.replace('\\', "_")),
                &format!("Suspicious scheduled task: {}", task_name),
                Severity::High,
                Category::Persistence,
            )
            .description(&format!("Scheduled task '{}' runs: {}. This command has characteristics of malicious persistence.", task_name, task_to_run))
            .metadata("task_name", task_name)
            .metadata("command", task_to_run));
        }
    }
}

fn audit_suspicious_services(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("sc", &["query", "type=", "service", "state=", "active"]);

    let mut service_names = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("SERVICE_NAME:") {
            let name = line.trim_start_matches("SERVICE_NAME:").trim();
            service_names.push(name.to_string());
        }
    }

    for name in service_names.iter().take(50) {
        let qc_output = run_cmd_lossy("sc", &["qc", name]);

        for line in qc_output.lines() {
            let line = line.trim();
            if line.contains("BINARY_PATH_NAME") {
                let path = line
                    .trim_start_matches("BINARY_PATH_NAME")
                    .trim_start_matches(':')
                    .trim();

                if is_suspicious_persistence_path(path) {
                    findings.push(Finding::new(
                        &format!("win-service-suspicious-{}", name),
                        &format!("Service '{}' has a suspicious binary path", name),
                        Severity::High,
                        Category::Persistence,
                    )
                    .description(&format!("Service '{}' binary path: {}. This path has characteristics of malicious persistence.", name, path))
                    .metadata("service", name)
                    .metadata("binary_path", path));
                }
            }
        }
    }
}

pub fn audit_credentials() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_stored_credentials(&mut findings);
    audit_browser_passwords(&mut findings);
    audit_wifi_passwords(&mut findings);
    audit_ssh_keys(&mut findings);
    audit_rdp_saved_sessions(&mut findings);

    Ok(findings)
}

fn audit_stored_credentials(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("cmdkey", &["/list"]);

    let mut cred_count = 0;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Target:") {
            cred_count += 1;
        }
    }

    if cred_count > 0 {
        findings.push(Finding::new(
            "win-cred-manager",
            &format!("{} stored credential(s) in Credential Manager", cred_count),
            Severity::Medium,
            Category::Credentials,
        )
        .description(&format!("Windows Credential Manager contains {} stored credential(s). These may include saved passwords for network resources, RDP sessions, or web services.", cred_count))
        .recommendation("Review stored credentials: cmdkey /list. Remove unnecessary: cmdkey /delete:<target>")
        .metadata("count", &cred_count.to_string()));
    }
}

fn audit_browser_passwords(findings: &mut Vec<Finding>) {
    // Chrome
    let chrome_login_db =
        dirs::data_dir().map(|d| d.join(r"Google\Chrome\User Data\Default\Login Data"));
    if let Some(path) = &chrome_login_db {
        if path.exists() {
            findings.push(Finding::new(
                "win-browser-chrome-passwords",
                "Google Chrome has saved passwords",
                Severity::Medium,
                Category::Credentials,
            )
            .description("Chrome's Login Data database exists, indicating saved passwords. These are encrypted with DPAPI but can be decrypted by any process running as the user.")
            .metadata("browser", "Chrome")
            .metadata("path", path.to_string_lossy().to_string()));
        }
    }

    // Edge
    let edge_login_db =
        dirs::data_dir().map(|d| d.join(r"Microsoft\Edge\User Data\Default\Login Data"));
    if let Some(path) = &edge_login_db {
        if path.exists() {
            findings.push(Finding::new(
                "win-browser-edge-passwords",
                "Microsoft Edge has saved passwords",
                Severity::Medium,
                Category::Credentials,
            )
            .description("Edge's Login Data database exists, indicating saved passwords. These are encrypted with DPAPI but can be decrypted by any process running as the user.")
            .metadata("browser", "Edge")
            .metadata("path", path.to_string_lossy().to_string()));
        }
    }

    // Firefox
    if let Some(app_data) = dirs::data_dir() {
        let firefox_dir = app_data.join(r"Mozilla\Firefox\Profiles");
        if firefox_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&firefox_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let profile_dir = entry.path();
                    let logins_json = profile_dir.join("logins.json");
                    if logins_json.exists() {
                        findings.push(Finding::new(
                            "win-browser-firefox-passwords",
                            "Firefox has saved passwords",
                            Severity::Medium,
                            Category::Credentials,
                        )
                        .description("Firefox logins.json exists, indicating saved passwords. These are encrypted but can be extracted with access to the profile.")
                        .metadata("browser", "Firefox")
                        .metadata("path", logins_json.to_string_lossy().to_string()));
                        break;
                    }
                }
            }
        }
    }

    // Brave
    let brave_login_db = dirs::data_dir()
        .map(|d| d.join(r"BraveSoftware\Brave-Browser\User Data\Default\Login Data"));
    if let Some(path) = &brave_login_db {
        if path.exists() {
            findings.push(
                Finding::new(
                    "win-browser-brave-passwords",
                    "Brave browser has saved passwords",
                    Severity::Medium,
                    Category::Credentials,
                )
                .description("Brave's Login Data database exists, indicating saved passwords.")
                .metadata("browser", "Brave")
                .metadata("path", path.to_string_lossy().to_string()),
            );
        }
    }
}

fn audit_wifi_passwords(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("netsh", &["wlan", "show", "profiles"]);

    let mut profiles = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.contains("All User Profile") {
            if let Some(pos) = line.find(':') {
                let profile_name = line[pos + 1..].trim();
                profiles.push(profile_name.to_string());
            }
        }
    }

    for profile in &profiles {
        let key_output = run_cmd_lossy(
            "netsh",
            &[
                "wlan",
                "show",
                "profile",
                &format!("name={}", profile),
                "key=clear",
            ],
        );

        for line in key_output.lines() {
            let line = line.trim();
            if line.contains("Key Content") {
                if let Some(pos) = line.find(':') {
                    let key_content = line[pos + 1..].trim();
                    if !key_content.is_empty() {
                        findings.push(Finding::new(
                            &format!("win-wifi-password-{}", profile),
                            &format!("Wi-Fi profile '{}' has stored password", profile),
                            Severity::Low,
                            Category::Credentials,
                        )
                        .description(&format!("Wi-Fi profile '{}' stores the password in plaintext (accessible via 'netsh wlan show profile key=clear').", profile))
                        .metadata("ssid", profile)
                        .metadata("has_password", "true"));
                    }
                }
                break;
            }
        }
    }
}

fn audit_ssh_keys(findings: &mut Vec<Finding>) {
    let ssh_dir = dirs::home_dir().map(|h| h.join(".ssh"));

    if let Some(ssh_dir) = &ssh_dir {
        if ssh_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(ssh_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    let file_name = entry.file_name().to_string_lossy().to_string();

                    // Check private keys (no .pub extension)
                    if !file_name.ends_with(".pub")
                        && !file_name.starts_with("known_hosts")
                        && !file_name.starts_with("config")
                    {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let is_private = content.contains("PRIVATE KEY");
                            if is_private {
                                // Check if it has a passphrase by looking for "ENCRYPTED"
                                let is_encrypted = content.contains("ENCRYPTED");

                                if !is_encrypted {
                                    findings.push(
                                        Finding::new(
                                            &format!("win-ssh-key-nopass-{}", file_name),
                                            &format!(
                                                "SSH private key '{}' has no passphrase",
                                                file_name
                                            ),
                                            Severity::High,
                                            Category::Credentials,
                                        )
                                        .metadata("key_file", &file_name),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn audit_rdp_saved_sessions(findings: &mut Vec<Finding>) {
    let rdp_files = dirs::document_dir().map(|d| d.join("Default.rdp"));

    if let Some(rdp_path) = &rdp_files {
        if rdp_path.exists() {
            findings.push(Finding::new(
                "win-rdp-saved-session",
                "Saved RDP session exists (Default.rdp)",
                Severity::Low,
                Category::Credentials,
            )
            .description("A saved RDP session file exists. This may contain server addresses and potentially saved credentials for remote desktop connections.")
            .metadata("file", rdp_path.to_string_lossy().to_string()));
        }
    }

    // Check registry for saved RDP servers
    let saved_servers = reg_subkeys(
        winreg::enums::HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Terminal Server Client\Servers",
    );

    if !saved_servers.is_empty() {
        findings.push(
            Finding::new(
                "win-rdp-saved-servers",
                &format!("{} saved RDP server(s) in registry", saved_servers.len()),
                Severity::Info,
                Category::Credentials,
            )
            .description(&format!(
                "RDP client has saved connections to: {}",
                saved_servers.join(", ")
            ))
            .metadata("servers", &saved_servers.join(", ")),
        );
    }
}

pub fn audit_shares() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_shares_list(&mut findings);
    audit_smbv1(&mut findings);
    audit_smb_signing(&mut findings);
    audit_rdp_config(&mut findings);

    Ok(findings)
}

fn audit_shares_list(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("net", &["share"]);

    let mut in_shares = false;
    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("Share name") || line.starts_with("---") {
            in_shares = true;
            continue;
        }
        if line.starts_with("The command") {
            in_shares = false;
            continue;
        }

        if !in_shares || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let share_name = parts[0];
        let resource = parts.get(1).unwrap_or(&"?");

        // Check for default admin shares
        if share_name.ends_with('$')
            && (share_name == "C$"
                || share_name == "D$"
                || share_name == "ADMIN$"
                || share_name == "IPC$")
        {
            findings.push(Finding::new(
                &format!("win-admin-share-{}", share_name),
                &format!("Default admin share '{}' is active", share_name),
                Severity::Medium,
                Category::Shares,
            )
            .description(&format!("Administrative share '{}' is active at {}. These shares allow remote administrative access and are accessible to anyone with admin credentials.", share_name, resource))
            .recommendation(&format!("Disable admin shares: net share {} /delete", share_name))
            .fixable(true)
            .metadata("share", share_name)
            .metadata("resource", *resource));
        } else if !share_name.ends_with('$') {
            // Regular share - check if accessible to Everyone
            let share_info = run_cmd_lossy("net", &["share", share_name]);

            let mut everyone_access = false;
            for info_line in share_info.lines() {
                let info_line = info_line.trim();
                if info_line.contains("Everyone")
                    && (info_line.contains("READ")
                        || info_line.contains("FULL")
                        || info_line.contains("CHANGE"))
                {
                    everyone_access = true;
                }
            }

            if everyone_access {
                findings.push(Finding::new(
                    &format!("win-share-everyone-{}", share_name),
                    &format!("Share '{}' is accessible to Everyone", share_name),
                    Severity::High,
                    Category::Shares,
                )
                .description(&format!("Share '{}' at {} is accessible by the 'Everyone' group, meaning any authenticated or guest user can access it.", share_name, resource))
                .recommendation(&format!("Remove Everyone from share permissions: net share {} /grant:Administrators,FULL", share_name))
                .fixable(true)
                .metadata("share", share_name)
                .metadata("resource", *resource)
                .metadata("access", "Everyone"));
            } else {
                findings.push(
                    Finding::new(
                        &format!("win-share-{}", share_name),
                        &format!("Share '{}' is active", share_name),
                        Severity::Info,
                        Category::Shares,
                    )
                    .metadata("share", share_name)
                    .metadata("resource", *resource),
                );
            }
        }
    }
}

fn audit_smbv1(findings: &mut Vec<Finding>) {
    // Check if SMBv1 is enabled via registry
    let smb1_enabled = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
    );

    match smb1_enabled {
        Some(1) | None => {
            // If None, SMB1 might be enabled by default on older Windows
            // Check via PowerShell
            let ps_output = run_cmd_lossy(
                "powershell",
                &[
                    "-Command",
                    "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State",
                ],
            );
            if ps_output.to_lowercase().contains("enabled") || smb1_enabled == Some(1) {
                findings.push(Finding::new(
                    "win-smbv1-enabled",
                    "SMBv1 protocol is enabled",
                    Severity::Critical,
                    Category::Shares,
                )
                .description("SMBv1 is enabled. This protocol is vulnerable to EternalBlue (MS17-010) and was used by WannaCry and NotPetya. It should be disabled immediately.")
                .recommendation("Disable SMBv1: Set SMB1=0 in LanmanServer\\Parameters, or: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
                .fixable(true)
                .metadata("protocol", "SMBv1"));
            }
        }
        Some(0) => {} // Disabled, good
        Some(_) => {}
    }
}

fn audit_smb_signing(findings: &mut Vec<Finding>) {
    let require_signing = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "RequireSecuritySignature",
    );

    if let Some(0) = require_signing {
        findings.push(Finding::new(
            "win-smb-signing-not-required",
            "SMB signing is not required by server",
            Severity::Medium,
            Category::Shares,
        )
        .description("SMB packet signing is not required, allowing potential SMB relay attacks on the network.")
        .recommendation("Set RequireSecuritySignature=1 in LanmanServer\\Parameters"));
    }

    let enable_signing = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "EnableSecuritySignature",
    );
    if let Some(0) = enable_signing {
        findings.push(
            Finding::new(
                "win-smb-client-signing-disabled",
                "SMB client signing is disabled",
                Severity::Low,
                Category::Shares,
            )
            .description(
                "SMB client-side signing is disabled, which may allow tampering with SMB traffic.",
            ),
        );
    }
}

fn audit_rdp_config(findings: &mut Vec<Finding>) {
    // Check RDP encryption level
    let encryption_level = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "MinEncryptionLevel",
    );

    if let Some(level) = encryption_level {
        // 1=Low, 2=Client Compatible, 3=High, 4=FIPS
        if level <= 1 {
            findings.push(Finding::new(
                "win-rdp-encryption-low",
                "RDP encryption level is set to Low",
                Severity::High,
                Category::Shares,
            )
            .description("RDP encryption is set to Low, which only encrypts client-to-server traffic with weak encryption. This may allow interception of session data.")
            .recommendation("Set MinEncryptionLevel=3 (High) or 4 (FIPS) in Terminal Server\\WinStations\\RDP-Tcp"));
        }
    }

    // Check if RDP allows connections from any version
    let security_layer = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "SecurityLayer",
    );

    if let Some(0) = security_layer {
        findings.push(Finding::new(
            "win-rdp-security-rdp",
            "RDP Security Layer is set to RDP Security (not NLA/TLS)",
            Severity::Medium,
            Category::Shares,
        )
        .description("RDP is using the legacy RDP Security Layer instead of NLA or TLS. This is vulnerable to man-in-the-middle attacks.")
        .recommendation("Set SecurityLayer=1 (NLA) or 2 (TLS) in Terminal Server\\WinStations\\RDP-Tcp"));
    }
}

pub fn audit_patches() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut findings = Vec::new();

    audit_windows_update(&mut findings);
    audit_pending_reboot(&mut findings);
    audit_winget_updates(&mut findings);
    audit_last_update_date(&mut findings);

    Ok(findings)
}

fn audit_windows_update(findings: &mut Vec<Finding>) {
    // Use PowerShell to query Windows Update
    let ps_script = r#"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and Type='Software'")
Write-Output "Count: $($result.Updates.Count)"
foreach ($update in $result.Updates) {
    Write-Output "Title: $($update.Title)"
    Write-Output "Severity: $($update.MsrcSeverity)"
    Write-Output "---"
}
"#;

    let output = run_cmd_lossy("powershell", &["-Command", ps_script]);

    let mut pending_count = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    let mut current_title = String::new();
    let mut current_severity;

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Count:") {
            if let Some(count) = line
                .split(':')
                .nth(1)
                .and_then(|s| s.trim().parse::<usize>().ok())
            {
                pending_count = count;
            }
        }
        if line.starts_with("Title:") {
            current_title = line.trim_start_matches("Title:").trim().to_string();
        }
        if line.starts_with("Severity:") {
            current_severity = line.trim_start_matches("Severity:").trim().to_string();

            if !current_title.is_empty() {
                pending_count += 1;
                let sev = current_severity.to_lowercase();
                if sev.contains("critical") {
                    critical_count += 1;
                    findings.push(Finding::new(
                        &format!("win-update-critical-{}", pending_count),
                        &format!("Critical update pending: {}", current_title),
                        Severity::Critical,
                        Category::Patches,
                    )
                    .description(&format!("A critical security update is pending installation: {}", current_title))
                    .recommendation("Install updates immediately: Open Windows Update and install all pending updates."));
                } else if sev.contains("important") || sev.contains("high") {
                    high_count += 1;
                    findings.push(
                        Finding::new(
                            &format!("win-update-high-{}", pending_count),
                            &format!("Important update pending: {}", current_title),
                            Severity::High,
                            Category::Patches,
                        )
                        .description(&format!(
                            "An important security update is pending: {}",
                            current_title
                        ))
                        .recommendation("Install pending updates via Windows Update."),
                    );
                }
            }
            current_title.clear();
            current_severity.clear();
        }
    }

    if pending_count > 0 && critical_count == 0 && high_count == 0 {
        findings.push(Finding::new(
            "win-updates-pending",
            &format!("{} pending Windows update(s)", pending_count),
            Severity::Medium,
            Category::Patches,
        )
        .description(&format!("There are {} pending Windows updates. Keeping the system updated is critical for security.", pending_count))
        .recommendation("Install updates: Open Windows Update or run 'winget upgrade --all'"));
    }

    if pending_count == 0 && output.contains("Count:") {
        // Updates are up to date
        findings.push(
            Finding::new(
                "win-updates-current",
                "Windows is up to date",
                Severity::Info,
                Category::Patches,
            )
            .description("No pending Windows updates found."),
        );
    }
}

fn audit_pending_reboot(findings: &mut Vec<Finding>) {
    // Check registry for pending reboot
    // Check if PendingFileRenameOperations exists
    use winreg::RegKey;
    let key = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager");

    if let Ok(key) = key {
        let has_pending: Option<Vec<String>> = key.get_value("PendingFileRenameOperations").ok();
        if has_pending.is_some() {
            findings.push(Finding::new(
                "win-pending-reboot",
                "System has a pending reboot for installed updates",
                Severity::Medium,
                Category::Patches,
            )
            .description("A reboot is pending to complete installation of updates. Security patches are not fully effective until the system is restarted.")
            .recommendation("Restart the computer to complete pending update installations."));
        }
    }

    // Also check Windows Update pending reboot
    let update_pending = reg_read_u32(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "Reserved",
    );
    if update_pending.is_some() {
        findings.push(
            Finding::new(
                "win-update-reboot-required",
                "Windows Update requires a reboot",
                Severity::Medium,
                Category::Patches,
            )
            .description(
                "Windows Update has installed updates that require a reboot to take effect.",
            )
            .recommendation("Restart the computer as soon as possible."),
        );
    }
}

fn audit_winget_updates(findings: &mut Vec<Finding>) {
    let output = run_cmd_lossy("winget", &["upgrade"]);

    if output.is_empty() || output.contains("No installed package") {
        return;
    }

    let mut count = 0;
    let mut in_upgrades = false;

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Name") && line.contains("Version") {
            in_upgrades = true;
            continue;
        }
        if line.starts_with("---") {
            continue;
        }
        if in_upgrades && !line.is_empty() && !line.starts_with("winget") {
            count += 1;
        }
    }

    if count > 0 {
        findings.push(Finding::new(
            "win-winget-updates",
            &format!("{} third-party app(s) have updates available", count),
            Severity::Low,
            Category::Patches,
        )
        .description(&format!("{} installed application(s) have updates available via winget. Outdated apps may contain security vulnerabilities.", count))
        .recommendation("Update all apps: winget upgrade --all")
        .metadata("count", &count.to_string()));
    }
}

fn audit_last_update_date(findings: &mut Vec<Finding>) {
    let ps_script = r#"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$count = $searcher.GetTotalHistoryCount()
if ($count -gt 0) {
    $history = $searcher.QueryHistory(0, 1)
    $lastDate = $history[0].Date
    Write-Output "LastUpdateDate: $($lastDate.ToString('yyyy-MM-dd'))"
} else {
    Write-Output "LastUpdateDate: Never"
}
"#;

    let output = run_cmd_lossy("powershell", &["-Command", ps_script]);

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("LastUpdateDate:") {
            let date_str = line.trim_start_matches("LastUpdateDate:").trim();

            if date_str == "Never" {
                findings.push(Finding::new(
                    "win-never-updated",
                    "Windows has never installed any updates",
                    Severity::High,
                    Category::Patches,
                )
                .description("No Windows Update history found. The system has never been updated, leaving it vulnerable to all known security issues."));
            } else {
                // Parse date and check if it's old
                if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    let now = chrono::Local::now().date_naive();
                    let days_since = (now - date).num_days();

                    if days_since > 60 {
                        findings.push(Finding::new(
                            "win-updates-stale",
                            &format!("Last Windows update was {} days ago", days_since),
                            Severity::Medium,
                            Category::Patches,
                        )
                        .description(&format!("The last Windows update was installed on {}, over {} days ago. Regular updates are critical for security.", date_str, days_since))
                        .recommendation("Check for updates: Open Windows Update or run 'winget upgrade --all'")
                        .metadata("last_update", date_str)
                        .metadata("days_since", &days_since.to_string()));
                    }
                }
            }
            break;
        }
    }
}
