pub mod linux_fix;
pub mod macos_fix;
pub mod registry_fix;
pub mod service_fix;
pub mod share_fix;

use crate::models::ScanResult;
use std::io::{self, BufRead, Write};

/// Run interactive fix mode: iterate through fixable findings and prompt the user.
pub fn run_interactive_fix(result: &ScanResult) {
    let fixable: Vec<_> = result.findings.iter().filter(|f| f.fixable).collect();

    if fixable.is_empty() {
        println!("\nNo fixable findings detected.");
        return;
    }

    println!("\n── Interactive Fix Mode ────────────────────────");
    println!("{} fixable findings found.\n", fixable.len());

    let stdin = io::stdin();
    let mut auto_fix = false;

    for finding in &fixable {
        if auto_fix {
            apply_fix(finding);
            continue;
        }

        print!(
            "  [{}] {} — [F]ix / [S]kip / [A]uto-fix all: ",
            finding.severity, finding.title
        );
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break;
        }

        match line.trim().to_lowercase().as_str() {
            "f" | "fix" => apply_fix(finding),
            "a" | "auto" => {
                auto_fix = true;
                apply_fix(finding);
            }
            _ => {} // skip
        }
    }

    println!("\nFix mode complete.");
}

fn apply_fix(finding: &crate::models::Finding) {
    let id = &finding.id;

    // Dispatch based on finding ID prefix
    let result = if id.starts_with("win-uac-disabled") {
        // Enable UAC
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA",
            "1",
        )
    } else if id.starts_with("win-firewall-disabled") {
        // Enable firewall for the profile
        let default_profile = String::from("allprofiles");
        let profile = finding.metadata.get("profile").unwrap_or(&default_profile);
        let profile_arg = if profile == "domainprofile" {
            "DomainProfile"
        } else if profile == "standardprofile" {
            "StandardProfile"
        } else if profile == "publicprofile" {
            "PublicProfile"
        } else {
            "AllProfiles"
        };
        std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                &profile_arg.to_lowercase(),
                "state",
                "on",
            ])
            .output()
            .map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    } else if id.starts_with("win-defender-disabled") {
        // Remove DisableAntiSpyware policy
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            "DisableAntiSpyware",
            "0",
        )
    } else if id.starts_with("win-defender-realtime-disabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring",
            "0",
        )
    } else if id.starts_with("win-smartscreen-disabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            "SmartScreenEnabled",
            "RequireAdmin",
        )
    } else if id.starts_with("win-autologin-enabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "AutoAdminLogon",
            "0",
        )
    } else if id.starts_with("win-clipboard-history-enabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            "AllowClipboardHistory",
            "0",
        )
    } else if id.starts_with("win-wifi-sense-enabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config",
            "AutoConnectAllowedOEM",
            "0",
        )
    } else if id.starts_with("win-telemetry-full") {
        registry_fix::apply_registry_fix(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            "AllowTelemetry",
            "1",
        )
    } else if id.starts_with("win-rdp-nla-disabled") {
        registry_fix::apply_registry_fix(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "UserAuthentication",
            "1",
        )
    } else if id.starts_with("win-smbv1-enabled") {
        share_fix::disable_smbv1()
    } else if id.starts_with("win-share-everyone") {
        let empty = String::new();
        let share = finding.metadata.get("share").unwrap_or(&empty);
        share_fix::fix_share_permissions(share)
    } else if id.starts_with("win-admin-share") {
        let empty = String::new();
        let share = finding.metadata.get("share").unwrap_or(&empty);
        share_fix::disable_admin_share(share)
    } else if id.starts_with("win-guest-enabled") {
        std::process::Command::new("net")
            .args(["user", "Guest", "/active:no"])
            .output()
            .map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    } else if id.starts_with("win-password-length-weak") {
        std::process::Command::new("net")
            .args(["accounts", "/minpwlen:12"])
            .output()
            .map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    } else if id.starts_with("win-lockout-disabled") {
        std::process::Command::new("net")
            .args(["accounts", "/lockoutthreshold:5"])
            .output()
            .map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    } else if id.starts_with("win-smb-signing-not-required") {
        registry_fix::apply_registry_fix(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "RequireSecuritySignature",
            "1",
        )
    } else if id.starts_with("win-rdp-encryption-low") {
        registry_fix::apply_registry_fix(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "MinEncryptionLevel",
            "3",
        )
    } else if id.starts_with("win-rdp-security-rdp") {
        registry_fix::apply_registry_fix(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "SecurityLayer",
            "1",
        )
    } else if id.starts_with("mac-gatekeeper-disabled") {
        macos_fix::enable_gatekeeper()
    } else if id.starts_with("mac-firewall-disabled") {
        macos_fix::enable_firewall()
    } else if id.starts_with("mac-firewall-stealth-disabled") {
        macos_fix::enable_stealth_mode()
    } else if id.starts_with("mac-filevault-disabled") {
        macos_fix::enable_filevault()
    } else if id.starts_with("mac-screensaver-insecure") {
        macos_fix::require_screensaver_password()
    } else if id.starts_with("mac-guest-access") {
        macos_fix::disable_guest_access()
    } else if id.starts_with("mac-ssh-root-login") {
        macos_fix::disable_ssh_root_login()
    } else if id.starts_with("mac-bluetooth-discoverable") {
        macos_fix::disable_bluetooth_discoverable()
    } else if id.starts_with("linux-ufw-disabled") {
        linux_fix::enable_ufw()
    } else if id.starts_with("linux-ssh-root-login") {
        linux_fix::disable_ssh_root_login()
    } else if id.starts_with("linux-ssh-password-auth") {
        linux_fix::disable_ssh_password_auth()
    } else if id.starts_with("linux-ssh-port-default") {
        linux_fix::change_ssh_port()
    } else if id.starts_with("linux-fail2ban-disabled") {
        linux_fix::enable_fail2ban()
    } else if id.starts_with("linux-ipv6-enabled") {
        linux_fix::disable_ipv6()
    } else if id.starts_with("linux-unattended-upgrades-disabled") {
        linux_fix::enable_unattended_upgrades()
    } else {
        println!("  → No automated fix available for: {}", finding.title);
        return;
    };

    match result {
        Ok(()) => {}
        Err(e) => println!("  ✗ Fix failed: {}", e),
    }
}
