/// Port knocking setup — hide SSH/RDP from port scanners using knock sequences.
use super::HardenResult;
use std::process::Command;

pub fn install_knockd(ports: &[u16], dry_run: bool) -> HardenResult {
    if ports.is_empty() {
        return HardenResult {
            action: "knock-install".to_string(),
            success: false,
            message: "No knock sequence specified. Use --sequence 7000,8000,9000".to_string(),
            findings: vec![],
        };
    }

    if dry_run {
        return HardenResult {
            action: "knock-install".to_string(),
            success: true,
            message: format!("[dry-run] Would install knockd with sequence: {:?}", ports),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Check if knockd is installed
        let installed = Command::new("which")
            .arg("knockd")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !installed {
            return HardenResult {
                action: "knock-install".to_string(),
                success: false,
                message: "knockd not installed. Run: sudo apt install knockd".to_string(),
                findings: vec![],
            };
        }

        // Generate knockd config
        let sequence: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let config = format!(
            r#"[options]
    UseSyslog

[openSSH]
    sequence = {}
    seq_timeout = 15
    tcpflags = syn
    start_command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    cmd_timeout = 30
    stop_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT

[closeSSH]
    sequence = {}
    seq_timeout = 15
    tcpflags = syn
    start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
"#,
            sequence.join(","),
            sequence.iter().rev().cloned().collect::<Vec<_>>().join(",")
        );

        let config_path = "/etc/knockd.conf";
        match std::fs::write(config_path, &config) {
            Ok(()) => {
                let _ = Command::new("systemctl")
                    .args(["enable", "--now", "knockd"])
                    .output();
                HardenResult {
                    action: "knock-install".to_string(),
                    success: true,
                    message: format!(
                        "knockd configured. Knock sequence: {:?} to open SSH, {:?} to close.",
                        ports,
                        ports.iter().rev().collect::<Vec<_>>()
                    ),
                    findings: vec![],
                }
            }
            Err(e) => HardenResult {
                action: "knock-install".to_string(),
                success: false,
                message: format!("Failed to write config (need root?): {}", e),
                findings: vec![],
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ports;
        HardenResult {
            action: "knock-install".to_string(),
            success: false,
            message: "Port knocking is only supported on Linux (knockd).".to_string(),
            findings: vec![],
        }
    }
}

pub fn remove_knockd() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "knockd"])
            .output();
        let _ = std::fs::remove_file("/etc/knockd.conf");
        HardenResult {
            action: "knock-remove".to_string(),
            success: true,
            message: "knockd disabled and config removed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "knock-remove".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
