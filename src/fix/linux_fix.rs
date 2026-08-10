use std::process::Command;

type FixResult = Result<(), Box<dyn std::error::Error>>;

/// Enable UFW (Uncomplicated Firewall).
pub fn enable_ufw() -> FixResult {
    Command::new("sudo").args(["ufw", "enable"]).output()?;
    Command::new("sudo")
        .args(["ufw", "default", "deny", "incoming"])
        .output()?;
    Command::new("sudo")
        .args(["ufw", "default", "allow", "outgoing"])
        .output()?;
    Ok(())
}

/// Disable SSH root login.
pub fn disable_ssh_root_login() -> FixResult {
    let config = std::fs::read_to_string("/etc/ssh/sshd_config")?;
    let updated = config
        .lines()
        .map(|line| {
            if line.starts_with("#PermitRootLogin") || line.starts_with("PermitRootLogin") {
                "PermitRootLogin no".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write("/etc/ssh/sshd_config", &updated)?;
    Command::new("sudo")
        .args(["systemctl", "restart", "sshd"])
        .output()?;
    Ok(())
}

/// Disable SSH password authentication (key-only).
pub fn disable_ssh_password_auth() -> FixResult {
    let config = std::fs::read_to_string("/etc/ssh/sshd_config")?;
    let updated = config
        .lines()
        .map(|line| {
            if line.starts_with("#PasswordAuthentication")
                || line.starts_with("PasswordAuthentication")
            {
                "PasswordAuthentication no".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write("/etc/ssh/sshd_config", &updated)?;
    Command::new("sudo")
        .args(["systemctl", "restart", "sshd"])
        .output()?;
    Ok(())
}

/// Change SSH port from default 22 to a non-standard port.
pub fn change_ssh_port() -> FixResult {
    let config = std::fs::read_to_string("/etc/ssh/sshd_config")?;
    let updated = config
        .lines()
        .map(|line| {
            if line.starts_with("#Port ") || line.starts_with("Port ") {
                "Port 2222".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write("/etc/ssh/sshd_config", &updated)?;
    Command::new("sudo")
        .args(["systemctl", "restart", "sshd"])
        .output()?;
    println!("  → SSH port changed to 2222. Update your firewall rules accordingly.");
    Ok(())
}

/// Enable fail2ban for brute-force protection.
pub fn enable_fail2ban() -> FixResult {
    Command::new("sudo")
        .args(["systemctl", "enable", "fail2ban"])
        .output()?;
    Command::new("sudo")
        .args(["systemctl", "start", "fail2ban"])
        .output()?;
    Ok(())
}

/// Disable IPv6 if not needed (prevents IPv6-based attacks).
pub fn disable_ipv6() -> FixResult {
    Command::new("sudo")
        .args(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        .output()?;
    Command::new("sudo")
        .args(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
        .output()?;

    // Persist across reboots
    let sysctl_conf = "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n";
    std::fs::OpenOptions::new()
        .append(true)
        .open("/etc/sysctl.d/99-disable-ipv6.conf")?
        .write_all(sysctl_conf.as_bytes())?;
    Ok(())
}

/// Enable unattended security upgrades (Debian/Ubuntu).
pub fn enable_unattended_upgrades() -> FixResult {
    Command::new("sudo")
        .args(["apt-get", "install", "-y", "unattended-upgrades"])
        .output()?;
    Command::new("sudo")
        .args(["dpkg-reconfigure", "-plow", "unattended-upgrades"])
        .output()?;
    Ok(())
}

use std::io::Write;
