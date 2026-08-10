/// Proxy chain manager — configure SOCKS5/HTTP proxy chains for traffic obfuscation.
use super::HardenResult;

pub fn set_proxy(proxy_type: &str, host: &str, port: u16, dry_run: bool) -> HardenResult {
    let proxy_url = format!("{}://{}:{}", proxy_type, host, port);

    if dry_run {
        return HardenResult {
            action: "proxy-set".to_string(),
            success: true,
            message: format!("[dry-run] Would set {} proxy to {}", proxy_type, proxy_url),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Set environment variables for the current session + system-wide
        let env_vars = [
            ("http_proxy", &proxy_url),
            ("https_proxy", &proxy_url),
            ("HTTP_PROXY", &proxy_url),
            ("HTTPS_PROXY", &proxy_url),
            ("all_proxy", &proxy_url),
            ("ALL_PROXY", &proxy_url),
        ];

        // Write to /etc/environment for persistence
        let mut content = String::new();
        if let Ok(existing) = std::fs::read_to_string("/etc/environment") {
            content = existing
                .lines()
                .filter(|l| {
                    !l.starts_with("http_proxy")
                        && !l.starts_with("https_proxy")
                        && !l.starts_with("HTTP_PROXY")
                        && !l.starts_with("HTTPS_PROXY")
                        && !l.starts_with("all_proxy")
                        && !l.starts_with("ALL_PROXY")
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        for (key, val) in &env_vars {
            content.push_str(&format!("\n{}=\"{}\"", key, val));
        }
        let _ = std::fs::write("/etc/environment", content);

        // Also set for current process
        for (key, val) in &env_vars {
            std::env::set_var(key, val);
        }

        HardenResult {
            action: "proxy-set".to_string(),
            success: true,
            message: format!(
                "Proxy set to {} (system-wide via /etc/environment)",
                proxy_url
            ),
            findings: vec![],
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: set network proxy via networksetup
        let out = Command::new("networksetup")
            .args(["-setwebproxy", "Wi-Fi", host, &port.to_string()])
            .output();
        let ok = out.map(|o| o.status.success()).unwrap_or(false);
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxy", "Wi-Fi", host, &port.to_string()])
            .output();
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxy", "Wi-Fi", host, &port.to_string()])
            .output();
        HardenResult {
            action: "proxy-set".to_string(),
            success: ok,
            message: format!("Proxy set to {} via networksetup", proxy_url),
            findings: vec![],
        }
    }

    #[cfg(windows)]
    {
        // Windows: set via registry
        let _ = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &format!("{}={}:{}", proxy_type, host, port),
                "/f",
            ])
            .output();
        let _ = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();
        HardenResult {
            action: "proxy-set".to_string(),
            success: true,
            message: format!("Proxy set to {} via registry", proxy_url),
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = proxy_url;
        HardenResult {
            action: "proxy-set".to_string(),
            success: false,
            message: "Not supported on this platform.".to_string(),
            findings: vec![],
        }
    }
}

pub fn clear_proxy() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/environment") {
            let new_content: String = content
                .lines()
                .filter(|l| {
                    !l.starts_with("http_proxy")
                        && !l.starts_with("https_proxy")
                        && !l.starts_with("HTTP_PROXY")
                        && !l.starts_with("HTTPS_PROXY")
                        && !l.starts_with("all_proxy")
                        && !l.starts_with("ALL_PROXY")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write("/etc/environment", new_content);
        }
        for key in &[
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            std::env::remove_var(key);
        }
        HardenResult {
            action: "proxy-clear".to_string(),
            success: true,
            message: "Proxy settings cleared.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("networksetup")
            .args(["-setwebproxystate", "Wi-Fi", "off"])
            .output();
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxystate", "Wi-Fi", "off"])
            .output();
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", "Wi-Fi", "off"])
            .output();
        HardenResult {
            action: "proxy-clear".to_string(),
            success: true,
            message: "Proxy settings cleared.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(windows)]
    {
        let _ = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();
        HardenResult {
            action: "proxy-clear".to_string(),
            success: true,
            message: "Proxy settings cleared.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "proxy-clear".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

pub fn show_proxy() -> String {
    let mut out = String::new();
    for key in &[
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        if let Ok(val) = std::env::var(key) {
            out.push_str(&format!("  {} = {}\n", key, val));
        }
    }
    if out.is_empty() {
        "  No proxy configured.".to_string()
    } else {
        out
    }
}
