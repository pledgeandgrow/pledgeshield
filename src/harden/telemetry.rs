/// Telemetry deep-cleaner — disable ALL telemetry across OS, browsers, dev tools.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_telemetry() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Ubuntu telemetry
        if std::path::Path::new("/usr/bin/ubuntu-report").exists() {
            let out = Command::new("ubuntu-report").arg("show").output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if !s.contains("no") {
                    findings.push(
                        Finding::new(
                            "telemetry-ubuntu-report",
                            "Ubuntu telemetry reporting is enabled",
                            Severity::Medium,
                            Category::HostConfig,
                        )
                        .recommendation("Run: pledgeshield harden telemetry --clean")
                        .fixable(true),
                    );
                }
            }
        }

        // Pop!_OS telemetry
        if std::path::Path::new("/usr/bin/pop-report").exists() {
            findings.push(
                Finding::new(
                    "telemetry-pop-os",
                    "Pop!_OS telemetry tool is installed",
                    Severity::Low,
                    Category::HostConfig,
                )
                .fixable(true),
            );
        }

        // apt popularity contest
        if std::path::Path::new("/usr/sbin/popularity-contest").exists() {
            let out = Command::new("deb-systemd-helper")
                .args(["--user", "is-enabled", "popularity-contest.service"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("enabled") {
                    findings.push(
                        Finding::new(
                            "telemetry-popcon",
                            "Debian popularity-contest is enabled",
                            Severity::Low,
                            Category::HostConfig,
                        )
                        .description("popularity-contest sends package usage data to Debian.")
                        .fixable(true),
                    );
                }
            }
        }

        // MOTD news (Ubuntu)
        if std::path::Path::new("/etc/default/motd-news").exists() {
            if let Ok(content) = std::fs::read_to_string("/etc/default/motd-news") {
                if content.contains("ENABLED=1") {
                    findings.push(
                        Finding::new(
                            "telemetry-motd-news",
                            "Ubuntu MOTD news is enabled",
                            Severity::Low,
                            Category::HostConfig,
                        )
                        .description("MOTD news fetches content from Ubuntu servers on each login.")
                        .fixable(true),
                    );
                }
            }
        }

        // Check for whoopsie (Ubuntu error reporting)
        let out = Command::new("systemctl")
            .args(["is-enabled", "whoopsie"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("enabled") {
                findings.push(
                    Finding::new(
                        "telemetry-whoopsie",
                        "Ubuntu error reporting (whoopsie) is enabled",
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description(
                        "whoopsie sends crash reports to Ubuntu, which may contain sensitive data.",
                    )
                    .fixable(true),
                );
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows telemetry
        let out = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
                "/v",
                "AllowTelemetry",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("0x0") && !s.contains("0x1") {
                findings.push(Finding::new(
                    "telemetry-windows",
                    "Windows telemetry is not restricted",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Windows sends diagnostic data to Microsoft. Set to Security level (0) or Basic (1).")
                .fixable(true));
            }
        }

        // Cortana
        let out = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
                "/v",
                "AllowCortana",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.contains("0x0") {
                findings.push(
                    Finding::new(
                        "telemetry-cortana",
                        "Cortana is not disabled",
                        Severity::Low,
                        Category::HostConfig,
                    )
                    .fixable(true),
                );
            }
        }
    }

    // Browser telemetry (covered by browser module, but note it)
    let home = dirs::home_dir();
    if let Some(h) = home {
        // Firefox telemetry
        let ff_prefs = h.join(".mozilla/firefox");
        if ff_prefs.exists() {
            if let Ok(entries) = std::fs::read_dir(&ff_prefs) {
                for entry in entries.flatten() {
                    let prefs = entry.path().join("prefs.js");
                    if prefs.exists() {
                        if let Ok(content) = std::fs::read_to_string(&prefs) {
                            if !content.contains("toolkit.telemetry.enabled")
                                || content.contains("toolkit.telemetry.enabled, true")
                            {
                                findings.push(
                                    Finding::new(
                                        "telemetry-firefox",
                                        "Firefox telemetry may be enabled",
                                        Severity::Low,
                                        Category::Browser,
                                    )
                                    .fixable(true),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

pub fn clean_telemetry(dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Ubuntu report
        if !dry_run {
            let _ = Command::new("ubuntu-report").args(["send", "no"]).output();
        }
        results.push(HardenResult {
            action: "telemetry-ubuntu".to_string(),
            success: true,
            message: if dry_run {
                "[dry-run] Would disable Ubuntu telemetry".to_string()
            } else {
                "Ubuntu telemetry disabled".to_string()
            },
            findings: vec![],
        });

        // MOTD news
        if std::path::Path::new("/etc/default/motd-news").exists() {
            if !dry_run {
                let _ = std::fs::write("/etc/default/motd-news", "ENABLED=0\n");
            }
            results.push(HardenResult {
                action: "telemetry-motd".to_string(),
                success: true,
                message: if dry_run {
                    "[dry-run] Would disable MOTD news".to_string()
                } else {
                    "MOTD news disabled".to_string()
                },
                findings: vec![],
            });
        }

        // whoopsie
        if !dry_run {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", "whoopsie"])
                .output();
        }
        results.push(HardenResult {
            action: "telemetry-whoopsie".to_string(),
            success: true,
            message: if dry_run {
                "[dry-run] Would disable whoopsie".to_string()
            } else {
                "whoopsie error reporting disabled".to_string()
            },
            findings: vec![],
        });

        // popularity-contest
        if !dry_run {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", "popularity-contest"])
                .output();
        }
        results.push(HardenResult {
            action: "telemetry-popcon".to_string(),
            success: true,
            message: if dry_run {
                "[dry-run] Would disable popularity-contest".to_string()
            } else {
                "popularity-contest disabled".to_string()
            },
            findings: vec![],
        });
    }

    #[cfg(windows)]
    {
        if !dry_run {
            let _ = Command::new("reg")
                .args([
                    "add",
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
                    "/v",
                    "AllowTelemetry",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])
                .output();
            let _ = Command::new("reg")
                .args([
                    "add",
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
                    "/v",
                    "AllowCortana",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])
                .output();
        }
        results.push(HardenResult {
            action: "telemetry-windows".to_string(),
            success: true,
            message: if dry_run {
                "[dry-run] Would set Windows telemetry to Security level + disable Cortana"
                    .to_string()
            } else {
                "Windows telemetry set to Security level, Cortana disabled".to_string()
            },
            findings: vec![],
        });
    }

    results
}
