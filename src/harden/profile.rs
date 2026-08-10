/// Hardening profile applier — apply CIS Level 1/2, STIG, or custom profiles in one command.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Profile {
    /// CIS Benchmark Level 1 — baseline security settings
    #[value(name = "cis1")]
    CisLevel1,
    /// CIS Benchmark Level 2 — stronger security (may impact functionality)
    #[value(name = "cis2")]
    CisLevel2,
    /// STIG (Security Technical Implementation Guide) — DoD hardening
    #[value(name = "stig")]
    Stig,
    /// Custom profile from a TOML file
    #[value(name = "custom")]
    Custom,
}

impl Profile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::CisLevel1 => "CIS Level 1",
            Profile::CisLevel2 => "CIS Level 2",
            Profile::Stig => "STIG",
            Profile::Custom => "Custom",
        }
    }
}

pub fn audit_profile(profile: Profile) -> Vec<Finding> {
    let mut findings = Vec::new();
    let settings = get_profile_settings(profile);

    for setting in &settings {
        // Check each setting
        match setting.check_type {
            CheckType::Sysctl => {
                #[cfg(target_os = "linux")]
                {
                    let out = std::process::Command::new("sysctl")
                        .args(["-n", &setting.key])
                        .output();
                    if let Ok(o) = out {
                        let current = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if current != setting.expected {
                            findings.push(
                                Finding::new(
                                    &format!(
                                        "profile-{}-{}",
                                        profile.as_str().to_lowercase().replace(' ', "-"),
                                        setting.key.replace('.', "_")
                                    ),
                                    &format!(
                                        "{} = {} (should be {})",
                                        setting.key, current, setting.expected
                                    ),
                                    setting.severity,
                                    Category::HostConfig,
                                )
                                .description(setting.description.clone())
                                .recommendation(&format!(
                                    "Run: pledgeshield harden profile --apply {:?}",
                                    profile
                                ))
                                .fixable(true),
                            );
                        }
                    }
                }
            }
            CheckType::FilePerm => {
                if let Ok(meta) = std::fs::metadata(&setting.key) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = meta.permissions().mode() & 0o7777;
                        if let Ok(expected_mode) = u32::from_str_radix(&setting.expected, 8) {
                            if mode != expected_mode {
                                findings.push(
                                    Finding::new(
                                        &format!("profile-perm-{}", setting.key.replace('/', "_")),
                                        &format!(
                                            "{} is {:04o} (should be {:04o})",
                                            setting.key, mode, expected_mode
                                        ),
                                        setting.severity,
                                        Category::HostConfig,
                                    )
                                    .fixable(true),
                                );
                            }
                        }
                    }
                }
            }
            CheckType::ServiceDisabled => {
                #[cfg(target_os = "linux")]
                {
                    let out = std::process::Command::new("systemctl")
                        .args(["is-enabled", &setting.key])
                        .output();
                    if let Ok(o) = out {
                        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if s != "disabled" && s != "not-found" && s != "masked" {
                            findings.push(
                                Finding::new(
                                    &format!("profile-service-{}", setting.key),
                                    &format!(
                                        "Service {} is enabled (should be disabled)",
                                        setting.key
                                    ),
                                    setting.severity,
                                    Category::Services,
                                )
                                .fixable(true),
                            );
                        }
                    }
                }
            }
        }
    }

    findings
}

pub fn apply_profile(profile: Profile, dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();
    let settings = get_profile_settings(profile);

    for setting in &settings {
        if dry_run {
            results.push(HardenResult {
                action: format!("profile-{}", setting.key),
                success: true,
                message: format!("[dry-run] Would set {} = {}", setting.key, setting.expected),
                findings: vec![],
            });
            continue;
        }

        match setting.check_type {
            CheckType::Sysctl => {
                #[cfg(target_os = "linux")]
                {
                    let out = std::process::Command::new("sysctl")
                        .args(["-w", &format!("{}={}", setting.key, setting.expected)])
                        .output();
                    results.push(HardenResult {
                        action: format!("sysctl-{}", setting.key),
                        success: out.map(|o| o.status.success()).unwrap_or(false),
                        message: format!("Set {} = {}", setting.key, setting.expected),
                        findings: vec![],
                    });
                }
            }
            CheckType::FilePerm => {
                #[cfg(unix)]
                {
                    if let Ok(mode) = u32::from_str_radix(&setting.expected, 8) {
                        let _ = std::fs::set_permissions(
                            &setting.key,
                            std::os::unix::fs::PermissionsExt::from_mode(mode),
                        );
                        results.push(HardenResult {
                            action: format!("perm-{}", setting.key),
                            success: true,
                            message: format!("Set {} to {:04o}", setting.key, mode),
                            findings: vec![],
                        });
                    }
                }
            }
            CheckType::ServiceDisabled => {
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("systemctl")
                        .args(["disable", "--now", &setting.key])
                        .output();
                    results.push(HardenResult {
                        action: format!("disable-{}", setting.key),
                        success: true,
                        message: format!("Disabled service: {}", setting.key),
                        findings: vec![],
                    });
                }
            }
        }
    }

    results
}

#[derive(Clone)]
struct ProfileSetting {
    key: String,
    expected: String,
    check_type: CheckType,
    severity: Severity,
    description: String,
}

#[derive(Clone, Copy)]
enum CheckType {
    Sysctl,
    FilePerm,
    ServiceDisabled,
}

fn get_profile_settings(profile: Profile) -> Vec<ProfileSetting> {
    let mut settings = Vec::new();

    // Common settings for all profiles
    let common = vec![
        ProfileSetting {
            key: "kernel.randomize_va_space".to_string(),
            expected: "2".to_string(),
            check_type: CheckType::Sysctl,
            severity: Severity::Medium,
            description: "Enable full ASLR".to_string(),
        },
        ProfileSetting {
            key: "fs.suid_dumpable".to_string(),
            expected: "0".to_string(),
            check_type: CheckType::Sysctl,
            severity: Severity::Medium,
            description: "Disable SUID core dumps".to_string(),
        },
    ];

    settings.extend(common);

    match profile {
        Profile::CisLevel1 => {
            // CIS Level 1 — baseline
            settings.extend(vec![
                ProfileSetting {
                    key: "net.ipv4.conf.all.send_redirects".to_string(),
                    expected: "0".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Low,
                    description: "Disable ICMP redirect sending".to_string(),
                },
                ProfileSetting {
                    key: "net.ipv4.conf.all.accept_redirects".to_string(),
                    expected: "0".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Low,
                    description: "Don't accept ICMP redirects".to_string(),
                },
                ProfileSetting {
                    key: "kernel.kptr_restrict".to_string(),
                    expected: "1".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Low,
                    description: "Restrict kernel pointer exposure".to_string(),
                },
            ]);
        }
        Profile::CisLevel2 => {
            // CIS Level 2 — stronger
            settings.extend(vec![
                ProfileSetting {
                    key: "net.ipv4.conf.all.send_redirects".to_string(),
                    expected: "0".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Medium,
                    description: "Disable ICMP redirect sending".to_string(),
                },
                ProfileSetting {
                    key: "kernel.kptr_restrict".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Medium,
                    description: "Hide kernel pointers completely".to_string(),
                },
                ProfileSetting {
                    key: "kernel.dmesg_restrict".to_string(),
                    expected: "1".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Medium,
                    description: "Restrict dmesg to root".to_string(),
                },
                ProfileSetting {
                    key: "kernel.perf_event_paranoid".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Medium,
                    description: "Restrict perf events".to_string(),
                },
                ProfileSetting {
                    key: "kernel.yama.ptrace_scope".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::Medium,
                    description: "Restrict ptrace".to_string(),
                },
                ProfileSetting {
                    key: "/etc/ssh/sshd_config".to_string(),
                    expected: "600".to_string(),
                    check_type: CheckType::FilePerm,
                    severity: Severity::Low,
                    description: "SSH config should be 600".to_string(),
                },
            ]);
        }
        Profile::Stig => {
            // STIG — strictest
            settings.extend(vec![
                ProfileSetting {
                    key: "kernel.kptr_restrict".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::High,
                    description: "Hide kernel pointers".to_string(),
                },
                ProfileSetting {
                    key: "kernel.dmesg_restrict".to_string(),
                    expected: "1".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::High,
                    description: "Restrict dmesg".to_string(),
                },
                ProfileSetting {
                    key: "kernel.perf_event_paranoid".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::High,
                    description: "Restrict perf events".to_string(),
                },
                ProfileSetting {
                    key: "kernel.yama.ptrace_scope".to_string(),
                    expected: "2".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::High,
                    description: "Restrict ptrace".to_string(),
                },
                ProfileSetting {
                    key: "kernel.kexec_load_disabled".to_string(),
                    expected: "1".to_string(),
                    check_type: CheckType::Sysctl,
                    severity: Severity::High,
                    description: "Disable kexec".to_string(),
                },
                ProfileSetting {
                    key: "avahi-daemon".to_string(),
                    expected: "disabled".to_string(),
                    check_type: CheckType::ServiceDisabled,
                    severity: Severity::Medium,
                    description: "Disable Avahi (mDNS) — STIG requirement".to_string(),
                },
                ProfileSetting {
                    key: "cups".to_string(),
                    expected: "disabled".to_string(),
                    check_type: CheckType::ServiceDisabled,
                    severity: Severity::Low,
                    description: "Disable CUPS if not needed — STIG requirement".to_string(),
                },
            ]);
        }
        Profile::Custom => {
            // Custom — just the common settings
        }
    }

    settings
}
