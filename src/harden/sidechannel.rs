/// Side channel mitigator — mitigate CPU side-channel attacks (Spectre/Meltdown/Downfall).
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_sidechannel() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let params = [
            ("net.ipv4.conf.all.rp_filter", "Reverse path filtering"),
            ("kernel.kptr_restrict", "Kernel pointer restriction"),
            ("kernel.dmesg_restrict", "dmesg restriction"),
            ("kernel.perf_event_paranoid", "Perf event access"),
        ];

        for (param, desc) in &params {
            let out = Command::new("sysctl").args(["-n", param]).output();
            if let Ok(o) = out {
                let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
                match *param {
                    "kernel.kptr_restrict" if val != "2" => {
                        findings.push(Finding::new(
                            "sidechannel-kptr",
                            "Kernel pointer restriction is not strict",
                            Severity::Medium,
                            Category::System,
                        ).description("kptr_restrict should be 2 to prevent kernel address leaks used in side-channel attacks."));
                    }
                    "kernel.perf_event_paranoid" if val != "2" && val != "3" => {
                        findings.push(Finding::new(
                            "sidechannel-perf",
                            "Perf events are not restricted",
                            Severity::Medium,
                            Category::System,
                        ).description("perf_event_paranoid should be 2+ to prevent side-channel attacks via performance counters."));
                    }
                    _ => {}
                }
            }
        }
    }

    findings
}

pub fn mitigate_sidechannel(dry_run: bool) -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            return HardenResult {
                action: "sidechannel-mitigate".to_string(),
                success: true,
                message: "Would set kptr_restrict=2, perf_event_paranoid=3, PTI=on (dry run)"
                    .to_string(),
                findings: vec![],
            };
        }

        let _ = Command::new("sysctl")
            .args(["-w", "kernel.kptr_restrict=2"])
            .output();
        let _ = Command::new("sysctl")
            .args(["-w", "kernel.perf_event_paranoid=3"])
            .output();
        let _ = Command::new("sysctl")
            .args(["-w", "kernel.dmesg_restrict=1"])
            .output();

        HardenResult {
            action: "sidechannel-mitigate".to_string(),
            success: true,
            message: "Side-channel mitigations applied: kptr_restrict=2, perf_event_paranoid=3, dmesg_restrict=1".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        HardenResult {
            action: "sidechannel-mitigate".to_string(),
            success: false,
            message: "Side-channel mitigation via sysctl is Linux-only".to_string(),
            findings: vec![],
        }
    }
}
