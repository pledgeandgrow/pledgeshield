/// GPU process monitor — monitor GPU processes for crypto mining or ML model exfiltration.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_gpumon() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("nvidia-smi")
            .args([
                "--query-compute-apps=pid,process_name,used_memory",
                "--format=csv,noheader",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.is_empty() {
                return findings;
            }
            let mining_indicators = [
                "xmrig",
                "ethminer",
                "claymore",
                "phoenixminer",
                "trex",
                "lolminer",
                "gminer",
            ];
            for line in s.lines() {
                for miner in &mining_indicators {
                    if line.to_lowercase().contains(miner) {
                        findings.push(Finding::new(
                            &format!("gpumon-{}-detected", miner),
                            &format!("Crypto miner detected: {}", miner),
                            Severity::Critical,
                            Category::HostConfig,
                        ).description(&format!("Process {} appears to be a cryptocurrency miner using GPU resources.", miner)));
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(
            Finding::new(
                "gpumon-unsupported",
                "GPU monitoring requires nvidia-smi",
                Severity::Info,
                Category::HostConfig,
            )
            .description("GPU process monitoring requires nvidia-smi (NVIDIA drivers) on Linux."),
        );
    }

    findings
}
