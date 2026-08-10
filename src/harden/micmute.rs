/// Microphone mute enforcer — mute mic at ALSA/PulseAudio/PipeWire level.
use super::HardenResult;
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_mic() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check PulseAudio/PipeWire for microphone status
        let out = Command::new("pactl")
            .args(["list", "sources", "short"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("input") || line.contains("capture") || line.contains("mic") {
                    let source = line.split_whitespace().nth(1).unwrap_or("");
                    if source.is_empty() {
                        continue;
                    }

                    // Check if this source is muted
                    let out2 = Command::new("pactl")
                        .args(["get-source-mute", source])
                        .output();
                    if let Ok(o2) = out2 {
                        let mute_status = String::from_utf8_lossy(&o2.stdout);
                        if mute_status.contains("no") {
                            findings.push(Finding::new(
                                &format!("mic-unmuted-{}", source),
                                &format!("Microphone {} is not muted", source),
                                Severity::Low,
                                Category::HostConfig,
                            )
                            .description("Your microphone is active and can capture audio. Mute it when not in use.")
                            .recommendation("Run: pledgeshield harden micmute --mute")
                            .fixable(true));
                        }
                    }
                }
            }
        }

        // Check which processes are recording audio
        let out = Command::new("fuser").arg("/dev/snd/pcmC0D0c").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if !s.trim().is_empty() {
                for pid in s.split_whitespace() {
                    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                        .map(|s| s.trim().to_string())
                        .unwrap_or("unknown".to_string());
                    findings.push(Finding::new(
                        &format!("mic-recording-{}", comm),
                        &format!("Process {} is recording audio (pid {})", comm, pid),
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("A process is actively recording from your microphone. Verify this is expected."));
                }
            }
        }
    }

    findings
}

pub fn mute_mic(dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "mic-mute".to_string(),
            success: true,
            message: "[dry-run] Would mute all microphone inputs.".to_string(),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        let out = Command::new("pactl")
            .args(["list", "sources", "short"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            let mut muted = 0;
            for line in s.lines() {
                if line.contains("input") || line.contains("capture") {
                    let source = line.split_whitespace().nth(1).unwrap_or("");
                    if !source.is_empty() {
                        let _ = Command::new("pactl")
                            .args(["set-source-mute", source, "1"])
                            .output();
                        muted += 1;
                    }
                }
            }
            HardenResult {
                action: "mic-mute".to_string(),
                success: true,
                message: format!("Muted {} microphone source(s).", muted),
                findings: vec![],
            }
        } else {
            HardenResult {
                action: "mic-mute".to_string(),
                success: false,
                message: "PulseAudio/PipeWire not available.".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "mic-mute".to_string(),
            success: false,
            message: "Microphone muting is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn unmute_mic() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("pactl")
            .args(["list", "sources", "short"])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("input") || line.contains("capture") {
                    let source = line.split_whitespace().nth(1).unwrap_or("");
                    if !source.is_empty() {
                        let _ = Command::new("pactl")
                            .args(["set-source-mute", source, "0"])
                            .output();
                    }
                }
            }
        }
        HardenResult {
            action: "mic-unmute".to_string(),
            success: true,
            message: "Microphone unmuted.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "mic-unmute".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
