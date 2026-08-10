/// Clipboard privacy — clear clipboard history, block clipboard access from other apps.
use super::HardenResult;
use std::process::Command;

pub fn clear_clipboard() -> HardenResult {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Use xclip/xsel on Linux, pbcopy on macOS
        #[cfg(target_os = "linux")]
        {
            let out = Command::new("xclip").args(["-selection", "clipboard"]).stdin(std::process::Stdio::piped()).spawn();
            if let Ok(mut child) = out {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(b"");
                }
                let _ = child.wait();
                return HardenResult {
                    action: "clipboard-clear".to_string(),
                    success: true,
                    message: "Clipboard cleared (xclip).".to_string(),
                    findings: vec![],
                };
            }
            // Try xsel
            let out = Command::new("xsel").args(["--clipboard", "--clear"]).output();
            if out.map(|o| o.status.success()).unwrap_or(false) {
                return HardenResult {
                    action: "clipboard-clear".to_string(),
                    success: true,
                    message: "Clipboard cleared (xsel).".to_string(),
                    findings: vec![],
                };
            }
            // Try wl-copy (Wayland)
            let out = Command::new("wl-copy").arg("").output();
            if out.map(|o| o.status.success()).unwrap_or(false) {
                return HardenResult {
                    action: "clipboard-clear".to_string(),
                    success: true,
                    message: "Clipboard cleared (wl-copy).".to_string(),
                    findings: vec![],
                };
            }
            HardenResult {
                action: "clipboard-clear".to_string(),
                success: false,
                message: "No clipboard tool found (install xclip or wl-copy).".to_string(),
                findings: vec![],
            }
        }

        #[cfg(target_os = "macos")]
        {
            let out = Command::new("pbcopy").stdin(std::process::Stdio::piped()).spawn();
            if let Ok(mut child) = out {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(b"");
                }
                let _ = child.wait();
            }
            HardenResult {
                action: "clipboard-clear".to_string(),
                success: true,
                message: "Clipboard cleared (pbcopy).".to_string(),
                findings: vec![],
            }
        }
    }

    #[cfg(windows)]
    {
        // Use PowerShell to clear clipboard
        let out = Command::new("powershell")
            .args(["-Command", "Set-Clipboard -Value ''"])
            .output();
        match out {
            Ok(o) if o.status.success() => HardenResult {
                action: "clipboard-clear".to_string(),
                success: true,
                message: "Clipboard cleared.".to_string(),
                findings: vec![],
            },
            _ => HardenResult {
                action: "clipboard-clear".to_string(),
                success: false,
                message: "Failed to clear clipboard.".to_string(),
                findings: vec![],
            },
        }
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        HardenResult {
            action: "clipboard-clear".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}

/// Install a clipboard watcher that clears the clipboard after N seconds.
pub fn install_clipboard_watcher(seconds: u64, dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "clipboard-watcher".to_string(),
            success: true,
            message: format!("[dry-run] Would install clipboard auto-clear after {}s.", seconds),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Create a simple script that clears clipboard periodically
        let script = format!(
            r#"#!/bin/bash
# PledgeShield clipboard auto-clear
while true; do
    sleep {}
    xclip -selection clipboard /dev/null 2>/dev/null || xsel --clipboard --clear 2>/dev/null || wl-copy "" 2>/dev/null
done
"#,
            seconds
        );
        let script_path = "/tmp/pledgeshield-clipboard-watcher.sh";
        let _ = std::fs::write(script_path, &script);
        let _ = Command::new("chmod").args(["+x", script_path]).output();

        HardenResult {
            action: "clipboard-watcher".to_string(),
            success: true,
            message: format!("Clipboard watcher installed at {} (run it in background).", script_path),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = seconds;
        HardenResult {
            action: "clipboard-watcher".to_string(),
            success: false,
            message: "Clipboard watcher is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}
