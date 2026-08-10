/// Memory scanner — scan process memory for known malware signatures.
use crate::models::{Category, Finding, Severity};

#[allow(dead_code)]
const MALWARE_SIGNATURES: &[(&str, &str)] = &[
    // (signature bytes as hex pattern, description)
    ("Metasploit Meterpreter", "meterpreter"),
    ("Cobalt Strike beacon", "cobalt-strike"),
    ("Empire PowerShell agent", "empire-agent"),
    ("Mimikatz", "mimikatz"),
    ("Sliver implant", "sliver"),
    ("Merlin agent", "merlin"),
];

const STRING_SIGNATURES: &[&str] = &[
    "meterpreter",
    "Mimikatz",
    "cobaltstrike",
    "beacon.x86",
    "beacon.x64",
    "sliver implant",
    "merlin agent",
    "empire-agent",
    "reverse_shell",
    "/dev/tcp/",
    "bash -i >& /dev/tcp",
    "nc -e /bin/sh",
    "rm -rf /",
    "chmod 777 /",
];

pub fn scan_memory() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let pid = &name;

                let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // Read /proc/[pid]/cmdline for string matching
                let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();

                // Convert null-separated cmdline to string
                let cmdline_str = String::from_utf8_lossy(&cmdline).replace('\0', " ");

                for sig in STRING_SIGNATURES {
                    if cmdline_str.to_lowercase().contains(&sig.to_lowercase()) {
                        findings.push(
                            Finding::new(
                                &format!(
                                    "memscan-{}-{}",
                                    pid,
                                    sig.replace(' ', "_").to_lowercase()
                                ),
                                &format!(
                                    "Malware signature '{}' in process {} (pid {})",
                                    sig, comm, pid
                                ),
                                Severity::Critical,
                                Category::HostConfig,
                            )
                            .description(&format!(
                                "Process command line contains known malware indicator: {}",
                                sig
                            )),
                        );
                    }
                }

                // Check environment variables for suspicious entries
                let environ = std::fs::read(format!("/proc/{}/environ", pid)).unwrap_or_default();
                let environ_str = String::from_utf8_lossy(&environ);

                // Check for LD_PRELOAD (common injection technique)
                if environ_str.contains("LD_PRELOAD=") {
                    let preload_val = environ_str
                        .split("LD_PRELOAD=")
                        .nth(1)
                        .and_then(|s| s.split('\0').next())
                        .unwrap_or("");
                    if !preload_val.is_empty() {
                        findings.push(Finding::new(
                            &format!("memscan-ldpreload-{}-{}", pid, comm),
                            &format!("LD_PRELOAD set in process {} (pid {}): {}", comm, pid, preload_val),
                            Severity::High,
                            Category::HostConfig,
                        )
                        .description("LD_PRELOAD is set in this process's environment. This is a common hooking/injection technique."));
                    }
                }
            }
        }
    }

    findings
}
