/// Anomalous process migration detector — detect processes migrating between namespaces/containers.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_migrate() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let nspid_path = format!("/proc/{}/ns/pid", name);
                let nsnet_path = format!("/proc/{}/ns/net", name);

                if let (Ok(pid_ns), Ok(net_ns)) = (
                    std::fs::read_link(&nspid_path),
                    std::fs::read_link(&nsnet_path),
                ) {
                    let init_pid_ns = std::fs::read_link("/proc/1/ns/pid");
                    let init_net_ns = std::fs::read_link("/proc/1/ns/net");

                    if let (Ok(ref init_pid), Ok(ref init_net)) = (init_pid_ns, init_net_ns) {
                        if pid_ns != *init_pid && net_ns == *init_net {
                            findings.push(Finding::new(
                                &format!("migrate-{}-namespace-mismatch", name),
                                &format!("PID {} has different PID namespace but shares network namespace", name),
                                Severity::High,
                                Category::System,
                            ).description("Process has different PID namespace but shares the host network namespace. This may indicate container escape or namespace migration."));
                        }
                    }
                }
            }
        }
    }

    findings
}
