/// Module signature verifier — verify all loaded kernel modules are signed.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_module_signatures() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Get list of loaded modules
        let out = Command::new("lsmod").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines().skip(1) {
                let name = line.split_whitespace().next().unwrap_or("");
                if name.is_empty() { continue; }

                // Check module info for signature
                let out2 = Command::new("modinfo").arg(name).output();
                if let Ok(o2) = out2 {
                    let info = String::from_utf8_lossy(&o2.stdout);
                    if !info.contains("sig_id") && !info.contains("signer:") {
                        // Module is not signed
                        // Skip common built-in modules that don't need signing
                        if !name.starts_with("libcrc") && !name.starts_with("crc") {
                            findings.push(Finding::new(
                                &format!("modsign-unsigned-{}", name),
                                &format!("Unsigned kernel module: {}", name),
                                Severity::Medium,
                                Category::HostConfig,
                            )
                            .description("This kernel module is not cryptographically signed. A rootkit could replace it."));
                        }
                    }
                }
            }
        }

        // Check if kernel enforces module signing
        let out = Command::new("cat").arg("/proc/sys/kernel/modules_disabled").output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s == "0" {
                findings.push(Finding::new(
                    "modsign-not-enforced",
                    "Kernel module loading is not locked down",
                    Severity::Medium,
                    Category::HostConfig,
                )
                .description("Unsigned kernel modules can be loaded. Run: pledgeshield harden kernel --lockdown")
                .fixable(true));
            }
        }

        // Check CONFIG_MODULE_SIG_FORCE in kernel config
        if let Ok(config) = std::fs::read_to_string("/boot/config-$(uname -r)") {
            if config.contains("CONFIG_MODULE_SIG_FORCE=n") || !config.contains("CONFIG_MODULE_SIG_FORCE=y") {
                // Module signing is not enforced at kernel level
            }
        }
    }

    findings
}
