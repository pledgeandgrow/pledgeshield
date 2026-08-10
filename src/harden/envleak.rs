/// Environment variable leak checker — scan /proc/[pid]/environ for secrets.
use crate::models::{Category, Finding, Severity};

const SECRET_ENV_VARS: &[&str] = &[
    "API_KEY", "API_SECRET", "ACCESS_TOKEN", "ACCESS_KEY",
    "SECRET_KEY", "PRIVATE_KEY", "PASSWORD", "PASSWD",
    "TOKEN", "AUTH_TOKEN", "BEARER_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN", "GITLAB_TOKEN",
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "DATABASE_URL", "DB_PASSWORD",
    "JWT_SECRET", "SESSION_SECRET",
    "ENCRYPTION_KEY", "ENCRYPT_KEY",
    "SLACK_TOKEN", "SLACK_WEBHOOK",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY", "AZURE_API_KEY",
];

pub fn audit_env_leaks() -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let pid = &name;

                let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                // Read environment variables
                let environ_path = format!("/proc/{}/environ", pid);
                if let Ok(data) = std::fs::read(&environ_path) {
                    let environ = String::from_utf8_lossy(&data);

                    for var in SECRET_ENV_VARS {
                        // Check if this env var is set
                        let pattern = format!("{}=", var);
                        if environ.contains(&pattern) {
                            // Extract the value to check if it's non-empty
                            let value = environ.split(&pattern)
                                .nth(1)
                                .and_then(|s| s.split('\0').next())
                                .unwrap_or("");

                            if !value.is_empty() && value.len() > 3 {
                                findings.push(Finding::new(
                                    &format!("envleak-{}-{}-{}", pid, comm, var.to_lowercase()),
                                    &format!("Secret in env var: {} (pid {}, process {})", var, pid, comm),
                                    Severity::Medium,
                                    Category::Credentials,
                                )
                                .description("A secret is exposed in this process's environment variables. Other processes (with sufficient privileges) can read it via /proc."));
                            }
                        }
                    }

                    // Check for LD_PRELOAD (injection)
                    if environ.contains("LD_PRELOAD=") {
                        let preload = environ.split("LD_PRELOAD=")
                            .nth(1)
                            .and_then(|s| s.split('\0').next())
                            .unwrap_or("");
                        if !preload.is_empty() {
                            findings.push(Finding::new(
                                &format!("envleak-ldpreload-{}-{}", pid, comm),
                                &format!("LD_PRELOAD set in {} (pid {}): {}", comm, pid, preload),
                                Severity::High,
                                Category::HostConfig,
                            )
                            .description("LD_PRELOAD is set in this process's environment — potential code injection."));
                        }
                    }
                }
            }
        }
    }

    findings
}
