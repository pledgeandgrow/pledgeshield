/// SSL/TLS certificate checker — check your own certs for expiration, weak ciphers.
use crate::models::{Category, Finding, Severity};
use std::process::Command;

pub fn audit_cert(path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if it's a file path or a hostname
    if path.starts_with("/") || path.contains("\\") {
        // File path
        audit_cert_file(path, &mut findings);
    } else {
        // Hostname — check via openssl
        audit_cert_host(path, &mut findings);
    }

    findings
}

fn audit_cert_file(path: &str, findings: &mut Vec<Finding>) {
    if !std::path::Path::new(path).exists() {
        findings.push(Finding::new(
            "cert-not-found",
            &format!("Certificate not found: {}", path),
            Severity::Medium,
            Category::HostConfig,
        ));
        return;
    }

    // Use openssl to check the cert
    let out = Command::new("openssl")
        .args(["x509", "-in", path, "-noout", "-dates", "-subject", "-issuer"])
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        check_cert_dates(&s, findings);
    }

    // Check key size
    let out = Command::new("openssl")
        .args(["x509", "-in", path, "-noout", "-text"])
        .output();
    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if s.contains("Public-Key: (1024 bit)") {
            findings.push(Finding::new(
                "cert-weak-key",
                "Certificate uses 1024-bit key (weak)",
                Severity::High,
                Category::HostConfig,
            )
            .description("1024-bit RSA keys are deprecated. Use at least 2048 bits (prefer 4096 or ECDSA)."));
        }
        if s.contains("SHA1") {
            findings.push(Finding::new(
                "cert-sha1",
                "Certificate uses SHA-1 signature (deprecated)",
                Severity::High,
                Category::HostConfig,
            )
            .description("SHA-1 is collision-vulnerable. Use SHA-256 or higher."));
        }
        if s.contains("MD5") {
            findings.push(Finding::new(
                "cert-md5",
                "Certificate uses MD5 signature (broken)",
                Severity::Critical,
                Category::HostConfig,
            )
            .description("MD5 is broken. Replace this certificate immediately."));
        }
    }
}

fn audit_cert_host(host: &str, findings: &mut Vec<Finding>) {
    let host_clean = host.split(':').next().unwrap_or(host);
    let out = Command::new("openssl")
        .args(["s_client", "-connect", &format!("{}:443", host_clean), "-servername", host_clean])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut child) = out {
        // Close stdin to signal end
        if let Some(stdin) = child.stdin.take() {
            drop(stdin);
        }
        if let Ok(output) = child.wait_with_output() {
            let s = String::from_utf8_lossy(&output.stdout);
            // Extract cert and check dates
            check_cert_dates(&s, findings);
        }
    } else {
        findings.push(Finding::new(
            "cert-connect-failed",
            &format!("Cannot connect to {}:443", host_clean),
            Severity::Low,
            Category::HostConfig,
        ));
    }
}

fn check_cert_dates(cert_text: &str, findings: &mut Vec<Finding>) {
    // Parse "notAfter=..." from openssl output
    for line in cert_text.lines() {
        if line.contains("notAfter=") {
            let date_str = line.split('=').nth(1).unwrap_or("").trim();
            // Try to parse the date
            if let Ok(date) = chrono::DateTime::parse_from_str(date_str, "%b %d %H:%M:%S %Y GMT") {
                let now = chrono::Utc::now();
                let days_left = (date.with_timezone(&chrono::Utc) - now).num_days();
                if days_left < 0 {
                    findings.push(Finding::new(
                        "cert-expired",
                        &format!("Certificate expired {} days ago", -days_left),
                        Severity::Critical,
                        Category::HostConfig,
                    )
                    .description("This certificate has expired. Services using it will be rejected by clients."));
                } else if days_left < 7 {
                    findings.push(Finding::new(
                        "cert-expiring-critical",
                        &format!("Certificate expires in {} days", days_left),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .description("Certificate expires very soon. Renew immediately."));
                } else if days_left < 30 {
                    findings.push(Finding::new(
                        "cert-expiring-soon",
                        &format!("Certificate expires in {} days", days_left),
                        Severity::Medium,
                        Category::HostConfig,
                    )
                    .description("Certificate will expire soon. Start renewal process."));
                }
            }
        }
    }
}
