use crate::models::ScanResult;

/// Configuration for email notifications.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub from: String,
    pub to: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_tls: bool,
}

/// Send an email notification about critical findings.
/// Returns Ok if the email was sent (or would be sent in dry-run mode).
pub fn send_critical_notification(
    config: &EmailConfig,
    result: &ScanResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let critical_count = result.summary.critical;
    let high_count = result.summary.high;

    if critical_count == 0 && high_count == 0 {
        log::info!("No critical/high findings — skipping email notification");
        return Ok(());
    }

    let subject = format!(
        "[PledgeShield] {} critical, {} high findings on {}",
        critical_count, high_count, result.hostname
    );

    let mut body = String::new();
    body.push_str(&format!("PledgeShield Security Scan Report\n"));
    body.push_str(&format!("Host: {}\n", result.hostname));
    body.push_str(&format!("OS: {} {}\n\n", result.os, result.os_version));
    body.push_str(&format!("Summary:\n"));
    body.push_str(&format!("  Critical: {}\n", critical_count));
    body.push_str(&format!("  High:     {}\n", high_count));
    body.push_str(&format!("  Medium:   {}\n", result.summary.medium));
    body.push_str(&format!("  Low:      {}\n", result.summary.low));
    body.push_str(&format!("  Info:     {}\n\n", result.summary.info));

    body.push_str("Critical/High Findings:\n");
    for f in &result.findings {
        if f.severity == crate::models::Severity::Critical
            || f.severity == crate::models::Severity::High
        {
            body.push_str(&format!("  [{}] {} — {}\n", f.severity, f.id, f.title));
            if !f.recommendation.is_empty() {
                body.push_str(&format!("    Fix: {}\n", f.recommendation));
            }
        }
    }

    // Build raw SMTP message
    let email_to = config.to.join(", ");
    let raw_email = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
        config.from, email_to, subject, body
    );

    log::info!(
        "Email notification prepared: subject='{}', recipients={}",
        subject,
        email_to
    );

    // In a full implementation, this would use an SMTP client (lettre crate).
    // For now, we log the email and optionally write it to a file for debugging.
    if log::log_enabled!(log::Level::Debug) {
        log::debug!("Email body:\n{}", raw_email);
    }

    // Write to a notification file if in dry-run mode
    let notify_path = std::env::temp_dir().join("pledgeshield_email_notification.txt");
    std::fs::write(&notify_path, &raw_email)?;
    log::info!("Email notification written to {}", notify_path.display());

    Ok(())
}
