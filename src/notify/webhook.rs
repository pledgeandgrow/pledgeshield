use crate::models::ScanResult;

/// Webhook destination type.
#[derive(Debug, Clone)]
pub enum WebhookType {
    Slack,
    Discord,
    Teams,
    Generic,
}

impl WebhookType {
    pub fn from_url(url: &str) -> Self {
        if url.contains("hooks.slack.com") {
            WebhookType::Slack
        } else if url.contains("discord.com/api/webhooks") {
            WebhookType::Discord
        } else if url.contains("office.com") || url.contains("webhook.office.com") {
            WebhookType::Teams
        } else {
            WebhookType::Generic
        }
    }
}

/// Configuration for webhook notifications.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub webhook_type: WebhookType,
}

/// Send a webhook notification about critical findings.
pub async fn send_webhook_notification(
    config: &WebhookConfig,
    result: &ScanResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let critical_count = result.summary.critical;
    let high_count = result.summary.high;

    if critical_count == 0 && high_count == 0 {
        log::info!("No critical/high findings — skipping webhook notification");
        return Ok(());
    }

    let payload = match config.webhook_type {
        WebhookType::Slack => build_slack_payload(result),
        WebhookType::Discord => build_discord_payload(result),
        WebhookType::Teams => build_teams_payload(result),
        WebhookType::Generic => build_generic_payload(result),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&config.url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        log::info!("Webhook notification sent successfully");
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Webhook failed ({}): {}", status, body).into());
    }

    Ok(())
}

fn build_slack_payload(result: &ScanResult) -> serde_json::Value {
    let color = if result.summary.critical > 0 {
        "#ff0000"
    } else if result.summary.high > 0 {
        "#ff7b00"
    } else {
        "#ffcc00"
    };

    let mut fields = vec![
        serde_json::json!({
            "title": "Host",
            "value": result.hostname,
            "short": true,
        }),
        serde_json::json!({
            "title": "OS",
            "value": format!("{} {}", result.os, result.os_version),
            "short": true,
        }),
        serde_json::json!({
            "title": "Critical",
            "value": result.summary.critical.to_string(),
            "short": true,
        }),
        serde_json::json!({
            "title": "High",
            "value": result.summary.high.to_string(),
            "short": true,
        }),
    ];

    // Add top critical findings
    let critical_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == crate::models::Severity::Critical)
        .take(5)
        .collect();

    if !critical_findings.is_empty() {
        let finding_text = critical_findings
            .iter()
            .map(|f| format!("• [{}] {} — {}", f.severity, f.id, f.title))
            .collect::<Vec<_>>()
            .join("\n");
        fields.push(serde_json::json!({
            "title": "Top Critical Findings",
            "value": finding_text,
            "short": false,
        }));
    }

    serde_json::json!({
        "attachments": [{
            "color": color,
            "title": "PledgeShield Security Alert",
            "fields": fields,
            "footer": "PledgeShield",
            "ts": chrono::Utc::now().timestamp(),
        }]
    })
}

fn build_discord_payload(result: &ScanResult) -> serde_json::Value {
    let color = if result.summary.critical > 0 {
        0xFF0000
    } else if result.summary.high > 0 {
        0xFF7B00
    } else {
        0xFFCC00
    };

    let mut description = format!(
        "**PledgeShield Security Alert**\n**Host:** {} | **OS:** {} {}\n**Critical:** {} | **High:** {} | **Medium:** {} | **Low:** {} | **Info:** {}",
        result.hostname,
        result.os,
        result.os_version,
        result.summary.critical,
        result.summary.high,
        result.summary.medium,
        result.summary.low,
        result.summary.info
    );

    let critical_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == crate::models::Severity::Critical)
        .take(5)
        .collect();

    if !critical_findings.is_empty() {
        description.push_str("\n\n**Top Critical Findings:**");
        for f in critical_findings {
            description.push_str(&format!("\n• `{}` — {}", f.id, f.title));
        }
    }

    serde_json::json!({
        "embeds": [{
            "title": "PledgeShield Security Alert",
            "description": description,
            "color": color,
            "footer": { "text": "PledgeShield" },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }]
    })
}

fn build_teams_payload(result: &ScanResult) -> serde_json::Value {
    let theme_color = if result.summary.critical > 0 {
        "FF0000"
    } else if result.summary.high > 0 {
        "FF7B00"
    } else {
        "FFCC00"
    };

    let mut facts = vec![
        serde_json::json!({ "name": "Host", "value": result.hostname }),
        serde_json::json!({ "name": "OS", "value": format!("{} {}", result.os, result.os_version) }),
        serde_json::json!({ "name": "Critical", "value": result.summary.critical.to_string() }),
        serde_json::json!({ "name": "High", "value": result.summary.high.to_string() }),
        serde_json::json!({ "name": "Medium", "value": result.summary.medium.to_string() }),
        serde_json::json!({ "name": "Low", "value": result.summary.low.to_string() }),
    ];

    let critical_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == crate::models::Severity::Critical)
        .take(3)
        .collect();

    for f in critical_findings {
        facts.push(serde_json::json!({
            "name": format!("⚠ {}", f.id),
            "value": f.title,
        }));
    }

    serde_json::json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": "PledgeShield Security Alert",
        "sections": [{
            "activityTitle": "PledgeShield Security Alert",
            "facts": facts,
        }]
    })
}

fn build_generic_payload(result: &ScanResult) -> serde_json::Value {
    serde_json::json!({
        "tool": "PledgeShield",
        "hostname": result.hostname,
        "os": result.os,
        "os_version": result.os_version,
        "summary": {
            "critical": result.summary.critical,
            "high": result.summary.high,
            "medium": result.summary.medium,
            "low": result.summary.low,
            "info": result.summary.info,
            "total": result.summary.total,
        },
        "scan_time": result.scan_completed.to_rfc3339(),
        "findings": result.findings.iter().filter(|f| {
            f.severity == crate::models::Severity::Critical || f.severity == crate::models::Severity::High
        }).map(|f| {
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.to_string(),
                "category": f.category.to_string(),
                "description": f.description,
                "recommendation": f.recommendation,
            })
        }).collect::<Vec<_>>(),
    })
}
