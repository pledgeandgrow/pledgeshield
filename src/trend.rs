use crate::history::ScanHistory;
use chrono::{DateTime, Utc};

/// Trend dashboard data point.
#[derive(Debug, Clone)]
pub struct TrendPoint {
    pub timestamp: DateTime<Utc>,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub total: i32,
}

/// Get detailed trend data from scan history.
pub fn get_trend_data(
    history: &ScanHistory,
    limit: u32,
) -> Result<Vec<TrendPoint>, Box<dyn std::error::Error>> {
    let entries = history.list(limit)?;

    let trend: Vec<TrendPoint> = entries
        .into_iter()
        .rev()
        .map(|e| TrendPoint {
            timestamp: e.timestamp,
            critical: e.critical,
            high: e.high,
            medium: e.medium,
            low: e.low,
            info: e.info,
            total: e.total,
        })
        .collect();

    Ok(trend)
}

/// Format a visual trend dashboard.
pub fn format_dashboard(trend: &[TrendPoint]) -> String {
    if trend.is_empty() {
        return "No scan history available for trend analysis.\n".to_string();
    }

    let max_total = trend.iter().map(|t| t.total).max().unwrap_or(1).max(1);
    let bar_width = 50;

    let mut buf = String::new();
    buf.push_str("╔══════════════════════════════════════════════════════════╗\n");
    buf.push_str("║          PledgeShield Trend Dashboard                    ║\n");
    buf.push_str("╚══════════════════════════════════════════════════════════╝\n\n");

    // Total findings over time
    buf.push_str("── Total Findings Over Time ──────────────────────────────\n");
    for point in trend {
        let bar_len = (point.total as f64 / max_total as f64 * bar_width as f64) as usize;
        let bar = "█".repeat(bar_len);
        let empty = "░".repeat(bar_width - bar_len);
        buf.push_str(&format!(
            "  {} │{}{} ({})\n",
            point.timestamp.format("%Y-%m-%d"),
            bar,
            empty,
            point.total
        ));
    }

    // Severity breakdown
    buf.push_str("\n── Severity Breakdown ────────────────────────────────────\n");
    buf.push_str(&format!(
        "{:<12} {:<8} {:<8} {:<8} {:<8} {:<8}\n",
        "Date", "Crit", "High", "Med", "Low", "Info"
    ));
    buf.push_str(&"─".repeat(60));
    buf.push('\n');

    for point in trend {
        buf.push_str(&format!(
            "{:<12} {:<8} {:<8} {:<8} {:<8} {:<8}\n",
            point.timestamp.format("%Y-%m-%d").to_string(),
            point.critical,
            point.high,
            point.medium,
            point.low,
            point.info,
        ));
    }

    // Trend analysis
    if trend.len() >= 2 {
        let first = &trend[0];
        let last = &trend[trend.len() - 1];
        let delta = last.total - first.total;

        buf.push_str("\n── Trend Analysis ────────────────────────────────────────\n");
        buf.push_str(&format!(
            "  First scan: {} findings ({})\n",
            first.total,
            first.timestamp.format("%Y-%m-%d")
        ));
        buf.push_str(&format!(
            "  Last scan:  {} findings ({})\n",
            last.total,
            last.timestamp.format("%Y-%m-%d")
        ));

        if delta < 0 {
            buf.push_str(&format!(
                "  Change:     \x1b[32m{} findings (improving)\x1b[0m\n",
                delta
            ));
        } else if delta > 0 {
            buf.push_str(&format!(
                "  Change:     \x1b[31m+{} findings (worsening)\x1b[0m\n",
                delta
            ));
        } else {
            buf.push_str("  Change:     0 findings (stable)\n");
        }

        // Critical trend
        let crit_delta = last.critical - first.critical;
        if crit_delta != 0 {
            buf.push_str(&format!(
                "  Critical:   {} → {} ({})\n",
                first.critical,
                last.critical,
                if crit_delta < 0 {
                    "improving"
                } else {
                    "worsening"
                }
            ));
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_dashboard_empty() {
        let dashboard = format_dashboard(&[]);
        assert!(dashboard.contains("No scan history"));
    }

    #[test]
    fn test_format_dashboard_with_data() {
        let trend = vec![
            TrendPoint {
                timestamp: Utc::now(),
                critical: 2,
                high: 3,
                medium: 1,
                low: 0,
                info: 0,
                total: 6,
            },
            TrendPoint {
                timestamp: Utc::now(),
                critical: 1,
                high: 2,
                medium: 1,
                low: 1,
                info: 0,
                total: 5,
            },
        ];

        let dashboard = format_dashboard(&trend);
        assert!(dashboard.contains("Trend Dashboard"));
        assert!(dashboard.contains("Severity Breakdown"));
        assert!(dashboard.contains("Trend Analysis"));
        assert!(dashboard.contains("improving"));
    }
}
