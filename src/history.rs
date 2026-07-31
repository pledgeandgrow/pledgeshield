use crate::models::ScanResult;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;

/// A single scan history entry.
#[derive(Debug, Clone)]
pub struct ScanHistoryEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub total: i32,
}

/// Scan history database.
pub struct ScanHistory {
    conn: Connection,
}

impl ScanHistory {
    /// Open or create the scan history database.
    pub fn open(path: Option<&std::path::Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = if let Some(p) = path {
            p.to_path_buf()
        } else {
            let mut dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
            dir.push("pledgeshield");
            std::fs::create_dir_all(&dir)?;
            dir.push("history.db");
            dir
        };

        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                os TEXT NOT NULL,
                os_version TEXT NOT NULL,
                critical INTEGER NOT NULL,
                high INTEGER NOT NULL,
                medium INTEGER NOT NULL,
                low INTEGER NOT NULL,
                info INTEGER NOT NULL,
                total INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(ScanHistory { conn })
    }

    /// Record a scan result in the history.
    pub fn record(&self, result: &ScanResult) -> Result<i64, Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT INTO scan_history (timestamp, hostname, os, os_version, critical, high, medium, low, info, total)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                result.scan_completed.to_rfc3339(),
                result.hostname,
                result.os,
                result.os_version,
                result.summary.critical,
                result.summary.high,
                result.summary.medium,
                result.summary.low,
                result.summary.info,
                result.summary.total,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// List all scan history entries, most recent first.
    pub fn list(&self, limit: u32) -> Result<Vec<ScanHistoryEntry>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, hostname, os, os_version, critical, high, medium, low, info, total
             FROM scan_history ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let entries = stmt.query_map(params![limit], |row| {
            let ts: String = row.get(1)?;
            let timestamp = DateTime::parse_from_rfc3339(&ts)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(ScanHistoryEntry {
                id: row.get(0)?,
                timestamp,
                hostname: row.get(2)?,
                os: row.get(3)?,
                os_version: row.get(4)?,
                critical: row.get(5)?,
                high: row.get(6)?,
                medium: row.get(7)?,
                low: row.get(8)?,
                info: row.get(9)?,
                total: row.get(10)?,
            })
        })?;

        let mut results = Vec::new();
        for entry in entries {
            results.push(entry?);
        }
        Ok(results)
    }

    /// Get trend data (total findings over time).
    pub fn trend(&self, limit: u32) -> Result<Vec<(DateTime<Utc>, i32)>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, total FROM scan_history ORDER BY timestamp ASC LIMIT ?1",
        )?;

        let entries = stmt.query_map(params![limit], |row| {
            let ts: String = row.get(0)?;
            let timestamp = DateTime::parse_from_rfc3339(&ts)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok((timestamp, row.get(1)?))
        })?;

        let mut results = Vec::new();
        for entry in entries {
            results.push(entry?);
        }
        Ok(results)
    }

    /// Clear all history entries.
    pub fn clear(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute("DELETE FROM scan_history", [])?;
        Ok(())
    }
}

/// Format scan history as a text table.
pub fn format_history(entries: &[ScanHistoryEntry]) -> String {
    let mut buf = String::new();
    buf.push_str("── Scan History ──────────────────────────────────────\n");
    buf.push_str(&format!(
        "{:<5} {:<22} {:<15} {:<10} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5}\n",
        "ID", "Timestamp", "Host", "OS", "Crit", "High", "Med", "Low", "Info", "Total"
    ));
    buf.push_str(&"─".repeat(80));
    buf.push('\n');

    for e in entries {
        buf.push_str(&format!(
            "{:<5} {:<22} {:<15} {:<10} {:<5} {:<5} {:<5} {:<5} {:<5} {:<5}\n",
            e.id,
            e.timestamp.format("%Y-%m-%d %H:%M"),
            e.hostname,
            e.os,
            e.critical,
            e.high,
            e.medium,
            e.low,
            e.info,
            e.total,
        ));
    }

    buf
}

/// Format trend data as a simple text chart.
pub fn format_trend(trend: &[(DateTime<Utc>, i32)]) -> String {
    if trend.is_empty() {
        return "No history data available.\n".to_string();
    }

    let max_total = trend.iter().map(|(_, t)| *t).max().unwrap_or(1).max(1);
    let bar_width = 40;

    let mut buf = String::new();
    buf.push_str("── Findings Trend ────────────────────────────────────\n");

    for (ts, total) in trend {
        let bar_len = (*total as f64 / max_total as f64 * bar_width as f64) as usize;
        let bar = "█".repeat(bar_len);
        buf.push_str(&format!(
            "  {} │{} ({})\n",
            ts.format("%Y-%m-%d"),
            bar,
            total
        ));
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Finding, ScanResult, Severity};

    fn make_scan_result() -> ScanResult {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test", Severity::Critical, Category::Config));
        result.add_finding(Finding::new("test-2", "Test2", Severity::High, Category::Services));
        result.finalize();
        result
    }

    #[test]
    fn test_history_record_and_list() {
        let db_path = std::env::temp_dir().join("pledgeshield_test_history.db");
        let _ = std::fs::remove_file(&db_path);

        let history = ScanHistory::open(Some(&db_path)).unwrap();
        let result = make_scan_result();

        let id = history.record(&result).unwrap();
        assert!(id > 0);

        let entries = history.list(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hostname, result.hostname);
        assert_eq!(entries[0].critical, 1);
        assert_eq!(entries[0].high, 1);
        assert_eq!(entries[0].total, 2);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_history_trend() {
        let db_path = std::env::temp_dir().join("pledgeshield_test_trend.db");
        let _ = std::fs::remove_file(&db_path);

        let history = ScanHistory::open(Some(&db_path)).unwrap();

        // Record multiple scans
        for i in 0..5 {
            let mut result = ScanResult::new();
            result.add_finding(Finding::new(
                &format!("test-{}", i), "Test", Severity::Critical, Category::Config,
            ));
            result.finalize();
            history.record(&result).unwrap();
        }

        let trend = history.trend(10).unwrap();
        assert_eq!(trend.len(), 5);
        assert!(trend.iter().all(|(_, t)| *t == 1));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_format_history() {
        let entries = vec![
            ScanHistoryEntry {
                id: 1,
                timestamp: Utc::now(),
                hostname: "test-host".to_string(),
                os: "Windows".to_string(),
                os_version: "11".to_string(),
                critical: 2,
                high: 3,
                medium: 1,
                low: 0,
                info: 0,
                total: 6,
            },
        ];

        let formatted = format_history(&entries);
        assert!(formatted.contains("Scan History"));
        assert!(formatted.contains("test-host"));
        assert!(formatted.contains("Windows"));
    }

    #[test]
    fn test_format_trend() {
        let trend = vec![
            (Utc::now(), 5),
            (Utc::now(), 3),
            (Utc::now(), 7),
        ];

        let formatted = format_trend(&trend);
        assert!(formatted.contains("Findings Trend"));
        assert!(formatted.contains("█"));
    }
}
