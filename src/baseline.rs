use crate::models::{Finding, ScanResult, Severity};
use std::collections::HashSet;
use std::path::Path;

/// Baseline diff result showing new, resolved, and unchanged findings.
#[derive(Debug)]
pub struct BaselineDiff {
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<String>,
    pub unchanged_count: usize,
}

/// Load a baseline scan result from a JSON file.
pub fn load_baseline(path: &Path) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let result: ScanResult = serde_json::from_str(&content)?;
    Ok(result)
}

/// Save current scan result as a baseline JSON file.
pub fn save_baseline(result: &ScanResult, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(path, json)?;
    log::info!("Baseline saved to {}", path.display());
    Ok(())
}

/// Compare current scan against a baseline.
pub fn diff_against_baseline(current: &ScanResult, baseline: &ScanResult) -> BaselineDiff {
    let baseline_ids: HashSet<&str> = baseline.findings.iter().map(|f| f.id.as_str()).collect();
    let current_ids: HashSet<&str> = current.findings.iter().map(|f| f.id.as_str()).collect();

    let new_findings: Vec<Finding> = current
        .findings
        .iter()
        .filter(|f| !baseline_ids.contains(f.id.as_str()))
        .cloned()
        .collect();

    let resolved_findings: Vec<String> = baseline
        .findings
        .iter()
        .filter(|f| !current_ids.contains(f.id.as_str()))
        .map(|f| f.id.clone())
        .collect();

    let unchanged_count = current
        .findings
        .iter()
        .filter(|f| baseline_ids.contains(f.id.as_str()))
        .count();

    BaselineDiff {
        new_findings,
        resolved_findings,
        unchanged_count,
    }
}

/// Format the baseline diff for display.
pub fn format_diff(diff: &BaselineDiff) -> String {
    let mut buf = String::new();

    buf.push_str("\n── Baseline Diff ───────────────────────────────\n");
    buf.push_str(&format!("  New findings:      {}\n", diff.new_findings.len()));
    buf.push_str(&format!("  Resolved findings: {}\n", diff.resolved_findings.len()));
    buf.push_str(&format!("  Unchanged:         {}\n\n", diff.unchanged_count));

    if !diff.new_findings.is_empty() {
        buf.push_str("── New Findings ────────────────────────────────\n");
        for f in &diff.new_findings {
            let color = f.severity.color_code();
            buf.push_str(&format!("  [{}{}{}] {} — {}\n",
                color, f.severity.as_str().to_uppercase(), "\x1b[0m", f.id, f.title));
        }
        buf.push('\n');
    }

    if !diff.resolved_findings.is_empty() {
        buf.push_str("── Resolved Findings ───────────────────────────\n");
        for id in &diff.resolved_findings {
            buf.push_str(&format!("  \x1b[32m✓ RESOLVED\x1b[0m {}\n", id));
        }
        buf.push('\n');
    }

    // Severity breakdown of new findings
    if !diff.new_findings.is_empty() {
        let critical = diff.new_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = diff.new_findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = diff.new_findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = diff.new_findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = diff.new_findings.iter().filter(|f| f.severity == Severity::Info).count();

        buf.push_str("── New Findings Summary ────────────────────────\n");
        buf.push_str(&format!("  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}\n",
            critical, high, medium, low, info));
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Finding, Severity};

    fn make_scan_result(ids: &[(&str, &str, Severity)]) -> ScanResult {
        let mut result = ScanResult::new();
        for (id, title, sev) in ids {
            result.add_finding(Finding::new(*id, *title, *sev, Category::Config));
        }
        result.finalize();
        result
    }

    #[test]
    fn test_diff_no_changes() {
        let baseline = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Low)]);
        let current = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Low)]);

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 2);
    }

    #[test]
    fn test_diff_new_finding() {
        let baseline = make_scan_result(&[("a", "A", Severity::High)]);
        let current = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Critical)]);

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].id, "b");
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn test_diff_resolved_finding() {
        let baseline = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Low)]);
        let current = make_scan_result(&[("a", "A", Severity::High)]);

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0], "b");
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn test_diff_both_new_and_resolved() {
        let baseline = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Low)]);
        let current = make_scan_result(&[("a", "A", Severity::High), ("c", "C", Severity::Critical)]);

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].id, "c");
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0], "b");
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn test_diff_empty_baseline() {
        let baseline = ScanResult::new();
        let current = make_scan_result(&[("a", "A", Severity::High)]);

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_diff_empty_current() {
        let baseline = make_scan_result(&[("a", "A", Severity::High)]);
        let current = ScanResult::new();

        let diff = diff_against_baseline(&current, &baseline);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_save_and_load_baseline() {
        let result = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Low)]);
        let path = std::env::temp_dir().join("pledgeshield_test_baseline.json");

        save_baseline(&result, &path).unwrap();
        let loaded = load_baseline(&path).unwrap();

        assert_eq!(loaded.findings.len(), 2);
        assert_eq!(loaded.findings[0].id, "a");
        assert_eq!(loaded.findings[1].id, "b");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_format_diff_output() {
        let baseline = make_scan_result(&[("a", "A", Severity::High)]);
        let current = make_scan_result(&[("a", "A", Severity::High), ("b", "B", Severity::Critical)]);

        let diff = diff_against_baseline(&current, &baseline);
        let output = format_diff(&diff);

        assert!(output.contains("New findings:      1"));
        assert!(output.contains("Unchanged:         1"));
        assert!(output.contains("b"));
    }
}
