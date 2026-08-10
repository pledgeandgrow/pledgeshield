use crate::cli::OutputFormat;
use crate::models::{Finding, ScanResult};
use std::io::{self, Write};

const RESET: &str = "\x1b[0m";

/// Write the scan result in the requested format to the given output path,
/// or stdout if no path is provided.
pub fn write_report(result: &ScanResult, format: &OutputFormat, output: Option<&std::path::Path>) -> io::Result<()> {
    match format {
        OutputFormat::Text => write_text(result, output),
        OutputFormat::Json => write_json(result, output),
        OutputFormat::Html => write_html(result, output),
        OutputFormat::Sarif => write_sarif(result, output),
        OutputFormat::Markdown => write_markdown(result, output),
        OutputFormat::Pdf => write_pdf(result, output),
    }
}

fn write_text(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    let mut buf = String::new();

    buf.push_str(&format!("\n╔══════════════════════════════════════════════╗\n"));
    buf.push_str(&format!("║          PledgeShield Security Report         ║\n"));
    buf.push_str(&format!("╚══════════════════════════════════════════════╝\n\n"));
    buf.push_str(&format!("Host:      {}\n", result.hostname));
    buf.push_str(&format!("OS:        {} {}\n", result.os, result.os_version));
    buf.push_str(&format!("Started:   {}\n", result.scan_started.format("%Y-%m-%d %H:%M:%S UTC")));
    buf.push_str(&format!("Completed: {}\n\n", result.scan_completed.format("%Y-%m-%d %H:%M:%S UTC")));

    // Summary
    buf.push_str("── Summary ──────────────────────────────────────\n");
    buf.push_str(&format!("  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}\n",
        result.summary.critical, result.summary.high, result.summary.medium,
        result.summary.low, result.summary.info));
    buf.push_str(&format!("  Total findings: {}\n\n", result.summary.total));

    if result.findings.is_empty() {
        buf.push_str("No findings. System looks hardened.\n");
    } else {
        for f in &result.findings {
            buf.push_str(&format_finding(f));
        }
    }

    write_output(&buf, output)
}

fn format_finding(f: &Finding) -> String {
    let color = f.severity.color_code();
    let mut s = String::new();
    s.push_str(&format!("── {} [{}{}{}] ─────────────────────────────\n",
        f.title, color, f.severity.as_str().to_uppercase(), RESET));
    s.push_str(&format!("  ID:          {}\n", f.id));
    s.push_str(&format!("  Category:    {}\n", f.category));
    if !f.description.is_empty() {
        s.push_str(&format!("  Description: {}\n", f.description));
    }
    if !f.recommendation.is_empty() {
        s.push_str(&format!("  Fix:         {}\n", f.recommendation));
    }
    if f.fixable {
        s.push_str("  Fixable:      yes\n");
    }
    if !f.metadata.is_empty() {
        s.push_str("  Details:\n");
        for (k, v) in &f.metadata {
            s.push_str(&format!("    {}: {}\n", k, v));
        }
    }
    s.push('\n');
    s
}

fn write_json(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    write_output(&json, output)
}

fn write_html(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    let template = include_str!("../templates/report.html");
    let findings_json = serde_json::to_string_pretty(result)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let html = template.replace("{{SCAN_RESULT_JSON}}", &findings_json);
    write_output(&html, output)
}

fn write_output(content: &str, output: Option<&std::path::Path>) -> io::Result<()> {
    match output {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(content.as_bytes())?;
            file.flush()?;
            println!("Report written to {}", path.display());
        }
        None => {
            print!("{}", content);
        }
    }
    Ok(())
}

fn write_sarif(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    use serde_json::json;

    let rules: Vec<serde_json::Value> = result.findings.iter().map(|f| {
        json!({
            "id": f.id,
            "name": f.title,
            "shortDescription": { "text": f.title },
            "fullDescription": { "text": f.description },
            "helpUri": format!("https://pledgeandgrow.com/findings/{}", f.id),
            "defaultConfiguration": {
                "level": severity_to_sarif_level(&f.severity)
            },
            "properties": {
                "category": f.category.to_string(),
                "fixable": f.fixable,
                "recommendation": f.recommendation,
            }
        })
    }).collect();

    let results: Vec<serde_json::Value> = result.findings.iter().map(|f| {
        json!({
            "ruleId": f.id,
            "level": severity_to_sarif_level(&f.severity),
            "message": { "text": f.description },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": result.hostname
                    }
                }
            }],
            "properties": {
                "severity": f.severity.as_str(),
                "category": f.category.to_string(),
                "recommendation": f.recommendation,
                "fixable": f.fixable,
                "metadata": f.metadata,
            }
        })
    }).collect();

    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PledgeShield",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://pledgeandgrow.com",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": result.scan_started.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "endTimeUtc": result.scan_completed.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            }],
            "properties": {
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
                }
            }
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    write_output(&json, output)
}

fn severity_to_sarif_level(severity: &crate::models::Severity) -> &'static str {
    match severity {
        crate::models::Severity::Critical => "error",
        crate::models::Severity::High => "error",
        crate::models::Severity::Medium => "warning",
        crate::models::Severity::Low => "note",
        crate::models::Severity::Info => "none",
    }
}

fn write_markdown(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    let mut buf = String::new();

    buf.push_str("# PledgeShield Security Report\n\n");
    buf.push_str(&format!("**Host:** {}  \n", result.hostname));
    buf.push_str(&format!("**OS:** {} {}  \n", result.os, result.os_version));
    buf.push_str(&format!("**Scanned:** {}  \n\n", result.scan_completed.format("%Y-%m-%d %H:%M:%S UTC")));

    // Summary table
    buf.push_str("## Summary\n\n");
    buf.push_str("| Severity | Count |\n");
    buf.push_str("|----------|-------|\n");
    buf.push_str(&format!("| Critical | {} |\n", result.summary.critical));
    buf.push_str(&format!("| High     | {} |\n", result.summary.high));
    buf.push_str(&format!("| Medium   | {} |\n", result.summary.medium));
    buf.push_str(&format!("| Low      | {} |\n", result.summary.low));
    buf.push_str(&format!("| Info     | {} |\n", result.summary.info));
    buf.push_str(&format!("| **Total**| **{}** |\n\n", result.summary.total));

    if result.findings.is_empty() {
        buf.push_str("No findings. System looks hardened.\n");
    } else {
        buf.push_str("## Findings\n\n");
        for f in &result.findings {
            buf.push_str(&format!("### {} [{}]\n\n", f.title, f.severity.as_str().to_uppercase()));
            buf.push_str(&format!("- **ID:** {}\n", f.id));
            buf.push_str(&format!("- **Category:** {}\n", f.category));
            if !f.description.is_empty() {
                buf.push_str(&format!("- **Description:** {}\n", f.description));
            }
            if !f.recommendation.is_empty() {
                buf.push_str(&format!("- **Recommendation:** {}\n", f.recommendation));
            }
            if f.fixable {
                buf.push_str("- **Fixable:** yes\n");
            }
            if !f.metadata.is_empty() {
                buf.push_str("- **Details:**\n");
                for (k, v) in &f.metadata {
                    buf.push_str(&format!("  - `{}`: {}\n", k, v));
                }
            }
            buf.push('\n');
        }
    }

    write_output(&buf, output)
}

fn write_pdf(result: &ScanResult, output: Option<&std::path::Path>) -> io::Result<()> {
    // Generate an HTML document styled for print, then instruct the user
    // to convert to PDF. A full PDF library would add heavy dependencies;
    // instead we produce a print-ready HTML that can be saved as PDF.
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">");
    html.push_str("<title>PledgeShield Security Report</title>");
    html.push_str("<style>");
    html.push_str("body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; margin: 2cm; line-height: 1.5; }");
    html.push_str("h1 { font-size: 1.5rem; border-bottom: 2px solid #333; padding-bottom: 0.5rem; }");
    html.push_str("h2 { font-size: 1.2rem; margin-top: 1.5rem; }");
    html.push_str("table { border-collapse: collapse; width: 100%; margin: 1rem 0; }");
    html.push_str("th, td { border: 1px solid #ccc; padding: 0.4rem 0.8rem; text-align: left; }");
    html.push_str("th { background: #f0f0f0; font-weight: 600; }");
    html.push_str(".finding { border: 1px solid #ddd; border-radius: 4px; padding: 0.8rem; margin: 0.8rem 0; }");
    html.push_str(".severity-critical { color: #c0392b; font-weight: bold; }");
    html.push_str(".severity-high { color: #e74c3c; font-weight: bold; }");
    html.push_str(".severity-medium { color: #f39c12; font-weight: bold; }");
    html.push_str(".severity-low { color: #2980b9; font-weight: bold; }");
    html.push_str(".severity-info { color: #7f8c8d; font-weight: bold; }");
    html.push_str("@media print { body { margin: 1cm; } .no-print { display: none; } }");
    html.push_str("</style></head><body>");

    html.push_str("<h1>PledgeShield Security Report</h1>");
    html.push_str(&format!("<p><strong>Host:</strong> {} | <strong>OS:</strong> {} {} | <strong>Scanned:</strong> {}</p>",
        result.hostname, result.os, result.os_version,
        result.scan_completed.format("%Y-%m-%d %H:%M:%S UTC")));

    html.push_str("<h2>Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>");
    html.push_str(&format!("<tr><td class=\"severity-critical\">Critical</td><td>{}</td></tr>", result.summary.critical));
    html.push_str(&format!("<tr><td class=\"severity-high\">High</td><td>{}</td></tr>", result.summary.high));
    html.push_str(&format!("<tr><td class=\"severity-medium\">Medium</td><td>{}</td></tr>", result.summary.medium));
    html.push_str(&format!("<tr><td class=\"severity-low\">Low</td><td>{}</td></tr>", result.summary.low));
    html.push_str(&format!("<tr><td class=\"severity-info\">Info</td><td>{}</td></tr>", result.summary.info));
    html.push_str(&format!("<tr><td><strong>Total</strong></td><td><strong>{}</strong></td></tr></table>", result.summary.total));

    if !result.findings.is_empty() {
        html.push_str("<h2>Findings</h2>");
        for f in &result.findings {
            html.push_str(&format!("<div class=\"finding\"><h3>{} <span class=\"severity-{}\">[{}]</span></h3>", f.title, f.severity, f.severity.as_str().to_uppercase()));
            html.push_str(&format!("<p><strong>ID:</strong> {} | <strong>Category:</strong> {}{}</p>",
                f.id, f.category, if f.fixable { " | <strong>Fixable</strong>" } else { "" }));
            if !f.description.is_empty() {
                html.push_str(&format!("<p>{}</p>", f.description));
            }
            if !f.recommendation.is_empty() {
                html.push_str(&format!("<p><strong>Recommendation:</strong> {}</p>", f.recommendation));
            }
            if !f.metadata.is_empty() {
                html.push_str("<ul>");
                for (k, v) in &f.metadata {
                    html.push_str(&format!("<li><strong>{}:</strong> {}</li>", k, v));
                }
                html.push_str("</ul>");
            }
            html.push_str("</div>");
        }
    }

    html.push_str("</body></html>");

    // If output path ends in .pdf, write as .html with a note
    let path = if let Some(p) = output {
        if p.extension().and_then(|e| e.to_str()) == Some("pdf") {
            // Change extension to .html for the print-ready file
            p.with_extension("html")
        } else {
            p.to_path_buf()
        }
    } else {
        // No path given — write HTML to stdout
        return write_output(&html, None);
    };

    write_output(&html, Some(&path))?;

    if output.and_then(|p| p.extension()).and_then(|e| e.to_str()) == Some("pdf") {
        eprintln!("  → Print-ready HTML written to {}. Open in browser and use 'Save as PDF'.", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Finding, ScanResult, Severity};

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "none");
    }

    #[test]
    fn test_write_report_text() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::High, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join("pledgeshield_test_report.txt");
        let r = write_report(&result, &OutputFormat::Text, Some(&path));
        assert!(r.is_ok());
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_report_json() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::High, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join("pledgeshield_test_report.json");
        let r = write_report(&result, &OutputFormat::Json, Some(&path));
        assert!(r.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test-1"));
        assert!(content.contains("Test Finding"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_report_sarif() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::High, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join("pledgeshield_test_report.sarif");
        let r = write_report(&result, &OutputFormat::Sarif, Some(&path));
        assert!(r.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("$schema"));
        assert!(content.contains("2.1.0"));
        assert!(content.contains("PledgeShield"));
        assert!(content.contains("test-1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_report_html() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::High, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join(format!("pledgeshield_test_report_{}.html", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let r = write_report(&result, &OutputFormat::Html, Some(&path));
        assert!(r.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains("<html") || content.contains("<!DOCTYPE"), "HTML content missing doctype/html tag");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_report_markdown() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::High, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join("pledgeshield_test_report.md");
        let r = write_report(&result, &OutputFormat::Markdown, Some(&path));
        assert!(r.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# PledgeShield Security Report"));
        assert!(content.contains("## Summary"));
        assert!(content.contains("| Severity | Count |"));
        assert!(content.contains("test-1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_report_pdf() {
        let mut result = ScanResult::new();
        result.add_finding(Finding::new("test-1", "Test Finding", Severity::Critical, Category::Config));
        result.finalize();

        let path = std::env::temp_dir().join("pledgeshield_test_report.pdf");
        let r = write_report(&result, &OutputFormat::Pdf, Some(&path));
        assert!(r.is_ok());

        // PDF writer creates an .html file instead
        let html_path = path.with_extension("html");
        assert!(html_path.exists());
        let content = std::fs::read_to_string(&html_path).unwrap();
        assert!(content.contains("<html"));
        assert!(content.contains("PledgeShield"));
        let _ = std::fs::remove_file(&html_path);
    }
}
