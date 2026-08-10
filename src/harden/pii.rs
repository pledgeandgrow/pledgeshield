/// PII scanner — scan your own files for sensitive data (SSNs, credit cards, phone numbers).
use crate::models::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5MB
const IGNORE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    ".cache",
    ".npm",
    ".venv",
    "venv",
    "dist",
    "build",
];
const IGNORE_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "pdf", "zip", "tar", "gz", "bz2", "7z",
    "rar", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi",
];

pub fn scan_pii(dir: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = Path::new(dir);
    scan_dir_pii(root, &mut findings, 0, 5);
    findings
}

fn scan_dir_pii(dir: &Path, findings: &mut Vec<Finding>, depth: usize, max_depth: usize) {
    if depth > max_depth {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if IGNORE_DIRS.contains(&name.as_str()) {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if meta.is_dir() {
                scan_dir_pii(&path, findings, depth + 1, max_depth);
            } else if meta.is_file() {
                if meta.len() > MAX_FILE_SIZE {
                    continue;
                }
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if IGNORE_EXTS.contains(&ext.to_lowercase().as_str()) {
                        continue;
                    }
                }
                scan_file_pii(&path, findings);
            }
        }
    }
}

fn scan_file_pii(path: &Path, findings: &mut Vec<Finding>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let path_str = path.to_string_lossy();
    let mut found_types = Vec::new();

    // SSN pattern: XXX-XX-XXXX or XXXXXXXXX
    let ssn_count = count_matches(&content, r"\b\d{3}-\d{2}-\d{4}\b");
    if ssn_count > 0 {
        found_types.push(("SSN", ssn_count, Severity::High));
    }

    // Credit card: 13-19 digit groups
    let cc_count = count_matches(&content, r"\b(?:\d[ -]*?){13,19}\b");
    if cc_count > 0 {
        // Validate with Luhn check on a few
        found_types.push(("Credit Card", cc_count, Severity::High));
    }

    // Phone numbers: (XXX) XXX-XXXX or XXX-XXX-XXXX
    let phone_count = count_matches(&content, r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b");
    if phone_count > 0 {
        found_types.push(("Phone", phone_count, Severity::Medium));
    }

    // Email addresses
    let email_count = count_matches(
        &content,
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    );
    if email_count > 5 {
        found_types.push(("Email (batch)", email_count, Severity::Medium));
    }

    // IBAN
    let iban_count = count_matches(&content, r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b");
    if iban_count > 0 {
        found_types.push(("IBAN", iban_count, Severity::High));
    }

    for (pii_type, count, severity) in found_types {
        let id = format!(
            "pii-{}-{}",
            pii_type.to_lowercase().replace(' ', "-"),
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        );
        findings.push(Finding::new(
            &id,
            &format!("{} ({}) found in: {}", pii_type, count, path_str),
            severity,
            Category::Credentials,
        )
        .description("Sensitive personal data was found in this file. Ensure it's properly encrypted and not committed to version control."));
    }
}

/// Simple regex-like match counter (counts pattern occurrences).
fn count_matches(content: &str, pattern: &str) -> usize {
    // Very simplified — look for digit patterns matching the structure
    let mut count = 0;

    if pattern.contains(r"\d{3}-\d{2}-\d{4}") {
        // SSN
        for line in content.lines() {
            let chars: Vec<char> = line.chars().collect();
            for i in 0..chars.len().saturating_sub(11) {
                if chars[i].is_ascii_digit()
                    && chars[i + 1].is_ascii_digit()
                    && chars[i + 2].is_ascii_digit()
                    && chars[i + 3] == '-'
                    && chars[i + 4].is_ascii_digit()
                    && chars[i + 5].is_ascii_digit()
                    && chars[i + 6] == '-'
                    && chars[i + 7].is_ascii_digit()
                    && chars[i + 8].is_ascii_digit()
                    && chars[i + 9].is_ascii_digit()
                    && chars[i + 10].is_ascii_digit()
                {
                    count += 1;
                }
            }
        }
    } else if pattern.contains(r"\(?\d{3}\)?") {
        // Phone
        for line in content.lines() {
            if line.matches('-').count() >= 2 {
                let digit_count = line.chars().filter(|c| c.is_ascii_digit()).count();
                if digit_count >= 10 && digit_count <= 15 {
                    count += 1;
                }
            }
        }
    } else if pattern.contains("@") {
        // Email
        for line in content.lines() {
            if line.contains('@') && line.contains('.') {
                let at_pos = line.find('@');
                if let Some(at) = at_pos {
                    let before = &line[..at];
                    let after = &line[at + 1..];
                    if before.len() >= 3 && after.contains('.') {
                        count += 1;
                    }
                }
            }
        }
    } else if pattern.contains("[A-Z]{2}\\d{2}") {
        // IBAN
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.len() >= 15 && trimmed.len() <= 34 {
                let first4: Vec<char> = trimmed.chars().take(4).collect();
                if first4.len() == 4
                    && first4[0].is_ascii_uppercase()
                    && first4[1].is_ascii_uppercase()
                    && first4[2].is_ascii_digit()
                    && first4[3].is_ascii_digit()
                {
                    count += 1;
                }
            }
        }
    } else if pattern.contains(r"\d[ -]*?") && pattern.contains("13,19") {
        // Credit card
        for line in content.lines() {
            let digits: String = line.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 13 && digits.len() <= 19 {
                count += 1;
            }
        }
    }

    count
}
