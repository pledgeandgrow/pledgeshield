/// Secret scanner — scan your own codebase/configs for committed API keys, tokens, private keys.
use crate::models::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

const SECRET_PATTERNS: &[(&str, &str, Severity)] = &[
    // (regex-ish pattern, description, severity)
    ("AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::Critical),
    (
        "aws_secret_access_key",
        "AWS Secret Access Key",
        Severity::Critical,
    ),
    (
        "ghp_[0-9a-zA-Z]{36}",
        "GitHub Personal Access Token",
        Severity::Critical,
    ),
    (
        "gho_[0-9a-zA-Z]{36}",
        "GitHub OAuth Token",
        Severity::Critical,
    ),
    (
        "github_pat_[0-9a-zA-Z_]{82}",
        "GitHub Fine-grained PAT",
        Severity::Critical,
    ),
    (
        "glpat-[0-9a-zA-Z_-]{20}",
        "GitLab Personal Access Token",
        Severity::Critical,
    ),
    (
        "xox[baprs]-[0-9a-zA-Z-]{10,}",
        "Slack Token",
        Severity::High,
    ),
    (
        "sk_live_[0-9a-zA-Z]{24}",
        "Stripe Live Secret Key",
        Severity::Critical,
    ),
    (
        "sk_test_[0-9a-zA-Z]{24}",
        "Stripe Test Secret Key",
        Severity::Medium,
    ),
    ("AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity::High),
    (
        "ya29.[0-9A-Za-z_-]+",
        "Google OAuth Access Token",
        Severity::High,
    ),
    (
        "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*",
        "JWT Token",
        Severity::High,
    ),
    (
        "-----BEGIN RSA PRIVATE KEY-----",
        "RSA Private Key",
        Severity::Critical,
    ),
    (
        "-----BEGIN EC PRIVATE KEY-----",
        "EC Private Key",
        Severity::Critical,
    ),
    (
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "OpenSSH Private Key",
        Severity::Critical,
    ),
    (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "PGP Private Key",
        Severity::Critical,
    ),
    (
        "api_key\\s*[:=]\\s*['\"][^'\"]{20,}['\"]",
        "API Key in config",
        Severity::High,
    ),
    (
        "secret\\s*[:=]\\s*['\"][^'\"]{20,}['\"]",
        "Secret in config",
        Severity::High,
    ),
    (
        "password\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
        "Password in config",
        Severity::High,
    ),
    (
        "token\\s*[:=]\\s*['\"][^'\"]{20,}['\"]",
        "Token in config",
        Severity::High,
    ),
    (
        "private_key\\s*[:=]\\s*['\"][^'\"]{20,}['\"]",
        "Private key in config",
        Severity::Critical,
    ),
];

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
    ".next",
    ".nuxt",
    ".gradle",
    ".idea",
    ".vscode",
];

const IGNORE_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "pdf", "zip", "tar", "gz", "bz2", "7z",
    "rar", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi", "lock", "toml", "sum",
];

const MAX_FILE_SIZE: u64 = 1024 * 1024; // 1MB

pub fn scan_secrets(dir: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = Path::new(dir);
    scan_dir(root, &mut findings, 0, 10);
    findings
}

fn scan_dir(dir: &Path, findings: &mut Vec<Finding>, depth: usize, max_depth: usize) {
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

        // Skip ignored directories
        if IGNORE_DIRS.contains(&name.as_str()) {
            continue;
        }

        if let Ok(meta) = entry.metadata() {
            if meta.is_dir() {
                scan_dir(&path, findings, depth + 1, max_depth);
            } else if meta.is_file() {
                // Skip large files
                if meta.len() > MAX_FILE_SIZE {
                    continue;
                }

                // Skip ignored extensions
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if IGNORE_EXTS.contains(&ext.to_lowercase().as_str()) {
                        continue;
                    }
                }

                scan_file(&path, findings);
            }
        }
    }
}

fn scan_file(path: &Path, findings: &mut Vec<Finding>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return, // Binary file or permission error
    };

    let path_str = path.to_string_lossy();
    let mut found_in_file = Vec::new();

    for (pattern, desc, severity) in SECRET_PATTERNS {
        // Simple substring match for literal patterns, regex-ish for others
        if pattern.contains('\\') || pattern.contains('[') {
            // Regex pattern — do a simplified match
            if simple_regex_match(pattern, &content) {
                found_in_file.push((desc, *severity));
            }
        } else {
            if content.contains(pattern) {
                found_in_file.push((desc, *severity));
            }
        }
    }

    for (desc, severity) in found_in_file {
        let id = format!(
            "secret-{}-{}",
            desc.replace(' ', "-").to_lowercase(),
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        );
        findings.push(Finding::new(
            &id,
            &format!("{} found in: {}", desc, path_str),
            severity,
            Category::Credentials,
        )
        .description("A secret was found in a file. If this file is committed to a repository, the secret is exposed.")
        .recommendation("Remove the secret from the file, rotate it, and add the file to .gitignore"));
    }
}

/// Very simplified regex matching — just checks if the pattern's literal parts exist
fn simple_regex_match(pattern: &str, content: &str) -> bool {
    // Extract literal prefixes (before any regex metachar)
    let literals: Vec<&str> = pattern
        .split(|c: char| c == '\\' || c == '[' || c == '.')
        .filter(|s| s.len() > 3)
        .collect();
    for lit in literals {
        if content.contains(lit) {
            return true;
        }
    }
    false
}
