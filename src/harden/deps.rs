/// Dependency vulnerability scanner — scan package manifests for known CVEs.
use crate::models::{Category, Finding, Severity};
use std::path::Path;

pub fn audit_dependencies(dir: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dir = Path::new(dir);

    // Node.js — package.json + package-lock.json
    let pkg_json = dir.join("package.json");
    let pkg_lock = dir.join("package-lock.json");
    if pkg_json.exists() {
        findings.extend(audit_npm(&pkg_json, &pkg_lock));
    }

    // Rust — Cargo.lock
    let cargo_lock = dir.join("Cargo.lock");
    if cargo_lock.exists() {
        findings.extend(audit_cargo(&cargo_lock));
    }

    // Python — requirements.txt
    let reqs = dir.join("requirements.txt");
    if reqs.exists() {
        findings.extend(audit_python(&reqs));
    }

    // Go — go.sum
    let go_sum = dir.join("go.sum");
    if go_sum.exists() {
        findings.extend(audit_go(&go_sum));
    }

    if findings.is_empty() && !pkg_json.exists() && !cargo_lock.exists() && !reqs.exists() && !go_sum.exists() {
        findings.push(Finding::new(
            "deps-no-manifest",
            "No package manifest found in directory",
            Severity::Info,
            Category::HostConfig,
        )
        .description("No package.json, Cargo.lock, requirements.txt, or go.sum found."));
    }

    findings
}

fn audit_npm(pkg_json: &Path, pkg_lock: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try npm audit
    let out = std::process::Command::new("npm")
        .args(["audit", "--json"])
        .current_dir(pkg_json.parent().unwrap_or(Path::new(".")))
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_object()) {
                for (name, info) in vulns {
                    let severity = info.get("severity").and_then(|s| s.as_str()).unwrap_or("low");
                    let sev = match severity {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "moderate" | "medium" => Severity::Medium,
                        _ => Severity::Low,
                    };
                    findings.push(Finding::new(
                        &format!("dep-npm-{}", name),
                        &format!("npm vulnerability in {}: {}", name, severity),
                        sev,
                        Category::HostConfig,
                    )
                    .description("A vulnerable npm package was found.")
                    .recommendation(&format!("Run: npm audit fix  (or: npm update {})", name))
                    .fixable(true));
                }
            }
        }
    }

    findings
}

fn audit_cargo(cargo_lock: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try cargo audit
    let out = std::process::Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(cargo_lock.parent().unwrap_or(Path::new(".")))
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        // cargo audit output is JSON with "vulnerabilities" array
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    let name = v.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("?");
                    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                    let severity = v.get("severity").and_then(|s| s.as_str()).unwrap_or("medium");
                    let sev = match severity {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        _ => Severity::Medium,
                    };
                    findings.push(Finding::new(
                        &format!("dep-cargo-{}", name),
                        &format!("Rust vulnerability in {}: {}", name, id),
                        sev,
                        Category::HostConfig,
                    )
                    .recommendation(&format!("Run: cargo update -p {}", name))
                    .fixable(true));
                }
            }
        }
    } else {
        // cargo-audit not installed
        findings.push(Finding::new(
            "deps-cargo-audit-missing",
            "cargo-audit not installed — cannot check Rust dependencies",
            Severity::Low,
            Category::HostConfig,
        )
        .description("Install cargo-audit to scan Rust dependencies: cargo install cargo-audit"));
    }

    findings
}

fn audit_python(reqs: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try safety or pip-audit
    let out = std::process::Command::new("pip-audit")
        .args(["-r", reqs.to_str().unwrap_or("requirements.txt"), "--format", "json"])
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                    let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                    findings.push(Finding::new(
                        &format!("dep-py-{}", name),
                        &format!("Python vulnerability in {}: {}", name, id),
                        Severity::High,
                        Category::HostConfig,
                    )
                    .recommendation(&format!("Update: pip install --upgrade {}", name))
                    .fixable(true));
                }
            }
        }
    }

    findings
}

fn audit_go(go_sum: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let out = std::process::Command::new("govulncheck")
        .args(["./..."])
        .current_dir(go_sum.parent().unwrap_or(Path::new(".")))
        .output();

    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            if line.contains("Vulnerability") {
                findings.push(Finding::new(
                    "dep-go-vuln",
                    &format!("Go vulnerability: {}", line),
                    Severity::High,
                    Category::HostConfig,
                )
                .recommendation("Run: go get -u && go mod tidy"));
            }
        }
    }

    findings
}
