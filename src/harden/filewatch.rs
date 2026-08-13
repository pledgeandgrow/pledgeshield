/// New file watcher — monitor critical directories for newly created executables.
use crate::models::{Category, Finding, Severity};
use std::collections::HashSet;
use std::path::Path;

const WATCH_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/etc",
    "/lib",
    "/usr/lib",
];

#[allow(dead_code)]
const EXECUTABLE_EXTS: &[&str] = &[
    "sh", "py", "pl", "rb", "php", "js", "exe", "bat", "cmd", "ps1", "vbs", "scr", "so", "dll",
    "dylib",
];

pub fn audit_new_files() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get baseline (if exists)
    let baseline = load_baseline();
    let current = scan_dirs();

    // Find new files not in baseline
    for file in &current {
        if !baseline.contains(file) {
            // Check if it's executable
            let path = Path::new(file);
            let is_exec = is_executable(path);
            let is_in_critical = WATCH_DIRS.iter().any(|d| file.starts_with(d));

            if is_exec || is_in_critical {
                let severity = if is_in_critical {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding::new(
                    &format!("filewatch-new-{}", file.replace('/', "_")),
                    &format!("New file detected: {}", file),
                    severity,
                    Category::HostConfig,
                )
                .description("A new file was created in a critical system directory. Verify this is from a legitimate package update."));
            }
        }
    }

    // Save current state as new baseline
    save_baseline(&current);

    findings
}

fn scan_dirs() -> HashSet<String> {
    let mut files = HashSet::new();

    #[cfg(target_os = "linux")]
    {
        for dir in WATCH_DIRS {
            let path = Path::new(dir);
            if path.exists() {
                scan_dir_recursive(path, &mut files, 0, 3);
            }
        }
    }

    files
}

#[cfg(target_os = "linux")]
fn scan_dir_recursive(dir: &Path, files: &mut HashSet<String>, depth: usize, max_depth: usize) {
    if depth > max_depth {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    files.insert(path.to_string_lossy().to_string());
                } else if meta.is_dir() {
                    scan_dir_recursive(&path, files, depth + 1, max_depth);
                }
            }
        }
    }
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            return mode & 0o111 != 0;
        }
        false
    }
    #[cfg(not(unix))]
    {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| EXECUTABLE_EXTS.contains(&e.to_lowercase().as_str()))
            .unwrap_or(false)
    }
}

fn baseline_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    home.join(".local/share/pledgeshield/filewatch-baseline.txt")
}

fn load_baseline() -> HashSet<String> {
    let path = baseline_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        content.lines().map(String::from).collect()
    } else {
        HashSet::new()
    }
}

fn save_baseline(files: &HashSet<String>) {
    let path = baseline_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content: Vec<String> = files.iter().cloned().collect();
    let _ = std::fs::write(&path, content.join("\n"));
}

/// Create initial baseline (no findings, just snapshot).
pub fn create_baseline() -> String {
    let current = scan_dirs();
    save_baseline(&current);
    format!("Baseline created with {} files.", current.len())
}

/// Monitor for new files in real-time.
pub fn monitor_new_files(interval: u64, max_runtime: u64) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PledgeShield New File Watcher                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Watching for new executables in system directories");
    println!("  Press Ctrl+C to stop.\n");

    let start = std::time::Instant::now();
    loop {
        let findings = audit_new_files();
        let now = chrono::Utc::now().format("%H:%M:%S");
        for f in &findings {
            println!("  {} [{}] {}", now, f.severity, f.title);
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
        if max_runtime > 0 && start.elapsed().as_secs() >= max_runtime {
            println!("\n  Stopping.");
            break;
        }
    }
}
