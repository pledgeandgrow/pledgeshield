use clap::Parser;
use pledgeshield::cli::{Cli, Commands, OutputFormat};
use pledgeshield::models::{ScanResult, Severity};
use pledgeshield::modules::{Module, ModuleRegistry};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            cve,
            modules,
            format,
            output,
            min_severity,
            fix,
            offline,
            refresh_cve,
            nvd_api_key,
            github_token,
            config: config_path,
            baseline: baseline_path,
            save_baseline,
            verify,
        } => {
            run_scan(
                cve,
                modules.as_deref(),
                &format,
                output.as_deref(),
                min_severity.as_deref(),
                fix,
                offline,
                refresh_cve,
                nvd_api_key.as_deref(),
                github_token.as_deref(),
                config_path.as_deref(),
                baseline_path.as_deref(),
                save_baseline.as_deref(),
                verify,
            )
            .await;
        }
        Commands::InitConfig { output } => {
            let sample = pledgeshield::config::PledgeShieldConfig::sample_toml();
            match std::fs::write(&output, &sample) {
                Ok(()) => println!("Sample config written to {}", output.display()),
                Err(e) => eprintln!("Failed to write config: {}", e),
            }
        }
    }
}

async fn run_scan(
    cve: bool,
    module_filter: Option<&[String]>,
    format: &OutputFormat,
    output: Option<&std::path::Path>,
    min_severity: Option<&str>,
    fix: bool,
    offline: bool,
    refresh_cve: bool,
    nvd_api_key: Option<&str>,
    github_token: Option<&str>,
    config_path: Option<&std::path::Path>,
    baseline_path: Option<&std::path::Path>,
    save_baseline: Option<&std::path::Path>,
    verify: bool,
) {
    // Load config
    let cfg = if let Some(path) = config_path {
        match pledgeshield::config::PledgeShieldConfig::load(path) {
            Ok(c) => {
                println!("Loaded config from {}", path.display());
                Some(c)
            }
            Err(e) => {
                eprintln!("Failed to load config from {}: {}", path.display(), e);
                return;
            }
        }
    } else {
        pledgeshield::config::PledgeShieldConfig::load_default()
    };

    // Merge config with CLI args (CLI takes precedence)
    let effective_cve = cve || cfg.as_ref().map(|c| c.scan.cve).unwrap_or(false);
    let effective_offline = offline || cfg.as_ref().map(|c| c.scan.offline).unwrap_or(false);
    let effective_nvd_key = nvd_api_key
        .map(String::from)
        .or_else(|| cfg.as_ref().and_then(|c| c.cve.nvd_api_key.clone()));
    let effective_github_token = github_token
        .map(String::from)
        .or_else(|| cfg.as_ref().and_then(|c| c.cve.github_token.clone()));

    let mut result = ScanResult::new();
    let registry = ModuleRegistry::new();

    let modules_to_run: Vec<&dyn Module> = if let Some(filter) = module_filter {
        registry.get_by_names(filter)
    } else if let Some(cfg) = &cfg {
        if cfg.scan.modules.is_empty() {
            registry.all()
        } else {
            registry.get_by_names(&cfg.scan.modules)
        }
    } else {
        registry.all()
    };

    if modules_to_run.is_empty() {
        eprintln!("No matching modules found.");
        return;
    }

    let total_modules = modules_to_run.len() + if effective_cve { 1 } else { 0 };
    println!("PledgeShield — scanning {} modules...\n", modules_to_run.len());

    let pb = ProgressBar::new(total_modules as u64);
    pb.set_style(
        ProgressStyle::with_template("  {bar:20} {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    // Run modules in parallel using threads
    let findings: Vec<Vec<pledgeshield::models::Finding>> = modules_to_run
        .iter()
        .map(|m| {
            pb.set_message(m.name().to_string());
            let r = m.scan();
            pb.inc(1);
            match r {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("\n  ERROR [{}]: {}", m.id(), e);
                    vec![]
                }
            }
        })
        .collect();

    pb.finish_and_clear();

    // Print module results
    for (i, module) in modules_to_run.iter().enumerate() {
        let count = findings[i].len();
        println!("  [{}] {} — {} findings", module.id(), module.name(), count);
    }

    // Collect findings with exclusions applied
    for module_findings in findings {
        for f in module_findings {
            // Apply config exclusions
            if let Some(ref cfg) = cfg {
                if cfg.is_excluded(&f) {
                    continue;
                }
            }
            result.add_finding(f);
        }
    }

    // CVE module is opt-in
    if effective_cve {
        print!("  [cve] Software vulnerability check... ");
        std::io::stdout().flush().ok();
        let cve_ctx = pledgeshield::cve::CveContext {
            offline: effective_offline,
            refresh: refresh_cve,
            nvd_api_key: effective_nvd_key,
            github_token: effective_github_token,
        };
        match pledgeshield::cve::run_cve_scan(&cve_ctx).await {
            Ok(cve_findings) => {
                let count = cve_findings.len();
                for f in cve_findings {
                    if let Some(ref cfg) = cfg {
                        if cfg.is_excluded(&f) {
                            continue;
                        }
                    }
                    result.add_finding(f);
                }
                println!("{} findings", count);
            }
            Err(e) => println!("ERROR: {}", e),
        }
    }

    // Apply severity filter
    let min_sev = min_severity
        .and_then(Severity::from_str)
        .or_else(|| cfg.as_ref().and_then(|c| c.min_severity()));
    if let Some(min) = min_sev {
        result.filter_by_severity(min);
    }

    // Apply threshold limits
    if let Some(ref cfg) = &cfg {
        if let Some(max_info) = cfg.thresholds.max_info {
            let info_count = result.findings.iter().filter(|f| f.severity == Severity::Info).count();
            if info_count > max_info {
                let mut kept = 0;
                result.findings.retain(|f| {
                    if f.severity == Severity::Info {
                        kept += 1;
                        kept <= max_info
                    } else {
                        true
                    }
                });
            }
        }
    }

    result.finalize();

    // Save baseline if requested
    if let Some(path) = save_baseline {
        if let Err(e) = pledgeshield::baseline::save_baseline(&result, path) {
            eprintln!("Failed to save baseline: {}", e);
        }
    }

    // Baseline diff if requested
    if let Some(path) = baseline_path {
        match pledgeshield::baseline::load_baseline(path) {
            Ok(baseline_result) => {
                let diff = pledgeshield::baseline::diff_against_baseline(&result, &baseline_result);
                print!("{}", pledgeshield::baseline::format_diff(&diff));
            }
            Err(e) => {
                eprintln!("Failed to load baseline: {}", e);
            }
        }
    }

    // Generate report
    if let Err(e) = pledgeshield::output::write_report(&result, format, output) {
        eprintln!("Failed to write report: {}", e);
    }

    // Interactive fix mode
    if fix {
        pledgeshield::fix::run_interactive_fix(&result);
    }

    // Remediation verification: re-scan after fixes and compare
    if verify {
        println!("\n── Remediation Verification ────────────────────");
        println!("Re-scanning to verify fixes...");
        let verify_result = rescan_modules(&modules_to_run);
        let diff = pledgeshield::baseline::diff_against_baseline(&verify_result, &result);
        if diff.resolved_findings.is_empty() && diff.new_findings.is_empty() {
            println!("  No changes detected — fixes may not have been applied.");
        } else {
            println!("  Resolved: {} findings", diff.resolved_findings.len());
            for id in &diff.resolved_findings {
                println!("    \x1b[32m✓\x1b[0m {}", id);
            }
            if !diff.new_findings.is_empty() {
                println!("  New: {} findings", diff.new_findings.len());
                for f in &diff.new_findings {
                    println!("    \x1b[31m!\x1b[0m {} — {}", f.id, f.title);
                }
            }
        }
    }

    // Exit code based on fail_on threshold
    if let Some(ref cfg) = &cfg {
        if let Some(fail_sev) = cfg.thresholds.fail_on.as_deref().and_then(Severity::from_str) {
            let has_fail = result.findings.iter().any(|f| f.severity <= fail_sev);
            if has_fail {
                std::process::exit(2);
            }
        }
    }
}

fn rescan_modules(modules: &[&dyn Module]) -> ScanResult {
    let mut result = ScanResult::new();
    for module in modules {
        if let Ok(findings) = module.scan() {
            for f in findings {
                result.add_finding(f);
            }
        }
    }
    result.finalize();
    result
}
