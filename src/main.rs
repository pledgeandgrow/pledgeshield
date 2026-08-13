use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use pledgeshield::cli::{Cli, Commands, HardenAction, OutputFormat, TorAction, VpnAction};
use pledgeshield::models::{ScanResult, Severity};
use pledgeshield::modules::{Module, ModuleRegistry};
use std::io::Write;

fn main() {
    // Use a larger stack (8MB) to handle the large HardenAction enum
    // which causes stack overflow on Windows debug builds with default 1MB stack
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(real_main)
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::main]
async fn real_main() {
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
            compliance,
            save_history,
            custom_checks,
            notify_webhook,
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
                compliance,
                save_history,
                custom_checks.as_deref(),
                notify_webhook.as_deref(),
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
        Commands::History { limit, clear } => {
            run_history(limit, clear);
        }
        Commands::Trend { limit } => {
            run_trend(limit);
        }
        Commands::Schedule {
            cron,
            command,
            remove,
        } => {
            run_schedule(cron, command, remove);
        }
        Commands::Harden { action } => {
            run_harden(action);
        }
        Commands::Vpn { action } => {
            run_vpn(action);
        }
        Commands::Monitor {
            interval,
            no_ports,
            no_processes,
            no_firewall,
            max_runtime,
        } => {
            let config = pledgeshield::monitor::MonitorConfig {
                interval,
                watch_ports: !no_ports,
                watch_processes: !no_processes,
                watch_firewall: !no_firewall,
                max_runtime,
            };
            run_monitor(config);
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
    compliance: bool,
    save_history: bool,
    custom_checks_path: Option<&std::path::Path>,
    notify_webhook: Option<&str>,
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
    println!(
        "PledgeShield — scanning {} modules...\n",
        modules_to_run.len()
    );

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

    // Custom user-defined checks (loaded from TOML/YAML)
    if let Some(path) = custom_checks_path {
        let custom_cfg = if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            pledgeshield::custom::load_custom_checks_yaml(path)
        } else {
            pledgeshield::custom::load_custom_checks(path)
        };
        match custom_cfg {
            Ok(c) => {
                let custom_findings = pledgeshield::custom::run_custom_checks(&c);
                let count = custom_findings.len();
                for f in custom_findings {
                    if let Some(ref cfg) = cfg {
                        if cfg.is_excluded(&f) {
                            continue;
                        }
                    }
                    result.add_finding(f);
                }
                println!("  [custom] User-defined checks — {} findings", count);
            }
            Err(e) => eprintln!("  [custom] Failed to load custom checks: {}", e),
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
    if let Some(cfg) = &cfg {
        if let Some(max_info) = cfg.thresholds.max_info {
            let info_count = result
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count();
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

    // Compliance mapping (CIS Benchmarks / NIST SP 800-53)
    if compliance {
        let (mapped, cis, nist) = pledgeshield::compliance::compliance_summary(&result.findings);
        println!("\n── Compliance Mapping ──────────────────────────");
        println!(
            "  {} of {} findings mapped (CIS: {}, NIST: {})",
            mapped,
            result.findings.len(),
            cis,
            nist
        );
        print!(
            "{}",
            pledgeshield::compliance::generate_compliance_report(&result.findings)
        );
    }

    // Record scan in history database
    let should_save_history =
        save_history || cfg.as_ref().map(|c| c.history.enabled).unwrap_or(false);
    if should_save_history {
        let hist_path = cfg
            .as_ref()
            .and_then(|c| c.history.path.as_deref())
            .map(std::path::PathBuf::from);
        match pledgeshield::history::ScanHistory::open(hist_path.as_deref()) {
            Ok(history) => {
                if let Err(e) = history.record(&result) {
                    eprintln!("Failed to record scan history: {}", e);
                } else {
                    println!("\nScan recorded to history database.");
                }
            }
            Err(e) => eprintln!("Failed to open history database: {}", e),
        }
    }

    // Notifications on critical/high findings
    let webhook_url = notify_webhook
        .map(String::from)
        .or_else(|| cfg.as_ref().and_then(|c| c.notify.webhook_url.clone()));
    if let Some(url) = webhook_url {
        if result.summary.critical > 0 || result.summary.high > 0 {
            let wh_cfg = pledgeshield::notify::webhook::WebhookConfig {
                webhook_type: pledgeshield::notify::webhook::WebhookType::from_url(&url),
                url,
            };
            if let Err(e) =
                pledgeshield::notify::webhook::send_webhook_notification(&wh_cfg, &result).await
            {
                eprintln!("Webhook notification failed: {}", e);
            } else {
                println!("Webhook notification sent.");
            }
        }
    }
    if let Some(email_cfg) = cfg.as_ref().and_then(|c| c.notify.email.as_ref()) {
        if !email_cfg.smtp_host.is_empty() {
            let ec = pledgeshield::notify::email::EmailConfig {
                smtp_host: email_cfg.smtp_host.clone(),
                smtp_port: email_cfg.smtp_port,
                from: email_cfg.from.clone(),
                to: email_cfg.to.clone(),
                username: email_cfg.username.clone(),
                password: email_cfg.password.clone(),
                use_tls: email_cfg.use_tls,
            };
            if let Err(e) = pledgeshield::notify::email::send_critical_notification(&ec, &result) {
                eprintln!("Email notification failed: {}", e);
            }
        }
    }

    // Exit code based on fail_on threshold
    if let Some(cfg) = &cfg {
        if let Some(fail_sev) = cfg
            .thresholds
            .fail_on
            .as_deref()
            .and_then(Severity::from_str)
        {
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

fn run_history(limit: u32, clear: bool) {
    match pledgeshield::history::ScanHistory::open(None) {
        Ok(history) => {
            if clear {
                match history.clear() {
                    Ok(()) => println!("Scan history cleared."),
                    Err(e) => eprintln!("Failed to clear history: {}", e),
                }
                return;
            }
            match history.list(limit) {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No scan history recorded yet.");
                    } else {
                        print!("{}", pledgeshield::history::format_history(&entries));
                    }
                }
                Err(e) => eprintln!("Failed to read history: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to open history database: {}", e),
    }
}

fn run_trend(limit: u32) {
    match pledgeshield::history::ScanHistory::open(None) {
        Ok(history) => match pledgeshield::trend::get_trend_data(&history, limit) {
            Ok(trend) => {
                print!("{}", pledgeshield::trend::format_dashboard(&trend));
            }
            Err(e) => eprintln!("Failed to read trend data: {}", e),
        },
        Err(e) => eprintln!("Failed to open history database: {}", e),
    }
}

fn run_schedule(cron: String, command: String, remove: bool) {
    if remove {
        match pledgeshield::notify::schedule::remove_schedule("PledgeShieldScheduledScan") {
            Ok(()) => println!("Scheduled scan removed."),
            Err(e) => eprintln!("Failed to remove scheduled scan: {}", e),
        }
        return;
    }
    let sched = pledgeshield::notify::schedule::ScheduleConfig { cron, command };
    match pledgeshield::notify::schedule::install_schedule(&sched) {
        Ok(()) => println!("Scheduled scan installed."),
        Err(e) => eprintln!("Failed to install scheduled scan: {}", e),
    }
}

fn run_harden(action: HardenAction) {
    match action {
        HardenAction::Ports {
            all,
            dry_run,
            restore,
        } => {
            if restore {
                println!("\n── Restoring firewall (removing PledgeShield block rules) ──");
                for r in pledgeshield::harden::ports::restore_ports() {
                    println!("{}", r);
                }
                return;
            }
            // First show what's open
            let findings = pledgeshield::harden::ports::audit_insecure_ports();
            if findings.is_empty() && !all {
                println!("\n  ✓ No known-insecure ports found listening.");
            } else if !findings.is_empty() {
                println!("\n── Insecure ports detected ──────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
            println!("\n── Closing ports ────────────────────────────────");
            for r in pledgeshield::harden::ports::close_insecure_ports(dry_run, all) {
                println!("{}", r);
            }
        }
        HardenAction::Mac {
            interface,
            mac,
            list,
            restore,
        } => {
            if list {
                let ifaces = pledgeshield::harden::mac::list_interfaces();
                if ifaces.is_empty() {
                    println!("No network interfaces found.");
                } else {
                    println!("Available network interfaces:");
                    for iface in &ifaces {
                        let current = pledgeshield::harden::mac::get_mac(iface)
                            .unwrap_or_else(|_| "?".to_string());
                        println!("  {} — current MAC: {}", iface, current);
                    }
                }
                return;
            }
            let iface = match interface {
                Some(i) => i,
                None => {
                    eprintln!("Error: --interface is required (use --list to see available).");
                    return;
                }
            };
            if restore {
                let r = pledgeshield::harden::mac::restore_mac(&iface);
                println!("{}", r);
                return;
            }
            let r = pledgeshield::harden::mac::spoof_mac(&iface, mac.as_deref());
            println!("{}", r);
        }
        HardenAction::Identity { dry_run } => {
            // First audit
            let findings = pledgeshield::harden::identity::audit_identity_exposure();
            if findings.is_empty() {
                println!("\n  ✓ No identity/privacy exposure detected.");
            } else {
                println!("\n── Identity/privacy exposure ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
            println!("\n── Applying identity hardening ───────────────────");
            for r in pledgeshield::harden::identity::harden_identity(dry_run) {
                println!("{}", r);
            }
        }
        HardenAction::Firewall {
            enable,
            harden,
            allow_ssh,
            disable,
            dry_run,
        } => {
            if disable {
                println!("\n── Disabling firewall ───────────────────────────");
                let r = pledgeshield::harden::firewall::disable_firewall();
                println!("{}", r);
                return;
            }
            if enable {
                println!("\n── Enabling firewall ────────────────────────────");
                let r = pledgeshield::harden::firewall::enable_firewall();
                println!("{}", r);
                return;
            }
            if harden {
                // First audit
                let findings = pledgeshield::harden::firewall::audit_firewall();
                if !findings.is_empty() {
                    println!("\n── Firewall issues detected ─────────────────────");
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                println!("\n── Hardening firewall ───────────────────────────");
                for r in pledgeshield::harden::firewall::harden_firewall(dry_run, allow_ssh) {
                    println!("{}", r);
                }
                return;
            }
            // Default: just audit
            let findings = pledgeshield::harden::firewall::audit_firewall();
            if findings.is_empty() {
                println!("\n  ✓ Firewall is enabled and properly configured.");
            } else {
                println!("\n── Firewall issues ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
                println!(
                    "\n  Run: pledgeshield harden firewall --harden{} to fix.",
                    if allow_ssh { " --allow-ssh" } else { "" }
                );
            }
        }
        HardenAction::Browser {
            dry_run,
            clear_data,
        } => {
            if clear_data {
                println!("\n── Clearing browser data ────────────────────────");
                println!("  (Make sure browsers are closed.)");
                for r in pledgeshield::harden::browser::clear_browser_data(dry_run) {
                    println!("{}", r);
                }
                return;
            }
            // First audit
            let findings = pledgeshield::harden::browser::audit_browser_privacy();
            if findings.is_empty() {
                println!("\n  ✓ No browser privacy issues detected.");
            } else {
                println!("\n── Browser privacy issues ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
            println!("\n── Hardening browser privacy ─────────────────────");
            for r in pledgeshield::harden::browser::harden_browser(dry_run) {
                println!("{}", r);
            }
        }

        // === Network & Traffic ===
        HardenAction::Doh {
            enable,
            disable,
            list,
            dry_run,
        } => {
            if list {
                println!("\n── Available DoH providers ──────────────────────");
                for p in pledgeshield::harden::doh::list_providers() {
                    println!("{}", p);
                }
                return;
            }
            if disable {
                println!("\n── Disabling DoH ────────────────────────────────");
                println!("{}", pledgeshield::harden::doh::disable_doh());
                return;
            }
            if let Some(provider) = enable {
                println!("\n── Enabling DoH ─────────────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::doh::enable_doh(&provider, dry_run)
                );
                return;
            }
            // Audit
            let findings = pledgeshield::harden::doh::audit_dns();
            if findings.is_empty() {
                println!("\n  ✓ DNS encryption is configured.");
            } else {
                println!("\n── DNS issues ───────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Wifi { forget } => {
            if let Some(name) = forget {
                println!("\n── Forgetting WiFi network ──────────────────────");
                match pledgeshield::harden::wifi::forget_network(&name) {
                    Ok(msg) => println!("  ✓ {}", msg),
                    Err(e) => println!("  ✗ {}", e),
                }
                return;
            }
            let findings = pledgeshield::harden::wifi::audit_wifi();
            if findings.is_empty() {
                println!("\n  ✓ No WiFi security issues detected.");
            } else {
                println!("\n── WiFi security issues ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Arp {
            monitor,
            interval,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::arp::monitor_arp(interval, max_runtime);
                return;
            }
            let findings = pledgeshield::harden::arp::detect_arp_spoof();
            if findings.is_empty() {
                println!("\n  ✓ No ARP spoofing detected.");
            } else {
                println!("\n── ARP spoofing alerts ──────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Isolation {
            allow,
            disable,
            dry_run,
        } => {
            if disable {
                println!("\n── Disabling network isolation ──────────────────");
                println!("{}", pledgeshield::harden::isolation::disable_isolation());
                return;
            }
            if !allow.is_empty() {
                println!("\n── Enabling network isolation ───────────────────");
                for r in pledgeshield::harden::isolation::enable_isolation(&allow, dry_run) {
                    println!("{}", r);
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden isolation --allow 1.1.1.1,8.8.8.8");
            println!("         pledgeshield harden isolation --disable");
        }

        HardenAction::Proxy {
            set,
            clear,
            show,
            dry_run,
        } => {
            if show {
                println!("\n── Current proxy settings ───────────────────────");
                print!("{}", pledgeshield::harden::proxy::show_proxy());
                return;
            }
            if clear {
                println!("\n── Clearing proxy ───────────────────────────────");
                println!("{}", pledgeshield::harden::proxy::clear_proxy());
                return;
            }
            if let Some(spec) = set {
                // Parse type:host:port
                let parts: Vec<&str> = spec.splitn(3, ':').collect();
                if parts.len() == 3 {
                    if let Ok(port) = parts[2].parse::<u16>() {
                        println!("\n── Setting proxy ────────────────────────────────");
                        println!(
                            "{}",
                            pledgeshield::harden::proxy::set_proxy(
                                parts[0], parts[1], port, dry_run
                            )
                        );
                        return;
                    }
                }
                eprintln!("Invalid proxy format. Use: type:host:port (e.g. socks5:127.0.0.1:9050)");
                return;
            }
            println!("\n  Usage: pledgeshield harden proxy --set socks5:127.0.0.1:9050");
            println!("         pledgeshield harden proxy --show");
            println!("         pledgeshield harden proxy --clear");
        }

        HardenAction::Ipv6 {
            disable,
            firewall,
            restore,
            dry_run,
        } => {
            if restore {
                println!("\n── Restoring IPv6 ───────────────────────────────");
                println!("{}", pledgeshield::harden::ipv6::restore_ipv6());
                return;
            }
            if disable {
                println!("\n── Disabling IPv6 ───────────────────────────────");
                println!("{}", pledgeshield::harden::ipv6::disable_ipv6(dry_run));
                return;
            }
            if firewall {
                println!("\n── Firewalling IPv6 ─────────────────────────────");
                println!("{}", pledgeshield::harden::ipv6::firewall_ipv6(dry_run));
                return;
            }
            let findings = pledgeshield::harden::ipv6::audit_ipv6();
            if findings.is_empty() {
                println!("\n  ✓ No IPv6 leak risks detected.");
            } else {
                println!("\n── IPv6 issues ──────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Hosts {
            update,
            restore,
            block,
            count,
            dry_run,
        } => {
            if count {
                println!(
                    "\n  {} domains blocked in hosts file.",
                    pledgeshield::harden::hosts::count_blocked()
                );
                return;
            }
            if restore {
                println!("\n── Restoring hosts file ─────────────────────────");
                println!("{}", pledgeshield::harden::hosts::restore_hosts());
                return;
            }
            if let Some(domain) = block {
                println!("\n── Blocking domain ──────────────────────────────");
                println!("{}", pledgeshield::harden::hosts::add_custom_block(&domain));
                return;
            }
            if update {
                println!("\n── Updating hosts blocklists ────────────────────");
                println!("{}", pledgeshield::harden::hosts::update_hosts(dry_run));
                return;
            }
            let findings = pledgeshield::harden::hosts::audit_hosts();
            if findings.is_empty() {
                println!(
                    "\n  ✓ Hosts file has good domain blocking ({} entries).",
                    pledgeshield::harden::hosts::count_blocked()
                );
            } else {
                println!("\n── Hosts file issues ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Traffic {
            monitor,
            interval,
            max_runtime,
            top,
        } => {
            if monitor {
                pledgeshield::harden::traffic::monitor_traffic(interval, max_runtime, top);
                return;
            }
            let findings = pledgeshield::harden::traffic::audit_traffic_anomalies();
            if findings.is_empty() {
                println!("\n  ✓ No anomalous traffic detected.");
            } else {
                println!("\n── Traffic anomalies ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Identity & Privacy ===
        HardenAction::Hostname {
            randomize,
            install_boot,
            show,
            dry_run,
        } => {
            if show {
                println!(
                    "\n  Current hostname: {}",
                    pledgeshield::harden::hostname::get_hostname()
                );
                return;
            }
            if install_boot {
                println!("\n── Installing boot-time hostname randomizer ─────");
                println!(
                    "{}",
                    pledgeshield::harden::hostname::install_boot_randomizer(dry_run)
                );
                return;
            }
            if randomize {
                println!("\n── Randomizing hostname ─────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::hostname::randomize_hostname(dry_run)
                );
                return;
            }
            println!(
                "\n  Current hostname: {}",
                pledgeshield::harden::hostname::get_hostname()
            );
            println!("  Use --randomize to change, --install-boot for boot-time randomization.");
        }

        HardenAction::Useragent {
            set,
            reset,
            dry_run,
        } => {
            if reset {
                println!("\n── Resetting user-agent ─────────────────────────");
                for r in pledgeshield::harden::useragent::reset_user_agent() {
                    println!("{}", r);
                }
                return;
            }
            if set.is_some() {
                let ua = set.unwrap();
                println!("\n── Spoofing user-agent ──────────────────────────");
                for r in pledgeshield::harden::useragent::spoof_user_agent(ua.as_deref(), dry_run) {
                    println!("{}", r);
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden useragent --set [custom-ua]");
            println!("         pledgeshield harden useragent --reset");
        }

        HardenAction::Webrtc {
            block,
            restore,
            dry_run,
        } => {
            if restore {
                println!("\n── Restoring WebRTC ─────────────────────────────");
                for r in pledgeshield::harden::webrtc::restore_webrtc() {
                    println!("{}", r);
                }
                return;
            }
            if block {
                println!("\n── Blocking WebRTC ──────────────────────────────");
                for r in pledgeshield::harden::webrtc::block_webrtc(dry_run) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::webrtc::audit_webrtc();
            if findings.is_empty() {
                println!("\n  ✓ No WebRTC leak risks detected.");
            } else {
                println!("\n── WebRTC issues ────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Bluetooth {
            list,
            hide,
            disable,
            remove,
            dry_run,
        } => {
            if list {
                println!("\n── Paired Bluetooth devices ─────────────────────");
                let devices = pledgeshield::harden::bluetooth::list_paired();
                if devices.is_empty() {
                    println!("  No paired devices (or Bluetooth not available).");
                } else {
                    for d in &devices {
                        println!("  {}", d);
                    }
                }
                return;
            }
            if let Some(mac) = remove {
                println!("\n── Removing paired device ───────────────────────");
                println!("{}", pledgeshield::harden::bluetooth::remove_device(&mac));
                return;
            }
            if disable {
                println!("\n── Disabling Bluetooth ──────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::bluetooth::disable_bluetooth(dry_run)
                );
                return;
            }
            if hide {
                println!("\n── Hiding Bluetooth discoverability ─────────────");
                println!(
                    "{}",
                    pledgeshield::harden::bluetooth::hide_discoverable(dry_run)
                );
                return;
            }
            let findings = pledgeshield::harden::bluetooth::audit_bluetooth();
            if findings.is_empty() {
                println!("\n  ✓ No Bluetooth issues detected.");
            } else {
                println!("\n── Bluetooth issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Devices {
            block_camera,
            restore_camera,
        } => {
            if restore_camera {
                println!("\n── Restoring camera access ──────────────────────");
                for msg in pledgeshield::harden::devices::restore_camera() {
                    println!("  {}", msg);
                }
                return;
            }
            if block_camera {
                println!("\n── Blocking camera access ───────────────────────");
                for msg in pledgeshield::harden::devices::block_camera(false) {
                    println!("  {}", msg);
                }
                return;
            }
            let findings = pledgeshield::harden::devices::audit_devices();
            if findings.is_empty() {
                println!("\n  ✓ No camera/mic access detected.");
            } else {
                println!("\n── Camera/mic access ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Clipboard {
            clear,
            watch,
            dry_run,
        } => {
            if let Some(secs) = watch {
                println!("\n── Installing clipboard watcher ─────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::clipboard::install_clipboard_watcher(secs, dry_run)
                );
                return;
            }
            if clear {
                println!("\n── Clearing clipboard ───────────────────────────");
                println!("{}", pledgeshield::harden::clipboard::clear_clipboard());
                return;
            }
            println!("\n  Usage: pledgeshield harden clipboard --clear");
            println!("         pledgeshield harden clipboard --watch 30  (auto-clear after 30s)");
        }

        HardenAction::Cleaner { dry_run } => {
            println!("\n── Cleaning activity traces ─────────────────────");
            for r in pledgeshield::harden::cleaner::clean_activity(dry_run) {
                println!("{}", r);
            }
        }

        // === System Hardening ===
        HardenAction::Usb {
            list,
            lockdown,
            restore,
            dry_run,
        } => {
            if list {
                println!("\n── Connected USB devices ────────────────────────");
                let devices = pledgeshield::harden::usb::list_usb();
                if devices.is_empty() {
                    println!("  No USB devices found.");
                } else {
                    for d in &devices {
                        println!("  {}", d);
                    }
                }
                return;
            }
            if restore {
                println!("\n── Restoring USB access ─────────────────────────");
                println!("{}", pledgeshield::harden::usb::restore_usb());
                return;
            }
            if lockdown {
                println!("\n── Locking down USB ─────────────────────────────");
                println!("{}", pledgeshield::harden::usb::lockdown_usb(dry_run));
                return;
            }
            let findings = pledgeshield::harden::usb::audit_usb();
            if findings.is_empty() {
                println!("\n  ✓ No USB security issues detected.");
            } else {
                println!("\n── USB issues ───────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Kernel {
            list,
            lockdown,
            dry_run,
        } => {
            if list {
                println!("\n── Loaded kernel modules ────────────────────────");
                let modules = pledgeshield::harden::kernel::list_modules();
                for m in modules.iter().take(50) {
                    println!("  {}", m);
                }
                if modules.len() > 50 {
                    println!("  ... and {} more", modules.len() - 50);
                }
                return;
            }
            if lockdown {
                println!("\n  ⚠ WARNING: This is irreversible until reboot!");
                println!("{}", pledgeshield::harden::kernel::lockdown_kernel(dry_run));
                return;
            }
            let findings = pledgeshield::harden::kernel::audit_kernel_modules();
            if findings.is_empty() {
                println!("\n  ✓ No kernel module issues detected.");
            } else {
                println!("\n── Kernel module issues ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Suid { remove, dry_run } => {
            if let Some(path) = remove {
                println!("\n── Removing SUID bit ────────────────────────────");
                match pledgeshield::harden::suid::remove_suid(&path, dry_run) {
                    Ok(msg) => println!("  ✓ {}", msg),
                    Err(e) => println!("  ✗ {}", e),
                }
                return;
            }
            let findings = pledgeshield::harden::suid::audit_suid();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious SUID/SGID binaries found.");
            } else {
                println!("\n── SUID/SGID findings ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Scheduler => {
            let findings = pledgeshield::harden::scheduler::audit_schedulers();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious scheduled tasks found.");
            } else {
                println!("\n── Suspicious scheduled tasks ───────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Integrity {
            baseline,
            check,
            remove,
        } => {
            if remove {
                println!("\n── Removing integrity baseline ──────────────────");
                println!("{}", pledgeshield::harden::integrity::remove_baseline());
                return;
            }
            if baseline {
                println!("\n── Creating integrity baseline ──────────────────");
                println!("{}", pledgeshield::harden::integrity::create_baseline());
                return;
            }
            if check {
                let findings = pledgeshield::harden::integrity::check_integrity();
                if findings.is_empty() {
                    println!("\n  ✓ All files match baseline.");
                } else {
                    println!("\n── Integrity violations ─────────────────────────");
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden integrity --baseline");
            println!("         pledgeshield harden integrity --check");
        }

        HardenAction::Proctree => {
            let findings = pledgeshield::harden::proctree::audit_process_tree();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious process trees detected.");
            } else {
                println!("\n── Suspicious process trees ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Lockscreen {
            enable,
            disable_autologin,
            dry_run,
        } => {
            if disable_autologin {
                println!("\n── Disabling auto-login ─────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::lockscreen::disable_autologin(dry_run)
                );
                return;
            }
            if let Some(timeout) = enable {
                println!("\n── Enabling lock screen ─────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::lockscreen::enable_lockscreen(timeout, dry_run)
                );
                return;
            }
            let findings = pledgeshield::harden::lockscreen::audit_lockscreen();
            if findings.is_empty() {
                println!("\n  ✓ Lock screen is properly configured.");
            } else {
                println!("\n── Lock screen issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Encryption { enable, dry_run } => {
            if enable {
                println!("\n── Disk encryption guide ────────────────────────");
                for step in pledgeshield::harden::encryption::enable_encryption(dry_run) {
                    println!("  {}", step);
                }
                return;
            }
            let findings = pledgeshield::harden::encryption::audit_encryption();
            if findings.is_empty() {
                println!("\n  ✓ All disks appear to be encrypted.");
            } else {
                println!("\n── Disk encryption issues ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Detection & Response ===
        HardenAction::Rootkit => {
            println!("\n── Scanning for rootkits ────────────────────────");
            let findings = pledgeshield::harden::rootkit::scan_rootkits();
            if findings.is_empty() {
                println!("  ✓ No rootkit indicators found.");
            } else {
                println!("\n── Rootkit indicators ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Canary {
            plant,
            check,
            remove,
            dry_run,
        } => {
            if remove {
                println!("\n── Removing canary files ────────────────────────");
                println!("{}", pledgeshield::harden::canary::remove_canaries());
                return;
            }
            if plant {
                println!("\n── Planting ransomware canaries ─────────────────");
                for r in pledgeshield::harden::canary::plant_canaries(dry_run) {
                    println!("{}", r);
                }
                return;
            }
            if check {
                let findings = pledgeshield::harden::canary::check_canaries();
                if findings.is_empty() {
                    println!("\n  ✓ All canary files are intact.");
                } else {
                    println!("\n── Canary alerts ────────────────────────────────");
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden canary --plant");
            println!("         pledgeshield harden canary --check");
        }

        HardenAction::Logins { block, dry_run } => {
            if let Some(ip) = block {
                println!("\n── Blocking IP ──────────────────────────────────");
                match pledgeshield::harden::logins::block_ip(&ip, dry_run) {
                    Ok(msg) => println!("  ✓ {}", msg),
                    Err(e) => println!("  ✗ {}", e),
                }
                return;
            }
            let findings = pledgeshield::harden::logins::audit_login_attempts();
            if findings.is_empty() {
                println!("\n  ✓ No brute force activity detected.");
            } else {
                println!("\n── Login attempt alerts ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Dnsmon {
            monitor,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::dnsmon::monitor_dns(max_runtime);
                return;
            }
            let findings = pledgeshield::harden::dnsmon::audit_dns_queries();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious DNS queries detected.");
            } else {
                println!("\n── Suspicious DNS queries ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Privacy Tools ===
        HardenAction::Shredder {
            file,
            passes,
            dry_run,
        } => {
            if let Some(path) = file {
                let p = std::path::Path::new(&path);
                if p.is_dir() {
                    println!("\n── Shredding directory ──────────────────────────");
                    for r in pledgeshield::harden::shredder::shred_dir(&path, passes, dry_run) {
                        println!("{}", r);
                    }
                } else {
                    println!("\n── Shredding file ───────────────────────────────");
                    println!(
                        "{}",
                        pledgeshield::harden::shredder::shred_file(&path, passes, dry_run)
                    );
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden shredder --file <path> [--passes 3]");
        }

        HardenAction::Memwipe {
            wipe_swap,
            encrypt_swap,
            install_ramwipe,
            drop_caches,
            dry_run,
        } => {
            if drop_caches {
                println!("\n── Dropping kernel caches ───────────────────────");
                println!("{}", pledgeshield::harden::memwipe::drop_caches());
                return;
            }
            if install_ramwipe {
                println!("\n── Installing RAM wipe on shutdown ──────────────");
                println!(
                    "{}",
                    pledgeshield::harden::memwipe::install_ram_wipe(dry_run)
                );
                return;
            }
            if encrypt_swap {
                println!("\n── Setting up encrypted swap ────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::memwipe::setup_encrypted_swap(dry_run)
                );
                return;
            }
            if wipe_swap {
                println!("\n── Wiping swap space ────────────────────────────");
                println!("{}", pledgeshield::harden::memwipe::wipe_swap(dry_run));
                return;
            }
            // Audit
            let findings = pledgeshield::harden::memwipe::audit_memory_security();
            if findings.is_empty() {
                println!("\n  ✓ Memory security looks good.");
            } else {
                println!("\n── Memory security issues ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Metadata {
            strip,
            output,
            list,
            dry_run,
        } => {
            if let Some(path) = list {
                println!("\n── Metadata in {} ──────────────────────", path);
                let info = pledgeshield::harden::metadata::list_metadata(&path);
                if info.is_empty() {
                    println!("  No metadata found or unsupported file type.");
                } else {
                    for line in &info {
                        println!("{}", line);
                    }
                }
                return;
            }
            if let Some(path) = strip {
                println!("\n── Stripping metadata ───────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::metadata::strip_metadata(
                        &path,
                        output.as_deref(),
                        dry_run
                    )
                );
                return;
            }
            println!("\n  Usage: pledgeshield harden metadata --strip <file> [--output <path>]");
            println!("         pledgeshield harden metadata --list <file>");
        }

        // === Boot & Firmware ===
        HardenAction::Uefi => {
            let findings = pledgeshield::harden::uefi::audit_uefi();
            if findings.is_empty() {
                println!("\n  ✓ UEFI/BIOS security looks good.");
            } else {
                println!("\n── UEFI/BIOS issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Bootlog => {
            let findings = pledgeshield::harden::bootlog::audit_bootlog();
            if findings.is_empty() {
                println!("\n  ✓ No boot-time anomalies detected.");
            } else {
                println!("\n── Boot log anomalies ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Sysctl { harden, restore } => {
            if restore {
                println!("\n── Restoring sysctl defaults ────────────────────");
                println!("{}", pledgeshield::harden::sysctl::restore_sysctl());
                return;
            }
            if harden {
                println!("\n── Hardening kernel parameters ──────────────────");
                for r in pledgeshield::harden::sysctl::harden_sysctl(false) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::sysctl::audit_sysctl();
            if findings.is_empty() {
                println!("\n  ✓ All kernel parameters are secure.");
            } else {
                println!("\n── Kernel parameter issues ──────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Modsign => {
            let findings = pledgeshield::harden::modsign::audit_module_signatures();
            if findings.is_empty() {
                println!("\n  ✓ All kernel modules are signed.");
            } else {
                println!("\n── Module signature issues ──────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Tpm => {
            let findings = pledgeshield::harden::tpm::audit_tpm();
            if findings.is_empty() {
                println!("\n  ✓ TPM is present and configured.");
            } else {
                println!("\n── TPM status ───────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === File & Data Protection ===
        HardenAction::Fileperms { fix, dry_run } => {
            if fix {
                println!("\n── Fixing file permissions ──────────────────────");
                for msg in pledgeshield::harden::fileperms::fix_permissions(dry_run) {
                    println!("  {}", msg);
                }
                return;
            }
            let findings = pledgeshield::harden::fileperms::audit_file_permissions();
            if findings.is_empty() {
                println!("\n  ✓ File permissions look good.");
            } else {
                println!("\n── File permission issues ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Sensitive => {
            let findings = pledgeshield::harden::sensitive::find_sensitive_files();
            if findings.is_empty() {
                println!("\n  ✓ No sensitive files found in home directory.");
            } else {
                println!("\n── Sensitive files found ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Exfil {
            monitor,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::exfil::monitor_exfiltration(max_runtime);
                return;
            }
            let findings = pledgeshield::harden::exfil::audit_exfiltration();
            if findings.is_empty() {
                println!("\n  ✓ No exfiltration activity detected.");
            } else {
                println!("\n── Exfiltration indicators ──────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Backup { dir, verify, hash } => {
            if let (Some(path), Some(expected)) = (verify, hash) {
                println!("\n── Verifying backup hash ────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::backup::verify_backup_hash(&path, &expected)
                );
                return;
            }
            let backup_dir = dir.as_deref().unwrap_or("/var/backups");
            let findings = pledgeshield::harden::backup::audit_backups(backup_dir);
            if findings.is_empty() {
                println!("\n  ✓ Backups look healthy.");
            } else {
                println!("\n── Backup issues ────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Diskmon {
            monitor,
            interval,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::diskmon::monitor_disk_usage(interval, max_runtime);
                return;
            }
            let findings = pledgeshield::harden::diskmon::audit_disk_usage();
            if findings.is_empty() {
                println!("\n  ✓ Disk usage looks normal.");
            } else {
                println!("\n── Disk usage issues ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Logtamper => {
            let findings = pledgeshield::harden::logtamper::audit_log_tampering();
            if findings.is_empty() {
                println!("\n  ✓ No log tampering detected.");
            } else {
                println!("\n── Log tampering indicators ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === SSH & Remote Access ===
        HardenAction::Ssh { harden, restore } => {
            if restore {
                println!("\n── Restoring SSH config ─────────────────────────");
                println!("{}", pledgeshield::harden::ssh::restore_ssh());
                return;
            }
            if harden {
                println!("\n── Hardening SSH config ─────────────────────────");
                println!("{}", pledgeshield::harden::ssh::harden_ssh(false));
                return;
            }
            let findings = pledgeshield::harden::ssh::audit_ssh();
            if findings.is_empty() {
                println!("\n  ✓ SSH config is secure.");
            } else {
                println!("\n── SSH config issues ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Sshkeys => {
            let findings = pledgeshield::harden::sshkeys::audit_ssh_keys();
            if findings.is_empty() {
                println!("\n  ✓ SSH keys look good.");
            } else {
                println!("\n── SSH key issues ───────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Knock { install, remove } => {
            if remove {
                println!("\n── Removing port knocking ───────────────────────");
                println!("{}", pledgeshield::harden::knock::remove_knockd());
                return;
            }
            if !install.is_empty() {
                println!("\n── Installing port knocking ─────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::knock::install_knockd(&install, false)
                );
                return;
            }
            println!("\n  Usage: pledgeshield harden knock --install 7000,8000,9000");
            println!("         pledgeshield harden knock --remove");
        }

        HardenAction::Fail2ban {
            install,
            configure,
            status,
        } => {
            if status {
                println!("\n── fail2ban status ──────────────────────────────");
                println!("{}", pledgeshield::harden::fail2ban::fail2ban_status());
                return;
            }
            if install {
                println!("\n── Installing fail2ban ──────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::fail2ban::install_fail2ban(false)
                );
                return;
            }
            if configure {
                println!("\n── Configuring fail2ban ─────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::fail2ban::configure_fail2ban(false)
                );
                return;
            }
            let findings = pledgeshield::harden::fail2ban::audit_fail2ban();
            if findings.is_empty() {
                println!("\n  ✓ fail2ban is installed and running.");
            } else {
                println!("\n── fail2ban issues ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Application Hardening ===
        HardenAction::Tls { check } => {
            if let Some(target) = check {
                let findings = pledgeshield::harden::tls::audit_cert(&target);
                if findings.is_empty() {
                    println!("\n  ✓ Certificate for {} looks good.", target);
                } else {
                    println!(
                        "\n── Certificate issues for {} ────────────────────",
                        target
                    );
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden tls --check <file-or-hostname>");
        }

        HardenAction::Deps { dir } => {
            let target = dir.as_deref().unwrap_or(".");
            let findings = pledgeshield::harden::deps::audit_dependencies(target);
            if findings.is_empty() {
                println!("\n  ✓ No dependency vulnerabilities found.");
            } else {
                println!("\n── Dependency vulnerabilities ────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Secrets { dir } => {
            let target = dir.as_deref().unwrap_or(".");
            let findings = pledgeshield::harden::secrets::scan_secrets(target);
            if findings.is_empty() {
                println!("\n  ✓ No secrets found in files.");
            } else {
                println!("\n── Secrets found ────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Vault => {
            let findings = pledgeshield::harden::vault::audit_vault();
            if findings.is_empty() {
                println!("\n  ✓ Browser password vaults look secure.");
            } else {
                println!("\n── Password vault issues ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Autorun { disable, dry_run } => {
            if disable {
                println!("\n── Disabling autorun/autoplay ───────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::autorun::disable_autorun(dry_run)
                );
                return;
            }
            let findings = pledgeshield::harden::autorun::audit_autorun();
            if findings.is_empty() {
                println!("\n  ✓ Autorun/AutoPlay is disabled.");
            } else {
                println!("\n── Autorun issues ───────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === System Monitoring ===
        HardenAction::Resource {
            monitor,
            interval,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::resource::monitor_resources(interval, max_runtime);
                return;
            }
            let findings = pledgeshield::harden::resource::audit_resources();
            if findings.is_empty() {
                println!("\n  ✓ System resources look normal.");
            } else {
                println!("\n── Resource anomalies ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Filewatch {
            monitor,
            baseline,
            interval,
            max_runtime,
        } => {
            if baseline {
                println!("\n── Creating file watch baseline ─────────────────");
                println!("  {}", pledgeshield::harden::filewatch::create_baseline());
                return;
            }
            if monitor {
                pledgeshield::harden::filewatch::monitor_new_files(interval, max_runtime);
                return;
            }
            let findings = pledgeshield::harden::filewatch::audit_new_files();
            if findings.is_empty() {
                println!("\n  ✓ No new files in system directories.");
            } else {
                println!("\n── New files detected ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Usermon { baseline } => {
            if baseline {
                println!("\n── Creating user monitor baseline ───────────────");
                let _ = pledgeshield::harden::usermon::audit_user_changes();
                println!("  Baseline created.");
                return;
            }
            let findings = pledgeshield::harden::usermon::audit_user_changes();
            if findings.is_empty() {
                println!("\n  ✓ No user account changes detected.");
            } else {
                println!("\n── User account changes ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Netcons { list } => {
            if list {
                println!("\n── Current network connections ──────────────────");
                for line in pledgeshield::harden::netcons::list_connections() {
                    println!("{}", line);
                }
                return;
            }
            let findings = pledgeshield::harden::netcons::audit_connections();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious network connections.");
            } else {
                println!("\n── Suspicious network connections ──────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Cronmon {
            monitor,
            baseline,
            interval,
            max_runtime,
        } => {
            if baseline {
                println!("\n── Creating cron monitor baseline ───────────────");
                println!("  {}", pledgeshield::harden::cronmon::create_baseline());
                return;
            }
            if monitor {
                pledgeshield::harden::cronmon::monitor_cron(interval, max_runtime);
                return;
            }
            let findings = pledgeshield::harden::cronmon::audit_cron_changes();
            if findings.is_empty() {
                println!("\n  ✓ No cron job changes detected.");
            } else {
                println!("\n── Cron job changes ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Privacy & Compliance ===
        HardenAction::Pii { dir } => {
            let target = dir.as_deref().unwrap_or(".");
            let findings = pledgeshield::harden::pii::scan_pii(target);
            if findings.is_empty() {
                println!("\n  ✓ No PII found in files.");
            } else {
                println!("\n── PII found in files ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Telemetry { clean, dry_run } => {
            if clean {
                println!("\n── Disabling telemetry ──────────────────────────");
                for r in pledgeshield::harden::telemetry::clean_telemetry(dry_run) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::telemetry::audit_telemetry();
            if findings.is_empty() {
                println!("\n  ✓ No telemetry detected.");
            } else {
                println!("\n── Telemetry detected ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Freespace {
            wipe,
            install_schedule,
            remove_schedule,
            dry_run,
        } => {
            if remove_schedule {
                println!("\n── Removing free space wipe schedule ────────────");
                println!(
                    "{}",
                    pledgeshield::harden::freespace::remove_wipe_schedule()
                );
                return;
            }
            if install_schedule {
                println!("\n── Installing free space wipe schedule ──────────");
                println!(
                    "{}",
                    pledgeshield::harden::freespace::install_wipe_schedule(dry_run)
                );
                return;
            }
            if let Some(path) = wipe {
                println!("\n── Wiping free space ────────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::freespace::wipe_freespace(&path, dry_run)
                );
                return;
            }
            println!("\n  Usage: pledgeshield harden freespace --wipe /");
            println!("         pledgeshield harden freespace --install-schedule");
        }

        HardenAction::Posture => {
            println!("\n── Security Posture Score ───────────────────────");
            println!("  Run a scan first to get findings, then this will score them.");
            println!("  Example: pledgeshield scan --output json | pledgeshield harden posture");
            // For now, run a quick audit
            let mut all_findings = Vec::new();
            all_findings.extend(pledgeshield::harden::sysctl::audit_sysctl());
            all_findings.extend(pledgeshield::harden::ssh::audit_ssh());
            all_findings.extend(pledgeshield::harden::fileperms::audit_file_permissions());
            all_findings.extend(pledgeshield::harden::uefi::audit_uefi());
            all_findings.extend(pledgeshield::harden::tpm::audit_tpm());
            all_findings.extend(pledgeshield::harden::autorun::audit_autorun());
            all_findings.extend(pledgeshield::harden::telemetry::audit_telemetry());
            all_findings.extend(pledgeshield::harden::fail2ban::audit_fail2ban());
            let score = pledgeshield::harden::posture::calculate_score(&all_findings);
            println!("{}", score);
        }

        HardenAction::Profile { apply, audit } => {
            if let Some(profile) = apply {
                println!(
                    "\n── Applying {} profile ─────────────────────",
                    profile.as_str()
                );
                for r in pledgeshield::harden::profile::apply_profile(profile, false) {
                    println!("{}", r);
                }
                return;
            }
            if let Some(profile) = audit {
                let findings = pledgeshield::harden::profile::audit_profile(profile);
                if findings.is_empty() {
                    println!("\n  ✓ System complies with {} profile.", profile.as_str());
                } else {
                    println!(
                        "\n── {} compliance gaps ─────────────────────",
                        profile.as_str()
                    );
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            println!("\n  Usage: pledgeshield harden profile --audit cis1");
            println!("         pledgeshield harden profile --apply cis2");
            println!("         pledgeshield harden profile --apply stig");
        }

        // === Process & Memory Defense ===
        HardenAction::Procinj => {
            let findings = pledgeshield::harden::procinj::audit_injections();
            if findings.is_empty() {
                println!("\n  ✓ No process injection indicators detected.");
            } else {
                println!("\n── Process injection indicators ──────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Hollow => {
            let findings = pledgeshield::harden::hollow::audit_hollow();
            if findings.is_empty() {
                println!("\n  ✓ No hollow processes detected.");
            } else {
                println!("\n── Hollow process indicators ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Memscan => {
            let findings = pledgeshield::harden::memscan::scan_memory();
            if findings.is_empty() {
                println!("\n  ✓ No malware signatures found in process memory.");
            } else {
                println!("\n── Malware signatures detected ───────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Ptrace => {
            let findings = pledgeshield::harden::ptrace::audit_ptrace();
            if findings.is_empty() {
                println!("\n  ✓ No debugging/ptrace activity detected.");
            } else {
                println!("\n── Ptrace/debugging alerts ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Thread => {
            let findings = pledgeshield::harden::thread::audit_threads();
            if findings.is_empty() {
                println!("\n  ✓ No thread anomalies detected.");
            } else {
                println!("\n── Thread anomalies ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Codeinject { block } => {
            if block {
                println!("\n── Blocking code injection ──────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::codeinject::block_injection(false)
                );
                return;
            }
            let findings = pledgeshield::harden::codeinject::audit_code_injection();
            if findings.is_empty() {
                println!("\n  ✓ Code injection defenses look good.");
            } else {
                println!("\n── Code injection risks ──────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Network Defense ===
        HardenAction::Ratelimit { enable, disable } => {
            if disable {
                println!("\n── Disabling rate limit ──────────────────────────");
                println!("{}", pledgeshield::harden::ratelimit::disable_rate_limit());
                return;
            }
            if let Some(max) = enable {
                println!("\n── Enabling rate limit ───────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::ratelimit::enable_rate_limit(max, false)
                );
                return;
            }
            println!("\n  Usage: pledgeshield harden ratelimit --enable 60");
            println!("         pledgeshield harden ratelimit --disable");
        }

        HardenAction::Geoip { enable, disable } => {
            if disable {
                println!("\n── Disabling geo-IP filter ───────────────────────");
                println!("{}", pledgeshield::harden::geoip::disable_geoip_filter());
                return;
            }
            if enable {
                println!("\n── Enabling geo-IP filter ────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::geoip::enable_geoip_filter(&[], false)
                );
                return;
            }
            let findings = pledgeshield::harden::geoip::audit_geoip();
            if findings.is_empty() {
                println!("\n  ✓ Geo-IP filter is enabled.");
            } else {
                println!("\n── Geo-IP issues ─────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Dohforce { enforce, disable } => {
            if disable {
                println!("\n── Disabling DNS enforcement ─────────────────────");
                println!("{}", pledgeshield::harden::dohforce::disable_enforcement());
                return;
            }
            if enforce {
                println!("\n── Enforcing encrypted DNS ───────────────────────");
                println!("{}", pledgeshield::harden::dohforce::enforce_doh(false));
                return;
            }
            let findings = pledgeshield::harden::dohforce::audit_dns_enforcement();
            if findings.is_empty() {
                println!("\n  ✓ DNS encryption is enforced.");
            } else {
                println!("\n── DNS enforcement issues ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Pcapdetect => {
            let findings = pledgeshield::harden::pcapdetect::audit_pcap();
            if findings.is_empty() {
                println!("\n  ✓ No packet capture detected.");
            } else {
                println!("\n── Packet capture indicators ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Roguedhcp => {
            let findings = pledgeshield::harden::roguedhcp::audit_rogue_dhcp();
            if findings.is_empty() {
                println!("\n  ✓ No rogue DHCP detected.");
            } else {
                println!("\n── Rogue DHCP indicators ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Deauth {
            monitor,
            max_runtime,
        } => {
            if monitor {
                pledgeshield::harden::deauth::monitor_deauth(max_runtime);
                return;
            }
            let findings = pledgeshield::harden::deauth::audit_deauth();
            if findings.is_empty() {
                println!("\n  ✓ No WiFi deauth attacks detected.");
            } else {
                println!("\n── WiFi deauth alerts ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Filesystem & Storage ===
        HardenAction::Immutable { set, unset } => {
            if unset {
                println!("\n── Removing immutable flags ──────────────────────");
                for r in pledgeshield::harden::immutable::unset_immutable() {
                    println!("{}", r);
                }
                return;
            }
            if set {
                println!("\n── Setting immutable flags ───────────────────────");
                for r in pledgeshield::harden::immutable::set_immutable(false) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::immutable::audit_immutable();
            if findings.is_empty() {
                println!("\n  ✓ Critical files are immutable.");
            } else {
                println!("\n── Immutable flag issues ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Mount { harden } => {
            if harden {
                println!("\n── Hardening mount options ───────────────────────");
                for r in pledgeshield::harden::mount::harden_mounts(false) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::mount::audit_mounts();
            if findings.is_empty() {
                println!("\n  ✓ Mount options are secure.");
            } else {
                println!("\n── Mount option issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Tmpsan { clean } => {
            if clean {
                println!("\n── Cleaning temp directories ─────────────────────");
                for r in pledgeshield::harden::tmpsan::clean_temp(false) {
                    println!("{}", r);
                }
                return;
            }
            let findings = pledgeshield::harden::tmpsan::audit_temp();
            if findings.is_empty() {
                println!("\n  ✓ Temp directories look clean.");
            } else {
                println!("\n── Temp directory issues ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Quota { enable } => {
            if enable {
                println!("\n── Enabling disk quotas ──────────────────────────");
                println!("{}", pledgeshield::harden::quota::enable_quotas(false));
                return;
            }
            let findings = pledgeshield::harden::quota::audit_quotas();
            if findings.is_empty() {
                println!("\n  ✓ Disk quotas are enabled.");
            } else {
                println!("\n── Disk quota issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Attrmon { baseline } => {
            if baseline {
                println!("\n── Creating attribute baseline ───────────────────");
                println!("  {}", pledgeshield::harden::attrmon::create_baseline());
                return;
            }
            let findings = pledgeshield::harden::attrmon::audit_attr_changes();
            if findings.is_empty() {
                println!("\n  ✓ No file attribute changes detected.");
            } else {
                println!("\n── File attribute changes ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Access Control ===
        HardenAction::Pam => {
            let findings = pledgeshield::harden::pam::audit_pam();
            if findings.is_empty() {
                println!("\n  ✓ PAM configuration looks secure.");
            } else {
                println!("\n── PAM issues ────────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Polkit => {
            let findings = pledgeshield::harden::polkit::audit_polkit();
            if findings.is_empty() {
                println!("\n  ✓ Polkit rules look secure.");
            } else {
                println!("\n── Polkit issues ─────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Macaudit => {
            let findings = pledgeshield::harden::macaudit::audit_mac();
            if findings.is_empty() {
                println!("\n  ✓ MAC (AppArmor/SELinux) is enforcing.");
            } else {
                println!("\n── MAC issues ────────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Caps => {
            let findings = pledgeshield::harden::caps::audit_capabilities();
            if findings.is_empty() {
                println!("\n  ✓ No dangerous capabilities found.");
            } else {
                println!("\n── Capability findings ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Nsaudit => {
            let findings = pledgeshield::harden::nsaudit::audit_namespaces();
            if findings.is_empty() {
                println!("\n  ✓ Namespace isolation looks good.");
            } else {
                println!("\n── Namespace issues ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === Hardware & Peripherals ===
        HardenAction::Thunderbolt { block } => {
            if block {
                println!("\n── Blocking Thunderbolt devices ──────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::thunderbolt::block_thunderbolt(false)
                );
                return;
            }
            let findings = pledgeshield::harden::thunderbolt::audit_thunderbolt();
            if findings.is_empty() {
                println!("\n  ✓ Thunderbolt security looks good.");
            } else {
                println!("\n── Thunderbolt issues ────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Webcam { block, restore } => {
            if restore {
                println!("\n── Restoring webcam ──────────────────────────────");
                println!("{}", pledgeshield::harden::webcam::restore_webcam());
                return;
            }
            if block {
                println!("\n── Blocking webcam ───────────────────────────────");
                println!("{}", pledgeshield::harden::webcam::block_webcam(false));
                return;
            }
            let findings = pledgeshield::harden::webcam::audit_webcam();
            if findings.is_empty() {
                println!("\n  ✓ No webcam issues detected.");
            } else {
                println!("\n── Webcam issues ─────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Micmute { mute, unmute } => {
            if unmute {
                println!("\n── Unmuting microphone ───────────────────────────");
                println!("{}", pledgeshield::harden::micmute::unmute_mic());
                return;
            }
            if mute {
                println!("\n── Muting microphone ─────────────────────────────");
                println!("{}", pledgeshield::harden::micmute::mute_mic(false));
                return;
            }
            let findings = pledgeshield::harden::micmute::audit_mic();
            if findings.is_empty() {
                println!("\n  ✓ Microphone is muted or not in use.");
            } else {
                println!("\n── Microphone issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Firewire { block, restore } => {
            if restore {
                println!("\n── Restoring FireWire ────────────────────────────");
                println!("{}", pledgeshield::harden::firewire::restore_firewire());
                return;
            }
            if block {
                println!("\n── Blocking FireWire ─────────────────────────────");
                println!("{}", pledgeshield::harden::firewire::block_firewire(false));
                return;
            }
            let findings = pledgeshield::harden::firewire::audit_firewire();
            if findings.is_empty() {
                println!("\n  ✓ No Firewire/DMA issues detected.");
            } else {
                println!("\n── Firewire/DMA issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === System Integrity ===
        HardenAction::Systemd => {
            let findings = pledgeshield::harden::systemd::audit_systemd();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious systemd units found.");
            } else {
                println!("\n── Systemd unit issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Envleak => {
            let findings = pledgeshield::harden::envleak::audit_env_leaks();
            if findings.is_empty() {
                println!("\n  ✓ No secrets found in environment variables.");
            } else {
                println!("\n── Environment variable leaks ────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Libaudit => {
            let findings = pledgeshield::harden::libaudit::audit_libraries();
            if findings.is_empty() {
                println!("\n  ✓ No library issues detected.");
            } else {
                println!("\n── Shared library issues ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Binhash => {
            let findings = pledgeshield::harden::binhash::audit_binary_hashes();
            if findings.is_empty() {
                println!("\n  ✓ All binary hashes match package manager records.");
            } else {
                println!("\n── Binary hash mismatches ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        // === New Defense Modules ===
        HardenAction::Sinkhole { enable, disable } => {
            if disable {
                println!("\n── Disabling DNS sinkhole ────────────────────────");
                println!("{}", pledgeshield::harden::sinkhole::disable_sinkhole());
                return;
            }
            if enable {
                println!("\n── Enabling DNS sinkhole ─────────────────────────");
                println!("{}", pledgeshield::harden::sinkhole::enable_sinkhole(false));
                return;
            }
            let findings = pledgeshield::harden::sinkhole::audit_sinkhole();
            if findings.is_empty() {
                println!("\n  ✓ DNS sinkhole is configured.");
            } else {
                println!("\n── DNS sinkhole issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Sandbox { apply } => {
            if apply {
                println!("\n── Applying process sandboxing ───────────────────");
                println!("{}", pledgeshield::harden::sandbox::apply_sandbox(false));
                return;
            }
            let findings = pledgeshield::harden::sandbox::audit_sandbox();
            if findings.is_empty() {
                println!("\n  ✓ Process sandboxing looks good.");
            } else {
                println!("\n── Sandboxing issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Llmnr => {
            let findings = pledgeshield::harden::llmnr::audit_llmnr();
            if findings.is_empty() {
                println!("\n  ✓ No LLMNR/NBT-NS poisoning indicators.");
            } else {
                println!("\n── LLMNR/NBT-NS issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Kerberos => {
            let findings = pledgeshield::harden::kerberos::audit_kerberos();
            if findings.is_empty() {
                println!("\n  ✓ No Kerberos anomalies detected.");
            } else {
                println!("\n── Kerberos issues ───────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Stickykeys => {
            let findings = pledgeshield::harden::stickykeys::audit_stickykeys();
            if findings.is_empty() {
                println!("\n  ✓ No Sticky Keys bypass detected.");
            } else {
                println!("\n── Sticky Keys bypass indicators ─────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Wsl => {
            let findings = pledgeshield::harden::wsl::audit_wsl();
            if findings.is_empty() {
                println!("\n  ✓ WSL configuration looks good.");
            } else {
                println!("\n── WSL issues ────────────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Metaguard { enable, disable } => {
            if disable {
                println!("\n── Disabling cloud metadata guard ────────────────");
                println!("{}", pledgeshield::harden::metaguard::disable_metaguard());
                return;
            }
            if enable {
                println!("\n── Enabling cloud metadata guard ─────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::metaguard::enable_metaguard(false)
                );
                return;
            }
            let findings = pledgeshield::harden::metaguard::audit_metaguard();
            if findings.is_empty() {
                println!("\n  ✓ Cloud metadata endpoints are blocked.");
            } else {
                println!("\n── Cloud metadata guard issues ───────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Smbrelay => {
            let findings = pledgeshield::harden::smbrelay::audit_smbrelay();
            if findings.is_empty() {
                println!("\n  ✓ SMB relay protection looks good.");
            } else {
                println!("\n── SMB relay issues ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Extwhitelist { list } => {
            if list {
                println!("\n── Approved browser extensions ──────────────────");
                for line in pledgeshield::harden::extwhitelist::list_extensions() {
                    println!("{}", line);
                }
                return;
            }
            let findings = pledgeshield::harden::extwhitelist::audit_extwhitelist();
            if findings.is_empty() {
                println!("\n  ✓ Browser extensions look good.");
            } else {
                println!("\n── Browser extension findings ────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Arplock { lock, unlock } => {
            if unlock {
                println!("\n── Unlocking ARP table ───────────────────────────");
                println!("{}", pledgeshield::harden::arplock::unlock_arp());
                return;
            }
            if lock {
                println!("\n── Locking ARP table ─────────────────────────────");
                println!("{}", pledgeshield::harden::arplock::lock_arp(false));
                return;
            }
            let findings = pledgeshield::harden::arplock::audit_arplock();
            if findings.is_empty() {
                println!("\n  ✓ ARP table is locked.");
            } else {
                println!("\n── ARP table issues ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Dnspoison => {
            let findings = pledgeshield::harden::dnspoison::audit_dnspoison();
            if findings.is_empty() {
                println!("\n  ✓ No DNS cache poisoning indicators.");
            } else {
                println!("\n── DNS cache poisoning indicators ────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Beacon => {
            let findings = pledgeshield::harden::beacon::audit_beacon();
            if findings.is_empty() {
                println!("\n  ✓ No Bluetooth tracking beacons detected.");
            } else {
                println!("\n── Bluetooth tracking beacons ────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Firmware => {
            let findings = pledgeshield::harden::firmware::audit_firmware();
            if findings.is_empty() {
                println!("\n  ✓ Firmware integrity looks good.");
            } else {
                println!("\n── Firmware integrity issues ─────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Memsnap { capture } => {
            if let Some(pid) = capture {
                println!("\n── Capturing memory snapshot ─────────────────────");
                println!("{}", pledgeshield::harden::memsnap::capture_snapshot(&pid));
                return;
            }
            let findings = pledgeshield::harden::memsnap::audit_memsnap();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious memory regions detected.");
            } else {
                println!("\n── Memory anomalies ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Honeyport { deploy } => {
            if let Some(port) = deploy {
                println!("\n── Deploying honeyport ───────────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::honeyport::deploy_honeyport(port, false)
                );
                return;
            }
            let findings = pledgeshield::harden::honeyport::audit_honeyport();
            if findings.is_empty() {
                println!("\n  ✓ Honeyport services detected.");
            } else {
                println!("\n── Honeyport status ──────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Credguard { enable } => {
            if enable {
                println!("\n── Enabling credential guard ─────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::credguard::enable_credguard(false)
                );
                return;
            }
            let findings = pledgeshield::harden::credguard::audit_credguard();
            if findings.is_empty() {
                println!("\n  ✓ Credential guard is enabled.");
            } else {
                println!("\n── Credential guard issues ───────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Sidechannel { mitigate } => {
            if mitigate {
                println!("\n── Applying side-channel mitigations ─────────────");
                println!(
                    "{}",
                    pledgeshield::harden::sidechannel::mitigate_sidechannel(false)
                );
                return;
            }
            let findings = pledgeshield::harden::sidechannel::audit_sidechannel();
            if findings.is_empty() {
                println!("\n  ✓ Side-channel mitigations are in place.");
            } else {
                println!("\n── Side-channel vulnerabilities ──────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Verify { package } => {
            if let Some(pkg) = package {
                println!("\n── Verifying package: {} ──────────────────────", pkg);
                let findings = pledgeshield::harden::verify::verify_package(&pkg);
                if findings.is_empty() {
                    println!("\n  ✓ Package {} is unmodified.", pkg);
                } else {
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            let findings = pledgeshield::harden::verify::audit_verify();
            if findings.is_empty() {
                println!("\n  ✓ Supply chain verification looks good.");
            } else {
                println!("\n── Supply chain issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Zerotrust { enable, disable } => {
            if disable {
                println!("\n── Disabling zero-trust policy ───────────────────");
                println!("{}", pledgeshield::harden::zerotrust::disable_zerotrust());
                return;
            }
            if enable {
                println!("\n── Enabling zero-trust policy ────────────────────");
                println!(
                    "{}",
                    pledgeshield::harden::zerotrust::enable_zerotrust(false)
                );
                return;
            }
            let findings = pledgeshield::harden::zerotrust::audit_zerotrust();
            if findings.is_empty() {
                println!("\n  ✓ Zero-trust policy is enforced.");
            } else {
                println!("\n── Zero-trust issues ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Escrow { show } => {
            if show {
                println!("\n── Recovery keys ─────────────────────────────────");
                println!("{}", pledgeshield::harden::escrow::escrow_keys());
                return;
            }
            let findings = pledgeshield::harden::escrow::audit_escrow();
            if findings.is_empty() {
                println!("\n  ✓ Disk encryption recovery keys are configured.");
            } else {
                println!("\n── Recovery key issues ───────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Dnstunnel => {
            let findings = pledgeshield::harden::dnstunnel::audit_dnstunnel();
            if findings.is_empty() {
                println!("\n  ✓ No DNS tunneling detected.");
            } else {
                println!("\n── DNS tunneling indicators ──────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Gpumon => {
            let findings = pledgeshield::harden::gpumon::audit_gpumon();
            if findings.is_empty() {
                println!("\n  ✓ No suspicious GPU processes detected.");
            } else {
                println!("\n── GPU process anomalies ─────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Freeze { freeze, resume } => {
            if let Some(pid) = resume {
                println!("\n── Resuming process {} ───────────────────────", pid);
                println!("{}", pledgeshield::harden::freeze::resume_process(&pid));
                return;
            }
            if let Some(pid) = freeze {
                println!("\n── Freezing process {} ───────────────────────", pid);
                println!("{}", pledgeshield::harden::freeze::freeze_process(&pid));
                return;
            }
            let findings = pledgeshield::harden::freeze::audit_freeze();
            if findings.is_empty() {
                println!("\n  ✓ No zombie or stopped processes detected.");
            } else {
                println!("\n── Process anomalies ─────────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Pinmon => {
            let findings = pledgeshield::harden::pinmon::audit_pinmon();
            if findings.is_empty() {
                println!("\n  ✓ No certificate pinning violations detected.");
            } else {
                println!("\n── Certificate pinning issues ────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Segment { enforce } => {
            if enforce {
                println!("\n── Enforcing network segmentation ────────────────");
                println!("{}", pledgeshield::harden::segment::enforce_segment(false));
                return;
            }
            let findings = pledgeshield::harden::segment::audit_segment();
            if findings.is_empty() {
                println!("\n  ✓ Network segmentation looks good.");
            } else {
                println!("\n── Network segmentation issues ───────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Rtfim { start } => {
            if start {
                println!("\n── Starting real-time FIM ────────────────────────");
                println!("{}", pledgeshield::harden::rtfim::start_rtfim());
                return;
            }
            let findings = pledgeshield::harden::rtfim::audit_rtfim();
            if findings.is_empty() {
                println!("\n  ✓ Real-time FIM is running.");
            } else {
                println!("\n── Real-time FIM issues ──────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Usbwhitelist { add, clear } => {
            if clear {
                println!("\n── Clearing USB whitelist ────────────────────────");
                println!("{}", pledgeshield::harden::usbwhitelist::clear_whitelist());
                return;
            }
            if let Some(device) = add {
                let parts: Vec<&str> = device.split(':').collect();
                if parts.len() == 2 {
                    println!(
                        "\n── Adding USB device {}/{} ──────────────────",
                        parts[0], parts[1]
                    );
                    println!(
                        "{}",
                        pledgeshield::harden::usbwhitelist::add_device(parts[0], parts[1])
                    );
                } else {
                    println!(
                        "\n  Usage: pledgeshield harden usbwhitelist --add vendor_id:product_id"
                    );
                }
                return;
            }
            let findings = pledgeshield::harden::usbwhitelist::audit_usbwhitelist();
            if findings.is_empty() {
                println!("\n  ✓ USB whitelist is configured.");
            } else {
                println!("\n── USB whitelist issues ──────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Imagescan { image } => {
            if let Some(img) = image {
                println!("\n── Scanning image: {} ──────────────────────────", img);
                let findings = pledgeshield::harden::imagescan::scan_image(&img);
                if findings.is_empty() {
                    println!("\n  ✓ No vulnerabilities found in {}.", img);
                } else {
                    for f in &findings {
                        println!("  [{}] {} — {}", f.severity, f.id, f.title);
                    }
                }
                return;
            }
            let findings = pledgeshield::harden::imagescan::audit_imagescan();
            if findings.is_empty() {
                println!("\n  ✓ Container image setup looks good.");
            } else {
                println!("\n── Container image issues ────────────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }

        HardenAction::Migrate => {
            let findings = pledgeshield::harden::migrate::audit_migrate();
            if findings.is_empty() {
                println!("\n  ✓ No anomalous process migration detected.");
            } else {
                println!("\n── Process migration anomalies ───────────────────");
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.id, f.title);
                }
            }
        }
    }
}

fn run_vpn(action: VpnAction) {
    match action {
        VpnAction::Status => {
            let s = pledgeshield::vpn::status();
            println!("\n{}", s);
        }
        VpnAction::Connect { config, vpn_type } => match vpn_type.as_str() {
            "wireguard" | "wg" => match pledgeshield::vpn::connect_wireguard(&config) {
                Ok(msg) => println!("\n  ✓ {}", msg),
                Err(e) => eprintln!("\n  ✗ {}", e),
            },
            "openvpn" | "ovpn" => match pledgeshield::vpn::connect_openvpn(&config) {
                Ok(msg) => println!("\n  ✓ {}", msg),
                Err(e) => eprintln!("\n  ✗ {}", e),
            },
            _ => eprintln!(
                "Unknown VPN type '{}'. Use: wireguard or openvpn.",
                vpn_type
            ),
        },
        VpnAction::Disconnect { vpn_type, config } => match vpn_type.as_str() {
            "wireguard" | "wg" => {
                let cfg = match config {
                    Some(c) => c,
                    None => {
                        let s = pledgeshield::vpn::status();
                        if !s.active || s.vpn_type != pledgeshield::vpn::VpnType::WireGuard {
                            eprintln!("No active WireGuard VPN detected.");
                            return;
                        }
                        match s.interface {
                            Some(i) => i,
                            None => {
                                eprintln!(
                                    "Error: --config required (could not auto-detect interface)."
                                );
                                return;
                            }
                        }
                    }
                };
                match pledgeshield::vpn::disconnect_wireguard(&cfg) {
                    Ok(msg) => println!("\n  ✓ {}", msg),
                    Err(e) => eprintln!("\n  ✗ {}", e),
                }
            }
            "openvpn" | "ovpn" => match pledgeshield::vpn::disconnect_openvpn() {
                Ok(msg) => println!("\n  ✓ {}", msg),
                Err(e) => eprintln!("\n  ✗ {}", e),
            },
            _ => eprintln!(
                "Unknown VPN type '{}'. Use: wireguard or openvpn.",
                vpn_type
            ),
        },
        VpnAction::List => {
            let configs = pledgeshield::vpn::list_wireguard_configs();
            if configs.is_empty() {
                println!("No WireGuard configs found in /etc/wireguard/.");
            } else {
                println!("Available WireGuard configs:");
                for c in &configs {
                    println!("  {}", c);
                }
            }
        }
        VpnAction::KillSwitchOn => match pledgeshield::vpn::enable_kill_switch() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        VpnAction::KillSwitchOff => match pledgeshield::vpn::disable_kill_switch() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        VpnAction::Tor { action } => {
            run_tor(action);
        }
    }
}

fn run_tor(action: TorAction) {
    match action {
        TorAction::Status => {
            let s = pledgeshield::vpn::tor::status();
            println!("\n{}", s);
            if !pledgeshield::vpn::tor::is_installed() {
                println!("  ⚠ Tor is not installed. Install with: sudo apt install tor");
            }
        }
        TorAction::Start => match pledgeshield::vpn::tor::start() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        TorAction::Stop => match pledgeshield::vpn::tor::stop() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        TorAction::Route => match pledgeshield::vpn::tor::route_traffic() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        TorAction::Unroute => match pledgeshield::vpn::tor::unroute_traffic() {
            Ok(msg) => println!("\n  ✓ {}", msg),
            Err(e) => eprintln!("\n  ✗ {}", e),
        },
        TorAction::CheckIp => {
            if !pledgeshield::vpn::tor::is_tor_running() {
                eprintln!("\n  ✗ Tor is not running. Start it first: pledgeshield vpn tor start");
                return;
            }
            print!("\n  Checking exit IP through Tor... ");
            std::io::stdout().flush().ok();
            match pledgeshield::vpn::tor::check_exit_ip() {
                Some(ip) => println!("\n  ✓ Your Tor exit IP: {}", ip),
                None => {
                    println!("\n  ✗ Could not determine exit IP (Tor may still be bootstrapping).")
                }
            }
        }
    }
}

fn run_monitor(config: pledgeshield::monitor::MonitorConfig) {
    // Set up Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    // We can't easily interrupt the thread::sleep in run_monitor,
    // so we run it with a short max_runtime loop.
    if config.max_runtime > 0 {
        pledgeshield::monitor::run_monitor(&config);
    } else {
        // Run in 60s chunks so we can check the Ctrl+C flag
        let mut cfg = config.clone();
        loop {
            cfg.max_runtime = 60;
            pledgeshield::monitor::run_monitor(&cfg);
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                println!("\n  Monitor stopped.");
                break;
            }
        }
    }
}

/// Simple Ctrl+C handler that sets a flag.
fn ctrlc_handler<F: Fn() + Send + 'static>(handler: F) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::raw::c_int;
        extern "C" {
            fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
        }
        static mut HANDLER: Option<Box<dyn Fn() + Send + 'static>> = None;
        extern "C" fn on_sig(_: c_int) {
            unsafe {
                let ptr = &raw const HANDLER;
                if let Some(h) = &*ptr {
                    h();
                }
            }
        }
        unsafe {
            HANDLER = Some(Box::new(handler));
            signal(2, on_sig); // SIGINT = 2
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = handler;
    }
}
