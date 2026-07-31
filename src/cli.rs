use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pledgeshield",
    version,
    about = "Personal device security auditor — finds what antivirus misses",
    long_about = "PledgeShield scans your device for misconfigurations, exposed services, \
                  unpatched software, privilege escalation vectors, and other attack surfaces."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a security scan
    Scan {
        /// Enable CVE checks against online APIs
        #[arg(long)]
        cve: bool,

        /// Comma-separated list of modules to run (e.g. services,shares,persistence)
        #[arg(long, value_delimiter = ',')]
        modules: Option<Vec<String>>,

        /// Output format: text, json, html, sarif, markdown, pdf
        #[arg(long, default_value = "text")]
        format: OutputFormat,

        /// Output file path (defaults to stdout)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Minimum severity to report: critical, high, medium, low, info
        #[arg(long)]
        min_severity: Option<String>,

        /// Interactive fix mode — prompt for each finding
        #[arg(long)]
        fix: bool,

        /// Offline mode — use cached CVE data only
        #[arg(long)]
        offline: bool,

        /// Force refresh CVE cache before scanning
        #[arg(long)]
        refresh_cve: bool,

        /// NVD API key (for higher rate limits)
        #[arg(long, env = "NVD_API_KEY")]
        nvd_api_key: Option<String>,

        /// GitHub token for GHSA API (higher rate limits)
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,

        /// Path to config file (TOML or YAML)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Path to baseline scan JSON for diff comparison
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Save current scan as baseline to the given path
        #[arg(long)]
        save_baseline: Option<PathBuf>,

        /// Verify remediation by re-scanning after fixes
        #[arg(long)]
        verify: bool,
    },

    /// Generate a sample config file
    InitConfig {
        /// Output path for the sample config
        #[arg(long, default_value = "pledgeshield.toml")]
        output: PathBuf,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Html,
    Sarif,
    Markdown,
    Pdf,
}
