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

        /// Print CIS/NIST compliance mapping for findings
        #[arg(long)]
        compliance: bool,

        /// Record this scan in the local SQLite history database
        #[arg(long)]
        save_history: bool,

        /// Path to a custom checks file (TOML or YAML) to run alongside built-in modules
        #[arg(long)]
        custom_checks: Option<PathBuf>,

        /// Webhook URL to notify on critical/high findings (Slack/Discord/Teams/generic)
        #[arg(long)]
        notify_webhook: Option<String>,
    },

    /// Generate a sample config file
    InitConfig {
        /// Output path for the sample config
        #[arg(long, default_value = "pledgeshield.toml")]
        output: PathBuf,
    },

    /// Show scan history from the local SQLite database
    History {
        /// Maximum number of entries to show
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Clear all history entries
        #[arg(long)]
        clear: bool,
    },

    /// Show a trend dashboard from scan history
    Trend {
        /// Maximum number of scans to include
        #[arg(long, default_value = "20")]
        limit: u32,
    },

    /// Install or remove a scheduled scan (cron / Task Scheduler / launchd)
    Schedule {
        /// Cron expression (Linux/macOS) or schedule keyword (Windows: daily/weekly/reboot)
        #[arg(long)]
        cron: String,

        /// PledgeShield scan arguments to run on schedule (e.g. "scan --format json --output /tmp/scan.json")
        #[arg(long, default_value = "scan")]
        command: String,

        /// Remove the scheduled task instead of installing it
        #[arg(long)]
        remove: bool,
    },

    /// Active defense: close insecure ports, spoof MAC, harden identity
    Harden {
        #[command(subcommand)]
        action: HardenAction,
    },

    /// VPN / proxy status & connection management (WireGuard, OpenVPN)
    Vpn {
        #[command(subcommand)]
        action: VpnAction,
    },

    /// Real-time security monitor — watch for new ports, processes, firewall changes
    Monitor {
        /// Polling interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Don't watch for new listening ports
        #[arg(long)]
        no_ports: bool,

        /// Don't watch for new root/SYSTEM processes
        #[arg(long)]
        no_processes: bool,

        /// Don't watch for firewall state changes
        #[arg(long)]
        no_firewall: bool,

        /// Stop after this many seconds (0 = run forever until Ctrl+C)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },
}

/// Active-defense hardening actions.
#[derive(Subcommand)]
pub enum HardenAction {
    /// Close insecure open ports via firewall rules
    Ports {
        /// Block ALL listening ports, not just known-insecure ones
        #[arg(long)]
        all: bool,

        /// Only show what would be done, don't change anything
        #[arg(long)]
        dry_run: bool,

        /// Remove PledgeShield-added firewall block rules
        #[arg(long)]
        restore: bool,
    },

    /// Spoof or randomize a network interface's MAC address
    Mac {
        /// Network interface (e.g. eth0, wlan0). Use `--list` to see available.
        #[arg(long)]
        interface: Option<String>,

        /// New MAC address. If omitted, a random locally-administered MAC is generated.
        #[arg(long)]
        mac: Option<String>,

        /// List available network interfaces
        #[arg(long)]
        list: bool,

        /// Restore the original MAC (cycles the interface; full restore may need reboot)
        #[arg(long)]
        restore: bool,
    },

    /// Harden identity/privacy: set privacy DNS, disable telemetry
    Identity {
        /// Only show what would be done, don't change anything
        #[arg(long)]
        dry_run: bool,
    },

    /// Enable/harden/disable the system firewall
    Firewall {
        /// Enable the firewall
        #[arg(long)]
        enable: bool,

        /// Harden: set default DROP/deny inbound, allow only essential
        #[arg(long)]
        harden: bool,

        /// Allow SSH (port 22) through the hardened firewall
        #[arg(long)]
        allow_ssh: bool,

        /// Disable the firewall entirely
        #[arg(long)]
        disable: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Harden browser privacy: disable telemetry, enable tracking protection, clear data
    Browser {
        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,

        /// Clear cookies, cache, and history (browser must be closed)
        #[arg(long)]
        clear_data: bool,
    },

    /// Configure DNS-over-HTTPS/TLS for encrypted DNS
    Doh {
        /// Enable DoH with a provider (cloudflare, google, quad9, adguard, or a URL)
        #[arg(long)]
        enable: Option<String>,

        /// Disable DoH and revert to plaintext DNS
        #[arg(long)]
        disable: bool,

        /// List available DoH providers
        #[arg(long)]
        list: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Audit WiFi security (open networks, WEP, auto-connect, saved networks)
    Wifi {
        /// Forget a saved network by name
        #[arg(long)]
        forget: Option<String>,
    },

    /// ARP spoofing detector — monitor for MITM attacks
    Arp {
        /// Run real-time ARP monitor
        #[arg(long)]
        monitor: bool,

        /// Polling interval in seconds (for --monitor)
        #[arg(long, default_value = "3")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// Network isolation — block all outbound except whitelisted IPs
    Isolation {
        /// Enable isolation (comma-separated whitelist of IPs)
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,

        /// Disable isolation (restore normal OUTPUT policy)
        #[arg(long)]
        disable: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Proxy chain manager — set/clear SOCKS5/HTTP proxy
    Proxy {
        /// Set proxy (type:host:port, e.g. socks5:127.0.0.1:9050)
        #[arg(long)]
        set: Option<String>,

        /// Clear proxy settings
        #[arg(long)]
        clear: bool,

        /// Show current proxy settings
        #[arg(long)]
        show: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// IPv6 leak guard — disable or firewall IPv6
    Ipv6 {
        /// Disable IPv6 entirely
        #[arg(long)]
        disable: bool,

        /// Block IPv6 traffic via firewall (keeps IPv6 stack)
        #[arg(long)]
        firewall: bool,

        /// Restore IPv6 (re-enable + remove firewall rules)
        #[arg(long)]
        restore: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Hosts file hardener — block ad/tracker/malware domains
    Hosts {
        /// Update blocklists from known sources
        #[arg(long)]
        update: bool,

        /// Restore original hosts file from backup
        #[arg(long)]
        restore: bool,

        /// Block a specific domain
        #[arg(long)]
        block: Option<String>,

        /// Show count of blocked domains
        #[arg(long)]
        count: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Bandwidth/traffic monitor — track per-process network usage
    Traffic {
        /// Run real-time traffic monitor
        #[arg(long)]
        monitor: bool,

        /// Polling interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,

        /// Number of top processes to show
        #[arg(long, default_value = "10")]
        top: usize,
    },

    /// Randomize machine hostname to prevent network tracking
    Hostname {
        /// Randomize hostname now
        #[arg(long)]
        randomize: bool,

        /// Install boot-time randomizer (systemd service)
        #[arg(long)]
        install_boot: bool,

        /// Show current hostname
        #[arg(long)]
        show: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Spoof browser user-agent to prevent fingerprinting
    Useragent {
        /// Set custom UA (omit to use a common one)
        #[arg(long)]
        set: Option<Option<String>>,

        /// Reset UA to browser default
        #[arg(long)]
        reset: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Block WebRTC to prevent IP leaks behind VPN
    Webrtc {
        /// Block WebRTC in all browsers
        #[arg(long)]
        block: bool,

        /// Restore WebRTC
        #[arg(long)]
        restore: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Bluetooth privacy — audit, hide, disable, remove paired devices
    Bluetooth {
        /// List paired devices
        #[arg(long)]
        list: bool,

        /// Disable Bluetooth discoverability
        #[arg(long)]
        hide: bool,

        /// Power off Bluetooth
        #[arg(long)]
        disable: bool,

        /// Remove a paired device by MAC
        #[arg(long)]
        remove: Option<String>,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Camera/mic guard — audit and block device access
    Devices {
        /// Block camera access
        #[arg(long)]
        block_camera: bool,

        /// Restore camera access
        #[arg(long)]
        restore_camera: bool,
    },

    /// Clipboard privacy — clear clipboard, install auto-clear watcher
    Clipboard {
        /// Clear clipboard now
        #[arg(long)]
        clear: bool,

        /// Install auto-clear watcher (clears after N seconds)
        #[arg(long)]
        watch: Option<u64>,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Clear recent files, shell history, temp files, activity traces
    Cleaner {
        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// USB device guard — audit, lockdown, restore
    Usb {
        /// List connected USB devices
        #[arg(long)]
        list: bool,

        /// Lockdown: only allow currently connected devices
        #[arg(long)]
        lockdown: bool,

        /// Restore: remove USB lockdown
        #[arg(long)]
        restore: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Kernel module lockdown — restrict module loading
    Kernel {
        /// List loaded kernel modules
        #[arg(long)]
        list: bool,

        /// Lock kernel module loading (irreversible until reboot!)
        #[arg(long)]
        lockdown: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// SUID/SGID scanner — find and remove suspicious SUID binaries
    Suid {
        /// Remove SUID bit from a specific binary
        #[arg(long)]
        remove: Option<String>,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Cron/systemd timer auditor — deep scan for suspicious scheduled tasks
    Scheduler,

    /// File integrity monitor — hash and verify critical system files
    Integrity {
        /// Create baseline of file hashes
        #[arg(long)]
        baseline: bool,

        /// Check current files against baseline
        #[arg(long)]
        check: bool,

        /// Remove baseline
        #[arg(long)]
        remove: bool,
    },

    /// Process tree analyzer — detect suspicious parent-child relationships
    Proctree,

    /// Lock screen enforcer — set timeout, disable auto-login
    Lockscreen {
        /// Enable screen lock with timeout (seconds)
        #[arg(long)]
        enable: Option<u32>,

        /// Disable auto-login
        #[arg(long)]
        disable_autologin: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Disk encryption enabler — audit and guide encryption setup
    Encryption {
        /// Show encryption guide
        #[arg(long)]
        enable: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Rootkit scanner — check for common rootkit indicators
    Rootkit,

    /// Ransomware canary — plant decoy files, check for encryption
    Canary {
        /// Plant canary files
        #[arg(long)]
        plant: bool,

        /// Check canary files for modification
        #[arg(long)]
        check: bool,

        /// Remove all canary files
        #[arg(long)]
        remove: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Login attempt monitor — track failed logins, detect brute force
    Logins {
        /// Block a specific IP
        #[arg(long)]
        block: Option<String>,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// DNS query monitor — detect DGA, C2, fast flux, suspicious TLDs
    Dnsmon {
        /// Run real-time DNS monitor
        #[arg(long)]
        monitor: bool,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// Secure file shredder — overwrite and delete files
    Shredder {
        /// File or directory to shred
        #[arg(long)]
        file: Option<String>,

        /// Number of overwrite passes
        #[arg(long, default_value = "3")]
        passes: u32,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Memory/swap wipe — prevent cold-boot attacks
    Memwipe {
        /// Wipe swap space
        #[arg(long)]
        wipe_swap: bool,

        /// Set up encrypted swap
        #[arg(long)]
        encrypt_swap: bool,

        /// Install RAM wipe on shutdown
        #[arg(long)]
        install_ramwipe: bool,

        /// Drop kernel caches now
        #[arg(long)]
        drop_caches: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Metadata stripper — remove EXIF/metadata from files
    Metadata {
        /// Strip metadata from a file
        #[arg(long)]
        strip: Option<String>,

        /// Output file path (default: <name>_clean.<ext>)
        #[arg(long)]
        output: Option<String>,

        /// List metadata in a file
        #[arg(long)]
        list: Option<String>,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    // === Boot & Firmware ===

    /// UEFI/BIOS security audit (Secure Boot, boot password)
    Uefi,

    /// Boot log analyzer — check for boot-time anomalies
    Bootlog,

    /// Kernel parameter (sysctl) hardener — ASLR, ptrace, dmesg restrictions
    Sysctl {
        /// Apply all secure sysctl settings
        #[arg(long)]
        harden: bool,

        /// Restore default sysctl settings (remove PledgeShield config)
        #[arg(long)]
        restore: bool,
    },

    /// Kernel module signature verifier
    Modsign,

    /// TPM status checker
    Tpm,

    // === File & Data Protection ===

    /// File permission auditor — find world-readable/writable sensitive files
    Fileperms {
        /// Fix permissions on sensitive files
        #[arg(long)]
        fix: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Sensitive file finder — locate private keys, certs, password files
    Sensitive,

    /// Data exfiltration guard — monitor for large file copies to USB/network
    Exfil {
        /// Run real-time exfiltration monitor
        #[arg(long)]
        monitor: bool,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// Backup integrity checker — verify backups exist, are recent, match hash
    Backup {
        /// Backup directory to check
        #[arg(long)]
        dir: Option<String>,

        /// Verify a backup file's hash
        #[arg(long)]
        verify: Option<String>,

        /// Expected hash for --verify
        #[arg(long)]
        hash: Option<String>,
    },

    /// Disk usage anomaly detector — flag sudden space changes (ransomware indicator)
    Diskmon {
        /// Run real-time disk usage monitor
        #[arg(long)]
        monitor: bool,

        /// Polling interval in seconds
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// Log tampering detector — check for truncated/deleted system logs
    Logtamper,

    // === SSH & Remote Access ===

    /// SSH config hardener — disable root login, password auth, enforce keys
    Ssh {
        /// Apply secure SSH settings
        #[arg(long)]
        harden: bool,

        /// Restore original SSH config
        #[arg(long)]
        restore: bool,
    },

    /// SSH key auditor — check key sizes, passphrases, permissions
    Sshkeys,

    /// Port knocking setup — hide SSH from port scanners
    Knock {
        /// Install knockd with a sequence (comma-separated ports)
        #[arg(long, value_delimiter = ',')]
        install: Vec<u16>,

        /// Remove knockd configuration
        #[arg(long)]
        remove: bool,
    },

    /// Fail2ban auto-configurator — install/configure brute force protection
    Fail2ban {
        /// Install fail2ban
        #[arg(long)]
        install: bool,

        /// Configure fail2ban with optimal jails
        #[arg(long)]
        configure: bool,

        /// Show fail2ban status
        #[arg(long)]
        status: bool,
    },

    // === Application Hardening ===

    /// SSL/TLS certificate checker — check your own certs for expiration/weak ciphers
    Tls {
        /// Certificate file path or hostname:port to check
        #[arg(long)]
        check: Option<String>,
    },

    /// Dependency vulnerability scanner — scan package manifests for CVEs
    Deps {
        /// Directory to scan (default: current directory)
        #[arg(long)]
        dir: Option<String>,
    },

    /// Secret scanner — scan your own files for committed API keys/tokens
    Secrets {
        /// Directory to scan
        #[arg(long)]
        dir: Option<String>,
    },

    /// Browser password vault auditor — check if saved passwords are encrypted
    Vault,

    /// Autorun/AutoPlay disabler — prevent malware auto-execution from USB
    Autorun {
        /// Disable autorun/autoplay
        #[arg(long)]
        disable: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    // === System Monitoring ===

    /// System resource anomaly detector — CPU/RAM spikes, crypto miners
    Resource {
        /// Run real-time resource monitor
        #[arg(long)]
        monitor: bool,

        /// Polling interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// New file watcher — monitor system directories for new executables
    Filewatch {
        /// Run real-time file watcher
        #[arg(long)]
        monitor: bool,

        /// Create initial baseline
        #[arg(long)]
        baseline: bool,

        /// Polling interval in seconds
        #[arg(long, default_value = "30")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    /// User account change monitor — alert on new users, UID changes, sudoers mods
    Usermon {
        /// Create initial baseline
        #[arg(long)]
        baseline: bool,
    },

    /// Network connection auditor — list all outbound connections with processes
    Netcons {
        /// List all current connections
        #[arg(long)]
        list: bool,
    },

    /// Crontab modification monitor — alert on new/modified scheduled tasks
    Cronmon {
        /// Run real-time cron modification monitor
        #[arg(long)]
        monitor: bool,

        /// Create initial baseline
        #[arg(long)]
        baseline: bool,

        /// Polling interval in seconds
        #[arg(long, default_value = "60")]
        interval: u64,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    // === Privacy & Compliance ===

    /// PII scanner — scan your own files for SSNs, credit cards, phone numbers
    Pii {
        /// Directory to scan
        #[arg(long)]
        dir: Option<String>,
    },

    /// Telemetry deep-cleaner — disable ALL telemetry across OS, browsers, dev tools
    Telemetry {
        /// Disable all detected telemetry
        #[arg(long)]
        clean: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Disk free space wiper — overwrite deleted files so they can't be recovered
    Freespace {
        /// Wipe free space on a path (e.g. / or /home)
        #[arg(long)]
        wipe: Option<String>,

        /// Install weekly wipe schedule
        #[arg(long)]
        install_schedule: bool,

        /// Remove weekly wipe schedule
        #[arg(long)]
        remove_schedule: bool,

        /// Only show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Security posture score — aggregate findings into 0-100 score with grade
    Posture,

    /// Hardening profile applier — apply CIS Level 1/2, STIG, or custom profiles
    Profile {
        /// Profile to apply: cis1, cis2, stig, custom
        #[arg(long)]
        apply: Option<crate::harden::profile::Profile>,

        /// Audit against a profile (show what would change)
        #[arg(long)]
        audit: Option<crate::harden::profile::Profile>,
    },

    // === Process & Memory Defense ===

    /// Process injection detector — scan for suspicious injected libraries
    Procinj,

    /// Hollow process detector — detect process name/binary mismatches
    Hollow,

    /// Memory scanner — scan process memory for malware signatures
    Memscan,

    /// Debugger/ptrace detector — alert if processes are being traced
    Ptrace,

    /// Thread anomaly detector — flag suspicious thread counts
    Thread,

    /// Code injection blocker — harden ptrace_scope, disable BPF
    Codeinject {
        /// Apply anti-injection hardening
        #[arg(long)]
        block: bool,
    },

    // === Network Defense ===

    /// Connection rate limiter — limit new outbound connections
    Ratelimit {
        /// Enable rate limiting (max connections per minute)
        #[arg(long)]
        enable: Option<u32>,

        /// Disable rate limiting
        #[arg(long)]
        disable: bool,
    },

    /// Geo-IP outbound filter — block connections to high-risk countries
    Geoip {
        /// Enable geo-IP filter
        #[arg(long)]
        enable: bool,

        /// Disable geo-IP filter
        #[arg(long)]
        disable: bool,
    },

    /// DNS-over-HTTPS enforcement — force encrypted DNS, block port 53
    Dohforce {
        /// Enforce DoH/DoT and block plaintext DNS
        #[arg(long)]
        enforce: bool,

        /// Disable enforcement
        #[arg(long)]
        disable: bool,
    },

    /// Packet capture detector — detect promiscuous mode and sniffers
    Pcapdetect,

    /// Rogue DHCP detector — detect DHCP responses from non-router sources
    Roguedhcp,

    /// WiFi deauth detector — detect deauthentication attacks
    Deauth {
        /// Run real-time deauth monitor
        #[arg(long)]
        monitor: bool,

        /// Max runtime in seconds (0 = forever)
        #[arg(long, default_value = "0")]
        max_runtime: u64,
    },

    // === Filesystem & Storage ===

    /// Immutable file setter — protect critical system files with chattr +i
    Immutable {
        /// Set immutable flag on critical files
        #[arg(long)]
        set: bool,

        /// Remove immutable flag
        #[arg(long)]
        unset: bool,
    },

    /// Mount option hardener — enforce nosuid, nodev, noexec on mount points
    Mount {
        /// Harden mount options
        #[arg(long)]
        harden: bool,
    },

    /// Temp directory sanitizer — clean /tmp, /var/tmp, /dev/shm
    Tmpsan {
        /// Clean stale files from temp directories
        #[arg(long)]
        clean: bool,
    },

    /// Quota enforcer — set disk quotas to prevent disk filling
    Quota {
        /// Enable disk quotas
        #[arg(long)]
        enable: bool,
    },

    /// File attribute monitor — watch for permission/immutable changes
    Attrmon {
        /// Create initial baseline
        #[arg(long)]
        baseline: bool,
    },

    // === Access Control ===

    /// PAM module auditor — check for backdoored/weak PAM modules
    Pam,

    /// Polkit/pkexec auditor — check for overly permissive polkit rules
    Polkit,

    /// AppArmor/SELinux enforcer — check MAC status
    Macaudit,

    /// Capability auditor — scan binaries for dangerous Linux capabilities
    Caps,

    /// Namespace isolation auditor — check process namespace isolation
    Nsaudit,

    // === Hardware & Peripherals ===

    /// Thunderbolt/USB4 guard — disable DMA, require device approval
    Thunderbolt {
        /// Block/deauthorize all Thunderbolt devices
        #[arg(long)]
        block: bool,
    },

    /// Webcam guard — disable webcam, check for unauthorized access
    Webcam {
        /// Block webcam (unload kernel module)
        #[arg(long)]
        block: bool,

        /// Restore webcam access
        #[arg(long)]
        restore: bool,
    },

    /// Microphone mute enforcer — mute mic at audio system level
    Micmute {
        /// Mute all microphones
        #[arg(long)]
        mute: bool,

        /// Unmute microphones
        #[arg(long)]
        unmute: bool,
    },

    /// Firewire/PCMCIA DMA guard — disable DMA access
    Firewire {
        /// Block FireWire/PCMCIA (unload modules)
        #[arg(long)]
        block: bool,

        /// Restore FireWire access
        #[arg(long)]
        restore: bool,
    },

    // === System Integrity ===

    /// Systemd unit auditor — deep scan for suspicious units
    Systemd,

    /// Environment variable leak checker — scan /proc for secrets in env
    Envleak,

    /// Shared library auditor — check LD_LIBRARY_PATH, RPATH, unusual paths
    Libaudit,

    /// Binary hash verifier — compare binaries against package manager hashes
    Binhash,
}

#[derive(Subcommand)]
pub enum VpnAction {
    /// Show current VPN status
    Status,

    /// Connect to a VPN
    Connect {
        /// WireGuard config name (in /etc/wireguard/) or OpenVPN .ovpn file path
        #[arg(long)]
        config: String,

        /// VPN type: wireguard or openvpn
        #[arg(long, default_value = "wireguard")]
        vpn_type: String,
    },

    /// Disconnect the active VPN
    Disconnect {
        /// VPN type: wireguard or openvpn
        #[arg(long, default_value = "wireguard")]
        vpn_type: String,

        /// WireGuard config name (for wireguard type)
        #[arg(long)]
        config: Option<String>,
    },

    /// List available WireGuard configs
    List,

    /// Enable a VPN kill switch (block all non-VPN traffic) — Linux only
    KillSwitchOn,

    /// Disable the VPN kill switch — Linux only
    KillSwitchOff,

    /// Tor proxy management
    Tor {
        #[command(subcommand)]
        action: TorAction,
    },
}

/// Tor proxy actions.
#[derive(Subcommand)]
pub enum TorAction {
    /// Show Tor status
    Status,

    /// Start the Tor daemon
    Start,

    /// Stop the Tor daemon
    Stop,

    /// Route all traffic through Tor (Linux, requires root)
    Route,

    /// Stop routing traffic through Tor (Linux)
    Unroute,

    /// Check your exit IP through Tor
    CheckIp,
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
