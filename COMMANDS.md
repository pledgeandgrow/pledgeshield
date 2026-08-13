# PledgeShield Commands

Complete command reference for PledgeShield.

---

## Top-Level Commands

```
pledgeshield <COMMAND>

Commands:
  scan         Run a security scan
  init-config  Generate a sample config file
  history      Show scan history from the local SQLite database
  trend        Show a trend dashboard from scan history
  schedule     Install or remove a scheduled scan (cron / Task Scheduler / launchd)
  harden       Active defense: 120+ hardening modules (firewall, privacy, detection, etc.)
  vpn          VPN / proxy status & connection management (WireGuard, OpenVPN, Tor)
  monitor      Real-time security monitor — watch for new ports, processes, firewall changes
```

---

## `scan` — Run a Security Scan

```
pledgeshield scan [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--cve` | Enable CVE scanning (NVD, OSV, GHSA, EPSS) |
| `--modules <LIST>` | Comma-separated list of modules to run (e.g. `services,shares,persistence`) |
| `--format <FORMAT>` | Output format: `text`, `json`, `html`, `sarif`, `markdown`, `pdf` (default: text) |
| `--output <PATH>` | Write report to file instead of stdout |
| `--min-severity <LVL>` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` |
| `--fix` | Interactive fix mode — prompt to apply fixes for each finding |
| `--offline` | Use cached CVE data only (air-gapped environments) |
| `--refresh-cve` | Force refresh CVE cache before scanning |
| `--nvd-api-key <KEY>` | NVD API key for higher rate limits (env: `NVD_API_KEY`) |
| `--github-token <TOKEN>` | GitHub token for GHSA API (env: `GITHUB_TOKEN`) |
| `--config <FILE>` | Load configuration from TOML/YAML file |
| `--baseline <FILE>` | Compare results against a baseline file |
| `--save-baseline <FILE>` | Save current scan as baseline to the given path |
| `--verify` | Verify that previously applied fixes are still in effect |
| `--compliance` | Print CIS/NIST compliance mapping for findings |
| `--save-history` | Save scan results to SQLite history database |
| `--custom-checks <FILE>` | Run user-defined checks from TOML/YAML file |
| `--notify-webhook <URL>` | Webhook URL to notify on critical/high findings (Slack/Discord/Teams) |

### Examples

```bash
# Basic scan
pledgeshield scan

# Full scan with CVE checking, compliance mapping, and HTML report
pledgeshield scan --cve --compliance --format html --output report.html

# Save to history and notify via webhook
pledgeshield scan --save-history --notify-webhook https://hooks.slack.com/services/xxx

# Interactive fix mode
pledgeshield scan --fix

# Run specific modules only
pledgeshield scan --modules services,shares,persistence

# Run custom checks from a TOML file
pledgeshield scan --custom-checks ./my-checks.toml

# Save baseline for future diff comparison
pledgeshield scan --save-baseline baseline.json

# Compare against baseline
pledgeshield scan --baseline baseline.json

# Offline mode (uses cached CVE data)
pledgeshield scan --cve --offline
```

---

## `init-config` — Generate Sample Config

```
pledgeshield init-config [OPTIONS]
```

Generates a sample configuration file in TOML or YAML format.

```bash
pledgeshield init-config --output pledgeshield.toml
```

---

## `history` — Scan History

```
pledgeshield history [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--limit <N>` | Show last N scans (default: 10) |
| `--clear` | Clear all scan history |

```bash
pledgeshield history --limit 20
pledgeshield history --clear
```

---

## `trend` — Trend Dashboard

```
pledgeshield trend [OPTIONS]
```

Shows a findings-over-time dashboard from scan history.

```bash
pledgeshield trend
pledgeshield trend --limit 30
```

---

## `schedule` — Scheduled Scans

```
pledgeshield schedule [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--install` | Install a scheduled scan |
| `--remove` | Remove a scheduled scan |
| `--cron <EXPR>` | Cron expression (Linux/macOS) or schedule (Windows) |
| `--command <CMD>` | Command to run (default: `scan`) |
| `--name <NAME>` | Name for the scheduled task |

```bash
# Daily scan at midnight
pledgeshield schedule --install --cron "0 0 * * *" --command "scan --cve"

# Remove a scheduled scan
pledgeshield schedule --remove --name "pledgeshield-daily"
```

---

## `harden` — Active Defense

```
pledgeshield harden <SUBCOMMAND> [OPTIONS]
```

120+ hardening modules across 19 categories. Run `pledgeshield harden --help` to see all available subcommands. See [MODULES.md](MODULES.md) for the full module reference.

### Network & Traffic

#### `harden ports` — Close Insecure Ports
```bash
pledgeshield harden ports                    # Close known-insecure ports
pledgeshield harden ports --all              # Block ALL listening ports
pledgeshield harden ports --dry-run          # Show what would be done
pledgeshield harden ports --restore          # Remove PledgeShield block rules
```

#### `harden firewall` — Firewall Management
```bash
pledgeshield harden firewall                 # Audit firewall status
pledgeshield harden firewall --enable        # Enable firewall
pledgeshield harden firewall --harden        # Set default DROP, allow only essential
pledgeshield harden firewall --harden --allow-ssh   # Harden but allow SSH
pledgeshield harden firewall --disable       # Disable firewall
pledgeshield harden firewall --dry-run       # Show what would be done
```

#### `harden doh` — DNS-over-HTTPS/TLS
```bash
pledgeshield harden doh                      # Audit DNS encryption
pledgeshield harden doh --list               # List available DoH providers
pledgeshield harden doh --enable cloudflare  # Enable DoH via Cloudflare
pledgeshield harden doh --enable google      # Enable DoH via Google
pledgeshield harden doh --enable quad9       # Enable DoH via Quad9
pledgeshield harden doh --enable adguard     # Enable DoH via AdGuard
pledgeshield harden doh --disable            # Disable DoH
pledgeshield harden doh --dry-run            # Show what would be done
```

#### `harden wifi` — WiFi Security Audit
```bash
pledgeshield harden wifi                     # Audit WiFi security
pledgeshield harden wifi --forget "NetworkName"  # Forget a saved network
```

#### `harden arp` — ARP Spoofing Detector
```bash
pledgeshield harden arp                      # Check for ARP spoofing
pledgeshield harden arp --monitor            # Real-time ARP monitoring
pledgeshield harden arp --monitor --interval 2 --max-runtime 60
```

#### `harden isolation` — Network Isolation
```bash
pledgeshield harden isolation --allow 1.1.1.1,8.8.8.8   # Block all except these IPs
pledgeshield harden isolation --disable                  # Restore normal traffic
pledgeshield harden isolation --dry-run                  # Show what would be done
```

#### `harden proxy` — Proxy Manager
```bash
pledgeshield harden proxy --set socks5:127.0.0.1:9050   # Set SOCKS5 proxy
pledgeshield harden proxy --set http:proxy.example.com:8080
pledgeshield harden proxy --show                         # Show current proxy
pledgeshield harden proxy --clear                        # Clear proxy settings
pledgeshield harden proxy --dry-run                      # Show what would be done
```

#### `harden ipv6` — IPv6 Leak Guard
```bash
pledgeshield harden ipv6                     # Audit IPv6 status
pledgeshield harden ipv6 --disable           # Disable IPv6 entirely
pledgeshield harden ipv6 --firewall          # Block IPv6 traffic via ip6tables
pledgeshield harden ipv6 --restore           # Restore IPv6
pledgeshield harden ipv6 --dry-run           # Show what would be done
```

#### `harden hosts` — Hosts File Hardener
```bash
pledgeshield harden hosts                    # Audit hosts file blocking
pledgeshield harden hosts --update           # Download and install blocklists
pledgeshield harden hosts --block ads.com    # Block a specific domain
pledgeshield harden hosts --count            # Show count of blocked domains
pledgeshield harden hosts --restore          # Restore original hosts file
pledgeshield harden hosts --dry-run          # Show what would be done
```

#### `harden traffic` — Bandwidth/Traffic Monitor
```bash
pledgeshield harden traffic                  # Audit for anomalous traffic
pledgeshield harden traffic --monitor        # Real-time traffic monitor
pledgeshield harden traffic --monitor --interval 2 --top 20 --max-runtime 60
```

---

### Identity & Privacy

#### `harden mac` — MAC Address Spoofer
```bash
pledgeshield harden mac --list               # List network interfaces
pledgeshield harden mac --interface eth0     # Spoof MAC on eth0 (random)
pledgeshield harden mac --interface eth0 --mac AA:BB:CC:DD:EE:FF
pledgeshield harden mac --interface eth0 --restore   # Restore original MAC
```

#### `harden identity` — Identity/Privacy Hardening
```bash
pledgeshield harden identity                 # Audit + harden identity
pledgeshield harden identity --dry-run       # Show what would be done
```

#### `harden hostname` — Hostname Randomizer
```bash
pledgeshield harden hostname --show          # Show current hostname
pledgeshield harden hostname --randomize     # Randomize hostname now
pledgeshield harden hostname --install-boot  # Install boot-time randomizer
pledgeshield harden hostname --dry-run       # Show what would be done
```

#### `harden useragent` — User-Agent Spoofer
```bash
pledgeshield harden useragent --set          # Set common UA (Chrome on Windows)
pledgeshield harden useragent --set "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
pledgeshield harden useragent --reset        # Reset to browser default
pledgeshield harden useragent --dry-run      # Show what would be done
```

#### `harden webrtc` — WebRTC Leak Blocker
```bash
pledgeshield harden webrtc                   # Audit WebRTC leak risk
pledgeshield harden webrtc --block           # Block WebRTC in all browsers
pledgeshield harden webrtc --restore         # Restore WebRTC
pledgeshield harden webrtc --dry-run         # Show what would be done
```

#### `harden bluetooth` — Bluetooth Privacy
```bash
pledgeshield harden bluetooth                # Audit Bluetooth
pledgeshield harden bluetooth --list         # List paired devices
pledgeshield harden bluetooth --hide         # Disable discoverability
pledgeshield harden bluetooth --disable      # Power off Bluetooth
pledgeshield harden bluetooth --remove AA:BB:CC:DD:EE:FF  # Remove paired device
pledgeshield harden bluetooth --dry-run      # Show what would be done
```

#### `harden devices` — Camera/Mic Guard
```bash
pledgeshield harden devices                  # Audit camera/mic access
pledgeshield harden devices --block-camera   # Block camera access
pledgeshield harden devices --restore-camera # Restore camera access
```

#### `harden clipboard` — Clipboard Privacy
```bash
pledgeshield harden clipboard --clear        # Clear clipboard now
pledgeshield harden clipboard --watch 30     # Auto-clear after 30 seconds
pledgeshield harden clipboard --dry-run      # Show what would be done
```

#### `harden cleaner` — Activity Cleaner
```bash
pledgeshield harden cleaner                  # Clear all activity traces
pledgeshield harden cleaner --dry-run        # Show what would be done
```

#### `harden browser` — Browser Privacy
```bash
pledgeshield harden browser                  # Audit + harden browser privacy
pledgeshield harden browser --clear-data     # Clear cookies, cache, history
pledgeshield harden browser --dry-run        # Show what would be done
```

---

### System Hardening

#### `harden usb` — USB Device Guard
```bash
pledgeshield harden usb                      # Audit USB security
pledgeshield harden usb --list               # List connected USB devices
pledgeshield harden usb --lockdown           # Only allow current devices
pledgeshield harden usb --restore            # Remove USB lockdown
pledgeshield harden usb --dry-run            # Show what would be done
```

#### `harden kernel` — Kernel Module Lockdown
```bash
pledgeshield harden kernel                   # Audit kernel modules
pledgeshield harden kernel --list            # List loaded modules
pledgeshield harden kernel --lockdown        # Lock module loading (irreversible until reboot!)
pledgeshield harden kernel --dry-run         # Show what would be done
```

#### `harden suid` — SUID/SGID Scanner
```bash
pledgeshield harden suid                     # Find SUID/SGID binaries
pledgeshield harden suid --remove /path/to/binary  # Remove SUID bit
pledgeshield harden suid --dry-run           # Show what would be done
```

#### `harden scheduler` — Cron/Systemd Auditor
```bash
pledgeshield harden scheduler                # Deep scan scheduled tasks
```

#### `harden integrity` — File Integrity Monitor
```bash
pledgeshield harden integrity --baseline     # Create hash baseline
pledgeshield harden integrity --check        # Check files against baseline
pledgeshield harden integrity --remove       # Remove baseline
```

#### `harden proctree` — Process Tree Analyzer
```bash
pledgeshield harden proctree                 # Detect suspicious process trees
```

#### `harden lockscreen` — Lock Screen Enforcer
```bash
pledgeshield harden lockscreen               # Audit lock screen settings
pledgeshield harden lockscreen --enable 300  # Set 5-minute lock timeout
pledgeshield harden lockscreen --disable-autologin  # Disable auto-login
pledgeshield harden lockscreen --dry-run     # Show what would be done
```

#### `harden encryption` — Disk Encryption
```bash
pledgeshield harden encryption               # Audit disk encryption
pledgeshield harden encryption --enable      # Show encryption setup guide
pledgeshield harden encryption --dry-run     # Show what would be done
```

---

### Detection & Response

#### `harden rootkit` — Rootkit Scanner
```bash
pledgeshield harden rootkit                  # Scan for rootkit indicators
```

#### `harden canary` — Ransomware Canary
```bash
pledgeshield harden canary --plant           # Plant canary files
pledgeshield harden canary --check           # Check canary files for modification
pledgeshield harden canary --remove          # Remove all canary files
pledgeshield harden canary --dry-run         # Show what would be done
```

#### `harden logins` — Login Attempt Monitor
```bash
pledgeshield harden logins                   # Check for brute force attempts
pledgeshield harden logins --block 1.2.3.4   # Block an IP address
pledgeshield harden logins --dry-run         # Show what would be done
```

#### `harden dnsmon` — DNS Query Monitor
```bash
pledgeshield harden dnsmon                   # Audit DNS queries for anomalies
pledgeshield harden dnsmon --monitor         # Real-time DNS monitoring
pledgeshield harden dnsmon --monitor --max-runtime 60
```

---

### Privacy Tools

#### `harden shredder` — Secure File Shredder
```bash
pledgeshield harden shredder --file /path/to/file           # Shred a file
pledgeshield harden shredder --file /path/to/dir            # Shred a directory
pledgeshield harden shredder --file /path --passes 7        # 7 overwrite passes
pledgeshield harden shredder --file /path --dry-run         # Show what would be done
```

#### `harden memwipe` — Memory/Swap Wipe
```bash
pledgeshield harden memwipe                  # Audit memory security
pledgeshield harden memwipe --wipe-swap      # Wipe swap space
pledgeshield harden memwipe --encrypt-swap   # Set up encrypted swap
pledgeshield harden memwipe --install-ramwipe  # Install RAM wipe on shutdown
pledgeshield harden memwipe --drop-caches    # Drop kernel caches now
pledgeshield harden memwipe --dry-run        # Show what would be done
```

#### `harden metadata` — Metadata Stripper
```bash
pledgeshield harden metadata --strip photo.jpg              # Strip metadata
pledgeshield harden metadata --strip photo.jpg --output clean.jpg
pledgeshield harden metadata --list photo.jpg               # List metadata
pledgeshield harden metadata --strip doc.pdf --dry-run      # Show what would be done
```

---

### Boot & Firmware

#### `harden uefi` — UEFI/BIOS Security Audit
```bash
pledgeshield harden uefi                        # Audit Secure Boot, boot password, boot order lock
```

#### `harden bootlog` — Boot Log Analyzer
```bash
pledgeshield harden bootlog                     # Analyze boot logs for anomalies
```

#### `harden sysctl` — Kernel Parameter Hardener
```bash
pledgeshield harden sysctl                      # Audit kernel parameters
pledgeshield harden sysctl --harden             # Apply hardened sysctl settings
pledgeshield harden sysctl --restore            # Restore original sysctl values
```

#### `harden modsign` — Module Signature Verifier
```bash
pledgeshield harden modsign                     # Check kernel module signature enforcement
```

#### `harden tpm` — TPM Status Checker
```bash
pledgeshield harden tpm                         # Check TPM status, version, measured boot
```

---

### File & Data Protection

#### `harden fileperms` — File Permission Auditor
```bash
pledgeshield harden fileperms                   # Find world-readable/writable sensitive files
pledgeshield harden fileperms --fix             # Fix permissions on sensitive files
```

#### `harden sensitive` — Sensitive File Finder
```bash
pledgeshield harden sensitive                   # Locate private keys, certs, password files
pledgeshield harden sensitive --path /home/user # Scan a specific directory
```

#### `harden exfil` — Exfiltration Guard
```bash
pledgeshield harden exfil                       # Audit for exfiltration indicators
pledgeshield harden exfil --monitor             # Real-time exfiltration monitoring
pledgeshield harden exfil --monitor --max-runtime 60
```

#### `harden backup` — Backup Integrity Checker
```bash
pledgeshield harden backup                      # Check backup existence and freshness
pledgeshield harden backup --verify /path       # Verify backup hash against baseline
```

#### `harden diskmon` — Disk Usage Anomaly Detector
```bash
pledgeshield harden diskmon                     # Check for sudden disk space changes
pledgeshield harden diskmon --monitor           # Real-time disk usage monitoring
```

#### `harden logtamper` — Log Tampering Detector
```bash
pledgeshield harden logtamper                   # Check for truncated/deleted system logs
```

---

### SSH & Remote Access

#### `harden ssh` — SSH Config Hardener
```bash
pledgeshield harden ssh                         # Audit SSH configuration
pledgeshield harden ssh --harden                # Apply hardened SSH settings
pledgeshield harden ssh --restore               # Restore original SSH config
```

#### `harden sshkeys` — SSH Key Auditor
```bash
pledgeshield harden sshkeys                     # Audit SSH key strength and permissions
```

#### `harden knock` — Port Knocking Setup
```bash
pledgeshield harden knock --install             # Install port knocking for SSH
pledgeshield harden knock --remove              # Remove port knocking
pledgeshield harden knock --sequence 7000,8000,9000  # Custom knock sequence
```

#### `harden fail2ban` — Fail2ban Configurator
```bash
pledgeshield harden fail2ban                    # Audit fail2ban status
pledgeshield harden fail2ban --install          # Install and configure fail2ban
pledgeshield harden fail2ban --remove           # Remove fail2ban configuration
```

---

### Application Hardening

#### `harden tls` — TLS Certificate Checker
```bash
pledgeshield harden tls                         # Check system TLS certificates
pledgeshield harden tls --domain example.com    # Check a specific domain's certificate
```

#### `harden deps` — Dependency Vulnerability Scanner
```bash
pledgeshield harden deps                        # Scan package manifests for CVEs
pledgeshield harden deps --path /project        # Scan a specific project directory
```

#### `harden secrets` — Secret Scanner
```bash
pledgeshield harden secrets                     # Scan files for committed secrets
pledgeshield harden secrets --path /home/user   # Scan a specific directory
```

#### `harden vault` — Browser Vault Auditor
```bash
pledgeshield harden vault                       # Check browser password vault encryption
```

#### `harden autorun` — Autorun/AutoPlay Disabler
```bash
pledgeshield harden autorun                     # Disable AutoPlay/AutoRun
pledgeshield harden autorun --restore           # Restore AutoPlay settings
```

---

### System Monitoring

#### `harden resource` — Resource Anomaly Detector
```bash
pledgeshield harden resource                    # Check for CPU/RAM anomalies
pledgeshield harden resource --monitor          # Real-time resource monitoring
```

#### `harden filewatch` — New File Watcher
```bash
pledgeshield harden filewatch                   # Audit for suspicious new files
pledgeshield harden filewatch --monitor         # Watch for new executables in real-time
pledgeshield harden filewatch --monitor --max-runtime 60
```

#### `harden usermon` — User Account Monitor
```bash
pledgeshield harden usermon                     # Check for new/modified user accounts
pledgeshield harden usermon --baseline          # Create user account baseline
```

#### `harden netcons` — Network Connection Auditor
```bash
pledgeshield harden netcons                     # List all outbound connections with processes
```

#### `harden cronmon` — Crontab Monitor
```bash
pledgeshield harden cronmon                     # Check for new/modified cron jobs
pledgeshield harden cronmon --baseline          # Create crontab baseline
```

---

### Privacy & Compliance

#### `harden pii` — PII Scanner
```bash
pledgeshield harden pii                         # Scan for PII (SSNs, credit cards, etc.)
pledgeshield harden pii --path /home/user       # Scan a specific directory
```

#### `harden telemetry` — Telemetry Deep-Cleaner
```bash
pledgeshield harden telemetry                   # Disable all OS/browser/dev tool telemetry
pledgeshield harden telemetry --restore         # Restore telemetry settings
```

#### `harden freespace` — Free Space Wiper
```bash
pledgeshield harden freespace                   # Wipe free space on default drive
pledgeshield harden freespace --path /home      # Wipe free space on specific path
pledgeshield harden freespace --passes 3        # Multi-pass wipe
```

#### `harden posture` — Security Posture Score
```bash
pledgeshield harden posture                     # Show 0-100 security posture score
pledgeshield harden posture --detailed          # Show detailed breakdown by category
```

#### `harden profile` — Hardening Profile Applier
```bash
pledgeshield harden profile --audit cis1        # Audit against CIS Level 1
pledgeshield harden profile --audit cis2        # Audit against CIS Level 2
pledgeshield harden profile --apply cis1        # Apply CIS Level 1 hardening
pledgeshield harden profile --apply cis2        # Apply CIS Level 2 hardening
pledgeshield harden profile --apply stig        # Apply STIG hardening
```

---

### Process & Memory Defense

#### `harden procinj` — Process Injection Detector
```bash
pledgeshield harden procinj                     # Scan for injected libraries
```

#### `harden hollow` — Hollow Process Detector
```bash
pledgeshield harden hollow                      # Detect process name/binary mismatches
```

#### `harden memscan` — Memory Scanner
```bash
pledgeshield harden memscan                     # Scan process memory for malware signatures
```

#### `harden ptrace` — Debugger/Ptrace Detector
```bash
pledgeshield harden ptrace                      # Alert if processes are being traced
```

#### `harden thread` — Thread Anomaly Detector
```bash
pledgeshield harden thread                      # Flag suspicious thread counts
```

#### `harden codeinject` — Code Injection Blocker
```bash
pledgeshield harden codeinject                  # Audit code injection defenses
pledgeshield harden codeinject --block          # Harden ptrace_scope, disable BPF
```

---

### Network Defense

#### `harden ratelimit` — Connection Rate Limiter
```bash
pledgeshield harden ratelimit --enable 60       # Max 60 new connections/min
pledgeshield harden ratelimit --disable         # Disable rate limiting
```

#### `harden geoip` — Geo-IP Outbound Filter
```bash
pledgeshield harden geoip --enable              # Enable geo-IP filter
pledgeshield harden geoip --disable             # Disable geo-IP filter
```

#### `harden dohforce` — DNS-over-HTTPS Enforcement
```bash
pledgeshield harden dohforce --enforce          # Force encrypted DNS, block port 53
pledgeshield harden dohforce --disable          # Disable enforcement
```

#### `harden pcapdetect` — Packet Capture Detector
```bash
pledgeshield harden pcapdetect                  # Detect promiscuous mode and sniffers
```

#### `harden roguedhcp` — Rogue DHCP Detector
```bash
pledgeshield harden roguedhcp                   # Detect rogue DHCP servers
```

#### `harden deauth` — WiFi Deauth Detector
```bash
pledgeshield harden deauth                      # Check for deauth attacks
pledgeshield harden deauth --monitor            # Real-time deauth monitoring
pledgeshield harden deauth --monitor --max-runtime 60
```

---

### Filesystem & Storage

#### `harden immutable` — Immutable File Setter
```bash
pledgeshield harden immutable                   # Audit immutable flags
pledgeshield harden immutable --set             # Set immutable on critical files
pledgeshield harden immutable --unset           # Remove immutable flags
```

#### `harden mount` — Mount Option Hardener
```bash
pledgeshield harden mount                       # Audit mount options
pledgeshield harden mount --harden              # Enforce nosuid, nodev, noexec
```

#### `harden tmpsan` — Temp Directory Sanitizer
```bash
pledgeshield harden tmpsan                      # Audit temp directories
pledgeshield harden tmpsan --clean              # Clean stale files from /tmp, /var/tmp, /dev/shm
```

#### `harden quota` — Quota Enforcer
```bash
pledgeshield harden quota                       # Audit disk quotas
pledgeshield harden quota --enable              # Enable disk quotas
```

#### `harden attrmon` — File Attribute Monitor
```bash
pledgeshield harden attrmon                     # Check for attribute changes
pledgeshield harden attrmon --baseline          # Create attribute baseline
```

---

### Access Control

#### `harden pam` — PAM Module Auditor
```bash
pledgeshield harden pam                         # Check for backdoored/weak PAM modules
```

#### `harden polkit` — Polkit Auditor
```bash
pledgeshield harden polkit                      # Check for overly permissive polkit rules
```

#### `harden macaudit` — AppArmor/SELinux Enforcer
```bash
pledgeshield harden macaudit                    # Check MAC enforcement status
```

#### `harden caps` — Capability Auditor
```bash
pledgeshield harden caps                        # Scan binaries for dangerous capabilities
```

#### `harden nsaudit` — Namespace Isolation Auditor
```bash
pledgeshield harden nsaudit                     # Check process namespace isolation
```

---

### Hardware & Peripherals

#### `harden thunderbolt` — Thunderbolt/USB4 Guard
```bash
pledgeshield harden thunderbolt                 # Audit Thunderbolt security
pledgeshield harden thunderbolt --block         # Block/deauthorize Thunderbolt devices
```

#### `harden webcam` — Webcam Guard
```bash
pledgeshield harden webcam                      # Audit webcam access
pledgeshield harden webcam --block              # Disable webcam (unload module)
pledgeshield harden webcam --restore            # Restore webcam access
```

#### `harden micmute` — Microphone Mute Enforcer
```bash
pledgeshield harden micmute                     # Audit microphone status
pledgeshield harden micmute --mute              # Mute all microphones
pledgeshield harden micmute --unmute            # Unmute microphones
```

#### `harden firewire` — Firewire/PCMCIA DMA Guard
```bash
pledgeshield harden firewire                    # Audit FireWire/DMA access
pledgeshield harden firewire --block            # Disable FireWire/PCMCIA modules
pledgeshield harden firewire --restore          # Restore FireWire access
```

---

### System Integrity

#### `harden systemd` — Systemd Unit Auditor
```bash
pledgeshield harden systemd                     # Deep scan for suspicious units
```

#### `harden envleak` — Environment Variable Leak Checker
```bash
pledgeshield harden envleak                     # Scan /proc for secrets in env vars
```

#### `harden libaudit` — Shared Library Auditor
```bash
pledgeshield harden libaudit                    # Check LD_LIBRARY_PATH, RPATH for issues
```

#### `harden binhash` — Binary Hash Verifier
```bash
pledgeshield harden binhash                     # Compare binary hashes against package manager
```

---

### Advanced Defense

#### `harden sinkhole` — DNS Sinkhole
```bash
pledgeshield harden sinkhole                    # Audit DNS sinkhole status
pledgeshield harden sinkhole --enable           # Enable DNS sinkhole for malicious domains
pledgeshield harden sinkhole --disable          # Disable DNS sinkhole
```

#### `harden sandbox` — Process Sandboxing
```bash
pledgeshield harden sandbox                     # Audit process sandboxing
pledgeshield harden sandbox --apply             # Apply seccomp/AppContainer sandboxing
```

#### `harden llmnr` — LLMNR/NBT-NS Poisoning Detector
```bash
pledgeshield harden llmnr                       # Check for LLMNR/NBT-NS poisoning indicators
```

#### `harden kerberos` — Kerberos Ticket Monitor
```bash
pledgeshield harden kerberos                    # Check for golden ticket indicators (Windows/AD)
```

#### `harden stickykeys` — Sticky Keys Bypass Detector
```bash
pledgeshield harden stickykeys                  # Detect accessibility tool replacement (Windows)
```

#### `harden wsl` — WSL Security Audit
```bash
pledgeshield harden wsl                         # Audit Windows Subsystem for Linux
```

#### `harden metaguard` — Cloud Metadata Guard
```bash
pledgeshield harden metaguard                   # Audit cloud metadata endpoint blocking
pledgeshield harden metaguard --enable           # Block cloud metadata endpoints (169.254.169.254)
pledgeshield harden metaguard --disable          # Remove cloud metadata blocking
```

#### `harden smbrelay` — SMB Relay Protection
```bash
pledgeshield harden smbrelay                    # Check SMB signing and SMBv1 status
```

#### `harden extwhitelist` — Browser Extension Whitelist
```bash
pledgeshield harden extwhitelist                # Audit browser extensions
pledgeshield harden extwhitelist --list          # List approved extensions
```

#### `harden arplock` — ARP Table Lock
```bash
pledgeshield harden arplock                     # Audit ARP table lock status
pledgeshield harden arplock --lock              # Lock ARP table (prevent spoofing)
pledgeshield harden arplock --unlock            # Unlock ARP table
```

#### `harden dnspoison` — DNS Cache Poisoning Detector
```bash
pledgeshield harden dnspoison                   # Check for DNS cache poisoning indicators
```

#### `harden beacon` — Bluetooth Beacon Scanner
```bash
pledgeshield harden beacon                      # Scan for Bluetooth tracking beacons (AirTags, Tile)
```

#### `harden firmware` — Firmware Integrity Checker
```bash
pledgeshield harden firmware                    # Check peripheral firmware integrity
```

#### `harden memsnap` — Memory Forensics Snapshot
```bash
pledgeshield harden memsnap                     # Audit for suspicious memory regions
pledgeshield harden memsnap --capture 1234      # Capture memory snapshot of PID 1234
```

#### `harden honeyport` — Network Honeytoken
```bash
pledgeshield harden honeyport                   # Check honeyport status
pledgeshield harden honeyport --deploy 2222     # Deploy honeyport on port 2222
```

#### `harden credguard` — Credential Guard
```bash
pledgeshield harden credguard                   # Audit credential guard status
pledgeshield harden credguard --enable           # Enable Credential Guard / PAM hardening
```

#### `harden sidechannel` — Side Channel Mitigator
```bash
pledgeshield harden sidechannel                 # Audit side-channel mitigations
pledgeshield harden sidechannel --mitigate       # Apply Spectre/Meltdown/Downfall mitigations
```

#### `harden verify` — Supply Chain Verifier
```bash
pledgeshield harden verify                      # Audit supply chain verification
pledgeshield harden verify --package openssl     # Verify specific package integrity
```

#### `harden zerotrust` — Zero Trust Agent
```bash
pledgeshield harden zerotrust                   # Audit zero-trust policy
pledgeshield harden zerotrust --enable           # Enable zero-trust (default deny INPUT)
pledgeshield harden zerotrust --disable          # Disable zero-trust policy
```

#### `harden escrow` — Disk Encryption Escrow
```bash
pledgeshield harden escrow                      # Audit recovery key status
pledgeshield harden escrow --show                # Display recovery keys
```

#### `harden dnstunnel` — DNS Tunneling Detector
```bash
pledgeshield harden dnstunnel                   # Check for DNS tunneling indicators
```

#### `harden gpumon` — GPU Process Monitor
```bash
pledgeshield harden gpumon                      # Monitor GPU processes for crypto mining
```

#### `harden freeze` — Process Tree Freezer
```bash
pledgeshield harden freeze                      # Audit for zombie/stopped processes
pledgeshield harden freeze --freeze 1234        # Freeze process PID 1234 (SIGSTOP)
pledgeshield harden freeze --resume 1234        # Resume frozen process PID 1234 (SIGCONT)
```

#### `harden pinmon` — Certificate Pinning Monitor
```bash
pledgeshield harden pinmon                      # Check for CA trust store modifications
```

#### `harden segment` — Network Segmentation Enforcer
```bash
pledgeshield harden segment                     # Audit network segmentation
pledgeshield harden segment --enforce            # Enforce segmentation (disable forwarding, block inter-interface)
```

#### `harden rtfim` — Real-Time FIM
```bash
pledgeshield harden rtfim                       # Check real-time FIM status
pledgeshield harden rtfim --start               # Start real-time file integrity monitoring
```

#### `harden usbwhitelist` — USB Device Whitelist
```bash
pledgeshield harden usbwhitelist                # Audit USB whitelist
pledgeshield harden usbwhitelist --add 046d:c52b   # Add device (vendor:product ID)
pledgeshield harden usbwhitelist --clear           # Clear whitelist
```

#### `harden imagescan` — Container Image Scanner
```bash
pledgeshield harden imagescan                   # Audit container image setup
pledgeshield harden imagescan --image nginx     # Scan specific image for vulnerabilities
```

#### `harden migrate` — Process Migration Detector
```bash
pledgeshield harden migrate                     # Detect anomalous process namespace migration
```

---

## `vpn` — VPN & Proxy Management

```
pledgeshield vpn <SUBCOMMAND> [OPTIONS]
```

### WireGuard / OpenVPN

```bash
pledgeshield vpn status                                      # Show VPN status
pledgeshield vpn connect --config myvpn --vpn-type wireguard # Connect to WireGuard
pledgeshield vpn connect --config /path/to.ovpn --vpn-type openvpn
pledgeshield vpn disconnect --vpn-type wireguard --config myvpn
pledgeshield vpn disconnect --vpn-type openvpn
pledgeshield vpn list                                        # List WireGuard configs
pledgeshield vpn kill-switch-on                              # Enable kill switch (Linux)
pledgeshield vpn kill-switch-off                             # Disable kill switch (Linux)
```

### Tor Proxy

```bash
pledgeshield vpn tor status       # Show Tor status
pledgeshield vpn tor start        # Start Tor daemon
pledgeshield vpn tor stop         # Stop Tor daemon
pledgeshield vpn tor route        # Route all traffic through Tor (Linux, root)
pledgeshield vpn tor unroute      # Stop routing through Tor
pledgeshield vpn tor check-ip     # Check exit IP through Tor
```

---

## `monitor` — Real-Time Security Monitor

```
pledgeshield monitor [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--interval <N>` | Polling interval in seconds (default: 5) |
| `--no-ports` | Don't watch for new listening ports |
| `--no-processes` | Don't watch for new root/SYSTEM processes |
| `--no-firewall` | Don't watch for firewall state changes |
| `--max-runtime <N>` | Stop after N seconds (0 = run forever, default: 0) |

```bash
# Default monitoring (all watchers, 5s interval)
pledgeshield monitor

# Fast polling, only watch ports
pledgeshield monitor --interval 2 --no-processes --no-firewall

# Run for 60 seconds then stop
pledgeshield monitor --max-runtime 60
```

---

## Global Options

| Flag | Description |
|------|-------------|
| `-h, --help` | Print help |
| `-V, --version` | Print version |

---

## Quick Start

```bash
# 1. Run a full security audit
pledgeshield scan --cve --compliance --format html --output report.html

# 2. Harden the system
pledgeshield harden firewall --harden --allow-ssh
pledgeshield harden ports --all
pledgeshield harden doh --enable cloudflare
pledgeshield harden ipv6 --firewall
pledgeshield harden hosts --update
pledgeshield harden lockscreen --enable 300
pledgeshield harden lockscreen --disable-autologin
pledgeshield harden browser
pledgeshield harden webrtc --block
pledgeshield harden cleaner
pledgeshield harden sysctl --harden
pledgeshield harden ssh --harden
pledgeshield harden telemetry
pledgeshield harden immutable --set

# 3. Set up detection
pledgeshield harden integrity --baseline
pledgeshield harden canary --plant
pledgeshield harden rootkit
pledgeshield harden attrmon --baseline
pledgeshield harden usermon --baseline
pledgeshield harden cronmon --baseline

# 4. Check posture
pledgeshield harden posture
pledgeshield harden profile --audit cis1

# 5. Start real-time monitoring
pledgeshield monitor --interval 5

# 6. Schedule daily scans
pledgeshield schedule --install --cron "0 0 * * *" --command "scan --cve --save-history"
```
