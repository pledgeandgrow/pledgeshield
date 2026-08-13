# PledgeShield

> Personal device security auditor for Windows, macOS, and Linux — finds what antivirus misses.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)](#platforms)

---

## AI-Assisted Usage

PledgeShield is designed to be used with an AI assistant. For the best experience, have your AI analyze [`COMMANDS.md`](COMMANDS.md) before running commands — it contains the complete command reference and examples.

## What It Is

PledgeShield is a Rust-based host security auditor for Windows, macOS, and Linux. It scans your device for misconfigurations, exposed services, unpatched software, privilege escalation vectors, and other attack surfaces that antivirus software doesn't look at.

Think `lynis` — but cross-platform, in Rust, one binary, no agent, no server.

---

## Problem It Solves

Antivirus (Microsoft Defender, XProtect, ClamAV, etc.) focuses on **malware detection** — catching known bad files in real-time. It does NOT assess:

- Whether your RDP/SSH is exposed to the internet
- Whether UAC (Windows) / Gatekeeper (macOS) / AppArmor (Linux) is properly configured
- Whether you have unnecessary services running
- Whether your installed software has known unpatched CVEs
- Whether someone left a scheduled task / launchd / cron for persistence
- Whether your file shares are open to everyone
- Whether stored credentials are sitting in plaintext

**PledgeShield fills this gap.** Run it, get a report, fix the issues.

---

## Quick Start

```bash
# Run a full security audit
pledgeshield scan

# Scan with CVE checking and compliance mapping
pledgeshield scan --cve --compliance --format html --output report.html

# Harden your system (120+ hardening modules)
pledgeshield harden firewall --harden --allow-ssh
pledgeshield harden ports --all
pledgeshield harden doh --enable cloudflare
pledgeshield harden sysctl --harden
pledgeshield harden ssh --harden

# Real-time monitoring
pledgeshield monitor

# Check your security posture score
pledgeshield harden posture
```

---

## Install

### Cargo (all platforms)
```bash
cargo install pledgeshield
```

### Homebrew (macOS/Linux)
```bash
brew install pledgeandgrow/tap/pledgeshield
```

### winget (Windows)
```bash
winget install PledgeAndGrow.PledgeShield
```

### apt (Debian/Ubuntu)
```bash
wget -qO - https://pledgeandgrow.github.io/pledgeshield/apt/pledgeshield-apt-public.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/pledgeshield.gpg
echo "deb [signed-by=/usr/share/keyrings/pledgeshield.gpg] https://pledgeandgrow.github.io/pledgeshield/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/pledgeshield.list
sudo apt update && sudo apt install pledgeshield
```

### npm
```bash
npm install -g pledgeshield
```

### PyPI
```bash
pip install pledgeshield
```

### RubyGems
```bash
gem install pledgeshield
```

### NuGet
```bash
dotnet tool install -g PledgeShield
```

### Binary download
Download from [GitHub Releases](https://github.com/pledgeandgrow/pledgeshield/releases) — prebuilt binaries for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), and Windows (x86_64).

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
  harden       Active defense: 120+ hardening modules
  vpn          VPN / proxy management (WireGuard, OpenVPN, Tor)
  monitor      Real-time security monitor
```

See [COMMANDS.md](COMMANDS.md) for the full command reference.

---

## Scan Features

### 1. Host Configuration Audit

**Windows:**
- UAC status and level
- SmartScreen status
- Windows Firewall profile rules (Domain, Private, Public)
- Windows Defender status and exclusions
- BitLocker / encryption status
- Windows telemetry settings
- Clipboard history exposure
- Wi-Fi Sense sharing
- Auto-login configuration

**macOS:**
- Gatekeeper status and spctl assessment
- SIP (System Integrity Protection) status
- FileVault encryption status
- XProtect & MRT status
- macOS firewall (Application Firewall) status
- TCC (Transparency, Consent, Control) permissions audit
- System telemetry settings
- Auto-login configuration

**Linux:**
- AppArmor or SELinux status and mode
- Firewall status (ufw / firewalld / iptables / nftables)
- Disk encryption status (LUKS)
- PAM configuration audit
- Kernel hardening (sysctl params: ASLR, dmesg restriction, etc.)
- Automatic updates configuration
- /etc/permissions and file ownership audit

### 2. Service & Port Inventory (all platforms)
- All running services with startup type
- Services running as root/SYSTEM (high privilege)
- Listening ports and associated processes
- Ports exposed to public (0.0.0.0) vs localhost only
- RDP, SSH, SMB, WinRM, VNC exposure check
- Unnecessary services recommendation

### 3. Software Vulnerability Check (all platforms)
- Enumerate installed software (platform-specific package managers)
- Check each program against CVE APIs (no manual database to maintain)
- Report unpatched versions with severity and CVE ID
- Suggest update actions

**CVE data sources (API-based, no manual updates needed):**
- [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — National Vulnerability Database
- [OSV.dev API](https://osv.dev/docs/) — Open Source Vulnerabilities, Google-backed
- [GitHub Security Advisories API](https://docs.github.com/en/rest/security/advisories) — GHSA database
- [FIRST EPSS API](https://www.first.org/epss/api) — Exploit prediction scoring for prioritization

### 4. Privilege & Account Audit (all platforms)
- All local user accounts and their privileges
- Administrator / sudo group membership
- Guest account status
- Password policy (length, complexity, expiration, lockout)
- Users with "Password never expires" flag
- Suspicious hidden accounts

### 5. Persistence Detection (all platforms)
- Scheduled tasks / cron / launchd (suspicious entries, unknown authors, odd triggers)
- Registry Run keys (Windows) / LaunchAgents (macOS) / systemd timers (Linux)
- Startup folder entries
- Services with suspicious paths
- WMI event subscriptions (Windows)
- DLL hijacking opportunities (Windows) / writable dirs in PATH (all)

### 6. Credential Exposure (all platforms)
- Stored Windows credentials / macOS Keychain / Linux keyring
- Saved RDP sessions (Windows)
- Browser saved passwords (Chrome, Edge, Firefox, Brave, Safari detection)
- Wi-Fi profiles with stored passwords
- SSH keys with no passphrase
- Generic credentials in Credential Manager / Keychain

### 7. Share & Exposure Audit (all platforms)
- All file/printer shares and their permissions (Windows/SMB)
- Shares accessible to "Everyone" or "Anonymous"
- Default admin shares (C$, D$, ADMIN$)
- SMB configuration (SMBv1 check, signing requirements)
- RDP configuration (NLA requirement, encryption level)
- NFS exports (Linux)
- AFP/SMB shares (macOS)

### 8. Patch Status (all platforms)
- Missing OS updates (Windows Update / softwareupdate / apt/dnf/pacman)
- Last successful update check date
- Pending reboot for installed updates
- Third-party software update status (winget, brew, choco)

### 9. Browser Extension Audit
- Installed browser extensions (Chrome, Edge, Firefox, Brave)
- Known-malicious extension detection
- Excessive permission flags

### 10. Container Security
- Docker/Podman/Kubernetes misconfiguration
- Privileged containers, root user, no seccomp
- Exposed ports, no resource limits

### 11. Compliance Mapping
- CIS Benchmark control IDs
- NIST SP 800-53 control IDs
- Custom checks from TOML/YAML files

---

## Active Defense (`harden`)

120+ modules that take action to secure your system. See [MODULES.md](MODULES.md) for the full list.

### Network & Traffic (10)
| Command | Description |
|---------|-------------|
| `harden ports` | Close insecure open ports (Telnet, FTP, RDP, VNC, SMB, Redis, MongoDB) |
| `harden firewall` | Enable/harden/disable system firewall (UFW/iptables/firewalld, socketfilterfw, netsh) |
| `harden doh` | Configure DNS-over-HTTPS/TLS (Cloudflare, Google, Quad9, AdGuard) |
| `harden wifi` | Audit WiFi for open networks, WEP, auto-connect, saved network leaks |
| `harden arp` | ARP spoofing detector — real-time MITM monitoring |
| `harden isolation` | Block all outbound except whitelisted IPs |
| `harden proxy` | Set/clear SOCKS5/HTTP proxy system-wide |
| `harden ipv6` | Disable or firewall IPv6 to prevent VPN/DNS leaks |
| `harden hosts` | Install ad/tracker/malware domain blocklists |
| `harden traffic` | Per-process bandwidth monitor — detect data exfiltration |

### Identity & Privacy (10)
| Command | Description |
|---------|-------------|
| `harden mac` | Spoof/randomize network interface MAC address |
| `harden identity` | Set privacy DNS, disable OS telemetry, clear machine IDs |
| `harden hostname` | Randomize machine hostname to prevent tracking |
| `harden useragent` | Spoof browser user-agent to prevent fingerprinting |
| `harden webrtc` | Block WebRTC to prevent IP leaks behind VPN |
| `harden bluetooth` | Audit, hide, disable Bluetooth, remove paired devices |
| `harden devices` | Audit and block camera/microphone access |
| `harden clipboard` | Clear clipboard, install auto-clear watcher |
| `harden cleaner` | Clear shell history, recent files, temp files, activity traces |
| `harden browser` | Disable browser telemetry, enable tracking protection, clear data |

### System Hardening (8)
| Command | Description |
|---------|-------------|
| `harden usb` | USB device guard — audit, lockdown via USBGuard |
| `harden kernel` | Restrict kernel module loading (irreversible until reboot) |
| `harden suid` | Find and remove suspicious SUID/SGID binaries |
| `harden scheduler` | Deep scan cron/systemd timers/launchd for suspicious tasks |
| `harden integrity` | Hash and verify critical system files (FIM) |
| `harden proctree` | Detect suspicious parent-child process relationships |
| `harden lockscreen` | Force screen lock timeout, disable auto-login |
| `harden encryption` | Detect unencrypted disks, guide LUKS/FileVault/BitLocker setup |

### Detection & Response (4)
| Command | Description |
|---------|-------------|
| `harden rootkit` | Check for hidden PIDs, LD_PRELOAD abuse, hidden kernel modules |
| `harden canary` | Plant decoy files, monitor for ransomware encryption |
| `harden logins` | Track failed SSH/RDP/login attempts, detect brute force |
| `harden dnsmon` | Monitor DNS for DGA, C2, fast flux, suspicious TLDs |

### Privacy Tools (3)
| Command | Description |
|---------|-------------|
| `harden shredder` | Securely delete files with multi-pass overwrite |
| `harden memwipe` | Wipe swap, set up encrypted swap, wipe RAM on shutdown |
| `harden metadata` | Strip EXIF/IPTC/XMP metadata from JPEG, PNG, PDF |

### Boot & Firmware (5)
| Command | Description |
|---------|-------------|
| `harden uefi` | Audit Secure Boot, boot password, boot order lock |
| `harden bootlog` | Analyze boot logs for I/O errors, firmware failures, driver crashes |
| `harden sysctl` | Harden kernel parameters: ASLR, ptrace_scope, dmesg restriction |
| `harden modsign` | Verify kernel module signatures, check CONFIG_MODULE_SIG_FORCE |
| `harden tpm` | Check TPM availability, version, measured boot, PCR state |

### File & Data Protection (6)
| Command | Description |
|---------|-------------|
| `harden fileperms` | Find world-readable/writable sensitive files |
| `harden sensitive` | Locate private keys, certs, password files across the system |
| `harden exfil` | Monitor for large file copies to USB/network |
| `harden backup` | Verify backups exist, are recent, match expected hashes |
| `harden diskmon` | Flag sudden disk space changes (ransomware indicator) |
| `harden logtamper` | Check for truncated/deleted system logs |

### SSH & Remote Access (4)
| Command | Description |
|---------|-------------|
| `harden ssh` | Disable root login, password auth, enforce key-only auth |
| `harden sshkeys` | Check SSH key sizes, passphrases, file permissions |
| `harden knock` | Configure port knocking to hide SSH from scanners |
| `harden fail2ban` | Install and configure fail2ban for brute force protection |

### Application Hardening (5)
| Command | Description |
|---------|-------------|
| `harden tls` | Check TLS certificates for expiration, weak ciphers |
| `harden deps` | Scan package manifests (Cargo, npm, pip, go.mod) for CVEs |
| `harden secrets` | Scan your own files for committed API keys/tokens |
| `harden vault` | Check if browser saved passwords are encrypted at rest |
| `harden autorun` | Disable AutoPlay/AutoRun from USB/CD/network drives |

### System Monitoring (5)
| Command | Description |
|---------|-------------|
| `harden resource` | Detect CPU/RAM spikes and crypto miner patterns |
| `harden filewatch` | Monitor system directories for new executable files |
| `harden usermon` | Alert on new users, UID changes, sudoers modifications |
| `harden netcons` | List all outbound connections with associated processes |
| `harden cronmon` | Alert on new or modified scheduled tasks |

### Privacy & Compliance (5)
| Command | Description |
|---------|-------------|
| `harden pii` | Scan files for SSNs, credit cards, phone numbers (GDPR) |
| `harden telemetry` | Disable ALL telemetry across OS, browsers, dev tools |
| `harden freespace` | Overwrite disk free space so deleted files can't be recovered |
| `harden posture` | Aggregate findings into 0-100 security posture score with grade |
| `harden profile` | Apply CIS Level 1/2, STIG, or custom hardening profiles |

### Process & Memory Defense (6)
| Command | Description |
|---------|-------------|
| `harden procinj` | Scan for suspicious injected libraries (LD_PRELOAD, maps anomalies) |
| `harden hollow` | Detect process name/binary mismatches (hollow processes) |
| `harden memscan` | Scan process memory for malware signatures |
| `harden ptrace` | Alert if processes are being traced/debugged |
| `harden thread` | Flag processes with suspicious thread counts |
| `harden codeinject` | Harden ptrace_scope, disable BPF for unprivileged users |

### Network Defense (6)
| Command | Description |
|---------|-------------|
| `harden ratelimit` | Limit new outbound connections per minute (iptables hashlimit) |
| `harden geoip` | Block connections to high-risk countries |
| `harden dohforce` | Force encrypted DNS, block plaintext DNS (port 53) |
| `harden pcapdetect` | Detect promiscuous mode interfaces and packet sniffers |
| `harden roguedhcp` | Detect DHCP responses from non-router sources |
| `harden deauth` | Detect WiFi deauthentication attacks (real-time monitor) |

### Filesystem & Storage (5)
| Command | Description |
|---------|-------------|
| `harden immutable` | Protect critical files with chattr +i (immutable) |
| `harden mount` | Enforce nosuid, nodev, noexec on mount points |
| `harden tmpsan` | Clean stale files from /tmp, /var/tmp, /dev/shm |
| `harden quota` | Set disk quotas to prevent disk filling (ransomware protection) |
| `harden attrmon` | Watch for permission/immutable flag changes on critical files |

### Access Control (5)
| Command | Description |
|---------|-------------|
| `harden pam` | Check for backdoored/weak PAM modules |
| `harden polkit` | Check for overly permissive polkit rules |
| `harden macaudit` | Check AppArmor/SELinux enforcement status |
| `harden caps` | Scan binaries for dangerous Linux capabilities |
| `harden nsaudit` | Check process namespace isolation |

### Hardware & Peripherals (4)
| Command | Description |
|---------|-------------|
| `harden thunderbolt` | Disable Thunderbolt DMA, require device approval |
| `harden webcam` | Disable webcam (unload uvcvideo module), audit access |
| `harden micmute` | Mute all microphones at the audio system level |
| `harden firewire` | Disable FireWire/PCMCIA DMA access |

### System Integrity (4)
| Command | Description |
|---------|-------------|
| `harden systemd` | Deep scan systemd units for suspicious services |
| `harden envleak` | Scan /proc for secrets in environment variables |
| `harden libaudit` | Check LD_LIBRARY_PATH, RPATH for library hijacking vectors |
| `harden binhash` | Compare binary hashes against package manager records |

### Advanced Defense (29)
| Command | Description |
|---------|-------------|
| `harden sinkhole` | DNS sinkhole — block known malicious domains at the local DNS level |
| `harden sandbox` | Process sandboxing — apply seccomp/AppContainer sandboxing |
| `harden llmnr` | LLMNR/NBT-NS poisoning detector |
| `harden kerberos` | Kerberos ticket monitor — detect golden ticket indicators (Windows/AD) |
| `harden stickykeys` | Sticky Keys bypass detector — detect accessibility tool replacement |
| `harden wsl` | WSL security audit — audit Windows Subsystem for Linux |
| `harden metaguard` | Cloud metadata guard — block SSRF access to cloud metadata endpoints |
| `harden smbrelay` | SMB relay protection — enforce SMB signing |
| `harden extwhitelist` | Browser extension whitelist — list approved extensions |
| `harden arplock` | ARP table lock — prevent ARP spoofing on static networks |
| `harden dnspoison` | DNS cache poisoning detector |
| `harden beacon` | Bluetooth beacon scanner — detect tracking beacons (AirTags, Tile, SmartTag) |
| `harden firmware` | Firmware integrity checker — verify peripheral firmware |
| `harden memsnap` | Memory forensics snapshot — capture process memory for analysis |
| `harden honeyport` | Network honeytoken — deploy fake services to detect lateral movement |
| `harden credguard` | Credential guard — enable Credential Guard / PAM hardening |
| `harden sidechannel` | Side channel mitigator — mitigate Spectre/Meltdown/Downfall |
| `harden verify` | Supply chain verifier — verify package checksums/signatures |
| `harden zerotrust` | Zero trust agent — enforce zero-trust network policy |
| `harden escrow` | Disk encryption escrow — escrow recovery keys |
| `harden dnstunnel` | DNS tunneling detector — detect DNS tunneling for data exfiltration |
| `harden gpumon` | GPU process monitor — detect crypto mining or ML exfiltration |
| `harden freeze` | Process tree freezer — freeze suspicious processes for forensics |
| `harden pinmon` | Certificate pinning monitor — monitor for CA trust changes |
| `harden segment` | Network segmentation enforcer — enforce segmentation on multi-homed machines |
| `harden rtfim` | Real-time FIM — real-time file integrity monitoring |
| `harden usbwhitelist` | USB device whitelist — only allow whitelisted USB devices |
| `harden imagescan` | Container image scanner — scan images for vulnerabilities |
| `harden migrate` | Anomalous process migration detector — detect container escape |

---

## VPN & Proxy

```bash
# WireGuard / OpenVPN
pledgeshield vpn status
pledgeshield vpn connect --config myvpn --vpn-type wireguard
pledgeshield vpn disconnect
pledgeshield vpn kill-switch-on      # Block all non-VPN traffic (Linux)

# Tor
pledgeshield vpn tor start
pledgeshield vpn tor route           # Route all traffic through Tor (Linux)
pledgeshield vpn tor check-ip        # Check exit IP
```

---

## Real-Time Monitor

```bash
# Watch for new ports, root processes, firewall changes
pledgeshield monitor

# Fast polling, 60 second run
pledgeshield monitor --interval 2 --max-runtime 60
```

---

## Scan Options

| Flag | Description |
|------|-------------|
| `--cve` | Enable CVE scanning (NVD, OSV, GHSA, EPSS) |
| `--compliance` | Map findings to CIS Benchmark and NIST 800-53 controls |
| `--format <FORMAT>` | Output: `text`, `json`, `html`, `sarif`, `markdown`, `pdf` (default: text) |
| `--output <PATH>` | Write report to file instead of stdout |
| `--modules <LIST>` | Comma-separated modules to run (e.g. `services,shares,persistence`) |
| `--min-severity <LVL>` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--fix` | Interactive fix mode — prompt to apply fixes for each finding |
| `--verify` | Verify that previously applied fixes are still in effect |
| `--offline` | Use cached CVE data only (air-gapped environments) |
| `--refresh-cve` | Force refresh CVE cache before scanning |
| `--nvd-api-key <KEY>` | NVD API key for higher rate limits (env: `NVD_API_KEY`) |
| `--github-token <TOKEN>` | GitHub token for GHSA API (env: `GITHUB_TOKEN`) |
| `--config <FILE>` | Load configuration from TOML/YAML file |
| `--baseline <FILE>` | Compare results against a baseline file |
| `--save-baseline <FILE>` | Save current scan as baseline |
| `--save-history` | Save scan results to SQLite history database |
| `--custom-checks <FILE>` | Run user-defined checks from TOML/YAML |
| `--notify-webhook <URL>` | Send results to webhook (Slack/Discord/Teams) |

---

## CVE API Integration

| API | Rate limit | Auth | Notes |
|-----|-----------|------|-------|
| NVD 2.0 | 6s/req (no key), 2s/req (with key) | Optional | Built-in rate limiting, CPE matching (35+ mappings) |
| OSV.dev | 1000 req/min | None | Free, batch queries supported |
| GHSA | 5000 req/hour (auth), 60 req/hour (no auth) | Optional | GitHub token |
| EPSS | No documented limit | None | Free, daily updates |

**Caching:** API responses cached to disk (TTL: 24h). Batch queries where supported. Offline mode uses last cached response.

---

## Architecture

```
SHARED MODULES (same concept, all 3 platforms)     PLATFORM-SPECIFIC (conditional compilation)
┌────────────────────────────────────┐             ┌─────────────────────────────────────┐
│ HostConfigModule                   │             │ #[cfg(windows)]                     │
│ ServicesModule                     │             │  WindowsHardeningModule             │
│ CveModule                          │             │  - UAC, SmartScreen, Defender       │
│ PrivilegesModule                   │             │  - BitLocker, Registry hardening    │
│ PersistenceModule                  │             │  - SMB shares, RDP, Credential Mgr  │
│ CredentialsModule                  │             │  - WMI, DLL hijack, Wi-Fi Sense     │
│ SharesModule                       │             │                                     │
│ PatchesModule                      │             │ #[cfg(macos)]                       │
│ BrowserModule                      │             │  MacosHardeningModule               │
│ ContainersModule                   │             │  - Gatekeeper, SIP, TCC permissions│
│ ComplianceModule                   │             │  - FileVault, Keychain audit        │
│ CustomChecks                       │             │  - XProtect, LaunchAgents/Daemons   │
└────────────────────────────────────┘             │                                     │
                                                   │ #[cfg(linux)]                       │
120+ harden modules (platform-conditional)          │  LinuxHardeningModule               │
VPN: WireGuard, OpenVPN, Tor                       │  - AppArmor / SELinux status        │
Real-time monitor                                  │  - systemd service audit            │
                                                   │  - fail2ban, /etc/ hardening        │
                                                   │  - PAM configuration                │
                                                   └─────────────────────────────────────┘
```

**~60% shared code, ~40% platform-specific.** CVE API integration is 100% platform-agnostic.

---

## Project Structure

```
pledgeshield/
├── Cargo.toml
├── README.md               # This file
├── COMMANDS.md             # Full command reference
├── MODULES.md              # All 121 modules documented
├── .github/workflows/
│   ├── ci.yml              # CI: test + build (3 platforms, 2 toolchains)
│   └── release.yml         # Release: 8 package managers + GitHub Releases
├── apt/                    # apt repository public key
├── src/
│   ├── main.rs             # Entry point, CLI dispatch
│   ├── cli.rs              # CLI argument definitions (clap)
│   ├── config.rs           # Config file loading (TOML/YAML)
│   ├── baseline.rs         # Baseline diff scanning
│   ├── models.rs           # Finding, Severity, ScanResult models
│   ├── output.rs           # Text, JSON, HTML, SARIF, Markdown, PDF output
│   ├── monitor.rs          # Real-time security monitor
│   ├── history.rs          # SQLite scan history
│   ├── trend.rs            # Trend dashboard
│   ├── compliance.rs       # CIS / NIST compliance mapping
│   ├── custom.rs           # User-defined checks
│   ├── containers.rs       # Docker/Podman/K8s checks
│   ├── browser.rs          # Browser extension audit
│   ├── network.rs          # Network exposure checks
│   ├── modules/            # 11 scan modules
│   ├── harden/             # 120+ active defense modules
│   ├── cve/                # CVE API clients (NVD, OSV, GHSA, EPSS, cache)
│   ├── fix/                # Interactive fix actions (Windows, macOS, Linux)
│   ├── notify/             # Email + webhook notifications + scheduled scans
│   ├── vpn/                # WireGuard, OpenVPN, Tor management
│   └── platform/           # Platform-specific implementations
└── templates/
    └── report.html         # HTML report template
```

---

## Finding Severity Levels

| Severity | Examples |
|----------|----------|
| **Critical** | RDP/SSH exposed to internet, SMBv1 enabled, no firewall, SIP disabled, SELinux disabled |
| **High** | UAC disabled, admin share open to Everyone, Gatekeeper disabled, unpatched critical CVE (EPSS > 0.5) |
| **Medium** | Unnecessary service running as root/SYSTEM, weak password policy, missing updates |
| **Low** | Telemetry settings, clipboard history enabled, minor misconfigurations |
| **Info** | Informational findings (installed software list, service inventory) |

---

## Competitive Positioning

| Tool | What it does | Where PledgeShield wins |
|------|-------------|------------------------|
| **Defender / XProtect / ClamAV** | Malware detection only | Host hardening, misconfig detection, CVE check, cross-platform |
| **Lynis** | Linux/Unix host audit | Cross-platform (Windows + macOS), Rust binary, CVE API integration |
| **Hardening Kitty** | Windows compliance checks | Cross-platform, broader scope, active defense modules |
| **Nessus / Qualys** | Enterprise vulnerability scanning | Free, lightweight, no agent/server, personal use |
| **Greenbone OpenVAS** | Open-source network vuln scanner | No server infrastructure, host-focused, Rust |
| **Wazuh** | HIDS/SIEM | No server needed, simpler, personal use |
| **Sysinternals** | Individual tools | Unified report, automated checks, actionable fixes |

**Key differentiators:**
- **Cross-platform** — Windows, macOS, and Linux from a single codebase
- **120+ active defense modules** — not just scanning, but hardening
- **Rust** — memory-safe, single binary, no runtime dependency
- **API-based CVE** — no local database to maintain, always current
- **Multi-source CVE** — NVD + OSV + GHSA with CPE matching and ecosystem detection
- **EPSS scoring** — prioritize by actual exploit likelihood, not just CVSS
- **SARIF output** — GitHub code scanning compatible for CI/CD integration
- **Baseline diff** — track security posture changes over time
- **Posture scoring** — 0-100 score with letter grade
- **Hardening profiles** — CIS Level 1/2, STIG, or custom
- **VPN management** — WireGuard, OpenVPN, Tor built in
- **Real-time monitor** — watch for new ports, processes, firewall changes
- **8 package managers** — cargo, npm, PyPI, RubyGems, NuGet, Homebrew, winget, apt

---

## Platforms

| OS | Architecture | Support Level |
|----|-------------|---------------|
| Linux | x86_64 | Full |
| Linux | aarch64 | Full |
| macOS | Apple Silicon (arm64) | Full |
| macOS | Intel (x86_64) | Full |
| Windows | x86_64 | Full |

---

## Tech Stack

- **Language:** Rust
- **CLI:** `clap`
- **HTTP:** `reqwest` (CVE API calls)
- **Serialization:** `serde`, `serde_json`, `serde_yaml`, `toml`
- **Database:** `rusqlite` (scan history)
- **Progress:** `indicatif`
- **Windows APIs:** `windows` crate, `winreg`, `wmi`
- **macOS APIs:** `core-foundation`, `system-configuration`, `security-framework`
- **Linux APIs:** `procfs`, `nix`, `sysctl`

---

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings

# Check formatting
cargo fmt --all -- --check
```

CI runs on every push and PR across Ubuntu, macOS, and Windows with stable and beta Rust toolchains.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**mehdi-berel** — [mehdi.berel@pledgeandgrow.com](mailto:mehdi.berel@pledgeandgrow.com)

---

## Links

- [GitHub Repository](https://github.com/pledgeandgrow/pledgeshield)
- [Issue Tracker](https://github.com/pledgeandgrow/pledgeshield/issues)
- [Releases](https://github.com/pledgeandgrow/pledgeshield/releases)
- [Full Command Reference](COMMANDS.md)
- [Full Module List](MODULES.md)
