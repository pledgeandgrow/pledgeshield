# PledgeShield

> Personal device security auditor for Windows, macOS, and Linux — finds what antivirus misses.

---

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

## Where It Fits

```
DEFENSE
├── PledgeGuard    — "Did we leak secrets in code?"
├── PledgeRecon    — "Is our code vulnerable?"
└── PledgeShield   — "Is my device hardened?" ← THIS

INTEL
└── PledgeTarget   — "What's out there?"

OFFENSE
└── PledgeStrike   — "Can we exploit it?"
```

No overlap with other PledgeCyber tools:
- No code/repo scanning → PledgeGuard & PledgeRecon own that
- No network scanning of external targets → that's recon
- No exploitation → PledgeStrike owns that
- Focuses exclusively on **local host hardening**

---

## Architecture — Cross-Platform Design

PledgeShield uses a trait-based module system with shared logic and platform-specific implementations:

```
SHARED MODULES (same concept, all 3 platforms)     PLATFORM-SPECIFIC (conditional compilation)
┌────────────────────────────────────┐             ┌─────────────────────────────────────┐
│ OpenPortsModule                    │             │ #[cfg(windows)]                     │
│ CveModule                          │             │  WindowsHardeningModule             │
│ UserAuditModule                    │             │  - UAC, SmartScreen, Defender       │
│ PasswordPolicyModule               │             │  - BitLocker, Registry hardening    │
│ FirewallModule                     │             │  - SMB shares, RDP, Credential Mgr  │
│ PersistenceModule                  │             │  - WMI, DLL hijack, Wi-Fi Sense     │
│ SshKeyModule                       │             │                                     │
│ BrowserCredsModule                 │             │ #[cfg(macos)]                       │
│ PatchStatusModule                  │             │  MacosHardeningModule               │
└────────────────────────────────────┘             │  - Gatekeeper, SIP, TCC permissions│
                                                   │  - FileVault, Keychain audit        │
                                                   │  - XProtect, LaunchAgents/Daemons   │
                                                   │                                     │
                                                   │ #[cfg(linux)]                       │
                                                   │  LinuxHardeningModule               │
                                                   │  - AppArmor / SELinux status        │
                                                   │  - systemd service audit            │
                                                   │  - fail2ban, /etc/ hardening        │
                                                   │  - PAM configuration                │
                                                   └─────────────────────────────────────┘
```

**~60% shared code, ~40% platform-specific.** The CVE API integration is 100% platform-agnostic.

---

## Features

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
- [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — National Vulnerability Database, free, comprehensive
- [OSV.dev API](https://osv.dev/docs/) — Open Source Vulnerabilities, Google-backed, broad coverage
- [GitHub Security Advisories API](https://docs.github.com/en/rest/security-advisories) — GHSA database
- [FIRST EPSS API](https://www.first.org/epss/api) — Exploit prediction scoring for prioritization

PledgeShield queries these APIs at scan time. No local CVE database to maintain — the APIs are always up to date. Offline mode caches the last API response for air-gapped environments.

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

---

## CVE API Integration

```
┌──────────────────────────────────────────────────┐
│                PledgeShield Scan                  │
│                                                   │
│  1. Enumerate installed software (platform-specific)    │
│     - Windows: Registry + winget + choco + pip/npm/cargo │
│     - macOS: system_profiler + brew + pip/npm/cargo      │
│     - Linux: dpkg/rpm/pacman + pip/npm/cargo             │
│                                                   │
│  2. Ecosystem detection for each package          │
│     - Maps package manager → OSV ecosystem        │
│     - Debian, AlmaLinux, Arch Linux, Homebrew,    │
│       PyPI, npm, Go, crates.io, RubyGems, etc.    │
│                                                   │
│  3. OSV batch query (all ecosystem-matched pkgs)  │
│     - Single API call for all packages            │
│     - Falls back to individual queries on error   │
│                                                   │
│  4. For each installed package:                   │
│     - NVD: Try CPE match first (35+ mappings)     │
│       - Fall back to keyword search if no match   │
│     - GHSA: Query by ecosystem + package name     │
│     - EPSS: Get exploit prediction score          │
│                                                   │
│  5. Cross-reference & deduplicate findings        │
│     - Merge results from NVD, OSV, GHSA           │
│     - Rank by EPSS score (exploit likelihood)     │
│     - Filter by severity (CVSS v3.x)              │
│                                                   │
│  6. Report                                        │
│     - Software name + version                     │
│     - CVE ID + CVSS score + EPSS score            │
│     - Source (NVD, OSV, or GHSA)                  │
│     - Recommended action (update to version X)    │
└──────────────────────────────────────────────────┘
```

### API Rate Limits & Caching

| API | Rate limit | Auth required | Notes |
|---|---|---|---|
| NVD 2.0 | 6s/req (no key), 2s/req (with key) | Optional API key | Built-in rate limiting |
| OSV.dev | 1000 req/min | None | Free, batch queries supported |
| GHSA | 5000 req/hour (auth), 60 req/hour (no auth) | Optional token | Use GitHub token for higher limit |
| EPSS | No documented limit | None | Free, daily updates |

**Caching strategy:**
- Cache API responses to disk (TTL: 24h)
- Batch queries where API supports it (OSV.dev batch endpoint)
- CPE-based NVD queries for precise matching (35+ vendor/product mappings)
- Offline mode: use last cached response
- User can force refresh with `--refresh-cve`

---

## Usage

### Basic scan
```bash
pledgeshield scan
```

### Full scan with CVE checks
```bash
pledgeshield scan --cve
```

### Specific modules only
```bash
pledgeshield scan --modules services,shares,persistence
pledgeshield scan --modules config
pledgeshield scan --modules cve
```

### Output formats
```bash
pledgeshield scan --format json --output report.json
pledgeshield scan --format html --output report.html
pledgeshield scan --format sarif --output report.sarif
pledgeshield scan --format text
```

### Severity filtering
```bash
pledgeshield scan --min-severity high
pledgeshield scan --cve --min-severity critical
```

### Fix mode (interactive)
```bash
pledgeshield scan --fix
# Shows each finding and asks: [F]ix / [S]kip / [A]uto-fix all
```

### Offline mode (uses cached CVE data)
```bash
pledgeshield scan --cve --offline
```

### Refresh CVE cache
```bash
pledgeshield scan --cve --refresh-cve
```

### Config file
```bash
# Generate a sample config
pledgeshield init-config --output pledgeshield.toml

# Use config file for scan settings
pledgeshield scan --config pledgeshield.toml
```

Config supports TOML and YAML, with:
- Module selection and severity filtering
- CVE API keys (NVD, GitHub token)
- Finding exclusions (by ID, category, or metadata)
- Thresholds (max info/low findings, fail-on severity for CI exit codes)

### Baseline diff scanning
```bash
# Save current scan as baseline
pledgeshield scan --save-baseline baseline.json

# Compare future scans against baseline
pledgeshield scan --baseline baseline.json
# Shows new findings, resolved findings, and unchanged count
```

### Remediation verification
```bash
# After applying fixes, verify they worked
pledgeshield scan --fix --verify
# Re-scans and reports which findings were resolved
```

### CI/CD integration
```bash
# SARIF output for GitHub code scanning
pledgeshield scan --format sarif --output results.sarif

# Exit code based on severity threshold (from config)
pledgeshield scan --config ci.toml
# Exits with code 2 if findings at or above fail_on severity
```

---

## Tech Stack

- **Language:** Rust
- **Windows APIs:** `windows` crate (official Microsoft Rust bindings), `winreg`, `wmi`
- **macOS APIs:** `core-foundation`, `system-configuration`, `security-framework` crates
- **Linux APIs:** `procfs`, `nix`, `sysctl` crates
- **HTTP:** `reqwest` (for CVE API calls)
- **CLI:** `clap`
- **Output:** `serde_json`, `serde_yaml`, `toml`, HTML via templates, SARIF 2.1.0
- **Config:** `toml` crate (TOML), `serde_yaml` (YAML config files)
- **Progress:** `indicatif` (progress bars during scan)
- **Distribution:** Cargo, npm (via napi-rs), Scoop, Homebrew, binary download

---

## Project Structure

```
pledgeshield/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs              # Entry point, CLI dispatch, scan orchestration
│   ├── cli.rs               # CLI argument definitions (clap)
│   ├── config.rs            # Config file loading (TOML/YAML), exclusions, thresholds
│   ├── baseline.rs          # Baseline diff scanning (save/load/compare)
│   ├── models.rs            # Finding, Severity, ScanResult models
│   ├── output.rs            # Text, JSON, HTML, SARIF report generation
│   ├── modules/
│   │   ├── mod.rs           # Module trait definition + registry
│   │   ├── config.rs        # Host configuration audit (shared interface)
│   │   ├── services.rs      # Service & port inventory (shared)
│   │   ├── cve.rs           # Software vulnerability check (shared, API-based)
│   │   ├── privileges.rs    # Privilege & account audit (shared)
│   │   ├── persistence.rs   # Persistence detection (shared)
│   │   ├── credentials.rs   # Credential exposure (shared)
│   │   ├── shares.rs        # Share & exposure audit (shared)
│   │   └── patches.rs       # Patch status (shared)
│   ├── platform/
│   │   ├── mod.rs           # Platform dispatch
│   │   ├── windows.rs       # #[cfg(windows)] — UAC, Defender, BitLocker, Registry, SMB, WMI
│   │   ├── macos.rs         # #[cfg(macos)] — Gatekeeper, SIP, FileVault, Keychain, TCC, XProtect
│   │   └── linux.rs         # #[cfg(linux)] — AppArmor/SELinux, systemd, fail2ban, PAM, sysctl
│   ├── cve/
│   │   ├── mod.rs           # CVE orchestration, ecosystem detection, software enumeration
│   │   ├── nvd.rs           # NVD API 2.0 client (rate limiting, CPE matching)
│   │   ├── osv.rs           # OSV.dev API client (single + batch queries)
│   │   ├── ghsa.rs          # GitHub Security Advisories client
│   │   ├── epss.rs          # EPSS API client
│   │   └── cache.rs         # Disk cache for API responses (TTL-based)
│   └── fix/
│       ├── mod.rs           # Fix orchestration + remediation verification
│       ├── registry_fix.rs  # Windows registry-based fixes
│       ├── service_fix.rs   # Service disable/enable (all platforms)
│       └── share_fix.rs     # Share permission fixes
└── templates/
    └── report.html          # HTML report template
```

---

## Finding Severity Levels

| Severity | Examples |
|---|---|
| **Critical** | RDP/SSH exposed to internet, SMBv1 enabled, no firewall, SIP disabled (macOS), SELinux disabled (Linux) |
| **High** | UAC disabled, admin share open to Everyone, Gatekeeper disabled, unpatched critical CVE (EPSS > 0.5) |
| **Medium** | Unnecessary service running as root/SYSTEM, weak password policy, missing updates |
| **Low** | Telemetry settings, clipboard history enabled, minor misconfigurations |
| **Info** | Informational findings (installed software list, service inventory) |

---

## Competitive Positioning

| Tool | What it does | Where PledgeShield wins |
|---|---|---|
| **Microsoft Defender / XProtect / ClamAV** | Malware detection only | Host hardening, misconfig detection, CVE check for installed software, cross-platform |
| **Lynis** | Linux/Unix host audit | Cross-platform (Windows + macOS), Rust binary, CVE API integration |
| **Hardening Kitty** | Windows compliance checks | Cross-platform, broader scope (persistence, credentials, shares, CVE), active maintenance |
| **Nessus / Qualys** | Enterprise vulnerability scanning | Free, lightweight, no agent/server, personal use |
| **Greenbone OpenVAS** | Open-source network vuln scanner | No server infrastructure, host-focused, Rust |
| **Wazuh** | HIDS/SIEM | No server needed, simpler, personal use |
| **Sysinternals** | Individual tools | Unified report, automated checks, actionable fixes |

**Key differentiators:**
- **Cross-platform** — Windows, macOS, and Linux from a single codebase
- **Rust** — memory-safe, single binary, no runtime dependency
- **API-based CVE** — no local database to maintain, always current
- **Multi-source CVE** — NVD + OSV + GHSA with CPE matching and ecosystem detection
- **EPSS scoring** — prioritize by actual exploit likelihood, not just CVSS
- **SARIF output** — GitHub code scanning compatible for CI/CD integration
- **Baseline diff** — track security posture changes over time
- **Config-driven** — TOML/YAML config for exclusions, thresholds, API keys
- **Remediation verification** — re-scan after fixes to confirm resolution
- **Interactive fix mode** — not just reporting, but guided remediation
- **Personal use** — no enterprise infrastructure needed

---

## Development Phases

### Phase 1 — MVP (Windows) ✅
- Host configuration audit (UAC, firewall, Defender, BitLocker)
- Service & port inventory
- Basic CLI + text output
- Windows only

### Phase 2 — CVE Integration (all platforms) ✅
- Software enumeration (platform-specific package managers)
- NVD + OSV.dev API integration
- CVE cache system
- JSON output

### Phase 3 — Deep Audit (all platforms) ✅
- Privilege & account audit
- Persistence detection
- Credential exposure
- Share & exposure audit
- Patch status

### Phase 4 — Cross-Platform Expansion ✅
- macOS hardening module (Gatekeeper, SIP, FileVault, Keychain, TCC, XProtect)
- Linux hardening module (AppArmor/SELinux, systemd, fail2ban, PAM, sysctl)
- Platform-specific persistence and credential checks

### Phase 5 — Reporting & Fixes ✅
- HTML report generation
- Interactive fix mode
- Severity scoring
- EPSS integration

### Phase 6 — CVE Enhancement & Polish ✅
- GHSA integration into CVE scan
- NVD rate limiting (6s/2s throttle with API key awareness)
- Ecosystem detection for OSV (Debian, npm, PyPI, Go, crates.io, etc.)
- OSV batch queries (single API call for all packages)
- CPE matching for NVD (35+ vendor/product mappings)
- Config file support (TOML/YAML with exclusions, thresholds, API keys)
- Baseline diff scanning (save/load/compare)
- SARIF 2.1.0 output format (GitHub code scanning compatible)
- Progress indicators (indicatif)
- Remediation verification (re-scan after fixes)
- `init-config` subcommand for sample config generation
- CI/CD exit codes based on severity thresholds

### Phase 7 — Hardening & Distribution (planned)
1. Unit tests for all audit modules (Windows, macOS, Linux)
2. Integration tests with mock command outputs
3. GitHub Actions CI matrix (Windows, macOS, Linux)
4. Cross-compilation for aarch64-apple-darwin, x86_64-unknown-linux-musl
5. npm package via napi-rs
6. Scoop manifest for Windows
7. Homebrew formula for macOS
8. Docker image for CI/headless scans
9. Windows fix mode expansion (macOS/Linux fix actions)
10. macOS fix mode (Gatekeeper enable, firewall enable, FileVault enable)
11. Linux fix mode (ufw enable, SSH hardening, fail2ban install)
12. HTML report interactive filtering (by severity, category, search)
13. HTML report CSV export button
14. Markdown output format
15. PDF report generation (via print CSS or external tool)
16. Scheduled scan support (cron/Task Scheduler integration)
17. Email notification on critical findings
18. Webhook notification (Slack, Discord, Teams)
19. Scan history tracking (local SQLite database)
20. Trend dashboard (findings over time, resolved vs new)
21. Compliance mapping (CIS Benchmarks, NIST SP 800-53)
22. Custom audit module plugins (user-defined checks via config)
23. Network interface exposure check (public IP detection, UPnP status)
24. Browser extension audit (installed extensions, risky permissions)
25. Container/runtime security checks (Docker, Podman, Kubernetes pod)

---

## Current Status

- **Phase:** 6 complete — all 25 goals implemented
- **Compiles:** Yes (Rust stable, cross-platform)
- **Platforms:** Windows, macOS, Linux
- **CVE APIs:** NVD, OSV, GHSA, EPSS (with rate limiting, caching, CPE matching)
- **Output formats:** Text, JSON, HTML, SARIF 2.1.0
- **Config:** TOML/YAML with exclusions, thresholds, API keys
- **Next phase:** Phase 7 — Hardening & Distribution
