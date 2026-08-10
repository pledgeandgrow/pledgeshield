# PledgeShield Modules

This document lists every module in PledgeShield, organized by category.

---

## Audit Modules (Scanner)

These modules run during `pledgeshield scan` and produce security findings.

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Host Config Audit | `src/modules/config.rs` | Checks OS version, hostname, timezone, kernel parameters, and system-wide configuration misconfigurations |
| 2 | Service & Port Inventory | `src/modules/services.rs` | Enumerates all running services and listening TCP/UDP ports, flags insecure services (Telnet, FTP, RDP) |
| 3 | Privilege & Account Audit | `src/modules/privileges.rs` | Audits user accounts, sudo access, empty passwords, UID 0 accounts, dormant users |
| 4 | Persistence Detection | `src/modules/persistence.rs` | Scans cron jobs, systemd timers, launchd agents, registry Run keys, startup folders for persistence mechanisms |
| 5 | Credential Exposure | `src/modules/credentials.rs` | Finds exposed secrets, API keys, SSH keys with bad permissions, world-readable config files |
| 6 | Share & Exposure Audit | `src/modules/shares.rs` | Checks NFS/SMB exports, anonymous FTP, shared directories with overly permissive access |
| 7 | Patch Status | `src/modules/patches.rs` | Checks for pending OS updates, outdated packages, unpatched CVEs |
| 8 | Network Exposure | `src/modules/network.rs` | UPnP status, public IP detection, wildcard listening sockets, IPv6 exposure |
| 9 | Browser Extension Audit | `src/modules/browser.rs` | Audits installed browser extensions for known-malicious entries, excessive permissions |
| 10 | Container Security | `src/modules/containers.rs` | Docker/Podman/K8s misconfig: privileged containers, root user, no seccomp, exposed ports |
| 11 | Compliance Mapping | `src/compliance.rs` | Maps findings to CIS Benchmark and NIST 800-53 control IDs (`--compliance` flag) |
| 12 | Custom Checks | `src/custom.rs` | User-defined checks from a TOML file (`--custom-checks` flag) |
| 13 | CVE Scanning | `src/cve/` | NVD, OSV, GHSA, EPSS cross-referencing (`--cve` flag) |

### Audit Support Modules

| Module | File | Description |
|--------|------|-------------|
| Scan History | `src/history.rs` | SQLite-backed scan history storage (`--save-history` flag) |
| Trend Dashboard | `src/trend.rs` | Findings-over-time dashboard from scan history |
| Notifications | `src/notify/` | Email + webhook notifications + scheduled scans |
| Baseline Diff | `src/baseline.rs` | Compare scan results against a known-good baseline |
| Output Formatting | `src/output.rs` | Text, JSON, HTML, SARIF, Markdown, PDF report generation |
| Fix Actions | `src/fix/` | Interactive remediation (`--fix` flag) |
| Remediation Verify | `src/fix/` | Verify that previously applied fixes are still in effect (`--verify` flag) |

---

## Active Defense Modules (`harden`)

These modules take action to secure the system. Invoked via `pledgeshield harden <subcommand>`.

### Network & Traffic (8)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Port Closer | `src/harden/ports.rs` | Closes insecure open ports (Telnet, FTP, RDP, VNC, SMB, Redis, MongoDB) via firewall rules |
| 2 | Firewall Hardener | `src/harden/firewall.rs` | Enable/harden/disable system firewall (UFW/iptables/firewalld on Linux, socketfilterfw on macOS, netsh on Windows). Sets default DROP, allows only established+loopback+SSH |
| 3 | DNS-over-HTTPS | `src/harden/doh.rs` | Configures encrypted DNS via systemd-resolved (DoT) or dnscrypt-proxy (DoH). Supports Cloudflare, Google, Quad9, AdGuard providers |
| 4 | WiFi Security | `src/harden/wifi.rs` | Audits WiFi for open networks, WEP, auto-connect to open networks, saved network leaks. Can forget saved networks |
| 5 | ARP Spoofing Detector | `src/harden/arp.rs` | Monitors ARP table for MAC changes, detects MITM attacks. Real-time monitoring mode with configurable interval |
| 6 | Network Isolation | `src/harden/isolation.rs` | Blocks all outbound traffic except whitelisted IPs via iptables OUTPUT DROP policy. Allows DNS + established connections |
| 7 | Proxy Manager | `src/harden/proxy.rs` | Sets/clears SOCKS5/HTTP proxy settings system-wide (environment variables on Linux, networksetup on macOS, registry on Windows) |
| 8 | IPv6 Leak Guard | `src/harden/ipv6.rs` | Disables IPv6 via sysctl or blocks IPv6 traffic via ip6tables. Prevents VPN/DNS leaks over IPv6 |
| 9 | Hosts File Hardener | `src/harden/hosts.rs` | Downloads and installs ad/tracker/malware domain blocklists into the hosts file. Supports StevenBlack, AdAway, malware lists. Custom domain blocking |
| 10 | Traffic Monitor | `src/harden/traffic.rs` | Tracks per-process network usage via /proc/[pid]/io. Flags anomalous data exfiltration (>100MB uploads). Real-time monitoring mode |

### Identity & Privacy (7)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | MAC Spoofer | `src/harden/mac.rs` | Spoofs or randomizes network interface MAC addresses. Generates locally-administered MACs. Can restore original |
| 2 | Identity Hardener | `src/harden/identity.rs` | Sets privacy DNS resolvers, disables OS telemetry (Ubuntu, Windows, macOS), clears machine IDs |
| 3 | Hostname Randomizer | `src/harden/hostname.rs` | Randomizes machine hostname to prevent tracking on networks. Can install systemd service for boot-time randomization |
| 4 | User-Agent Spoofer | `src/harden/useragent.rs` | Sets browser user-agent strings to prevent fingerprinting. Supports Chrome, Edge, Brave, Chromium, Firefox |
| 5 | WebRTC Leak Blocker | `src/harden/webrtc.rs` | Disables WebRTC in Firefox (prefs.js) and Chromium-based browsers (policy). Prevents real IP leaks behind VPN |
| 6 | Bluetooth Privacy | `src/harden/bluetooth.rs` | Audits Bluetooth state, disables discoverability, powers off Bluetooth, lists/removes paired devices |
| 7 | Camera/Mic Guard | `src/harden/devices.rs` | Audits which processes have camera/microphone access (via /proc fd scanning on Linux, TCC database on macOS). Can block camera devices |
| 8 | Clipboard Privacy | `src/harden/clipboard.rs` | Clears clipboard contents (xclip/xsel/wl-copy/pbcopy/PowerShell). Can install auto-clear watcher that wipes clipboard after N seconds |
| 9 | Activity Cleaner | `src/harden/cleaner.rs` | Clears shell history (bash, zsh, python, mysql, psql), less/vim history, recent files, thumbnail cache, temp files |
| 10 | Browser Privacy | `src/harden/browser.rs` | Disables browser telemetry, enables Safe Browsing + tracking protection, configures Firefox DoH, blocks WebRTC IP leak. Can clear cookies/cache/history |

### System Hardening (8)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | USB Device Guard | `src/harden/usb.rs` | Audits connected USB devices. Lockdown mode via USBGuard (only currently connected devices allowed). Lists connected devices |
| 2 | Kernel Module Lockdown | `src/harden/kernel.rs` | Restricts kernel module loading (irreversible until reboot via `kernel.modules_disabled=1`). Detects suspicious loaded modules. Lists loaded modules |
| 3 | SUID/SGID Scanner | `src/harden/suid.rs` | Finds all SUID/SGID binaries, flags suspicious ones (outside known-safe list, in unusual locations like /tmp, /home). Can remove SUID bit |
| 4 | Scheduler Auditor | `src/harden/scheduler.rs` | Deep scans cron jobs, systemd timers, launchd agents, Windows scheduled tasks for suspicious entries (download+exec, netcat listeners, reverse shells) |
| 5 | File Integrity Monitor | `src/harden/integrity.rs` | Hashes critical system files (/etc/passwd, /etc/shadow, /bin/su, etc.) and alerts on changes. Baseline creation, integrity check, baseline removal |
| 6 | Process Tree Analyzer | `src/harden/proctree.rs` | Detects suspicious parent-child process relationships (browser→shell, Office→PowerShell, web server→shell, FTP→shell). Indicates possible exploitation |
| 7 | Lock Screen Enforcer | `src/harden/lockscreen.rs` | Forces screen lock timeout (GNOME, macOS, Windows). Disables auto-login (GDM, LightDM, macOS, Windows). Audits current settings |
| 8 | Disk Encryption | `src/harden/encryption.rs` | Detects unencrypted disks and swap. Provides guided setup for LUKS (Linux), FileVault (macOS), BitLocker (Windows) |

### Detection & Response (4)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Rootkit Scanner | `src/harden/rootkit.rs` | Checks for rootkit indicators: hidden PIDs (ps vs /proc), LD_PRELOAD abuse, hidden kernel modules (lsmod vs /proc/modules), suspicious files in /dev, recently modified system binaries |
| 2 | Ransomware Canary | `src/harden/canary.rs` | Plants decoy files in user directories (Documents, Desktop, Downloads, Pictures). Monitors for mass encryption/modification. Early ransomware warning system |
| 3 | Login Attempt Monitor | `src/harden/logins.rs` | Tracks failed SSH/RDP/login attempts from auth logs. Detects brute force (>=10 failures per IP). Checks fail2ban status. Can block IPs |
| 4 | DNS Query Monitor | `src/harden/dnsmon.rs` | Monitors DNS queries for anomalies: DGA patterns (random-looking domains), known C2 domains, suspicious TLDs (.xyz, .top, .click), fast flux (many IPs per domain). Real-time monitoring mode |

### Privacy Tools (3)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Secure File Shredder | `src/harden/shredder.rs` | Securely deletes files by multi-pass overwrite (zeros, ones, alternating, random) + rename + delete. Supports individual files and directories |
| 2 | Memory/Swap Wipe | `src/harden/memwipe.rs` | Wipes swap space (disable, dd random, re-enable). Sets up encrypted swap with random key at boot. Installs systemd service to wipe RAM on shutdown. Drops kernel caches |
| 3 | Metadata Stripper | `src/harden/metadata.rs` | Strips EXIF/IPTC/XMP metadata from JPEG, PNG, and PDF files. Falls back to exiftool for unsupported types. Can list metadata without stripping |

### Boot & Firmware (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | UEFI/BIOS Auditor | `src/harden/uefi.rs` | Audits Secure Boot status, boot password, Boot Order lock, and TPM-backed firmware protection |
| 2 | Boot Log Analyzer | `src/harden/bootlog.rs` | Analyzes boot logs (journalctl/dmesg) for anomalies: I/O errors, firmware failures, driver crashes, boot time spikes |
| 3 | Sysctl Hardener | `src/harden/sysctl.rs` | Hardens kernel parameters: ASLR, ptrace_scope, dmesg restriction, kernel pointer restriction, core dumps |
| 4 | Module Signature Verifier | `src/harden/modsign.rs` | Verifies kernel module signatures, checks CONFIG_MODULE_SIG_FORCE, flags unsigned modules |
| 5 | TPM Status Checker | `src/harden/tpm.rs` | Checks TPM availability, version (1.2/2.0), measured boot, PCR state, and disk encryption binding |

### File & Data Protection (6)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | File Permission Auditor | `src/harden/fileperms.rs` | Finds world-readable/writable sensitive files (.ssh, .gnupg, .aws, .kube, password files, private keys) |
| 2 | Sensitive File Finder | `src/harden/sensitive.rs` | Locates private keys, certificates, password files, token files across the system. Checks permissions |
| 3 | Exfiltration Guard | `src/harden/exfil.rs` | Monitors for large file copies to USB/network. Detects mass file access patterns indicative of data theft |
| 4 | Backup Integrity Checker | `src/harden/backup.rs` | Verifies backups exist, are recent, and match expected hashes. Alerts on stale or corrupted backups |
| 5 | Disk Usage Anomaly Detector | `src/harden/diskmon.rs` | Flags sudden disk space changes — a key ransomware indicator. Monitors free space trends |
| 6 | Log Tampering Detector | `src/harden/logtamper.rs` | Checks for truncated, deleted, or modified system logs. Detects log clearing attempts |

### SSH & Remote Access (4)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | SSH Config Hardener | `src/harden/ssh.rs` | Disables root login, password auth, X11 forwarding. Enforces key-only auth, strong ciphers, ClientAlive intervals |
| 2 | SSH Key Auditor | `src/harden/sshkeys.rs` | Checks SSH key sizes (RSA >= 2048), passphrases, file permissions. Flags weak or shared keys |
| 3 | Port Knocking Setup | `src/harden/knock.rs` | Configures port knocking to hide SSH from port scanners. Installs knockd with custom sequences |
| 4 | Fail2ban Configurator | `src/harden/fail2ban.rs` | Installs and configures fail2ban for brute force protection. Sets up SSH, Nginx, Apache jails |

### Application Hardening (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | TLS Certificate Checker | `src/harden/tls.rs` | Checks your own TLS certificates for expiration, weak ciphers, missing intermediate certs, wildcards |
| 2 | Dependency Vulnerability Scanner | `src/harden/deps.rs` | Scans package manifests (Cargo.toml, package.json, requirements.txt, go.mod) for known CVEs |
| 3 | Secret Scanner | `src/harden/secrets.rs` | Scans your own files for committed API keys, tokens, passwords. High-entropy string detection |
| 4 | Browser Vault Auditor | `src/harden/vault.rs` | Checks if browser saved passwords are encrypted at rest. Audits vault encryption status |
| 5 | Autorun Disabler | `src/harden/autorun.rs` | Disables AutoPlay/AutoRun to prevent malware auto-execution from USB/CD/network drives |

### System Monitoring (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Resource Anomaly Detector | `src/harden/resource.rs` | Detects CPU/RAM spikes and crypto miner patterns. Monitors per-process resource usage |
| 2 | New File Watcher | `src/harden/filewatch.rs` | Monitors system directories for new executable files. Alerts on binaries in /tmp, /dev/shm, user dirs |
| 3 | User Account Monitor | `src/harden/usermon.rs` | Alerts on new user accounts, UID changes, sudoers modifications, group membership changes |
| 4 | Network Connection Auditor | `src/harden/netcons.rs` | Lists all outbound connections with associated processes. Flags suspicious destinations |
| 5 | Crontab Monitor | `src/harden/cronmon.rs` | Alerts on new or modified scheduled tasks. Detects persistence via cron modifications |

### Privacy & Compliance (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | PII Scanner | `src/harden/pii.rs` | Scans your own files for SSNs, credit card numbers, phone numbers, email addresses. GDPR compliance |
| 2 | Telemetry Deep-Cleaner | `src/harden/telemetry.rs` | Disables ALL telemetry across OS, browsers, dev tools. Covers Windows, macOS, Ubuntu, Firefox, Chrome |
| 3 | Free Space Wiper | `src/harden/freespace.rs` | Overwrites disk free space so deleted files can't be recovered. Supports zeros, random, multi-pass |
| 4 | Posture Score | `src/harden/posture.rs` | Aggregates all findings into a 0-100 security posture score with letter grade. Actionable recommendations |
| 5 | Profile Applier | `src/harden/profile.rs` | Applies CIS Level 1/2, STIG, or custom hardening profiles. Audit mode shows what would change |

### Process & Memory Defense (6)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Process Injection Detector | `src/harden/procinj.rs` | Scans for suspicious injected libraries (LD_PRELOAD, /proc/pid/maps anomalies, injected shared objects) |
| 2 | Hollow Process Detector | `src/harden/hollow.rs` | Detects process name/binary mismatches where the running binary doesn't match the reported name |
| 3 | Memory Scanner | `src/harden/memscan.rs` | Scans process memory for malware signatures. Checks /proc/pid/mem for known bad strings/byte patterns |
| 4 | Ptrace Detector | `src/harden/ptrace.rs` | Alerts if processes are being traced/debugged. Checks /proc/status TracerPid, yama ptrace_scope |
| 5 | Thread Anomaly Detector | `src/harden/thread.rs` | Flags processes with suspicious thread counts. Detects thread injection and thread hijacking |
| 6 | Code Injection Blocker | `src/harden/codeinject.rs` | Hardens ptrace_scope to prevent injection, disables BPF for unprivileged users. Reversible blocking mode |

### Network Defense (6)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Connection Rate Limiter | `src/harden/ratelimit.rs` | Limits new outbound connections per minute via iptables hashlimit. Prevents beaconing and mass exfiltration |
| 2 | Geo-IP Outbound Filter | `src/harden/geoip.rs` | Blocks connections to high-risk countries. Configurable country blocklist via iptables geoip module |
| 3 | DNS-over-HTTPS Enforcement | `src/harden/dohforce.rs` | Forces encrypted DNS and blocks plaintext DNS (port 53). Prevents DNS manipulation and snooping |
| 4 | Packet Capture Detector | `src/harden/pcapdetect.rs` | Detects promiscuous mode interfaces and packet sniffers. Checks for running tcpdump/wireshark/tshark |
| 5 | Rogue DHCP Detector | `src/harden/roguedhcp.rs` | Detects DHCP responses from non-router sources. Prevents MITM via rogue DHCP servers |
| 6 | WiFi Deauth Detector | `src/harden/deauth.rs` | Detects WiFi deauthentication attacks (802.11 deauth frames). Real-time monitoring mode with timeout |

### Filesystem & Storage (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Immutable File Setter | `src/harden/immutable.rs` | Protects critical system files with chattr +i. Prevents modification even by root until flag removed |
| 2 | Mount Option Hardener | `src/harden/mount.rs` | Enforces nosuid, nodev, noexec on mount points (/tmp, /home, removable media). Updates /etc/fstab |
| 3 | Temp Directory Sanitizer | `src/harden/tmpsan.rs` | Cleans stale files from /tmp, /var/tmp, /dev/shm. Removes world-writable sticky bit issues |
| 4 | Quota Enforcer | `src/harden/quota.rs` | Sets disk quotas to prevent disk filling (ransomware protection). Configures usrquota, grpquota |
| 5 | File Attribute Monitor | `src/harden/attrmon.rs` | Watches for permission and immutable flag changes on critical files. Baseline comparison |

### Access Control (5)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | PAM Module Auditor | `src/harden/pam.rs` | Checks for backdoored or weak PAM modules. Audits pam.d configs for insecure auth settings |
| 2 | Polkit Auditor | `src/harden/polkit.rs` | Checks for overly permissive polkit rules. Detects pkexec misconfigurations and privilege escalation |
| 3 | MAC Enforcer (AppArmor/SELinux) | `src/harden/macaudit.rs` | Checks AppArmor/SELinux enforcement status. Alerts on permissive mode, disabled modules, unconfined processes |
| 4 | Capability Auditor | `src/harden/caps.rs` | Scans binaries for dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, etc.) |
| 5 | Namespace Isolation Auditor | `src/harden/nsaudit.rs` | Checks process namespace isolation. Detects processes sharing host PID/net/mnt namespaces |

### Hardware & Peripherals (4)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Thunderbolt/USB4 Guard | `src/harden/thunderbolt.rs` | Disables Thunderbolt DMA, requires device approval. Blacklists Thunderbolt kernel modules |
| 2 | Webcam Guard | `src/harden/webcam.rs` | Disables webcam by unloading uvcvideo module. Audits for unauthorized webcam access. Restorable |
| 3 | Microphone Mute Enforcer | `src/harden/micmute.rs` | Mutes all microphones at the audio system level (ALSA/PulseAudio/PipeWire). Restorable |
| 4 | Firewire/PCMCIA DMA Guard | `src/harden/firewire.rs` | Disables FireWire and PCMCIA DMA access by unloading kernel modules. Blacklists for persistence |

### System Integrity (4)

| # | Module | File | Description |
|---|--------|------|-------------|
| 1 | Systemd Unit Auditor | `src/harden/systemd.rs` | Deep scans systemd units for suspicious services: odd ExecStart, network downloads, shell spawns, hidden units |
| 2 | Environment Variable Leak Checker | `src/harden/envleak.rs` | Scans /proc/*/environ for secrets in environment variables. Detects API keys/tokens passed to processes |
| 3 | Shared Library Auditor | `src/harden/libaudit.rs` | Checks LD_LIBRARY_PATH, RPATH, RUNPATH for unusual paths. Detects library hijacking vectors |
| 4 | Binary Hash Verifier | `src/harden/binhash.rs` | Compares binary hashes against package manager records (dpkg, rpm). Detects trojanized binaries |

---

## VPN & Proxy Modules

| Module | File | Description |
|--------|------|-------------|
| VPN Manager | `src/vpn/mod.rs` | WireGuard and OpenVPN connection management (status, connect, disconnect, list configs, kill switch) |
| Tor Proxy | `src/vpn/tor.rs` | Tor daemon management (start, stop, status). Transparent traffic routing via iptables (Linux). Exit IP verification via Tor check API |

---

## Real-Time Monitor

| Module | File | Description |
|--------|------|-------------|
| Security Monitor | `src/monitor.rs` | Real-time daemon that watches for: new listening ports (especially sensitive ports like SSH/RDP/SMB), new root/SYSTEM processes, and firewall state changes. Configurable polling interval and max runtime. Ctrl+C to stop |

---

## Platform Abstraction

| Module | File | Description |
|--------|------|-------------|
| Linux Platform | `src/platform/linux.rs` | Linux-specific system calls, package manager detection, service management |
| macOS Platform | `src/platform/macos.rs` | macOS-specific system calls, TCC database access, networksetup integration |
| Windows Platform | `src/platform/windows.rs` | Windows-specific system calls, registry access, WMI queries, netsh/firewall integration |

---

## Module Statistics

| Category | Count |
|----------|-------|
| Audit modules (scanner) | 13 |
| Audit support modules | 7 |
| Active defense — Network & Traffic | 10 |
| Active defense — Identity & Privacy | 10 |
| Active defense — System Hardening | 8 |
| Active defense — Detection & Response | 4 |
| Active defense — Privacy Tools | 3 |
| Active defense — Boot & Firmware | 5 |
| Active defense — File & Data Protection | 6 |
| Active defense — SSH & Remote Access | 4 |
| Active defense — Application Hardening | 5 |
| Active defense — System Monitoring | 5 |
| Active defense — Privacy & Compliance | 5 |
| Active defense — Process & Memory Defense | 6 |
| Active defense — Network Defense | 6 |
| Active defense — Filesystem & Storage | 5 |
| Active defense — Access Control | 5 |
| Active defense — Hardware & Peripherals | 4 |
| Active defense — System Integrity | 4 |
| VPN & Proxy | 2 |
| Real-time monitor | 1 |
| Platform abstraction | 3 |
| **Total** | **121** |

### Source files in `src/harden/`

```
arp.rs          attrmon.rs      autorun.rs      backup.rs
binhash.rs      bluetooth.rs    bootlog.rs      browser.rs
canary.rs       caps.rs         cleaner.rs      clipboard.rs
codeinject.rs   cronmon.rs      deauth.rs       deps.rs
devices.rs      diskmon.rs      dnsmon.rs       doh.rs
dohforce.rs     encryption.rs   envleak.rs      exfil.rs
fail2ban.rs     fileperms.rs    filewatch.rs    firewall.rs
firewire.rs     freespace.rs    geoip.rs        hollow.rs
hostname.rs     hosts.rs        identity.rs     immutable.rs
integrity.rs    ipv6.rs         isolation.rs    kernel.rs
knock.rs        libaudit.rs     lockscreen.rs   logins.rs
logtamper.rs    mac.rs          macaudit.rs     memscan.rs
memwipe.rs      metadata.rs     micmute.rs      mod.rs
modsign.rs      mount.rs        netcons.rs      nsaudit.rs
pam.rs          pcapdetect.rs   pii.rs          polkit.rs
ports.rs        posture.rs      procinj.rs      proctree.rs
profile.rs      proxy.rs        ptrace.rs       quota.rs
ratelimit.rs    resource.rs     roguedhcp.rs    rootkit.rs
scheduler.rs    secrets.rs      sensitive.rs    shredder.rs
ssh.rs          sshkeys.rs      suid.rs         sysctl.rs
systemd.rs      telemetry.rs    thread.rs       thunderbolt.rs
tls.rs          tmpsan.rs       tpm.rs          traffic.rs
uefi.rs         usb.rs          useragent.rs    usermon.rs
vault.rs        webcam.rs       webrtc.rs       wifi.rs
```
