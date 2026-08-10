pub mod arp;
pub mod attrmon;
pub mod autorun;
pub mod backup;
pub mod binhash;
pub mod bluetooth;
pub mod bootlog;
pub mod browser;
pub mod canary;
pub mod caps;
pub mod cleaner;
pub mod clipboard;
pub mod codeinject;
pub mod cronmon;
pub mod deauth;
pub mod deps;
pub mod devices;
pub mod diskmon;
pub mod dnsmon;
pub mod doh;
pub mod dohforce;
pub mod encryption;
pub mod envleak;
pub mod exfil;
pub mod fail2ban;
pub mod fileperms;
pub mod filewatch;
pub mod firewall;
pub mod firewire;
pub mod freespace;
pub mod geoip;
pub mod hollow;
pub mod hostname;
pub mod hosts;
pub mod identity;
pub mod immutable;
pub mod integrity;
pub mod ipv6;
pub mod isolation;
pub mod kernel;
pub mod knock;
pub mod libaudit;
pub mod lockscreen;
pub mod logins;
pub mod logtamper;
pub mod mac;
pub mod macaudit;
pub mod memscan;
pub mod memwipe;
pub mod metadata;
pub mod micmute;
pub mod modsign;
pub mod mount;
pub mod netcons;
pub mod nsaudit;
pub mod pam;
pub mod pcapdetect;
pub mod pii;
pub mod polkit;
pub mod ports;
pub mod posture;
pub mod procinj;
pub mod proctree;
pub mod profile;
pub mod proxy;
pub mod ptrace;
pub mod quota;
pub mod ratelimit;
pub mod resource;
pub mod roguedhcp;
pub mod rootkit;
pub mod scheduler;
pub mod secrets;
pub mod sensitive;
pub mod shredder;
pub mod ssh;
pub mod sshkeys;
pub mod suid;
pub mod sysctl;
pub mod systemd;
pub mod telemetry;
pub mod thread;
pub mod thunderbolt;
pub mod tls;
pub mod tmpsan;
pub mod tpm;
pub mod traffic;
pub mod uefi;
pub mod usb;
pub mod useragent;
pub mod usermon;
pub mod vault;
pub mod webcam;
pub mod webrtc;
pub mod wifi;

use crate::models::Finding;

/// Result of a hardening action.
#[derive(Debug, Clone)]
pub struct HardenResult {
    /// What was attempted
    pub action: String,
    /// Whether it succeeded
    pub success: bool,
    /// Human-readable detail
    pub message: String,
    /// Findings that motivated this action (if any)
    pub findings: Vec<Finding>,
}

impl std::fmt::Display for HardenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icon = if self.success { "✓" } else { "✗" };
        write!(f, "  {} {} — {}", icon, self.action, self.message)
    }
}
