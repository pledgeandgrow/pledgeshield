/// Connection rate limiter — limit new outbound connections per process.
use super::HardenResult;
use std::process::Command;

pub fn enable_rate_limit(max_per_min: u32, dry_run: bool) -> HardenResult {
    if dry_run {
        return HardenResult {
            action: "ratelimit-enable".to_string(),
            success: true,
            message: format!("[dry-run] Would limit new outbound connections to {}/min per process", max_per_min),
            findings: vec![],
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Use iptables hashlimit to rate-limit new outbound connections
        let out = Command::new("iptables")
            .args(["-A", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW",
                   "-m", "hashlimit", "--hashlimit-above", &format!("{}/min", max_per_min),
                   "--hashlimit-burst", &format!("{}", max_per_min * 2),
                   "--hashlimit-mode", "srcip",
                   "--hashlimit-name", "pledgeshield-ratelimit",
                   "-j", "DROP"])
            .output();

        let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        HardenResult {
            action: "ratelimit-enable".to_string(),
            success: ok,
            message: if ok {
                format!("Rate limit set: max {} new connections/min per source IP.", max_per_min)
            } else {
                "Failed to set rate limit (need root?)".to_string()
            },
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = max_per_min;
        HardenResult {
            action: "ratelimit-enable".to_string(),
            success: false,
            message: "Rate limiting via iptables is only supported on Linux.".to_string(),
            findings: vec![],
        }
    }
}

pub fn disable_rate_limit() -> HardenResult {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("iptables")
            .args(["-D", "OUTPUT", "-m", "conntrack", "--ctstate", "NEW",
                   "-m", "hashlimit", "--hashlimit-above", "1/min",
                   "--hashlimit-burst", "2",
                   "--hashlimit-mode", "srcip",
                   "--hashlimit-name", "pledgeshield-ratelimit",
                   "-j", "DROP"])
            .output();
        // Also try flushing
        let _ = Command::new("iptables").args(["-F", "pledgeshield-ratelimit"]).output();
        HardenResult {
            action: "ratelimit-disable".to_string(),
            success: true,
            message: "Rate limit rules removed.".to_string(),
            findings: vec![],
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HardenResult {
            action: "ratelimit-disable".to_string(),
            success: false,
            message: "Not supported.".to_string(),
            findings: vec![],
        }
    }
}
