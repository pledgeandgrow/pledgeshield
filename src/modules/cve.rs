use crate::models::Finding;
use crate::modules::Module;

/// Stub CVE module for the module registry (not the API-based CVE scan).
/// The actual CVE scan is orchestrated separately via `cve::run_cve_scan`.
pub struct CveModule;

impl Module for CveModule {
    fn id(&self) -> &'static str {
        "cve"
    }

    fn name(&self) -> &'static str {
        "Software Vulnerability Check"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        // The CVE scan is async and handled by the cve subsystem.
        // This stub exists so the module can be listed in the registry.
        Ok(vec![])
    }
}
