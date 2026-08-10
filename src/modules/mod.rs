pub mod browser;
pub mod config;
pub mod containers;
pub mod credentials;
pub mod cve;
pub mod network;
pub mod patches;
pub mod persistence;
pub mod privileges;
pub mod services;
pub mod shares;

use crate::models::Finding;

/// Trait that every scan module implements.
pub trait Module: Send + Sync {
    /// Short identifier (e.g. "services", "config")
    fn id(&self) -> &'static str;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Run the scan and return findings
    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>>;
}

/// Registry that holds all available modules.
pub struct ModuleRegistry {
    modules: Vec<Box<dyn Module>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        let modules: Vec<Box<dyn Module>> = vec![
            Box::new(config::ConfigModule),
            Box::new(services::ServicesModule),
            Box::new(privileges::PrivilegesModule),
            Box::new(persistence::PersistenceModule),
            Box::new(credentials::CredentialsModule),
            Box::new(shares::SharesModule),
            Box::new(patches::PatchesModule),
            Box::new(network::NetworkModule),
            Box::new(browser::BrowserModule),
            Box::new(containers::ContainersModule),
        ];

        Self { modules }
    }

    pub fn all(&self) -> Vec<&dyn Module> {
        self.modules.iter().map(|m| m.as_ref()).collect()
    }

    pub fn get_by_names(&self, names: &[String]) -> Vec<&dyn Module> {
        self.modules
            .iter()
            .filter(|m| names.iter().any(|n| n == m.id()))
            .map(|m| m.as_ref())
            .collect()
    }
}
