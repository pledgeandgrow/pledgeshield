use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct ConfigModule;

impl Module for ConfigModule {
    fn id(&self) -> &'static str {
        "config"
    }

    fn name(&self) -> &'static str {
        "Host Configuration Audit"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_config()
    }
}
