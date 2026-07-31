use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct SharesModule;

impl Module for SharesModule {
    fn id(&self) -> &'static str {
        "shares"
    }

    fn name(&self) -> &'static str {
        "Share & Exposure Audit"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_shares()
    }
}
