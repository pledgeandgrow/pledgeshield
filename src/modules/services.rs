use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct ServicesModule;

impl Module for ServicesModule {
    fn id(&self) -> &'static str {
        "services"
    }

    fn name(&self) -> &'static str {
        "Service & Port Inventory"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_services()
    }
}
