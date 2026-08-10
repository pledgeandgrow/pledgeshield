use crate::models::Finding;
use crate::modules::Module;

pub struct NetworkModule;

impl Module for NetworkModule {
    fn id(&self) -> &'static str {
        "network"
    }

    fn name(&self) -> &'static str {
        "Network Exposure Audit"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        Ok(crate::network::audit_network_exposure())
    }
}
