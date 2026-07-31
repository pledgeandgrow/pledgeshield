use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct PersistenceModule;

impl Module for PersistenceModule {
    fn id(&self) -> &'static str {
        "persistence"
    }

    fn name(&self) -> &'static str {
        "Persistence Detection"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_persistence()
    }
}
