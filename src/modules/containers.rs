use crate::models::Finding;
use crate::modules::Module;

pub struct ContainersModule;

impl Module for ContainersModule {
    fn id(&self) -> &'static str {
        "containers"
    }

    fn name(&self) -> &'static str {
        "Container Runtime Security"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        Ok(crate::containers::audit_container_security())
    }
}
