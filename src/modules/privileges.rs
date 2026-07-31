use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct PrivilegesModule;

impl Module for PrivilegesModule {
    fn id(&self) -> &'static str {
        "privileges"
    }

    fn name(&self) -> &'static str {
        "Privilege & Account Audit"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_privileges()
    }
}
