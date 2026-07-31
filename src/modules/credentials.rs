use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct CredentialsModule;

impl Module for CredentialsModule {
    fn id(&self) -> &'static str {
        "credentials"
    }

    fn name(&self) -> &'static str {
        "Credential Exposure"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_credentials()
    }
}
