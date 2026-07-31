use crate::models::Finding;
use crate::modules::Module;
use crate::platform;

pub struct PatchesModule;

impl Module for PatchesModule {
    fn id(&self) -> &'static str {
        "patches"
    }

    fn name(&self) -> &'static str {
        "Patch Status"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        platform::audit_patches()
    }
}
