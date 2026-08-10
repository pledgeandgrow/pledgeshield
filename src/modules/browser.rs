use crate::models::Finding;
use crate::modules::Module;

pub struct BrowserModule;

impl Module for BrowserModule {
    fn id(&self) -> &'static str {
        "browser"
    }

    fn name(&self) -> &'static str {
        "Browser Extension Audit"
    }

    fn scan(&self) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        Ok(crate::browser::audit_browser_extensions())
    }
}
