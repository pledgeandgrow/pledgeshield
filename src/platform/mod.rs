#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

use crate::models::Finding;

pub fn audit_config() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_config()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_config()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_config()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_services() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_services()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_services()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_services()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_privileges() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_privileges()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_privileges()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_privileges()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_persistence() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_persistence()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_persistence()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_persistence()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_credentials() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_credentials()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_credentials()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_credentials()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_shares() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_shares()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_shares()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_shares()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}

pub fn audit_patches() -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        windows::audit_patches()
    }
    #[cfg(target_os = "macos")]
    {
        macos::audit_patches()
    }
    #[cfg(target_os = "linux")]
    {
        linux::audit_patches()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err("unsupported platform".into())
    }
}
