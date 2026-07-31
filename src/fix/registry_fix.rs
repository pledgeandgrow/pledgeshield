/// Windows registry-based fixes.

#[cfg(target_os = "windows")]
pub fn apply_registry_fix(key: &str, value: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    use winreg::enums::*;
    use winreg::RegKey;

    log::info!("Registry fix: {}\\{} = {}", key, value, data);

    let (hive, subkey) = if key.starts_with("HKLM") {
        (HKEY_LOCAL_MACHINE, key.trim_start_matches("HKLM\\"))
    } else if key.starts_with("HKCU") {
        (HKEY_CURRENT_USER, key.trim_start_matches("HKCU\\"))
    } else {
        return Err(format!("Unsupported registry hive in key: {}", key).into());
    };

    let hk = RegKey::predef(hive);
    let (key_obj, _created) = hk.create_subkey(subkey)?;
    
    // Try to parse as u32 first, otherwise write as string
    if let Ok(u32_val) = data.parse::<u32>() {
        key_obj.set_value(value, &u32_val)?;
    } else {
        key_obj.set_value(value, &data)?;
    }

    println!("  ✓ Registry updated: {}\\{} = {}", key, value, data);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn apply_registry_fix(key: &str, value: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Registry fix not supported on this platform: {}\\{} = {}", key, value, data);
    Err("Registry fixes are only supported on Windows".into())
}
