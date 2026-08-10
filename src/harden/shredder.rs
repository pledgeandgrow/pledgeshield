/// Secure file shredder — securely delete files (multi-pass overwrite) so they can't be recovered.
use super::HardenResult;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Securely delete a file by overwriting it multiple times before deletion.
pub fn shred_file(path: &str, passes: u32, dry_run: bool) -> HardenResult {
    let path = Path::new(path);

    if !path.exists() {
        return HardenResult {
            action: "shred".to_string(),
            success: false,
            message: format!("File not found: {}", path.display()),
            findings: vec![],
        };
    }

    if !path.is_file() {
        return HardenResult {
            action: "shred".to_string(),
            success: false,
            message: format!("Not a regular file: {}", path.display()),
            findings: vec![],
        };
    }

    if dry_run {
        return HardenResult {
            action: "shred".to_string(),
            success: true,
            message: format!("[dry-run] Would shred {} with {} passes", path.display(), passes),
            findings: vec![],
        };
    }

    // Get file size
    let size = match fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => return HardenResult {
            action: "shred".to_string(),
            success: false,
            message: format!("Cannot get file size: {}", e),
            findings: vec![],
        },
    };

    // Open file for read/write
    let mut file = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) => return HardenResult {
            action: "shred".to_string(),
            success: false,
            message: format!("Cannot open file: {}", e),
            findings: vec![],
        },
    };

    // Overwrite passes
    for pass in 0..passes {
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            return HardenResult {
                action: "shred".to_string(),
                success: false,
                message: format!("Seek failed: {}", e),
                findings: vec![],
            };
        }

        let pattern: u8 = match pass % 3 {
            0 => 0x00,  // Zeros
            1 => 0xFF,  // Ones
            _ => 0xAA,  // Alternating
        };

        let buffer = vec![pattern; 4096.min(size as usize)];
        let mut written = 0u64;
        while written < size {
            let to_write = (size - written).min(buffer.len() as u64) as usize;
            if let Err(e) = file.write_all(&buffer[..to_write]) {
                return HardenResult {
                    action: "shred".to_string(),
                    success: false,
                    message: format!("Write failed at pass {}: {}", pass + 1, e),
                    findings: vec![],
                };
            }
            written += to_write as u64;
        }
        let _ = file.sync_all();
    }

    // Final pass with random data
    let _ = file.seek(SeekFrom::Start(0));
    let mut rng_state: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42);
    let mut written = 0u64;
    while written < size {
        let to_write = (size - written).min(4096) as usize;
        let mut buf = vec![0u8; to_write];
        for b in &mut buf {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (rng_state >> 33) as u8;
        }
        let _ = file.write_all(&buf);
        written += to_write as u64;
    }
    let _ = file.sync_all();
    drop(file);

    // Rename to random name (to remove metadata from directory entry)
    let dir = path.parent().unwrap_or(Path::new("."));
    let rng_name = format!(".pledgeshield-shred-{}", std::process::id());
    let temp_path = dir.join(&rng_name);
    let _ = fs::rename(path, &temp_path);

    // Delete the file
    match fs::remove_file(&temp_path) {
        Ok(()) => HardenResult {
            action: "shred".to_string(),
            success: true,
            message: format!("Shredded {} ({} passes + random + rename)", path.display(), passes),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "shred".to_string(),
            success: false,
            message: format!("Overwritten but delete failed: {}", e),
            findings: vec![],
        },
    }
}

/// Securely delete a directory and all its contents.
pub fn shred_dir(path: &str, passes: u32, dry_run: bool) -> Vec<HardenResult> {
    let mut results = Vec::new();
    let path = Path::new(path);

    if !path.exists() {
        results.push(HardenResult {
            action: "shred-dir".to_string(),
            success: false,
            message: format!("Directory not found: {}", path.display()),
            findings: vec![],
        });
        return results;
    }

    // Walk and shred all files
    walk_and_shred(path, passes, dry_run, &mut results);

    // Remove the directory structure
    if !dry_run {
        let _ = fs::remove_dir_all(path);
    }

    results
}

fn walk_and_shred(dir: &Path, passes: u32, dry_run: bool, results: &mut Vec<HardenResult>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_and_shred(&path, passes, dry_run, results);
            } else if path.is_file() {
                results.push(shred_file(&path.to_string_lossy(), passes, dry_run));
            }
        }
    }
}
