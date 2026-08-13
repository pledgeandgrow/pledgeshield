/// Metadata stripper — strip EXIF/metadata from files (photos, documents) before sharing.
use super::HardenResult;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Strip metadata from a file. Supports JPEG, PNG, TIFF, PDF.
pub fn strip_metadata(path: &str, output: Option<&str>, dry_run: bool) -> HardenResult {
    let path = Path::new(path);

    if !path.exists() {
        return HardenResult {
            action: "metadata-strip".to_string(),
            success: false,
            message: format!("File not found: {}", path.display()),
            findings: vec![],
        };
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let output_path = output.map(String::from).unwrap_or_else(|| {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let parent = path.parent().unwrap_or(Path::new("."));
        parent
            .join(format!("{}_clean.{}", stem, ext))
            .to_string_lossy()
            .to_string()
    });

    if dry_run {
        return HardenResult {
            action: "metadata-strip".to_string(),
            success: true,
            message: format!(
                "[dry-run] Would strip metadata from {} -> {}",
                path.display(),
                output_path
            ),
            findings: vec![],
        };
    }

    let content = match fs::read(path) {
        Ok(c) => c,
        Err(e) => {
            return HardenResult {
                action: "metadata-strip".to_string(),
                success: false,
                message: format!("Cannot read file: {}", e),
                findings: vec![],
            };
        }
    };

    let cleaned = match ext.as_str() {
        "jpg" | "jpeg" => strip_jpeg_metadata(&content),
        "png" => strip_png_metadata(&content),
        "pdf" => strip_pdf_metadata(&content),
        _ => {
            // For unknown types, try exiftool if available
            return strip_with_exiftool(path, &output_path);
        }
    };

    match fs::File::create(&output_path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&cleaned) {
                return HardenResult {
                    action: "metadata-strip".to_string(),
                    success: false,
                    message: format!("Write failed: {}", e),
                    findings: vec![],
                };
            }
            let original_size = content.len();
            let new_size = cleaned.len();
            let removed = original_size.saturating_sub(new_size);
            HardenResult {
                action: "metadata-strip".to_string(),
                success: true,
                message: format!(
                    "Stripped {} bytes of metadata. Output: {}",
                    removed, output_path
                ),
                findings: vec![],
            }
        }
        Err(e) => HardenResult {
            action: "metadata-strip".to_string(),
            success: false,
            message: format!("Cannot create output file: {}", e),
            findings: vec![],
        },
    }
}

/// Strip JPEG metadata: remove EXIF, IPTC, XMP, and comments.
/// Keeps the image data and required markers.
fn strip_jpeg_metadata(data: &[u8]) -> Vec<u8> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return data.to_vec(); // Not a JPEG
    }

    let mut output = Vec::new();
    output.push(0xFF);
    output.push(0xD8); // SOI

    let mut i = 2;
    while i < data.len() - 1 {
        if data[i] != 0xFF {
            output.push(data[i]);
            i += 1;
            continue;
        }

        let marker = data[i + 1];

        // Skip these markers (metadata):
        // 0xE0-0xEF = APP0-APP15 (EXIF, IPTC, XMP, etc.)
        // 0xFE = COM (comment)
        // 0xDD = DQT? No, that's quantization table — keep it
        if (0xE0..=0xEF).contains(&marker) || marker == 0xFE {
            // Skip this marker and its data
            if i + 3 < data.len() {
                let len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
                i += 2 + len;
            } else {
                i += 2;
            }
        } else {
            // Keep this marker
            output.push(0xFF);
            output.push(marker);
            i += 2;

            // For markers with length fields, copy the data
            if marker != 0xDA
                && marker != 0xD9
                && marker != 0x01
                && (0xD0..=0xD7).contains(&marker) == false
            {
                if i + 1 < data.len() {
                    let len = ((data[i] as usize) << 8) | (data[i + 1] as usize);
                    output.extend_from_slice(&data[i..i + len]);
                    i += len;
                }
            } else if marker == 0xDA {
                // SOS — copy until EOI
                if i + 1 < data.len() {
                    let _len = ((data[i] as usize) << 8) | (data[i + 1] as usize);
                    output.extend_from_slice(&data[i..]);
                    i = data.len();
                }
            }
        }
    }

    output
}

/// Strip PNG metadata: remove tEXt, iTXt, zTXt, eXIf chunks.
fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    if data.len() < 8 || &data[0..8] != b"\x89PNG\r\n\x1a\n" {
        return data.to_vec(); // Not a PNG
    }

    let mut output = Vec::new();
    output.extend_from_slice(&data[0..8]); // PNG signature

    let mut i = 8;
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let chunk_type = &data[i + 4..i + 8];

        if i + 12 + len > data.len() {
            break;
        }

        // Skip metadata chunks
        let skip = matches!(
            chunk_type,
            b"tEXt" | b"iTXt" | b"zTXt" | b"eXIf" | b"tIME" | b"iCCP" | b"sTER"
        );

        if !skip {
            output.extend_from_slice(&data[i..i + 12 + len]);
        }

        i += 12 + len; // length + type + data + CRC
    }

    output
}

/// Strip PDF metadata: remove /Info dictionary references.
fn strip_pdf_metadata(data: &[u8]) -> Vec<u8> {
    // Simple approach: remove /Title, /Author, /Subject, /Keywords, /Creator, /Producer, /CreationDate, /ModDate
    let content = String::from_utf8_lossy(data);
    let mut cleaned = content.to_string();

    let patterns = [
        "/Title",
        "/Author",
        "/Subject",
        "/Keywords",
        "/Creator",
        "/Producer",
        "/CreationDate",
        "/ModDate",
    ];

    for pattern in &patterns {
        while let Some(idx) = cleaned.find(pattern) {
            // Find the end of the value (either next / or > or end of dict)
            let rest = &cleaned[idx..];
            if let Some(end) = rest[1..].find('/') {
                cleaned.replace_range(idx..idx + end + 1, "");
            } else if let Some(end) = rest.find('>') {
                cleaned.replace_range(idx..end + idx + 1, "");
            } else {
                break;
            }
        }
    }

    cleaned.into_bytes()
}

/// Fallback: use exiftool if installed.
fn strip_with_exiftool(path: &Path, output: &str) -> HardenResult {
    let installed = std::process::Command::new("which")
        .arg("exiftool")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !installed {
        return HardenResult {
            action: "metadata-strip".to_string(),
            success: false,
            message: "Cannot strip metadata for this file type. Install exiftool: sudo apt install libimage-exiftool-perl".to_string(),
            findings: vec![],
        };
    }

    let out = std::process::Command::new("exiftool")
        .args(["-all=", "-o", output, path.to_str().unwrap_or("")])
        .output();

    match out {
        Ok(o) if o.status.success() => HardenResult {
            action: "metadata-strip".to_string(),
            success: true,
            message: format!("Stripped metadata via exiftool. Output: {}", output),
            findings: vec![],
        },
        Ok(o) => HardenResult {
            action: "metadata-strip".to_string(),
            success: false,
            message: format!("exiftool failed: {}", String::from_utf8_lossy(&o.stderr)),
            findings: vec![],
        },
        Err(e) => HardenResult {
            action: "metadata-strip".to_string(),
            success: false,
            message: format!("exiftool error: {}", e),
            findings: vec![],
        },
    }
}

/// List metadata in a file (without stripping).
pub fn list_metadata(path: &str) -> Vec<String> {
    let mut info = Vec::new();
    let path = Path::new(path);

    if let Ok(content) = fs::read(path) {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" => {
                info.extend(list_jpeg_metadata(&content));
            }
            "png" => {
                info.extend(list_png_metadata(&content));
            }
            _ => {
                info.push("Use exiftool for detailed metadata listing.".to_string());
            }
        }
    }

    info
}

fn list_jpeg_metadata(data: &[u8]) -> Vec<String> {
    let mut info = Vec::new();
    let mut i = 2;
    while i < data.len() - 1 {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        if (0xE0..=0xEF).contains(&marker) {
            let names = [
                "APP0 (JFIF)",
                "APP1 (EXIF/XMP)",
                "APP2",
                "APP3",
                "APP4",
                "APP5",
                "APP6",
                "APP7",
                "APP8",
                "APP9",
                "APP10",
                "APP11 (IPTC)",
                "APP13",
                "APP14",
                "APP15",
            ];
            let name = names.get((marker - 0xE0) as usize).unwrap_or(&"APP?");
            info.push(format!("  0x{:02X}: {}", marker, name));
        }
        if marker == 0xFE {
            info.push("  0xFE: Comment".to_string());
        }
        if i + 3 < data.len() {
            let len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
            i += 2 + len;
        } else {
            i += 2;
        }
    }
    info
}

fn list_png_metadata(data: &[u8]) -> Vec<String> {
    let mut info = Vec::new();
    let mut i = 8;
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let chunk_type = String::from_utf8_lossy(&data[i + 4..i + 8]).to_string();
        info.push(format!("  {} ({} bytes)", chunk_type, len));
        if i + 12 + len > data.len() {
            break;
        }
        i += 12 + len;
    }
    info
}
