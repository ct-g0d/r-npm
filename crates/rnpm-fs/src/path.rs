use std::path::{Path, PathBuf};

/// Normalizes path separators to Windows backslashes, strips redundant `.` and `..`
/// components lexically, and converts the path to a Windows verbatim path (`\\?\` or `\\?\UNC\`)
/// to overcome the 260-character `MAX_PATH` limitation on Windows NTFS.
///
/// On non-Windows platforms, returns the lexically cleaned path.
pub fn to_verbatim_path(path: &Path) -> PathBuf {
    #[cfg(not(windows))]
    {
        use path_clean::PathClean;
        path.clean()
    }

    #[cfg(windows)]
    {
        let path_str = path.to_string_lossy();
        if path_str.is_empty() {
            return PathBuf::new();
        }

        // If it already has verbatim prefix, just normalize separators
        if path_str.starts_with(r"\\?\") || path_str.starts_with(r"\??\") {
            let normalized = path_str.replace('/', "\\");
            return PathBuf::from(normalized);
        }

        // Make path absolute if relative so verbatim path has a valid root
        let abs_path = if path.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                cwd.join(path)
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        };

        // Normalize all slashes to backslashes
        let abs_str = abs_path.to_string_lossy().replace('/', "\\");

        // Check if UNC path (e.g. \\server\share\...)
        if abs_str.starts_with(r"\\") {
            let unc_tail = &abs_str[2..];
            let cleaned = clean_windows_components(unc_tail);
            PathBuf::from(format!(r"\\?\UNC\{cleaned}"))
        } else {
            let cleaned = clean_windows_components(&abs_str);
            PathBuf::from(format!(r"\\?\{cleaned}"))
        }
    }
}

/// Strips the Windows verbatim prefix (`\\?\` or `\\?\UNC\`) if present.
/// Useful for external tools or child processes that do not support verbatim prefixes.
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else if let Some(stripped) = s.strip_prefix(r"\??\UNC\") {
        PathBuf::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = s.strip_prefix(r"\??\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn clean_windows_components(path_str: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let mut drive_prefix = String::new();

    let work_str = if path_str.len() >= 2 && path_str.as_bytes()[1] == b':' {
        let drive_char = (path_str.as_bytes()[0] as char).to_ascii_uppercase();
        drive_prefix = format!("{drive_char}:");
        &path_str[2..]
    } else {
        path_str
    };

    for part in work_str.split('\\') {
        if part.is_empty() || part == "." {
            continue;
        } else if part == ".." {
            if !parts.is_empty() {
                parts.pop();
            }
        } else {
            parts.push(part);
        }
    }

    if !drive_prefix.is_empty() {
        if parts.is_empty() {
            format!(r"{drive_prefix}\")
        } else {
            format!(r"{drive_prefix}\{}", parts.join("\\"))
        }
    } else {
        parts.join("\\")
    }
}
