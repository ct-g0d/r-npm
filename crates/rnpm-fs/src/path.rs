#[cfg(windows)]
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[cfg(windows)]
#[inline]
fn is_clean_windows_tail_ascii(bytes: &[u8]) -> Option<bool> {
    let len = bytes.len();
    if len == 0 {
        return Some(true);
    }
    if bytes == b"."
        || bytes.starts_with(br".\")
        || bytes.starts_with(b"\\")
        || bytes.ends_with(br"\.")
        || bytes.ends_with(b"\\")
    {
        return None;
    }
    let mut all_ascii = true;
    let mut i = 0;
    while i < len {
        let b = bytes[i];
        if b >= 0x80 {
            all_ascii = false;
        }
        if b == b'/' {
            return None;
        }
        if b == b'\\' && i + 1 < len {
            let next = bytes[i + 1];
            if next == b'\\' {
                return None;
            }
            if next == b'.' && i + 2 < len && bytes[i + 2] == b'\\' {
                return None;
            }
        }
        if b == b'.' && i + 1 < len && bytes[i + 1] == b'.' {
            return None;
        }
        i += 1;
    }
    Some(all_ascii)
}

#[cfg(windows)]
#[inline]
pub(crate) fn is_clean_already_verbatim(bytes: &[u8]) -> bool {
    if !(bytes.starts_with(br"\\?\") || bytes.starts_with(br"\??\")) {
        return false;
    }
    is_clean_windows_tail_ascii(&bytes[4..]).is_some()
}

#[cfg(windows)]
#[inline]
pub(crate) fn is_clean_drive_abs(bytes: &[u8]) -> bool {
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && is_clean_windows_tail_ascii(&bytes[3..]).is_some()
}

/// Encodes `path` as a null-terminated Windows verbatim UTF-16 path into `buf`,
/// avoiding intermediate `String`/`PathBuf` allocations on clean paths.
#[cfg(windows)]
pub(crate) fn encode_verbatim_wide(path: &Path, buf: &mut Vec<u16>) {
    use std::os::windows::ffi::OsStrExt;
    buf.clear();
    let os = path.as_os_str();
    let bytes = os.as_encoded_bytes();
    if bytes.is_empty() {
        buf.push(0);
        return;
    }
    if bytes.starts_with(br"\\?\") || bytes.starts_with(br"\??\") {
        if let Some(all_ascii) = is_clean_windows_tail_ascii(&bytes[4..]) {
            if all_ascii {
                buf.reserve(bytes.len() + 1);
                for &b in bytes {
                    buf.push(b as u16);
                }
                buf.push(0);
            } else {
                buf.extend(os.encode_wide());
                buf.push(0);
            }
            return;
        }
    }
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        if let Some(all_ascii) = is_clean_windows_tail_ascii(&bytes[3..]) {
            if all_ascii {
                buf.reserve(bytes.len() + 5);
                buf.extend_from_slice(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]);
                for &b in bytes {
                    buf.push(b as u16);
                }
                buf.push(0);
            } else {
                buf.extend_from_slice(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]);
                buf.extend(os.encode_wide());
                buf.push(0);
            }
            return;
        }
    }
    let verb = to_verbatim_path(path);
    buf.extend(verb.as_os_str().encode_wide());
    buf.push(0);
}

/// Invokes `f` with a null-terminated Windows verbatim UTF-16 slice for `path`.
/// Uses a stack buffer for short clean paths so common operations allocate zero heap memory.
#[cfg(windows)]
#[inline]
pub(crate) fn with_verbatim_wide<R>(path: &Path, f: impl FnOnce(&[u16]) -> R) -> R {
    use std::os::windows::ffi::OsStrExt;
    let os = path.as_os_str();
    let bytes = os.as_encoded_bytes();
    const STACK_CAP: usize = 384;

    if !bytes.is_empty() && bytes.len() + 6 <= STACK_CAP {
        if is_clean_already_verbatim(bytes) {
            let mut stack = [0u16; STACK_CAP];
            let mut n = 0;
            for ch in os.encode_wide() {
                stack[n] = ch;
                n += 1;
            }
            stack[n] = 0;
            return f(&stack[..=n]);
        }
        if is_clean_drive_abs(bytes) {
            let mut stack = [0u16; STACK_CAP];
            stack[0] = b'\\' as u16;
            stack[1] = b'\\' as u16;
            stack[2] = b'?' as u16;
            stack[3] = b'\\' as u16;
            let mut n = 4;
            for ch in os.encode_wide() {
                stack[n] = ch;
                n += 1;
            }
            stack[n] = 0;
            return f(&stack[..=n]);
        }
    }

    let mut vec = Vec::with_capacity(bytes.len() + 8);
    encode_verbatim_wide(path, &mut vec);
    f(&vec)
}

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
        let os = path.as_os_str();
        let bytes = os.as_encoded_bytes();
        if bytes.is_empty() {
            return PathBuf::new();
        }

        // Fast path: already verbatim and clean
        if is_clean_already_verbatim(bytes) {
            return path.to_path_buf();
        }

        // Fast path: clean absolute drive path (e.g. C:\foo\bar)
        if is_clean_drive_abs(bytes) {
            let mut out = OsString::with_capacity(4 + bytes.len());
            out.push(OsStr::new(r"\\?\"));
            out.push(os);
            return PathBuf::from(out);
        }

        let path_str = path.to_string_lossy();
        if path_str.starts_with(r"\\?\") || path_str.starts_with(r"\??\") {
            let normalized = path_str.replace('/', "\\");
            if normalized.starts_with(r"\\?\UNC\") || normalized.starts_with(r"\??\UNC\") {
                let unc_tail = &normalized[8..];
                let cleaned = clean_windows_components(unc_tail, 2);
                return PathBuf::from(format!(r"\\?\UNC\{cleaned}"));
            } else {
                let tail = &normalized[4..];
                let min_preserve = usize::from(!(tail.len() >= 2 && tail.as_bytes()[1] == b':'));
                let cleaned = clean_windows_components(tail, min_preserve);
                return PathBuf::from(format!(r"\\?\{cleaned}"));
            }
        }

        // Make path absolute if relative so verbatim path has a valid root
        let abs_path = if path.is_relative() || !path.has_root() {
            std::path::absolute(path).unwrap_or_else(|_| {
                if let Ok(cwd) = std::env::current_dir() {
                    cwd.join(path)
                } else {
                    path.to_path_buf()
                }
            })
        } else {
            path.to_path_buf()
        };

        // Normalize all slashes to backslashes
        let abs_str = abs_path.to_string_lossy().replace('/', "\\");

        // Check if UNC path (e.g. \\server\share\...)
        if let Some(unc_tail) = abs_str.strip_prefix(r"\\") {
            let cleaned = clean_windows_components(unc_tail, 2);
            PathBuf::from(format!(r"\\?\UNC\{cleaned}"))
        } else {
            let cleaned = clean_windows_components(&abs_str, 0);
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
fn clean_windows_components(path_str: &str, min_preserve: usize) -> String {
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
            if parts.len() > min_preserve {
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
