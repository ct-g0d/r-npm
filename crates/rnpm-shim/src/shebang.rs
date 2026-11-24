use crate::error::ShimError;
use std::path::Path;

/// Parsed shebang information from a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShebangInfo {
    /// The executable binary (e.g., "node", "sh", "python").
    pub program: String,
    /// Any command line arguments specified in the shebang (e.g., ["--harmony"]).
    pub args: Vec<String>,
}

impl Default for ShebangInfo {
    fn default() -> Self {
        Self {
            program: "node".to_string(),
            args: Vec::new(),
        }
    }
}

/// Normalizes CRLF line endings on the shebang line in raw bytes.
/// Returns the normalized bytes and a boolean indicating if changes were made.
pub fn normalize_shebang_bytes(bytes: &[u8]) -> (Vec<u8>, bool) {
    let clean_bytes = if bytes.starts_with(b"\xEF\xBB\xBF#!") {
        &bytes[3..]
    } else if bytes.starts_with(b"#!") {
        bytes
    } else {
        return (bytes.to_vec(), false);
    };

    let bom_offset = bytes.len() - clean_bytes.len();

    if let Some(newline_pos) = clean_bytes.iter().position(|&b| b == b'\n') {
        if newline_pos > 0 && clean_bytes[newline_pos - 1] == b'\r' {
            let abs_newline_pos = bom_offset + newline_pos;
            let mut result = Vec::with_capacity(bytes.len() - 1);
            result.extend_from_slice(&bytes[..abs_newline_pos - 1]);
            result.push(b'\n');
            result.extend_from_slice(&bytes[abs_newline_pos + 1..]);
            return (result, true);
        }
    }

    (bytes.to_vec(), false)
}

/// Normalizes CRLF line endings on the shebang line in a string.
/// Returns the normalized string and a boolean indicating if changes were made.
pub fn normalize_shebang_str(content: &str) -> (String, bool) {
    let clean = content.strip_prefix('\u{feff}').unwrap_or(content);
    if !clean.starts_with("#!") {
        return (content.to_string(), false);
    }

    if let Some(idx) = content.find('\n') {
        let first_line = &content[..idx];
        if first_line.ends_with('\r') {
            let shebang_trimmed = first_line.trim_end_matches('\r');
            let rest = &content[idx + 1..];
            let mut result = String::with_capacity(content.len());
            result.push_str(shebang_trimmed);
            result.push('\n');
            result.push_str(rest);
            return (result, true);
        }
    }

    (content.to_string(), false)
}

/// Reads the target script file from disk, normalizes any CRLF shebang line,
/// and writes the file back if modified.
/// Reads at most the first 512 bytes first: if it does NOT start with `#!` (or UTF-8 BOM `\xEF\xBB\xBF#!`),
/// returns immediately without reading or rewriting the rest of the file.
/// ONLY reads/rewrites the full file when line 1 actually contains `\r\n`.
/// Returns `Ok(true)` if the file was modified, `Ok(false)` otherwise.
pub fn normalize_shebang_file(file_path: &Path) -> Result<bool, ShimError> {
    use std::io::Read;

    let mut file = match std::fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(ShimError::Io {
                path: file_path.to_path_buf(),
                source: e,
            });
        }
    };

    let mut header = [0u8; 512];
    let n = file.read(&mut header).map_err(|e| ShimError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;
    let header_slice = &header[..n];

    let clean = if header_slice.starts_with(b"\xEF\xBB\xBF#!") {
        &header_slice[3..]
    } else if header_slice.starts_with(b"#!") {
        header_slice
    } else {
        return Ok(false);
    };

    // Check if line 1 contains \r\n
    let has_crlf = if let Some(nl_pos) = clean.iter().position(|&b| b == b'\n') {
        nl_pos > 0 && clean[nl_pos - 1] == b'\r'
    } else if n == 512 {
        // Line 1 is longer than 512 bytes, scan forward until newline
        let mut prev_byte = header_slice[511];
        let mut found_crlf = false;
        let mut byte = [0u8; 1];
        while let Ok(1) = file.read(&mut byte) {
            if byte[0] == b'\n' {
                found_crlf = prev_byte == b'\r';
                break;
            }
            prev_byte = byte[0];
        }
        found_crlf
    } else {
        // Reached EOF before any newline
        false
    };

    if !has_crlf {
        return Ok(false);
    }

    drop(file);

    let bytes = std::fs::read(file_path).map_err(|e| ShimError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;

    let (normalized, changed) = normalize_shebang_bytes(&bytes);
    if changed {
        #[cfg(unix)]
        let mut orig_unix_mode: Option<u32> = None;
        #[cfg(windows)]
        let mut orig_readonly = false;

        if let Ok(metadata) = std::fs::metadata(file_path) {
            let mut perms = metadata.permissions();
            if perms.readonly() {
                #[cfg(windows)]
                {
                    orig_readonly = true;
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(file_path, perms);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = perms.mode();
                    orig_unix_mode = Some(mode);
                    perms.set_mode(mode | 0o200);
                    let _ = std::fs::set_permissions(file_path, perms);
                }
            }
        }
        let write_res = std::fs::write(file_path, &normalized).map_err(|e| ShimError::Io {
            path: file_path.to_path_buf(),
            source: e,
        });
        #[cfg(unix)]
        if let Some(mode) = orig_unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(mode));
        }
        #[cfg(windows)]
        if orig_readonly {
            if let Ok(meta) = std::fs::metadata(file_path) {
                let mut perms = meta.permissions();
                perms.set_readonly(true);
                let _ = std::fs::set_permissions(file_path, perms);
            }
        }
        write_res?;
    }

    Ok(changed)
}

/// Splits a shebang line into tokens respecting quotes and backslash escaping.
pub fn split_shebang_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape = false;

    for c in line.chars() {
        if escape {
            current.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && !in_single_quote {
            escape = true;
            continue;
        }
        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            continue;
        }
        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            continue;
        }
        if c.is_whitespace() && !in_single_quote && !in_double_quote {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parses the shebang line from script content, returning `ShebangInfo` if present.
pub fn parse_shebang(content: &str) -> Option<ShebangInfo> {
    let clean = content.strip_prefix('\u{feff}').unwrap_or(content);
    if !clean.starts_with("#!") {
        return None;
    }

    let first_line = clean.lines().next()?;
    let line = first_line.trim_start_matches("#!").trim();
    if line.is_empty() {
        return None;
    }

    let mut tokens = split_shebang_tokens(line);
    if tokens.is_empty() {
        return None;
    }

    let mut idx = 0;
    // Check if invoked via /usr/bin/env or env
    if tokens[idx].ends_with("/env") || tokens[idx] == "env" {
        idx += 1;
        // Check for -S option in env (e.g., /usr/bin/env -S node --harmony or /usr/bin/env -Snode)
        if idx < tokens.len() {
            if tokens[idx] == "-S" {
                idx += 1;
            } else if let Some(rest) = tokens[idx].strip_prefix("-S") {
                tokens[idx] = rest.to_string();
            }
        }
        // Skip environment variable declarations (e.g. FOO=BAR)
        while idx < tokens.len() && tokens[idx].contains('=') && !tokens[idx].starts_with('-') {
            idx += 1;
        }
    }

    if idx >= tokens.len() {
        return None;
    }

    let raw_prog = &tokens[idx];
    let prog_name = Path::new(raw_prog)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw_prog)
        .to_string();

    let args: Vec<String> = tokens[idx + 1..].iter().map(|s| s.to_string()).collect();

    Some(ShebangInfo {
        program: prog_name,
        args,
    })
}

/// Reads the shebang line from a script file on disk.
/// Reads at most the first 512 bytes first: if it does NOT start with `#!` (or UTF-8 BOM `\xEF\xBB\xBF#!`),
/// returns immediately without reading or allocating for the rest of the file.
pub fn read_shebang_from_file(file_path: &Path) -> Result<Option<ShebangInfo>, ShimError> {
    use std::io::Read;

    let mut file = match std::fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ShimError::Io {
                path: file_path.to_path_buf(),
                source: e,
            });
        }
    };

    let mut header = [0u8; 512];
    let n = file.read(&mut header).map_err(|e| ShimError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;
    let header_slice = &header[..n];

    let clean = if header_slice.starts_with(b"\xEF\xBB\xBF#!") {
        &header_slice[3..]
    } else if header_slice.starts_with(b"#!") {
        header_slice
    } else {
        return Ok(None);
    };

    if let Some(nl_pos) = clean.iter().position(|&b| b == b'\n') {
        let first_line = &clean[..nl_pos];
        let content = String::from_utf8_lossy(first_line);
        return Ok(parse_shebang(&content));
    }

    if n < 512 {
        let content = String::from_utf8_lossy(clean);
        return Ok(parse_shebang(&content));
    }

    // Shebang line exceeds 512 bytes: read remainder of the line
    let mut line_bytes = clean.to_vec();
    let mut byte = [0u8; 1];
    while let Ok(1) = file.read(&mut byte) {
        if byte[0] == b'\n' {
            break;
        }
        line_bytes.push(byte[0]);
    }
    let content = String::from_utf8_lossy(&line_bytes);
    Ok(parse_shebang(&content))
}
