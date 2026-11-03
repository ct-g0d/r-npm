use std::path::Path;
use crate::error::ShimError;

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
/// Returns `Ok(true)` if the file was modified, `Ok(false)` otherwise.
pub fn normalize_shebang_file(file_path: &Path) -> Result<bool, ShimError> {
    if !file_path.exists() {
        return Ok(false);
    }

    let bytes = std::fs::read(file_path).map_err(|e| ShimError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;

    let (normalized, changed) = normalize_shebang_bytes(&bytes);
    if changed {
        std::fs::write(file_path, &normalized).map_err(|e| ShimError::Io {
            path: file_path.to_path_buf(),
            source: e,
        })?;
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

    let tokens = split_shebang_tokens(line);
    if tokens.is_empty() {
        return None;
    }

    let mut idx = 0;
    // Check if invoked via /usr/bin/env or env
    if tokens[idx].ends_with("/env") || tokens[idx] == "env" {
        idx += 1;
        // Check for -S option in env (e.g., /usr/bin/env -S node --harmony)
        if idx < tokens.len() && tokens[idx] == "-S" {
            idx += 1;
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

    let args: Vec<String> = tokens[idx + 1..]
        .iter()
        .map(|s| s.to_string())
        .collect();

    Some(ShebangInfo {
        program: prog_name,
        args,
    })
}

/// Reads the shebang line from a script file on disk.
pub fn read_shebang_from_file(file_path: &Path) -> Result<Option<ShebangInfo>, ShimError> {
    if !file_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(file_path).map_err(|e| ShimError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;

    Ok(parse_shebang(&content))
}
