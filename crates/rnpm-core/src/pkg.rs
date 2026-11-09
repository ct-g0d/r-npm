use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::manifest::{Manifest, ManifestFormat};

/// Represents a single segment in a package manifest property path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// Object property key (e.g. `scripts`, `@scope/pkg`).
    Key(String),
    /// Array index or numeric key (e.g. `0`).
    Index(usize),
    /// Append to an array (from empty brackets `[]`).
    Append,
}

/// Parses a property path string into a sequence of [`PathSegment`]s.
///
/// Supports:
/// - Dot notation: `scripts.build`, `author.name`, `name`
/// - Bracket notation with double or single quotes: `dependencies["@scope/pkg"]`, `dependencies['react']`
/// - Bracket notation with array indices or unquoted keys: `keywords[0]`, `workspaces[0]`
/// - Append notation: `keywords[]`, `workspaces[]`
/// - Compound / nested paths: `scripts["test:unit"]`, `workspaces[0].packages`, `matrix[0][1]`
pub fn parse_path(path: &str) -> Result<Vec<PathSegment>> {
    let s = path.trim();
    if s.is_empty() {
        bail!("Field path cannot be empty");
    }

    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut segments = Vec::new();
    let mut i = 0;

    // Allow leading dot if not immediately followed by another dot or end of string
    if chars[0] == '.' {
        i += 1;
        if i >= len {
            bail!("Invalid field path: '{}'", path);
        }
        if chars[i] == '.' {
            bail!("Consecutive dots in path expression: '{}'", path);
        }
    }

    while i < len {
        // Skip leading whitespace between tokens
        while i < len && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }

        if chars[i] == '.' {
            i += 1;
            while i < len && chars[i].is_whitespace() {
                i += 1;
            }
            if i >= len {
                bail!("Trailing dot in path expression: '{}'", path);
            }
            if chars[i] == '.' {
                bail!("Consecutive dots in path expression: '{}'", path);
            }
        } else if chars[i] == '[' {
            i += 1; // consume '['
            while i < len && chars[i].is_whitespace() {
                i += 1;
            }
            if i >= len {
                bail!("Unclosed bracket in path expression: '{}'", path);
            }

            if chars[i] == '"' || chars[i] == '\'' {
                let quote = chars[i];
                i += 1; // consume opening quote
                let mut key = String::new();
                let mut closed = false;

                while i < len {
                    let c = chars[i];
                    if c == '\\' {
                        i += 1;
                        if i >= len {
                            bail!("Dangling backslash in path expression: '{}'", path);
                        }
                        match chars[i] {
                            'n' => key.push('\n'),
                            't' => key.push('\t'),
                            'r' => key.push('\r'),
                            '\\' => key.push('\\'),
                            '\'' => key.push('\''),
                            '"' => key.push('"'),
                            other => {
                                key.push('\\');
                                key.push(other);
                            }
                        }
                        i += 1;
                    } else if c == quote {
                        closed = true;
                        i += 1; // consume closing quote
                        break;
                    } else {
                        key.push(c);
                        i += 1;
                    }
                }

                if !closed {
                    bail!("Unclosed quote {} in path expression: '{}'", quote, path);
                }

                while i < len && chars[i].is_whitespace() {
                    i += 1;
                }
                if i >= len || chars[i] != ']' {
                    bail!(
                        "Expected ']' after quoted string in path expression: '{}'",
                        path
                    );
                }
                i += 1; // consume ']'
                segments.push(PathSegment::Key(key));
            } else {
                let mut content = String::new();
                let mut closed = false;

                while i < len {
                    if chars[i] == ']' {
                        closed = true;
                        i += 1; // consume ']'
                        break;
                    }
                    content.push(chars[i]);
                    i += 1;
                }

                if !closed {
                    bail!("Unclosed bracket in path expression: '{}'", path);
                }

                let trimmed = content.trim();
                if trimmed.is_empty() {
                    segments.push(PathSegment::Append);
                } else if let Ok(idx) = trimmed.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                } else {
                    segments.push(PathSegment::Key(trimmed.to_string()));
                }
            }

            // After ']', verify next character is valid separator ('.', '[', whitespace, or end of string)
            while i < len && chars[i].is_whitespace() {
                i += 1;
            }
            if i < len && chars[i] != '.' && chars[i] != '[' {
                bail!(
                    "Expected '.' or '[' after ']' in path expression: '{}', found '{}'",
                    path,
                    chars[i]
                );
            }
        } else {
            let mut key = String::new();
            while i < len && chars[i] != '.' && chars[i] != '[' && !chars[i].is_whitespace() {
                key.push(chars[i]);
                i += 1;
            }
            let key = key.trim();
            if key.is_empty() {
                bail!("Empty key segment in path expression: '{}'", path);
            }
            segments.push(PathSegment::Key(key.to_string()));
        }
    }

    if segments.is_empty() {
        bail!("No valid segments in path expression: '{}'", path);
    }

    Ok(segments)
}

/// Traverses a JSON [`Value`] using the provided [`PathSegment`]s.
///
/// Returns `Some(&Value)` if the path exists, or `None` if any segment cannot be resolved.
pub fn get_value_at_path<'a>(root: &'a Value, segments: &[PathSegment]) -> Option<&'a Value> {
    if segments.is_empty() {
        return Some(root);
    }
    let mut curr = root;
    for segment in segments {
        match curr {
            Value::Object(map) => match segment {
                PathSegment::Key(key) => {
                    curr = map.get(key)?;
                }
                PathSegment::Index(idx) => {
                    let key_str = idx.to_string();
                    curr = map.get(&key_str)?;
                }
                PathSegment::Append => return None,
            },
            Value::Array(arr) => match segment {
                PathSegment::Index(idx) => {
                    curr = arr.get(*idx)?;
                }
                PathSegment::Key(key) => {
                    if let Ok(idx) = key.parse::<usize>() {
                        curr = arr.get(idx)?;
                    } else {
                        return None;
                    }
                }
                PathSegment::Append => return None,
            },
            _ => return None,
        }
    }
    Some(curr)
}

/// Coerces a raw value string into a [`serde_json::Value`] according to npm coercion rules:
/// - `"true"` -> `Value::Bool(true)`
/// - `"false"` -> `Value::Bool(false)`
/// - `"null"` -> `Value::Null`
/// - Valid number string (e.g. `"42"`, `"3.14"`) -> `Value::Number`
/// - Valid JSON object/array string (starts with `{` or `[`) -> parsed JSON via `serde_json::from_str`
/// - Otherwise -> `Value::String(value)`
pub fn coerce_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed == "true" {
        Value::Bool(true)
    } else if trimmed == "false" {
        Value::Bool(false)
    } else if trimmed == "null" {
        Value::Null
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            parsed
        } else {
            Value::String(raw.to_string())
        }
    } else if let Ok(num) = serde_json::from_str::<serde_json::Number>(trimmed) {
        Value::Number(num)
    } else {
        Value::String(raw.to_string())
    }
}

/// Navigates `root` along `segments`, creating intermediate `Value::Object` (or `Value::Array`)
/// containers if absent, and assigns `value` to the leaf segment.
pub fn set_value(root: &mut Value, segments: &[PathSegment], value: Value) -> Result<()> {
    if segments.is_empty() {
        bail!("Path cannot be empty");
    }

    if !root.is_object() {
        *root = Value::Object(serde_json::Map::new());
    }

    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        let is_leaf = i == segments.len() - 1;

        if is_leaf {
            match segment {
                PathSegment::Key(key) => match current {
                    Value::Object(map) => {
                        map.insert(key.clone(), value);
                    }
                    Value::Array(arr) => {
                        if let Ok(idx) = key.parse::<usize>() {
                            if idx < arr.len() {
                                arr[idx] = value;
                            } else {
                                while arr.len() < idx {
                                    arr.push(Value::Null);
                                }
                                arr.push(value);
                            }
                        } else {
                            bail!("Cannot set named property '{}' on array", key);
                        }
                    }
                    _ => {
                        let mut map = serde_json::Map::new();
                        map.insert(key.clone(), value);
                        *current = Value::Object(map);
                    }
                },
                PathSegment::Index(idx) => {
                    let idx = *idx;
                    match current {
                        Value::Array(arr) => {
                            if idx < arr.len() {
                                arr[idx] = value;
                            } else {
                                while arr.len() < idx {
                                    arr.push(Value::Null);
                                }
                                arr.push(value);
                            }
                        }
                        Value::Object(map) => {
                            map.insert(idx.to_string(), value);
                        }
                        _ => {
                            let mut arr = Vec::new();
                            while arr.len() < idx {
                                arr.push(Value::Null);
                            }
                            arr.push(value);
                            *current = Value::Array(arr);
                        }
                    }
                }
                PathSegment::Append => match current {
                    Value::Array(arr) => {
                        arr.push(value);
                    }
                    _ => {
                        *current = Value::Array(vec![value]);
                    }
                },
            }
            return Ok(());
        }

        // Intermediate segment
        let next_is_array = matches!(
            &segments[i + 1],
            PathSegment::Index(_) | PathSegment::Append
        );

        match segment {
            PathSegment::Key(key) => match current {
                Value::Object(map) => {
                    let needs_new_container = match map.get(key) {
                        None => true,
                        Some(Value::Null) => true,
                        Some(Value::Object(_)) => false,
                        Some(Value::Array(_)) => false,
                        Some(_) => true,
                    };
                    if needs_new_container {
                        let new_container = if next_is_array {
                            Value::Array(Vec::new())
                        } else {
                            Value::Object(serde_json::Map::new())
                        };
                        map.insert(key.clone(), new_container);
                    }
                    current = map.get_mut(key).unwrap();
                }
                Value::Array(arr) => {
                    let idx = key.parse::<usize>().map_err(|_| {
                        anyhow!("Cannot navigate named property '{}' on array", key)
                    })?;
                    while arr.len() <= idx {
                        arr.push(Value::Null);
                    }
                    let is_container = matches!(arr[idx], Value::Object(_) | Value::Array(_));
                    if !is_container {
                        arr[idx] = if next_is_array {
                            Value::Array(Vec::new())
                        } else {
                            Value::Object(serde_json::Map::new())
                        };
                    }
                    current = &mut arr[idx];
                }
                _ => {
                    let mut map = serde_json::Map::new();
                    let new_container = if next_is_array {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(serde_json::Map::new())
                    };
                    map.insert(key.clone(), new_container);
                    *current = Value::Object(map);
                    if let Value::Object(m) = current {
                        current = m.get_mut(key).unwrap();
                    }
                }
            },
            PathSegment::Index(idx) => {
                let idx = *idx;
                match current {
                    Value::Array(arr) => {
                        while arr.len() <= idx {
                            arr.push(Value::Null);
                        }
                        let is_container = matches!(arr[idx], Value::Object(_) | Value::Array(_));
                        if !is_container {
                            arr[idx] = if next_is_array {
                                Value::Array(Vec::new())
                            } else {
                                Value::Object(serde_json::Map::new())
                            };
                        }
                        current = &mut arr[idx];
                    }
                    Value::Object(map) => {
                        let key = idx.to_string();
                        let needs_new_container = match map.get(&key) {
                            None => true,
                            Some(Value::Null) => true,
                            Some(Value::Object(_)) => false,
                            Some(Value::Array(_)) => false,
                            Some(_) => true,
                        };
                        if needs_new_container {
                            let new_container = if next_is_array {
                                Value::Array(Vec::new())
                            } else {
                                Value::Object(serde_json::Map::new())
                            };
                            map.insert(key.clone(), new_container);
                        }
                        current = map.get_mut(&key).unwrap();
                    }
                    _ => {
                        let mut arr = Vec::new();
                        while arr.len() <= idx {
                            arr.push(Value::Null);
                        }
                        arr[idx] = if next_is_array {
                            Value::Array(Vec::new())
                        } else {
                            Value::Object(serde_json::Map::new())
                        };
                        *current = Value::Array(arr);
                        if let Value::Array(a) = current {
                            current = &mut a[idx];
                        }
                    }
                }
            }
            PathSegment::Append => match current {
                Value::Array(arr) => {
                    let new_container = if next_is_array {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(serde_json::Map::new())
                    };
                    arr.push(new_container);
                    current = arr.last_mut().unwrap();
                }
                _ => {
                    let new_container = if next_is_array {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(serde_json::Map::new())
                    };
                    *current = Value::Array(vec![new_container]);
                    if let Value::Array(a) = current {
                        current = a.last_mut().unwrap();
                    }
                }
            },
        }
    }

    Ok(())
}

/// Navigates `root` along `segments` and removes the leaf property or array element.
pub fn delete_value(root: &mut Value, segments: &[PathSegment]) {
    if segments.is_empty() {
        return;
    }

    if segments.len() == 1 {
        match &segments[0] {
            PathSegment::Key(key) => {
                if let Value::Object(map) = root {
                    map.remove(key);
                }
            }
            PathSegment::Index(idx) => {
                if let Value::Array(arr) = root {
                    if *idx < arr.len() {
                        arr.remove(*idx);
                    }
                } else if let Value::Object(map) = root {
                    map.remove(&idx.to_string());
                }
            }
            PathSegment::Append => {}
        }
        return;
    }

    // Multiple segments: navigate down to the parent of the leaf segment
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        match segment {
            PathSegment::Key(key) => match current {
                Value::Object(map) => {
                    if let Some(next) = map.get_mut(key) {
                        current = next;
                    } else {
                        return;
                    }
                }
                Value::Array(arr) => {
                    if let Ok(idx) = key.parse::<usize>() {
                        if idx < arr.len() {
                            current = &mut arr[idx];
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                }
                _ => return,
            },
            PathSegment::Index(idx) => {
                let idx = *idx;
                match current {
                    Value::Array(arr) => {
                        if idx < arr.len() {
                            current = &mut arr[idx];
                        } else {
                            return;
                        }
                    }
                    Value::Object(map) => {
                        let key = idx.to_string();
                        if let Some(next) = map.get_mut(&key) {
                            current = next;
                        } else {
                            return;
                        }
                    }
                    _ => return,
                }
            }
            PathSegment::Append => return,
        }
    }

    // Remove the leaf from `current`
    let leaf = &segments[segments.len() - 1];
    match leaf {
        PathSegment::Key(key) => match current {
            Value::Object(map) => {
                map.remove(key);
            }
            Value::Array(arr) => {
                if let Ok(idx) = key.parse::<usize>() {
                    if idx < arr.len() {
                        arr.remove(idx);
                    }
                }
            }
            _ => {}
        },
        PathSegment::Index(idx) => {
            let idx = *idx;
            match current {
                Value::Array(arr) => {
                    if idx < arr.len() {
                        arr.remove(idx);
                    }
                }
                Value::Object(map) => {
                    map.remove(&idx.to_string());
                }
                _ => {}
            }
        }
        PathSegment::Append => {}
    }
}

/// Resolves the file path of a `package.json` given a file or directory path.
pub fn resolve_manifest_path(manifest_path: &Path) -> PathBuf {
    if manifest_path.is_file() {
        manifest_path.to_path_buf()
    } else if manifest_path.is_dir() {
        manifest_path.join("package.json")
    } else if manifest_path
        .file_name()
        .is_some_and(|f| f == "package.json")
    {
        manifest_path.to_path_buf()
    } else {
        let candidate = manifest_path.join("package.json");
        if candidate.exists() {
            candidate
        } else {
            manifest_path.to_path_buf()
        }
    }
}

/// Accesses and extracts properties from a `package.json` manifest.
///
/// - If `field_paths` is empty, returns entire `package.json` formatted as JSON.
/// - If single field:
///   - If resolved value is a primitive string and `json` is `false`, returns raw string (without quotes).
///   - Otherwise, returns resolved value formatted as pretty-printed JSON.
///   - If the field does not exist, returns `{}`.
/// - If multiple fields:
///   - Returns a JSON object with `{ field_path: resolved_value, ... }` formatted as pretty-printed JSON.
pub fn pkg_get(manifest_path: &Path, field_paths: &[String], json: bool) -> Result<String> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "Failed to read package manifest at '{}'",
            resolved_path.display()
        )
    })?;
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);

    let manifest_val: Value = serde_json::from_str(clean_str).with_context(|| {
        format!(
            "Failed to parse JSON in package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    if field_paths.is_empty() {
        return Ok(serde_json::to_string_pretty(&manifest_val)?);
    }

    if field_paths.len() == 1 {
        let path_str = &field_paths[0];
        let segments = parse_path(path_str)?;
        let value = match get_value_at_path(&manifest_val, &segments) {
            Some(v) => v,
            None => return Ok("{}".to_string()),
        };

        if let Value::String(s) = value {
            if !json {
                return Ok(s.clone());
            }
        }
        return Ok(serde_json::to_string_pretty(value)?);
    }

    let mut result_map = serde_json::Map::new();
    for path_str in field_paths {
        let segments = parse_path(path_str)?;
        if let Some(value) = get_value_at_path(&manifest_val, &segments) {
            result_map.insert(path_str.clone(), value.clone());
        }
    }

    Ok(serde_json::to_string_pretty(&Value::Object(result_map))?)
}

/// Retrieves package manifest values as a [`serde_json::Value`].
///
/// - If `field_paths` is empty: returns the full manifest value.
/// - If single field: returns that field's value or `{}` if not found.
/// - If multiple fields: returns a JSON object `{ field: value, ... }` of found fields.
pub fn pkg_get_value(manifest_path: &Path, field_paths: &[String]) -> Result<Value> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "Failed to read package manifest at '{}'",
            resolved_path.display()
        )
    })?;
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);

    let manifest_val: Value = serde_json::from_str(clean_str).with_context(|| {
        format!(
            "Failed to parse JSON in package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    if field_paths.is_empty() {
        return Ok(manifest_val);
    }

    if field_paths.len() == 1 {
        let path_str = &field_paths[0];
        let segments = parse_path(path_str)?;
        let val = get_value_at_path(&manifest_val, &segments)
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        return Ok(val);
    }

    let mut result_map = serde_json::Map::new();
    for path_str in field_paths {
        let segments = parse_path(path_str)?;
        if let Some(value) = get_value_at_path(&manifest_val, &segments) {
            result_map.insert(path_str.clone(), value.clone());
        }
    }

    Ok(Value::Object(result_map))
}

/// Retrieves properties across workspace members formatted as pretty-printed JSON:
/// `{ "<workspace-name>": <extracted-value>, ... }`.
pub fn pkg_get_workspaces(members: &[(&str, &Path)], field_paths: &[String]) -> Result<String> {
    let mut root_map = serde_json::Map::new();
    for (name, path) in members {
        let val = pkg_get_value(path, field_paths)?;
        root_map.insert((*name).to_string(), val);
    }
    Ok(serde_json::to_string_pretty(&Value::Object(root_map))?)
}

/// Sets properties in `package.json` at `manifest_path` based on `<path>=<value>` assignments.
///
/// Intermediate `Value::Object` (or `Value::Array`) containers are created automatically
/// if absent. Values are coerced according to npm rules. The resulting JSON is persisted
/// with 2 spaces indentation and a trailing newline (`\n`).
pub fn pkg_set(manifest_path: &Path, assignments: &[String]) -> Result<()> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).map_err(|e| {
        anyhow!(
            "Failed to read manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);
    let mut root: Value = serde_json::from_str(clean_str).map_err(|e| {
        anyhow!(
            "Failed to parse JSON in manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;

    if !root.is_object() {
        root = Value::Object(serde_json::Map::new());
    }

    for assignment in assignments {
        let (path_str, raw_val) = assignment.split_once('=').ok_or_else(|| {
            anyhow!(
                "Invalid assignment '{}': expected <path>=<value>",
                assignment
            )
        })?;
        let path_str = path_str.trim();
        if path_str.is_empty() {
            bail!("Assignment path cannot be empty: '{}'", assignment);
        }
        let val = coerce_value(raw_val);
        let segments = parse_path(path_str)?;
        set_value(&mut root, &segments, val)?;
    }

    let format = ManifestFormat::detect(&content);
    let formatted = Manifest::format_json_value(&root, &format)
        .map_err(|e| anyhow!("Failed to serialize manifest: {}", e))?;
    std::fs::write(&resolved_path, formatted).map_err(|e| {
        anyhow!(
            "Failed to write manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;

    Ok(())
}

/// Deletes specified properties from `package.json` at `manifest_path``.
///
/// Multiple array index deletions targeting the same array container are sorted descending
/// so element shifting does not alter remaining deletion targets.
/// The resulting JSON is persisted preserving original formatting (indentation, newlines).
pub fn pkg_delete(manifest_path: &Path, fields: &[String]) -> Result<()> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).map_err(|e| {
        anyhow!(
            "Failed to read manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);
    let mut root: Value = serde_json::from_str(clean_str).map_err(|e| {
        anyhow!(
            "Failed to parse JSON in manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;

    let mut parsed_fields: Vec<(String, Vec<PathSegment>)> = Vec::new();
    for field in fields {
        let trimmed = field.trim();
        if trimmed.is_empty() {
            continue;
        }
        let segments = parse_path(trimmed)?;
        parsed_fields.push((trimmed.to_string(), segments));
    }

    // Sort array index deletions in descending index order if targeting the same parent path,
    // ensuring index shifts do not corrupt sibling deletion targets.
    parsed_fields.sort_by(|(_, segs_a), (_, segs_b)| {
        if segs_a.len() == segs_b.len() && !segs_a.is_empty() {
            let parent_a = &segs_a[..segs_a.len() - 1];
            let parent_b = &segs_b[..segs_b.len() - 1];
            if parent_a == parent_b {
                if let (PathSegment::Index(idx_a), PathSegment::Index(idx_b)) =
                    (&segs_a[segs_a.len() - 1], &segs_b[segs_b.len() - 1])
                {
                    return idx_b.cmp(idx_a);
                }
            }
        }
        std::cmp::Ordering::Equal
    });

    for (_, segments) in parsed_fields {
        delete_value(&mut root, &segments);
    }

    let format = ManifestFormat::detect(&content);
    let formatted = Manifest::format_json_value(&root, &format)
        .map_err(|e| anyhow!("Failed to serialize manifest: {}", e))?;
    std::fs::write(&resolved_path, formatted).map_err(|e| {
        anyhow!(
            "Failed to write manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;

    Ok(())
}

