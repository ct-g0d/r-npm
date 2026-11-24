use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::manifest::{Manifest, ManifestFormat};
use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
use crate::semver::Version;

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
                let mut escaped = false;

                while i < len {
                    if escaped {
                        content.push(chars[i]);
                        escaped = false;
                        i += 1;
                    } else if chars[i] == '\\' {
                        escaped = true;
                        i += 1;
                    } else if chars[i] == ']' {
                        closed = true;
                        i += 1; // consume ']'
                        break;
                    } else {
                        content.push(chars[i]);
                        i += 1;
                    }
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
            let mut escaped = false;
            while i < len {
                if escaped {
                    key.push(chars[i]);
                    escaped = false;
                    i += 1;
                } else if chars[i] == '\\' {
                    escaped = true;
                    i += 1;
                } else if chars[i] == '.' || chars[i] == '[' || chars[i].is_whitespace() {
                    break;
                } else {
                    key.push(chars[i]);
                    i += 1;
                }
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

/// Traverses an [`OrderedJsonValue`] using the provided [`PathSegment`]s.
///
/// Returns `Some(&OrderedJsonValue)` if the path exists, or `None` if any segment cannot be resolved.
pub fn get_value_at_path<'a>(
    root: &'a OrderedJsonValue,
    segments: &[PathSegment],
) -> Option<&'a OrderedJsonValue> {
    if segments.is_empty() {
        return Some(root);
    }
    let mut curr = root;
    for segment in segments {
        match curr {
            OrderedJsonValue::Object(map) => match segment {
                PathSegment::Key(key) => {
                    curr = map.get(key)?;
                }
                PathSegment::Index(idx) => {
                    let key_str = idx.to_string();
                    curr = map.get(&key_str)?;
                }
                PathSegment::Append => return None,
            },
            OrderedJsonValue::Array(arr) => match segment {
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

/// Coerces a raw value string into an [`OrderedJsonValue`] according to npm coercion rules:
/// - `"true"` -> `OrderedJsonValue::Bool(true)`
/// - `"false"` -> `OrderedJsonValue::Bool(false)`
/// - `"null"` -> `OrderedJsonValue::Null`
/// - Valid number string (e.g. `"42"`, `"3.14"`) -> `OrderedJsonValue::Number`
/// - Valid JSON object/array string (starts with `{` or `[`) -> parsed JSON via `serde_json::from_str`
/// - Otherwise -> `OrderedJsonValue::String(value)`
pub fn coerce_value(raw: &str) -> OrderedJsonValue {
    let trimmed = raw.trim();
    if trimmed == "true" {
        OrderedJsonValue::Bool(true)
    } else if trimmed == "false" {
        OrderedJsonValue::Bool(false)
    } else if trimmed == "null" {
        OrderedJsonValue::Null
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<OrderedJsonValue>(trimmed) {
            parsed
        } else {
            OrderedJsonValue::String(raw.to_string())
        }
    } else if let Ok(num) = serde_json::from_str::<serde_json::Number>(trimmed) {
        OrderedJsonValue::Number(num)
    } else {
        OrderedJsonValue::String(raw.to_string())
    }
}

/// Navigates `root` along `segments`, creating intermediate `OrderedJsonValue::Object` (or `OrderedJsonValue::Array`)
/// containers if absent, and assigns `value` to the leaf segment.
pub fn set_value(
    root: &mut OrderedJsonValue,
    segments: &[PathSegment],
    value: OrderedJsonValue,
) -> Result<()> {
    if segments.is_empty() {
        bail!("Path cannot be empty");
    }

    if !root.is_object() {
        *root = OrderedJsonValue::Object(OrderedJsonMap::new());
    }

    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        let is_leaf = i == segments.len() - 1;

        if is_leaf {
            match segment {
                PathSegment::Key(key) => match current {
                    OrderedJsonValue::Object(map) => {
                        map.insert(key.clone(), value);
                    }
                    OrderedJsonValue::Array(arr) => {
                        if let Ok(idx) = key.parse::<usize>() {
                            if idx < arr.len() {
                                arr[idx] = value;
                            } else {
                                while arr.len() < idx {
                                    arr.push(OrderedJsonValue::Null);
                                }
                                arr.push(value);
                            }
                        } else {
                            bail!("Cannot set named property '{}' on array", key);
                        }
                    }
                    _ => {
                        let mut map = OrderedJsonMap::new();
                        map.insert(key.clone(), value);
                        *current = OrderedJsonValue::Object(map);
                    }
                },
                PathSegment::Index(idx) => {
                    let idx = *idx;
                    match current {
                        OrderedJsonValue::Array(arr) => {
                            if idx < arr.len() {
                                arr[idx] = value;
                            } else {
                                while arr.len() < idx {
                                    arr.push(OrderedJsonValue::Null);
                                }
                                arr.push(value);
                            }
                        }
                        OrderedJsonValue::Object(map) => {
                            map.insert(idx.to_string(), value);
                        }
                        _ => {
                            let mut arr = Vec::new();
                            while arr.len() < idx {
                                arr.push(OrderedJsonValue::Null);
                            }
                            arr.push(value);
                            *current = OrderedJsonValue::Array(arr);
                        }
                    }
                }
                PathSegment::Append => match current {
                    OrderedJsonValue::Array(arr) => {
                        arr.push(value);
                    }
                    _ => {
                        bail!("Can't use append syntax in non-Array element");
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
                OrderedJsonValue::Object(map) => {
                    let needs_new_container = match map.get(key) {
                        None => true,
                        Some(OrderedJsonValue::Null) => true,
                        Some(OrderedJsonValue::Object(_)) => {
                            if matches!(&segments[i + 1], PathSegment::Append) {
                                bail!("Can't use append syntax in non-Array element");
                            }
                            false
                        }
                        Some(OrderedJsonValue::Array(_)) => false,
                        Some(_) => {
                            if matches!(&segments[i + 1], PathSegment::Append) {
                                bail!(
                                    "Property {} already exists and is not an Array or Object.",
                                    key
                                );
                            }
                            true
                        }
                    };
                    if needs_new_container {
                        let new_container = if next_is_array {
                            OrderedJsonValue::Array(Vec::new())
                        } else {
                            OrderedJsonValue::Object(OrderedJsonMap::new())
                        };
                        map.insert(key.clone(), new_container);
                    }
                    current = map.get_mut(key).unwrap();
                }
                OrderedJsonValue::Array(arr) => {
                    let idx = key.parse::<usize>().map_err(|_| {
                        anyhow!("Cannot navigate named property '{}' on array", key)
                    })?;
                    while arr.len() <= idx {
                        arr.push(OrderedJsonValue::Null);
                    }
                    let is_container = matches!(
                        arr[idx],
                        OrderedJsonValue::Object(_) | OrderedJsonValue::Array(_)
                    );
                    if !is_container {
                        arr[idx] = if next_is_array {
                            OrderedJsonValue::Array(Vec::new())
                        } else {
                            OrderedJsonValue::Object(OrderedJsonMap::new())
                        };
                    }
                    current = &mut arr[idx];
                }
                _ => {
                    let mut map = OrderedJsonMap::new();
                    let new_container = if next_is_array {
                        OrderedJsonValue::Array(Vec::new())
                    } else {
                        OrderedJsonValue::Object(OrderedJsonMap::new())
                    };
                    map.insert(key.clone(), new_container);
                    *current = OrderedJsonValue::Object(map);
                    if let OrderedJsonValue::Object(m) = current {
                        current = m.get_mut(key).unwrap();
                    }
                }
            },
            PathSegment::Index(idx) => {
                let idx = *idx;
                match current {
                    OrderedJsonValue::Array(arr) => {
                        while arr.len() <= idx {
                            arr.push(OrderedJsonValue::Null);
                        }
                        let is_container = matches!(
                            arr[idx],
                            OrderedJsonValue::Object(_) | OrderedJsonValue::Array(_)
                        );
                        if !is_container {
                            arr[idx] = if next_is_array {
                                OrderedJsonValue::Array(Vec::new())
                            } else {
                                OrderedJsonValue::Object(OrderedJsonMap::new())
                            };
                        }
                        current = &mut arr[idx];
                    }
                    OrderedJsonValue::Object(map) => {
                        let key = idx.to_string();
                        let needs_new_container = match map.get(&key) {
                            None => true,
                            Some(OrderedJsonValue::Null) => true,
                            Some(OrderedJsonValue::Object(_)) => false,
                            Some(OrderedJsonValue::Array(_)) => false,
                            Some(_) => true,
                        };
                        if needs_new_container {
                            let new_container = if next_is_array {
                                OrderedJsonValue::Array(Vec::new())
                            } else {
                                OrderedJsonValue::Object(OrderedJsonMap::new())
                            };
                            map.insert(key.clone(), new_container);
                        }
                        current = map.get_mut(&key).unwrap();
                    }
                    _ => {
                        let mut arr = Vec::new();
                        while arr.len() <= idx {
                            arr.push(OrderedJsonValue::Null);
                        }
                        arr[idx] = if next_is_array {
                            OrderedJsonValue::Array(Vec::new())
                        } else {
                            OrderedJsonValue::Object(OrderedJsonMap::new())
                        };
                        *current = OrderedJsonValue::Array(arr);
                        if let OrderedJsonValue::Array(a) = current {
                            current = &mut a[idx];
                        }
                    }
                }
            }
            PathSegment::Append => match current {
                OrderedJsonValue::Array(arr) => {
                    let new_container = if next_is_array {
                        OrderedJsonValue::Array(Vec::new())
                    } else {
                        OrderedJsonValue::Object(OrderedJsonMap::new())
                    };
                    arr.push(new_container);
                    current = arr.last_mut().unwrap();
                }
                _ => {
                    let new_container = if next_is_array {
                        OrderedJsonValue::Array(Vec::new())
                    } else {
                        OrderedJsonValue::Object(OrderedJsonMap::new())
                    };
                    *current = OrderedJsonValue::Array(vec![new_container]);
                    if let OrderedJsonValue::Array(a) = current {
                        current = a.last_mut().unwrap();
                    }
                }
            },
        }
    }

    Ok(())
}

/// Navigates `root` along `segments` and removes the leaf property or array element.
pub fn delete_value(root: &mut OrderedJsonValue, segments: &[PathSegment]) {
    if segments.is_empty() {
        return;
    }

    if segments.len() == 1 {
        match &segments[0] {
            PathSegment::Key(key) => {
                if let OrderedJsonValue::Object(map) = root {
                    map.shift_remove(key);
                }
            }
            PathSegment::Index(idx) => {
                if let OrderedJsonValue::Array(arr) = root {
                    if *idx < arr.len() {
                        arr.remove(*idx);
                    }
                } else if let OrderedJsonValue::Object(map) = root {
                    map.shift_remove(&idx.to_string());
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
                OrderedJsonValue::Object(map) => {
                    if let Some(next) = map.get_mut(key) {
                        current = next;
                    } else {
                        return;
                    }
                }
                OrderedJsonValue::Array(arr) => {
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
                    OrderedJsonValue::Array(arr) => {
                        if idx < arr.len() {
                            current = &mut arr[idx];
                        } else {
                            return;
                        }
                    }
                    OrderedJsonValue::Object(map) => {
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
            OrderedJsonValue::Object(map) => {
                map.shift_remove(key);
            }
            OrderedJsonValue::Array(arr) => {
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
                OrderedJsonValue::Array(arr) => {
                    if idx < arr.len() {
                        arr.remove(idx);
                    }
                }
                OrderedJsonValue::Object(map) => {
                    map.shift_remove(&idx.to_string());
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
pub fn pkg_get(manifest_path: &Path, field_paths: &[String], _json: bool) -> Result<String> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "Failed to read package manifest at '{}'",
            resolved_path.display()
        )
    })?;
    let format = ManifestFormat::detect(&content);
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);

    let manifest_val: OrderedJsonValue = serde_json::from_str(clean_str).with_context(|| {
        format!(
            "Failed to parse JSON in package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    if field_paths.is_empty() {
        return Ok(Manifest::format_json_value(&manifest_val, &format)?);
    }

    if field_paths.len() == 1 {
        let path_str = &field_paths[0];
        let segments = parse_path(path_str)?;
        if segments.iter().any(|s| matches!(s, PathSegment::Append)) {
            bail!("Empty brackets are not valid syntax for retrieving values.");
        }
        let value = match get_value_at_path(&manifest_val, &segments) {
            Some(v) => v,
            None => return Ok("{}".to_string()),
        };

        return Ok(Manifest::format_json_value(
            value,
            &ManifestFormat::default(),
        )?);
    }

    let mut result_map = OrderedJsonMap::new();
    for path_str in field_paths {
        let segments = parse_path(path_str)?;
        if segments.iter().any(|s| matches!(s, PathSegment::Append)) {
            bail!("Empty brackets are not valid syntax for retrieving values.");
        }
        if let Some(value) = get_value_at_path(&manifest_val, &segments) {
            result_map.insert(path_str.clone(), value.clone());
        }
    }

    Ok(Manifest::format_json_value(
        &OrderedJsonValue::Object(result_map),
        &ManifestFormat::default(),
    )?)
}

/// Retrieves package manifest values as an [`OrderedJsonValue`].
///
/// - If `field_paths` is empty: returns the full manifest value.
/// - If single field: returns that field's value or `{}` if not found.
/// - If multiple fields: returns a JSON object `{ field: value, ... }` of found fields.
pub fn pkg_get_value(manifest_path: &Path, field_paths: &[String]) -> Result<OrderedJsonValue> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "Failed to read package manifest at '{}'",
            resolved_path.display()
        )
    })?;
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);

    let manifest_val: OrderedJsonValue = serde_json::from_str(clean_str).with_context(|| {
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
        if segments.iter().any(|s| matches!(s, PathSegment::Append)) {
            bail!("Empty brackets are not valid syntax for retrieving values.");
        }
        let val = get_value_at_path(&manifest_val, &segments)
            .cloned()
            .unwrap_or_else(|| OrderedJsonValue::Object(OrderedJsonMap::new()));
        return Ok(val);
    }

    let mut result_map = OrderedJsonMap::new();
    for path_str in field_paths {
        let segments = parse_path(path_str)?;
        if segments.iter().any(|s| matches!(s, PathSegment::Append)) {
            bail!("Empty brackets are not valid syntax for retrieving values.");
        }
        if let Some(value) = get_value_at_path(&manifest_val, &segments) {
            result_map.insert(path_str.clone(), value.clone());
        }
    }

    Ok(OrderedJsonValue::Object(result_map))
}

/// Retrieves properties across workspace members formatted as pretty-printed JSON:
/// `{ "<workspace-name>": <extracted-value>, ... }`.
pub fn pkg_get_workspaces(members: &[(&str, &Path)], field_paths: &[String]) -> Result<String> {
    let mut root_map = OrderedJsonMap::new();
    for (name, path) in members {
        let val = pkg_get_value(path, field_paths)?;
        root_map.insert((*name).to_string(), val);
    }
    let format = ManifestFormat::default();
    Ok(Manifest::format_json_value(
        &OrderedJsonValue::Object(root_map),
        &format,
    )?)
}

/// Sets properties in `package.json` at `manifest_path` based on `<path>=<value>` assignments.
///
/// Intermediate containers are created automatically if absent. Values are coerced
/// according to npm rules. The resulting JSON is persisted preserving original formatting
/// (indentation, newlines, UTF-8 BOM, and trailing newlines).
pub fn pkg_set(manifest_path: &Path, assignments: &[String]) -> Result<()> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).map_err(|e| {
        anyhow!(
            "Failed to read manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;
    let format = ManifestFormat::detect(&content);
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);
    let mut root: OrderedJsonValue = serde_json::from_str(clean_str).map_err(|e| {
        anyhow!(
            "Failed to parse JSON in manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;

    if !root.is_object() {
        root = OrderedJsonValue::Object(OrderedJsonMap::new());
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

/// Deletes specified properties from `package.json` at `manifest_path`.
///
/// Multiple array index deletions targeting the same array container are sorted descending
/// so element shifting does not alter remaining deletion targets.
/// The resulting JSON is persisted preserving original formatting (indentation, newlines, BOM).
pub fn pkg_delete(manifest_path: &Path, fields: &[String]) -> Result<()> {
    let resolved_path = resolve_manifest_path(manifest_path);
    let content = std::fs::read_to_string(&resolved_path).map_err(|e| {
        anyhow!(
            "Failed to read manifest at '{}': {}",
            resolved_path.display(),
            e
        )
    })?;
    let format = ManifestFormat::detect(&content);
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);
    let mut root: OrderedJsonValue = serde_json::from_str(clean_str).map_err(|e| {
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

/// Repairs and normalizes package manifest properties according to npm's `pkg fix` / `@npmcli/package-json` `fix()`
/// while preserving key ordering, formatting, indentation, and newlines.
pub fn pkg_fix(manifest_path: &Path) -> Result<()> {
    let resolved_path = resolve_manifest_path(manifest_path);
    if !resolved_path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&resolved_path).with_context(|| {
        format!(
            "Failed to read package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    let format = ManifestFormat::detect(&content);
    let clean_str = content.strip_prefix('\u{feff}').unwrap_or(&content);

    let mut root: OrderedJsonValue = serde_json::from_str(clean_str).with_context(|| {
        format!(
            "Failed to parse JSON in package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    if let OrderedJsonValue::Object(ref mut map) = root {
        fix_manifest_object(map);
    }

    let formatted = Manifest::format_json_value(&root, &format)
        .map_err(|e| anyhow!("Failed to serialize manifest: {}", e))?;

    std::fs::write(&resolved_path, formatted).with_context(|| {
        format!(
            "Failed to write package manifest at '{}'",
            resolved_path.display()
        )
    })?;

    Ok(())
}

fn fix_manifest_object(map: &mut OrderedJsonMap) {
    // 1. Remove attributes starting with '_'
    let underscore_keys: Vec<String> = map
        .keys()
        .filter(|k| k.starts_with('_'))
        .cloned()
        .collect();
    for k in underscore_keys {
        map.shift_remove(&k);
    }

    // 2. Name cleanup
    let mut unscoped_name = String::new();
    if let Some(val) = map.get_mut("name") {
        if let OrderedJsonValue::String(s) = val {
            let trimmed = s.trim().to_string();
            unscoped_name = extract_unscoped_name(&trimmed);
            *s = trimmed;
        }
    } else {
        map.insert("name".to_string(), OrderedJsonValue::String(String::new()));
    }

    // 3. Version cleanup
    if let Some(val) = map.get_mut("version") {
        if let OrderedJsonValue::String(s) = val {
            *s = clean_semver_version(s);
        }
    } else {
        map.insert(
            "version".to_string(),
            OrderedJsonValue::String(String::new()),
        );
    }

    // 4. bin normalization
    normalize_bin(map, &unscoped_name);

    // 5. directories.bin cleanup
    normalize_directories(map);

    // 6. repository normalization
    normalize_repository(map);

    // 7. bugs normalization
    normalize_bugs(map);

    // 8. funding normalization
    normalize_funding(map);

    // 9. bundleDependencies / bundledDependencies
    normalize_bundle_dependencies(map);

    // 10. scripts path cleanup
    normalize_scripts(map);

    // 11. dependencies cleanup
    normalize_dependency_fields(map);

    // 12. keywords normalization
    normalize_keywords(map);
}

fn extract_unscoped_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((_scope, pkg)) = rest.split_once('/') {
            return pkg.to_string();
        }
    }
    name.to_string()
}

fn clean_semver_version(v: &str) -> String {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let stripped = trimmed
        .trim_start_matches(['=', 'v', 'V'])
        .trim();
    let without_build = stripped.split('+').next().unwrap_or(stripped);
    if Version::parse(without_build).is_ok() {
        without_build.to_string()
    } else {
        stripped.to_string()
    }
}

fn normalize_bin_path(path_str: &str) -> String {
    let unixified = path_str.replace('\\', "/");
    let trimmed = unixified.trim();
    let stripped = trimmed.strip_prefix("./").unwrap_or(trimmed);
    let stripped = stripped.strip_prefix('/').unwrap_or(stripped);
    stripped.to_string()
}

fn normalize_bin(map: &mut OrderedJsonMap, unscoped_name: &str) {
    if let Some(bin_val) = map.shift_remove("bin") {
        match bin_val {
            OrderedJsonValue::String(s) => {
                let clean_path = normalize_bin_path(&s);
                if !clean_path.is_empty() {
                    let cmd_name = if !unscoped_name.is_empty() {
                        unscoped_name.to_string()
                    } else {
                        Path::new(&clean_path)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or("app")
                            .to_string()
                    };
                    let mut bin_map = OrderedJsonMap::new();
                    bin_map.insert(cmd_name, OrderedJsonValue::String(clean_path));
                    map.insert("bin".to_string(), OrderedJsonValue::Object(bin_map));
                }
            }
            OrderedJsonValue::Array(arr) => {
                let mut bin_map = OrderedJsonMap::new();
                for item in arr {
                    if let OrderedJsonValue::String(p) = item {
                        let clean_path = normalize_bin_path(&p);
                        if !clean_path.is_empty() {
                            let cmd_name = Path::new(&clean_path)
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or("")
                                .to_string();
                            if !cmd_name.is_empty() {
                                bin_map.insert(cmd_name, OrderedJsonValue::String(clean_path));
                            }
                        }
                    }
                }
                if !bin_map.is_empty() {
                    map.insert("bin".to_string(), OrderedJsonValue::Object(bin_map));
                }
            }
            OrderedJsonValue::Object(orig_map) => {
                let mut bin_map = OrderedJsonMap::new();
                for (k, v) in orig_map {
                    if let OrderedJsonValue::String(target) = v {
                        let clean_target = normalize_bin_path(&target);
                        let unix_k = k.replace('\\', "/");
                        let base_k = Path::new(&unix_k)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or(k.as_str())
                            .to_string();
                        if !base_k.is_empty() && !clean_target.is_empty() {
                            bin_map.insert(base_k, OrderedJsonValue::String(clean_target));
                        }
                    }
                }
                if !bin_map.is_empty() {
                    map.insert("bin".to_string(), OrderedJsonValue::Object(bin_map));
                }
            }
            _ => {}
        }
    }
}

fn normalize_directories(map: &mut OrderedJsonMap) {
    if let Some(val) = map.get_mut("directories") {
        if let OrderedJsonValue::Object(ref mut dir_map) = val {
            if let Some(bin_dir) = dir_map.get_mut("bin") {
                if let OrderedJsonValue::String(s) = bin_dir {
                    let cleaned = s.trim().replace('\\', "/");
                    if cleaned.is_empty() {
                        dir_map.shift_remove("bin");
                    } else {
                        *s = cleaned;
                    }
                } else {
                    dir_map.shift_remove("bin");
                }
            }
        } else {
            map.shift_remove("directories");
            return;
        }
    }
    if let Some(OrderedJsonValue::Object(ref dir_map)) = map.get("directories") {
        if dir_map.is_empty() {
            map.shift_remove("directories");
        }
    }
}

fn normalize_git_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let (url_part, hash_part) = match trimmed.split_once('#') {
        Some((u, h)) => (u.trim(), Some(h.trim())),
        None => (trimmed, None),
    };

    let mut normalized_base = if let Some(rest) = url_part.strip_prefix("github:") {
        let repo = rest.trim_end_matches(".git");
        format!("git+https://github.com/{repo}.git")
    } else if let Some(rest) = url_part.strip_prefix("gitlab:") {
        let repo = rest.trim_end_matches(".git");
        format!("git+https://gitlab.com/{repo}.git")
    } else if let Some(rest) = url_part.strip_prefix("bitbucket:") {
        let repo = rest.trim_end_matches(".git");
        format!("git+https://bitbucket.org/{repo}.git")
    } else if let Some(rest) = url_part.strip_prefix("gist:") {
        let id = rest.trim_end_matches(".git");
        format!("git+https://gist.github.com/{id}.git")
    } else if url_part.starts_with("git@") {
        if let Some((user_host, path)) = url_part.split_once(':') {
            let path_with_git = if path.ends_with(".git") {
                path.to_string()
            } else {
                format!("{path}.git")
            };
            format!("git+ssh://{user_host}/{path_with_git}")
        } else {
            format!("git+ssh://{url_part}")
        }
    } else if url_part.starts_with("git+ssh://")
        || url_part.starts_with("git+file://")
        || url_part.starts_with("git://")
    {
        url_part.to_string()
    } else if let Some(rest) = url_part.strip_prefix("git+https://") {
        let without_git = rest.trim_end_matches(".git");
        format!("git+https://{without_git}.git")
    } else if let Some(rest) = url_part.strip_prefix("git+http://") {
        let without_git = rest.trim_end_matches(".git");
        format!("git+http://{without_git}.git")
    } else if url_part.starts_with("http://") || url_part.starts_with("https://") {
        if let Ok(parsed) = url::Url::parse(url_part) {
            let host = parsed.host_str().unwrap_or("").to_lowercase();
            if host == "github.com" || host == "gitlab.com" || host == "bitbucket.org" {
                let path = parsed.path().trim_start_matches('/').trim_end_matches(".git");
                let scheme = parsed.scheme();
                format!("git+{scheme}://{host}/{path}.git")
            } else {
                url_part.to_string()
            }
        } else {
            url_part.to_string()
        }
    } else if is_bare_git_shorthand(url_part) {
        let without_git = url_part.trim_end_matches(".git");
        format!("git+https://github.com/{without_git}.git")
    } else {
        url_part.to_string()
    };

    if let Some(hash) = hash_part {
        if !hash.is_empty() {
            normalized_base.push('#');
            normalized_base.push_str(hash);
        }
    }

    normalized_base
}

fn is_bare_git_shorthand(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let user = parts[0];
    let repo = parts[1];
    if user.is_empty() || repo.is_empty() {
        return false;
    }
    if user.contains(':') || user.contains('@') || user.starts_with('.') || user.starts_with('-') {
        return false;
    }
    true
}

fn normalize_repository(map: &mut OrderedJsonMap) {
    if !map.contains_key("repository") {
        if let Some(OrderedJsonValue::Array(arr)) = map.get("repositories") {
            if let Some(first) = arr.first() {
                map.insert("repository".to_string(), first.clone());
            }
        }
    }

    if let Some(val) = map.get_mut("repository") {
        match val {
            OrderedJsonValue::String(s) => {
                let norm = normalize_git_url(s);
                let mut repo_obj = OrderedJsonMap::new();
                repo_obj.insert("type".to_string(), OrderedJsonValue::String("git".to_string()));
                repo_obj.insert("url".to_string(), OrderedJsonValue::String(norm));
                *val = OrderedJsonValue::Object(repo_obj);
            }
            OrderedJsonValue::Object(repo_map) => {
                if !repo_map.contains_key("type") {
                    repo_map.insert("type".to_string(), OrderedJsonValue::String("git".to_string()));
                }
                if let Some(OrderedJsonValue::String(url_str)) = repo_map.get_mut("url") {
                    *url_str = normalize_git_url(url_str);
                }
            }
            _ => {}
        }
    }
}

fn normalize_bugs(map: &mut OrderedJsonMap) {
    if let Some(val) = map.shift_remove("bugs") {
        match val {
            OrderedJsonValue::String(s) => {
                let trimmed = s.trim();
                if is_email(trimmed) {
                    let mut bugs_obj = OrderedJsonMap::new();
                    bugs_obj.insert("email".to_string(), OrderedJsonValue::String(trimmed.to_string()));
                    map.insert("bugs".to_string(), OrderedJsonValue::Object(bugs_obj));
                } else if trimmed.starts_with("http://")
                    || trimmed.starts_with("https://")
                    || url::Url::parse(trimmed).is_ok()
                {
                    let mut bugs_obj = OrderedJsonMap::new();
                    bugs_obj.insert("url".to_string(), OrderedJsonValue::String(trimmed.to_string()));
                    map.insert("bugs".to_string(), OrderedJsonValue::Object(bugs_obj));
                }
            }
            OrderedJsonValue::Object(mut bugs_map) => {
                if !bugs_map.contains_key("url") {
                    if let Some(w) = bugs_map.shift_remove("web").or_else(|| bugs_map.shift_remove("name")) {
                        bugs_map.insert("url".to_string(), w);
                    }
                }
                let mut clean_bugs = OrderedJsonMap::new();
                if let Some(OrderedJsonValue::String(url_str)) = bugs_map.get("url") {
                    let t = url_str.trim();
                    if !t.is_empty() {
                        clean_bugs.insert("url".to_string(), OrderedJsonValue::String(t.to_string()));
                    }
                }
                if let Some(OrderedJsonValue::String(email_str)) = bugs_map.get("email") {
                    let t = email_str.trim();
                    if is_email(t) {
                        clean_bugs.insert("email".to_string(), OrderedJsonValue::String(t.to_string()));
                    }
                }
                if !clean_bugs.is_empty() {
                    map.insert("bugs".to_string(), OrderedJsonValue::Object(clean_bugs));
                }
            }
            _ => {}
        }
    }
}

fn is_email(s: &str) -> bool {
    if let Some(at_idx) = s.find('@') {
        at_idx > 0 && at_idx < s.len() - 1 && s[at_idx + 1..].contains('.')
    } else {
        false
    }
}

fn normalize_funding(map: &mut OrderedJsonMap) {
    if let Some(val) = map.shift_remove("funding") {
        match val {
            OrderedJsonValue::String(s) => {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    let mut fund_obj = OrderedJsonMap::new();
                    fund_obj.insert("url".to_string(), OrderedJsonValue::String(trimmed.to_string()));
                    map.insert("funding".to_string(), OrderedJsonValue::Object(fund_obj));
                }
            }
            OrderedJsonValue::Array(arr) => {
                let mut new_arr = Vec::new();
                for item in arr {
                    match item {
                        OrderedJsonValue::String(s) => {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                let mut fund_obj = OrderedJsonMap::new();
                                fund_obj.insert("url".to_string(), OrderedJsonValue::String(trimmed.to_string()));
                                new_arr.push(OrderedJsonValue::Object(fund_obj));
                            }
                        }
                        OrderedJsonValue::Object(mut fund_map) => {
                            if let Some(OrderedJsonValue::String(u)) = fund_map.get_mut("url") {
                                *u = u.trim().to_string();
                                if !u.is_empty() {
                                    new_arr.push(OrderedJsonValue::Object(fund_map));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if !new_arr.is_empty() {
                    map.insert("funding".to_string(), OrderedJsonValue::Array(new_arr));
                }
            }
            OrderedJsonValue::Object(mut fund_map) => {
                if let Some(OrderedJsonValue::String(u)) = fund_map.get_mut("url") {
                    *u = u.trim().to_string();
                    if !u.is_empty() {
                        map.insert("funding".to_string(), OrderedJsonValue::Object(fund_map));
                    }
                }
            }
            _ => {}
        }
    }
}

fn normalize_bundle_dependencies(map: &mut OrderedJsonMap) {
    if !map.contains_key("bundleDependencies") {
        if let Some(val) = map.shift_remove("bundledDependencies") {
            map.insert("bundleDependencies".to_string(), val);
        }
    } else {
        map.shift_remove("bundledDependencies");
    }

    let deps_keys: Option<Vec<OrderedJsonValue>> =
        if let Some(OrderedJsonValue::Bool(true)) = map.get("bundleDependencies") {
            if let Some(OrderedJsonValue::Object(deps)) = map.get("dependencies") {
                Some(
                    deps.keys()
                        .map(|k| OrderedJsonValue::String(k.clone()))
                        .collect(),
                )
            } else {
                Some(Vec::new())
            }
        } else {
            None
        };

    if let Some(keys) = deps_keys {
        map.insert(
            "bundleDependencies".to_string(),
            OrderedJsonValue::Array(keys),
        );
    } else if let Some(val) = map.get_mut("bundleDependencies") {
        match val {
            OrderedJsonValue::Bool(false) => {
                *val = OrderedJsonValue::Array(Vec::new());
            }
            OrderedJsonValue::Object(obj) => {
                let keys = obj
                    .keys()
                    .map(|k| OrderedJsonValue::String(k.clone()))
                    .collect();
                *val = OrderedJsonValue::Array(keys);
            }
            _ => {}
        }
    }
}

fn normalize_scripts(map: &mut OrderedJsonMap) {
    if let Some(val) = map.get_mut("scripts") {
        if let OrderedJsonValue::Object(scripts_map) = val {
            let mut cleaned = OrderedJsonMap::new();
            for (name, cmd) in scripts_map.iter() {
                if let OrderedJsonValue::String(cmd_str) = cmd {
                    let stripped = strip_node_modules_bin(cmd_str);
                    cleaned.insert(name.clone(), OrderedJsonValue::String(stripped));
                }
            }
            *scripts_map = cleaned;
        } else {
            map.shift_remove("scripts");
        }
    }
}

fn strip_node_modules_bin(cmd: &str) -> String {
    let trimmed = cmd.trim();
    let candidates = [
        "node_modules/.bin/",
        "node_modules\\.bin\\",
        "./node_modules/.bin/",
        ".\\node_modules\\.bin\\",
    ];
    for prefix in candidates {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    trimmed.to_string()
}

fn normalize_dependency_fields(map: &mut OrderedJsonMap) {
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(val) = map.get_mut(field) {
            match val {
                OrderedJsonValue::String(s) => {
                    let mut new_map = OrderedJsonMap::new();
                    for part in s.split(|c: char| c.is_whitespace() || c == ',') {
                        let t = part.trim();
                        if !t.is_empty() {
                            new_map.insert(t.to_string(), OrderedJsonValue::String("*".to_string()));
                        }
                    }
                    *val = OrderedJsonValue::Object(new_map);
                }
                OrderedJsonValue::Array(arr) => {
                    let mut new_map = OrderedJsonMap::new();
                    for item in arr.iter() {
                        if let OrderedJsonValue::String(s) = item {
                            let t = s.trim();
                            if !t.is_empty() {
                                new_map.insert(t.to_string(), OrderedJsonValue::String("*".to_string()));
                            }
                        }
                    }
                    *val = OrderedJsonValue::Object(new_map);
                }
                OrderedJsonValue::Object(deps_map) => {
                    let mut cleaned = OrderedJsonMap::new();
                    for (k, v) in deps_map.iter() {
                        if let OrderedJsonValue::String(v_str) = v {
                            cleaned.insert(k.clone(), OrderedJsonValue::String(v_str.clone()));
                        }
                    }
                    *deps_map = cleaned;
                }
                _ => {
                    map.shift_remove(field);
                }
            }
        }
    }
}

fn normalize_keywords(map: &mut OrderedJsonMap) {
    if let Some(val) = map.get_mut("keywords") {
        if let OrderedJsonValue::String(s) = val {
            let items: Vec<OrderedJsonValue> = s
                .split(',')
                .map(|kw| OrderedJsonValue::String(kw.trim().to_string()))
                .filter(|kw| {
                    if let OrderedJsonValue::String(item) = kw {
                        !item.is_empty()
                    } else {
                        false
                    }
                })
                .collect();
            *val = OrderedJsonValue::Array(items);
        }
    }
}
