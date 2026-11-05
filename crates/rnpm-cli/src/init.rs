use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde_json::Value;

/// Configuration options for `npm init` execution.
#[derive(Debug, Clone)]
pub struct InitOptions {
    /// Non-interactive generation using default values (-y / --yes / -f / --force)
    pub yes: bool,
    /// Optional package scope (e.g. `@myorg` or `myorg`)
    pub scope: Option<String>,
    /// Target project directory
    pub directory: PathBuf,
}

/// Normalizes a package initializer string into a corresponding `create-*` package spec.
///
/// Rules:
/// - If `@<scope>/<pkg>` -> `@<scope>/create-<pkg>` (or `@<scope>/create` if `<pkg>` is empty).
/// - If `@<scope>` -> `@<scope>/create`.
/// - If `<initializer>` already starts with `create-` (or `@scope/create-`) keep as is.
/// - Otherwise: `react-app` -> `create-react-app`, `vite@latest` -> `create-vite@latest`.
/// - Version/tag specifiers (e.g. `@latest`, `@1.0.0`) are preserved.
pub fn transform_initializer(initializer: &str) -> String {
    let s = initializer.trim();
    if s.is_empty() {
        return s.to_string();
    }

    if let Some(rest) = s.strip_prefix('@') {
        // Scoped package
        if let Some(slash_idx) = rest.find('/') {
            let scope = &rest[..slash_idx];
            let after_slash = &rest[slash_idx + 1..];

            // Separate package name and optional version tag (e.g. `pkg@1.0.0`)
            let (pkg, ver_opt) = match after_slash.find('@') {
                Some(at_idx) => (&after_slash[..at_idx], Some(&after_slash[at_idx..])),
                None => (after_slash, None),
            };
            let ver_suffix = ver_opt.unwrap_or("");

            if pkg.is_empty() {
                format!("@{scope}/create{ver_suffix}")
            } else if pkg.starts_with("create-") || pkg == "create" {
                format!("@{scope}/{pkg}{ver_suffix}")
            } else {
                format!("@{scope}/create-{pkg}{ver_suffix}")
            }
        } else {
            // No slash: e.g. `@scope` or `@scope@latest`
            let (scope, ver_opt) = match rest.find('@') {
                Some(at_idx) => (&rest[..at_idx], Some(&rest[at_idx..])),
                None => (rest, None),
            };
            let ver_suffix = ver_opt.unwrap_or("");
            format!("@{scope}/create{ver_suffix}")
        }
    } else {
        // Unscoped package: e.g. `react-app`, `vite@latest`, `create-react-app`
        let (pkg, ver_opt) = match s.find('@') {
            Some(at_idx) => (&s[..at_idx], Some(&s[at_idx..])),
            None => (s, None),
        };
        let ver_suffix = ver_opt.unwrap_or("");

        if pkg.starts_with("create-") || pkg == "create" {
            format!("{pkg}{ver_suffix}")
        } else {
            format!("create-{pkg}{ver_suffix}")
        }
    }
}

/// Sanitizes a directory name into a valid npm package name.
pub fn sanitize_package_name(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let mut sanitized = String::new();
    for c in lower.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            sanitized.push(c);
        } else {
            sanitized.push('-');
        }
    }
    let trimmed = sanitized.trim_matches(|c| c == '-' || c == '_' || c == '.');
    if trimmed.is_empty() {
        "package".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Applies a scope prefix to a package name.
pub fn apply_scope(name: &str, scope: &str) -> String {
    let clean_scope = scope.trim();
    let clean_scope = clean_scope.strip_prefix('@').unwrap_or(clean_scope);
    let clean_scope = clean_scope.trim_end_matches('/');
    if clean_scope.is_empty() {
        return name.to_string();
    }

    let unscoped_name = if let Some(slash_idx) = name.find('/') {
        &name[slash_idx + 1..]
    } else {
        name
    };

    format!("@{clean_scope}/{unscoped_name}")
}

/// Attempts to detect a Git remote origin URL from ancestor `.git/config` files.
pub fn detect_git_repo(dir: &Path) -> Option<String> {
    let mut curr = Some(dir);
    while let Some(d) = curr {
        let config_file = d.join(".git").join("config");
        if config_file.is_file() {
            if let Ok(content) = std::fs::read_to_string(config_file) {
                let mut in_remote_origin = false;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') {
                        in_remote_origin = trimmed.eq_ignore_ascii_case("[remote \"origin\"]");
                    } else if in_remote_origin {
                        if let Some(rest) = trimmed.strip_prefix("url =") {
                            return Some(rest.trim().to_string());
                        } else if let Some(rest) = trimmed.strip_prefix("url=") {
                            return Some(rest.trim().to_string());
                        }
                    }
                }
            }
            break;
        }
        curr = d.parent();
    }
    None
}

/// Prompts user for a field with an optional default value.
pub fn prompt_field<R: BufRead, W: Write>(
    prompt: &str,
    default: &str,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<String> {
    if !default.is_empty() {
        write!(writer, "{prompt}: ({default}) ")?;
    } else {
        write!(writer, "{prompt}: ")?;
    }
    writer.flush()?;

    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line)?;
    if bytes_read == 0 {
        // EOF fallback
        return Ok(default.to_string());
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Executes `npm init` workflow (non-interactive or interactive).
pub fn run_init<R: BufRead, W: Write>(
    options: &InitOptions,
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let manifest_path = options.directory.join("package.json");

    let existing_val: Option<Value> = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("Failed to read existing manifest at '{}'", manifest_path.display()))?;
        let clean = content.strip_prefix('\u{feff}').unwrap_or(&content);
        serde_json::from_str(clean).ok()
    } else {
        None
    };

    // Calculate default package name
    let dir_name = options
        .directory
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty() && n != "." && n != "/")
        .unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|cwd| cwd.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "package".to_string())
        });
    let base_name = sanitize_package_name(&dir_name);
    let name_with_scope = if let Some(ref sc) = options.scope {
        apply_scope(&base_name, sc)
    } else {
        base_name
    };

    let default_name = if let Some(ref ext) = existing_val {
        if let Some(n) = ext.get("name").and_then(|v| v.as_str()) {
            if let Some(ref sc) = options.scope {
                apply_scope(n, sc)
            } else {
                n.to_string()
            }
        } else {
            name_with_scope
        }
    } else {
        name_with_scope
    };

    let default_version = existing_val
        .as_ref()
        .and_then(|ext| ext.get("version").and_then(|v| v.as_str()))
        .unwrap_or("1.0.0")
        .to_string();

    let default_description = existing_val
        .as_ref()
        .and_then(|ext| ext.get("description").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let default_main = existing_val
        .as_ref()
        .and_then(|ext| ext.get("main").and_then(|v| v.as_str()))
        .unwrap_or("index.js")
        .to_string();

    let default_test = existing_val
        .as_ref()
        .and_then(|ext| ext.get("scripts").and_then(|s| s.get("test")).and_then(|v| v.as_str()))
        .unwrap_or("echo \"Error: no test specified\" && exit 1")
        .to_string();

    let default_repo = existing_val
        .as_ref()
        .and_then(|ext| {
            ext.get("repository").and_then(|r| {
                if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                    Some(url.to_string())
                } else {
                    r.as_str().map(|s| s.to_string())
                }
            })
        })
        .or_else(|| detect_git_repo(&options.directory))
        .unwrap_or_default();

    let default_keywords = existing_val
        .as_ref()
        .and_then(|ext| {
            ext.get("keywords").and_then(|k| {
                k.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
            })
        })
        .unwrap_or_default();

    let default_author = existing_val
        .as_ref()
        .and_then(|ext| {
            ext.get("author").and_then(|a| {
                if let Some(name) = a.get("name").and_then(|v| v.as_str()) {
                    Some(name.to_string())
                } else {
                    a.as_str().map(|s| s.to_string())
                }
            })
        })
        .unwrap_or_default();

    let default_license = existing_val
        .as_ref()
        .and_then(|ext| ext.get("license").and_then(|v| v.as_str()))
        .unwrap_or("ISC")
        .to_string();

    if options.yes {
        // Non-interactive generation with npm defaults
        let mut map = if let Some(Value::Object(m)) = existing_val {
            m
        } else {
            let mut fresh = serde_json::Map::new();
            fresh.insert("name".to_string(), Value::String(default_name.clone()));
            fresh.insert("version".to_string(), Value::String("1.0.0".to_string()));
            fresh.insert("description".to_string(), Value::String("".to_string()));
            fresh.insert("main".to_string(), Value::String("index.js".to_string()));

            let mut scripts = serde_json::Map::new();
            scripts.insert(
                "test".to_string(),
                Value::String("echo \"Error: no test specified\" && exit 1".to_string()),
            );
            fresh.insert("scripts".to_string(), Value::Object(scripts));
            fresh.insert("keywords".to_string(), Value::Array(Vec::new()));
            fresh.insert("author".to_string(), Value::String("".to_string()));
            fresh.insert("license".to_string(), Value::String("ISC".to_string()));
            fresh
        };

        if !map.contains_key("name") {
            map.insert("name".to_string(), Value::String(default_name));
        } else if let Some(ref sc) = options.scope {
            if let Some(n) = map.get("name").and_then(|v| v.as_str()) {
                map.insert("name".to_string(), Value::String(apply_scope(n, sc)));
            }
        }
        if !map.contains_key("version") {
            map.insert("version".to_string(), Value::String("1.0.0".to_string()));
        }
        if !map.contains_key("description") {
            map.insert("description".to_string(), Value::String("".to_string()));
        }
        if !map.contains_key("main") {
            map.insert("main".to_string(), Value::String("index.js".to_string()));
        }
        if !map.contains_key("scripts") {
            let mut scripts = serde_json::Map::new();
            scripts.insert(
                "test".to_string(),
                Value::String("echo \"Error: no test specified\" && exit 1".to_string()),
            );
            map.insert("scripts".to_string(), Value::Object(scripts));
        } else if let Some(Value::Object(ref mut scripts)) = map.get_mut("scripts") {
            if !scripts.contains_key("test") {
                scripts.insert(
                    "test".to_string(),
                    Value::String("echo \"Error: no test specified\" && exit 1".to_string()),
                );
            }
        }
        if !map.contains_key("keywords") {
            map.insert("keywords".to_string(), Value::Array(Vec::new()));
        }
        if !map.contains_key("author") {
            map.insert("author".to_string(), Value::String("".to_string()));
        }
        if !map.contains_key("license") {
            map.insert("license".to_string(), Value::String("ISC".to_string()));
        }

        let mut formatted = serde_json::to_string_pretty(&Value::Object(map))?;
        formatted.push('\n');

        std::fs::create_dir_all(&options.directory)?;
        std::fs::write(&manifest_path, &formatted)?;
        writeln!(writer, "Wrote to {}:\n\n{}", manifest_path.display(), formatted)?;
        return Ok(());
    }

    // Interactive mode
    writeln!(writer, "This utility will walk you through creating a package.json file.")?;
    writeln!(
        writer,
        "It only covers the most common items, and tries to guess sensible defaults.\n"
    )?;
    writeln!(writer, "See `npm help init` for definitive documentation on these fields")?;
    writeln!(writer, "and exactly what they do.\n")?;
    writeln!(writer, "Use `npm install <pkg>` afterwards to install a package and")?;
    writeln!(writer, "save it as a dependency in the package.json file.\n")?;
    writeln!(writer, "Press ^C at any time to quit.")?;

    let name = prompt_field("package name", &default_name, reader, writer)?;
    let version = prompt_field("version", &default_version, reader, writer)?;
    let description = prompt_field("description", &default_description, reader, writer)?;
    let entry_point = prompt_field("entry point", &default_main, reader, writer)?;
    let test_command = prompt_field("test command", &default_test, reader, writer)?;
    let git_repo = prompt_field("git repository", &default_repo, reader, writer)?;
    let keywords_str = prompt_field("keywords", &default_keywords, reader, writer)?;
    let author = prompt_field("author", &default_author, reader, writer)?;
    let license = prompt_field("license", &default_license, reader, writer)?;

    let mut map = if let Some(Value::Object(m)) = existing_val {
        m
    } else {
        serde_json::Map::new()
    };

    map.insert("name".to_string(), Value::String(name));
    map.insert("version".to_string(), Value::String(version));
    map.insert("description".to_string(), Value::String(description));
    map.insert("main".to_string(), Value::String(entry_point));

    let mut scripts_map = match map.remove("scripts") {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    if !test_command.is_empty() {
        scripts_map.insert("test".to_string(), Value::String(test_command));
    } else if !scripts_map.contains_key("test") {
        scripts_map.insert(
            "test".to_string(),
            Value::String("echo \"Error: no test specified\" && exit 1".to_string()),
        );
    }
    map.insert("scripts".to_string(), Value::Object(scripts_map));

    if !git_repo.is_empty() {
        let mut repo = serde_json::Map::new();
        repo.insert("type".to_string(), Value::String("git".to_string()));
        repo.insert("url".to_string(), Value::String(git_repo));
        map.insert("repository".to_string(), Value::Object(repo));
    }

    let keywords_vec: Vec<Value> = if !keywords_str.is_empty() {
        keywords_str
            .split([',', ' '])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect()
    } else if let Some(Value::Array(k)) = map.remove("keywords") {
        k
    } else {
        Vec::new()
    };
    map.insert("keywords".to_string(), Value::Array(keywords_vec));

    map.insert("author".to_string(), Value::String(author));
    map.insert("license".to_string(), Value::String(license));

    let mut formatted = serde_json::to_string_pretty(&Value::Object(map))?;
    formatted.push('\n');

    write!(
        writer,
        "About to write to {}:\n\n{}\n\nIs this OK? (yes) ",
        manifest_path.display(),
        formatted
    )?;
    writer.flush()?;

    let mut conf_line = String::new();
    let bytes_read = reader.read_line(&mut conf_line)?;
    let conf = conf_line.trim().to_ascii_lowercase();
    if bytes_read > 0 && (conf == "no" || conf == "n") {
        writeln!(writer, "npm notice canceled")?;
        return Ok(());
    }

    std::fs::create_dir_all(&options.directory)?;
    std::fs::write(&manifest_path, &formatted)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn test_transform_initializer_cases() {
        assert_eq!(transform_initializer("react-app"), "create-react-app");
        assert_eq!(transform_initializer("create-react-app"), "create-react-app");
        assert_eq!(transform_initializer("vite@latest"), "create-vite@latest");
        assert_eq!(transform_initializer("next-app@14.0.0"), "create-next-app@14.0.0");
        assert_eq!(transform_initializer("@scope/pkg"), "@scope/create-pkg");
        assert_eq!(transform_initializer("@scope/create-pkg"), "@scope/create-pkg");
        assert_eq!(transform_initializer("@scope"), "@scope/create");
        assert_eq!(transform_initializer("@scope/"), "@scope/create");
        assert_eq!(transform_initializer("@scope@latest"), "@scope/create@latest");
        assert_eq!(transform_initializer("@scope/bar@1.0.0"), "@scope/create-bar@1.0.0");
    }

    #[test]
    fn test_sanitize_package_name_and_scope() {
        assert_eq!(sanitize_package_name("My Awesome App"), "my-awesome-app");
        assert_eq!(sanitize_package_name("   ...my_lib--   "), "my_lib");
        assert_eq!(sanitize_package_name(""), "package");
        assert_eq!(apply_scope("foo", "@myorg"), "@myorg/foo");
        assert_eq!(apply_scope("foo", "myorg"), "@myorg/foo");
        assert_eq!(apply_scope("@old/foo", "@neworg"), "@neworg/foo");
    }

    #[test]
    fn test_run_init_non_interactive_yes() {
        let dir = tempdir().unwrap();
        let options = InitOptions {
            yes: true,
            scope: None,
            directory: dir.path().to_path_buf(),
        };

        let mut input = Cursor::new(Vec::new());
        let mut output = Vec::new();
        run_init(&options, &mut input, &mut output).unwrap();

        let manifest_path = dir.path().join("package.json");
        assert!(manifest_path.is_file());

        let json: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["description"], "");
        assert_eq!(json["main"], "index.js");
        assert_eq!(json["scripts"]["test"], "echo \"Error: no test specified\" && exit 1");
        assert_eq!(json["keywords"], Value::Array(vec![]));
        assert_eq!(json["author"], "");
        assert_eq!(json["license"], "ISC");
    }

    #[test]
    fn test_run_init_with_scope() {
        let dir = tempdir().unwrap();
        let options = InitOptions {
            yes: true,
            scope: Some("@testscope".to_string()),
            directory: dir.path().to_path_buf(),
        };

        let mut input = Cursor::new(Vec::new());
        let mut output = Vec::new();
        run_init(&options, &mut input, &mut output).unwrap();

        let manifest_path = dir.path().join("package.json");
        let json: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let name = json["name"].as_str().unwrap();
        assert!(name.starts_with("@testscope/"));
    }

    #[test]
    fn test_run_init_preserves_existing_package_json() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("package.json");
        std::fs::write(
            &manifest_path,
            r#"{
  "name": "custom-existing",
  "version": "3.2.1",
  "dependencies": {
    "chalk": "^4.0.0"
  }
}"#,
        ).unwrap();

        let options = InitOptions {
            yes: true,
            scope: None,
            directory: dir.path().to_path_buf(),
        };

        let mut input = Cursor::new(Vec::new());
        let mut output = Vec::new();
        run_init(&options, &mut input, &mut output).unwrap();

        let json: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(json["name"], "custom-existing");
        assert_eq!(json["version"], "3.2.1");
        assert_eq!(json["dependencies"]["chalk"], "^4.0.0");
        assert_eq!(json["main"], "index.js");
        assert_eq!(json["license"], "ISC");
    }

    #[test]
    fn test_run_init_interactive_accept() {
        let dir = tempdir().unwrap();
        let options = InitOptions {
            yes: false,
            scope: None,
            directory: dir.path().to_path_buf(),
        };

        let simulated_input = "my-interactive-pkg\n2.0.0\ncustom desc\nmain.js\nvitest\nhttps://github.com/org/repo.git\ncli, fast\nJane Doe\nMIT\nyes\n";
        let mut input = Cursor::new(simulated_input.as_bytes().to_vec());
        let mut output = Vec::new();

        run_init(&options, &mut input, &mut output).unwrap();

        let manifest_path = dir.path().join("package.json");
        assert!(manifest_path.is_file());

        let json: Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(json["name"], "my-interactive-pkg");
        assert_eq!(json["version"], "2.0.0");
        assert_eq!(json["description"], "custom desc");
        assert_eq!(json["main"], "main.js");
        assert_eq!(json["scripts"]["test"], "vitest");
        assert_eq!(json["repository"]["url"], "https://github.com/org/repo.git");
        assert_eq!(json["keywords"], serde_json::json!(["cli", "fast"]));
        assert_eq!(json["author"], "Jane Doe");
        assert_eq!(json["license"], "MIT");
    }

    #[test]
    fn test_run_init_interactive_cancel() {
        let dir = tempdir().unwrap();
        let options = InitOptions {
            yes: false,
            scope: None,
            directory: dir.path().to_path_buf(),
        };

        let simulated_input = "pkg\n1.0.0\n\n\n\n\n\n\n\nno\n";
        let mut input = Cursor::new(simulated_input.as_bytes().to_vec());
        let mut output = Vec::new();

        run_init(&options, &mut input, &mut output).unwrap();

        let manifest_path = dir.path().join("package.json");
        assert!(!manifest_path.exists());
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("npm notice canceled"));
    }
}
