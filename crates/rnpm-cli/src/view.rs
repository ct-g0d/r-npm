use std::collections::HashSet;
use std::path::Path;
use reqwest::{Method, StatusCode, Url};
use serde_json::Value;

use rnpm_config::Config;
use rnpm_core::semver::{Range, Version};
use rnpm_install::apply_npmrc_to_client_config;
use rnpm_registry::client::{encode_package_name, RegistryClient, RegistryClientConfig};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewOptions {
    pub args: Vec<String>,
    pub json: bool,
    pub registry: Option<String>,
}

/// Parse view options and CLI arguments.
///
/// Normalizes flags like `--json` or `--registry <url>` / `--registry=<url>` if passed inside `args`,
/// extracts target package name and optional version/dist-tag specifier, and collects any requested fields.
pub fn parse_view_options(
    options: &ViewOptions,
) -> Result<(String, Option<String>, Vec<String>, bool, Option<String>), String> {
    let mut effective_json = options.json;
    let mut effective_registry = options.registry.clone();
    let mut positional = Vec::new();

    let mut i = 0;
    while i < options.args.len() {
        let arg = &options.args[i];
        if arg == "--json" {
            effective_json = true;
        } else if arg == "--registry" {
            if i + 1 < options.args.len() {
                effective_registry = Some(options.args[i + 1].clone());
                i += 1;
            }
        } else if let Some(val) = arg.strip_prefix("--registry=") {
            effective_registry = Some(val.to_string());
        } else if !arg.starts_with('-') {
            positional.push(arg.clone());
        }
        i += 1;
    }

    if positional.is_empty() {
        return Err("Must provide a package name to view".to_string());
    }

    let first = &positional[0];
    let (pkg_name, spec) = if let Some(stripped) = first.strip_prefix('@') {
        if let Some(idx) = stripped.find('@') {
            let name = format!("@{}", &stripped[..idx]);
            let s = stripped[idx + 1..].trim();
            let spec_opt = if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            };
            (name, spec_opt)
        } else {
            (first.clone(), None)
        }
    } else if let Some(idx) = first.find('@') {
        let name = first[..idx].to_string();
        let s = first[idx + 1..].trim();
        let spec_opt = if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
        (name, spec_opt)
    } else {
        (first.clone(), None)
    };

    let fields = positional[1..].to_vec();
    Ok((pkg_name, spec, fields, effective_json, effective_registry))
}

/// Convenience helper for extracting package name, optional spec, and fields from raw args.
pub fn parse_view_args(args: &[String]) -> Result<(String, Option<String>, Vec<String>), String> {
    let opts = ViewOptions {
        args: args.to_vec(),
        json: false,
        registry: None,
    };
    let (pkg_name, spec, fields, _, _) = parse_view_options(&opts)?;
    Ok((pkg_name, spec, fields))
}

/// Main entrypoint for `rnpm view` / `info` / `v` / `show`.
pub async fn run_view(project_dir: &Path, options: &ViewOptions) -> anyhow::Result<i32> {
    let (pkg_name, spec, fields, json_mode, registry_opt) = match parse_view_options(options) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("npm error code EUSAGE");
            eprintln!("npm error {e}");
            return Ok(1);
        }
    };

    let config = Config::load(Some(project_dir)).unwrap_or_default();
    let registry_url = if let Some(reg) = &registry_opt {
        let mut u = Url::parse(reg)?;
        if !u.path().ends_with('/') {
            let p = format!("{}/", u.path());
            u.set_path(&p);
        }
        u
    } else {
        config.npmrc.registry_for_package(&pkg_name).clone()
    };

    let mut client_config = RegistryClientConfig::default();
    client_config.default_registry = registry_url.clone();
    client_config.scoped_registries = config.npmrc.scoped_registries.clone();
    client_config.auth_tokens = config.npmrc.auth_tokens.clone();
    if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
        client_config.auth_token = Some(token.to_string());
    }

    let mut trusted_hosts = HashSet::new();
    if let Some(h) = registry_url.host_str() {
        trusted_hosts.insert(h.to_ascii_lowercase());
    }
    for scoped_reg in config.npmrc.scoped_registries.values() {
        if let Some(h) = scoped_reg.host_str() {
            trusted_hosts.insert(h.to_ascii_lowercase());
            if let Some(p) = scoped_reg.port_or_known_default() {
                trusted_hosts.insert(format!("{}:{}", h.to_ascii_lowercase(), p));
            }
        }
    }
    client_config.trusted_hosts = trusted_hosts;

    apply_npmrc_to_client_config(&mut client_config, &config.npmrc);

    let client = RegistryClient::with_config(client_config)
        .map_err(|e| anyhow::anyhow!("Failed to initialize registry client: {e}"))?;

    let encoded_name = encode_package_name(&pkg_name);
    let base_str = registry_url.as_str().trim_end_matches('/');
    let packument_url = Url::parse(&format!("{base_str}/{encoded_name}"))?;

    let (resp, _permit) = match client
        .execute_with_permit(Method::GET, packument_url.clone(), Some("application/json"), None)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("npm error code EREGISTRY");
            eprintln!("npm error Failed to fetch package metadata: {e}");
            return Ok(1);
        }
    };

    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        eprintln!("npm error code E404");
        eprintln!("npm error 404 Not Found - GET {packument_url} - Not found");
        eprintln!("npm error '{pkg_name}' is not in this registry.");
        return Ok(1);
    }

    if !status.is_success() {
        eprintln!("npm error code EHTTP");
        eprintln!("npm error HTTP error {status} fetching {packument_url}");
        return Ok(1);
    }

    let packument: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("npm error code EJSONPARSE");
            eprintln!("npm error Failed to parse registry response as JSON: {e}");
            return Ok(1);
        }
    };

    let resolved_version = match resolve_packument_version(&packument, spec.as_deref()) {
        Ok(v) => v,
        Err(spec_str) => {
            eprintln!("npm error code ETARGET");
            eprintln!("npm error notarget No matching version found for {pkg_name}@{spec_str}.");
            eprintln!("npm error notarget In most cases you or one of your dependencies are requesting");
            eprintln!("npm error notarget a package version that doesn't exist.");
            return Ok(1);
        }
    };

    let version_doc = packument
        .get("versions")
        .and_then(|v| v.get(&resolved_version))
        .cloned()
        .unwrap_or_else(|| packument.clone());

    if fields.is_empty() {
        if json_mode {
            println!("{}", serde_json::to_string_pretty(&version_doc)?);
        } else {
            let summary = format_npm_summary(&pkg_name, &resolved_version, &version_doc, &packument);
            println!("{summary}");
        }
    } else if fields.len() == 1 {
        let field_path = &fields[0];
        let val = extract_field_value(field_path, &version_doc, &packument);
        match val {
            Some(v) => {
                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    println!("{}", format_single_field_text(&v));
                }
            }
            None => {
                if json_mode {
                    println!("null");
                }
            }
        }
    } else {
        let mut entries = Vec::new();
        let mut json_map = serde_json::Map::new();

        for field_path in &fields {
            if let Some(val) = extract_field_value(field_path, &version_doc, &packument) {
                json_map.insert(field_path.clone(), val.clone());
                entries.push((field_path.clone(), val));
            }
        }

        if json_mode {
            println!("{}", serde_json::to_string_pretty(&Value::Object(json_map))?);
        } else {
            println!("{}", format_multi_fields_text(&entries));
        }
    }

    Ok(0)
}

/// Resolve target version from packument dist-tags, exact versions, or semver ranges.
pub fn resolve_packument_version(packument: &Value, spec: Option<&str>) -> Result<String, String> {
    let dist_tags = packument.get("dist-tags").and_then(|t| t.as_object());
    let versions = packument.get("versions").and_then(|v| v.as_object());

    // 1. If no spec is specified, default to "latest" tag from dist-tags
    if spec.is_none() {
        if let Some(tags) = dist_tags {
            if let Some(tag_ver) = tags.get("latest").and_then(|v| v.as_str()) {
                return Ok(tag_ver.to_string());
            }
        }
        // Fallback if no "latest" tag: if versions exist, pick max version
        if let Some(vers) = versions {
            let mut all_versions = Vec::new();
            for k in vers.keys() {
                if let Ok(v) = Version::parse(k) {
                    all_versions.push((v, k.clone()));
                }
            }
            if let Some((_, max_k)) = all_versions.into_iter().max_by(|a, b| a.0.cmp(&b.0)) {
                return Ok(max_k);
            }
        }
        return Err("latest".to_string());
    }

    let target_spec = spec.unwrap().trim();

    // 2. Check if dist-tag matches (e.g. latest, next, beta)
    if let Some(tags) = dist_tags {
        if let Some(tag_ver) = tags.get(target_spec).and_then(|v| v.as_str()) {
            return Ok(tag_ver.to_string());
        }
    }

    // 3. Check if exact version matches in `versions`
    if let Some(vers) = versions {
        if vers.contains_key(target_spec) {
            return Ok(target_spec.to_string());
        }
        // Also check if target_spec parsed as Version matches
        if let Ok(parsed_target) = Version::parse(target_spec) {
            let parsed_str = parsed_target.to_string();
            if vers.contains_key(&parsed_str) {
                return Ok(parsed_str);
            }
        }
    }

    // 4. Check if SemVer range matches in `versions`
    if let (Some(vers), Ok(range)) = (versions, Range::parse(target_spec)) {
        let mut matching_versions = Vec::new();
        for (ver_str, _) in vers {
            if let Ok(v) = Version::parse(ver_str) {
                if range.satisfies(&v) {
                    matching_versions.push((v, ver_str.clone()));
                }
            }
        }

        if let Some((_, max_ver_str)) = matching_versions.into_iter().max_by(|a, b| a.0.cmp(&b.0)) {
            return Ok(max_ver_str);
        }
    }

    Err(target_spec.to_string())
}

/// Extract a field value using dot notation, checking version doc first, then root packument.
pub fn extract_field_value(field_path: &str, version_doc: &Value, packument: &Value) -> Option<Value> {
    let trimmed_path = field_path.trim();
    if trimmed_path.is_empty() {
        return None;
    }

    // Special root field: "versions" returns the array of all versions
    if trimmed_path == "versions" {
        if let Some(vers_map) = packument.get("versions").and_then(|v| v.as_object()) {
            let mut list: Vec<(Option<Version>, String)> = vers_map
                .keys()
                .map(|k| (Version::parse(k).ok(), k.clone()))
                .collect();
            list.sort_by(|a, b| match (&a.0, &b.0) {
                (Some(v1), Some(v2)) => v1.cmp(v2),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.1.cmp(&b.1),
            });
            let array_vals = list.into_iter().map(|(_, s)| Value::String(s)).collect();
            return Some(Value::Array(array_vals));
        } else if let Some(vers_arr) = packument.get("versions").and_then(|v| v.as_array()) {
            return Some(Value::Array(vers_arr.clone()));
        }
    }

    // 1. Check target version manifest first
    if let Some(val) = get_dot_path(version_doc, trimmed_path) {
        return Some(val.clone());
    }

    // 2. Check root packument
    if let Some(val) = get_dot_path(packument, trimmed_path) {
        return Some(val.clone());
    }

    None
}

fn get_dot_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(root);
    }

    match root {
        Value::Object(map) => {
            // First check if the entire remaining path is a direct key in map
            if let Some(val) = map.get(path) {
                return Some(val);
            }

            // Otherwise, try splitting by '.' from left to right
            for (idx, _) in path.match_indices('.') {
                let prefix = &path[..idx];
                let suffix = &path[idx + 1..];

                if let Some(child) = map.get(prefix) {
                    if let Some(val) = get_dot_path(child, suffix) {
                        return Some(val);
                    }
                }
            }
            None
        }
        Value::Array(arr) => {
            if let Some((prefix, suffix)) = path.split_once('.') {
                let idx: usize = prefix.parse().ok()?;
                let child = arr.get(idx)?;
                get_dot_path(child, suffix)
            } else {
                let idx: usize = path.parse().ok()?;
                arr.get(idx)
            }
        }
        _ => None,
    }
}

/// Format single field in text mode.
/// Strings are printed without surrounding quotes.
pub fn format_single_field_text(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else if arr.len() <= 3 && arr.iter().all(|x| x.is_string() || x.is_number()) {
                let items: Vec<String> = arr.iter().map(format_primitive_for_list).collect();
                format!("[ {} ]", items.join(", "))
            } else {
                let mut lines = Vec::new();
                lines.push("[".to_string());
                for (i, item) in arr.iter().enumerate() {
                    let formatted = format_primitive_for_list(item);
                    let comma = if i + 1 < arr.len() { "," } else { "" };
                    lines.push(format!("  {formatted}{comma}"));
                }
                lines.push("]".to_string());
                lines.join("\n")
            }
        }
        Value::Object(_) => serde_json::to_string_pretty(val).unwrap_or_default(),
    }
}

fn format_primitive_for_list(val: &Value) -> String {
    match val {
        Value::String(s) => format!("'{s}'"),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(val).unwrap_or_default(),
    }
}

/// Format multiple fields in text mode: `key = 'val'`.
pub fn format_multi_fields_text(entries: &[(String, Value)]) -> String {
    let mut lines = Vec::new();
    for (k, v) in entries {
        match v {
            Value::String(s) => lines.push(format!("{k} = '{s}'")),
            Value::Number(n) => lines.push(format!("{k} = {n}")),
            Value::Bool(b) => lines.push(format!("{k} = {b}")),
            Value::Null => lines.push(format!("{k} = null")),
            Value::Array(_) | Value::Object(_) => {
                let json_repr = serde_json::to_string(v).unwrap_or_default();
                lines.push(format!("{k} = {json_repr}"));
            }
        }
    }
    lines.join("\n")
}

/// Format human-readable npm-style package summary.
pub fn format_npm_summary(name: &str, version: &str, doc: &Value, packument: &Value) -> String {
    let mut lines = Vec::new();

    let license = doc
        .get("license")
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                Some(s.to_string())
            } else if let Some(obj) = v.as_object() {
                obj.get("type").and_then(|t| t.as_str()).map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "UNLICENSED".to_string());

    let deps_count = doc
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|m| m.len())
        .unwrap_or(0);
    let deps_str = if deps_count == 0 {
        "none".to_string()
    } else {
        deps_count.to_string()
    };

    let versions_count = packument
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|m| m.len())
        .unwrap_or(1);

    lines.push(format!(
        "{name}@{version} | {license} | deps: {deps_str} | versions: {versions_count}"
    ));

    if let Some(desc) = doc.get("description").and_then(|v| v.as_str()) {
        if !desc.trim().is_empty() {
            lines.push(desc.to_string());
        }
    }

    if let Some(homepage) = doc.get("homepage").and_then(|v| v.as_str()) {
        if !homepage.trim().is_empty() {
            lines.push(homepage.to_string());
        }
    }

    if let Some(keywords) = doc.get("keywords").and_then(|k| k.as_array()) {
        let kw_strs: Vec<&str> = keywords.iter().filter_map(|k| k.as_str()).collect();
        if !kw_strs.is_empty() {
            lines.push(String::new());
            lines.push(format!("keywords: {}", kw_strs.join(", ")));
        }
    }

    if let Some(dist) = doc.get("dist") {
        let has_tarball = dist.get("tarball").is_some();
        let has_shasum = dist.get("shasum").is_some();
        let has_integrity = dist.get("integrity").is_some();
        let has_unpacked = dist.get("unpackedSize").is_some();

        if has_tarball || has_shasum || has_integrity || has_unpacked {
            lines.push(String::new());
            lines.push("dist".to_string());
            if let Some(tarball) = dist.get("tarball").and_then(|v| v.as_str()) {
                lines.push(format!(".tarball: {tarball}"));
            }
            if let Some(shasum) = dist.get("shasum").and_then(|v| v.as_str()) {
                lines.push(format!(".shasum: {shasum}"));
            }
            if let Some(integrity) = dist.get("integrity").and_then(|v| v.as_str()) {
                lines.push(format!(".integrity: {integrity}"));
            }
            if let Some(unpacked_val) = dist.get("unpackedSize") {
                let formatted = if let Some(u) = unpacked_val.as_u64() {
                    format_bytes(u, true)
                } else if let Some(f) = unpacked_val.as_f64() {
                    format_bytes(f as u64, true)
                } else if let Some(s) = unpacked_val.as_str() {
                    s.to_string()
                } else {
                    unpacked_val.to_string()
                };
                lines.push(format!(".unpackedSize: {formatted}"));
            }
        }
    }

    let maintainers_opt = doc
        .get("maintainers")
        .or_else(|| packument.get("maintainers"))
        .and_then(|m| m.as_array());

    if let Some(maintainers) = maintainers_opt {
        if !maintainers.is_empty() {
            lines.push(String::new());
            lines.push("maintainers:".to_string());
            for m in maintainers {
                if let Some(s) = m.as_str() {
                    lines.push(format!("- {s}"));
                } else if let Some(obj) = m.as_object() {
                    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let email = obj.get("email").and_then(|v| v.as_str());
                    if let Some(em) = email {
                        if !em.is_empty() {
                            lines.push(format!("- {name} <{em}>"));
                        } else {
                            lines.push(format!("- {name}"));
                        }
                    } else {
                        lines.push(format!("- {name}"));
                    }
                }
            }
        }
    }

    if let Some(tags) = packument.get("dist-tags").and_then(|t| t.as_object()) {
        if !tags.is_empty() {
            lines.push(String::new());
            lines.push("dist-tags:".to_string());
            for (tag, v) in tags {
                if let Some(v_str) = v.as_str() {
                    lines.push(format!("{tag}: {v_str}"));
                } else {
                    lines.push(format!("{tag}: {v}"));
                }
            }
        }
    }

    let time_val = packument
        .get("time")
        .and_then(|t| t.get(version))
        .and_then(|v| v.as_str());

    let publisher_val = doc
        .get("_npmUser")
        .and_then(|u| {
            let name = u
                .get("name")
                .or_else(|| u.get("username"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let email = u.get("email").and_then(|v| v.as_str());
            if let Some(em) = email {
                if !em.is_empty() {
                    Some(format!("{name} <{em}>"))
                } else {
                    Some(name.to_string())
                }
            } else if !name.is_empty() {
                Some(name.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            doc.get("publisher")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            maintainers_opt.and_then(|m| m.first()).and_then(|first_m| {
                if let Some(s) = first_m.as_str() {
                    Some(s.to_string())
                } else if let Some(obj) = first_m.as_object() {
                    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let email = obj.get("email").and_then(|v| v.as_str());
                    if let Some(em) = email {
                        Some(format!("{name} <{em}>"))
                    } else {
                        Some(name.to_string())
                    }
                } else {
                    None
                }
            })
        });

    if let Some(t) = time_val {
        lines.push(String::new());
        if let Some(p) = publisher_val {
            lines.push(format!("published {t} by {p}"));
        } else {
            lines.push(format!("published {t}"));
        }
    }

    lines.join("\n")
}

pub fn format_bytes(bytes: u64, space: bool) -> String {
    let spacer = if space { " " } else { "" };
    if bytes < 1000 {
        format!("{bytes}{spacer}B")
    } else if bytes < 999_950 {
        format!("{:.1}{spacer}kB", bytes as f64 / 1000.0)
    } else if bytes < 999_950_000 {
        format!("{:.1}{spacer}MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.1}{spacer}GB", bytes as f64 / 1_000_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct MockServer {
        port: u16,
        _shutdown: tokio::sync::oneshot::Sender<()>,
    }

    impl MockServer {
        async fn start<F>(handler: F) -> Self
        where
            F: Fn(&str, &str) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
            let handler = Arc::new(handler);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => break,
                        accept_res = listener.accept() => {
                            if let Ok((mut stream, _)) = accept_res {
                                let h = handler.clone();
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 8192];
                                    let n = stream.read(&mut buf).await.unwrap_or(0);
                                    if n > 0 {
                                        let req_str = String::from_utf8_lossy(&buf[..n]);
                                        let mut lines = req_str.lines();
                                        let req_line = lines.next().unwrap_or("");
                                        let parts: Vec<&str> = req_line.split_whitespace().collect();
                                        let method = parts.first().copied().unwrap_or("GET");
                                        let path = parts.get(1).copied().unwrap_or("/");

                                        let (status, headers, body) = h(method, path);
                                        let status_text = match status {
                                            200 => "OK",
                                            404 => "Not Found",
                                            500 => "Internal Server Error",
                                            _ => "Response",
                                        };
                                        let mut resp = format!(
                                            "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                            body.len()
                                        );
                                        for (k, v) in headers {
                                            resp.push_str(&format!("{k}: {v}\r\n"));
                                        }
                                        resp.push_str("\r\n");
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                        let _ = stream.write_all(&body).await;
                                        let _ = stream.flush().await;
                                    }
                                });
                            }
                        }
                    }
                }
            });

            Self {
                port,
                _shutdown: tx,
            }
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    #[test]
    fn test_parse_view_args_variations() {
        let (name, spec, fields) = parse_view_args(&["react".to_string()]).unwrap();
        assert_eq!(name, "react");
        assert_eq!(spec, None);
        assert!(fields.is_empty());

        let (name, spec, fields) =
            parse_view_args(&["react@18.2.0".to_string(), "versions".to_string()]).unwrap();
        assert_eq!(name, "react");
        assert_eq!(spec, Some("18.2.0".to_string()));
        assert_eq!(fields, vec!["versions"]);

        let (name, spec, fields) = parse_view_args(&[
            "@scope/pkg@^2.0.0".to_string(),
            "dist-tags.latest".to_string(),
        ])
        .unwrap();
        assert_eq!(name, "@scope/pkg");
        assert_eq!(spec, Some("^2.0.0".to_string()));
        assert_eq!(fields, vec!["dist-tags.latest"]);

        let (name, spec, fields) = parse_view_args(&["@scope/pkg".to_string()]).unwrap();
        assert_eq!(name, "@scope/pkg");
        assert_eq!(spec, None);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_parse_view_options_flags() {
        let opts = ViewOptions {
            args: vec![
                "chalk".to_string(),
                "--json".to_string(),
                "name".to_string(),
                "version".to_string(),
            ],
            json: false,
            registry: None,
        };
        let (name, spec, fields, json, reg) = parse_view_options(&opts).unwrap();
        assert_eq!(name, "chalk");
        assert_eq!(spec, None);
        assert_eq!(fields, vec!["name", "version"]);
        assert!(json);
        assert_eq!(reg, None);

        let opts2 = ViewOptions {
            args: vec![
                "--registry".to_string(),
                "https://custom.reg".to_string(),
                "lodash@4.17.21".to_string(),
            ],
            json: true,
            registry: None,
        };
        let (name, spec, fields, json, reg) = parse_view_options(&opts2).unwrap();
        assert_eq!(name, "lodash");
        assert_eq!(spec, Some("4.17.21".to_string()));
        assert!(fields.is_empty());
        assert!(json);
        assert_eq!(reg, Some("https://custom.reg".to_string()));
    }

    #[test]
    fn test_resolve_packument_version_dist_tags_and_ranges() {
        let packument = serde_json::json!({
            "name": "chalk",
            "dist-tags": {
                "latest": "4.1.2",
                "next": "5.0.0-beta.1"
            },
            "versions": {
                "2.4.2": { "version": "2.4.2" },
                "4.1.0": { "version": "4.1.0" },
                "4.1.2": { "version": "4.1.2" },
                "5.0.0-beta.1": { "version": "5.0.0-beta.1" }
            }
        });

        assert_eq!(resolve_packument_version(&packument, None).unwrap(), "4.1.2");
        assert_eq!(
            resolve_packument_version(&packument, Some("latest")).unwrap(),
            "4.1.2"
        );
        assert_eq!(
            resolve_packument_version(&packument, Some("next")).unwrap(),
            "5.0.0-beta.1"
        );
        assert_eq!(
            resolve_packument_version(&packument, Some("2.4.2")).unwrap(),
            "2.4.2"
        );
        assert_eq!(
            resolve_packument_version(&packument, Some("^4.0.0")).unwrap(),
            "4.1.2"
        );
        assert_eq!(
            resolve_packument_version(&packument, Some(">=2.0.0 <4.0.0")).unwrap(),
            "2.4.2"
        );
        assert!(resolve_packument_version(&packument, Some("^6.0.0")).is_err());
    }

    #[test]
    fn test_extract_field_value_dot_notation() {
        let version_doc = serde_json::json!({
            "name": "express",
            "version": "4.18.2",
            "repository": {
                "type": "git",
                "url": "git+https://github.com/expressjs/express.git"
            },
            "dependencies": {
                "accepts": "~1.3.8",
                "qs": "6.11.0"
            }
        });

        let packument = serde_json::json!({
            "dist-tags": {
                "latest": "4.18.2"
            },
            "versions": {
                "4.18.1": {},
                "4.18.2": {}
            },
            "time": {
                "modified": "2023-01-01T00:00:00.000Z",
                "4.18.2": "2022-10-08T00:00:00.000Z"
            }
        });

        let url_val = extract_field_value("repository.url", &version_doc, &packument).unwrap();
        assert_eq!(
            url_val.as_str().unwrap(),
            "git+https://github.com/expressjs/express.git"
        );

        let tag_val = extract_field_value("dist-tags.latest", &version_doc, &packument).unwrap();
        assert_eq!(tag_val.as_str().unwrap(), "4.18.2");

        let dep_val = extract_field_value("dependencies.qs", &version_doc, &packument).unwrap();
        assert_eq!(dep_val.as_str().unwrap(), "6.11.0");

        let time_val = extract_field_value("time.4.18.2", &version_doc, &packument).unwrap();
        assert_eq!(time_val.as_str().unwrap(), "2022-10-08T00:00:00.000Z");

        let vers_val = extract_field_value("versions", &version_doc, &packument).unwrap();
        let arr = vers_val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str().unwrap(), "4.18.1");
        assert_eq!(arr[1].as_str().unwrap(), "4.18.2");
    }

    #[test]
    fn test_formatting_single_and_multi_fields() {
        let single_str = Value::String("6.0.1".to_string());
        assert_eq!(format_single_field_text(&single_str), "6.0.1");

        let arr = serde_json::json!(["react", "ui"]);
        let formatted_arr = format_single_field_text(&arr);
        assert!(formatted_arr.contains("'react'"));
        assert!(formatted_arr.contains("'ui'"));

        let entries = vec![
            ("name".to_string(), Value::String("chalk".to_string())),
            ("version".to_string(), Value::String("2.4.2".to_string())),
        ];
        let multi_text = format_multi_fields_text(&entries);
        assert_eq!(multi_text, "name = 'chalk'\nversion = '2.4.2'");
    }

    #[test]
    fn test_format_npm_summary_structure() {
        let version_doc = serde_json::json!({
            "name": "chalk",
            "version": "2.4.2",
            "description": "Terminal string styling done right",
            "homepage": "https://github.com/chalk/chalk#readme",
            "license": "MIT",
            "keywords": ["color", "colour", "ansi"],
            "dependencies": {
                "ansi-styles": "^3.2.1",
                "escape-string-regexp": "^1.0.5",
                "supports-color": "^5.3.0"
            },
            "dist": {
                "tarball": "https://registry.npmjs.org/chalk/-/chalk-2.4.2.tgz",
                "shasum": "cd42541677a54333cf541a49108c1432b44c9424",
                "integrity": "sha512-M8vU4...==",
                "unpackedSize": 30000
            },
            "maintainers": [
                { "name": "sindresorhus", "email": "sindresorhus@gmail.com" }
            ],
            "_npmUser": {
                "name": "sindresorhus",
                "email": "sindresorhus@gmail.com"
            }
        });

        let packument = serde_json::json!({
            "name": "chalk",
            "dist-tags": {
                "latest": "2.4.2"
            },
            "versions": {
                "2.4.2": {}
            },
            "time": {
                "2.4.2": "2018-12-14T10:00:00.000Z"
            }
        });

        let summary = format_npm_summary("chalk", "2.4.2", &version_doc, &packument);
        assert!(summary.contains("chalk@2.4.2 | MIT | deps: 3 | versions: 1"));
        assert!(summary.contains("Terminal string styling done right"));
        assert!(summary.contains("https://github.com/chalk/chalk#readme"));
        assert!(summary.contains("keywords: color, colour, ansi"));
        assert!(summary.contains("dist"));
        assert!(summary.contains(".tarball: https://registry.npmjs.org/chalk/-/chalk-2.4.2.tgz"));
        assert!(summary.contains(".shasum: cd42541677a54333cf541a49108c1432b44c9424"));
        assert!(summary.contains(".integrity: sha512-M8vU4...=="));
        assert!(summary.contains(".unpackedSize: 30.0 kB"));
        assert!(summary.contains("maintainers:"));
        assert!(summary.contains("- sindresorhus <sindresorhus@gmail.com>"));
        assert!(summary.contains("dist-tags:"));
        assert!(summary.contains("latest: 2.4.2"));
        assert!(summary.contains("published 2018-12-14T10:00:00.000Z by sindresorhus <sindresorhus@gmail.com>"));
    }

    #[tokio::test]
    async fn test_run_view_full_manifest_and_json() {
        let packument_json = serde_json::json!({
            "name": "mock-pkg",
            "dist-tags": {
                "latest": "1.0.0"
            },
            "versions": {
                "1.0.0": {
                    "name": "mock-pkg",
                    "version": "1.0.0",
                    "description": "Mock package for view tests",
                    "license": "ISC",
                    "dist": {
                        "tarball": "http://127.0.0.1/mock.tgz"
                    }
                }
            }
        });

        let packument_bytes = serde_json::to_vec(&packument_json).unwrap();
        let server = MockServer::start(move |_method, path| {
            if path == "/mock-pkg" {
                (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    packument_bytes.clone(),
                )
            } else {
                (404, vec![], b"Not Found".to_vec())
            }
        })
        .await;

        let temp_dir = tempfile::tempdir().unwrap();

        // 1. Text mode full manifest
        let opts = ViewOptions {
            args: vec!["mock-pkg".to_string()],
            json: false,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 0);

        // 2. JSON mode full manifest
        let opts_json = ViewOptions {
            args: vec!["mock-pkg".to_string()],
            json: true,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts_json).await.unwrap();
        assert_eq!(code, 0);

        // 3. Single field text mode
        let opts_field = ViewOptions {
            args: vec!["mock-pkg".to_string(), "version".to_string()],
            json: false,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts_field).await.unwrap();
        assert_eq!(code, 0);

        // 4. Multiple fields json mode
        let opts_multi = ViewOptions {
            args: vec![
                "mock-pkg".to_string(),
                "name".to_string(),
                "version".to_string(),
            ],
            json: true,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts_multi).await.unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn test_run_view_not_found_e404() {
        let server = MockServer::start(|_method, _path| (404, vec![], b"Not Found".to_vec())).await;
        let temp_dir = tempfile::tempdir().unwrap();

        let opts = ViewOptions {
            args: vec!["missing-pkg".to_string()],
            json: false,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn test_run_view_version_not_found_etarget() {
        let packument_json = serde_json::json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": { "name": "pkg", "version": "1.0.0" }
            }
        });
        let bytes = serde_json::to_vec(&packument_json).unwrap();
        let server = MockServer::start(move |_method, _path| {
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                bytes.clone(),
            )
        })
        .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let opts = ViewOptions {
            args: vec!["pkg@^2.0.0".to_string()],
            json: false,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn test_run_view_scoped_package_and_range() {
        let packument_json = serde_json::json!({
            "name": "@myorg/tool",
            "dist-tags": { "latest": "2.1.0" },
            "versions": {
                "1.0.0": { "name": "@myorg/tool", "version": "1.0.0" },
                "2.0.0": { "name": "@myorg/tool", "version": "2.0.0" },
                "2.1.0": { "name": "@myorg/tool", "version": "2.1.0" }
            }
        });
        let bytes = serde_json::to_vec(&packument_json).unwrap();
        let server = MockServer::start(move |_method, path| {
            if path == "/@myorg%2ftool" {
                (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    bytes.clone(),
                )
            } else {
                (404, vec![], b"Not found".to_vec())
            }
        })
        .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let opts = ViewOptions {
            args: vec![
                "@myorg/tool@^2.0.0".to_string(),
                "dist-tags.latest".to_string(),
            ],
            json: false,
            registry: Some(server.url()),
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn test_run_view_empty_args_eusage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let opts = ViewOptions {
            args: vec![],
            json: false,
            registry: None,
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn test_run_view_scoped_registry_from_npmrc() {
        let packument_json = serde_json::json!({
            "name": "@scoped/my-lib",
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": { "name": "@scoped/my-lib", "version": "1.2.3" }
            }
        });
        let bytes = serde_json::to_vec(&packument_json).unwrap();
        let server = MockServer::start(move |_method, path| {
            if path == "/@scoped%2fmy-lib" {
                (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    bytes.clone(),
                )
            } else {
                (404, vec![], b"Not Found".to_vec())
            }
        })
        .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let npmrc_path = temp_dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, format!("@scoped:registry = {}\n", server.url())).unwrap();

        let opts = ViewOptions {
            args: vec!["@scoped/my-lib".to_string(), "version".to_string()],
            json: false,
            registry: None,
        };
        let code = run_view(temp_dir.path(), &opts).await.unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_format_npm_summary_no_deps_and_maintainers_fallback() {
        let version_doc = serde_json::json!({
            "name": "zero-deps",
            "version": "1.0.0",
            "maintainers": ["Alice <alice@example.com>"],
            "publisher": { "name": "Alice" }
        });

        let packument = serde_json::json!({
            "name": "zero-deps",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {}
            },
            "time": {
                "1.0.0": "2024-01-01T12:00:00.000Z"
            }
        });

        let summary = format_npm_summary("zero-deps", "1.0.0", &version_doc, &packument);
        assert!(summary.contains("zero-deps@1.0.0 | UNLICENSED | deps: none | versions: 1"));
        assert!(summary.contains("maintainers:\n- Alice <alice@example.com>"));
        assert!(summary.contains("published 2024-01-01T12:00:00.000Z by Alice"));
    }

    #[test]
    fn test_formatting_primitive_and_object_fields() {
        let num = Value::Number(serde_json::Number::from(42));
        assert_eq!(format_single_field_text(&num), "42");

        let b = Value::Bool(true);
        assert_eq!(format_single_field_text(&b), "true");

        let null_val = Value::Null;
        assert_eq!(format_single_field_text(&null_val), "null");

        let obj = serde_json::json!({
            "type": "git",
            "url": "git+https://example.com"
        });
        let formatted_obj = format_single_field_text(&obj);
        assert!(formatted_obj.contains("\"type\": \"git\""));
        assert!(formatted_obj.contains("\"url\": \"git+https://example.com\""));
    }
}
