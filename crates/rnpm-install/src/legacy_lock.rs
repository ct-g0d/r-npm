//! npm's `#inflateAncientLockfile` (arborist build-ideal-tree.js).
//!
//! A lockfileVersion 1 entry carries only version/resolved/integrity/flags and
//! a `requires` map that cannot tell regular, optional and peer edges apart.
//! npm replaces every such entry's package data with the abbreviated
//! (`fullMetadata: false`) manifest of the locked version before building the
//! ideal tree. That manifest has no `license` and no `libc`, so unchanged
//! entries keep neither when the lock is rewritten.

use std::collections::{BTreeMap, HashSet};

use rnpm_lockfile::{LockfilePackage, LockfileV3, PackageBin, PackageEngines};
use rnpm_registry::metadata::AbbreviatedVersion;
use rnpm_registry::RegistryClient;
use serde::Deserialize;

#[derive(Deserialize)]
struct Header {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<serde_json::Value>,
    #[serde(default)]
    requires: Option<serde_json::Value>,
}

fn header(raw: &str) -> Option<Header> {
    serde_json::from_str(raw).ok()
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn parse_json_string_end(bytes: &[u8], quote_idx: usize) -> Option<usize> {
    let mut i = quote_idx + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            return Some(i + 1);
        } else if b < 0x20 {
            return None;
        }
        i += 1;
    }
    None
}

fn skip_json_value(bytes: &[u8], start: usize) -> Option<usize> {
    let i = skip_ws(bytes, start);
    let &first = bytes.get(i)?;
    match first {
        b'"' => parse_json_string_end(bytes, i),
        b'{' | b'[' => {
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < bytes.len() {
                match bytes[j] {
                    b'"' => j = parse_json_string_end(bytes, j)?,
                    b'{' | b'[' => {
                        depth += 1;
                        j += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        j += 1;
                        if depth == 0 {
                            return Some(j);
                        }
                    }
                    b'/' => return None,
                    _ => j += 1,
                }
            }
            None
        }
        b't' => bytes[i..].starts_with(b"true").then_some(i + 4),
        b'f' => bytes[i..].starts_with(b"false").then_some(i + 5),
        b'n' => bytes[i..].starts_with(b"null").then_some(i + 4),
        b'-' | b'0'..=b'9' => {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || matches!(bytes[j], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                j += 1;
            }
            Some(j)
        }
        _ => None,
    }
}

fn scan_top_level_lockfile_version(raw: &str) -> Option<u32> {
    let bytes = raw.strip_prefix('\u{feff}').unwrap_or(raw).as_bytes();
    let mut i = skip_ws(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i = skip_ws(bytes, i + 1);
    if bytes.get(i) == Some(&b'}') {
        return None;
    }

    let mut found_version: Option<u32> = None;
    loop {
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        let key_start = i + 1;
        let after_key = parse_json_string_end(bytes, i)?;
        let key = &bytes[key_start..after_key - 1];
        i = skip_ws(bytes, after_key);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(bytes, i + 1);

        if key == b"lockfileVersion" {
            if bytes.get(i) == Some(&b'"') {
                let end = parse_json_string_end(bytes, i)?;
                let inner = &bytes[i + 1..end - 1];
                if inner.is_empty() || !inner.iter().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                found_version = std::str::from_utf8(inner).ok()?.parse::<u32>().ok();
                i = end;
            } else {
                let vs = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i == vs {
                    return None;
                }
                found_version = std::str::from_utf8(&bytes[vs..i]).ok()?.parse::<u32>().ok();
            }
        } else {
            i = skip_json_value(bytes, i)?;
        }

        i = skip_ws(bytes, i);
        match bytes.get(i) {
            Some(&b',') => {
                i = skip_ws(bytes, i + 1);
            }
            Some(&b'}') => {
                let tail = skip_ws(bytes, i + 1);
                return if tail == bytes.len() {
                    found_version
                } else {
                    None
                };
            }
            _ => return None,
        }
    }
}

/// Extract `lockfileVersion` from raw lockfile JSON text.
pub fn detect_lockfile_version(raw: &str) -> Option<u32> {
    if let Some(v) = scan_top_level_lockfile_version(raw) {
        return Some(v);
    }
    header(raw).and_then(|h| match h.lockfile_version? {
        serde_json::Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        serde_json::Value::String(s) => s.parse::<u32>().ok(),
        _ => None,
    })
}

/// True when the raw lockfile text predates lockfileVersion 2.
pub(crate) fn is_old_lockfile(raw: &str) -> bool {
    detect_lockfile_version(raw).is_some_and(|v| v < 2)
}

/// Shrinkwrap's `ancientLockfile`: a pre-v2 lock whose `requires` is falsy.
pub(crate) fn is_ancient_lockfile(raw: &str) -> bool {
    let Some(h) = header(raw) else { return false; };
    let truthy = match h.requires {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => b,
        Some(serde_json::Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    };
    detect_lockfile_version(raw).is_some_and(|v| v < 2) && !truthy
}

/// npm's warning before inflating an old lock. Shrinkwrap's
/// `ancientLockfile` (a pre-v2 lock without `requires`) changes the heading.
pub(crate) fn old_lockfile_warning(raw: &str, file_name: &str) -> String {
    let ancient = is_ancient_lockfile(raw);
    let heading = if ancient {
        "ancient lockfile"
    } else {
        "old lockfile"
    };
    [
        String::new(),
        format!("The {file_name} file was created with an old version of npm,"),
        "so supplemental metadata must be fetched from the registry.".into(),
        String::new(),
        "This is a one-time fix-up, please be patient...".into(),
        String::new(),
    ]
    .iter()
    .map(|line| format!("npm warn {heading} {line}").trim_end().to_string())
    .collect::<Vec<_>>()
    .join(
        "
",
    )
}

/// Package name for a hydratable registry entry, or `None` for the root,
/// links, link targets outside node_modules, and non-registry versions.
fn registry_entry_name(location: &str, pkg: &LockfilePackage) -> Option<String> {
    if location.is_empty() || pkg.link == Some(true) || !location.starts_with("node_modules/") {
        return None;
    }
    let version = pkg.version.as_deref()?;
    if version.contains(':') || version.contains('/') {
        return None;
    }
    pkg.name.clone().or_else(|| {
        location
            .rsplit_once("node_modules/")
            .map(|(_, name)| name.to_string())
    })
}

/// Hydrate every registry entry of a migrated v1 lock in place. Fetch failures
/// leave the entry as migrated, as npm does. Returns the hydrated locations.
pub(crate) async fn hydrate_old_lockfile(
    client: &RegistryClient,
    lockfile: &mut LockfileV3,
    skip_names: &HashSet<String>,
) -> HashSet<String> {
    let mut names: Vec<String> = lockfile
        .packages
        .iter()
        .filter_map(|(loc, pkg)| registry_entry_name(loc, pkg))
        .filter(|name| !skip_names.contains(name))
        .collect();
    names.sort();
    names.dedup();

    let fetched: BTreeMap<String, _> = names
        .iter()
        .cloned()
        .zip(client.get_package_metadata_concurrent(&names).await)
        .filter_map(|(name, res)| match res {
            Ok(meta) => Some((name, meta)),
            Err(err) => {
                tracing::warn!("old lockfile: Could not fetch metadata for {name}: {err}");
                None
            }
        })
        .collect();

    let mut hydrated = HashSet::new();
    for (loc, pkg) in &mut lockfile.packages {
        let Some(name) = registry_entry_name(loc, pkg) else {
            continue;
        };
        let version = pkg.version.as_deref().unwrap_or_default();
        if let Some(manifest) = fetched.get(&name).and_then(|m| m.versions.get(version)) {
            apply_manifest(pkg, manifest);
            hydrated.insert(loc.clone());
        }
    }
    hydrated
}

/// Replace a lock entry's package data with an abbreviated manifest, keeping
/// its identity (version/resolved/integrity) and dependency flags.
fn apply_manifest(pkg: &mut LockfilePackage, m: &AbbreviatedVersion) {
    fn map<'a>(
        src: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Option<BTreeMap<String, String>> {
        let map: BTreeMap<_, _> = src
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        (!map.is_empty()).then_some(map)
    }
    pkg.raw_value = None;

    // An optional declaration supersedes the same key in `dependencies`.
    pkg.dependencies = map(m
        .dependencies
        .iter()
        .filter(|(k, _)| !m.optional_dependencies.contains_key(*k)));
    pkg.optional_dependencies = map(&m.optional_dependencies);
    pkg.peer_dependencies = map(&m.peer_dependencies);
    pkg.peer_dependencies_meta = (!m.peer_dependencies_meta.is_empty()).then(|| {
        m.peer_dependencies_meta
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or_default()))
            .collect()
    });
    pkg.dev_dependencies = None;
    pkg.bundle_dependencies = (!m.bundle_dependencies.is_empty())
        .then(|| rnpm_lockfile::BundledDependencies::List(m.bundle_dependencies.clone()));

    pkg.os = (!m.os.is_empty()).then(|| m.os.clone());
    pkg.cpu = (!m.cpu.is_empty()).then(|| m.cpu.clone());
    pkg.libc = (!m.libc.is_empty()).then(|| m.libc.clone());
    pkg.license = m.license.clone();
    pkg.engines = m
        .engines_raw
        .clone()
        .and_then(|raw| serde_json::from_value::<PackageEngines>(raw).ok())
        .or_else(|| {
            (!m.engines.is_empty()).then(|| {
                PackageEngines::Map(
                    m.engines
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
            })
        })
        .filter(|e| !e.is_empty());
    pkg.bin = m.bin.as_ref().and_then(|bin| normalize_bin(bin, &m.name));
    pkg.has_install_script = m.has_install_script.then_some(true);

    pkg.extra.remove("funding");
    pkg.extra.remove("deprecated");
    if let Some(funding) = m.extra.get("funding") {
        let funding = match funding.as_str() {
            Some(url) => serde_json::json!({ "url": url }),
            None => funding.clone(),
        };
        pkg.extra.insert("funding".into(), funding);
    }
    if let Some(deprecated) = m.deprecated.as_ref().filter(|d| !d.is_empty()) {
        pkg.extra
            .insert("deprecated".into(), serde_json::json!(deprecated));
    }
}

/// npm-normalize-package-bin: a string bin is keyed by the unscoped name and
/// leading `./` is dropped; an empty map is no bin at all.
fn normalize_bin(bin: &rnpm_registry::metadata::PackageBin, name: &str) -> Option<PackageBin> {
    let clean = |p: &str| p.strip_prefix("./").unwrap_or(p).to_string();
    let map: BTreeMap<String, String> = match bin {
        rnpm_registry::metadata::PackageBin::Single(path) => {
            let bin_name = name.rsplit('/').next().unwrap_or(name);
            BTreeMap::from([(bin_name.to_string(), clean(path))])
        }
        rnpm_registry::metadata::PackageBin::Map(m) => {
            m.iter().map(|(k, v)| (k.clone(), clean(v))).collect()
        }
    };
    (!map.is_empty()).then_some(PackageBin::Map(map))
}

/// Undo later enrichment (installed manifests, full packuments) on entries
/// that are still the hydrated v1 nodes: npm writes those from the abbreviated
/// manifest. Flags come from the new tree.
pub(crate) fn restore_hydrated_entries(
    lockfile: &mut LockfileV3,
    hydrated_lock: &LockfileV3,
    hydrated: &HashSet<String>,
) {
    for loc in hydrated {
        let (Some(pkg), Some(old)) = (
            lockfile.packages.get_mut(loc),
            hydrated_lock.packages.get(loc),
        ) else {
            continue;
        };
        if pkg.version != old.version
            || pkg.resolved != old.resolved
            || pkg.integrity != old.integrity
        {
            continue;
        }
        let mut restored = old.clone();
        restored.dev = pkg.dev;
        restored.optional = pkg.optional;
        restored.dev_optional = pkg.dev_optional;
        restored.peer = pkg.peer;
        restored.peer_optional = pkg.peer_optional;
        restored.in_bundle = pkg.in_bundle;
        restored.extraneous = pkg.extraneous;
        *pkg = restored;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_pre_v2_lockfiles() {
        assert!(is_old_lockfile(r#"{"lockfileVersion":1}"#));
        assert!(!is_old_lockfile(r#"{"lockfileVersion":2}"#));
        assert!(!is_old_lockfile(r#"{"lockfileVersion":3}"#));
        assert!(!is_old_lockfile("not json"));
        // JavaScript truthiness for `requires`, not a strict bool.
        assert!(is_old_lockfile(r#"{"lockfileVersion":1,"requires":1}"#));
        assert!(!is_ancient_lockfile(
            r#"{"lockfileVersion":1,"requires":1}"#
        ));
        assert!(is_ancient_lockfile(r#"{"lockfileVersion":1,"requires":0}"#));
    }

    #[test]
    fn warning_names_the_file_and_ancient_heading() {
        let old = old_lockfile_warning(
            r#"{"lockfileVersion":1,"requires":true}"#,
            "npm-shrinkwrap.json",
        );
        assert!(old.starts_with(
            "npm warn old lockfile
npm warn old lockfile The npm-shrinkwrap.json file"
        ));
        assert!(old.ends_with(
            "patient...
npm warn old lockfile"
        ));
        let ancient = old_lockfile_warning(r#"{"lockfileVersion":1}"#, "package-lock.json");
        assert!(ancient.starts_with(
            "npm warn ancient lockfile
"
        ));
    }

    #[test]
    fn abbreviated_manifest_replaces_v1_requires() {
        let lock = rnpm_lockfile::parse_and_migrate(
            r#"{"name":"root","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{
                "owner":{"version":"1.0.0","resolved":"https://r/owner-1.0.0.tgz","integrity":"sha512-x","optional":true,
                         "requires":{"native":"1.0.0","shared":"^1.0.0"}}}}"#,
        )
        .unwrap();
        let manifest: AbbreviatedVersion = serde_json::from_value(serde_json::json!({
            "name": "owner", "version": "1.0.0", "license": null,
            "dependencies": {"native": "1.0.0", "shared": "^1.0.0"},
            "optionalDependencies": {"native": "1.0.0"},
            "peerDependencies": {"peer": "*"},
            "peerDependenciesMeta": {"peer": {"optional": true}},
            "os": ["darwin"], "bin": "./cli.js",
            "funding": "https://example.invalid/fund"
        }))
        .unwrap();
        let mut pkg = lock.packages["node_modules/owner"].clone();
        apply_manifest(&mut pkg, &manifest);

        let deps = |m: &[(&str, &str)]| {
            Some(
                m.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        };
        assert_eq!(pkg.dependencies, deps(&[("shared", "^1.0.0")]));
        assert_eq!(pkg.optional_dependencies, deps(&[("native", "1.0.0")]));
        assert_eq!(pkg.peer_dependencies, deps(&[("peer", "*")]));
        assert_eq!(
            pkg.peer_dependencies_meta.unwrap()["peer"],
            serde_json::json!({"optional": true})
        );
        assert_eq!(pkg.os.unwrap().into_vec(), vec!["darwin".to_string()]);
        assert_eq!(
            pkg.bin,
            Some(PackageBin::Map(BTreeMap::from([(
                "owner".into(),
                "cli.js".into()
            )])))
        );
        assert_eq!(
            pkg.extra["funding"],
            serde_json::json!({"url": "https://example.invalid/fund"})
        );
        assert_eq!(pkg.license, None);
        assert_eq!(pkg.optional, Some(true));
        assert_eq!(pkg.integrity.as_deref(), Some("sha512-x"));
    }

    #[test]
    fn test_detect_lockfile_version_ignores_nested_lockfile_version_key() {
        let nested_first = r#"{
  "name": "root",
  "packages": {
    "node_modules/fake": {
      "lockfileVersion": 1
    }
  },
  "lockfileVersion": 3
}"#;
        assert_eq!(detect_lockfile_version(nested_first), Some(3));
        assert_eq!(detect_lockfile_version("\u{feff}{\"lockfileVersion\": \"2\"}"), Some(2));
        assert_eq!(detect_lockfile_version("not-json"), None);
        // Truncated / malformed JSON must return None rather than a partial integer.
        assert_eq!(detect_lockfile_version("{\"lockfileVersion\": 3"), None);
        assert_eq!(detect_lockfile_version("{\"lockfileVersion\": 3, garbage"), None);
        // JSONC comments must fall back cleanly and return None (not match inside comments).
        assert_eq!(
            detect_lockfile_version("{ /* \"lockfileVersion\": 1 */ \"lockfileVersion\": 3 }"),
            None
        );
        // Duplicate top-level keys match serde_json (last wins).
        assert_eq!(
            detect_lockfile_version("{\"lockfileVersion\": 2, \"lockfileVersion\": 3}"),
            Some(3)
        );
        // Top-level string value equal to key name still parses correctly.
        assert_eq!(
            detect_lockfile_version("{\"name\": \"lockfileVersion\", \"lockfileVersion\": 3}"),
            Some(3)
        );
    }
}
