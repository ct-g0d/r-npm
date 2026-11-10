use crate::error::LockfileError;
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use rnpm_core::to_posix_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Helper function to omit booleans during serialization if false or None.
fn is_false_or_none(v: &Option<bool>) -> bool {
    v.map(|b| !b).unwrap_or(true)
}

/// Helper function to omit empty maps or None during serialization.
fn is_none_or_empty_map<V>(v: &Option<BTreeMap<String, V>>) -> bool {
    v.as_ref().map(|m| m.is_empty()).unwrap_or(true)
}

/// Helper function to omit empty bundleDependencies or false during serialization.
fn is_empty_bundle_deps(v: &Option<BundledDependencies>) -> bool {
    match v {
        None => true,
        Some(BundledDependencies::Boolean(false)) => true,
        Some(BundledDependencies::List(list)) => list.is_empty(),
        _ => false,
    }
}

/// Helper function to omit empty engines or None during serialization.
fn is_none_or_empty_engines(v: &Option<PackageEngines>) -> bool {
    v.as_ref().map(|e| e.is_empty()).unwrap_or(true)
}

/// Helper function to omit empty vectors or None during serialization.
fn is_none_or_empty_vec<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().map(|l| l.is_empty()).unwrap_or(true)
}

/// Package supported engine constraints.
///
/// In npm package-lock files, `engines` is usually a map of engine names to semver constraints,
/// but npm has also published and tolerated array, string, and arbitrary JSON representations.
/// Uninterpreted representations are preserved during deserialization and serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageEngines {
    Map(BTreeMap<String, String>),
    List(Vec<serde_json::Value>),
    String(String),
    Other(serde_json::Value),
}

impl PackageEngines {
    /// Returns the engines map if this is a map, or attempts to parse string/list entries if possible.
    pub fn as_map(&self) -> Option<BTreeMap<String, String>> {
        match self {
            PackageEngines::Map(map) => Some(map.clone()),
            PackageEngines::List(list) => {
                let mut map = BTreeMap::new();
                for item in list {
                    if let Some(s) = item.as_str() {
                        if let Some((name, range)) = parse_engine_entry(s) {
                            map.insert(name, range);
                        }
                    }
                }
                if map.is_empty() {
                    None
                } else {
                    Some(map)
                }
            }
            PackageEngines::String(s) => {
                if let Some((name, range)) = parse_engine_entry(s) {
                    let mut map = BTreeMap::new();
                    map.insert(name, range);
                    Some(map)
                } else {
                    None
                }
            }
            PackageEngines::Other(serde_json::Value::Object(obj)) => {
                let mut map = BTreeMap::new();
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        map.insert(k.clone(), s.to_string());
                    }
                }
                if map.is_empty() {
                    None
                } else {
                    Some(map)
                }
            }
            _ => None,
        }
    }

    /// Returns a reference to the map if this engines representation is a `Map`.
    pub fn map_ref(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            PackageEngines::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Looks up an engine constraint by engine name.
    /// Handles map, list, string, and arbitrary JSON object/array representations.
    pub fn get(&self, engine: &str) -> Option<String> {
        self.get_str(engine).map(str::to_string)
    }

    /// Looks up an engine constraint by engine name, returning a borrowed slice if possible.
    pub fn get_str<'a>(&'a self, engine: &str) -> Option<&'a str> {
        match self {
            PackageEngines::Map(map) => map.get(engine).map(|s| s.as_str()),
            PackageEngines::List(list) => {
                for item in list {
                    if let Some(s) = item.as_str() {
                        for (name, range) in parse_engine_entries_from_str(s) {
                            if name == engine {
                                return Some(range);
                            }
                        }
                    }
                }
                None
            }
            PackageEngines::String(s) => {
                for (name, range) in parse_engine_entries_from_str(s) {
                    if name == engine {
                        return Some(range);
                    }
                }
                None
            }
            PackageEngines::Other(serde_json::Value::Object(obj)) => {
                obj.get(engine).and_then(|v| v.as_str())
            }
            PackageEngines::Other(serde_json::Value::Array(arr)) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        for (name, range) in parse_engine_entries_from_str(s) {
                            if name == engine {
                                return Some(range);
                            }
                        }
                    }
                }
                None
            }
            PackageEngines::Other(serde_json::Value::String(s)) => {
                for (name, range) in parse_engine_entries_from_str(s) {
                    if name == engine {
                        return Some(range);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Returns true if this engines representation contains no constraints.
    pub fn is_empty(&self) -> bool {
        match self {
            PackageEngines::Map(map) => map.is_empty(),
            PackageEngines::List(list) => list.is_empty(),
            PackageEngines::String(s) => s.trim().is_empty(),
            PackageEngines::Other(serde_json::Value::Null) => true,
            PackageEngines::Other(serde_json::Value::Object(obj)) => obj.is_empty(),
            PackageEngines::Other(serde_json::Value::Array(arr)) => arr.is_empty(),
            _ => false,
        }
    }
}

fn parse_engine_entries_from_str(s: &str) -> Vec<(&str, &str)> {
    let mut res = Vec::new();
    if s.contains(',') {
        for part in s.split(',') {
            if let Some(pair) = parse_engine_entry_str(part) {
                res.push(pair);
            }
        }
    } else if let Some(pair) = parse_engine_entry_str(s) {
        res.push(pair);
    }
    res
}

fn parse_engine_entry_str(entry: &str) -> Option<(&str, &str)> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(idx) = trimmed.find(|c: char| c.is_whitespace() || c == '@') {
        let name = trimmed[..idx].trim();
        let range = trimmed[idx + 1..].trim();
        if !name.is_empty() && !range.is_empty() {
            return Some((name, range));
        }
    }
    if let Some(idx) = trimmed.find(['>', '<', '=', '~', '^']) {
        let name = trimmed[..idx].trim();
        let range = trimmed[idx..].trim();
        if !name.is_empty() && !range.is_empty() {
            return Some((name, range));
        }
    }
    None
}

fn parse_engine_entry(entry: &str) -> Option<(String, String)> {
    parse_engine_entry_str(entry).map(|(n, r)| (n.to_string(), r.to_string()))
}

impl Default for PackageEngines {
    fn default() -> Self {
        PackageEngines::Map(BTreeMap::new())
    }
}

impl From<BTreeMap<String, String>> for PackageEngines {
    fn from(map: BTreeMap<String, String>) -> Self {
        PackageEngines::Map(map)
    }
}

impl From<std::collections::HashMap<String, String>> for PackageEngines {
    fn from(map: std::collections::HashMap<String, String>) -> Self {
        PackageEngines::Map(map.into_iter().collect())
    }
}

impl FromIterator<(String, String)> for PackageEngines {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        PackageEngines::Map(iter.into_iter().collect())
    }
}

impl From<Vec<String>> for PackageEngines {
    fn from(list: Vec<String>) -> Self {
        PackageEngines::List(list.into_iter().map(serde_json::Value::String).collect())
    }
}

impl From<String> for PackageEngines {
    fn from(s: String) -> Self {
        PackageEngines::String(s)
    }
}

impl From<&str> for PackageEngines {
    fn from(s: &str) -> Self {
        PackageEngines::String(s.to_string())
    }
}

/// Package executable configuration: single path or named binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageBin {
    Single(String),
    Map(BTreeMap<String, String>),
}

/// Metadata for a package node in lockfile v3 `packages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LockfilePackage {
    /// Internal marker used for freshly generated npm 11 lockfiles. npm 11
    /// writes `dev` and `optional` separately for a package reachable only
    /// through a dev optional branch; older lockfiles may still use the
    /// combined `devOptional` field.
    #[serde(skip)]
    pub preserve_dev_optional_split: bool,

    /// Raw JSON value captured on disk to preserve untouched key ordering.
    #[serde(skip)]
    pub raw_value: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub integrity: Option<String>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub link: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub dev: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub optional: Option<bool>,

    #[serde(
        rename = "devOptional",
        skip_serializing_if = "is_false_or_none",
        default
    )]
    pub dev_optional: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub peer: Option<bool>,

    #[serde(
        rename = "peerOptional",
        skip_serializing_if = "is_false_or_none",
        default
    )]
    pub peer_optional: Option<bool>,

    #[serde(
        rename = "inBundle",
        alias = "bundled",
        skip_serializing_if = "is_false_or_none",
        default
    )]
    pub in_bundle: Option<bool>,

    #[serde(
        rename = "hasInstallScript",
        skip_serializing_if = "is_false_or_none",
        default
    )]
    pub has_install_script: Option<bool>,

    #[serde(
        rename = "hasShrinkwrap",
        skip_serializing_if = "is_false_or_none",
        default
    )]
    pub has_shrinkwrap: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub extraneous: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub license: Option<String>,

    #[serde(skip_serializing_if = "is_none_or_empty_vec", default)]
    pub os: Option<Vec<String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_vec", default)]
    pub cpu: Option<Vec<String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_vec", default)]
    pub libc: Option<Vec<String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_map", default)]
    pub dependencies: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bin: Option<PackageBin>,

    #[serde(
        rename = "devDependencies",
        skip_serializing_if = "is_none_or_empty_map",
        default
    )]
    pub dev_dependencies: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_engines", default)]
    pub engines: Option<PackageEngines>,

    #[serde(
        rename = "optionalDependencies",
        skip_serializing_if = "is_none_or_empty_map",
        default
    )]
    pub optional_dependencies: Option<BTreeMap<String, String>>,

    #[serde(
        rename = "peerDependencies",
        skip_serializing_if = "is_none_or_empty_map",
        default
    )]
    pub peer_dependencies: Option<BTreeMap<String, String>>,

    #[serde(
        rename = "peerDependenciesMeta",
        skip_serializing_if = "is_none_or_empty_map",
        default
    )]
    pub peer_dependencies_meta: Option<BTreeMap<String, serde_json::Value>>,

    #[serde(
        rename = "bundleDependencies",
        alias = "bundledDependencies",
        skip_serializing_if = "is_empty_bundle_deps",
        default
    )]
    pub bundle_dependencies: Option<BundledDependencies>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workspaces: Option<Vec<String>>,

    /// Preserved hidden-tree metadata or arbitrary package properties.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl LockfilePackage {
    /// Returns true if this package is a development dependency (`dev: true`).
    pub fn is_dev(&self) -> bool {
        self.dev == Some(true)
    }

    /// Returns true if this package is an optional dependency (`optional: true`).
    pub fn is_optional(&self) -> bool {
        self.optional == Some(true)
    }

    /// Returns true if this package is both dev and optional (`devOptional: true`).
    pub fn is_dev_optional(&self) -> bool {
        self.dev_optional == Some(true)
    }

    /// Returns true if this package is needed for development (either `dev: true` or `devOptional: true`).
    pub fn is_effective_dev(&self) -> bool {
        self.is_dev() || self.is_dev_optional()
    }

    /// Returns true if this package is optional (either `optional: true` or `devOptional: true`).
    pub fn is_effective_optional(&self) -> bool {
        self.is_optional() || self.is_dev_optional()
    }

    /// Returns true if this package is a peer dependency (`peer: true`).
    pub fn is_peer(&self) -> bool {
        self.peer == Some(true)
    }

    /// Returns true if this package is an optional peer dependency (`peerOptional: true`).
    pub fn is_peer_optional(&self) -> bool {
        self.peer_optional == Some(true)
    }

    /// Returns true if this package is bundled in its parent package (`inBundle: true`).
    pub fn is_in_bundle(&self) -> bool {
        self.in_bundle == Some(true)
    }

    /// Returns true if this package has an install or postinstall lifecycle script (`hasInstallScript: true`).
    pub fn has_install_script(&self) -> bool {
        self.has_install_script == Some(true)
    }

    /// Returns true if this package contains a shrinkwrap file (`hasShrinkwrap: true`).
    pub fn has_shrinkwrap(&self) -> bool {
        self.has_shrinkwrap == Some(true)
    }

    /// Returns true if this package is marked extraneous (`extraneous: true`).
    pub fn is_extraneous(&self) -> bool {
        self.extraneous == Some(true)
            || self.extra.get("extraneous") == Some(&serde_json::Value::Bool(true))
    }

    /// Returns true if this package is a symlink or workspace link (`link: true`).
    pub fn is_link(&self) -> bool {
        self.link == Some(true)
    }

    /// Sets the `dev` flag (clearing `false` to `None`).
    pub fn set_dev(&mut self, val: bool) {
        self.dev = if val { Some(true) } else { None };
    }

    pub fn with_dev(mut self, val: bool) -> Self {
        self.set_dev(val);
        self
    }

    /// Sets the `optional` flag (clearing `false` to `None`).
    pub fn set_optional(&mut self, val: bool) {
        self.optional = if val { Some(true) } else { None };
    }

    pub fn with_optional(mut self, val: bool) -> Self {
        self.set_optional(val);
        self
    }

    /// Sets the `devOptional` flag (clearing `false` to `None`).
    pub fn set_dev_optional(&mut self, val: bool) {
        self.dev_optional = if val { Some(true) } else { None };
    }

    pub fn with_dev_optional(mut self, val: bool) -> Self {
        self.set_dev_optional(val);
        self
    }

    /// Sets the `peer` flag (clearing `false` to `None`).
    pub fn set_peer(&mut self, val: bool) {
        self.peer = if val { Some(true) } else { None };
    }

    pub fn with_peer(mut self, val: bool) -> Self {
        self.set_peer(val);
        self
    }

    /// Sets the `peerOptional` flag (clearing `false` to `None`).
    pub fn set_peer_optional(&mut self, val: bool) {
        self.peer_optional = if val { Some(true) } else { None };
    }

    pub fn with_peer_optional(mut self, val: bool) -> Self {
        self.set_peer_optional(val);
        self
    }

    /// Sets the `inBundle` flag (clearing `false` to `None`).
    pub fn set_in_bundle(&mut self, val: bool) {
        self.in_bundle = if val { Some(true) } else { None };
    }

    pub fn with_in_bundle(mut self, val: bool) -> Self {
        self.set_in_bundle(val);
        self
    }

    /// Sets the `hasInstallScript` flag (clearing `false` to `None`).
    pub fn set_has_install_script(&mut self, val: bool) {
        self.has_install_script = if val { Some(true) } else { None };
    }

    pub fn with_has_install_script(mut self, val: bool) -> Self {
        self.set_has_install_script(val);
        self
    }

    /// Sets the `hasShrinkwrap` flag (clearing `false` to `None`).
    pub fn set_has_shrinkwrap(&mut self, val: bool) {
        self.has_shrinkwrap = if val { Some(true) } else { None };
    }

    pub fn with_has_shrinkwrap(mut self, val: bool) -> Self {
        self.set_has_shrinkwrap(val);
        self
    }

    /// Sets the `link` flag (clearing `false` to `None`).
    pub fn set_link(&mut self, val: bool) {
        self.link = if val { Some(true) } else { None };
    }

    pub fn with_link(mut self, val: bool) -> Self {
        self.set_link(val);
        self
    }

    /// Sets npm dependency relationship rules:
    /// - If both `is_dev` and `is_optional` are true, sets `dev: true` and `optional: true` (npm 11 / lockfile v3 parity).
    /// - If only `is_dev` is true, sets `dev: true`.
    /// - If only `is_optional` is true, sets `optional: true`.
    /// - If neither, clears all three flags.
    pub fn set_dependency_types(&mut self, is_dev: bool, is_optional: bool) {
        if is_dev && is_optional {
            self.dev = Some(true);
            self.optional = Some(true);
            self.dev_optional = None;
        } else if is_dev {
            self.dev = Some(true);
            self.dev_optional = None;
            self.optional = None;
        } else if is_optional {
            self.optional = Some(true);
            self.dev = None;
            self.dev_optional = None;
        } else {
            self.dev = None;
            self.optional = None;
            self.dev_optional = None;
        }
    }

    /// Returns the engines map if available, converting from map/list/string formats.
    pub fn engines_map(&self) -> Option<BTreeMap<String, String>> {
        self.engines.as_ref().and_then(|e| e.as_map())
    }

    /// Normalizes boolean flags to ensure npm lockfile v3 fidelity:
    /// - If legacy `devOptional: true` is set, clears `dev` and `optional`.
    /// - For npm 11 / lockfile v3, packages reachable via dev and optional branches retain `dev: true, optional: true`.
    /// - Any `false` boolean flags are normalized to `None`.
    pub fn normalize_flags(&mut self) {
        if self.dev == Some(false) {
            self.dev = None;
        }
        if self.optional == Some(false) {
            self.optional = None;
        }
        if self.dev_optional == Some(false) {
            self.dev_optional = None;
        }
        if self.peer == Some(false) {
            self.peer = None;
        }
        if self.peer_optional == Some(false) {
            self.peer_optional = None;
        }
        if self.in_bundle == Some(false) {
            self.in_bundle = None;
        }
        if self.has_install_script == Some(false) {
            self.has_install_script = None;
        }
        if self.has_shrinkwrap == Some(false) {
            self.has_shrinkwrap = None;
        }
        if self.link == Some(false) {
            self.link = None;
        }

        if self.dev_optional == Some(true) {
            self.dev = None;
            self.optional = None;
        }

        if let Some(os) = &self.os {
            if os.is_empty() {
                self.os = None;
            }
        }
        if let Some(cpu) = &self.cpu {
            if cpu.is_empty() {
                self.cpu = None;
            }
        }
        if let Some(libc) = &self.libc {
            if libc.is_empty() {
                self.libc = None;
            }
        }
        if let Some(e) = &self.engines {
            if e.is_empty() {
                self.engines = None;
            }
        }

        self.extra.remove("directories");
        if let Some(v) = self.extra.get("deprecated") {
            if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                self.extra.remove("deprecated");
            }
        }
    }

    /// Returns list of package names that are marked as bundled in this package.
    pub fn bundled_package_names(&self) -> Vec<String> {
        match &self.bundle_dependencies {
            None => {
                if let Some(extra_val) = self
                    .extra
                    .get("bundleDependencies")
                    .or_else(|| self.extra.get("bundledDependencies"))
                {
                    if let Some(list) = extra_val.as_array() {
                        return list
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                    } else if let Some(b) = extra_val.as_bool() {
                        if b {
                            return self
                                .dependencies
                                .as_ref()
                                .map(|d| d.keys().cloned().collect())
                                .unwrap_or_default();
                        }
                    }
                }
                Vec::new()
            }
            Some(BundledDependencies::Boolean(true)) => self
                .dependencies
                .as_ref()
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default(),
            Some(BundledDependencies::Boolean(false)) => Vec::new(),
            Some(BundledDependencies::List(list)) => list.clone(),
        }
    }

    /// Checks if a dependency is marked as an optional peer dependency in `peerDependenciesMeta`.
    pub fn is_peer_dep_optional(&self, dep_name: &str) -> bool {
        let Some(meta_map) = &self.peer_dependencies_meta else {
            return false;
        };
        let Some(val) = meta_map.get(dep_name) else {
            return false;
        };
        val.get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Sets or unsets `optional: true` for a peer dependency in `peerDependenciesMeta`.
    pub fn set_peer_dep_optional(&mut self, dep_name: impl Into<String>, optional: bool) {
        let name = dep_name.into();
        if optional {
            let map = self
                .peer_dependencies_meta
                .get_or_insert_with(BTreeMap::new);
            map.insert(name, serde_json::json!({ "optional": true }));
        } else if let Some(map) = &mut self.peer_dependencies_meta {
            map.remove(&name);
            if map.is_empty() {
                self.peer_dependencies_meta = None;
            }
        }
    }
}

/// npm `package-lock.json` lockfile version 3 document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileV3 {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,

    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires: Option<bool>,

    /// Node packages keyed by their POSIX forward-slash path (e.g. `""`, `"node_modules/foo"`).
    /// Sorted keys via `BTreeMap` guarantee deterministic byte output across runs.
    pub packages: BTreeMap<String, LockfilePackage>,
}

impl LockfileV3 {
    /// Create a new LockfileV3 with an empty root package `""`.
    pub fn new(name: impl Into<String>, version: Option<String>) -> Self {
        let name_str = name.into();
        let mut packages = BTreeMap::new();
        packages.insert(
            "".to_string(),
            LockfilePackage {
                name: Some(name_str.clone()),
                version: version.clone(),
                ..Default::default()
            },
        );

        Self {
            name: name_str,
            version,
            lockfile_version: 3,
            requires: Some(true),
            packages,
        }
    }

    /// Insert a package into the lockfile, normalizing the path to POSIX forward slashes.
    pub fn insert_package(&mut self, path: &str, mut package: LockfilePackage) {
        let posix_key = to_posix_path(path);
        package.normalize_flags();
        self.packages.insert(posix_key, package);
    }

    /// Retrieve a package by path, normalizing the lookup key to POSIX forward slashes.
    pub fn get_package(&self, path: &str) -> Option<&LockfilePackage> {
        let posix_key = to_posix_path(path);
        self.packages.get(&posix_key)
    }

    /// Remove a package by path, normalizing the lookup key to POSIX forward slashes.
    pub fn remove_package(&mut self, path: &str) -> Option<LockfilePackage> {
        let posix_key = to_posix_path(path);
        self.packages.remove(&posix_key)
    }

    /// Access the root package `""`.
    pub fn root_package(&self) -> Option<&LockfilePackage> {
        self.packages.get("")
    }

    /// Access mutable reference to the root package `""`.
    pub fn root_package_mut(&mut self) -> Option<&mut LockfilePackage> {
        let pkg = self.packages.get_mut("")?;
        pkg.raw_value = None;
        Some(pkg)
    }

    /// Create a new LockfileV3 populated from a `package.json` Manifest.
    pub fn from_manifest(manifest: &rnpm_core::manifest::Manifest) -> Self {
        let name_str = manifest.name.clone().unwrap_or_default();
        let version = manifest.version.clone();
        let mut packages = BTreeMap::new();

        let peer_meta = if manifest.peer_dependencies_meta.is_empty() {
            None
        } else {
            let mut map = BTreeMap::new();
            for (k, v) in &manifest.peer_dependencies_meta {
                if v.optional {
                    map.insert(k.clone(), serde_json::json!({ "optional": true }));
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        };

        packages.insert(
            "".to_string(),
            LockfilePackage {
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                dependencies: if manifest.dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.dependencies.clone())
                },
                dev_dependencies: if manifest.dev_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.dev_dependencies.clone())
                },
                peer_dependencies: if manifest.peer_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.peer_dependencies.clone())
                },
                peer_dependencies_meta: peer_meta,
                optional_dependencies: if manifest.optional_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.optional_dependencies.clone())
                },
                bundle_dependencies: manifest.bundled_dependencies.clone(),
                extra: {
                    let mut extra = manifest.extra.clone();
                    extra.remove("overrides");
                    extra.remove("directories");
                    extra.remove("private");
                    if let Some(v) = extra.get("deprecated") {
                        if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                            extra.remove("deprecated");
                        }
                    }
                    extra
                },
                ..Default::default()
            },
        );

        Self {
            name: name_str,
            version,
            lockfile_version: 3,
            requires: Some(true),
            packages,
        }
    }

    /// Synchronize the root package descriptor `""` from a manifest.
    pub fn sync_root_manifest(&mut self, manifest: &rnpm_core::manifest::Manifest) {
        if let Some(name) = &manifest.name {
            self.name = name.clone();
        }
        self.version = manifest.version.clone();

        let root = self.packages.entry("".to_string()).or_default();
        root.name = manifest.name.clone();
        root.version = manifest.version.clone();
        root.dependencies = if manifest.dependencies.is_empty() {
            None
        } else {
            Some(manifest.dependencies.clone())
        };
        root.dev_dependencies = if manifest.dev_dependencies.is_empty() {
            None
        } else {
            Some(manifest.dev_dependencies.clone())
        };
        root.optional_dependencies = if manifest.optional_dependencies.is_empty() {
            None
        } else {
            Some(manifest.optional_dependencies.clone())
        };
        root.peer_dependencies = if manifest.peer_dependencies.is_empty() {
            None
        } else {
            Some(manifest.peer_dependencies.clone())
        };
        root.peer_dependencies_meta = if manifest.peer_dependencies_meta.is_empty() {
            None
        } else {
            let mut map = BTreeMap::new();
            for (k, v) in &manifest.peer_dependencies_meta {
                if v.optional {
                    map.insert(k.clone(), serde_json::json!({ "optional": true }));
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        };
        root.bundle_dependencies = manifest.bundled_dependencies.clone();
        for (k, v) in &manifest.extra {
            if k == "overrides" || k == "directories" {
                continue;
            }
            if k == "deprecated" && (v == &serde_json::Value::Bool(false) || v.is_null() || v == "")
            {
                continue;
            }
            root.extra.insert(k.clone(), v.clone());
        }
        root.extra.remove("overrides");
        root.extra.remove("directories");
        if let Some(v) = root.extra.get("deprecated") {
            if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                root.extra.remove("deprecated");
            }
        }
    }

    /// Normalizes all package keys to POSIX forward slashes and normalizes package flags.
    pub fn normalize(&mut self) {
        let old_packages = std::mem::take(&mut self.packages);
        for (k, mut v) in old_packages {
            v.normalize_flags();
            self.packages.insert(to_posix_path(&k), v);
        }
    }

    /// Populates or updates the flags for a specific package path.
    pub fn populate_package_flags(
        &mut self,
        path: &str,
        dev: Option<bool>,
        optional: Option<bool>,
        dev_optional: Option<bool>,
        peer: Option<bool>,
        peer_optional: Option<bool>,
        in_bundle: Option<bool>,
        has_install_script: Option<bool>,
    ) -> bool {
        let key = to_posix_path(path);
        if let Some(pkg) = self.packages.get_mut(&key) {
            if let Some(v) = dev {
                pkg.set_dev(v);
            }
            if let Some(v) = optional {
                pkg.set_optional(v);
            }
            if let Some(v) = dev_optional {
                pkg.set_dev_optional(v);
            }
            if let Some(v) = peer {
                pkg.set_peer(v);
            }
            if let Some(v) = peer_optional {
                pkg.set_peer_optional(v);
            }
            if let Some(v) = in_bundle {
                pkg.set_in_bundle(v);
            }
            if let Some(v) = has_install_script {
                pkg.set_has_install_script(v);
            }
            pkg.normalize_flags();
            true
        } else {
            false
        }
    }

    /// Iterator over packages that have `dev: true`.
    pub fn dev_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_dev())
    }

    /// Iterator over packages that have `optional: true`.
    pub fn optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_optional())
    }

    /// Iterator over packages that have `devOptional: true`.
    pub fn dev_optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.is_dev_optional())
    }

    /// Iterator over packages that have `peer: true`.
    pub fn peer_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_peer())
    }

    /// Iterator over packages that have `peerOptional: true`.
    pub fn peer_optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.is_peer_optional())
    }

    /// Iterator over packages that have `inBundle: true`.
    pub fn bundled_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_in_bundle())
    }

    /// Iterator over packages that have `hasInstallScript: true`.
    pub fn script_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.has_install_script())
    }

    /// Standard relative path to the hidden lockfile inside `node_modules`.
    pub const HIDDEN_LOCKFILE_PATH: &'static str = "node_modules/.package-lock.json";

    /// Checks if this lockfile v3 matches the given package.json manifest.
    /// Returns true if all direct dependencies in the manifest match the root package descriptor,
    /// overrides match, and every required package exists in the lockfile `packages` map satisfying its spec.
    pub fn matches_manifest(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
    ) -> bool {
        self.matches_manifest_ext(manifest, include_dev, false)
    }

    pub fn matches_manifest_for_ci(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
    ) -> bool {
        self.matches_manifest_ext(manifest, include_dev, true)
    }

    pub fn matches_manifest_ext(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
        allow_extra_lock_deps: bool,
    ) -> bool {
        let Some(root_pkg) = self.root_package() else {
            return false;
        };

        // Check package name if defined in manifest
        if let Some(ref m_name) = manifest.name {
            if let Some(ref r_name) = root_pkg.name {
                if m_name != r_name {
                    return false;
                }
            }
        }

        // Check package version if defined in manifest
        if let Some(ref m_ver) = manifest.version {
            if let Some(ref r_ver) = root_pkg.version {
                if m_ver != r_ver {
                    return false;
                }
            }
        }

        // 1. Check dependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.dependencies,
            &root_pkg.dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 2. Check devDependencies
        if include_dev
            && !Self::map_matches(
                &self.packages,
                &manifest.dev_dependencies,
                &root_pkg.dev_dependencies,
                allow_extra_lock_deps,
            )
        {
            return false;
        }

        // 3. Check optionalDependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.optional_dependencies,
            &root_pkg.optional_dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 4. Check peerDependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.peer_dependencies,
            &root_pkg.peer_dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 5. Check peerDependenciesMeta
        if !Self::peer_meta_matches(
            &manifest.peer_dependencies_meta,
            &root_pkg.peer_dependencies_meta,
        ) {
            return false;
        }

        // 6. Check bundleDependencies
        if !Self::bundled_deps_matches(manifest, root_pkg) {
            return false;
        }

        // 7. Verify direct dependencies exist in packages map and satisfy specs
        for (dep, spec) in &manifest.dependencies {
            if manifest.optional_dependencies.contains_key(dep) {
                continue;
            }
            let key = format!("node_modules/{dep}");
            let Some(pkg) = self.packages.get(&key) else {
                return false;
            };
            if !Self::package_satisfies_spec(dep, pkg, spec) {
                return false;
            }
        }

        // 8. Verify direct devDependencies exist in packages map and satisfy specs
        if include_dev {
            for (dep, spec) in &manifest.dev_dependencies {
                let key = format!("node_modules/{dep}");
                let Some(pkg) = self.packages.get(&key) else {
                    return false;
                };
                if !Self::package_satisfies_spec(dep, pkg, spec) {
                    return false;
                }
            }
        }

        // 9. Verify optional dependencies in packages map satisfy specs if present
        for (dep, spec) in &manifest.optional_dependencies {
            let key = format!("node_modules/{dep}");
            if let Some(pkg) = self.packages.get(&key) {
                if !Self::package_satisfies_spec(dep, pkg, spec) {
                    return false;
                }
            }
        }

        // 10. Verify peer dependencies in packages map
        for (dep, spec) in &manifest.peer_dependencies {
            let is_optional = manifest
                .peer_dependencies_meta
                .get(dep)
                .map(|m| m.optional)
                .unwrap_or_else(|| root_pkg.is_peer_dep_optional(dep));

            let key = format!("node_modules/{dep}");
            if let Some(pkg) = self.packages.get(&key) {
                if !Self::package_satisfies_spec(dep, pkg, spec) {
                    return false;
                }
            } else if !is_optional {
                return false;
            }
        }

        true
    }

    pub fn package_satisfies_spec(install_name: &str, pkg: &LockfilePackage, spec: &str) -> bool {
        if pkg.link == Some(true) {
            return true;
        }
        let Some(ref ver_str) = pkg.version else {
            return false;
        };
        let Ok(target) = PackageTarget::parse(spec) else {
            return false;
        };
        match &target {
            PackageTarget::Alias { name, target } => {
                if pkg.name.as_deref() != Some(name) {
                    return false;
                }
                Self::version_matches_target(ver_str, target)
            }
            other => {
                if let Some(ref real_name) = pkg.name {
                    if real_name != install_name {
                        return false;
                    }
                }
                Self::version_matches_target(ver_str, other)
            }
        }
    }

    fn version_matches_target(ver_str: &str, target: &PackageTarget) -> bool {
        let Ok(v) = Version::parse(ver_str) else {
            return false;
        };
        match target {
            PackageTarget::Version(expected) => &v == expected,
            PackageTarget::Range(range) => range.satisfies(&v),
            PackageTarget::Tag(_) => true,
            PackageTarget::File(_) => true,
            PackageTarget::Git { .. } => true,
            PackageTarget::Url(_) => true,
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    true
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    range.satisfies(&v)
                } else if let Ok(expected) = Version::parse(s) {
                    v == expected
                } else {
                    true
                }
            }
            PackageTarget::Alias { target, .. } => Self::version_matches_target(ver_str, target),
        }
    }

    fn map_matches(
        packages: &std::collections::BTreeMap<String, LockfilePackage>,
        manifest_map: &std::collections::BTreeMap<String, String>,
        lock_map: &Option<std::collections::BTreeMap<String, String>>,
        allow_extra_lock_deps: bool,
    ) -> bool {
        let empty_lock = std::collections::BTreeMap::new();
        let lock = lock_map.as_ref().unwrap_or(&empty_lock);

        if !allow_extra_lock_deps && manifest_map.len() != lock.len() {
            return false;
        }

        for (k, manifest_spec) in manifest_map {
            let Some(lock_spec) = lock.get(k) else {
                return false;
            };
            if lock_spec == manifest_spec {
                continue;
            }
            // If lock spec is a Version and manifest spec is a Range, check satisfies
            if let Ok(v) = Version::parse(lock_spec) {
                if let Ok(r) = rnpm_core::semver::Range::parse(manifest_spec) {
                    if r.satisfies(&v) {
                        continue;
                    }
                }
            }
            // If lock spec is a Range and manifest spec is a Version, check satisfies
            if let Ok(v) = Version::parse(manifest_spec) {
                if let Ok(r) = rnpm_core::semver::Range::parse(lock_spec) {
                    if r.satisfies(&v) {
                        continue;
                    }
                }
            }
            // For other spec differences, verify whether resolved package in packages satisfies manifest spec,
            // but ONLY if the lock spec itself was not a file/link/target that diverged.
            if lock_spec.starts_with("file:") || manifest_spec.starts_with("file:") {
                return false;
            }
            let key = format!("node_modules/{k}");
            let Some(pkg) = packages.get(&key) else {
                return false;
            };
            if !Self::package_satisfies_spec(k, pkg, manifest_spec) {
                return false;
            }
        }
        true
    }

    fn peer_meta_matches(
        manifest_meta: &BTreeMap<String, rnpm_core::manifest::PeerDependencyMeta>,
        lock_meta: &Option<BTreeMap<String, serde_json::Value>>,
    ) -> bool {
        let manifest_opts: BTreeMap<&str, bool> = manifest_meta
            .iter()
            .filter(|(_, meta)| meta.optional)
            .map(|(k, meta)| (k.as_str(), meta.optional))
            .collect();

        let lock_opts: BTreeMap<&str, bool> = lock_meta
            .as_ref()
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| {
                        let opt = v.get("optional").and_then(|o| o.as_bool()).unwrap_or(false);
                        if opt {
                            Some((k.as_str(), true))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        manifest_opts == lock_opts
    }

    fn bundled_deps_matches(
        manifest: &rnpm_core::manifest::Manifest,
        root_pkg: &LockfilePackage,
    ) -> bool {
        let mut m_names = manifest.bundled_package_names();
        let mut r_names = root_pkg.bundled_package_names();
        if m_names.is_empty() && r_names.is_empty() {
            return true;
        }
        m_names.sort();
        r_names.sort();
        m_names == r_names
    }

    /// Deterministic serialization to formatted JSON string (2-space indent, trailing newline).
    /// Guarantees strict LF line endings and normalized POSIX forward-slash package keys.
    /// Fast-path avoids cloning the entire package tree when all keys are already normalized POSIX paths.
    pub fn to_json_string(&self) -> Result<String, LockfileError> {
        let mut root = serde_json::Map::new();
        root.insert("name".into(), serde_json::Value::String(self.name.clone()));
        if let Some(v) = &self.version {
            root.insert("version".into(), serde_json::Value::String(v.clone()));
        }
        root.insert(
            "lockfileVersion".into(),
            serde_json::Value::Number(self.lockfile_version.into()),
        );
        if let Some(r) = self.requires {
            root.insert("requires".into(), serde_json::Value::Bool(r));
        }
        let mut packages = serde_json::Map::new();
        for (k, v) in &self.packages {
            let mut pkg = v.clone();
            pkg.normalize_flags();
            let pkg_val = if let Some(ref raw) = pkg.raw_value {
                raw.clone()
            } else {
                serde_json::to_value(&pkg)?
            };
            packages.insert(to_posix_path(k), pkg_val);
        }
        root.insert("packages".into(), serde_json::Value::Object(packages));
        let mut out = String::new();
        stringify_npm_nice(&serde_json::Value::Object(root), 0, &mut out);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        let lf_json = out.replace("\r\n", "\n");
        Ok(lf_json)
    }

    pub fn to_json_string_formatted(
        &self,
        format: &rnpm_core::ManifestFormat,
    ) -> Result<String, LockfileError> {
        let mut root = serde_json::Map::new();
        root.insert("name".into(), serde_json::Value::String(self.name.clone()));
        if let Some(v) = &self.version {
            root.insert("version".into(), serde_json::Value::String(v.clone()));
        }
        root.insert(
            "lockfileVersion".into(),
            serde_json::Value::Number(self.lockfile_version.into()),
        );
        if let Some(r) = self.requires {
            root.insert("requires".into(), serde_json::Value::Bool(r));
        }
        let mut packages = serde_json::Map::new();
        for (k, v) in &self.packages {
            let mut pkg = v.clone();
            pkg.normalize_flags();
            let pkg_val = if let Some(ref raw) = pkg.raw_value {
                raw.clone()
            } else {
                serde_json::to_value(&pkg)?
            };
            packages.insert(to_posix_path(k), pkg_val);
        }
        root.insert("packages".into(), serde_json::Value::Object(packages));
        let mut out = String::new();
        stringify_npm_nice_indent(
            &serde_json::Value::Object(root),
            &format.indent,
            0,
            &mut out,
        );
        if !out.ends_with('\n') {
            out.push('\n');
        }
        let final_json = if format.newline == "\r\n" {
            out.replace("\r\n", "\n").replace('\n', "\r\n")
        } else {
            out.replace("\r\n", "\n")
        };
        Ok(final_json)
    }

    /// Serialize using npm's requested lockfile format.  The resolver keeps a
    /// single v3 graph internally, then projects it to the legacy v1/v2
    /// representations only at the filesystem boundary.
    pub fn to_json_string_version(&self, version: u32) -> Result<String, LockfileError> {
        self.to_json_string_version_formatted(version, &rnpm_core::ManifestFormat::default())
    }

    pub fn to_json_string_version_formatted(
        &self,
        version: u32,
        format: &rnpm_core::ManifestFormat,
    ) -> Result<String, LockfileError> {
        match version {
            3 => self.to_json_string_formatted(format),
            1 | 2 => {
                let mut root = serde_json::Map::new();
                root.insert("name".into(), serde_json::Value::String(self.name.clone()));
                if let Some(v) = &self.version {
                    root.insert("version".into(), serde_json::Value::String(v.clone()));
                }
                root.insert(
                    "lockfileVersion".into(),
                    serde_json::Value::Number(version.into()),
                );
                root.insert("requires".into(), serde_json::Value::Bool(true));

                let legacy = self.to_legacy_dependencies();
                if version == 1 {
                    root.insert("dependencies".into(), legacy);
                } else {
                    let packages = self.to_v3_packages_value()?;
                    root.insert("packages".into(), packages);
                    root.insert("dependencies".into(), legacy);
                }
                let mut out = String::new();
                stringify_npm_nice_indent(
                    &serde_json::Value::Object(root),
                    &format.indent,
                    0,
                    &mut out,
                );
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                let final_json = if format.newline == "\r\n" {
                    out.replace("\r\n", "\n").replace('\n', "\r\n")
                } else {
                    out.replace("\r\n", "\n")
                };
                Ok(final_json)
            }
            other => Err(LockfileError::UnsupportedVersion(other)),
        }
    }

    /// Save using npm lockfile-version semantics (1, 2, or 3).
    pub fn save_to_file_version(&self, path: &Path, version: u32) -> Result<(), LockfileError> {
        let format = if path.exists() {
            std::fs::read_to_string(path)
                .map(|s| rnpm_core::ManifestFormat::detect(&s))
                .unwrap_or_default()
        } else if let Some(parent) = path.parent() {
            let root_dir = if parent.ends_with("node_modules") {
                parent.parent().unwrap_or(parent)
            } else {
                parent
            };
            let lock_path = root_dir.join("package-lock.json");
            let sw_path = root_dir.join("npm-shrinkwrap.json");
            let pkg_json = root_dir.join("package.json");
            if lock_path.exists() {
                std::fs::read_to_string(&lock_path)
                    .map(|s| rnpm_core::ManifestFormat::detect(&s))
                    .unwrap_or_default()
            } else if sw_path.exists() {
                std::fs::read_to_string(&sw_path)
                    .map(|s| rnpm_core::ManifestFormat::detect(&s))
                    .unwrap_or_default()
            } else if pkg_json.exists() {
                std::fs::read_to_string(&pkg_json)
                    .map(|s| rnpm_core::ManifestFormat::detect(&s))
                    .unwrap_or_default()
            } else {
                rnpm_core::ManifestFormat::default()
            }
        } else {
            rnpm_core::ManifestFormat::default()
        };

        let content = self.to_json_string_version_formatted(version, &format)?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    fn to_v3_packages_value(&self) -> Result<serde_json::Value, LockfileError> {
        let mut packages = serde_json::Map::new();
        for (key, package) in &self.packages {
            let pkg_val = if let Some(ref raw) = package.raw_value {
                raw.clone()
            } else {
                serde_json::to_value(package)?
            };
            packages.insert(to_posix_path(key), pkg_val);
        }
        Ok(serde_json::Value::Object(packages))
    }

    fn to_legacy_dependencies(&self) -> serde_json::Value {
        fn package_value(package: &LockfilePackage) -> serde_json::Value {
            let mut value = serde_json::Map::new();
            if let Some(v) = &package.version {
                value.insert("version".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &package.resolved {
                value.insert("resolved".into(), serde_json::Value::String(v.clone()));
            }
            if let Some(v) = &package.integrity {
                value.insert("integrity".into(), serde_json::Value::String(v.clone()));
            }
            if package.dev == Some(true) {
                value.insert("dev".into(), serde_json::Value::Bool(true));
            }
            if package.optional == Some(true) {
                value.insert("optional".into(), serde_json::Value::Bool(true));
            }
            if package.dev_optional == Some(true) {
                value.insert("devOptional".into(), serde_json::Value::Bool(true));
            }
            if package.peer == Some(true) {
                value.insert("peer".into(), serde_json::Value::Bool(true));
            }
            if package.peer_optional == Some(true) {
                value.insert("peerOptional".into(), serde_json::Value::Bool(true));
            }
            if package.in_bundle == Some(true) {
                value.insert("bundled".into(), serde_json::Value::Bool(true));
            }
            if package.has_install_script == Some(true) {
                value.insert("hasInstallScript".into(), serde_json::Value::Bool(true));
            }
            if package.has_shrinkwrap == Some(true) {
                value.insert("hasShrinkwrap".into(), serde_json::Value::Bool(true));
            }
            if let Some(deps) = &package.dependencies {
                value.insert(
                    "requires".into(),
                    serde_json::to_value(deps).unwrap_or_default(),
                );
            }
            serde_json::Value::Object(value)
        }

        fn insert_node(
            root: &mut serde_json::Map<String, serde_json::Value>,
            segments: &[&str],
            package: &LockfilePackage,
        ) {
            if segments.is_empty() {
                return;
            }
            let name = segments[0];
            if segments.len() == 1 {
                root.insert(name.to_string(), package_value(package));
                return;
            }
            let entry = root
                .entry(name.to_string())
                .or_insert_with(|| serde_json::json!({}));
            let object = entry
                .as_object_mut()
                .expect("legacy dependency entry must be an object");
            let nested = object
                .entry("dependencies")
                .or_insert_with(|| serde_json::json!({}));
            insert_node(
                nested
                    .as_object_mut()
                    .expect("legacy dependencies must be an object"),
                &segments[1..],
                package,
            );
        }

        let mut root = serde_json::Map::new();
        let mut keys: Vec<_> = self.packages.keys().filter(|k| !k.is_empty()).collect();
        keys.sort_by_key(|k| k.matches("/node_modules/").count());
        for key in keys {
            let path = key.trim_start_matches("node_modules/");
            let segments: Vec<_> = path.split("/node_modules/").collect();
            if let Some(package) = self.packages.get(key) {
                insert_node(&mut root, &segments, package);
            }
        }
        serde_json::Value::Object(root)
    }

    /// Save the lockfile deterministically to disk.
    pub fn save_to_file(&self, path: &Path) -> Result<(), LockfileError> {
        self.save_to_file_version(path, 3)
    }

    /// Load and parse a v3 lockfile from a string, normalizing all package keys to POSIX paths.
    pub fn from_json_str(s: &str) -> Result<Self, LockfileError> {
        let mut lockfile: Self = serde_json::from_str(s)?;
        let raw_val: Option<serde_json::Value> = serde_json::from_str(s).ok();
        let raw_packages = raw_val
            .as_ref()
            .and_then(|v| v.get("packages"))
            .and_then(|p| p.as_object());
        let packages = std::mem::take(&mut lockfile.packages);
        for (k, mut v) in packages {
            v.normalize_flags();
            let posix_k = to_posix_path(&k);
            if let Some(raw_pkgs) = raw_packages {
                if let Some(raw_p) = raw_pkgs.get(&k).or_else(|| raw_pkgs.get(&posix_k)) {
                    v.raw_value = Some(raw_p.clone());
                }
            }
            lockfile.packages.insert(posix_k, v);
        }
        Ok(lockfile)
    }

    /// Load and parse a v3 lockfile from disk.
    pub fn load_from_file(path: &Path) -> Result<Self, LockfileError> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    /// Load the hidden lockfile from `<project_dir>/node_modules/.package-lock.json`.
    pub fn load_hidden(project_dir: &Path) -> Result<Self, LockfileError> {
        let hidden_path = project_dir.join(Self::HIDDEN_LOCKFILE_PATH);
        Self::load_from_file(&hidden_path)
    }

    /// Save this lockfile as the hidden lockfile at `<project_dir>/node_modules/.package-lock.json`.
    ///
    /// Per npm Arborist parity (`Shrinkwrap` with `hiddenLockfile: true`):
    /// - Lockfile version is always forced to 3 (packages-only, no legacy dependencies).
    /// - Root `""` entry is omitted from `packages`.
    /// - Package entries retain installed metadata (`version`, `resolved`, `integrity`, `engines`, etc.)
    ///   while omitting extraneous fields like `directories`.
    /// - Platform-skipped optional packages (e.g. `fsevents` on Windows) are omitted because
    ///   npm's hidden lockfile lists only what is physically on disk.
    /// - Fields are ordered in npm's `json-stringify-nice` order so diffs against npm are minimal.
    pub fn save_hidden(&self, project_dir: &Path) -> Result<(), LockfileError> {
        let hidden_path = project_dir.join(Self::HIDDEN_LOCKFILE_PATH);
        let mut hidden = self.clone();
        hidden.lockfile_version = 3;
        hidden.packages.remove("");
        for pkg in hidden.packages.values_mut() {
            pkg.normalize_flags();
        }

        // Per npm Arborist parity: hidden lockfile lists only what is physically on disk!
        // Do NOT include platform-skipped optional packages (like `fsevents` on Windows).
        hidden.packages.retain(|pkg_key, pkg| {
            if pkg_key.is_empty() {
                return false;
            }
            let disk_path = project_dir.join(pkg_key);
            let exists_on_disk =
                disk_path.exists() || std::fs::symlink_metadata(&disk_path).is_ok();
            if exists_on_disk {
                return true;
            }
            let is_optional = pkg.optional.unwrap_or(false)
                || pkg.dev_optional.unwrap_or(false)
                || pkg.is_effective_optional();
            if is_optional && is_platform_incompatible(pkg) {
                return false;
            }
            if is_optional && project_dir.join("node_modules").is_dir() {
                return false;
            }
            true
        });

        let format = [
            hidden_path.clone(),
            project_dir.join("package-lock.json"),
            project_dir.join("npm-shrinkwrap.json"),
            project_dir.join("package.json"),
        ]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|raw| rnpm_core::ManifestFormat::detect(&raw))
        .unwrap_or_default();
        let content = hidden.to_npm_json_string_formatted(&format)?;

        if let Some(parent) = hidden_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&hidden_path, content)?;
        Ok(())
    }

    /// Serializes with npm's `json-stringify-nice` key ordering so diffs against npm are minimal.
    pub fn to_npm_json_string(&self) -> Result<String, LockfileError> {
        self.to_npm_json_string_formatted(&rnpm_core::ManifestFormat::default())
    }

    fn to_npm_json_string_formatted(
        &self,
        format: &rnpm_core::ManifestFormat,
    ) -> Result<String, LockfileError> {
        let has_any_raw = self.packages.values().any(|p| p.raw_value.is_some());
        let value = if has_any_raw {
            let mut root = serde_json::Map::new();
            root.insert("name".into(), serde_json::Value::String(self.name.clone()));
            if let Some(v) = &self.version {
                root.insert("version".into(), serde_json::Value::String(v.clone()));
            }
            root.insert(
                "lockfileVersion".into(),
                serde_json::Value::Number(self.lockfile_version.into()),
            );
            if let Some(r) = self.requires {
                root.insert("requires".into(), serde_json::Value::Bool(r));
            }
            let mut packages = serde_json::Map::new();
            for (k, v) in &self.packages {
                let mut pkg = v.clone();
                pkg.normalize_flags();
                let pkg_val = if let Some(ref raw) = pkg.raw_value {
                    raw.clone()
                } else {
                    serde_json::to_value(&pkg)?
                };
                packages.insert(to_posix_path(k), pkg_val);
            }
            root.insert("packages".into(), serde_json::Value::Object(packages));
            serde_json::Value::Object(root)
        } else {
            let mut normalized_packages = BTreeMap::new();
            for (k, v) in &self.packages {
                let mut pkg = v.clone();
                pkg.normalize_flags();
                normalized_packages.insert(to_posix_path(k), pkg);
            }
            let mut copy = self.clone();
            copy.packages = normalized_packages;
            serde_json::to_value(&copy)?
        };
        let mut out = String::new();
        stringify_npm_nice_indent(&value, &format.indent, 0, &mut out);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        if format.newline == "\r\n" {
            out = out.replace('\n', "\r\n");
        }
        Ok(out)
    }
}

const SW_KEY_ORDER: &[&str] = &[
    "name",
    "version",
    "lockfileVersion",
    "resolved",
    "integrity",
    "requires",
    "packages",
    "dependencies",
];

fn indent_spaces(out: &mut String, indent: &str, level: usize) {
    for _ in 0..level {
        out.push_str(indent);
    }
}

const NPM_CHAR_RANK: [u8; 256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 6, 12, 25, 35, 26, 24, 10, 13, 14, 20, 29, 3, 2, 8, 21,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 5, 4, 30, 31, 32, 7,
    19, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75,
    77, 79, 81, 83, 85, 87, 89, 91, 93, 95, 97, 15, 23, 16, 28, 1,
    27, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74,
    76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 17, 33, 18, 34, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

pub fn npm_key_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let n = a_bytes.len().min(b_bytes.len());
    for i in 0..n {
        let ra = NPM_CHAR_RANK[a_bytes[i] as usize];
        let rb = NPM_CHAR_RANK[b_bytes[i] as usize];
        if ra != rb {
            return ra.cmp(&rb);
        }
    }
    a_bytes.len().cmp(&b_bytes.len())
}

pub(crate) fn stringify_npm_nice(val: &serde_json::Value, indent_level: usize, out: &mut String) {
    stringify_npm_nice_indent(val, "  ", indent_level, out);
}

pub(crate) fn stringify_npm_nice_indent(
    val: &serde_json::Value,
    indent: &str,
    indent_level: usize,
    out: &mut String,
) {
    match val {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            out.push_str(&serde_json::to_string(s).unwrap_or_default());
        }
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
            } else {
                out.push_str("[\n");
                for (i, item) in arr.iter().enumerate() {
                    indent_spaces(out, indent, indent_level + 1);
                    stringify_npm_nice_indent(item, indent, indent_level + 1, out);
                    if i + 1 < arr.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent_spaces(out, indent, indent_level);
                out.push(']');
            }
        }
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
            } else {
                out.push_str("{\n");
                let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();

                let is_obj = |v: &serde_json::Value| -> bool { v.is_object() };

                let key_priority =
                    |k: &str| -> Option<usize> { SW_KEY_ORDER.iter().position(|&p| p == k) };

                entries.sort_by(|(ak, av), (bk, bv)| {
                    let a_obj = is_obj(av);
                    let b_obj = is_obj(bv);
                    if a_obj != b_obj {
                        if a_obj {
                            return std::cmp::Ordering::Greater;
                        } else {
                            return std::cmp::Ordering::Less;
                        }
                    }
                    match (key_priority(ak), key_priority(bk)) {
                        (Some(pa), Some(pb)) => pa.cmp(&pb),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => npm_key_compare(ak, bk),
                    }
                });

                for (i, (k, v)) in entries.iter().enumerate() {
                    indent_spaces(out, indent, indent_level + 1);
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push_str(": ");
                    stringify_npm_nice_indent(v, indent, indent_level + 1, out);
                    if i + 1 < entries.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent_spaces(out, indent, indent_level);
                out.push('}');
            }
        }
    }
}

pub(crate) fn is_platform_incompatible(pkg: &LockfilePackage) -> bool {
    let is_optional = pkg.optional.unwrap_or(false)
        || pkg.dev_optional.unwrap_or(false)
        || pkg.is_effective_optional();
    if !is_optional {
        return false;
    }

    let current_os = if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        std::env::consts::OS
    };

    let current_cpu = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "wasm32") {
        "wasm32"
    } else {
        std::env::consts::ARCH
    };

    let current_libc = if cfg!(target_os = "linux") {
        if cfg!(target_env = "musl") {
            Some("musl")
        } else {
            Some("glibc")
        }
    } else {
        None
    };

    fn matches_list(current: &str, list_opt: Option<&[String]>) -> bool {
        let list = match list_opt {
            Some(l) if !l.is_empty() => l,
            _ => return true,
        };
        let mut has_positive = false;
        let mut positive_match = false;
        for item in list {
            if let Some(negated) = item.strip_prefix('!') {
                if negated == current {
                    return false;
                }
            } else {
                has_positive = true;
                if item == current {
                    positive_match = true;
                }
            }
        }
        if has_positive {
            positive_match
        } else {
            true
        }
    }

    let os_ok = matches_list(current_os, pkg.os.as_deref());
    let cpu_ok = matches_list(current_cpu, pkg.cpu.as_deref());
    let libc_ok = match (&pkg.libc, current_libc) {
        (Some(libc_list), Some(curr)) if !libc_list.is_empty() => {
            matches_list(curr, Some(libc_list))
        }
        (Some(libc_list), None) if !libc_list.is_empty() => {
            !libc_list.iter().any(|s| !s.starts_with('!'))
        }
        _ => true,
    };

    !(os_ok && cpu_ok && libc_ok)
}
