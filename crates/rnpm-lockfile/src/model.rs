use rnpm_core::semver::{Range, Version};
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::spec::PackageTarget;
use rnpm_core::to_posix_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use crate::error::LockfileError;

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

    #[serde(rename = "devOptional", skip_serializing_if = "is_false_or_none", default)]
    pub dev_optional: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none", default)]
    pub peer: Option<bool>,

    #[serde(rename = "peerOptional", skip_serializing_if = "is_false_or_none", default)]
    pub peer_optional: Option<bool>,

    #[serde(rename = "inBundle", alias = "bundled", skip_serializing_if = "is_false_or_none", default)]
    pub in_bundle: Option<bool>,

    #[serde(rename = "hasInstallScript", skip_serializing_if = "is_false_or_none", default)]
    pub has_install_script: Option<bool>,

    #[serde(rename = "hasShrinkwrap", skip_serializing_if = "is_false_or_none", default)]
    pub has_shrinkwrap: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bin: Option<PackageBin>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub license: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub engines: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub libc: Option<Vec<String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_map", default)]
    pub dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "devDependencies", skip_serializing_if = "is_none_or_empty_map", default)]
    pub dev_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependencies", skip_serializing_if = "is_none_or_empty_map", default)]
    pub peer_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependenciesMeta", skip_serializing_if = "is_none_or_empty_map", default)]
    pub peer_dependencies_meta: Option<BTreeMap<String, serde_json::Value>>,

    #[serde(rename = "optionalDependencies", skip_serializing_if = "is_none_or_empty_map", default)]
    pub optional_dependencies: Option<BTreeMap<String, String>>,

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

    /// Sets npm v9/v10 dependency relationship rules:
    /// - If both `is_dev` and `is_optional` are true, sets `devOptional: true` and clears `dev` and `optional`.
    /// - If only `is_dev` is true, sets `dev: true`.
    /// - If only `is_optional` is true, sets `optional: true`.
    /// - If neither, clears all three flags.
    pub fn set_dependency_types(&mut self, is_dev: bool, is_optional: bool) {
        if is_dev && is_optional {
            self.dev_optional = Some(true);
            self.dev = None;
            self.optional = None;
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

    /// Normalizes boolean flags to ensure npm v9/v10 lockfile v3 fidelity:
    /// - `devOptional` is set when both `dev` and `optional` are true, clearing `dev` and `optional`.
    /// - Any `false` boolean flags are normalized to `None`.
    pub fn normalize_flags(&mut self) {
        if self.dev == Some(false) { self.dev = None; }
        if self.optional == Some(false) { self.optional = None; }
        if self.dev_optional == Some(false) { self.dev_optional = None; }
        if self.peer == Some(false) { self.peer = None; }
        if self.peer_optional == Some(false) { self.peer_optional = None; }
        if self.in_bundle == Some(false) { self.in_bundle = None; }
        if self.has_install_script == Some(false) { self.has_install_script = None; }
        if self.has_shrinkwrap == Some(false) { self.has_shrinkwrap = None; }
        if self.link == Some(false) { self.link = None; }

        if self.dev_optional == Some(true) {
            self.dev = None;
            self.optional = None;
        } else if !self.preserve_dev_optional_split && self.dev == Some(true) && self.optional == Some(true) {
            self.dev_optional = Some(true);
            self.dev = None;
            self.optional = None;
        }
    }

    /// Returns list of package names that are marked as bundled in this package.
    pub fn bundled_package_names(&self) -> Vec<String> {
        match &self.bundle_dependencies {
            None => {
                if let Some(extra_val) = self.extra.get("bundleDependencies").or_else(|| self.extra.get("bundledDependencies")) {
                    if let Some(list) = extra_val.as_array() {
                        return list.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                    } else if let Some(b) = extra_val.as_bool() {
                        if b {
                            return self.dependencies.as_ref().map(|d| d.keys().cloned().collect()).unwrap_or_default();
                        }
                    }
                }
                Vec::new()
            }
            Some(BundledDependencies::Boolean(true)) => {
                self.dependencies
                    .as_ref()
                    .map(|d| d.keys().cloned().collect())
                    .unwrap_or_default()
            }
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
        val.get("optional").and_then(|v| v.as_bool()).unwrap_or(false)
    }

    /// Sets or unsets `optional: true` for a peer dependency in `peerDependenciesMeta`.
    pub fn set_peer_dep_optional(&mut self, dep_name: impl Into<String>, optional: bool) {
        let name = dep_name.into();
        if optional {
            let map = self.peer_dependencies_meta.get_or_insert_with(BTreeMap::new);
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
        self.packages.get_mut("")
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
                extra: manifest.extra.clone(),
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
            root.extra.insert(k.clone(), v.clone());
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
            if let Some(v) = dev { pkg.set_dev(v); }
            if let Some(v) = optional { pkg.set_optional(v); }
            if let Some(v) = dev_optional { pkg.set_dev_optional(v); }
            if let Some(v) = peer { pkg.set_peer(v); }
            if let Some(v) = peer_optional { pkg.set_peer_optional(v); }
            if let Some(v) = in_bundle { pkg.set_in_bundle(v); }
            if let Some(v) = has_install_script { pkg.set_has_install_script(v); }
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
        self.packages.iter().filter(|(_, pkg)| pkg.is_dev_optional())
    }

    /// Iterator over packages that have `peer: true`.
    pub fn peer_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_peer())
    }

    /// Iterator over packages that have `peerOptional: true`.
    pub fn peer_optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_peer_optional())
    }

    /// Iterator over packages that have `inBundle: true`.
    pub fn bundled_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_in_bundle())
    }

    /// Iterator over packages that have `hasInstallScript: true`.
    pub fn script_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.has_install_script())
    }

    /// Standard relative path to the hidden lockfile inside `node_modules`.
    pub const HIDDEN_LOCKFILE_PATH: &'static str = "node_modules/.package-lock.json";

    /// Checks if this lockfile v3 matches the given package.json manifest.
    /// Returns true if all direct dependencies in the manifest match the root package descriptor,
    /// overrides match, and every required package exists in the lockfile `packages` map satisfying its spec.
    pub fn matches_manifest(&self, manifest: &rnpm_core::manifest::Manifest, include_dev: bool) -> bool {
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

        // Check overrides metadata match
        if manifest.extra.get("overrides") != root_pkg.extra.get("overrides") {
            return false;
        }

        // 1. Check dependencies
        if !Self::map_matches(&manifest.dependencies, &root_pkg.dependencies) {
            return false;
        }

        // 2. Check devDependencies
        if include_dev
            && !Self::map_matches(&manifest.dev_dependencies, &root_pkg.dev_dependencies) {
                return false;
            }

        // 3. Check optionalDependencies
        if !Self::map_matches(&manifest.optional_dependencies, &root_pkg.optional_dependencies) {
            return false;
        }

        // 4. Check peerDependencies
        if !Self::map_matches(&manifest.peer_dependencies, &root_pkg.peer_dependencies) {
            return false;
        }

        // 5. Check peerDependenciesMeta
        if !Self::peer_meta_matches(&manifest.peer_dependencies_meta, &root_pkg.peer_dependencies_meta) {
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

    fn package_satisfies_spec(install_name: &str, pkg: &LockfilePackage, spec: &str) -> bool {
        if pkg.link == Some(true) {
            if let Ok(target) = PackageTarget::parse(spec) {
                match target {
                    PackageTarget::File(_) | PackageTarget::Workspace(_) => return true,
                    _ => {}
                }
            }
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
        manifest_map: &std::collections::BTreeMap<String, String>,
        lock_map: &Option<std::collections::BTreeMap<String, String>>,
    ) -> bool {
        if manifest_map.is_empty() {
            lock_map.as_ref().map(|m| m.is_empty()).unwrap_or(true)
        } else {
            let Some(lock) = lock_map else {
                return false;
            };
            if manifest_map.len() != lock.len() {
                return false;
            }
            for (k, manifest_spec) in manifest_map {
                let Some(lock_spec) = lock.get(k) else {
                    return false;
                };
                if lock_spec == manifest_spec {
                    continue;
                }
                if let Ok(v) = Version::parse(lock_spec) {
                    if let Ok(r) = Range::parse(manifest_spec) {
                        if r.satisfies(&v) {
                            continue;
                        }
                    }
                }
                return false;
            }
            true
        }
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
        let mut normalized_packages = BTreeMap::new();
        for (k, v) in &self.packages {
            let mut pkg = v.clone();
            pkg.normalize_flags();
            normalized_packages.insert(to_posix_path(k), pkg);
        }
        let mut copy = self.clone();
        copy.packages = normalized_packages;
        let json = serde_json::to_string_pretty(&copy)?;
        let mut lf_json = json.replace("\r\n", "\n");
        if !lf_json.ends_with('\n') {
            lf_json.push('\n');
        }
        Ok(lf_json)
    }

    /// Serialize using npm's requested lockfile format.  The resolver keeps a
    /// single v3 graph internally, then projects it to the legacy v1/v2
    /// representations only at the filesystem boundary.
    pub fn to_json_string_version(&self, version: u32) -> Result<String, LockfileError> {
        match version {
            3 => self.to_json_string(),
            1 | 2 => {
                let mut root = serde_json::Map::new();
                root.insert("name".into(), serde_json::Value::String(self.name.clone()));
                if let Some(v) = &self.version {
                    root.insert("version".into(), serde_json::Value::String(v.clone()));
                }
                root.insert("lockfileVersion".into(), serde_json::Value::Number(version.into()));
                root.insert("requires".into(), serde_json::Value::Bool(true));

                let legacy = self.to_legacy_dependencies();
                if version == 1 {
                    root.insert("dependencies".into(), legacy);
                } else {
                    let packages = self.to_v3_packages_value()?;
                    root.insert("packages".into(), packages);
                    root.insert("dependencies".into(), legacy);
                }
                let mut out = serde_json::to_string_pretty(&serde_json::Value::Object(root))?;
                if !out.ends_with('\n') { out.push('\n'); }
                Ok(out)
            }
            other => Err(LockfileError::UnsupportedVersion(other)),
        }
    }

    /// Save using npm lockfile-version semantics (1, 2, or 3).
    pub fn save_to_file_version(&self, path: &Path, version: u32) -> Result<(), LockfileError> {
        let content = self.to_json_string_version(version)?;
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        fs::write(path, content)?;
        Ok(())
    }

    fn to_v3_packages_value(&self) -> Result<serde_json::Value, LockfileError> {
        let mut packages = serde_json::Map::new();
        for (key, package) in &self.packages {
            packages.insert(to_posix_path(key), serde_json::to_value(package)?);
        }
        Ok(serde_json::Value::Object(packages))
    }

    fn to_legacy_dependencies(&self) -> serde_json::Value {
        fn package_value(package: &LockfilePackage) -> serde_json::Value {
            let mut value = serde_json::Map::new();
            if let Some(v) = &package.version { value.insert("version".into(), serde_json::Value::String(v.clone())); }
            if let Some(v) = &package.resolved { value.insert("resolved".into(), serde_json::Value::String(v.clone())); }
            if let Some(v) = &package.integrity { value.insert("integrity".into(), serde_json::Value::String(v.clone())); }
            if package.dev == Some(true) { value.insert("dev".into(), serde_json::Value::Bool(true)); }
            if package.optional == Some(true) { value.insert("optional".into(), serde_json::Value::Bool(true)); }
            if package.dev_optional == Some(true) { value.insert("devOptional".into(), serde_json::Value::Bool(true)); }
            if package.peer == Some(true) { value.insert("peer".into(), serde_json::Value::Bool(true)); }
            if package.peer_optional == Some(true) { value.insert("peerOptional".into(), serde_json::Value::Bool(true)); }
            if package.in_bundle == Some(true) { value.insert("bundled".into(), serde_json::Value::Bool(true)); }
            if package.has_install_script == Some(true) { value.insert("hasInstallScript".into(), serde_json::Value::Bool(true)); }
            if package.has_shrinkwrap == Some(true) { value.insert("hasShrinkwrap".into(), serde_json::Value::Bool(true)); }
            if let Some(deps) = &package.dependencies { value.insert("requires".into(), serde_json::to_value(deps).unwrap_or_default()); }
            serde_json::Value::Object(value)
        }

        fn insert_node(root: &mut serde_json::Map<String, serde_json::Value>, segments: &[&str], package: &LockfilePackage) {
            if segments.is_empty() { return; }
            let name = segments[0];
            if segments.len() == 1 {
                root.insert(name.to_string(), package_value(package));
                return;
            }
            let entry = root.entry(name.to_string()).or_insert_with(|| serde_json::json!({}));
            let object = entry.as_object_mut().expect("legacy dependency entry must be an object");
            let nested = object.entry("dependencies").or_insert_with(|| serde_json::json!({}));
            insert_node(nested.as_object_mut().expect("legacy dependencies must be an object"), &segments[1..], package);
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
        let packages = std::mem::take(&mut lockfile.packages);
        for (k, mut v) in packages {
            v.normalize_flags();
            lockfile.packages.insert(to_posix_path(&k), v);
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
    pub fn save_hidden(&self, project_dir: &Path) -> Result<(), LockfileError> {
        let hidden_path = project_dir.join(Self::HIDDEN_LOCKFILE_PATH);
        self.save_to_file(&hidden_path)
    }
}
