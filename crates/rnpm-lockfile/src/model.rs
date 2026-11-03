use rnpm_core::semver::{Range, Version};
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

    #[serde(rename = "inBundle", skip_serializing_if = "is_false_or_none", default)]
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

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "devDependencies", skip_serializing_if = "Option::is_none", default)]
    pub dev_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependencies", skip_serializing_if = "Option::is_none", default)]
    pub peer_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependenciesMeta", skip_serializing_if = "Option::is_none", default)]
    pub peer_dependencies_meta: Option<BTreeMap<String, serde_json::Value>>,

    #[serde(rename = "optionalDependencies", skip_serializing_if = "Option::is_none", default)]
    pub optional_dependencies: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workspaces: Option<Vec<String>>,

    /// Preserved hidden-tree metadata or arbitrary package properties.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
    pub fn insert_package(&mut self, path: &str, package: LockfilePackage) {
        let posix_key = to_posix_path(path);
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
        if include_dev {
            if !Self::map_matches(&manifest.dev_dependencies, &root_pkg.dev_dependencies) {
                return false;
            }
        }

        // 3. Check optionalDependencies
        if !Self::map_matches(&manifest.optional_dependencies, &root_pkg.optional_dependencies) {
            return false;
        }

        // 4. Check peerDependencies
        if !Self::map_matches(&manifest.peer_dependencies, &root_pkg.peer_dependencies) {
            return false;
        }

        // 5. Verify direct dependencies exist in packages map and satisfy specs
        for (dep, spec) in &manifest.dependencies {
            let key = format!("node_modules/{dep}");
            let Some(pkg) = self.packages.get(&key) else {
                return false;
            };
            if !Self::package_satisfies_spec(dep, pkg, spec) {
                return false;
            }
        }

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

        for (dep, spec) in &manifest.optional_dependencies {
            let key = format!("node_modules/{dep}");
            if let Some(pkg) = self.packages.get(&key) {
                if !Self::package_satisfies_spec(dep, pkg, spec) {
                    return false;
                }
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
                    &v == &expected
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

    /// Deterministic serialization to formatted JSON string (2-space indent, trailing newline).
    /// Guarantees strict LF line endings and normalized POSIX forward-slash package keys.
    /// Fast-path avoids cloning the entire package tree when all keys are already normalized POSIX paths.
    pub fn to_json_string(&self) -> Result<String, LockfileError> {
        let has_non_posix = self.packages.keys().any(|k| k.contains('\\'));
        let json = if has_non_posix {
            let mut normalized_packages = BTreeMap::new();
            for (k, v) in &self.packages {
                normalized_packages.insert(to_posix_path(k), v.clone());
            }
            let mut copy = self.clone();
            copy.packages = normalized_packages;
            serde_json::to_string_pretty(&copy)?
        } else {
            serde_json::to_string_pretty(self)?
        };
        let mut lf_json = json.replace("\r\n", "\n");
        if !lf_json.ends_with('\n') {
            lf_json.push('\n');
        }
        Ok(lf_json)
    }

    /// Save the lockfile deterministically to disk.
    pub fn save_to_file(&self, path: &Path) -> Result<(), LockfileError> {
        let content = self.to_json_string()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    /// Load and parse a v3 lockfile from a string, normalizing all package keys to POSIX paths.
    pub fn from_json_str(s: &str) -> Result<Self, LockfileError> {
        let mut lockfile: Self = serde_json::from_str(s)?;
        let packages = std::mem::take(&mut lockfile.packages);
        for (k, v) in packages {
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
