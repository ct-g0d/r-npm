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

    /// Access the root package `""`.
    pub fn root_package(&self) -> Option<&LockfilePackage> {
        self.packages.get("")
    }

    /// Access mutable reference to the root package `""`.
    pub fn root_package_mut(&mut self) -> Option<&mut LockfilePackage> {
        self.packages.get_mut("")
    }

    /// Deterministic serialization to formatted JSON string (2-space indent, trailing newline).
    pub fn to_json_string(&self) -> Result<String, LockfileError> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        Ok(json)
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

    /// Load and parse a v3 lockfile from a string.
    pub fn from_json_str(s: &str) -> Result<Self, LockfileError> {
        let lockfile: Self = serde_json::from_str(s)?;
        Ok(lockfile)
    }

    /// Load and parse a v3 lockfile from disk.
    pub fn load_from_file(path: &Path) -> Result<Self, LockfileError> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }
}
