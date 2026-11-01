use std::collections::BTreeMap;
use rnpm_core::manifest::PeerDependencyMeta;
use rnpm_lockfile::PackageBin;
use serde::{Deserialize, Serialize};
use crate::error::SolverError;

/// Metadata for a specific version of a package.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PackageVersionMetadata {
    pub name: String,
    pub version: String,
    pub dist_tarball: Option<String>,
    pub dist_integrity: Option<String>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies_meta: BTreeMap<String, PeerDependencyMeta>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub os: Option<Vec<String>>,
    #[serde(default)]
    pub cpu: Option<Vec<String>>,
    #[serde(default)]
    pub bin: Option<PackageBin>,
    #[serde(default)]
    pub has_install_script: bool,
    #[serde(default)]
    pub deprecated: Option<String>,
}

/// Metadata document containing dist-tags and all known versions of a package.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    #[serde(default)]
    pub dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub versions: BTreeMap<String, PackageVersionMetadata>,
}

/// Abstract provider for retrieving package metadata from a registry, cache, or mock source.
pub trait PackageMetadataProvider: Send + Sync {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError>;
}

/// In-memory package provider convenient for unit tests, fixtures, and synthetic graph creation.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPackageProvider {
    packages: BTreeMap<String, PackageMetadata>,
}

impl InMemoryPackageProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a package version to the in-memory provider.
    pub fn add_version(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        configure: impl FnOnce(&mut PackageVersionMetadata),
    ) {
        let name_str = name.into();
        let version_str = version.into();

        let pkg = self
            .packages
            .entry(name_str.clone())
            .or_insert_with(|| {
                let mut dist_tags = BTreeMap::new();
                dist_tags.insert("latest".to_string(), version_str.clone());
                PackageMetadata {
                    name: name_str.clone(),
                    dist_tags,
                    versions: BTreeMap::new(),
                }
            });

        // Update latest dist-tag if none or default
        if !pkg.dist_tags.contains_key("latest") {
            pkg.dist_tags.insert("latest".to_string(), version_str.clone());
        }

        let mut v_meta = PackageVersionMetadata {
            name: name_str.clone(),
            version: version_str.clone(),
            ..Default::default()
        };
        configure(&mut v_meta);
        pkg.versions.insert(version_str, v_meta);
    }

    /// Set a dist-tag on a package.
    pub fn set_dist_tag(&mut self, pkg_name: &str, tag: &str, version: &str) {
        if let Some(pkg) = self.packages.get_mut(pkg_name) {
            pkg.dist_tags.insert(tag.to_string(), version.to_string());
        }
    }
}

impl PackageMetadataProvider for InMemoryPackageProvider {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError> {
        Ok(self.packages.get(name).cloned())
    }
}
