use crate::error::SolverError;
use rnpm_core::manifest::PeerDependencyMeta;
use rnpm_core::semver::Version;
use rnpm_core::PlatformList;
use rnpm_lockfile::PackageBin;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    pub dependency_order: Vec<String>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies_meta: BTreeMap<String, PeerDependencyMeta>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub os: Option<PlatformList>,
    #[serde(default)]
    pub cpu: Option<PlatformList>,
    #[serde(default)]
    pub libc: Option<PlatformList>,
    #[serde(default)]
    pub bin: Option<PackageBin>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub engines: BTreeMap<String, String>,
    #[serde(default)]
    pub has_install_script: bool,
    #[serde(default)]
    pub deprecated: Option<String>,
    /// Cached parsed semver for fast zero-allocation evaluation.
    #[serde(skip, default)]
    pub parsed_version: Option<Version>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl PackageVersionMetadata {
    #[inline]
    pub fn semver(&self) -> Option<&Version> {
        self.parsed_version.as_ref()
    }

    /// Parse PackageVersionMetadata from a package manifest (package.json).
    pub fn from_manifest(manifest: &rnpm_core::manifest::Manifest) -> Self {
        // npm treats optionalDependencies as the authoritative declaration
        // when a package lists the same name in both maps.  Keep the entry in
        // the optional map so lockfiles and reachability flags retain the
        // optional edge, but do not duplicate it in `dependencies`.
        let optional_dependencies = manifest.optional_dependencies.clone();
        let mut dependencies = manifest.dependencies.clone();
        for name in optional_dependencies.keys() {
            dependencies.remove(name);
        }

        let version_str = manifest.version.clone().unwrap_or_default();
        let parsed_version = Version::parse(&version_str).ok();

        Self {
            name: manifest.name.clone().unwrap_or_default(),
            version: version_str,
            parsed_version,
            dist_tarball: None,
            dist_integrity: None,
            dependency_order: dependencies.keys().cloned().collect(),
            dependencies,
            dev_dependencies: manifest.dev_dependencies.clone(),
            peer_dependencies: manifest.peer_dependencies.clone(),
            peer_dependencies_meta: manifest.peer_dependencies_meta.clone(),
            optional_dependencies,
            os: manifest.os.clone(),
            cpu: manifest.cpu.clone(),
            libc: manifest.libc.clone(),
            bin: manifest.bin.clone().map(|b| match b {
                rnpm_core::manifest::PackageBin::Single(s) => PackageBin::Single(s),
                rnpm_core::manifest::PackageBin::Map(m) => PackageBin::Map(m),
            }),
            license: manifest
                .extra
                .get("license")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            engines: manifest.engines.clone(),
            has_install_script: manifest.scripts.contains_key("preinstall")
                || manifest.scripts.contains_key("install")
                || manifest.scripts.contains_key("postinstall"),
            deprecated: None,
            extra: {
                let mut extra = manifest.extra.clone();
                if let Some(ref bd) = manifest.bundled_dependencies {
                    if let Ok(val) = serde_json::to_value(bd) {
                        extra.insert("bundleDependencies".to_string(), val);
                    }
                }
                extra
            },
        }
    }

    /// Parse PackageVersionMetadata from raw package.json manifest bytes.
    pub fn from_manifest_slice(bytes: &[u8]) -> Result<Self, rnpm_core::error::ManifestError> {
        let manifest = rnpm_core::manifest::Manifest::from_slice(bytes)?;
        Ok(Self::from_manifest(&manifest))
    }
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

impl PackageMetadata {
    /// Pre-parse all version SemVers if not already parsed.
    pub fn ensure_parsed_versions(&mut self) {
        for (v_str, v_meta) in &mut self.versions {
            if v_meta.parsed_version.is_none() {
                v_meta.parsed_version = Version::parse(v_str).ok();
            }
        }
    }
}

/// Abstract provider for retrieving package metadata from a registry, cache, or mock source.
pub trait PackageMetadataProvider: Send + Sync {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError>;
    fn prefetch_packages(&self, _names: &[&str]) {}
    /// Metadata already in memory, without touching the network. Providers
    /// that never fetch can answer with `get_package`.
    fn cached_package(&self, name: &str) -> Option<PackageMetadata> {
        self.get_package(name).ok().flatten()
    }

    /// Retrieve package metadata for a specific dependency edge.
    /// `is_root` indicates whether the dependency originates directly from the
    /// root project or a workspace member package (`true`) vs a transitive dependency (`false`).
    fn get_package_for_edge(
        &self,
        name: &str,
        _range: &str,
        _is_root: bool,
    ) -> Result<Option<PackageMetadata>, SolverError> {
        self.get_package(name)
    }

    /// Prefetch package metadata for dependency edges.
    /// Each element is `(package_name, is_root)`.
    fn prefetch_packages_for_edge(&self, edges: &[(&str, bool)]) {
        let names: Vec<&str> = edges.iter().map(|(n, _)| *n).collect();
        self.prefetch_packages(&names);
    }
}

/// In-memory package provider convenient for unit tests, fixtures, and synthetic graph creation.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPackageProvider {
    packages: BTreeMap<String, PackageMetadata>,
    explicit_latest: BTreeSet<String>,
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

        let pkg = self.packages.entry(name_str.clone()).or_insert_with(|| {
            let mut dist_tags = BTreeMap::new();
            dist_tags.insert("latest".to_string(), version_str.clone());
            PackageMetadata {
                name: name_str.clone(),
                dist_tags,
                versions: BTreeMap::new(),
            }
        });

        // Keep the synthetic provider's implicit latest tag aligned with the
        // highest version, while preserving an explicitly assigned tag.
        if !pkg.dist_tags.contains_key("latest") {
            pkg.dist_tags
                .insert("latest".to_string(), version_str.clone());
        } else if !self.explicit_latest.contains(&name_str) {
            let should_update = pkg
                .dist_tags
                .get("latest")
                .and_then(|current| Version::parse(current).ok())
                .zip(Version::parse(&version_str).ok())
                .map(|(current, next)| next > current)
                .unwrap_or(false);
            if should_update {
                pkg.dist_tags
                    .insert("latest".to_string(), version_str.clone());
            }
        }

        let parsed_version = Version::parse(&version_str).ok();
        let mut v_meta = PackageVersionMetadata {
            name: name_str.clone(),
            version: version_str.clone(),
            parsed_version,
            ..Default::default()
        };
        configure(&mut v_meta);
        pkg.versions.insert(version_str, v_meta);
    }

    /// Set a dist-tag on a package.
    pub fn set_dist_tag(&mut self, pkg_name: &str, tag: &str, version: &str) {
        if let Some(pkg) = self.packages.get_mut(pkg_name) {
            pkg.dist_tags.insert(tag.to_string(), version.to_string());
            if tag == "latest" {
                self.explicit_latest.insert(pkg_name.to_string());
            }
        }
    }
}

impl PackageMetadataProvider for InMemoryPackageProvider {
    fn get_package(&self, name: &str) -> Result<Option<PackageMetadata>, SolverError> {
        Ok(self.packages.get(name).cloned())
    }
}
