use crate::error::LockfileError;
use crate::model::{LockfilePackage, LockfileV3};
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::to_posix_path;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Legacy dependency node from npm lockfile v1 or v2.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyDependency {
    pub version: String,
    #[serde(default)]
    pub resolved: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(default)]
    pub dev: Option<bool>,
    #[serde(default)]
    pub optional: Option<bool>,
    #[serde(rename = "devOptional", default)]
    pub dev_optional: Option<bool>,
    #[serde(default)]
    pub peer: Option<bool>,
    #[serde(rename = "peerOptional", default)]
    pub peer_optional: Option<bool>,
    #[serde(default, alias = "inBundle")]
    pub bundled: Option<bool>,
    #[serde(rename = "hasInstallScript", default)]
    pub has_install_script: Option<bool>,
    #[serde(rename = "hasShrinkwrap", default)]
    pub has_shrinkwrap: Option<bool>,
    #[serde(default)]
    pub requires: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, LegacyDependency>>,
}

/// Generic container matching any npm lockfile version (v1, v2, or v3).
#[derive(Debug, Clone, Deserialize)]
pub struct AnyLockfile {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,
    #[serde(default)]
    pub requires: Option<bool>,
    #[serde(default)]
    pub packages: Option<BTreeMap<String, LockfilePackage>>,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, LegacyDependency>>,
}

/// Recursively flattens legacy nested `dependencies` from lockfile v1 into v3 `packages` map.
fn flatten_legacy_dependencies(
    parent_path: &str,
    deps: &BTreeMap<String, LegacyDependency>,
    out_packages: &mut BTreeMap<String, LockfilePackage>,
) {
    for (dep_name, dep) in deps {
        let node_path = if parent_path.is_empty() {
            format!("node_modules/{dep_name}")
        } else {
            format!("{parent_path}/node_modules/{dep_name}")
        };

        let mut pkg = LockfilePackage {
            version: Some(dep.version.clone()),
            resolved: dep.resolved.clone(),
            integrity: dep.integrity.clone(),
            dev: if dep.dev == Some(true) {
                Some(true)
            } else {
                None
            },
            optional: if dep.optional == Some(true) {
                Some(true)
            } else {
                None
            },
            dev_optional: if dep.dev_optional == Some(true) {
                Some(true)
            } else {
                None
            },
            peer: if dep.peer == Some(true) {
                Some(true)
            } else {
                None
            },
            peer_optional: if dep.peer_optional == Some(true) {
                Some(true)
            } else {
                None
            },
            in_bundle: if dep.bundled == Some(true) {
                Some(true)
            } else {
                None
            },
            has_install_script: if dep.has_install_script == Some(true) {
                Some(true)
            } else {
                None
            },
            has_shrinkwrap: if dep.has_shrinkwrap == Some(true) {
                Some(true)
            } else {
                None
            },
            dependencies: dep.requires.clone(),
            ..Default::default()
        };
        pkg.normalize_flags();

        out_packages.insert(node_path.clone(), pkg);

        if let Some(child_deps) = &dep.dependencies {
            flatten_legacy_dependencies(&node_path, child_deps, out_packages);
        }
    }
}

/// Enriches packages map in v2 lockfile with flags from legacy `dependencies` tree if missing.
fn enrich_packages_from_legacy(
    parent_path: &str,
    deps: &BTreeMap<String, LegacyDependency>,
    packages: &mut BTreeMap<String, LockfilePackage>,
) {
    for (dep_name, dep) in deps {
        let node_path = if parent_path.is_empty() {
            format!("node_modules/{dep_name}")
        } else {
            format!("{parent_path}/node_modules/{dep_name}")
        };

        if let Some(pkg) = packages.get_mut(&node_path) {
            if pkg.dev.is_none() && dep.dev == Some(true) {
                pkg.dev = Some(true);
            }
            if pkg.optional.is_none() && dep.optional == Some(true) {
                pkg.optional = Some(true);
            }
            if pkg.dev_optional.is_none() && dep.dev_optional == Some(true) {
                pkg.dev_optional = Some(true);
            }
            if pkg.peer.is_none() && dep.peer == Some(true) {
                pkg.peer = Some(true);
            }
            if pkg.peer_optional.is_none() && dep.peer_optional == Some(true) {
                pkg.peer_optional = Some(true);
            }
            if pkg.in_bundle.is_none() && dep.bundled == Some(true) {
                pkg.in_bundle = Some(true);
            }
            if pkg.has_install_script.is_none() && dep.has_install_script == Some(true) {
                pkg.has_install_script = Some(true);
            }
            if pkg.has_shrinkwrap.is_none() && dep.has_shrinkwrap == Some(true) {
                pkg.has_shrinkwrap = Some(true);
            }
            pkg.normalize_flags();
        }

        if let Some(child_deps) = &dep.dependencies {
            enrich_packages_from_legacy(&node_path, child_deps, packages);
        }
    }
}

/// Migrates any parsed lockfile (v1, v2, or v3) to standard lockfile v3 format.
pub fn migrate_to_v3(raw: AnyLockfile) -> Result<LockfileV3, LockfileError> {
    match raw.lockfile_version {
        1 => {
            let mut packages = BTreeMap::new();

            // Create root package `""`
            let mut root_deps = BTreeMap::new();
            let mut root_dev_deps = BTreeMap::new();
            let mut root_opt_deps = BTreeMap::new();
            let mut root_peer_deps = BTreeMap::new();
            let mut root_peer_meta = BTreeMap::new();
            let mut root_bundled = Vec::new();

            if let Some(deps) = &raw.dependencies {
                for (name, dep) in deps {
                    root_deps.insert(name.clone(), dep.version.clone());
                    if dep.dev == Some(true) {
                        root_dev_deps.insert(name.clone(), dep.version.clone());
                    }
                    if dep.optional == Some(true) {
                        root_opt_deps.insert(name.clone(), dep.version.clone());
                    }
                    if dep.peer == Some(true) {
                        root_peer_deps.insert(name.clone(), dep.version.clone());
                        if dep.peer_optional == Some(true) {
                            root_peer_meta
                                .insert(name.clone(), serde_json::json!({ "optional": true }));
                        }
                    }
                    if dep.bundled == Some(true) {
                        root_bundled.push(name.clone());
                    }
                }
            }

            packages.insert(
                "".to_string(),
                LockfilePackage {
                    name: Some(raw.name.clone()),
                    version: raw.version.clone(),
                    dependencies: if root_deps.is_empty() {
                        None
                    } else {
                        Some(root_deps)
                    },
                    dev_dependencies: if root_dev_deps.is_empty() {
                        None
                    } else {
                        Some(root_dev_deps)
                    },
                    optional_dependencies: if root_opt_deps.is_empty() {
                        None
                    } else {
                        Some(root_opt_deps)
                    },
                    peer_dependencies: if root_peer_deps.is_empty() {
                        None
                    } else {
                        Some(root_peer_deps)
                    },
                    peer_dependencies_meta: if root_peer_meta.is_empty() {
                        None
                    } else {
                        Some(root_peer_meta)
                    },
                    bundle_dependencies: if root_bundled.is_empty() {
                        None
                    } else {
                        Some(BundledDependencies::List(root_bundled))
                    },
                    ..Default::default()
                },
            );

            // Flatten legacy dependencies tree
            if let Some(deps) = &raw.dependencies {
                flatten_legacy_dependencies("", deps, &mut packages);
            }

            Ok(LockfileV3 {
                name: raw.name,
                version: raw.version,
                lockfile_version: 3,
                requires: raw.requires.or(Some(true)),
                packages,
            })
        }
        2 => {
            // v2 has both `packages` (like v3) and `dependencies` (like v1).
            let mut packages = match raw.packages {
                Some(pkgs) if !pkgs.is_empty() => {
                    let mut normalized = BTreeMap::new();
                    for (k, mut v) in pkgs {
                        v.normalize_flags();
                        normalized.insert(to_posix_path(&k), v);
                    }
                    if let Some(deps) = &raw.dependencies {
                        enrich_packages_from_legacy("", deps, &mut normalized);
                    }
                    normalized
                }
                _ => {
                    // Fallback to migrating from dependencies
                    let mut pkgs = BTreeMap::new();
                    if let Some(deps) = &raw.dependencies {
                        flatten_legacy_dependencies("", deps, &mut pkgs);
                    }
                    pkgs
                }
            };

            // Ensure root package `""` is present
            let root = packages
                .entry("".to_string())
                .or_insert_with(|| LockfilePackage {
                    name: Some(raw.name.clone()),
                    version: raw.version.clone(),
                    ..Default::default()
                });
            root.normalize_flags();

            Ok(LockfileV3 {
                name: raw.name,
                version: raw.version,
                lockfile_version: 3,
                requires: raw.requires.or(Some(true)),
                packages,
            })
        }
        3 => {
            let mut packages = BTreeMap::new();
            if let Some(pkgs) = raw.packages {
                for (k, mut v) in pkgs {
                    v.normalize_flags();
                    packages.insert(to_posix_path(&k), v);
                }
            }

            // Ensure root package `""` exists
            let root = packages
                .entry("".to_string())
                .or_insert_with(|| LockfilePackage {
                    name: Some(raw.name.clone()),
                    version: raw.version.clone(),
                    ..Default::default()
                });
            root.normalize_flags();

            Ok(LockfileV3 {
                name: raw.name,
                version: raw.version,
                lockfile_version: 3,
                requires: raw.requires.or(Some(true)),
                packages,
            })
        }
        other => Err(LockfileError::UnsupportedVersion(other)),
    }
}

/// Parse a lockfile JSON string of any version (1, 2, or 3) and migrate to v3.
pub fn parse_and_migrate(json_str: &str) -> Result<LockfileV3, LockfileError> {
    let raw: AnyLockfile = serde_json::from_str(json_str)?;
    migrate_to_v3(raw)
}

/// Load a lockfile from disk and migrate to v3 if necessary.
pub fn load_and_migrate(path: &Path) -> Result<LockfileV3, LockfileError> {
    let content = fs::read_to_string(path)?;
    parse_and_migrate(&content)
}
