use crate::error::LockfileError;
use crate::model::{LockfilePackage, LockfileV3};
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::to_posix_path;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(crate) fn default_lockfile_version() -> u32 {
    1
}

pub(crate) fn deserialize_lockfile_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u32::try_from(u).map_err(serde::de::Error::custom)
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= (u32::MAX as f64) {
                    Ok(f as u32)
                } else {
                    Err(serde::de::Error::custom(
                        "lockfileVersion float must be a non-negative whole integer within u32 range",
                    ))
                }
            } else {
                Err(serde::de::Error::custom("invalid lockfileVersion number"))
            }
        }
        serde_json::Value::String(s) => {
            if let Ok(u) = s.parse::<u32>() {
                Ok(u)
            } else if let Ok(f) = s.parse::<f64>() {
                if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= (u32::MAX as f64) {
                    Ok(f as u32)
                } else {
                    Err(serde::de::Error::custom("invalid lockfileVersion string"))
                }
            } else {
                Err(serde::de::Error::custom("invalid lockfileVersion string"))
            }
        }
        serde_json::Value::Null => Ok(1),
        _ => Err(serde::de::Error::custom(
            "lockfileVersion must be a number or string",
        )),
    }
}

/// Legacy dependency node from npm lockfile v1 or v2.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyDependency {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(
        rename = "lockfileVersion",
        default = "default_lockfile_version",
        deserialize_with = "deserialize_lockfile_version"
    )]
    pub lockfile_version: u32,
    #[serde(default)]
    pub requires: Option<bool>,
    #[serde(default)]
    pub packages: Option<BTreeMap<String, LockfilePackage>>,
    #[serde(default)]
    pub dependencies: Option<BTreeMap<String, LegacyDependency>>,
}

fn parse_legacy_version_and_name(
    dep_name: &str,
    dep_version: &str,
    explicit_name: Option<&str>,
) -> (Option<String>, Option<String>) {
    if let Some(alias_part) = dep_version.strip_prefix("npm:") {
        if let Some(at_idx) = alias_part.rfind('@') {
            if at_idx > 0 {
                let name = &alias_part[..at_idx];
                let ver = &alias_part[at_idx + 1..];
                return (
                    if name != dep_name {
                        Some(name.to_string())
                    } else {
                        None
                    },
                    if ver.is_empty() {
                        None
                    } else {
                        Some(ver.to_string())
                    },
                );
            }
        }
        (
            if alias_part != dep_name {
                Some(alias_part.to_string())
            } else {
                None
            },
            None,
        )
    } else {
        let name = explicit_name.and_then(|n| {
            if n != dep_name {
                Some(n.to_string())
            } else {
                None
            }
        });
        let ver = if dep_version.is_empty() {
            None
        } else {
            Some(dep_version.to_string())
        };
        (name, ver)
    }
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

        let is_dir_link = dep.version.starts_with("file:")
            && !dep.version.ends_with(".tgz")
            && !dep.version.ends_with(".tar.gz")
            && !dep.version.ends_with(".tar");

        let (alias_or_name, clean_version) = if is_dir_link {
            (None, None)
        } else {
            parse_legacy_version_and_name(dep_name, &dep.version, dep.name.as_deref())
        };

        let resolved = if is_dir_link {
            let raw_target = dep.version.strip_prefix("file:").unwrap().trim_matches('/');
            Some(to_posix_path(raw_target))
        } else {
            dep.resolved.clone()
        };

        let mut pkg = LockfilePackage {
            name: alias_or_name,
            version: clean_version,
            resolved: resolved.clone(),
            integrity: if is_dir_link { None } else { dep.integrity.clone() },
            link: if is_dir_link { Some(true) } else { None },
            dev: if !is_dir_link && dep.dev == Some(true) {
                Some(true)
            } else {
                None
            },
            optional: if !is_dir_link && dep.optional == Some(true) {
                Some(true)
            } else {
                None
            },
            dev_optional: if !is_dir_link && dep.dev_optional == Some(true) {
                Some(true)
            } else {
                None
            },
            peer: if !is_dir_link && dep.peer == Some(true) {
                Some(true)
            } else {
                None
            },
            peer_optional: if !is_dir_link && dep.peer_optional == Some(true) {
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

        if is_dir_link {
            if let Some(target) = resolved {
                out_packages.entry(target).or_insert_with(|| {
                    let mut target_pkg = LockfilePackage {
                        name: dep.name.clone().or_else(|| Some(dep_name.clone())),
                        dependencies: dep.requires.clone(),
                        ..Default::default()
                    };
                    target_pkg.normalize_flags();
                    target_pkg
                });
            }
        }

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
            if pkg.name.is_none() {
                let (alias_or_name, _) =
                    parse_legacy_version_and_name(dep_name, &dep.version, dep.name.as_deref());
                if let Some(name) = alias_or_name {
                    pkg.name = Some(name);
                }
            }
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
            let is_dir_link = dep.version.starts_with("file:")
                && !dep.version.ends_with(".tgz")
                && !dep.version.ends_with(".tar.gz")
                && !dep.version.ends_with(".tar");
            if is_dir_link {
                if pkg.link.is_none() {
                    pkg.link = Some(true);
                }
                if pkg.resolved.is_none() {
                    let raw_target = dep.version.strip_prefix("file:").unwrap().trim_matches('/');
                    pkg.resolved = Some(to_posix_path(raw_target));
                }
            }
            pkg.normalize_flags();
        } else {
            // Missing from packages map in v2: inflate from legacy dependency.
            // Insert missing paths only to preserve valid child metadata
            // (e.g. version, bin, hasInstallScript) that already exists in `packages`.
            let mut sub_map = BTreeMap::new();
            let mut single_dep = BTreeMap::new();
            single_dep.insert(dep_name.clone(), dep.clone());
            flatten_legacy_dependencies(parent_path, &single_dep, &mut sub_map);
            for (path, pkg) in sub_map {
                packages.entry(path).or_insert(pkg);
            }
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
        2 | 3 => {
            // v2 has both `packages` (like v3) and `dependencies` (like v1).
            // v3 normally has only `packages`, but if packages is empty, fall back to dependencies.
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

            // If root package dependencies are missing, reconstruct from raw.dependencies
            if root.dependencies.is_none() {
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
                if !root_deps.is_empty() {
                    root.dependencies = Some(root_deps);
                }
                if !root_dev_deps.is_empty() {
                    root.dev_dependencies = Some(root_dev_deps);
                }
                if !root_opt_deps.is_empty() {
                    root.optional_dependencies = Some(root_opt_deps);
                }
                if !root_peer_deps.is_empty() {
                    root.peer_dependencies = Some(root_peer_deps);
                }
                if !root_peer_meta.is_empty() {
                    root.peer_dependencies_meta = Some(root_peer_meta);
                }
                if !root_bundled.is_empty() {
                    root.bundle_dependencies = Some(BundledDependencies::List(root_bundled));
                }
            }

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
    if raw.lockfile_version == 3 {
        if (raw.packages.is_none() || raw.packages.as_ref().is_some_and(|p| p.is_empty()))
            && raw.dependencies.is_some()
        {
            return migrate_to_v3(raw);
        }
        return LockfileV3::from_json_str(json_str);
    }
    migrate_to_v3(raw)
}

/// Load a lockfile from disk and migrate to v3 if necessary.
pub fn load_and_migrate(path: &Path) -> Result<LockfileV3, LockfileError> {
    let content = fs::read_to_string(path)?;
    parse_and_migrate(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageBin;

    #[test]
    fn test_v2_migration_preserves_child_metadata_when_parent_missing() {
        let v2_json = r#"{
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": {
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "parent-pkg": "^1.0.0"
                    }
                },
                "node_modules/parent-pkg/node_modules/child-pkg": {
                    "version": "2.5.0",
                    "resolved": "https://registry.npmjs.org/child-pkg/-/child-pkg-2.5.0.tgz",
                    "integrity": "sha512-child512",
                    "bin": {
                        "child-cli": "bin/cli.js"
                    },
                    "hasInstallScript": true
                }
            },
            "dependencies": {
                "parent-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/parent-pkg/-/parent-pkg-1.0.0.tgz",
                    "integrity": "sha512-parent512",
                    "dependencies": {
                        "child-pkg": {
                            "version": "2.0.0",
                            "resolved": "https://registry.npmjs.org/child-pkg/-/child-pkg-2.0.0.tgz",
                            "integrity": "sha512-child-legacy512"
                        },
                        "child-two": {
                            "version": "1.2.0",
                            "resolved": "https://registry.npmjs.org/child-two/-/child-two-1.2.0.tgz",
                            "integrity": "sha512-childtwo512"
                        }
                    }
                }
            }
        }"#;

        let migrated = parse_and_migrate(v2_json).expect("migration must succeed");
        assert_eq!(migrated.lockfile_version, 3);

        // Missing parent should be inflated from legacy dependencies
        let parent = migrated
            .packages
            .get("node_modules/parent-pkg")
            .expect("parent-pkg must be inflated from legacy dependencies");
        assert_eq!(parent.version.as_deref(), Some("1.0.0"));

        // Valid child package metadata already in packages must be preserved
        let child = migrated
            .packages
            .get("node_modules/parent-pkg/node_modules/child-pkg")
            .expect("child-pkg must be present");
        assert_eq!(
            child.version.as_deref(),
            Some("2.5.0"),
            "child version must be preserved from packages rather than overwritten by legacy"
        );
        assert_eq!(
            child.bin,
            Some(PackageBin::Map(
                [("child-cli".to_string(), "bin/cli.js".to_string())]
                    .into_iter()
                    .collect()
            )),
            "child bin must be preserved from packages"
        );
        assert_eq!(
            child.has_install_script,
            Some(true),
            "child hasInstallScript must be preserved from packages"
        );

        // Sibling child that was missing from packages must be inserted from legacy dependencies
        let child_two = migrated
            .packages
            .get("node_modules/parent-pkg/node_modules/child-two")
            .expect("missing sibling child-two must be inserted from legacy dependencies");
        assert_eq!(child_two.version.as_deref(), Some("1.2.0"));
    }
}
