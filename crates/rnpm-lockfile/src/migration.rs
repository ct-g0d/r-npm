use crate::error::LockfileError;
use crate::model::{
    KeyStr, LockfilePackage, LockfileV3, LockfileVersionSeed, OptPackagesField, OptPackagesMapSeed,
};
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::{to_posix_path, to_posix_path_cow};
use serde::de::{DeserializeSeed, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

pub(crate) fn default_lockfile_version() -> u32 {
    1
}

#[inline]
fn parse_version_f64<E: serde::de::Error>(f: f64) -> Result<u32, E> {
    if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= (u32::MAX as f64) {
        Ok(f as u32)
    } else {
        Err(E::custom(
            "lockfileVersion float must be a non-negative whole integer within u32 range",
        ))
    }
}

pub(crate) fn deserialize_lockfile_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    struct LockfileVersionVisitor;
    impl<'de> Visitor<'de> for LockfileVersionVisitor {
        type Value = u32;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a lockfileVersion number or string")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
            u32::try_from(v).map_err(E::custom)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
            if v >= 0 {
                u32::try_from(v as u64).map_err(E::custom)
            } else {
                Err(E::custom(
                    "lockfileVersion float must be a non-negative whole integer within u32 range",
                ))
            }
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
            parse_version_f64(v)
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            if let Ok(u) = s.parse::<u32>() {
                Ok(u)
            } else if let Ok(f) = s.parse::<f64>() {
                parse_version_f64(f)
            } else {
                Err(E::custom("invalid lockfileVersion string"))
            }
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(1)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(1)
        }
        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            deserialize_lockfile_version(d)
        }
    }
    deserializer.deserialize_any(LockfileVersionVisitor)
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
            let raw_target = raw_target
                .strip_prefix("./")
                .unwrap_or(raw_target)
                .trim_matches('/');
            let posix = to_posix_path(raw_target);
            let canonical = if posix == "." || posix.is_empty() {
                "".to_string()
            } else {
                posix
            };
            Some(canonical)
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
            dependencies: if is_dir_link {
                None
            } else {
                dep.requires.clone()
            },
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
                pkg.dev = None;
                pkg.optional = None;
                pkg.dev_optional = None;
                pkg.peer = None;
                pkg.peer_optional = None;
                if pkg.resolved.is_none() {
                    let raw_target = dep.version.strip_prefix("file:").unwrap().trim_matches('/');
                    let raw_target = raw_target
                        .strip_prefix("./")
                        .unwrap_or(raw_target)
                        .trim_matches('/');
                    let posix = to_posix_path(raw_target);
                    let canonical = if posix == "." || posix.is_empty() {
                        "".to_string()
                    } else {
                        posix
                    };
                    pkg.resolved = Some(canonical);
                }
                pkg.dependencies = None;
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
                        let norm_k = match to_posix_path_cow(&k) {
                            Cow::Borrowed(_) => k,
                            Cow::Owned(s) => s,
                        };
                        normalized.insert(norm_k, v);
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

struct ParsedLockfile {
    name: String,
    version: Option<String>,
    lockfile_version: u32,
    requires: Option<bool>,
    packages: Option<BTreeMap<String, LockfilePackage>>,
    packages_was_null: bool,
    dependencies: Option<BTreeMap<String, LegacyDependency>>,
}

impl<'de> Deserialize<'de> for ParsedLockfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ParsedLockfileVisitor;

        impl<'de> Visitor<'de> for ParsedLockfileVisitor {
            type Value = ParsedLockfile;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a lockfile JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut name: Option<String> = None;
                let mut version: Option<Option<String>> = None;
                let mut lockfile_version: Option<u32> = None;
                let mut requires: Option<Option<bool>> = None;
                let mut seen_packages = false;
                let mut packages_was_null = false;
                let mut packages: Option<BTreeMap<String, LockfilePackage>> = None;
                let mut packages_raw: Option<serde_json::Value> = None;
                let mut seen_deps = false;
                let mut dependencies: Option<BTreeMap<String, LegacyDependency>> = None;
                let mut legacy_deps_raw: Option<serde_json::Value> = None;

                while let Some(key) = map.next_key::<KeyStr<'de>>()? {
                    match key.as_str() {
                        "name" => {
                            if name.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "version" => {
                            if version.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value()?);
                        }
                        "lockfileVersion" => {
                            if lockfile_version.is_some() {
                                return Err(serde::de::Error::duplicate_field("lockfileVersion"));
                            }
                            lockfile_version = Some(map.next_value_seed(LockfileVersionSeed)?);
                        }
                        "requires" => {
                            if requires.is_some() {
                                return Err(serde::de::Error::duplicate_field("requires"));
                            }
                            requires = Some(map.next_value()?);
                        }
                        "packages" => {
                            if seen_packages {
                                return Err(serde::de::Error::duplicate_field("packages"));
                            }
                            seen_packages = true;
                            match lockfile_version {
                                Some(v) if v != 1 && v != 2 && v != 3 => {
                                    map.next_value::<serde::de::IgnoredAny>()?;
                                }
                                Some(v) => {
                                    let is_v3 = v == 3;
                                    match map.next_value_seed(OptPackagesMapSeed {
                                        capture_raw: is_v3,
                                        normalize: is_v3,
                                        normalize_keys: is_v3,
                                    })? {
                                        OptPackagesField::Null => packages_was_null = true,
                                        OptPackagesField::Map(pkgs) => packages = Some(pkgs),
                                    }
                                }
                                None => {
                                    // Defer version-dependent raw capture & validation until lockfileVersion is known.
                                    packages_raw = Some(map.next_value()?);
                                }
                            }
                        }
                        "dependencies" => {
                            if seen_deps {
                                return Err(serde::de::Error::duplicate_field("dependencies"));
                            }
                            seen_deps = true;
                            let v3_with_nonempty_pkgs = lockfile_version == Some(3)
                                && packages.as_ref().is_some_and(|p| !p.is_empty());
                            let unsupported =
                                lockfile_version.is_some_and(|v| v != 1 && v != 2 && v != 3);
                            if v3_with_nonempty_pkgs || unsupported {
                                map.next_value::<serde::de::IgnoredAny>()?;
                            } else if matches!(lockfile_version, Some(1 | 2)) {
                                dependencies = map.next_value()?;
                            } else {
                                // Keep untyped until both lockfileVersion and packages presence are known.
                                legacy_deps_raw = Some(map.next_value()?);
                            }
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let effective_version = lockfile_version.unwrap_or_else(default_lockfile_version);
                if effective_version != 1 && effective_version != 2 && effective_version != 3 {
                    return Ok(ParsedLockfile {
                        name: name.unwrap_or_default(),
                        version: version.unwrap_or(None),
                        lockfile_version: effective_version,
                        requires: requires.unwrap_or(None),
                        packages: None,
                        packages_was_null: false,
                        dependencies: None,
                    });
                }

                if let Some(raw_pkgs) = packages_raw {
                    let is_v3 = effective_version == 3;
                    match (OptPackagesMapSeed {
                        capture_raw: is_v3,
                        normalize: is_v3,
                        normalize_keys: is_v3,
                    })
                    .deserialize(raw_pkgs)
                    .map_err(serde::de::Error::custom)?
                    {
                        OptPackagesField::Null => packages_was_null = true,
                        OptPackagesField::Map(pkgs) => packages = Some(pkgs),
                    }
                }

                if let Some(raw_deps) = legacy_deps_raw {
                    let packages_empty = packages.as_ref().is_none_or(|p| p.is_empty());
                    if !(effective_version == 3 && !packages_empty) {
                        dependencies = Option::<BTreeMap<String, LegacyDependency>>::deserialize(
                            raw_deps,
                        )
                        .map_err(serde::de::Error::custom)?;
                    }
                }

                Ok(ParsedLockfile {
                    name: name.unwrap_or_default(),
                    version: version.unwrap_or(None),
                    lockfile_version: effective_version,
                    requires: requires.unwrap_or(None),
                    packages,
                    packages_was_null,
                    dependencies,
                })
            }
        }

        deserializer.deserialize_map(ParsedLockfileVisitor)
    }
}

/// Parse a lockfile JSON string of any version (1, 2, or 3) and migrate to v3.
pub fn parse_and_migrate(json_str: &str) -> Result<LockfileV3, LockfileError> {
    let parsed: ParsedLockfile = serde_json::from_str(json_str)?;
    match parsed.lockfile_version {
        3 => {
            let packages_empty = parsed.packages.as_ref().is_none_or(|p| p.is_empty());
            let has_deps = parsed.dependencies.as_ref().is_some_and(|d| !d.is_empty());
            if packages_empty && has_deps {
                let raw = AnyLockfile {
                    name: parsed.name,
                    version: parsed.version,
                    lockfile_version: parsed.lockfile_version,
                    requires: parsed.requires,
                    packages: parsed.packages,
                    dependencies: parsed.dependencies,
                };
                return migrate_to_v3(raw);
            }
            if parsed.packages_was_null {
                // Match LockfileV3::from_json_str rejecting `"packages": null`.
                let _: BTreeMap<String, serde_json::Value> = serde_json::from_str("null")?;
            }
            Ok(LockfileV3 {
                name: parsed.name,
                version: parsed.version,
                lockfile_version: 3,
                requires: parsed.requires,
                packages: parsed.packages.unwrap_or_default(),
            })
        }
        1 | 2 => {
            let raw = AnyLockfile {
                name: parsed.name,
                version: parsed.version,
                lockfile_version: parsed.lockfile_version,
                requires: parsed.requires,
                packages: parsed.packages,
                dependencies: parsed.dependencies,
            };
            migrate_to_v3(raw)
        }
        other => Err(LockfileError::UnsupportedVersion(other)),
    }
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

    #[test]
    fn test_reordered_v3_nonempty_packages_ignores_legacy_dependencies_and_preserves_bytes() {
        let canonical = r#"{
            "name": "reordered-v3",
            "version": "1.2.3",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "reordered-v3",
                    "version": "1.2.3",
                    "dependencies": {
                        "dep-a": "^1.0.0"
                    }
                },
                "node_modules/dep-a": {
                    "customUnknownField": { "b": 2, "a": 1 },
                    "version": "1.0.5",
                    "resolved": "https://registry.npmjs.org/dep-a/-/dep-a-1.0.5.tgz",
                    "integrity": "sha512-depa",
                    "hasInstallScript": false
                }
            },
            "dependencies": {
                "broken": 123
            }
        }"#;

        let reordered_variants = [
            // dependencies: null before packages and lockfileVersion
            r#"{
                "dependencies": null,
                "packages": {
                    "": {
                        "name": "reordered-v3",
                        "version": "1.2.3",
                        "dependencies": { "dep-a": "^1.0.0" }
                    },
                    "node_modules/dep-a": {
                        "customUnknownField": { "b": 2, "a": 1 },
                        "version": "1.0.5",
                        "resolved": "https://registry.npmjs.org/dep-a/-/dep-a-1.0.5.tgz",
                        "integrity": "sha512-depa",
                        "hasInstallScript": false
                    }
                },
                "requires": true,
                "lockfileVersion": 3,
                "version": "1.2.3",
                "name": "reordered-v3"
            }"#,
            // dependencies as arbitrary string before packages, with lockfileVersion first
            r#"{
                "lockfileVersion": 3,
                "dependencies": "ignored-legacy-payload",
                "requires": true,
                "name": "reordered-v3",
                "version": "1.2.3",
                "packages": {
                    "": {
                        "name": "reordered-v3",
                        "version": "1.2.3",
                        "dependencies": { "dep-a": "^1.0.0" }
                    },
                    "node_modules/dep-a": {
                        "customUnknownField": { "b": 2, "a": 1 },
                        "version": "1.0.5",
                        "resolved": "https://registry.npmjs.org/dep-a/-/dep-a-1.0.5.tgz",
                        "integrity": "sha512-depa",
                        "hasInstallScript": false
                    }
                }
            }"#,
            // packages before dependencies before lockfileVersion
            r#"{
                "packages": {
                    "": {
                        "name": "reordered-v3",
                        "version": "1.2.3",
                        "dependencies": { "dep-a": "^1.0.0" }
                    },
                    "node_modules/dep-a": {
                        "customUnknownField": { "b": 2, "a": 1 },
                        "version": "1.0.5",
                        "resolved": "https://registry.npmjs.org/dep-a/-/dep-a-1.0.5.tgz",
                        "integrity": "sha512-depa",
                        "hasInstallScript": false
                    }
                },
                "dependencies": { "broken": 123 },
                "name": "reordered-v3",
                "version": "1.2.3",
                "requires": true,
                "lockfileVersion": 3
            }"#,
        ];

        let expected = LockfileV3::from_json_str(canonical).expect("LockfileV3 parse");
        let expected_bytes = expected.to_json_string().expect("LockfileV3 serialize");

        let migrated_canon = parse_and_migrate(canonical).expect("canonical parse_and_migrate");
        assert_eq!(migrated_canon, expected);
        assert_eq!(
            migrated_canon.to_json_string().unwrap(),
            expected_bytes,
            "canonical v3 migration must preserve exact raw package serialization"
        );

        for (idx, variant) in reordered_variants.iter().enumerate() {
            let parsed = parse_and_migrate(variant)
                .unwrap_or_else(|e| panic!("variant {idx} should succeed: {e}"));
            assert_eq!(parsed, expected, "variant {idx} LockfileV3 mismatch");
            assert_eq!(
                parsed.to_json_string().unwrap(),
                expected_bytes,
                "variant {idx} rewrite bytes mismatch"
            );
        }
    }

    #[test]
    fn test_reordered_v3_empty_or_null_packages_with_legacy_dependencies() {
        let v3_empty_pkgs_first = r#"{
            "dependencies": {
                "foo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                    "integrity": "sha512-foo"
                }
            },
            "packages": {},
            "lockfileVersion": 3,
            "name": "empty-pkgs",
            "version": "1.0.0"
        }"#;
        let v3_empty_pkgs_canonical = r#"{
            "name": "empty-pkgs",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {},
            "dependencies": {
                "foo": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                    "integrity": "sha512-foo"
                }
            }
        }"#;
        let a = parse_and_migrate(v3_empty_pkgs_canonical).expect("canonical empty pkgs");
        let b = parse_and_migrate(v3_empty_pkgs_first).expect("reordered empty pkgs");
        assert_eq!(a, b);
        assert_eq!(a.to_json_string().unwrap(), b.to_json_string().unwrap());
        assert_eq!(
            a.packages.get("node_modules/foo").and_then(|p| p.version.as_deref()),
            Some("1.0.0")
        );

        // `"packages": null` with `"dependencies": null` must fail regardless of field order
        let null_orders = [
            r#"{"lockfileVersion": 3, "packages": null, "dependencies": null, "name": "n"}"#,
            r#"{"dependencies": null, "packages": null, "name": "n", "lockfileVersion": 3}"#,
            r#"{"packages": null, "name": "n", "dependencies": null, "lockfileVersion": 3}"#,
        ];
        for (idx, json) in null_orders.iter().enumerate() {
            assert!(
                parse_and_migrate(json).is_err(),
                "null packages variant {idx} must be rejected"
            );
        }
    }

    #[test]
    fn test_reordered_v1_v2_and_unsupported_versions() {
        let v1_canonical = r#"{
            "name": "app-v1",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "requires": true,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                }
            }
        }"#;
        let v1_reordered = r#"{
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                }
            },
            "requires": true,
            "version": "1.0.0",
            "name": "app-v1",
            "lockfileVersion": 1
        }"#;
        let v1_omitted_version = r#"{
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-lodash"
                }
            },
            "requires": true,
            "version": "1.0.0",
            "name": "app-v1"
        }"#;

        let res_v1 = parse_and_migrate(v1_canonical).expect("v1 canonical");
        let res_v1_reordered = parse_and_migrate(v1_reordered).expect("v1 reordered");
        let res_v1_omitted = parse_and_migrate(v1_omitted_version).expect("v1 omitted version");
        assert_eq!(res_v1, res_v1_reordered);
        assert_eq!(res_v1, res_v1_omitted);
        assert_eq!(
            res_v1.to_json_string().unwrap(),
            res_v1_reordered.to_json_string().unwrap()
        );

        let v2_canonical = r#"{
            "name": "app-v2",
            "version": "2.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": { "name": "app-v2", "version": "2.0.0" },
                "node_modules/a": { "version": "1.0.0", "extraField": true }
            },
            "dependencies": {
                "a": { "version": "1.0.0" },
                "b": { "version": "2.0.0" }
            }
        }"#;
        let v2_reordered = r#"{
            "dependencies": {
                "a": { "version": "1.0.0" },
                "b": { "version": "2.0.0" }
            },
            "packages": {
                "": { "name": "app-v2", "version": "2.0.0" },
                "node_modules/a": { "version": "1.0.0", "extraField": true }
            },
            "version": "2.0.0",
            "name": "app-v2",
            "requires": true,
            "lockfileVersion": 2
        }"#;

        let res_v2 = parse_and_migrate(v2_canonical).expect("v2 canonical");
        let res_v2_reordered = parse_and_migrate(v2_reordered).expect("v2 reordered");
        assert_eq!(res_v2, res_v2_reordered);
        // v2 migration intentionally drops capture_raw so normalization/regeneration is canonical
        assert!(res_v2_reordered
            .packages
            .values()
            .all(|pkg| pkg.raw_value.is_none()));
        assert_eq!(
            res_v2.to_json_string().unwrap(),
            res_v2_reordered.to_json_string().unwrap()
        );

        let unsupported_first =
            r#"{"lockfileVersion": 99, "packages": {"bad": 123}, "dependencies": "bad"}"#;
        let unsupported_last =
            r#"{"dependencies": "bad", "packages": {"bad": 123}, "lockfileVersion": 99}"#;
        assert!(matches!(
            parse_and_migrate(unsupported_first),
            Err(LockfileError::UnsupportedVersion(99))
        ));
        assert!(matches!(
            parse_and_migrate(unsupported_last),
            Err(LockfileError::UnsupportedVersion(99))
        ));
    }
}
