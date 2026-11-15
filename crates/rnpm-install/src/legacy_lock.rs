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

pub(crate) const OLD_LOCKFILE_WARNING: &str = "npm warn old lockfile
npm warn old lockfile The package-lock.json file was created with an old version of npm,
npm warn old lockfile so supplemental metadata must be fetched from the registry.
npm warn old lockfile
npm warn old lockfile This is a one-time fix-up, please be patient...
npm warn old lockfile";

/// True when the raw lockfile text predates lockfileVersion 2.
pub(crate) fn is_old_lockfile(raw: &str) -> bool {
    #[derive(Deserialize)]
    struct Version {
        #[serde(rename = "lockfileVersion")]
        lockfile_version: Option<u64>,
    }
    serde_json::from_str::<Version>(raw)
        .ok()
        .and_then(|v| v.lockfile_version)
        .is_some_and(|v| v < 2)
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
) -> HashSet<String> {
    let mut names: Vec<String> = lockfile
        .packages
        .iter()
        .filter_map(|(loc, pkg)| registry_entry_name(loc, pkg))
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
}
