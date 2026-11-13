use anyhow::{anyhow, Result};
use flate2::read::GzDecoder;
use rnpm_cache::Cache;
use rnpm_core::manifest::Manifest;
use rnpm_lockfile::LockfileV3;
use rnpm_registry::RegistryClient;
use rnpm_solver::{DependencyGraph, Node, NodeFlags};
use std::collections::BTreeMap;
use std::io::Read;

/// Arborist loads the physical tree in bundled tarballs before writing the
/// ideal lockfile. These packages have no separate resolved URL or integrity.
pub(crate) async fn inflate(
    lockfile: &mut LockfileV3,
    cache: &Cache,
    client: &RegistryClient,
    offline: bool,
    project_dir: &std::path::Path,
) -> Result<()> {
    let owners: Vec<_> = lockfile
        .packages
        .iter()
        .filter(|(location, package)| {
            !location.is_empty()
                && package.in_bundle != Some(true)
                && package
                    .bundle_dependencies
                    .as_ref()
                    .is_some_and(|bundled| match bundled {
                        rnpm_core::manifest::BundledDependencies::Boolean(value) => *value,
                        rnpm_core::manifest::BundledDependencies::List(names) => !names.is_empty(),
                    })
        })
        .map(|(location, package)| (location.clone(), package.clone()))
        .collect();
    if owners.is_empty() {
        return Ok(());
    }
    for (location, owner) in owners {
        let Some(url) = owner.resolved.as_deref() else {
            continue;
        };
        let expected = owner
            .integrity
            .as_deref()
            .map(str::parse::<rnpm_core::Integrity>)
            .transpose()?;
        let cached = cache.get(url)?.map(|(_, data)| data).filter(|data| {
            expected
                .as_ref()
                .is_none_or(|integrity| integrity.verify(data).is_ok())
        });
        let bytes = match cached {
            Some(bytes) => bytes,
            None if offline => return Err(anyhow!(
                "npm error code ENOTCACHED\nnpm error Bundled package tarball is not cached: {url}"
            )),
            None => {
                let bytes = if let Some(file) = url.strip_prefix("file:") {
                    std::fs::read(project_dir.join(file))?
                } else {
                    client.download_tarball_bytes(url).await?
                };
                if let Some(integrity) = &expected {
                    integrity.verify(&bytes)?;
                }
                cache.put_with_integrity(url, &bytes, expected.as_ref(), None)?;
                bytes
            }
        };
        let mut bundled = DependencyGraph::new();
        let mut archive = tar::Archive::new(GzDecoder::new(bytes.as_slice()));
        for entry in archive.entries()? {
            let entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.to_string_lossy().replace('\\', "/");
            let Some(relative) = path
                .strip_prefix("package/")
                .and_then(|p| p.strip_suffix("/package.json"))
            else {
                continue;
            };
            if !is_package_location(relative) {
                continue;
            }
            let mut bytes = Vec::new();
            entry.take(16 * 1024 * 1024).read_to_end(&mut bytes)?;
            let manifest = Manifest::from_slice(&bytes)?;
            let full_location = format!("{location}/{relative}");
            let install_name = relative
                .rsplit_once("node_modules/")
                .map(|(_, name)| name)
                .unwrap_or(relative);
            let mut dependencies = manifest.dependencies.clone();
            dependencies.retain(|name, _| !manifest.optional_dependencies.contains_key(name));
            let node = Node {
                location: full_location.clone(),
                install_name: install_name.into(),
                name: manifest.name.clone().unwrap_or_else(|| install_name.into()),
                version: manifest.version.clone().unwrap_or_default(),
                dependencies,
                peer_dependencies: manifest.peer_dependencies.clone(),
                peer_dependencies_meta: manifest.peer_dependencies_meta.clone(),
                optional_dependencies: manifest.optional_dependencies.clone(),
                os: manifest.os.clone(),
                cpu: manifest.cpu.clone(),
                libc: manifest.libc.clone(),
                engines: manifest.engines.clone(),
                license: manifest
                    .extra
                    .get("license")
                    .and_then(|v| {
                        v.as_str()
                            .or_else(|| v.get("type").and_then(|v| v.as_str()))
                    })
                    .map(str::to_owned),
                bin: manifest.bin.clone().map(|bin| match bin {
                    rnpm_core::manifest::PackageBin::Single(value) => {
                        rnpm_lockfile::PackageBin::Single(value)
                    }
                    rnpm_core::manifest::PackageBin::Map(value) => {
                        rnpm_lockfile::PackageBin::Map(value)
                    }
                }),
                flags: NodeFlags {
                    bundled: true,
                    peer: owner.peer == Some(true),
                    has_install_script: ["preinstall", "install", "postinstall"]
                        .iter()
                        .any(|name| manifest.scripts.contains_key(*name)),
                    ..Default::default()
                },
                extra: {
                    let mut extra: BTreeMap<_, _> = manifest.extra.clone();
                    if let Some(url) = extra.get("funding").and_then(|v| v.as_str()) {
                        extra.insert("funding".into(), serde_json::json!({"url":url}));
                    }
                    if let Some(value) = &manifest.bundled_dependencies {
                        extra.insert("bundleDependencies".into(), serde_json::to_value(value)?);
                    }
                    extra
                },
                ..Default::default()
            };
            bundled.nodes.insert(full_location, node);
        }
        for (location, package) in bundled.to_lockfile_v3("", None).packages {
            if !location.is_empty() {
                lockfile.packages.insert(location, package);
            }
        }
    }
    let mut graph = DependencyGraph::from_lockfile_v3(lockfile);
    graph.normalize_dependency_flags();
    for (location, package) in &mut lockfile.packages {
        if package.in_bundle != Some(true) {
            continue;
        }
        if let Some(node) = graph.nodes.get(location) {
            package.dev = node.flags.dev.then_some(true);
            package.optional = node.flags.optional.then_some(true);
            package.dev_optional = node.flags.dev_optional.then_some(true);
            package.preserve_dev_optional_split = true;
        }
    }
    Ok(())
}

fn is_package_location(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    let mut i = 0;
    while i < parts.len() {
        if parts[i] != "node_modules" {
            return false;
        }
        i += 1;
        let Some(name) = parts.get(i) else {
            return false;
        };
        if name.is_empty() || *name == "." || *name == ".." {
            return false;
        }
        i += 1;
        if name.starts_with('@') {
            let Some(name) = parts.get(i) else {
                return false;
            };
            if name.is_empty() || *name == "." || *name == ".." {
                return false;
            }
            i += 1;
        }
    }
    i > 0
}
