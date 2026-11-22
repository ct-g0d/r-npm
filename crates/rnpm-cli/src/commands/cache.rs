use crate::CacheAction;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) async fn run(
    action: CacheAction,
    cache_arg: Option<PathBuf>,
    current_dir: PathBuf,
) -> Result<()> {
    let config = rnpm_config::Config::load(Some(&current_dir)).unwrap_or_default();
    let cache_path = cache_arg
        .clone()
        .or_else(|| match &action {
            CacheAction::Clean { cache: c, .. } => c.clone(),
            CacheAction::Verify { cache: c } => c.clone(),
            CacheAction::Add { cache: c, .. } => c.clone(),
            CacheAction::Ls { cache: c, .. } => c.clone(),
            CacheAction::Npx { cache: c, action: npx_action, .. } => {
                c.clone().or_else(|| match npx_action {
                    crate::CacheNpxAction::Rm { cache: c, .. } => c.clone(),
                    crate::CacheNpxAction::Info { cache: c, .. } => c.clone(),
                    crate::CacheNpxAction::Ls { cache: c, .. } => c.clone(),
                })
            }
        })
        .unwrap_or_else(|| {
            if let Some(user_cache) = config.npmrc.settings.get("cache") {
                PathBuf::from(user_cache)
            } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                PathBuf::from(appdata).join("rnpm").join("cache")
            } else {
                std::env::temp_dir().join(".rnpm-cache")
            }
        });

    let cache = rnpm_cache::Cache::new(&cache_path)
        .with_context(|| format!("Failed to initialize cache at {}", cache_path.display()))?;

    match action {
        CacheAction::Clean { force, .. } => {
            if !force {
                eprintln!("npm error As of npm@5, the npm cache self-heals from corruption issues by treating integrity mismatches as cache misses.");
                eprintln!("npm error As a result, data extracted from the cache is guaranteed to be valid.");
                eprintln!("npm error If you want to make sure everything is consistent, use `npm cache verify` instead.");
                eprintln!("npm error Deleting the cache can only make npm go slower, and is not likely to correct any problems you may be encountering!");
                eprintln!("npm error");
                eprintln!("npm error On the other hand, if you're debugging an issue with the installer, or race conditions that depend on the timing of writing to an empty cache, you can use `npm install --cache /tmp/empty-cache` to use a temporary cache instead of removing the actual one.");
                eprintln!("npm error");
                eprintln!("npm error If you're sure you want to delete the entire cache, rerun this command with --force.");
                std::process::exit(1);
            }
            cache.clean()?;
            let stores = std::collections::BTreeSet::from([
                rnpm_cache::PackStore::default_location(Some(&cache_path)),
                rnpm_cache::PackStore::default_location(None),
            ]);
            for store in stores {
                rnpm_cache::PackStore::clean_at(&store)?;
            }
        }
        CacheAction::Verify { .. } => {
            let start = std::time::Instant::now();
            let report = cache.verify()?;
            let elapsed = start.elapsed().as_secs_f64();
            println!("Cache verified and compacted ({}):", cache_path.display());
            println!(
                "Content verified: {} ({} bytes)",
                report.verified_blobs, report.total_blob_bytes
            );
            println!("Index entries: {}", report.verified_indices);
            if report.corrupted_blobs > 0
                || report.corrupted_indices > 0
                || report.orphaned_indices > 0
                || report.stale_temp_files_cleaned > 0
            {
                println!(
                    "Cleaned: {} corrupt blob(s), {} corrupt index file(s), {} orphaned index pointer(s), {} stale temp file(s)",
                    report.corrupted_blobs,
                    report.corrupted_indices,
                    report.orphaned_indices,
                    report.stale_temp_files_cleaned
                );
            }
            println!("Finished in {:.3}s", elapsed);
        }
        CacheAction::Ls { path: filter, .. } => {
            if cache_path.exists() {
                let mut entries = Vec::new();
                collect_entries(&cache_path.join("index-v5"), &mut entries);
                collect_entries(&cache_path.join("_cacache/index-v5"), &mut entries);
                entries.sort();
                entries.dedup();
                for entry in entries {
                    if let Some(ref filt) = filter {
                        if entry.contains(filt) {
                            println!("{}", entry);
                        }
                    } else {
                        println!("{}", entry);
                    }
                }
            }
        }
        CacheAction::Add { package, .. } => {
            let target_file = current_dir.join(package.strip_prefix("file:").unwrap_or(&package));
            if target_file.exists() && target_file.is_file() {
                let data = std::fs::read(&target_file)?;
                let key = format!(
                    "pacote:tarball:file:{}",
                    target_file.to_string_lossy().replace('\\', "/")
                );
                cache.put(&key, &data, None)?;
            } else if target_file.is_dir() {
                let (_, data) = rnpm_fs::pack_directory(&target_file, None)?;
                let key = format!(
                    "pacote:tarball:file:{}",
                    target_file.to_string_lossy().replace('\\', "/")
                );
                cache.put(&key, &data, None)?;
            } else {
                cache_registry_package(&cache, &current_dir, &package).await?;
            }
        }
        CacheAction::Npx {
            action: npx_action,
            cache: c,
            force,
            dry_run,
        } => {
            let npx_cache_override = c.or(cache_arg);
            let final_cache = npx_cache_override.unwrap_or(cache_path);
            run_npx(npx_action, &final_cache, force, dry_run).await?;
        }
    }

    Ok(())
}

async fn run_npx(
    action: crate::CacheNpxAction,
    cache_path: &Path,
    parent_force: bool,
    parent_dry_run: bool,
) -> Result<()> {
    let npx_cache = match &action {
        crate::CacheNpxAction::Ls { cache: Some(c) }
        | crate::CacheNpxAction::Rm { cache: Some(c), .. }
        | crate::CacheNpxAction::Info { cache: Some(c), .. } => c.join("_npx"),
        _ => cache_path.join("_npx"),
    };

    match action {
        crate::CacheNpxAction::Ls { .. } => {
            if !npx_cache.exists() {
                println!("npx cache does not exist");
                return Ok(());
            }
            let mut entries: Vec<(String, PathBuf)> = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&npx_cache) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        entries.push((entry.file_name().to_string_lossy().to_string(), p));
                    }
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (hash, pkg_path) in entries {
                let pkg_json_path = pkg_path.join("package.json");
                let pkg_val: Option<serde_json::Value> = std::fs::read_to_string(&pkg_json_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
                let mut line = format!("{hash}:");
                if pkg_val.is_none() {
                    line.push_str(" (empty/invalid)");
                } else if let Some(npx) = pkg_val.as_ref().and_then(|p| p.get("_npx")).and_then(|v| v.as_object()) {
                    if let Some(pkgs) = npx.get("packages").and_then(|v| v.as_array()) {
                        let list: Vec<&str> = pkgs.iter().filter_map(|p| p.as_str()).collect();
                        line.push(' ');
                        line.push_str(&list.join(", "));
                    } else {
                        line.push_str(" (unknown)");
                    }
                } else {
                    line.push_str(" (unknown)");
                }
                println!("{line}");
            }
        }
        crate::CacheNpxAction::Rm {
            keys,
            force,
            dry_run,
            ..
        } => {
            let effective_force = force || parent_force;
            let effective_dry_run = dry_run || parent_dry_run;
            if keys.is_empty() {
                if !effective_force {
                    anyhow::bail!("npm error code EUSAGE\nnpm error Please use --force to remove entire npx cache");
                }
                if npx_cache.exists() && !effective_dry_run {
                    std::fs::remove_dir_all(&npx_cache)?;
                }
                return Ok(());
            }
            if !npx_cache.exists() {
                anyhow::bail!("npm error code EUSAGE\nnpm error Invalid npx key {}", keys[0]);
            }
            let mut existing_keys = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&npx_cache) {
                for entry in rd.flatten() {
                    if entry.path().is_dir() {
                        existing_keys.push(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
            for key in &keys {
                let resolved = resolve_abbrev(&existing_keys, key)
                    .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error Invalid npx key {key}"))?;
                let target = npx_cache.join(resolved);
                println!("Removing npx key at {}", target.display());
                if !effective_dry_run {
                    std::fs::remove_dir_all(&target)?;
                }
            }
        }
        crate::CacheNpxAction::Info { keys, .. } => {
            if keys.is_empty() {
                anyhow::bail!("npm error code EUSAGE\nnpm error npx info requires at least one key");
            }
            if !npx_cache.exists() {
                anyhow::bail!("npm error code EUSAGE\nnpm error Invalid npx key {}", keys[0]);
            }
            let mut existing_keys = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&npx_cache) {
                for entry in rd.flatten() {
                    if entry.path().is_dir() {
                        existing_keys.push(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
            for key in &keys {
                let resolved = resolve_abbrev(&existing_keys, key)
                    .ok_or_else(|| anyhow::anyhow!("npm error code EUSAGE\nnpm error Invalid npx key {key}"))?;
                let hash = resolved;
                let path = npx_cache.join(hash);
                let pkg_json_path = path.join("package.json");
                let pkg_val: Option<serde_json::Value> = std::fs::read_to_string(&pkg_json_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
                let has_lock = path.join("package-lock.json").is_file()
                    || path.join("node_modules/.package-lock.json").is_file();
                let valid = pkg_val.is_some() && (has_lock || path.join("node_modules").is_dir());
                if valid {
                    println!("valid npx cache entry with key {hash}");
                    println!("location: {}", path.display());
                    let pkg = pkg_val.unwrap();
                    if let Some(pkgs) = pkg.get("_npx").and_then(|v| v.get("packages")).and_then(|v| v.as_array()) {
                        println!("packages:");
                        for p in pkgs {
                            if let Some(spec_str) = p.as_str() {
                                let (pkg_name, _) = crate::parse_package_spec(spec_str);
                                let ver = get_installed_pkg_version(&path, &pkg_name);
                                if let Some(v) = ver {
                                    println!("- {spec_str} ({pkg_name}@{v})");
                                } else {
                                    println!("- {spec_str} ({spec_str})");
                                }
                            }
                        }
                    } else {
                        println!("packages: (unknown)");
                        println!("dependencies:");
                        if let Some(deps) = pkg.get("dependencies").and_then(|v| v.as_object()) {
                            for (dep_name, dep_val) in deps {
                                let ver = get_installed_pkg_version(&path, dep_name);
                                if let Some(v) = ver {
                                    println!("- {dep_name}@{v}");
                                } else {
                                    let req = dep_val.as_str().unwrap_or("*");
                                    println!("- {dep_name}@{req}");
                                }
                            }
                        }
                    }
                } else {
                    println!("invalid npx cache entry with key {hash}");
                    println!("location: {}", path.display());
                }
                println!();
            }
        }
    }
    Ok(())
}

fn resolve_abbrev<'a>(keys: &'a [String], input: &str) -> Option<&'a str> {
    if let Some(exact) = keys.iter().find(|k| *k == input) {
        return Some(exact.as_str());
    }
    let candidates: Vec<&'a str> = keys
        .iter()
        .filter(|k| k.starts_with(input))
        .map(|k| k.as_str())
        .collect();
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

fn get_installed_pkg_version(path: &Path, pkg_name: &str) -> Option<String> {
    let pkg_json = path.join("node_modules").join(pkg_name).join("package.json");
    if let Ok(text) = std::fs::read_to_string(pkg_json) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(v) = val.get("version").and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
        }
    }
    let lock_path = path.join("package-lock.json");
    if let Ok(text) = std::fs::read_to_string(lock_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            let key = format!("node_modules/{pkg_name}");
            if let Some(packages) = val.get("packages").and_then(|p| p.as_object()) {
                if let Some(pkg_obj) = packages.get(&key) {
                    if let Some(v) = pkg_obj.get("version").and_then(|v| v.as_str()) {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

fn collect_entries(current: &Path, list: &mut Vec<String>) {
    if let Ok(rd) = std::fs::read_dir(current) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_entries(&p, list);
            } else if p.is_file() {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    let mut live = std::collections::BTreeMap::new();
                    let records: Vec<&str> =
                        if serde_json::from_str::<serde_json::Value>(&text).is_ok() {
                            vec![&text]
                        } else {
                            text.lines()
                                .filter_map(|line| line.split_once('\t').map(|(_, json)| json))
                                .collect()
                        };
                    for record in records {
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(record) {
                            if let Some(key) = value.get("key").and_then(|v| v.as_str()) {
                                live.insert(
                                    key.to_string(),
                                    value.get("integrity").is_some_and(|v| !v.is_null()),
                                );
                            }
                        }
                    }
                    list.extend(
                        live.into_iter()
                            .filter_map(|(key, valid)| valid.then_some(key)),
                    );
                }
            }
        }
    }
}

async fn cache_registry_package(
    cache: &rnpm_cache::Cache,
    cwd: &Path,
    package: &str,
) -> Result<()> {
    use rnpm_core::spec::{PackageSpec, PackageTarget};
    let spec = PackageSpec::parse(package)?;
    let (_, client) = crate::make_registry_client(cwd, None)?;
    if let PackageTarget::Url(url) = &spec.target {
        let bytes = client.download_tarball_bytes(url.as_str()).await?;
        cache.put(
            &format!("make-fetch-happen:request-cache:{url}"),
            &bytes,
            None,
        )?;
        cache.put(&format!("pacote:tarball:{package}"), &bytes, None)?;
        return Ok(());
    }
    let (name, target) = if let PackageTarget::Alias { name, target } = &spec.target {
        (name.as_str(), target.as_ref())
    } else {
        (spec.name.as_str(), &spec.target)
    };
    let (bytes, version, metadata, tarball_url) =
        download_registry_package(&client, package, name, target).await?;
    cache.put(
        &format!(
            "make-fetch-happen:request-cache:{}",
            client.package_metadata_url(name)?
        ),
        &serde_json::to_vec(&metadata)?,
        None,
    )?;
    cache.put(
        &format!("make-fetch-happen:request-cache:{tarball_url}"),
        &bytes,
        None,
    )?;
    cache.put(&format!("pacote:tarball:{name}@{version}"), &bytes, None)?;
    Ok(())
}

/// Resolve a registry spec like pacote (a range prefers the `latest` tag
/// when it satisfies) and download its verified tarball.
pub(crate) async fn download_registry_package(
    client: &rnpm_registry::RegistryClient,
    package: &str,
    name: &str,
    target: &rnpm_core::spec::PackageTarget,
) -> Result<(
    Vec<u8>,
    String,
    rnpm_registry::metadata::AbbreviatedPackageMetadata,
    String,
)> {
    use rnpm_core::spec::PackageTarget;
    let metadata = client.get_package_metadata(name).await?;
    let version = match target {
        PackageTarget::Version(version) => version.to_string(),
        PackageTarget::Tag(tag) => metadata.dist_tags.get(tag).cloned().ok_or_else(|| anyhow::anyhow!("npm error code ETARGET\nnpm error No matching tag found for {name}@{tag}"))?,
        PackageTarget::Range(range) => metadata
            .dist_tags
            .get("latest")
            .filter(|l| rnpm_core::semver::Version::parse(l).is_ok_and(|v| range.satisfies(&v)))
            .cloned()
            .or_else(|| {
                metadata
                    .versions
                    .keys()
                    .filter_map(|v| rnpm_core::semver::Version::parse(v).ok())
                    .filter(|v| range.satisfies(v))
                    .max()
                    .map(|v| v.to_string())
            })
            .ok_or_else(|| anyhow::anyhow!("npm error code ETARGET\nnpm error No matching version found for {package}"))?,
        _ => anyhow::bail!("npm error code EUNSUPPORTEDPROTOCOL\nnpm error Unsupported cache package spec: {package}"),
    };
    let resolved = metadata.versions.get(&version).ok_or_else(|| {
        anyhow::anyhow!("npm error code ETARGET\nnpm error No matching version found for {package}")
    })?;
    let bytes = client
        .download_tarball_bytes(&resolved.dist.tarball)
        .await?;
    if let Some(integrity) = &resolved.dist.integrity {
        rnpm_core::integrity::Integrity::parse(integrity)?.verify(&bytes)?;
    } else if let Some(shasum) = &resolved.dist.shasum {
        let actual = rnpm_core::integrity::Algorithm::Sha1.compute_digest(&bytes);
        anyhow::ensure!(
            data_encoding::HEXLOWER.encode(&actual) == *shasum,
            "npm error code EINTEGRITY\nnpm error Tarball checksum mismatch"
        );
    }
    let tarball_url = resolved.dist.tarball.clone();
    Ok((bytes, version, metadata, tarball_url))
}
