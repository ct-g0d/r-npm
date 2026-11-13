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
        .or_else(|| match &action {
            CacheAction::Clean { cache: c, .. } => c.clone(),
            CacheAction::Verify { cache: c } => c.clone(),
            CacheAction::Add { cache: c, .. } => c.clone(),
            CacheAction::Ls { cache: c, .. } => c.clone(),
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
            println!("rnpm: cache cleared successfully ({})", cache_path.display());
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
    }

    Ok(())
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
) -> Result<(Vec<u8>, String, rnpm_registry::metadata::AbbreviatedPackageMetadata, String)> {
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
