use crate::CacheAction;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) fn run(action: CacheAction, cache_arg: Option<PathBuf>, current_dir: PathBuf) -> Result<()> {
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
                eprintln!("npm error code EUSAGE");
                eprintln!("npm error As of npm@5, the npm cache self-heals from corruption issues");
                eprintln!("npm error and data extracted from the cache is guaranteed to be valid.");
                eprintln!("npm error If you want to make sure everything is healthy, use 'rnpm cache verify' instead.");
                eprintln!("npm error If you are sure you want to delete the entire cache, run:");
                eprintln!("npm error   rnpm cache clean --force");
                std::process::exit(1);
            }
            cache.clean()?;
            println!("rnpm: cache cleared successfully ({})", cache_path.display());
        }
        CacheAction::Verify { .. } => {
            let start = std::time::Instant::now();
            let report = cache.verify()?;
            let elapsed = start.elapsed().as_secs_f64();
            println!("Cache verified and compacted ({})", cache_path.display());
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
                collect_entries(&cache_path, &cache_path, &mut entries);
                entries.sort();
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
            let target_file = Path::new(&package);
            if target_file.exists() && target_file.is_file() {
                let data = std::fs::read(target_file)?;
                let file_name = target_file
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("package.tgz");
                let key = format!("file:{}", file_name);
                cache.put(&key, &data, None)?;
                println!("Added {} to cache", package);
            } else {
                // If it's a package spec, store marker into cache index
                let key = format!("pkg:{}", package);
                cache.put(&key, package.as_bytes(), None)?;
                println!("Added {} to cache", package);
            }
        }
    }

    Ok(())
}

fn collect_entries(base: &Path, current: &Path, list: &mut Vec<String>) {
    if let Ok(rd) = std::fs::read_dir(current) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_entries(base, &p, list);
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(base) {
                    let s = rel.to_string_lossy().replace('\\', "/");
                    list.push(s);
                }
            }
        }
    }
}
