use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn populate_from_node_modules(root: &Path, lock: &mut rnpm_lockfile::LockfileV3) -> Result<()> {
    let nm_root = root.join("node_modules");
    if !nm_root.is_dir() {
        return Ok(());
    }
    let mut visited = HashSet::new();
    if let Ok(canon) = std::fs::canonicalize(root) {
        visited.insert(canon);
    }
    walk_nm(&nm_root, root, lock, &mut visited)?;
    Ok(())
}

fn walk_nm(
    dir: &Path,
    root: &Path,
    lock: &mut rnpm_lockfile::LockfileV3,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let Ok(sym_meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let is_symlink_or_junction =
            sym_meta.file_type().is_symlink() || rnpm_fs::is_junction(&path).unwrap_or(false);
        if !is_symlink_or_junction && !sym_meta.is_dir() {
            continue;
        }
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if file_name.starts_with('.') {
            continue;
        }
        if file_name.starts_with('@') {
            if !is_symlink_or_junction {
                walk_nm(&path, root, lock, visited)?;
            }
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_symlink_or_junction {
            let resolved = std::fs::canonicalize(&path)
                .ok()
                .and_then(|target| {
                    let canon_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
                    target
                        .strip_prefix(&canon_root)
                        .ok()
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                })
                .or_else(|| {
                    std::fs::read_link(&path)
                        .ok()
                        .map(|t| t.to_string_lossy().replace('\\', "/"))
                });
            lock.packages.insert(
                rel,
                rnpm_lockfile::LockfilePackage {
                    resolved,
                    link: Some(true),
                    ..Default::default()
                },
            );
            continue;
        }
        if let Ok(canon) = std::fs::canonicalize(&path) {
            if !visited.insert(canon) {
                continue;
            }
        }
        let manifest_path = path.join("package.json");
        if manifest_path.is_file() {
            if let Ok(manifest) = rnpm_core::Manifest::from_file(&manifest_path) {
                let pkg = rnpm_lockfile::LockfilePackage {
                    version: manifest.version.clone(),
                    dependencies: if manifest.dependencies.is_empty() {
                        None
                    } else {
                        Some(manifest.dependencies.clone())
                    },
                    // npm lockfile v3 omits devDependencies on installed node_modules/* entries.
                    dev_dependencies: None,
                    peer_dependencies: if manifest.peer_dependencies.is_empty() {
                        None
                    } else {
                        Some(manifest.peer_dependencies.clone())
                    },
                    optional_dependencies: if manifest.optional_dependencies.is_empty() {
                        None
                    } else {
                        Some(manifest.optional_dependencies.clone())
                    },
                    ..Default::default()
                };
                lock.packages.insert(rel, pkg);
            }
            let nested = path.join("node_modules");
            if nested.is_dir() {
                walk_nm(&nested, root, lock, visited)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn run(current_dir: PathBuf) -> Result<()> {
    let src = current_dir.join("package-lock.json");
    let dst = current_dir.join("npm-shrinkwrap.json");
    if dst.exists() {
        eprintln!("npm notice npm-shrinkwrap.json up to date");
    } else if src.exists() {
        if std::fs::rename(&src, &dst).is_err() {
            std::fs::copy(&src, &dst)?;
            std::fs::remove_file(&src)?;
        }
        eprintln!("npm notice package-lock.json has been renamed to npm-shrinkwrap.json");
    } else if current_dir.join("package.json").exists() {
        let pkg_path = current_dir.join("package.json");
        let manifest = rnpm_core::Manifest::from_file(&pkg_path)
            .map_err(|e| anyhow!("npm error code EJSONPARSE\n{}", e))?;
        let mut lock = rnpm_lockfile::LockfileV3::from_manifest(&manifest);

        if rnpm_install::fast_path::validate_hidden_lockfile_simple(&current_dir) {
            if let Ok(hidden) = rnpm_lockfile::LockfileV3::load_hidden(&current_dir) {
                for (k, v) in hidden.packages {
                    if !k.is_empty() {
                        lock.packages.insert(k, v);
                    }
                }
            }
        }

        if lock.packages.len() <= 1 && current_dir.join("node_modules").is_dir() {
            populate_from_node_modules(&current_dir, &mut lock)?;
        }

        lock.save_to_file(&dst)?;
        eprintln!("npm notice created a lockfile as npm-shrinkwrap.json with version 3");
    } else {
        return Err(anyhow!(
            "npm error code ENOENT\nnpm error package.json not found"
        ));
    }
    Ok(())
}
