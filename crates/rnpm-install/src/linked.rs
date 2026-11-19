//! The `install-strategy` setting and the link helpers its layouts share.
//! The linked layout itself is npm's isolated tree, in `isolated.rs`.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

use rnpm_fs::junction::{create_junction, is_junction, remove_dir_all_safe, remove_junction};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

/// Strategy used for installing packages into node_modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallStrategy {
    #[default]
    Hoisted,
    Linked,
    Nested,
    Shallow,
}

impl std::str::FromStr for InstallStrategy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hoisted" => Ok(InstallStrategy::Hoisted),
            "linked" => Ok(InstallStrategy::Linked),
            "nested" => Ok(InstallStrategy::Nested),
            "shallow" => Ok(InstallStrategy::Shallow),
            other => Err(anyhow!(
                "Unknown install strategy: '{other}'. Valid strategies are: hoisted, linked, nested, shallow"
            )),
        }
    }
}

impl std::fmt::Display for InstallStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallStrategy::Hoisted => write!(f, "hoisted"),
            InstallStrategy::Linked => write!(f, "linked"),
            InstallStrategy::Nested => write!(f, "nested"),
            InstallStrategy::Shallow => write!(f, "shallow"),
        }
    }
}


/// Safely creates or replaces an NTFS junction or directory.
pub fn create_or_replace_junction(link: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    if is_junction(link).unwrap_or(false) {
        let _ = remove_junction(link);
    } else if link.exists() {
        let _ = remove_dir_all_safe(link);
    }
    create_junction(link, target).map_err(|e| {
        anyhow!(
            "Failed to create junction from {:?} to {:?}: {}",
            link,
            target,
            e
        )
    })?;
    Ok(())
}

/// Recursively copies a directory (used for native addon fallbacks).
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let target_path = dst.join(entry.file_name());
        if entry_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target_path)?;
        } else {
            fs::copy(entry.path(), &target_path)?;
        }
    }
    Ok(())
}

/// Resolves a dependency from an arbitrary consumer location in a LockfileV3 tree.
pub fn resolve_lockfile_dep<'a>(
    lockfile: &'a LockfileV3,
    consumer_loc: &str,
    dep_name: &str,
) -> Option<(String, &'a LockfilePackage)> {
    if consumer_loc.is_empty() {
        let root_key = format!("node_modules/{dep_name}");
        if let Some(pkg) = lockfile.packages.get(&root_key) {
            return Some((root_key, pkg));
        }
        return None;
    }

    let mut current = consumer_loc;
    loop {
        let candidate = format!("{current}/node_modules/{dep_name}");
        if let Some(pkg) = lockfile.packages.get(&candidate) {
            return Some((candidate, pkg));
        }
        if let Some(idx) = current.rfind("/node_modules/") {
            current = &current[..idx];
        } else {
            break;
        }
    }

    let root_candidate = format!("node_modules/{dep_name}");
    if let Some(pkg) = lockfile.packages.get(&root_candidate) {
        return Some((root_candidate, pkg));
    }

    None
}
