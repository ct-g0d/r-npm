//! Workspace discovery and monorepo manifest loading.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::WorkspaceError;
use crate::manifest::Manifest;
use crate::to_posix_path;

/// Discovered workspace package member in a monorepo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMember {
    /// Package name declared in member's package.json
    pub name: String,
    /// Package version declared in member's package.json (if any)
    pub version: Option<String>,
    /// Absolute or canonical path to member directory
    pub path: PathBuf,
    /// Relative POSIX path from workspace root (e.g. "packages/pkg-a")
    pub relative_path: String,
    /// Parsed manifest for this workspace member
    pub manifest: Manifest,
}

impl WorkspaceMember {
    /// Returns the path to this member's package.json
    pub fn manifest_path(&self) -> PathBuf {
        self.path.join("package.json")
    }
}

/// Discover workspace members starting from root directory and reading package.json.
pub fn discover_workspaces(root_dir: &Path) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let manifest_path = root_dir.join("package.json");
    if !manifest_path.exists() {
        return Ok(Vec::new());
    }
    let manifest = Manifest::from_file(&manifest_path).map_err(WorkspaceError::Manifest)?;
    discover_workspaces_from_manifest(root_dir, &manifest)
}

/// Discover workspace members given a pre-parsed root manifest.
pub fn discover_workspaces_from_manifest(
    root_dir: &Path,
    root_manifest: &Manifest,
) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let patterns = root_manifest.workspace_patterns();
    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let dirs = match_glob_patterns(root_dir, &patterns).map_err(WorkspaceError::Io)?;
    let mut members = Vec::new();
    let mut seen_names: BTreeMap<String, PathBuf> = BTreeMap::new();

    for dir in dirs {
        let manifest_path = dir.join("package.json");
        if !manifest_path.exists() {
            continue;
        }

        let member_manifest = Manifest::from_file(&manifest_path).map_err(WorkspaceError::Manifest)?;
        let name = member_manifest.name.clone().unwrap_or_else(|| {
            dir.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".to_string())
        });

        if let Some(prev_path) = seen_names.insert(name.clone(), dir.clone()) {
            return Err(WorkspaceError::DuplicatePackage {
                name,
                first: prev_path,
                second: dir,
            });
        }

        let rel_path = dir.strip_prefix(root_dir).unwrap_or(&dir);
        let posix_rel = to_posix_path(&rel_path.to_string_lossy());

        members.push(WorkspaceMember {
            name,
            version: member_manifest.version.clone(),
            path: dir,
            relative_path: posix_rel,
            manifest: member_manifest,
        });
    }

    members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(members)
}

/// Match directory glob patterns relative to root_dir.
pub fn match_glob_patterns(root_dir: &Path, patterns: &[String]) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut matched_dirs = HashSet::new();

    let (negative_patterns, positive_patterns): (Vec<_>, Vec<_>) =
        patterns.iter().partition(|p| p.starts_with('!'));

    for pattern in positive_patterns {
        let clean_pattern = pattern.trim();
        let clean_pattern = clean_pattern.strip_prefix("./").unwrap_or(clean_pattern);
        let clean_pattern = clean_pattern.strip_prefix(".\\").unwrap_or(clean_pattern);
        let posix_pattern = clean_pattern.replace('\\', "/");

        let segments: Vec<&str> = posix_pattern
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if segments.is_empty() {
            continue;
        }

        traverse_segments(root_dir, &segments, &mut matched_dirs)?;
    }

    // Filter out exclusions
    let mut final_results: Vec<PathBuf> = Vec::new();
    for dir in matched_dirs {
        let rel_path = dir.strip_prefix(root_dir).unwrap_or(&dir);
        let posix_rel = to_posix_path(&rel_path.to_string_lossy());

        let mut excluded = false;
        for neg in &negative_patterns {
            let neg_clean = neg.trim().strip_prefix('!').unwrap_or(neg).trim();
            let neg_clean = neg_clean.strip_prefix("./").unwrap_or(neg_clean);
            let neg_clean = neg_clean.strip_prefix(".\\").unwrap_or(neg_clean);
            let posix_neg = neg_clean.replace('\\', "/");

            if matches_neg_pattern(&posix_neg, &posix_rel) {
                excluded = true;
                break;
            }
        }

        if !excluded {
            final_results.push(dir);
        }
    }

    final_results.sort();
    Ok(final_results)
}

fn traverse_segments(
    current: &Path,
    segments: &[&str],
    results: &mut HashSet<PathBuf>,
) -> std::io::Result<()> {
    if segments.is_empty() {
        if current.join("package.json").is_file() {
            results.insert(current.to_path_buf());
        }
        return Ok(());
    }

    let segment = segments[0];
    let remaining = &segments[1..];

    if segment == "**" {
        // Option 1: ** matches 0 directory levels
        traverse_segments(current, remaining, results)?;

        // Option 2: ** matches 1 or more directory levels
        if current.is_dir() {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if should_skip_dir(&name_str) {
                        continue;
                    }
                    let child_path = entry.path();
                    // Recurse keeping ** to go deeper
                    traverse_segments(&child_path, segments, results)?;
                    // Or match remaining from here
                    traverse_segments(&child_path, remaining, results)?;
                }
            }
        }
    } else if segment == "*" {
        if current.is_dir() {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if should_skip_dir(&name_str) {
                        continue;
                    }
                    traverse_segments(&entry.path(), remaining, results)?;
                }
            }
        }
    } else if segment.contains('*') || segment.contains('?') {
        if current.is_dir() {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if should_skip_dir(&name_str) {
                        continue;
                    }
                    if wildcard_match(segment, &name_str) {
                        traverse_segments(&entry.path(), remaining, results)?;
                    }
                }
            }
        }
    } else {
        let child = current.join(segment);
        if child.is_dir() {
            traverse_segments(&child, remaining, results)?;
        }
    }

    Ok(())
}

fn should_skip_dir(name: &str) -> bool {
    name.starts_with('.')
        || name == "node_modules"
        || name == "target"
        || name == "dist"
        || name == "build"
}

/// Simple glob wildcard matching for segments with '*' and '?'.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let p_chars: Vec<char> = pattern.chars().collect();
    let t_chars: Vec<char> = text.chars().collect();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_chars.len() {
        if p_idx < p_chars.len() && (p_chars[p_idx] == '?' || p_chars[p_idx] == t_chars[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_chars.len() && p_chars[p_idx] == '*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_chars.len() && p_chars[p_idx] == '*' {
        p_idx += 1;
    }

    p_idx == p_chars.len()
}

fn matches_neg_pattern(neg_pattern: &str, rel_path: &str) -> bool {
    if neg_pattern == rel_path {
        return true;
    }
    // If neg_pattern ends with /*
    if let Some(prefix) = neg_pattern.strip_suffix("/*") {
        if rel_path.starts_with(prefix) && rel_path[prefix.len()..].starts_with('/') {
            let rest = &rel_path[prefix.len() + 1..];
            return !rest.contains('/');
        }
    }
    // If neg_pattern ends with /**
    if let Some(prefix) = neg_pattern.strip_suffix("/**") {
        if rel_path == prefix || (rel_path.starts_with(prefix) && rel_path[prefix.len()..].starts_with('/')) {
            return true;
        }
    }
    wildcard_match(neg_pattern, rel_path)
}
