//! Workspace discovery and monorepo manifest loading.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

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

        let member_manifest =
            Manifest::from_file(&manifest_path).map_err(WorkspaceError::Manifest)?;
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
pub fn match_glob_patterns(
    root_dir: &Path,
    patterns: &[String],
) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut ordered_dirs: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    let (negative_patterns, positive_patterns): (Vec<_>, Vec<_>) =
        patterns.iter().partition(|p| p.starts_with('!'));

    for pattern in positive_patterns {
        let clean_pattern = pattern.trim();
        let clean_pattern = clean_pattern.strip_prefix("./").unwrap_or(clean_pattern);
        let clean_pattern = clean_pattern.strip_prefix(".\\").unwrap_or(clean_pattern);
        let posix_pattern = clean_pattern.replace('\\', "/");

        let mut segments: Vec<&str> = Vec::new();
        for s in posix_pattern.split('/').filter(|s| !s.is_empty()) {
            if s == "**" && segments.last() == Some(&"**") {
                continue;
            }
            segments.push(s);
        }

        if segments.is_empty() {
            continue;
        }

        let mut pattern_results = HashSet::new();
        let mut visited = HashSet::new();
        traverse_segments(root_dir, &segments, &mut pattern_results, &mut visited)?;

        let mut sorted_matches: Vec<PathBuf> = pattern_results.into_iter().collect();
        sorted_matches.sort();

        for dir in sorted_matches {
            if seen.insert(dir.clone()) {
                ordered_dirs.push(dir);
            }
        }
    }

    // Filter out exclusions
    let mut final_results: Vec<PathBuf> = Vec::new();
    for dir in ordered_dirs {
        let rel_path = dir.strip_prefix(root_dir).unwrap_or(&dir);
        let posix_rel = to_posix_path(&rel_path.to_string_lossy());

        let mut excluded = false;
        for neg in &negative_patterns {
            let neg_clean = neg.trim().strip_prefix('!').unwrap_or(neg).trim();
            let neg_clean = neg_clean.strip_prefix("./").unwrap_or(neg_clean);
            let neg_clean = neg_clean.strip_prefix(".\\").unwrap_or(neg_clean);
            let posix_neg = neg_clean.replace('\\', "/");
            let posix_neg = posix_neg.trim_end_matches('/');

            if matches_neg_pattern(posix_neg, &posix_rel) {
                excluded = true;
                break;
            }
        }

        if !excluded {
            final_results.push(dir);
        }
    }

    Ok(final_results)
}

fn traverse_segments(
    current: &Path,
    segments: &[&str],
    results: &mut HashSet<PathBuf>,
    visited: &mut HashSet<(PathBuf, usize)>,
) -> std::io::Result<()> {
    if !visited.insert((current.to_path_buf(), segments.len())) {
        return Ok(());
    }

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
        traverse_segments(current, remaining, results, visited)?;

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
                    traverse_segments(&child_path, segments, results, visited)?;
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
                    traverse_segments(&entry.path(), remaining, results, visited)?;
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
                        traverse_segments(&entry.path(), remaining, results, visited)?;
                    }
                }
            }
        }
    } else {
        let child = current.join(segment);
        if child.is_dir() {
            traverse_segments(&child, remaining, results, visited)?;
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
    if pattern.is_ascii() && text.is_ascii() {
        let p = pattern.as_bytes();
        let t = text.as_bytes();
        let mut p_idx = 0;
        let mut t_idx = 0;
        let mut star_idx = None;
        let mut match_idx = 0;

        while t_idx < t.len() {
            if p_idx < p.len() && (p[p_idx] == b'?' || p[p_idx] == t[t_idx]) {
                p_idx += 1;
                t_idx += 1;
            } else if p_idx < p.len() && p[p_idx] == b'*' {
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

        while p_idx < p.len() && p[p_idx] == b'*' {
            p_idx += 1;
        }
        return p_idx == p.len();
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
    let neg_pattern = neg_pattern.trim_end_matches('/');
    let rel_path = rel_path.trim_end_matches('/');
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
        if rel_path == prefix
            || (rel_path.starts_with(prefix) && rel_path[prefix.len()..].starts_with('/'))
        {
            return true;
        }
    }
    if wildcard_match(neg_pattern, rel_path) {
        return true;
    }
    let neg_segs: Vec<&str> = neg_pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
    if !neg_segs.is_empty() && match_segments(&neg_segs, &path_segs) {
        return true;
    }
    false
}

fn match_segments(pat_segs: &[&str], path_segs: &[&str]) -> bool {
    if pat_segs.is_empty() {
        return path_segs.is_empty();
    }

    let segment = pat_segs[0];
    let remaining = &pat_segs[1..];

    if segment == "**" {
        // Option 1: ** matches 0 directory levels
        if match_segments(remaining, path_segs) {
            return true;
        }

        // Option 2: ** matches 1 or more directory levels
        if !path_segs.is_empty() {
            let seg = path_segs[0];
            if should_skip_dir(seg) {
                return false;
            }
            if match_segments(pat_segs, &path_segs[1..]) {
                return true;
            }
        }

        false
    } else if segment == "*" {
        if path_segs.is_empty() {
            return false;
        }
        let seg = path_segs[0];
        if should_skip_dir(seg) {
            return false;
        }
        match_segments(remaining, &path_segs[1..])
    } else if segment.contains('*') || segment.contains('?') {
        if path_segs.is_empty() {
            return false;
        }
        let seg = path_segs[0];
        if should_skip_dir(seg) {
            return false;
        }
        if wildcard_match(segment, seg) {
            match_segments(remaining, &path_segs[1..])
        } else {
            false
        }
    } else {
        if path_segs.is_empty() {
            return false;
        }
        let seg = path_segs[0];
        if should_skip_dir(seg) {
            return false;
        }
        if segment == seg {
            match_segments(remaining, &path_segs[1..])
        } else {
            false
        }
    }
}

/// Check if a relative POSIX path matches workspace patterns, using the same glob semantics
/// as workspace discovery (`match_glob_patterns`).
pub fn path_matches_workspace_patterns(path: &str, patterns: &[String]) -> bool {
    let mut clean_path = path.trim();
    if let Some(stripped) = clean_path.strip_prefix("./") {
        clean_path = stripped;
    } else if let Some(stripped) = clean_path.strip_prefix(".\\") {
        clean_path = stripped;
    }
    let clean_path_cow = crate::to_posix_path_cow(clean_path);
    let clean_path = clean_path_cow.trim_end_matches('/');
    if clean_path.is_empty() {
        return false;
    }

    let path_segs: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
    if path_segs.is_empty() || path_segs.iter().any(|s| should_skip_dir(s)) {
        return false;
    }

    let (negative_patterns, positive_patterns): (Vec<_>, Vec<_>) =
        patterns.iter().partition(|p| p.starts_with('!'));

    // 1. Must match at least one positive pattern
    let mut matched = false;
    for pattern in positive_patterns {
        let clean_pattern = pattern.trim();
        let clean_pattern = clean_pattern.strip_prefix("./").unwrap_or(clean_pattern);
        let clean_pattern = clean_pattern.strip_prefix(".\\").unwrap_or(clean_pattern);
        let posix_pattern_cow = crate::to_posix_path_cow(clean_pattern);
        let posix_pattern = posix_pattern_cow.trim_end_matches('/');

        let pat_segs: Vec<&str> = posix_pattern.split('/').filter(|s| !s.is_empty()).collect();
        if pat_segs.is_empty() {
            continue;
        }

        if match_segments(&pat_segs, &path_segs) {
            matched = true;
            break;
        }
    }

    if !matched {
        return false;
    }

    // 2. Must NOT match any negative pattern
    for neg in &negative_patterns {
        let neg_clean = neg.trim().strip_prefix('!').unwrap_or(neg).trim();
        let neg_clean = neg_clean.strip_prefix("./").unwrap_or(neg_clean);
        let neg_clean = neg_clean.strip_prefix(".\\").unwrap_or(neg_clean);
        let posix_neg_cow = crate::to_posix_path_cow(neg_clean);
        let posix_neg = posix_neg_cow.trim_end_matches('/');

        if matches_neg_pattern(posix_neg, clean_path) {
            return false;
        }

        let neg_segs: Vec<&str> = posix_neg.split('/').filter(|s| !s.is_empty()).collect();
        if !neg_segs.is_empty() && match_segments(&neg_segs, &path_segs) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negation_pattern_with_trailing_slash() {
        assert!(matches_neg_pattern("packages/ignored/", "packages/ignored"));
        assert!(matches_neg_pattern("packages/ignored", "packages/ignored/"));
        assert!(matches_neg_pattern("packages/*/ignored/", "packages/a/ignored"));

        let patterns = vec![
            "packages/*".to_string(),
            "!packages/ignored/".to_string(),
        ];
        assert!(path_matches_workspace_patterns("packages/pkg-a", &patterns));
        assert!(!path_matches_workspace_patterns("packages/ignored", &patterns));
    }
}
