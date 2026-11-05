use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf, Prefix};
use path_clean::clean;
use crate::error::ShimError;

/// Strips Windows verbatim prefix (`\\?\` or `\\?\UNC\`) if present.
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Checks if two Windows path prefixes are equivalent (case-insensitive for drive letters).
fn prefixes_equal(a: &Prefix, b: &Prefix) -> bool {
    match (a, b) {
        (Prefix::Disk(d1), Prefix::Disk(d2)) => d1.eq_ignore_ascii_case(d2),
        (Prefix::VerbatimDisk(d1), Prefix::VerbatimDisk(d2)) => {
            d1.eq_ignore_ascii_case(d2)
        }
        (Prefix::Disk(d1), Prefix::VerbatimDisk(d2)) => {
            d1.eq_ignore_ascii_case(d2)
        }
        (Prefix::VerbatimDisk(d1), Prefix::Disk(d2)) => {
            d1.eq_ignore_ascii_case(d2)
        }
        (Prefix::UNC(s1, p1), Prefix::UNC(s2, p2))
        | (Prefix::VerbatimUNC(s1, p1), Prefix::VerbatimUNC(s2, p2))
        | (Prefix::UNC(s1, p1), Prefix::VerbatimUNC(s2, p2))
        | (Prefix::VerbatimUNC(s1, p1), Prefix::UNC(s2, p2)) => {
            s1.to_string_lossy().to_lowercase() == s2.to_string_lossy().to_lowercase()
                && p1.to_string_lossy().to_lowercase() == p2.to_string_lossy().to_lowercase()
        }
        _ => a == b,
    }
}

/// Compares two path component OsStrs, case-insensitively on Windows.
fn components_equal(a: &OsStr, b: &OsStr) -> bool {
    if a == b {
        return true;
    }
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        false
    }
}

/// Computes the relative path from `from` directory to `to` file,
/// returning a normalized string with forward slashes (`/`).
///
/// Example:
/// - `from`: `node_modules/.bin`
/// - `to`: `node_modules/my-pkg/bin/cli.js`
/// - Returns: `../my-pkg/bin/cli.js`
pub fn compute_relative_path(from: &Path, to: &Path) -> Result<String, ShimError> {
    // If one is absolute and the other relative, make both absolute using current_dir
    let (from_resolved, to_resolved) = if from.is_absolute() != to.is_absolute() {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let f = if from.is_absolute() {
            from.to_path_buf()
        } else {
            cwd.join(from)
        };
        let t = if to.is_absolute() {
            to.to_path_buf()
        } else {
            cwd.join(to)
        };
        (f, t)
    } else {
        (from.to_path_buf(), to.to_path_buf())
    };

    let from_clean = clean(strip_verbatim_prefix(&from_resolved));
    let to_clean = clean(strip_verbatim_prefix(&to_resolved));

    let from_components: Vec<Component> = from_clean
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    let to_components: Vec<Component> = to_clean
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();

    // Check prefix / root compatibility
    let mut i = 0;
    let mut j = 0;

    // Check Prefix components if present
    let from_prefix = from_components.first().and_then(|c| match c {
        Component::Prefix(p) => Some(p.kind()),
        _ => None,
    });
    let to_prefix = to_components.first().and_then(|c| match c {
        Component::Prefix(p) => Some(p.kind()),
        _ => None,
    });

    match (from_prefix, to_prefix) {
        (Some(p1), Some(p2)) => {
            if !prefixes_equal(&p1, &p2) {
                return Err(ShimError::IncompatiblePaths {
                    from: from.to_path_buf(),
                    to: to.to_path_buf(),
                });
            }
            i += 1;
            j += 1;
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ShimError::IncompatiblePaths {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            });
        }
        (None, None) => {}
    }

    // Check RootDir component
    let from_has_root = matches!(from_components.get(i), Some(Component::RootDir));
    let to_has_root = matches!(to_components.get(j), Some(Component::RootDir));
    if from_has_root != to_has_root {
        return Err(ShimError::IncompatiblePaths {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
        });
    }
    if from_has_root {
        i += 1;
        j += 1;
    }

    // Normal components
    let from_normal: Vec<&OsStr> = from_components[i..]
        .iter()
        .map(|c| c.as_os_str())
        .collect();
    let to_normal: Vec<&OsStr> = to_components[j..]
        .iter()
        .map(|c| c.as_os_str())
        .collect();

    // Find common prefix
    let mut common = 0;
    while common < from_normal.len()
        && common < to_normal.len()
        && components_equal(from_normal[common], to_normal[common])
    {
        common += 1;
    }

    let up_count = from_normal.len() - common;
    let mut segments = Vec::new();

    for _ in 0..up_count {
        segments.push("..".to_string());
    }

    for comp in &to_normal[common..] {
        segments.push(comp.to_string_lossy().to_string());
    }

    if segments.is_empty() {
        Ok(".".to_string())
    } else {
        Ok(segments.join("/"))
    }
}
