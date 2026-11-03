pub mod error;
pub mod integrity;
pub mod manifest;
pub mod pkg;
pub mod semver;
pub mod spec;
pub mod workspace;

pub use error::{CoreError, IntegrityError, ManifestError, SemverError, SpecError, WorkspaceError};
pub use integrity::{Algorithm, Integrity, IntegrityEntry};
pub use manifest::{
    BundledDependencies, Manifest, PackageBin, PackageWorkspaces, PeerDependencyMeta,
};
pub use pkg::{
    get_value_at_path, parse_path, pkg_delete, pkg_get, pkg_set, resolve_manifest_path,
    PathSegment,
};
pub use semver::{Comparator, ComparatorSet, Op, PrereleaseId, Range, Version};
pub use spec::{PackageSpec, PackageTarget};
pub use workspace::{
    discover_workspaces, discover_workspaces_from_manifest, match_glob_patterns, WorkspaceMember,
};

use std::borrow::Cow;

/// Normalizes path to use POSIX forward slashes ('/').
pub fn to_posix_path(path: &str) -> String {
    if path.contains('\\') {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

/// Normalizes path to use POSIX forward slashes ('/'), borrowing if already POSIX.
pub fn to_posix_path_cow(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

#[cfg(test)]
mod tests;
