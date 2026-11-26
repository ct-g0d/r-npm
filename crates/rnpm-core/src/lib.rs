#![allow(
    clippy::unnecessary_unwrap,
    clippy::manual_strip,
    clippy::should_implement_trait
)]

pub mod error;
mod fast_hash;
pub mod integrity;
pub mod manifest;
pub mod ordered_json;
pub mod overrides;
pub mod pkg;
pub mod platform_list;
pub mod semver;
pub mod spec;
pub mod workspace;

pub use error::{
    CoreError, IntegrityError, ManifestError, OverrideError, SemverError, SpecError, WorkspaceError,
};
pub use integrity::{Algorithm, Integrity, IntegrityEntry};
pub use manifest::{
    BundledDependencies, Manifest, ManifestFormat, PackageBin, PackageWorkspaces,
    PeerDependencyMeta,
};
pub use ordered_json::{OrderedJsonMap, OrderedJsonValue};
pub use overrides::{OverrideValue, Overrides};
pub use pkg::{
    coerce_value, delete_value, get_value_at_path, parse_path, pkg_delete, pkg_fix, pkg_get,
    pkg_get_value, pkg_get_workspaces, pkg_set, resolve_manifest_path, set_value, PathSegment,
};
pub use platform_list::PlatformList;
pub use semver::{Comparator, ComparatorSet, Op, PrereleaseId, Range, Version};
pub use spec::{is_scp_git_url, PackageSpec, PackageTarget};
pub use workspace::{
    discover_workspaces, discover_workspaces_from_manifest, match_glob_patterns,
    path_matches_workspace_patterns, WorkspaceMember,
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
