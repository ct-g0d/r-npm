pub mod error;
pub mod integrity;
pub mod manifest;
pub mod semver;
pub mod spec;
pub mod workspace;

pub use error::{CoreError, IntegrityError, ManifestError, SemverError, SpecError, WorkspaceError};
pub use integrity::{Algorithm, Integrity, IntegrityEntry};
pub use manifest::{
    BundledDependencies, Manifest, PackageBin, PackageWorkspaces, PeerDependencyMeta,
};
pub use semver::{Comparator, ComparatorSet, Op, PrereleaseId, Range, Version};
pub use spec::{PackageSpec, PackageTarget};
pub use workspace::{
    discover_workspaces, discover_workspaces_from_manifest, match_glob_patterns, WorkspaceMember,
};

/// Normalizes path to use POSIX forward slashes ('/').
pub fn to_posix_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests;
