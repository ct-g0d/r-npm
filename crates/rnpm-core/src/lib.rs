pub mod error;
pub mod integrity;
pub mod manifest;
pub mod semver;
pub mod spec;

pub use error::{CoreError, IntegrityError, ManifestError, SemverError, SpecError};
pub use integrity::{Algorithm, Integrity, IntegrityEntry};
pub use manifest::{
    BundledDependencies, Manifest, PackageBin, PackageWorkspaces, PeerDependencyMeta,
};
pub use semver::{Comparator, ComparatorSet, Op, PrereleaseId, Range, Version};
pub use spec::{PackageSpec, PackageTarget};

/// Normalizes path to use POSIX forward slashes ('/').
pub fn to_posix_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests;
