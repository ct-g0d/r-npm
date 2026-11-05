//! Dependency graph resolution, hoisting, overrides, peer dependencies, and workspaces.

#![allow(clippy::result_large_err, clippy::type_complexity, clippy::too_many_arguments, clippy::field_reassign_with_default)]

pub mod aliases;
pub mod error;
pub mod graph;
pub mod hoisting;
pub mod overrides;
pub mod peer;
pub mod platform;
pub mod solver;
pub mod types;
pub mod workspace;

#[cfg(test)]
mod tests;

pub use aliases::DependencySpec;
pub use error::SolverError;
pub use graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
pub use overrides::Overrides;
pub use platform::Platform;
pub use solver::{
    resolve_dependency_graph, resolve_dependency_graph_with_lockfile, resolve_fast_path,
    ResolverOptions, Solver,
};
pub use types::{
    InMemoryPackageProvider, PackageMetadata, PackageMetadataProvider, PackageVersionMetadata,
};
pub use workspace::{resolve_workspace_graph, topological_sort, WorkspaceDependencyGraph};

pub type SolverNode = Node;
