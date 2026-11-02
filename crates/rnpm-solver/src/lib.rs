//! Dependency graph resolution, hoisting, overrides, peer dependencies, and workspaces.

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
pub use solver::{resolve_dependency_graph, ResolverOptions, Solver};
pub use types::{
    InMemoryPackageProvider, PackageMetadata, PackageMetadataProvider, PackageVersionMetadata,
};
pub use workspace::{resolve_workspace_graph, topological_sort, WorkspaceDependencyGraph};

pub type SolverNode = Node;
