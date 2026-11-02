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

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverNode {
    pub name: String,
    pub version: String,
    pub dependencies: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests;
