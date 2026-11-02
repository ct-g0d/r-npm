//! Dependency graph resolution, hoisting, overrides, and peer dependencies.

pub mod aliases;
pub mod error;
pub mod graph;
pub mod hoisting;
pub mod overrides;
pub mod peer;
pub mod platform;
pub mod solver;
pub mod types;

pub use error::SolverError;
pub use graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
pub use platform::Platform;
pub use solver::{resolve_dependency_graph, ResolverOptions, Solver};
pub use types::{InMemoryPackageProvider, PackageMetadata, PackageMetadataProvider, PackageVersionMetadata};

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
