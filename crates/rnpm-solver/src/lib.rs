//! Dependency graph resolution, hoisting, overrides, and peer dependencies.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverNode {
    pub name: String,
    pub version: String,
    pub dependencies: BTreeMap<String, String>,
}
