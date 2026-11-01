use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use rnpm_core::manifest::Manifest;
use crate::env::LifecycleOptions;
use crate::error::LifecycleError;
use crate::hooks::run_lifecycle_hook;
use crate::process::ScriptOutput;

/// Package origin source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    /// Root workspace / project package. Runs prepare.
    Root,
    /// Registry package. NEVER runs prepare.
    Registry,
    /// Local file: package. Runs prepare mirroring root.
    LocalFile,
    /// Bundled dependency unpacked directly.
    Bundled,
}

/// A node in the dependency graph scheduled for lifecycle execution.
#[derive(Debug, Clone)]
pub struct LifecyclePackageNode {
    pub id: String,
    pub package_dir: PathBuf,
    pub manifest: Manifest,
    pub source: PackageSource,
    pub optional: bool,
    pub dependencies: Vec<String>,
}

/// Execution record of a single lifecycle hook.
#[derive(Debug, Clone)]
pub struct HookExecution {
    pub package_id: String,
    pub event: String,
    pub output: ScriptOutput,
}

/// Sort packages in bottom-up topological order:
/// Leaf dependencies (packages with no child dependencies) execute first.
/// Dependent packages execute only after all child dependencies finish.
/// Root package executes last.
pub fn sort_topological(nodes: &[LifecyclePackageNode]) -> Vec<usize> {
    let n = nodes.len();
    if n <= 1 {
        return (0..n).collect();
    }

    let mut id_to_idx: HashMap<&str, usize> = HashMap::new();
    for (idx, node) in nodes.iter().enumerate() {
        id_to_idx.insert(&node.id, idx);
    }

    // Build DAG: if node A depends on B, then B must execute before A.
    // Edge: B -> A.
    // In-degree of A = count of prerequisites B.
    let mut in_degree: Vec<usize> = vec![0; n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (a_idx, node) in nodes.iter().enumerate() {
        let mut seen_deps: HashSet<usize> = HashSet::new();
        for dep_id in &node.dependencies {
            if let Some(&b_idx) = id_to_idx.get(dep_id.as_str()) {
                if b_idx != a_idx && seen_deps.insert(b_idx) {
                    adj[b_idx].push(a_idx);
                    in_degree[a_idx] += 1;
                }
            }
        }
    }

    // Ready queue: nodes with 0 prerequisites.
    // Root should not be prioritized over dependencies, so put non-roots first.
    let mut ready: VecDeque<usize> = VecDeque::new();
    let mut non_roots: Vec<usize> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();

    for i in 0..n {
        if in_degree[i] == 0 {
            if nodes[i].source == PackageSource::Root {
                roots.push(i);
            } else {
                non_roots.push(i);
            }
        }
    }

    // Deterministic sort by ID
    non_roots.sort_by(|&a, &b| nodes[a].id.cmp(&nodes[b].id));
    for idx in non_roots {
        ready.push_back(idx);
    }
    for idx in roots {
        ready.push_back(idx);
    }

    let mut order: Vec<usize> = Vec::with_capacity(n);
    let mut visited: HashSet<usize> = HashSet::new();

    while order.len() < n {
        if let Some(curr) = ready.pop_front() {
            if visited.insert(curr) {
                order.push(curr);
                for &dependent in &adj[curr] {
                    if in_degree[dependent] > 0 {
                        in_degree[dependent] -= 1;
                        if in_degree[dependent] == 0 {
                            ready.push_back(dependent);
                        }
                    }
                }
            }
        } else {
            // Cycle detected: pick remaining unvisited node with lowest in-degree
            let mut candidates: Vec<usize> = (0..n).filter(|i| !visited.contains(i)).collect();
            candidates.sort_by(|&a, &b| {
                let a_is_root = nodes[a].source == PackageSource::Root;
                let b_is_root = nodes[b].source == PackageSource::Root;
                a_is_root
                    .cmp(&b_is_root)
                    .then_with(|| in_degree[a].cmp(&in_degree[b]))
                    .then_with(|| nodes[a].id.cmp(&nodes[b].id))
            });

            if let Some(&next) = candidates.first() {
                visited.insert(next);
                order.push(next);
                for &dependent in &adj[next] {
                    if in_degree[dependent] > 0 {
                        in_degree[dependent] -= 1;
                        if in_degree[dependent] == 0 {
                            ready.push_back(dependent);
                        }
                    }
                }
            } else {
                break;
            }
        }
    }

    order
}

/// Execute lifecycle scripts in bottom-up topological sequence according to Section 1 & Section 2.
pub async fn execute_topological(
    nodes: &[LifecyclePackageNode],
    options: &LifecycleOptions,
) -> Result<Vec<HookExecution>, LifecycleError> {
    if options.ignore_scripts {
        return Ok(Vec::new());
    }

    let order = sort_topological(nodes);
    let mut executions: Vec<HookExecution> = Vec::new();

    for idx in order {
        let node = &nodes[idx];

        // Determine hooks to run based on package source (Section 1.2):
        // - Root package: preinstall -> install -> postinstall -> prepare
        // - Registry dependencies: preinstall -> install -> postinstall (NEVER prepare)
        // - Local file: dependencies: preinstall -> install -> postinstall -> prepare
        // - Bundled dependencies: preinstall -> install -> postinstall
        let hooks: &[&str] = match node.source {
            PackageSource::Root | PackageSource::LocalFile => &[
                "preinstall",
                "install",
                "postinstall",
                "prepare",
            ],
            PackageSource::Registry | PackageSource::Bundled => &[
                "preinstall",
                "install",
                "postinstall",
            ],
        };

        let mut node_failed = false;

        for &hook in hooks {
            match run_lifecycle_hook(&node.manifest, &node.package_dir, hook, options).await {
                Ok(Some(out)) => {
                    executions.push(HookExecution {
                        package_id: node.id.clone(),
                        event: hook.to_string(),
                        output: out,
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    if node.optional {
                        // Section 7: Optional dependency build failure isolation
                        let pkg_name = node.manifest.name.as_deref().unwrap_or(&node.id);
                        let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                        eprintln!(
                            "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                            pkg_name,
                            pkg_ver,
                            node.package_dir.display()
                        );
                        eprintln!(
                            "npm warn optional {} failed at the {} script.",
                            pkg_name,
                            hook
                        );

                        if options.remove_failed_optional && node.package_dir.exists() {
                            let _ = std::fs::remove_dir_all(&node.package_dir);
                        }

                        node_failed = true;
                        break;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        if node_failed {
            // Optional node failed and was isolated. Continue to next package.
            continue;
        }
    }

    Ok(executions)
}
