use std::collections::{BTreeMap, VecDeque};
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use tracing::{debug, warn};

use crate::aliases::DependencySpec;
use crate::error::SolverError;
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::hoisting::{determine_placement, PlacementDecision};
use crate::overrides::Overrides;
use crate::peer::PeerContext;
use crate::platform::Platform;
use crate::types::{PackageMetadata, PackageMetadataProvider, PackageVersionMetadata};

/// Configuration options for dependency resolution.
#[derive(Debug, Clone)]
pub struct ResolverOptions {
    /// Target platform for evaluating `os` and `cpu` filters on optional dependencies.
    pub platform: Platform,
    /// Whether to include `devDependencies` from the root project.
    pub dev: bool,
    /// When true, peer dependencies are completely ignored during tree construction.
    pub legacy_peer_deps: bool,
    /// When true, unresolved or conflicting peer dependencies cause an ERESOLVE error.
    pub strict_peers: bool,
    /// Optional lockfile v3 to enable fast-path resolution when matching package.json specs.
    pub lockfile: Option<std::sync::Arc<rnpm_lockfile::LockfileV3>>,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            platform: Platform::current(),
            dev: true,
            legacy_peer_deps: false,
            strict_peers: true,
            lockfile: None,
        }
    }
}

/// Internal task queued for resolution.
#[derive(Debug, Clone)]
struct ResolveTask {
    parent_location: String,
    parent_package_name: String,
    install_name: String,
    raw_spec: String,
    dep_type: DependencyType,
    ancestors: std::sync::Arc<Vec<String>>,
}

/// Main solver coordinator for building the dependency graph.
pub struct Solver<'a, P: PackageMetadataProvider> {
    provider: &'a P,
    options: ResolverOptions,
    overrides: Overrides,
    peer_ctx: PeerContext,
    graph: DependencyGraph,
    queue: VecDeque<ResolveTask>,
}

impl<'a, P: PackageMetadataProvider> Solver<'a, P> {
    pub fn new(provider: &'a P, options: ResolverOptions, overrides: Overrides) -> Self {
        Self {
            provider,
            options,
            overrides,
            peer_ctx: PeerContext::new(),
            graph: DependencyGraph::new(),
            queue: VecDeque::new(),
        }
    }

    /// Attaches an existing LockfileV3 for fast-path resolution.
    pub fn with_lockfile(mut self, lockfile: std::sync::Arc<rnpm_lockfile::LockfileV3>) -> Self {
        self.options.lockfile = Some(lockfile);
        self
    }

    /// Resolves the dependency graph starting from a root manifest.
    pub fn resolve(mut self, root_manifest: &Manifest) -> Result<DependencyGraph, SolverError> {
        // Fast-path: if lockfile v3 matches root_manifest specs, bypass expensive traversal
        if let Some(ref lockfile) = self.options.lockfile {
            if lockfile.matches_manifest(root_manifest, self.options.dev) {
                debug!("Fast-path: lockfile v3 matches manifest specs; bypassing tree traversal");
                if let Some(graph) = resolve_fast_path(root_manifest, lockfile, &self.options) {
                    return Ok(graph);
                }
            }
        }

        let root_name = root_manifest
            .name
            .clone()
            .unwrap_or_else(|| "root".to_string());
        let root_version = root_manifest
            .version
            .clone()
            .unwrap_or_else(|| "1.0.0".to_string());

        // Initialize root node at ""
        let root_node = Node {
            location: String::new(),
            install_name: root_name.clone(),
            name: root_name.clone(),
            version: root_version,
            resolved: None,
            integrity: None,
            flags: NodeFlags::default(),
            dependencies: root_manifest.dependencies.clone(),
            dev_dependencies: root_manifest.dev_dependencies.clone(),
            peer_dependencies: root_manifest.peer_dependencies.clone(),
            optional_dependencies: root_manifest.optional_dependencies.clone(),
            os: root_manifest.os.clone(),
            cpu: root_manifest.cpu.clone(),
            libc: root_manifest.libc.clone(),
            bin: root_manifest.bin.clone().map(|b| match b {
                rnpm_core::manifest::PackageBin::Single(s) => {
                    rnpm_lockfile::PackageBin::Single(s)
                }
                rnpm_core::manifest::PackageBin::Map(m) => rnpm_lockfile::PackageBin::Map(m),
            }),
            parsed_version: None,
            extra: BTreeMap::new(),
        };
        self.graph.nodes.insert(String::new(), root_node);

        // Collect and sort root dependencies deterministically
        let mut root_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();

        // 1. devDependencies (if enabled)
        if self.options.dev {
            for (k, v) in &root_manifest.dev_dependencies {
                root_deps.insert(k.clone(), (v.clone(), DependencyType::Dev));
            }
        }

        // 2. dependencies (override devDependencies)
        for (k, v) in &root_manifest.dependencies {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
        }

        // 3. optionalDependencies (override dependencies for failure isolation)
        for (k, v) in &root_manifest.optional_dependencies {
            root_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
        }

        let root_ancestors = std::sync::Arc::new(vec![root_name.clone()]);
        for (install_name, (raw_spec, dep_type)) in root_deps {
            self.queue.push_back(ResolveTask {
                parent_location: String::new(),
                parent_package_name: root_name.clone(),
                install_name,
                raw_spec,
                dep_type,
                ancestors: root_ancestors.clone(),
            });
        }

        // Process resolution queue
        while let Some(task) = self.queue.pop_front() {
            self.process_task(task)?;
        }

        Ok(self.graph)
    }

    fn process_task(&mut self, task: ResolveTask) -> Result<(), SolverError> {
        // 1. Apply overrides without allocations if no rules exist
        let effective_spec = if self.overrides.rules.is_empty() {
            task.raw_spec.clone()
        } else if let Some(overridden) = self.overrides.resolve_override_strings(
            &task.install_name,
            &task.raw_spec,
            &task.ancestors,
        ) {
            debug!(
                "Overriding dependency '{}': '{}' -> '{}'",
                task.install_name, task.raw_spec, overridden
            );
            overridden
        } else {
            task.raw_spec.clone()
        };

        // 2. Parse dependency spec (separating alias and real package name)
        let dep_spec = DependencySpec::parse(&task.install_name, &effective_spec)?;

        // 3. Check for cyclic peer dependencies and existing peer instances
        let is_peer = task.dep_type == DependencyType::Peer
            || task.dep_type == DependencyType::PeerOptional;
        if is_peer {
            if self
                .peer_ctx
                .is_cycle(&task.parent_package_name, &dep_spec.package_name)
            {
                debug!(
                    "Peer cycle detected between '{}' and '{}', resolving to active instance",
                    task.parent_package_name, dep_spec.package_name
                );
                // Look for existing node with package_name in tree
                if let Some((loc, _)) = self
                    .graph
                    .nodes
                    .iter()
                    .find(|(_, n)| n.name == dep_spec.package_name)
                {
                    self.graph.edges.push(DependencyEdge {
                        from_location: task.parent_location,
                        to_location: loc.clone(),
                        install_name: task.install_name,
                        package_name: dep_spec.package_name,
                        spec: effective_spec,
                        dep_type: task.dep_type,
                    });
                    return Ok(());
                }
            }

            // Check if peer is already satisfied in ancestor/root scope
            let root_candidate = format!("node_modules/{}", dep_spec.install_name);
            if let Some(existing) = self.graph.nodes.get(&root_candidate) {
                if existing.name == dep_spec.package_name {
                    if crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        debug!(
                            "Peer dependency '{}@{}' satisfied by existing node at '{}'",
                            dep_spec.package_name, effective_spec, root_candidate
                        );
                        self.graph.edges.push(DependencyEdge {
                            from_location: task.parent_location,
                            to_location: root_candidate,
                            install_name: task.install_name,
                            package_name: dep_spec.package_name,
                            spec: effective_spec,
                            dep_type: task.dep_type,
                        });
                        return Ok(());
                    } else if task.dep_type == DependencyType::Peer {
                        if self.options.strict_peers {
                            return Err(SolverError::peer_conflict(
                                &task.parent_package_name,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing.version.clone()),
                                Some(existing.location.clone()),
                                (*task.ancestors).clone(),
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                    dep_spec.package_name, existing.version, existing.location, effective_spec
                                ),
                            ));
                        } else {
                            warn!(
                                "Peer dependency conflict: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                task.parent_package_name, dep_spec.package_name, effective_spec, dep_spec.package_name, existing.version
                            );
                        }
                    }
                }
            }
        }

        // 4. Resolve package metadata and choose matching version
        let pkg_meta_opt = self.provider.get_package(&dep_spec.package_name)?;
        let Some(pkg_meta) = pkg_meta_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "Optional dependency '{}' not found, skipping",
                    dep_spec.package_name
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
                return Ok(());
            }
            if task.dep_type == DependencyType::Peer {
                if !self.options.strict_peers {
                    warn!(
                        "Unresolved peer dependency '{}@{}' (non-strict mode), skipping",
                        dep_spec.package_name, effective_spec
                    );
                    return Ok(());
                }
                return Err(SolverError::peer_conflict(
                    task.parent_package_name,
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    (*task.ancestors).clone(),
                    format!("Peer package '{}' not found in registry", effective_spec),
                ));
            }
            return Err(SolverError::UnresolvedDependency {
                name: dep_spec.package_name,
                spec: effective_spec,
                message: "Package not found in metadata provider".to_string(),
            });
        };

        let matched_version_opt = self.select_version(&pkg_meta, &dep_spec.target);
        let Some(chosen_version) = matched_version_opt else {
            if task.dep_type == DependencyType::Optional
                || task.dep_type == DependencyType::PeerOptional
            {
                debug!(
                    "No matching version for optional dependency '{}@{}', skipping",
                    dep_spec.package_name, effective_spec
                );
                if task.dep_type == DependencyType::Optional {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
                return Ok(());
            }
            if task.dep_type == DependencyType::Peer {
                if !self.options.strict_peers {
                    warn!(
                        "Unresolved peer dependency '{}@{}' (non-strict mode), skipping",
                        dep_spec.package_name, effective_spec
                    );
                    return Ok(());
                }
                return Err(SolverError::peer_conflict(
                    task.parent_package_name,
                    dep_spec.package_name,
                    effective_spec.clone(),
                    None,
                    None,
                    (*task.ancestors).clone(),
                    format!("No version satisfying '{}'", effective_spec),
                ));
            }
            return Err(SolverError::UnresolvedDependency {
                name: dep_spec.package_name,
                spec: effective_spec,
                message: "No matching version found satisfying constraint".to_string(),
            });
        };

        // 5. Platform filtering for optional dependencies
        if task.dep_type == DependencyType::Optional {
            let compatible = self.options.platform.matches_with_libc(
                chosen_version.os.as_deref(),
                chosen_version.cpu.as_deref(),
                chosen_version.libc.as_deref(),
            );
            if !compatible {
                debug!(
                    "Optional package '{}@{}' filtered out by platform ({:?})",
                    dep_spec.package_name, chosen_version.version, self.options.platform
                );
                self.graph.skipped.insert(dep_spec.package_name.clone());
                self.graph.skipped.insert(task.install_name.clone());
                return Ok(());
            }
        }

        // 6. Hoisting & Tree Placement
        let placement = determine_placement(
            &self.graph,
            &task.parent_location,
            &dep_spec.install_name,
            &dep_spec.package_name,
            &dep_spec.target,
        );

        match placement {
            PlacementDecision::Reuse(existing_loc) => {
                debug!(
                    "Deduplicated '{}': reusing existing node at '{}'",
                    dep_spec.install_name, existing_loc
                );
                self.graph.edges.push(DependencyEdge {
                    from_location: task.parent_location,
                    to_location: existing_loc,
                    install_name: task.install_name,
                    package_name: dep_spec.package_name,
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });
            }
            PlacementDecision::PlaceNew(target_loc) => {
                debug!(
                    "Placing package '{}' (install: '{}', version: '{}') at '{}'",
                    dep_spec.package_name,
                    dep_spec.install_name,
                    chosen_version.version,
                    target_loc
                );

                let flags = NodeFlags {
                    dev: task.dep_type == DependencyType::Dev,
                    optional: task.dep_type == DependencyType::Optional,
                    peer: is_peer,
                    bundled: false,
                    has_install_script: chosen_version.has_install_script,
                    skipped: false,
                    link: false,
                };

                let parsed_ver = Version::parse(&chosen_version.version).ok();
                let node = Node {
                    location: target_loc.clone(),
                    install_name: task.install_name.clone(),
                    name: dep_spec.package_name.clone(),
                    version: chosen_version.version.clone(),
                    parsed_version: parsed_ver,
                    resolved: chosen_version.dist_tarball.clone(),
                    integrity: chosen_version.dist_integrity.clone(),
                    flags,
                    dependencies: chosen_version.dependencies.clone(),
                    dev_dependencies: chosen_version.dev_dependencies.clone(),
                    peer_dependencies: chosen_version.peer_dependencies.clone(),
                    optional_dependencies: chosen_version.optional_dependencies.clone(),
                    os: chosen_version.os.clone(),
                    cpu: chosen_version.cpu.clone(),
                    libc: chosen_version.libc.clone(),
                    bin: chosen_version.bin.clone(),
                    extra: BTreeMap::new(),
                };

                self.graph.nodes.insert(target_loc.clone(), node);

                self.graph.edges.push(DependencyEdge {
                    from_location: task.parent_location,
                    to_location: target_loc.clone(),
                    install_name: task.install_name.clone(),
                    package_name: dep_spec.package_name.clone(),
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });

                // Enqueue child dependencies with Arc ancestors to avoid vector clones
                let mut child_ancestors = (*task.ancestors).clone();
                child_ancestors.push(dep_spec.package_name.clone());
                let child_ancestors = std::sync::Arc::new(child_ancestors);

                let mut child_deps: BTreeMap<String, (String, DependencyType)> = BTreeMap::new();

                for (k, v) in &chosen_version.dependencies {
                    child_deps.insert(k.clone(), (v.clone(), DependencyType::Prod));
                }
                for (k, v) in &chosen_version.optional_dependencies {
                    child_deps.insert(k.clone(), (v.clone(), DependencyType::Optional));
                }

                // Peer dependencies
                if !self.options.legacy_peer_deps {
                    for (k, v) in &chosen_version.peer_dependencies {
                        let is_opt_peer = chosen_version
                            .peer_dependencies_meta
                            .get(k)
                            .map(|m| m.optional)
                            .unwrap_or(false);
                        let p_type = if is_opt_peer {
                            DependencyType::PeerOptional
                        } else {
                            DependencyType::Peer
                        };
                        child_deps.insert(k.clone(), (v.clone(), p_type));
                        self.peer_ctx.enter(&dep_spec.package_name, k);
                    }
                }

                for (c_name, (c_spec, c_type)) in child_deps {
                    self.queue.push_back(ResolveTask {
                        parent_location: target_loc.clone(),
                        parent_package_name: dep_spec.package_name.clone(),
                        install_name: c_name,
                        raw_spec: c_spec,
                        dep_type: c_type,
                        ancestors: child_ancestors.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Selects the highest version matching target constraint in a single linear pass (O(N), zero Vec allocations).
    fn select_version(
        &self,
        meta: &PackageMetadata,
        target: &PackageTarget,
    ) -> Option<PackageVersionMetadata> {
        match target {
            PackageTarget::Version(expected) => {
                let v_str = expected.to_string();
                meta.versions.get(&v_str).cloned()
            }
            PackageTarget::Tag(tag) => {
                let tagged_version = meta.dist_tags.get(tag)?;
                meta.versions.get(tagged_version).cloned()
            }
            PackageTarget::Range(range) => {
                let mut best: Option<(&PackageVersionMetadata, Version)> = None;
                for (ver_str, v_meta) in &meta.versions {
                    if let Ok(parsed) = Version::parse(ver_str) {
                        if range.satisfies(&parsed) {
                            match &best {
                                Some((_, best_v)) => {
                                    if &parsed > best_v {
                                        best = Some((v_meta, parsed));
                                    }
                                }
                                None => {
                                    best = Some((v_meta, parsed));
                                }
                            }
                        }
                    }
                }
                best.map(|(v_meta, _)| (*v_meta).clone())
            }
            PackageTarget::Alias { target, .. } => self.select_version(meta, target),
            PackageTarget::File(_) => {
                // If versions exist, return highest/latest, else None
                meta.versions.values().last().cloned()
            }
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    meta.versions.values().last().cloned()
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    let mut best: Option<(&PackageVersionMetadata, Version)> = None;
                    for (ver_str, v_meta) in &meta.versions {
                        if let Ok(parsed) = Version::parse(ver_str) {
                            if range.satisfies(&parsed) {
                                match &best {
                                    Some((_, best_v)) => {
                                        if &parsed > best_v {
                                            best = Some((v_meta, parsed));
                                        }
                                    }
                                    None => {
                                        best = Some((v_meta, parsed));
                                    }
                                }
                            }
                        }
                    }
                    best.map(|(v_meta, _)| (*v_meta).clone())
                } else {
                    meta.versions.values().last().cloned()
                }
            }
        }
    }
}

/// Attempts fast-path dependency graph construction from a lockfile v3 without tree traversal.
/// Returns `Some(DependencyGraph)` if the lockfile matches the manifest, or `None` otherwise.
pub fn resolve_fast_path(
    manifest: &Manifest,
    lockfile: &rnpm_lockfile::LockfileV3,
    options: &ResolverOptions,
) -> Option<DependencyGraph> {
    if lockfile.matches_manifest(manifest, options.dev) {
        let mut graph = DependencyGraph::from_lockfile_v3(lockfile);
        // Apply platform filters for optional dependencies
        for node in graph.nodes.values_mut() {
            if node.flags.optional {
                let compatible = options.platform.matches_with_libc(
                    node.os.as_deref(),
                    node.cpu.as_deref(),
                    node.libc.as_deref(),
                );
                if !compatible {
                    node.flags.skipped = true;
                    graph.skipped.insert(node.name.clone());
                    graph.skipped.insert(node.install_name.clone());
                }
            }
        }
        Some(graph)
    } else {
        None
    }
}

/// Convenience function to resolve a dependency graph from a manifest and package provider.
pub fn resolve_dependency_graph<P: PackageMetadataProvider>(
    manifest: &Manifest,
    provider: &P,
    options: &ResolverOptions,
) -> Result<DependencyGraph, SolverError> {
    resolve_dependency_graph_with_lockfile(manifest, provider, options, None)
}

/// Resolves a dependency graph with optional lockfile fast-path bypass.
pub fn resolve_dependency_graph_with_lockfile<P: PackageMetadataProvider>(
    manifest: &Manifest,
    provider: &P,
    options: &ResolverOptions,
    lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> Result<DependencyGraph, SolverError> {
    let mut opts = options.clone();
    if let Some(lf) = lockfile {
        opts.lockfile = Some(std::sync::Arc::new(lf.clone()));
    }
    let overrides = Overrides::from_json_value(
        manifest.extra.get("overrides"),
        manifest.dependencies.clone(),
    );
    let solver = Solver::new(provider, opts, overrides);
    solver.resolve(manifest)
}
