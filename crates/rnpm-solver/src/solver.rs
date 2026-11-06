use std::collections::{BTreeMap, VecDeque};
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use tracing::{debug, warn};

use crate::aliases::DependencySpec;
use crate::error::SolverError;
use crate::graph::{DependencyEdge, DependencyGraph, DependencyType, Node, NodeFlags};
use crate::hoisting::{determine_placement_with_peers, PlacementDecision};
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
    /// When true, fail immediately with npm-compatible ERESOLVE error on any peer dependency conflict/mismatch.
    pub strict_peer_deps: bool,
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
            strict_peer_deps: false,
            lockfile: None,
        }
    }
}

impl ResolverOptions {
    /// Returns true if peer conflicts or mismatches should fail with an ERESOLVE error.
    #[inline]
    pub fn is_strict_peers(&self) -> bool {
        !self.legacy_peer_deps && (self.strict_peers || self.strict_peer_deps)
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
    dev_path: bool,
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

    /// Attaches an existing base graph to the solver (e.g. pre-populated workspace graph).
    pub fn with_graph(mut self, graph: DependencyGraph) -> Self {
        self.graph = graph;
        self
    }

    /// Enqueue an external dependency resolution task.
    pub fn enqueue_task(
        &mut self,
        parent_location: String,
        parent_package_name: String,
        install_name: String,
        raw_spec: String,
        dep_type: DependencyType,
        ancestors: std::sync::Arc<Vec<String>>,
    ) {
        if self.options.legacy_peer_deps
            && (dep_type == DependencyType::Peer || dep_type == DependencyType::PeerOptional)
        {
            return;
        }
        if dep_type == DependencyType::Peer || dep_type == DependencyType::PeerOptional {
            self.peer_ctx.enter(&parent_package_name, &install_name);
        }
        self.queue.push_back(ResolveTask {
            parent_location,
            parent_package_name,
            install_name,
            raw_spec,
            dep_type,
            dev_path: dep_type == DependencyType::Dev,
            ancestors,
        });
    }

    fn push_task(&mut self, task: ResolveTask) {
        if task.dev_path {
            self.queue.push_back(task);
            return;
        }
        if task.parent_location.is_empty() {
            let insert_at = self
                .queue
                .iter()
                .position(|queued| queued.dev_path)
                .unwrap_or(self.queue.len());
            self.queue.insert(insert_at, task);
            return;
        }

        // Arborist resolves a package's dependency branch before moving to
        // the next root sibling. Keeping descendants at the front of the
        // queue lets the first compatible version claim the shared hoisted
        // slot (for example picomatch@2 from Jest before Vite's picomatch@4),
        // while the explicit root ordering above remains stable.
        self.queue.push_front(task);
    }

    /// Processes all queued dependency resolution tasks until completion.
    pub fn resolve_tasks(&mut self) -> Result<(), SolverError> {
        while let Some(task) = self.queue.pop_front() {
            self.process_task(task)?;
        }
        Ok(())
    }

    /// Extracts the resolved dependency graph.
    pub fn into_graph(self) -> DependencyGraph {
        let mut graph = self.graph;
        graph.normalize_dependency_flags();
        graph
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
            peer_dependencies_meta: root_manifest.peer_dependencies_meta.clone(),
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
            license: root_manifest.extra.get("license").and_then(|v| v.as_str()).map(str::to_owned),
            engines: root_manifest.engines.clone(),
            parsed_version: None,
            extra: root_manifest.extra.clone(),
        };
        self.graph.nodes.insert(String::new(), root_node);

        // Collect root dependencies with npm's precedence order. npm walks
        // production dependencies before dev-only branches, so a compatible
        // package first reached through a production dependency gets the
        // highest hoisting priority. Keep the BTreeMap for deterministic
        // fallback ordering and duplicate/override semantics, then enqueue
        // the effective entries by dependency class.
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

        // 4. peerDependencies from root (auto-install if not legacy_peer_deps and not already present)
        if !self.options.legacy_peer_deps {
            for (k, v) in &root_manifest.peer_dependencies {
                let is_opt_peer = root_manifest
                    .peer_dependencies_meta
                    .get(k)
                    .map(|m| m.optional)
                    .unwrap_or(false);
                let p_type = if is_opt_peer {
                    DependencyType::PeerOptional
                } else {
                    DependencyType::Peer
                };
                root_deps
                    .entry(k.clone())
                    .or_insert_with(|| (v.clone(), p_type));
            }
        }

        let root_ancestors = std::sync::Arc::new(vec![root_name.clone()]);
        let mut queued = std::collections::HashSet::new();
        let enqueue_root = |install_name: &str,
                            this: &mut Solver<'a, P>,
                            queued: &mut std::collections::HashSet<String>| {
            if !queued.insert(install_name.to_string()) {
                return;
            }
            if let Some((raw_spec, dep_type)) = root_deps.get(install_name).cloned() {
                this.push_task(ResolveTask {
                    parent_location: String::new(),
                    parent_package_name: root_name.clone(),
                    install_name: install_name.to_string(),
                    raw_spec,
                    dep_type,
                    dev_path: dep_type == DependencyType::Dev,
                    ancestors: root_ancestors.clone(),
                });
            }
        };

        // npm's Arborist normalizes dependency keys lexicographically before
        // walking the root tree. Using the manifest's insertion order here
        // lets an arbitrary package.json edit change which version claims a
        // shared hoisted slot.
        for install_name in root_manifest.dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        for install_name in root_manifest.optional_dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        if !self.options.legacy_peer_deps {
            for install_name in root_manifest.peer_dependencies.keys() {
                enqueue_root(install_name, &mut self, &mut queued);
            }
        }
        for install_name in root_manifest.dev_dependencies.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }
        for install_name in root_deps.keys() {
            enqueue_root(install_name, &mut self, &mut queued);
        }

        // Process resolution queue
        while let Some(task) = self.queue.pop_front() {
            self.process_task(task)?;
        }

        self.graph.normalize_dependency_flags();
        Ok(self.graph)
    }

    fn process_task(&mut self, task: ResolveTask) -> Result<(), SolverError> {
        if self.options.legacy_peer_deps
            && (task.dep_type == DependencyType::Peer || task.dep_type == DependencyType::PeerOptional)
        {
            return Ok(());
        }

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
        } else if let Some(alias_str) = task.raw_spec.strip_prefix("npm:") {
            let (real_pkg, inner_spec) = if alias_str.starts_with('@') {
                if let Some(slash) = alias_str.find('/') {
                    let after = &alias_str[slash + 1..];
                    if let Some(at) = after.find('@') {
                        (&alias_str[..slash + 1 + at], &after[at + 1..])
                    } else {
                        (alias_str, "*")
                    }
                } else {
                    (alias_str, "*")
                }
            } else if let Some(at) = alias_str.find('@') {
                (&alias_str[..at], &alias_str[at + 1..])
            } else {
                (alias_str, "*")
            };

            if let Some(overridden) = self.overrides.resolve_override_strings(
                real_pkg,
                inner_spec,
                &task.ancestors,
            ) {
                debug!(
                    "Overriding aliased package '{}' (install: '{}'): '{}' -> '{}'",
                    real_pkg, task.install_name, inner_spec, overridden
                );
                if overridden.starts_with("npm:") {
                    overridden
                } else {
                    format!("npm:{}@{}", real_pkg, overridden)
                }
            } else {
                task.raw_spec.clone()
            }
        } else {
            task.raw_spec.clone()
        };

        // 2. Parse dependency spec (separating alias and real package name)
        let dep_spec = DependencySpec::parse(&task.install_name, &effective_spec)?;

        // 3. Check for cyclic peer dependencies and existing peer instances
        let is_peer = task.dep_type == DependencyType::Peer
            || task.dep_type == DependencyType::PeerOptional;
        if is_peer
            && self
                .queue
                .iter()
                .any(|queued| {
                    queued.parent_location.is_empty()
                        && (queued.install_name == task.install_name
                            || queued.install_name == dep_spec.package_name)
                })
        {
            // A depth-first subtree can encounter a peer before the root's
            // direct dependency that is meant to satisfy it.  Defer that
            // peer until the pending root task has been resolved so strict
            // diagnostics and alias satisfaction see the same visible node
            // npm would use.
            self.queue.push_back(task);
            return Ok(());
        }
        if is_peer {
            let dep_alias = if task.install_name != dep_spec.package_name {
                Some(task.install_name.as_str())
            } else {
                None
            };
            if self
                .peer_ctx
                .is_cycle_on_path_with_alias(&task.ancestors, &dep_spec.package_name, dep_alias)
            {
                let cycle_path_str = self
                    .peer_ctx
                    .find_cycle_path_on_path(&task.ancestors, &dep_spec.package_name, dep_alias)
                    .map(|p| p.join(" -> "))
                    .unwrap_or_else(|| {
                        format!("{} -> {}", task.parent_package_name, dep_spec.package_name)
                    });
                debug!(
                    "Peer cycle detected: {}, resolving to active instance",
                    cycle_path_str
                );
                // Look for existing node with package_name or install_name visible in ancestor scope
                if let Some(existing) = crate::hoisting::find_visible_peer_node(
                    &self.graph,
                    &task.parent_location,
                    &task.install_name,
                    &dep_spec.package_name,
                ) {
                    if !crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        if task.dep_type == DependencyType::Peer {
                            if self.options.is_strict_peers() {
                                return Err(SolverError::peer_conflict(
                                    &task.parent_package_name,
                                    &dep_spec.package_name,
                                    &effective_spec,
                                    Some(existing.version.clone()),
                                    Some(existing.location.clone()),
                                    (*task.ancestors).clone(),
                                    format!(
                                        "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                        existing.name, existing.version, existing.location, effective_spec
                                    ),
                                ));
                            } else {
                                warn!(
                                    "Peer dependency conflict in cycle: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                    task.parent_package_name, dep_spec.package_name, effective_spec, existing.name, existing.version
                                );
                            }
                        } else if task.dep_type == DependencyType::PeerOptional {
                            debug!(
                                "Optional peer dependency '{}' for '{}' in cycle conflicts with installed {}@{} at '{}'; omitting optional peer",
                                dep_spec.package_name, task.parent_package_name, existing.name, existing.version, existing.location
                            );
                            return Ok(());
                        }
                    }

                    self.graph.edges.push(DependencyEdge {
                        from_location: task.parent_location,
                        to_location: existing.location.clone(),
                        install_name: task.install_name,
                        package_name: dep_spec.package_name,
                        spec: effective_spec,
                        dep_type: task.dep_type,
                    });
                    return Ok(());
                }
            }

            // Check if peer is already satisfied in ancestor/root scope
            if let Some(existing) = crate::hoisting::find_visible_peer_node(
                &self.graph,
                &task.parent_location,
                &task.install_name,
                &dep_spec.package_name,
            ) {
                if crate::hoisting::node_matches_peer_name(existing, &task.install_name, &dep_spec.package_name) {
                    if crate::hoisting::node_satisfies_target(existing, &dep_spec.target) {
                        debug!(
                            "Peer dependency '{}@{}' satisfied by existing node at '{}'",
                            dep_spec.package_name, effective_spec, existing.location
                        );
                        self.graph.edges.push(DependencyEdge {
                            from_location: task.parent_location,
                            to_location: existing.location.clone(),
                            install_name: task.install_name,
                            package_name: dep_spec.package_name,
                            spec: effective_spec,
                            dep_type: task.dep_type,
                        });
                        return Ok(());
                    } else if task.dep_type == DependencyType::Peer {
                        if self.options.is_strict_peers() {
                            return Err(SolverError::peer_conflict(
                                &task.parent_package_name,
                                &dep_spec.package_name,
                                &effective_spec,
                                Some(existing.version.clone()),
                                Some(existing.location.clone()),
                                (*task.ancestors).clone(),
                                format!(
                                    "Installed {}@{} at '{}' does not satisfy peer constraint '{}'",
                                    existing.name, existing.version, existing.location, effective_spec
                                ),
                            ));
                        } else {
                            warn!(
                                "Peer dependency conflict: {} requires {}@{}, but found {}@{} (non-strict mode)",
                                task.parent_package_name, dep_spec.package_name, effective_spec, existing.name, existing.version
                            );
                        }
                    } else if task.dep_type == DependencyType::PeerOptional {
                        debug!(
                            "Optional peer dependency '{}' for '{}' conflicts with installed {}@{} at '{}'; omitting optional peer",
                            dep_spec.package_name, task.parent_package_name, existing.name, existing.version, existing.location
                        );
                        return Ok(());
                    }
                }
            } else if task.dep_type == DependencyType::PeerOptional {
                // If an optional peer is NOT present in the scope, npm does not automatically download/install it
                debug!(
                    "Optional peer dependency '{}@{}' for '{}' is not present in scope; skipping auto-install",
                    dep_spec.package_name, effective_spec, task.parent_package_name
                );
                return Ok(());
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
                if !self.options.is_strict_peers() {
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
                if !self.options.is_strict_peers() {
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
        let compatible = self.options.platform.matches_with_libc(
            chosen_version.os.as_deref(),
            chosen_version.cpu.as_deref(),
            chosen_version.libc.as_deref(),
        );
        let platform_skipped = !compatible && task.dep_type == DependencyType::Optional;
        if !compatible && !platform_skipped {
                let wanted = format!(
                    "os: {:?}, cpu: {:?}, libc: {:?}",
                    chosen_version.os.as_deref().unwrap_or(&[]),
                    chosen_version.cpu.as_deref().unwrap_or(&[]),
                    chosen_version.libc.as_deref().unwrap_or(&[])
                );
                let current = format!(
                    "os: {}, cpu: {}, libc: {}",
                    self.options.platform.os,
                    self.options.platform.cpu,
                    self.options.platform.libc.as_deref().unwrap_or("none")
                );
                return Err(SolverError::platform_incompatible(
                    &dep_spec.package_name,
                    &chosen_version.version,
                    wanted,
                    current,
                    (*task.ancestors).clone(),
                    format!("Package '{}@{}' is incompatible with the current platform", dep_spec.package_name, chosen_version.version),
                ));
        }
        if platform_skipped {
            debug!(
                "Optional package '{}@{}' retained in lockfile but skipped on platform ({:?})",
                dep_spec.package_name, chosen_version.version, self.options.platform
            );
        }

        // 6. Hoisting & Tree Placement
        let placement = determine_placement_with_peers(
            &self.graph,
            &task.parent_location,
            &dep_spec.install_name,
            &dep_spec.package_name,
            &dep_spec.target,
            &chosen_version.peer_dependencies,
            &chosen_version.peer_dependencies_meta,
        );
        let parent_skipped = self
            .graph
            .nodes
            .get(&task.parent_location)
            .map(|node| node.flags.skipped)
            .unwrap_or(false);

        match placement {
            PlacementDecision::Reuse(existing_loc) => {
                debug!(
                    "Deduplicated '{}': reusing existing node at '{}'",
                    dep_spec.install_name, existing_loc
                );
                if parent_skipped {
                    if let Some(existing) = self.graph.nodes.get_mut(&existing_loc) {
                        existing.flags.skipped = true;
                    }
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }
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
                // Arborist can rehome an earlier transitive occupant when a
                // later branch needs a different version in the shared root
                // slot. Without this repair, traversal order leaves the
                // lower version at the root and nests the higher-priority
                // package, producing the common Jest p-limit mismatch.
                if target_loc == format!("node_modules/{}", dep_spec.install_name)
                    && self.graph.nodes.get(&target_loc).is_some_and(|existing| {
                        existing.name == dep_spec.package_name
                            && !crate::hoisting::node_satisfies_target(existing, &dep_spec.target)
                    })
                {
                    let _ = self.rehome_transitive_root_node(&target_loc, &dep_spec.install_name);
                }
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
                    skipped: platform_skipped || parent_skipped,
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
                    peer_dependencies_meta: chosen_version.peer_dependencies_meta.clone(),
                    optional_dependencies: chosen_version.optional_dependencies.clone(),
                    os: chosen_version.os.clone(),
                    cpu: chosen_version.cpu.clone(),
                    libc: chosen_version.libc.clone(),
                    bin: chosen_version.bin.clone(),
                    license: chosen_version.license.clone(),
                    engines: chosen_version.engines.clone(),
                    extra: {
                        let mut extra = chosen_version.extra.clone();
                        if let Some(deprecated) = &chosen_version.deprecated {
                            extra.insert("deprecated".to_string(), serde_json::Value::String(deprecated.clone()));
                        }
                        extra
                    },
                };

                self.graph.nodes.insert(target_loc.clone(), node);

                if platform_skipped || parent_skipped {
                    self.graph.skipped.insert(dep_spec.package_name.clone());
                    self.graph.skipped.insert(task.install_name.clone());
                }

                self.graph.edges.push(DependencyEdge {
                    from_location: task.parent_location,
                    to_location: target_loc.clone(),
                    install_name: task.install_name.clone(),
                    package_name: dep_spec.package_name.clone(),
                    spec: effective_spec,
                    dep_type: task.dep_type,
                });

                // Enqueue child dependencies with Arc ancestors to avoid vector clones.
                // A platform-skipped optional package is retained as a lockfile
                // record together with its dependency metadata. Descendants inherit
                // optional/skipped reachability and therefore remain out of the
                // physical install while preserving cross-platform lockfile parity.

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
                        if let Some((_, DependencyType::Prod)) = child_deps.get(k) {
                            // Direct production dependency already present; do not overwrite with Peer or PeerOptional
                            continue;
                        }
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
                    }
                }

                // npm's Arborist walks package dependency names in sorted
                // order.  Registry packuments preserve insertion order, but
                // using that order here changes which compatible version wins
                // a shared hoisted slot (for example Express's `ms`).  The
                // BTreeMap keeps traversal deterministic and matches npm's
                // lockfile dependency ordering.
                let child_tasks = child_deps.into_iter().map(|(c_name, (c_spec, c_type))| ResolveTask {
                        parent_location: target_loc.clone(),
                        parent_package_name: dep_spec.package_name.clone(),
                        install_name: c_name,
                        raw_spec: c_spec,
                        dep_type: c_type,
                        dev_path: task.dev_path || c_type == DependencyType::Dev,
                        ancestors: child_ancestors.clone(),
                    }).collect::<Vec<_>>();
                // Keep a package's direct dependencies ahead of their
                // descendants. This matches Arborist's breadth-first
                // placement pass and lets a later direct dependency claim a
                // compatible root slot before an earlier sibling's nested
                // subtree is expanded.
                for child_task in child_tasks {
                    self.push_task(child_task);
                }
            }
        }

        Ok(())
    }

    /// Move a transitive root occupant beneath the sole package that still
    /// requires its version. Direct root dependencies are never moved, and
    /// ambiguous multi-parent occupants are left untouched for the normal
    /// conflict-nesting path.
    fn rehome_transitive_root_node(&mut self, root_location: &str, install_name: &str) -> bool {
        let incoming: Vec<_> = self
            .graph
            .edges
            .iter()
            .filter(|edge| edge.to_location == root_location)
            .collect();
        if incoming.is_empty() || incoming.iter().any(|edge| edge.from_location.is_empty()) {
            return false;
        }
        let Some(existing_node) = self.graph.nodes.get(root_location).cloned() else {
            return false;
        };
        let compatible_edges: Vec<_> = incoming
            .iter()
            .filter(|edge| {
                PackageTarget::parse(&edge.spec)
                    .map(|target| crate::hoisting::node_satisfies_target(&existing_node, &target))
                    .unwrap_or(false)
            })
            .collect();
        if compatible_edges.is_empty() {
            return false;
        }
        let parent = compatible_edges[0].from_location.clone();
        if compatible_edges.iter().any(|edge| edge.from_location != parent) {
            return false;
        }
        let nested = format!("{parent}/node_modules/{install_name}");
        if self.graph.nodes.contains_key(&nested) {
            return false;
        }
        let Some(mut node) = self.graph.nodes.remove(root_location) else {
            return false;
        };
        node.location = nested.clone();
        self.graph.nodes.insert(nested.clone(), node);
        for edge in &mut self.graph.edges {
            if edge.to_location != root_location { continue; }
            let keep_nested = PackageTarget::parse(&edge.spec)
                .map(|target| crate::hoisting::node_satisfies_target(&existing_node, &target))
                .unwrap_or(false);
            if keep_nested { edge.to_location = nested.clone(); }
        }
        true
    }

    /// Selects the highest version matching target constraint in a single linear pass (O(N), zero Vec allocations, zero metadata clones).
    fn select_version<'b>(
        &self,
        meta: &'b PackageMetadata,
        target: &PackageTarget,
    ) -> Option<&'b PackageVersionMetadata> {
        match target {
            PackageTarget::Version(expected) => {
                let v_str = expected.to_string();
                if let Some(v) = meta.versions.get(&v_str) {
                    Some(v)
                } else {
                    meta.versions.iter().find_map(|(ver_str, v_meta)| {
                        if let Ok(parsed) = Version::parse(ver_str) {
                            if &parsed == expected {
                                return Some(v_meta);
                            }
                        }
                        None
                    })
                }
            }
            PackageTarget::Tag(tag) => {
                let tagged_version = meta.dist_tags.get(tag)?;
                meta.versions.get(tagged_version)
            }
            PackageTarget::Range(range) => {
                // npm resolves registry ranges through the `latest` dist-tag
                // when that tagged version satisfies the requested range. This
                // matters when a registry intentionally keeps a newer version
                // outside the default channel or leaves `latest` on an older
                // compatible release.
                if let Some(latest_version) = meta.dist_tags.get("latest") {
                    if let Some(latest) = meta.versions.get(latest_version) {
                        if Version::parse(&latest.version).ok().is_some_and(|v| range.satisfies(&v)) {
                            return Some(latest);
                        }
                    }
                }
                let mut best: Option<(&'b PackageVersionMetadata, Version)> = None;
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
                best.map(|(v_meta, _)| v_meta)
            }
            PackageTarget::Alias { target, .. } => self.select_version(meta, target),
            PackageTarget::File(_) | PackageTarget::Git { .. } | PackageTarget::Url(_) => {
                select_max_semver_version(meta)
            }
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    select_max_semver_version(meta)
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    let mut best: Option<(&'b PackageVersionMetadata, Version)> = None;
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
                    best.map(|(v_meta, _)| v_meta)
                } else {
                    select_max_semver_version(meta)
                }
            }
        }
    }
}

/// Returns the highest version in `meta.versions` by SemVer comparison,
/// falling back to the last entry if no versions parse as valid SemVer.
fn select_max_semver_version<'b>(
    meta: &'b PackageMetadata,
) -> Option<&'b PackageVersionMetadata> {
    let mut best: Option<(&'b PackageVersionMetadata, Version)> = None;
    for (ver_str, v_meta) in &meta.versions {
        if let Ok(parsed) = Version::parse(ver_str) {
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
    best.map(|(v_meta, _)| v_meta).or_else(|| meta.versions.values().last())
}

/// Attempts fast-path dependency graph construction from a lockfile v3 without tree traversal.
/// Returns `Some(DependencyGraph)` if the lockfile matches the manifest and all dependencies
/// and constraints are verified, or `None` if any lockfile drift is detected.
pub fn resolve_fast_path(
    manifest: &Manifest,
    lockfile: &rnpm_lockfile::LockfileV3,
    options: &ResolverOptions,
) -> Option<DependencyGraph> {
    if !lockfile.matches_manifest(manifest, options.dev) {
        return None;
    }

    let overrides = Overrides::from_json_value(
        manifest.extra.get("overrides"),
        manifest.dependencies.clone(),
    );

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
        } else if !node.location.is_empty() {
            let compatible = options.platform.matches_with_libc(
                node.os.as_deref(),
                node.cpu.as_deref(),
                node.libc.as_deref(),
            );
            if !compatible {
                return None;
            }
        }
    }

    // Comprehensive lockfile drift check: verify that all non-skipped dependencies
    // exist in the lockfile and satisfy their version/override constraints.
    if !validate_fast_path_graph(&graph, options, &overrides) {
        debug!("Fast-path: lockfile drift detected; falling back to full resolution");
        return None;
    }

    Some(graph)
}

fn validate_fast_path_graph(
    graph: &DependencyGraph,
    options: &ResolverOptions,
    overrides: &Overrides,
) -> bool {
    let mut buf = String::with_capacity(128);

    for (loc, node) in &graph.nodes {
        if node.flags.skipped {
            continue;
        }

        // Direct prod dependencies
        for (dep_name, dep_spec) in &node.dependencies {
            if !validate_fast_path_dep(
                graph,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Prod,
                options,
                overrides,
                &mut buf,
            ) {
                return false;
            }
        }

        // devDependencies (only checked on root node if options.dev)
        if loc.is_empty() && options.dev {
            for (dep_name, dep_spec) in &node.dev_dependencies {
                if !validate_fast_path_dep(
                    graph,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Dev,
                    options,
                    overrides,
                    &mut buf,
                ) {
                    return false;
                }
            }
        }

        // optionalDependencies (if target exists and is not skipped, must satisfy constraint)
        for (dep_name, dep_spec) in &node.optional_dependencies {
            if !validate_fast_path_dep(
                graph,
                loc,
                dep_name,
                dep_spec,
                DependencyType::Optional,
                options,
                overrides,
                &mut buf,
            ) {
                return false;
            }
        }

        // peerDependencies (if !options.legacy_peer_deps)
        if !options.legacy_peer_deps {
            for (dep_name, dep_spec) in &node.peer_dependencies {
                if !validate_fast_path_dep(
                    graph,
                    loc,
                    dep_name,
                    dep_spec,
                    DependencyType::Peer,
                    options,
                    overrides,
                    &mut buf,
                ) {
                    return false;
                }
            }
        }
    }

    true
}

fn validate_fast_path_dep(
    graph: &DependencyGraph,
    from_loc: &str,
    dep_name: &str,
    raw_spec: &str,
    dep_type: DependencyType,
    options: &ResolverOptions,
    overrides: &Overrides,
    buf: &mut String,
) -> bool {
    let target_loc = DependencyGraph::find_in_scope_hierarchy(&graph.nodes, from_loc, dep_name, buf);

    let Some(target) = target_loc else {
        // Missing target
        if dep_type == DependencyType::Optional {
            return true;
        }
        if dep_type == DependencyType::Peer {
            return !options.is_strict_peers();
        }
        // Required dependency missing in lockfile -> drift!
        return false;
    };

    let Some(target_node) = graph.nodes.get(target) else {
        return false;
    };

    if target_node.flags.skipped {
        return dep_type == DependencyType::Optional;
    }

    // Determine effective spec taking overrides into account
    let effective_spec = if overrides.rules.is_empty() {
        raw_spec
    } else {
        let mut ancestors = Vec::new();
        if !from_loc.is_empty() {
            let mut curr = from_loc;
            while !curr.is_empty() {
                if let Some(n) = graph.nodes.get(curr) {
                    ancestors.push(n.name.as_str());
                }
                if let Some(idx) = curr.rfind("/node_modules/") {
                    curr = &curr[..idx];
                } else {
                    break;
                }
            }
            ancestors.reverse();
        }
        if let Some(overridden) = overrides.resolve_override(dep_name, raw_spec, &ancestors) {
            if let Ok(parsed_override) = DependencySpec::parse(dep_name, &overridden) {
                return target_node.name == parsed_override.package_name
                    && crate::hoisting::node_satisfies_target(target_node, &parsed_override.target);
            }
            return false;
        }
        raw_spec
    };

    let Ok(parsed_spec) = DependencySpec::parse(dep_name, effective_spec) else {
        return false;
    };

    if target_node.name != parsed_spec.package_name {
        return false;
    }

    if !crate::hoisting::node_satisfies_target(target_node, &parsed_spec.target) {
        if dep_type == DependencyType::Peer {
            return !options.is_strict_peers();
        }
        return false;
    }

    true
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
