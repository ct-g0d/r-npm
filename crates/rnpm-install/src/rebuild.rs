use std::path::PathBuf;
use anyhow::{Context, Result};

use rnpm_core::manifest::Manifest;
use rnpm_lifecycle::{
    execute_topological, LifecycleOptions, LifecyclePackageNode, PackageSource,
    ScriptSandboxPolicy,
};
use crate::prune::{extract_package_name_from_path, scan_node_modules};

/// Options controlling `npm rebuild` execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildOptions {
    /// Project root directory. Defaults to ".".
    pub project_dir: PathBuf,
    /// Specific package names or specs to rebuild. If empty, rebuilds all installed packages.
    pub packages: Vec<String>,
    /// Skip running lifecycle build scripts.
    pub ignore_scripts: bool,
    /// Run scripts with direct stdio inheritance.
    pub foreground_scripts: bool,
    /// Enforce strict sandbox policy.
    pub strict_sandbox: bool,
}

impl Default for RebuildOptions {
    fn default() -> Self {
        Self {
            project_dir: PathBuf::from("."),
            packages: Vec::new(),
            ignore_scripts: false,
            foreground_scripts: false,
            strict_sandbox: false,
        }
    }
}

impl RebuildOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            ..Default::default()
        }
    }

    pub fn with_packages(mut self, packages: Vec<String>) -> Self {
        self.packages = packages;
        self
    }

    pub fn with_ignore_scripts(mut self, ignore: bool) -> Self {
        self.ignore_scripts = ignore;
        self
    }

    pub fn with_foreground_scripts(mut self, fg: bool) -> Self {
        self.foreground_scripts = fg;
        self
    }

    pub fn with_strict_sandbox(mut self, strict: bool) -> Self {
        self.strict_sandbox = strict;
        self
    }
}

/// Summary of an executed rebuild operation.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RebuildSummary {
    /// List of packages rebuilt (e.g. "package-name@version").
    pub rebuilt_packages: Vec<String>,
}

/// Matches an installed package against a filter string.
/// Filter can be:
/// - Exact package name: "foo", "@scope/bar"
/// - Unscoped name: "bar" for "@scope/bar"
/// - Name with version: "foo@1.0.0"
/// - Relative path: "node_modules/foo", "foo"
pub fn matches_rebuild_filter(
    filter: &str,
    pkg_name: &str,
    pkg_version: Option<&str>,
    pkg_path: &str,
) -> bool {
    let clean_filter = filter.trim();
    if clean_filter.is_empty() {
        return false;
    }

    // 1. Exact name match
    if clean_filter == pkg_name {
        return true;
    }

    // 2. Unscoped name match: filter "foo" matches "@scope/foo"
    if let Some(slash_idx) = pkg_name.find('/') {
        let unscoped = &pkg_name[slash_idx + 1..];
        if clean_filter == unscoped {
            return true;
        }
    }

    // 3. Exact name@version match
    if let Some(v) = pkg_version {
        let name_at_version = format!("{pkg_name}@{v}");
        if clean_filter == name_at_version {
            return true;
        }
        if let Some(slash_idx) = pkg_name.find('/') {
            let unscoped = &pkg_name[slash_idx + 1..];
            if clean_filter == format!("{unscoped}@{v}") {
                return true;
            }
        }
    }

    // 4. Path match: "node_modules/foo" or "packages/foo"
    let norm_filter = clean_filter.replace('\\', "/");
    let norm_path = pkg_path.replace('\\', "/");
    if norm_filter == norm_path {
        return true;
    }
    if let Some(stripped) = norm_path.strip_prefix("node_modules/") {
        if norm_filter == stripped {
            return true;
        }
    }

    false
}

/// Re-runs compilation and lifecycle build scripts for installed packages.
pub async fn execute_rebuild(options: &RebuildOptions) -> Result<RebuildSummary> {
    let project_dir = &options.project_dir;
    let node_modules_dir = project_dir.join("node_modules");

    if !node_modules_dir.is_dir() {
        return Ok(RebuildSummary::default());
    }

    if options.ignore_scripts {
        return Ok(RebuildSummary::default());
    }

    // 1. Discover all packages in node_modules
    let discovered = scan_node_modules(project_dir)
        .with_context(|| format!("Failed to scan node_modules in {}", project_dir.display()))?;

    // 2. Identify rebuild candidate packages
    let mut candidate_nodes = Vec::new();
    let mut candidate_names = Vec::new();

    for pkg_rel_path in discovered {
        let full_path = project_dir.join(&pkg_rel_path);
        let manifest_path = full_path.join("package.json");
        if !manifest_path.is_file() {
            continue;
        }

        let mut manifest = match Manifest::from_file(&manifest_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let name = manifest
            .name
            .clone()
            .unwrap_or_else(|| extract_package_name_from_path(&pkg_rel_path));
        let version = manifest.version.clone();

        // Check selective filter if packages specified
        if !options.packages.is_empty() {
            let matches_any = options
                .packages
                .iter()
                .any(|f| matches_rebuild_filter(f, &name, version.as_deref(), &pkg_rel_path));
            if !matches_any {
                continue;
            }
        }

        // Native add-on check: if binding.gyp is present, ensure default install script is set
        let binding_gyp = full_path.join("binding.gyp");
        let has_binding_gyp = binding_gyp.is_file();

        if has_binding_gyp && !manifest.scripts.contains_key("install") {
            // Check if cmake-js is configured or fallback to node-gyp rebuild
            let cmake_file = full_path.join("CMakeLists.txt");
            if cmake_file.is_file()
                && (manifest.dependencies.contains_key("cmake-js")
                    || manifest.dev_dependencies.contains_key("cmake-js"))
            {
                manifest
                    .scripts
                    .insert("install".to_string(), "cmake-js compile".to_string());
            } else {
                manifest
                    .scripts
                    .insert("install".to_string(), "node-gyp rebuild".to_string());
            }
        }

        // Determine if there are lifecycle build scripts to run
        let has_build_script = manifest.scripts.contains_key("preinstall")
            || manifest.scripts.contains_key("install")
            || manifest.scripts.contains_key("postinstall");

        if !has_build_script {
            continue;
        }

        // Collect dependencies for topological sorting
        let mut deps = Vec::new();
        for dep in manifest.dependencies.keys() {
            deps.push(dep.clone());
        }

        let id = match &version {
            Some(v) => format!("{name}@{v}"),
            None => name.clone(),
        };
        candidate_names.push(id);

        candidate_nodes.push(LifecyclePackageNode {
            package_path: pkg_rel_path,
            disk_path: full_path,
            manifest,
            source: PackageSource::Registry,
            dependencies: deps,
            optional: false,
        });
    }

    if candidate_nodes.is_empty() {
        return Ok(RebuildSummary::default());
    }

    // 3. Sort candidates bottom-up (deeper nesting first, dependencies before dependents)
    // Deeper paths have more `/node_modules/` segments
    candidate_nodes.sort_by(|a, b| {
        let count_a = a.package_path.matches("/node_modules/").count();
        let count_b = b.package_path.matches("/node_modules/").count();
        count_b.cmp(&count_a)
    });

    // 4. Configure lifecycle execution options
    let sandbox_policy = if options.strict_sandbox {
        ScriptSandboxPolicy::restricted()
    } else {
        ScriptSandboxPolicy::permissive()
    };

    let lifecycle_opts = LifecycleOptions {
        root_dir: project_dir.clone(),
        init_cwd: project_dir.clone(),
        ignore_scripts: options.ignore_scripts,
        capture_output: !options.foreground_scripts,
        foreground_scripts: options.foreground_scripts,
        timeout: None,
        sandbox_policy,
    };

    // Execute through lifecycle topological runner with empty root manifest (dependencies only)
    let root_manifest = Manifest::default();
    execute_topological(&candidate_nodes, &root_manifest, &lifecycle_opts).await?;

    Ok(RebuildSummary {
        rebuilt_packages: candidate_names,
    })
}
