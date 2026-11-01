use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use anyhow::{Context, Result};
use tracing::{debug, info, warn};
use rnpm_core::manifest::Manifest;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    Registry,
    Local,
}

#[derive(Debug, Clone)]
pub struct LifecyclePackageNode {
    pub package_path: String,
    pub disk_path: PathBuf,
    pub manifest: Manifest,
    pub source: PackageSource,
    pub dependencies: Vec<String>,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct LifecycleOptions {
    pub root_dir: PathBuf,
    pub init_cwd: PathBuf,
    pub ignore_scripts: bool,
    pub capture_output: bool,
}

/// Context for running a lifecycle script per docs/lifecycle-contract.md.
#[derive(Debug, Clone)]
pub struct LifecycleContext {
    pub project_root: PathBuf,
    pub package_dir: PathBuf,
    pub package_name: String,
    pub package_version: Option<String>,
    pub event: String,
    pub script_cmd: String,
    pub node_execpath: Option<PathBuf>,
    pub npm_execpath: Option<PathBuf>,
    pub extra_env: HashMap<String, String>,
}

impl LifecycleContext {
    pub fn new(
        project_root: impl Into<PathBuf>,
        package_dir: impl Into<PathBuf>,
        package_name: impl Into<String>,
        event: impl Into<String>,
        script_cmd: impl Into<String>,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            package_dir: package_dir.into(),
            package_name: package_name.into(),
            package_version: None,
            event: event.into(),
            script_cmd: script_cmd.into(),
            node_execpath: None,
            npm_execpath: None,
            extra_env: HashMap::new(),
        }
    }
}

/// Scrub sensitive authentication tokens and credentials from environment map.
pub fn is_sensitive_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();

    if lower.contains("authtoken")
        || lower.contains("password")
        || lower.contains("secret")
    {
        return true;
    }

    if lower.starts_with("//") || lower.contains("/:_") {
        return true;
    }

    if (lower.contains("_auth") || lower.contains("auth_")) && !lower.contains("author") {
        return true;
    }

    if lower.ends_with("token") || lower.starts_with("token") || lower.contains("_token") || lower.contains("token_") {
        return true;
    }

    false
}

/// Builds the scrubbed and populated environment map for the lifecycle script.
pub fn build_lifecycle_env(ctx: &LifecycleContext) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    // 1. Inherit existing environment while scrubbing sensitive credentials
    for (k, v) in std::env::vars() {
        if !is_sensitive_credential_key(&k) {
            env.insert(k, v);
        } else {
            debug!("Scrubbed sensitive credential key: {}", k);
        }
    }

    // 2. Extra env passed in (also scrubbed)
    for (k, v) in &ctx.extra_env {
        if !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    // 3. Hierarchical PATH construction
    let mut path_entries: Vec<PathBuf> = Vec::new();

    // Local package node_modules/.bin
    let local_bin = ctx.package_dir.join("node_modules").join(".bin");
    if local_bin.exists() {
        path_entries.push(local_bin);
    }

    // Project root node_modules/.bin
    let root_bin = ctx.project_root.join("node_modules").join(".bin");
    if root_bin.exists() && root_bin != ctx.package_dir.join("node_modules").join(".bin") {
        path_entries.push(root_bin);
    }

    // Node executable directory
    let node_bin = ctx.node_execpath.clone().unwrap_or_else(|| {
        if let Ok(cur_node) = std::env::var("NODE") {
            PathBuf::from(cur_node)
        } else {
            PathBuf::from("node")
        }
    });

    if let Some(parent) = node_bin.parent() {
        if parent.as_os_str() != "" {
            path_entries.push(parent.to_path_buf());
        }
    }

    // Append existing system PATH
    let existing_path = std::env::var("PATH").unwrap_or_default();
    let joined_custom_path = std::env::join_paths(&path_entries)
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let final_path = if joined_custom_path.is_empty() {
        existing_path
    } else if existing_path.is_empty() {
        joined_custom_path
    } else {
        format!("{joined_custom_path}{}{existing_path}", if cfg!(windows) { ";" } else { ":" })
    };

    env.insert("PATH".to_string(), final_path);

    // 4. Standard npm environment contract
    env.insert("INIT_CWD".to_string(), ctx.project_root.to_string_lossy().to_string());
    env.insert("npm_lifecycle_event".to_string(), ctx.event.clone());
    env.insert("npm_lifecycle_script".to_string(), ctx.script_cmd.clone());
    env.insert("npm_package_name".to_string(), ctx.package_name.clone());

    if let Some(ref ver) = ctx.package_version {
        env.insert("npm_package_version".to_string(), ver.clone());
    }

    let pkg_json = ctx.package_dir.join("package.json");
    env.insert("npm_package_json".to_string(), pkg_json.to_string_lossy().to_string());

    let node_str = node_bin.to_string_lossy().to_string();
    env.insert("NODE".to_string(), node_str.clone());
    env.insert("npm_node_execpath".to_string(), node_str);

    let rnpm_exec = ctx.npm_execpath.clone().unwrap_or_else(|| {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm"))
    });
    env.insert("npm_execpath".to_string(), rnpm_exec.to_string_lossy().to_string());

    env
}

/// Spawns and executes a lifecycle script within the specified context.
pub fn execute_lifecycle_script(ctx: &LifecycleContext) -> Result<ExitStatus> {
    info!(
        "Running lifecycle script '{}' for package {} in {}",
        ctx.event,
        ctx.package_name,
        ctx.package_dir.display()
    );

    let env = build_lifecycle_env(ctx);

    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("cmd.exe");
        c.raw_arg(format!("/d /s /c {}", ctx.script_cmd));
        c
    };

    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&ctx.script_cmd);
        c
    };

    cmd.current_dir(&ctx.package_dir);
    cmd.env_clear();
    cmd.envs(env);

    let status = cmd.status()
        .with_context(|| format!("Failed to spawn lifecycle script for {}", ctx.package_name))?;

    if !status.success() {
        warn!(
            "Lifecycle script '{}' failed for {} with exit code: {:?}",
            ctx.event, ctx.package_name, status.code()
        );
    }

    Ok(status)
}

/// Executes dependency lifecycle scripts bottom-up (topologically), followed by root hooks.
pub async fn execute_topological(
    nodes: &[LifecyclePackageNode],
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
) -> Result<()> {
    if opts.ignore_scripts {
        return Ok(());
    }

    // Topological sorting: leaf nodes first (bottom-up)
    // We compute dependency depth/ranks
    let mut name_to_node: HashMap<String, &LifecyclePackageNode> = HashMap::new();
    for node in nodes {
        if let Some(ref name) = node.manifest.name {
            name_to_node.insert(name.clone(), node);
        }
    }

    // Order nodes: nodes with no dependencies in nodes list first
    let mut ordered: Vec<&LifecyclePackageNode> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    fn visit<'a>(
        node: &'a LifecyclePackageNode,
        name_to_node: &HashMap<String, &'a LifecyclePackageNode>,
        visited: &mut HashSet<String>,
        ordered: &mut Vec<&'a LifecyclePackageNode>,
    ) {
        let name = node.manifest.name.as_deref().unwrap_or("");
        if visited.contains(name) {
            return;
        }
        for dep in &node.dependencies {
            if let Some(dep_node) = name_to_node.get(dep) {
                visit(dep_node, name_to_node, visited, ordered);
            }
        }
        visited.insert(name.to_string());
        ordered.push(node);
    }

    for node in nodes {
        visit(node, &name_to_node, &mut visited, &mut ordered);
    }

    // Execute dependency hooks in bottom-up order:
    // Hooks: preinstall -> install -> postinstall
    // Note: Registry dependencies NEVER run `prepare` per docs/lifecycle-contract.md!
    for node in ordered {
        let hooks = match node.source {
            PackageSource::Registry => &["preinstall", "install", "postinstall"][..],
            PackageSource::Local => &["preinstall", "install", "postinstall", "prepare"][..],
        };

        for &hook in hooks {
            if let Some(script_cmd) = node.manifest.scripts.get(hook) {
                let mut ctx = LifecycleContext::new(
                    &opts.root_dir,
                    &node.disk_path,
                    node.manifest.name.as_deref().unwrap_or("unknown"),
                    hook,
                    script_cmd,
                );
                ctx.package_version = node.manifest.version.clone();

                match execute_lifecycle_script(&ctx) {
                    Ok(status) if status.success() => {},
                    Ok(status) => {
                        if node.optional {
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {} failed at {} script",
                                node.manifest.name.as_deref().unwrap_or("unknown"),
                                hook
                            );
                        } else {
                            return Err(anyhow::anyhow!(
                                "Lifecycle script '{}' failed for package {} with exit code: {:?}",
                                hook, node.manifest.name.as_deref().unwrap_or("unknown"), status.code()
                            ));
                        }
                    },
                    Err(e) => {
                        if node.optional {
                            warn!("Optional dependency lifecycle script error: {e}");
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    // Root package lifecycle execution: preinstall -> install -> postinstall -> prepare
    let root_hooks = ["preinstall", "install", "postinstall", "prepare"];
    for hook in root_hooks {
        if let Some(script_cmd) = root_manifest.scripts.get(hook) {
            let mut ctx = LifecycleContext::new(
                &opts.root_dir,
                &opts.root_dir,
                root_manifest.name.as_deref().unwrap_or("root"),
                hook,
                script_cmd,
            );
            ctx.package_version = root_manifest.version.clone();
            let status = execute_lifecycle_script(&ctx)?;
            if !status.success() {
                return Err(anyhow::anyhow!(
                    "Root lifecycle script '{}' failed with exit code: {:?}",
                    hook, status.code()
                ));
            }
        }
    }

    Ok(())
}
