use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use rnpm_core::manifest::Manifest;

/// Options configuring lifecycle environment and execution.
#[derive(Debug, Clone)]
pub struct LifecycleOptions {
    /// Initial working directory where the CLI was invoked (`INIT_CWD`).
    pub init_cwd: Option<PathBuf>,
    /// Path to the active Node.js binary (`npm_node_execpath` / `NODE`).
    pub node_path: Option<PathBuf>,
    /// Path to the rnpm binary (`npm_execpath`).
    pub rnpm_path: Option<PathBuf>,
    /// Workspace root directory for ancestor `.bin` searching.
    pub workspace_root: Option<PathBuf>,
    /// When true, all scripts (`preinstall`, `install`, `postinstall`, `prepare`) are skipped.
    pub ignore_scripts: bool,
    /// Explicit npm configuration map transformed into `npm_config_*`.
    pub config_env: BTreeMap<String, String>,
    /// If true, automatically delete package directory when an optional dependency fails.
    pub remove_failed_optional: bool,
    /// Output capture mode.
    pub capture_output: bool,
}

impl Default for LifecycleOptions {
    fn default() -> Self {
        Self {
            init_cwd: None,
            node_path: None,
            rnpm_path: None,
            workspace_root: None,
            ignore_scripts: false,
            config_env: BTreeMap::new(),
            remove_failed_optional: true,
            capture_output: true,
        }
    }
}

/// Construct hierarchical `PATH` string according to Section 3.1:
/// 1. `node_modules/.bin` of the package executing the script.
/// 2. `node_modules/.bin` of every ancestor directory up to the workspace root.
/// 3. Directory containing the active `node` executable.
/// 4. System `PATH`.
pub fn construct_path(
    package_dir: &Path,
    workspace_root: Option<&Path>,
    node_path: Option<&Path>,
) -> OsString {
    let mut bin_dirs: Vec<PathBuf> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    let mut add_dir = |p: PathBuf| {
        // Normalize path for deduplication
        let key = p.clean();
        if seen.insert(key.clone()) {
            bin_dirs.push(p);
        }
    };

    // 1. package_dir/node_modules/.bin
    add_dir(package_dir.join("node_modules").join(".bin"));

    // 2. Ancestor directories up to workspace root (or filesystem root)
    let ws_root = workspace_root.map(PathCleanExt::clean);
    let mut current = package_dir.parent();
    while let Some(dir) = current {
        add_dir(dir.join("node_modules").join(".bin"));
        if let Some(ref root) = ws_root {
            if dir.clean() == *root {
                break;
            }
        }
        current = dir.parent();
    }

    // 3. Directory containing active node executable
    let resolved_node = find_node_execpath(node_path);
    if let Some(parent) = resolved_node.parent() {
        add_dir(parent.to_path_buf());
    }

    // 4. System PATH
    let system_path = std::env::var_os("PATH")
        .or_else(|| std::env::var_os("Path"))
        .unwrap_or_default();

    for p in std::env::split_paths(&system_path) {
        add_dir(p);
    }

    std::env::join_paths(bin_dirs).unwrap_or_default()
}

/// Helper trait for path cleaning.
trait PathCleanExt {
    fn clean(&self) -> PathBuf;
}

impl PathCleanExt for Path {
    fn clean(&self) -> PathBuf {
        let mut out = PathBuf::new();
        for component in self.components() {
            out.push(component);
        }
        out
    }
}

/// Find active Node.js binary path.
pub fn find_node_execpath(custom: Option<&Path>) -> PathBuf {
    if let Some(p) = custom {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("npm_node_execpath") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("NODE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }

    // Search system PATH
    let path_var = std::env::var_os("PATH")
        .or_else(|| std::env::var_os("Path"))
        .unwrap_or_default();

    for dir in std::env::split_paths(&path_var) {
        #[cfg(windows)]
        {
            let exe = dir.join("node.exe");
            if exe.is_file() {
                return exe;
            }
            let cmd = dir.join("node.cmd");
            if cmd.is_file() {
                return cmd;
            }
        }
        #[cfg(not(windows))]
        {
            let bin = dir.join("node");
            if bin.is_file() {
                return bin;
            }
        }
    }

    PathBuf::from("node")
}

/// Find rnpm binary path.
pub fn find_rnpm_execpath(custom: Option<&Path>) -> PathBuf {
    if let Some(p) = custom {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("npm_execpath") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm"))
}

/// Check if an environment variable key is sensitive and must be stripped before spawning child processes.
/// Rules from docs/lifecycle-contract.md Section 4.1:
/// 1. Strip all configuration keys containing: `_authToken`, `_password`, `_auth`, `password`, `token`
/// 2. Strip URI-scoped auth tokens: `//registry.npmjs.org/:_authToken`, `//npm.pkg.github.com/:_authToken`, `^//.*:_authToken$`
pub fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();

    // Check URI-scoped auth keys e.g. //registry.npmjs.org/:_authToken
    if lower.contains(":_authtoken") || lower.contains(":_auth") || lower.contains(":_password") {
        return true;
    }

    if lower.starts_with("//") && (lower.contains("authtoken") || lower.contains("auth") || lower.contains("token") || lower.contains("password")) {
        return true;
    }

    // Direct npm_config URI scoped representations
    if lower.starts_with("npm_config_//") {
        return true;
    }

    // Check sensitive substrings
    if lower.contains("_authtoken") || lower.contains("authtoken") {
        return true;
    }
    if lower.contains("_password") || lower.contains("password") {
        return true;
    }
    if lower.contains("_auth") {
        return true;
    }
    if lower.contains("token") {
        return true;
    }

    false
}

/// Sanitize user agent string to eliminate private tokens.
pub fn sanitize_user_agent(ua: &str) -> String {
    // If user agent has sensitive bearer or token info, strip it
    scrub_text(ua)
}

/// Redact sensitive tokens and passwords from stdout, stderr, or error traces.
/// Section 4.2: Logging & Error Scrubbing.
pub fn scrub_text(text: &str) -> String {
    let mut result = text.to_string();

    // 1. Redact Bearer tokens
    result = replace_bearer(&result);

    // 2. Redact npm tokens: npm_[A-Za-z0-9_-]{32,}
    result = replace_npm_tokens(&result);

    // 3. Redact :_authToken=<val> and other key-value credentials
    result = replace_kv_pairs(&result, "_authToken");
    result = replace_kv_pairs(&result, "_authtoken");
    result = replace_kv_pairs(&result, "password");
    result = replace_kv_pairs(&result, "token");

    result
}

fn replace_bearer(text: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices("bearer ") {
        if idx < last_idx {
            continue;
        }
        out.push_str(&text[last_idx..idx + 7]);
        let remainder = &text[idx + 7..];
        let end_token = remainder
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '\n')
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + 7 + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_npm_tokens(text: &str) -> String {
    let mut out = String::new();
    let mut last_idx = 0;

    for (idx, _) in text.match_indices("npm_") {
        if idx < last_idx {
            continue;
        }
        let remainder = &text[idx + 4..];
        let end_token = remainder
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(remainder.len());
        if end_token >= 32 {
            out.push_str(&text[last_idx..idx]);
            out.push_str("npm_[REDACTED]");
            last_idx = idx + 4 + end_token;
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_kv_pairs(text: &str, key_name: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let pattern = format!("{key_name}=");
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(&pattern) {
        if idx < last_idx {
            continue;
        }
        let key_len = pattern.len();
        out.push_str(&text[last_idx..idx + key_len]);
        let remainder = &text[idx + key_len..];
        let end_token = remainder
            .find(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '"' || c == '\'')
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + key_len + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

/// Scrub an environment map by stripping sensitive keys and sanitizing user agent.
pub fn scrub_credentials_env(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut clean_env = BTreeMap::new();

    for (key, val) in env {
        if is_sensitive_key(key) {
            continue;
        }
        if key.eq_ignore_ascii_case("npm_config_user_agent") {
            clean_env.insert(key.clone(), sanitize_user_agent(val));
        } else {
            clean_env.insert(key.clone(), val.clone());
        }
    }

    clean_env
}

/// Build the full execution environment for running a lifecycle script.
pub fn build_lifecycle_env(
    package_dir: &Path,
    manifest: &Manifest,
    event: &str,
    script: &str,
    options: &LifecycleOptions,
) -> BTreeMap<String, String> {
    // 1. Inherit parent environment, scrubbed of all credentials
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    env = scrub_credentials_env(&env);

    // 2. Add npm_config_* entries from options.config_env, scrubbed
    for (k, v) in &options.config_env {
        let key = if k.starts_with("npm_config_") {
            k.to_ascii_lowercase()
        } else {
            format!("npm_config_{}", k.replace('-', "_").to_ascii_lowercase())
        };

        if !is_sensitive_key(&key) {
            if key == "npm_config_user_agent" {
                env.insert(key, sanitize_user_agent(v));
            } else {
                env.insert(key, v.clone());
            }
        }
    }

    // Default user agent if not provided
    env.entry("npm_config_user_agent".to_string()).or_insert_with(|| {
        format!(
            "rnpm/{} node/{} {} {}",
            env!("CARGO_PKG_VERSION"),
            find_node_version(),
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    });

    // 3. INIT_CWD
    let init_cwd = options
        .init_cwd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| package_dir.to_path_buf());
    env.insert("INIT_CWD".to_string(), init_cwd.to_string_lossy().to_string());

    // 4. NODE and npm_node_execpath
    let node_path = find_node_execpath(options.node_path.as_deref());
    let node_str = node_path.to_string_lossy().to_string();
    env.insert("NODE".to_string(), node_str.clone());
    env.insert("npm_node_execpath".to_string(), node_str);

    // 5. npm_execpath
    let rnpm_path = find_rnpm_execpath(options.rnpm_path.as_deref());
    env.insert("npm_execpath".to_string(), rnpm_path.to_string_lossy().to_string());

    // 6. npm_lifecycle_event and npm_lifecycle_script
    env.insert("npm_lifecycle_event".to_string(), event.to_string());
    env.insert("npm_lifecycle_script".to_string(), script.to_string());

    // 7. npm_package_name and npm_package_version
    if let Some(ref name) = manifest.name {
        env.insert("npm_package_name".to_string(), name.clone());
    }
    if let Some(ref version) = manifest.version {
        env.insert("npm_package_version".to_string(), version.clone());
    }

    // 8. npm_package_json
    let pkg_json_path = package_dir.join("package.json");
    env.insert("npm_package_json".to_string(), pkg_json_path.to_string_lossy().to_string());

    // 9. Reconstruct hierarchical PATH
    let hierarchical_path = construct_path(package_dir, options.workspace_root.as_deref(), options.node_path.as_deref());
    let path_str = hierarchical_path.to_string_lossy().to_string();
    env.insert("PATH".to_string(), path_str.clone());
    #[cfg(windows)]
    {
        env.insert("Path".to_string(), path_str);
    }

    env
}

fn find_node_version() -> String {
    // Return a default version string or attempt to detect
    "v20.0.0".to_string()
}
