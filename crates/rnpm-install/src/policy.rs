//! npm's install-time source and script policies.
//!
//! * `allow-git`, `allow-remote`, `allow-registry`, `allow-file` and
//!   `allow-directory` (pacote's `canUse`): `all`, `root` or `none`.
//! * `allowScripts` (package.json) / `allow-scripts` (.npmrc), plus
//!   `--strict-allow-scripts` and `--dangerously-allow-all-scripts`
//!   (arborist's script-allowed.js, install-scripts.js and
//!   unreviewed-scripts.js).

use anyhow::{anyhow, Result};
use rnpm_core::manifest::Manifest;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::HashSet;
use std::path::Path;

#[path = "allow_scripts.rs"]
pub mod allow_scripts;
pub use allow_scripts::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllowMode {
    #[default]
    All,
    Root,
    None,
}

impl AllowMode {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("none" | "false" | "0") => AllowMode::None,
            Some("root") => AllowMode::Root,
            _ => AllowMode::All,
        }
    }
}

/// Which dependency sources may be fetched.
#[derive(Debug, Clone, Default)]
pub struct SourcePolicy {
    pub git: AllowMode,
    pub remote: AllowMode,
    pub registry: AllowMode,
    pub file: AllowMode,
    pub directory: AllowMode,
}

impl SourcePolicy {
    pub fn from_config(config: &rnpm_config::Config) -> Self {
        Self {
            git: AllowMode::parse(config.get("allow-git")),
            remote: AllowMode::parse(config.get("allow-remote")),
            registry: AllowMode::parse(config.get("allow-registry")),
            file: AllowMode::parse(config.get("allow-file")),
            directory: AllowMode::parse(config.get("allow-directory")),
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        [
            self.git,
            self.remote,
            self.registry,
            self.file,
            self.directory,
        ]
        .iter()
        .all(|m| *m == AllowMode::All)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Git,
    Remote,
    Registry,
    File,
    Directory,
}

impl SourceKind {
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Git => "git",
            SourceKind::Remote => "remote",
            SourceKind::Registry => "registry",
            SourceKind::File => "file",
            SourceKind::Directory => "directory",
        }
    }
}

pub fn is_registry_tarball(resolved: &str) -> bool {
    let resolved = resolved.trim();
    let rest = if resolved.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://")) {
        &resolved[8..]
    } else if resolved.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://")) {
        &resolved[7..]
    } else {
        return false;
    };
    let Some((_host, path)) = rest.split_once('/') else {
        return false;
    };
    let Some(idx) = path.find("/-/") else {
        return false;
    };
    if idx == 0 {
        return false;
    }
    let before = &path[..idx];
    let name_part = before
        .replace("%2f", "/")
        .replace("%2F", "/")
        .replace("%40", "@");
    let segs: Vec<&str> = name_part.split('/').filter(|s| !s.is_empty()).collect();
    let name = match segs.as_slice() {
        [.., scope, n] if scope.starts_with('@') => format!("{scope}/{n}"),
        [.., n] => (*n).to_string(),
        [] => return false,
    };
    let unscoped = name.rsplit('/').next().unwrap_or(&name);
    let file = path[idx + 3..].split(['?', '#']).next().unwrap_or("");
    if !file.ends_with(".tgz") {
        return false;
    }
    let Some(file_without_tgz) = file.strip_suffix(".tgz") else {
        return false;
    };
    let prefix = format!("{unscoped}-");
    let Some(ver) = file_without_tgz.strip_prefix(&prefix) else {
        return false;
    };
    let first_char = ver.chars().next();
    first_char.is_some_and(|c| {
        c.is_ascii_digit()
            || (c == 'v'
                && ver
                    .strip_prefix('v')
                    .and_then(|v| v.chars().next())
                    .is_some_and(|d| d.is_ascii_digit()))
    })
}

pub(crate) fn is_git_spec(spec: &str) -> bool {
    let spec = spec.trim();
    let lower = spec.to_ascii_lowercase();
    if [
        "git+",
        "git://",
        "git@",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
    {
        return true;
    }
    if lower.ends_with(".git") || lower.contains(".git#") {
        return true;
    }
    for host in [
        "https://github.com/",
        "http://github.com/",
        "https://gitlab.com/",
        "http://gitlab.com/",
        "https://bitbucket.org/",
        "http://bitbucket.org/",
        "https://gist.github.com/",
        "http://gist.github.com/",
    ] {
        if let Some(path) = lower.strip_prefix(host) {
            let base = path.split_once('#').map(|(b, _)| b).unwrap_or(path);
            if !base.ends_with(".tgz")
                && !base.ends_with(".tar.gz")
                && !base.ends_with(".tar")
                && !base.contains("/archive/")
                && !base.contains("/releases/download/")
            {
                return true;
            }
        }
    }
    // GitHub shortcut: "user/repo" or "user/repo#committish"
    if !spec.starts_with('@')
        && !spec.starts_with('.')
        && !spec.starts_with('/')
        && !spec.starts_with('\\')
        && !spec.starts_with('~')
        && !(spec.len() >= 2 && spec.as_bytes()[1] == b':' && spec.as_bytes()[0].is_ascii_alphabetic())
    {
        let base = spec.split_once('#').map(|(b, _)| b).unwrap_or(spec);
        if let Some((user, repo)) = base.split_once('/') {
            if !user.is_empty()
                && !repo.is_empty()
                && !repo.contains('/')
                && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && repo.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return true;
            }
        }
    }
    false
}

/// Unpack potentially nested `npm:` aliases safely, returning the underlying spec
/// or `""` if bare alias with no target spec.
pub fn unpack_alias(mut spec: &str) -> &str {
    loop {
        let trimmed = spec.trim();
        let Some(rest) = (if trimmed.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("npm:")) {
            Some(&trimmed[4..])
        } else {
            None
        }) else {
            return trimmed;
        };
        let sub = rest.trim();
        let extracted = if sub.starts_with('@') {
            if let Some(slash_idx) = sub.find('/') {
                if let Some(at_idx) = sub[slash_idx + 1..].find('@') {
                    sub[slash_idx + 1 + at_idx + 1..].trim()
                } else {
                    ""
                }
            } else {
                ""
            }
        } else if let Some(at_idx) = sub.find('@') {
            sub[at_idx + 1..].trim()
        } else {
            ""
        };
        if extracted.is_empty() {
            return "";
        }
        spec = extracted;
    }
}

/// Classify a dependency spec string into its `SourceKind`.
pub fn parse_source_kind(spec: &str) -> SourceKind {
    let spec = unpack_alias(spec);

    if spec.is_empty() {
        return SourceKind::Registry;
    }

    if is_git_spec(spec) {
        return SourceKind::Git;
    }
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return SourceKind::Remote;
    }
    if lower.starts_with("file:") {
        let path = spec[5..].trim();
        let lower_path = path.to_ascii_lowercase();
        return if lower_path.ends_with(".tgz")
            || lower_path.ends_with(".tar.gz")
            || lower_path.ends_with(".tar")
        {
            SourceKind::File
        } else {
            SourceKind::Directory
        };
    }
    if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".tar") {
        return SourceKind::File;
    }
    if spec.starts_with("./")
        || spec.starts_with(".\\")
        || spec.starts_with("../")
        || spec.starts_with("..\\")
        || spec.starts_with('/')
        || spec.starts_with('\\')
        || spec.starts_with("~/")
        || spec.starts_with("~\\")
        || (spec.len() >= 2 && spec.as_bytes()[1] == b':' && spec.as_bytes()[0].is_ascii_alphabetic())
    {
        return SourceKind::Directory;
    }
    SourceKind::Registry
}

fn classify(pkg: &LockfilePackage) -> SourceKind {
    let resolved = pkg.resolved.as_deref().unwrap_or("").trim();
    if pkg.link == Some(true) {
        return SourceKind::Directory;
    }
    let lower = resolved.to_ascii_lowercase();
    if lower.starts_with("file:") {
        let path = resolved[5..].trim();
        let lower_path = path.to_ascii_lowercase();
        return if lower_path.ends_with(".tgz")
            || lower_path.ends_with(".tar.gz")
            || lower_path.ends_with(".tar")
        {
            SourceKind::File
        } else {
            SourceKind::Directory
        };
    }
    if is_git_spec(resolved) {
        return SourceKind::Git;
    }
    if (lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".tar"))
        && !lower.starts_with("http://")
        && !lower.starts_with("https://")
    {
        return SourceKind::File;
    }
    if lower.starts_with("./")
        || lower.starts_with(".\\")
        || lower.starts_with("../")
        || lower.starts_with("..\\")
        || lower.starts_with('/')
        || lower.starts_with('\\')
        || lower.starts_with('~')
        || (resolved.len() >= 2
            && resolved.as_bytes()[1] == b':'
            && resolved.as_bytes()[0].is_ascii_alphabetic())
    {
        return SourceKind::Directory;
    }
    if resolved.is_empty() || is_registry_tarball(resolved) {
        return SourceKind::Registry;
    }
    SourceKind::Remote
}

fn split_parent_and_name(location: &str) -> Option<(&str, &str)> {
    let loc = location.trim_matches('/');
    if let Some(idx) = loc.rfind("/node_modules/") {
        let parent = &loc[..idx];
        let name = &loc[idx + "/node_modules/".len()..];
        if !name.contains("/node_modules/") {
            return Some((parent, name));
        }
    } else if let Some(name) = loc.strip_prefix("node_modules/") {
        if !name.contains("/node_modules/") {
            return Some(("", name));
        }
    }
    None
}

fn is_declared_root_spec(spec: &str, kind: SourceKind, root_declared: &HashSet<String>) -> bool {
    let extracted = unpack_alias(spec);
    let norm_spec = spec.replace('\\', "/");
    let norm_extracted = extracted.replace('\\', "/");
    if root_declared.contains(spec)
        || root_declared.contains(extracted)
        || root_declared.contains(&norm_spec)
        || root_declared.contains(&norm_extracted)
    {
        return true;
    }
    if kind == SourceKind::Git {
        if let Some((spec_repo, spec_ref)) = git_identity(spec) {
            let matched = root_declared.iter().any(|d| {
                if let Some((d_repo, d_ref)) = git_identity(d) {
                    if d_repo.eq_ignore_ascii_case(&spec_repo) {
                        return d_ref.is_empty() || d_ref == spec_ref;
                    }
                }
                false
            });
            if matched {
                return true;
            }
        }
    }
    root_declared.iter().any(|d| {
        let d_unpacked = unpack_alias(d);
        let d_norm = d.replace('\\', "/");
        let d_unpacked_norm = d_unpacked.replace('\\', "/");
        d == spec
            || d == extracted
            || d_norm == norm_spec
            || d_unpacked_norm == norm_extracted
            || d_unpacked == extracted
    })
}

fn is_direct_root_dep(
    location: &str,
    packages: &std::collections::BTreeMap<String, LockfilePackage>,
    workspace_paths: &HashSet<String>,
    root_declared: &HashSet<String>,
    kind: SourceKind,
) -> bool {
    let location_norm = location.replace('\\', "/");
    let Some((parent, name)) = split_parent_and_name(&location_norm) else {
        return false;
    };
    let is_root_or_ws = parent.is_empty() || workspace_paths.contains(parent);
    if !is_root_or_ws {
        return false;
    }
    let check_pkg = |pkg: &LockfilePackage| -> bool {
        for map in [
            &pkg.dependencies,
            &pkg.dev_dependencies,
            &pkg.optional_dependencies,
            &pkg.peer_dependencies,
        ]
        .into_iter()
        .flatten()
        {
            if let Some(spec) = map.get(name) {
                let spec_kind = parse_source_kind(spec);
                if spec_kind == kind {
                    if kind != SourceKind::Registry && !is_declared_root_spec(spec, kind, root_declared) {
                        return false;
                    }
                    return true;
                }
            }
        }
        false
    };

    let get_pkg = |loc: &str| -> Option<&LockfilePackage> {
        packages.get(loc).or_else(|| {
            packages.iter().find_map(|(k, v)| {
                if k.replace('\\', "/") == loc {
                    Some(v)
                } else {
                    None
                }
            })
        })
    };

    if parent.is_empty() {
        if let Some(root_pkg) = get_pkg("") {
            if check_pkg(root_pkg) {
                return true;
            }
        }
        for ws in workspace_paths {
            if let Some(ws_pkg) = get_pkg(ws) {
                if check_pkg(ws_pkg) {
                    return true;
                }
            }
        }
    } else if let Some(parent_pkg) = get_pkg(parent) {
        if check_pkg(parent_pkg) {
            return true;
        }
    }
    false
}

/// Reject a single dependency source if disabled by `allow-*` source policy.
///
/// `is_root` is true if the package is declared directly by the root project,
/// workspaces, or explicit command-line package arguments.
pub fn check_source_gate(
    policy: &SourcePolicy,
    kind: SourceKind,
    is_root: bool,
) -> Result<()> {
    if policy.is_unrestricted() {
        return Ok(());
    }
    let mode = match kind {
        SourceKind::Git => policy.git,
        SourceKind::Remote => policy.remote,
        SourceKind::Registry => policy.registry,
        SourceKind::File => policy.file,
        SourceKind::Directory => policy.directory,
    };
    let allowed = match mode {
        AllowMode::All => true,
        AllowMode::Root => is_root,
        AllowMode::None => false,
    };
    if !allowed {
        let qualifier = if mode == AllowMode::Root {
            " non-root"
        } else {
            ""
        };
        return Err(anyhow!(
            "npm error code EALLOW{}\nnpm error Fetching{qualifier} packages of type \"{}\" have been disabled",
            kind.label().to_ascii_uppercase(),
            kind.label()
        ));
    }
    Ok(())
}

/// Reject sources disabled by `allow-*`, as pacote does while fetching.
/// `root_declared` holds the dependency names the project root and its
/// workspaces declare; `workspace_paths` are workspace member locations.
pub fn check_sources(
    lockfile: &LockfileV3,
    root_declared: &HashSet<String>,
    workspace_paths: &HashSet<String>,
    policy: &SourcePolicy,
) -> Result<()> {
    check_sources_with_root_context(lockfile, root_declared, workspace_paths, policy, false)
}

/// Reject sources disabled by `allow-*`, with optional forced non-root context
/// (e.g. for staging dependency preparation of git dependencies).
pub fn check_sources_with_root_context(
    lockfile: &LockfileV3,
    root_declared: &HashSet<String>,
    workspace_paths: &HashSet<String>,
    policy: &SourcePolicy,
    force_non_root: bool,
) -> Result<()> {
    if policy.is_unrestricted() {
        return Ok(());
    }

    let norm_workspace_paths: HashSet<String> =
        workspace_paths.iter().map(|p| p.replace('\\', "/")).collect();

    // 1. Collect all explicit remote URLs from root_declared and lockfile specs.
    let mut explicit_remote_specs = HashSet::new();
    let mut add_remote_spec = |spec: &str| {
        let extracted = unpack_alias(spec);
        let lower = extracted.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            explicit_remote_specs.insert(extracted.to_string());
            explicit_remote_specs.insert(lower.clone());
            if let Some((base, _)) = extracted.split_once('#') {
                explicit_remote_specs.insert(base.to_string());
                explicit_remote_specs.insert(base.to_ascii_lowercase());
            }
        }
    };

    if !force_non_root {
        for item in root_declared {
            add_remote_spec(item);
        }
    }
    for pkg in lockfile.packages.values() {
        for map in [
            &pkg.dependencies,
            &pkg.dev_dependencies,
            &pkg.optional_dependencies,
            &pkg.peer_dependencies,
        ]
        .into_iter()
        .flatten()
        {
            for spec in map.values() {
                add_remote_spec(spec);
            }
        }
    }

    // 2. Gate every original dependency edge by (parsed_source_kind, is_actual_root_or_workspace_edge).
    for (requester_loc, pkg) in &lockfile.packages {
        let norm_req = requester_loc.replace('\\', "/");
        let is_root_edge = if force_non_root {
            false
        } else {
            norm_req.is_empty() || norm_workspace_paths.contains(&norm_req)
        };
        for map in [
            &pkg.dependencies,
            &pkg.dev_dependencies,
            &pkg.optional_dependencies,
            &pkg.peer_dependencies,
        ]
        .into_iter()
        .flatten()
        {
            for spec in map.values() {
                let kind = parse_source_kind(spec);
                let actual_root = is_root_edge
                    && (kind == SourceKind::Registry
                        || is_declared_root_spec(spec, kind, root_declared));
                check_source_gate(policy, kind, actual_root)?;
            }
        }

        // Gate overrides in pkg.extra if present
        if let Some(overrides) = pkg.extra.get("overrides") {
            fn check_overrides_recursive(
                val: &serde_json::Value,
                policy: &SourcePolicy,
                is_root_edge: bool,
            ) -> Result<()> {
                match val {
                    serde_json::Value::String(spec) => {
                        if !spec.starts_with('$') {
                            let kind = parse_source_kind(spec);
                            check_source_gate(policy, kind, is_root_edge)?;
                        }
                    }
                    serde_json::Value::Object(map) => {
                        for v in map.values() {
                            check_overrides_recursive(v, policy, false)?;
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        for v in arr {
                            check_overrides_recursive(v, policy, is_root_edge)?;
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
            check_overrides_recursive(overrides, policy, is_root_edge)?;
        }
    }

    // 3. Gate every placed package node in lockfile.packages.
    for (location, pkg) in &lockfile.packages {
        let norm_loc = location.replace('\\', "/");
        if norm_loc.is_empty() {
            continue;
        }
        if pkg.link == Some(true)
            && pkg
                .resolved
                .as_deref()
                .is_some_and(|target| norm_workspace_paths.contains(&target.replace('\\', "/")))
        {
            continue;
        }
        let is_explicit_remote = pkg
            .resolved
            .as_deref()
            .map(|r| r.trim())
            .is_some_and(|r| {
                explicit_remote_specs.contains(r)
                    || explicit_remote_specs.contains(&r.to_ascii_lowercase())
            });
        let kind = if is_explicit_remote {
            SourceKind::Remote
        } else {
            classify(pkg)
        };
        let is_root = if force_non_root {
            false
        } else if norm_workspace_paths.contains(&norm_loc) {
            true
        } else {
            is_direct_root_dep(&norm_loc, &lockfile.packages, &norm_workspace_paths, root_declared, kind)
        };
        check_source_gate(policy, kind, is_root)?;
    }
    Ok(())
}

// -------------------------------------------------------------------------
// engines (npm-install-checks checkEngine)
// -------------------------------------------------------------------------

fn js_inspect_str(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', "\\'"))
    }
}

fn js_inspect_map(map: &[(String, String)]) -> String {
    let body = map
        .iter()
        .map(|(k, v)| {
            let key = if k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                k.clone()
            } else {
                js_inspect_str(k)
            };
            format!("{key}: {}", js_inspect_str(v))
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {body} }}")
}

fn js_inspect_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => js_inspect_str(s),
        serde_json::Value::Array(items) if items.is_empty() => "[]".into(),
        serde_json::Value::Array(items) => {
            format!(
                "[ {} ]",
                items
                    .iter()
                    .map(js_inspect_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        serde_json::Value::Object(map) if map.is_empty() => "{}".into(),
        serde_json::Value::Object(map) => {
            let body = map
                .iter()
                .map(|(k, v)| {
                    let key = if k
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                    {
                        k.clone()
                    } else {
                        js_inspect_str(k)
                    };
                    format!("{key}: {}", js_inspect_value(v))
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {body} }}")
        }
        other => other.to_string(),
    }
}

/// npm-install-checks' libc family on Linux: read from `/usr/bin/ldd`.
fn linux_libc_family() -> Option<String> {
    let ldd = std::fs::read_to_string("/usr/bin/ldd").ok()?;
    if ldd.contains("musl") {
        Some("musl".into())
    } else if ldd.contains("GNU C Library") {
        Some("glibc".into())
    } else {
        None
    }
}

/// node's `os.release()`: the kernel release, or `major.minor.build` on Windows.
fn os_release() -> Option<String> {
    let out = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()?
    } else {
        std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()?
    };
    let text = String::from_utf8_lossy(&out.stdout);
    if cfg!(windows) {
        let start = text.find(|c: char| c.is_ascii_digit())?;
        let ver: String = text[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        Some(ver.split('.').take(3).collect::<Vec<_>>().join("."))
    } else {
        Some(text.trim().to_string())
    }
}

/// npm-install-checks `checkDevEngines`, as npm runs it before arborist
/// commands and `run`: an unmatched `devEngines` entry fails with
/// EBADDEVENGINES (or warns with `onFail: "warn"`, or under `--force`).
pub fn check_dev_engines(project_dir: &Path, force: bool) -> Result<()> {
    let Some(dev_engines) = std::fs::read_to_string(project_dir.join("package.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|pkg| pkg.get("devEngines").cloned())
    else {
        return Ok(());
    };
    let Some(wanted) = dev_engines.as_object() else {
        return Err(anyhow!(
            "npm error Invalid non-object value for \"devEngines\""
        ));
    };

    let node_version = rnpm_lifecycle::node_version();
    let node_version = if node_version.starts_with('v') {
        node_version
    } else {
        format!("v{node_version}")
    };
    let os_name = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };
    let cpu_name = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "x86" => "ia32",
        "aarch64" => "arm64",
        other => other,
    };
    let current_for = |engine: &str| -> Vec<(&'static str, Option<String>)> {
        match engine {
            "packageManager" => vec![
                ("name", Some("npm".into())),
                ("version", Some(rnpm_lifecycle::NPM_VERSION.into())),
            ],
            "runtime" => vec![
                ("name", Some("node".into())),
                ("version", Some(node_version.clone())),
            ],
            "os" => vec![("name", Some(os_name.into())), ("version", os_release())],
            "cpu" => vec![("name", Some(cpu_name.into()))],
            _ => vec![("name", linux_libc_family().filter(|_| os_name == "linux"))],
        }
    };

    struct Failure {
        message: String,
        errors: Vec<String>,
        is_warn: bool,
        current: String,
        required: String,
    }
    let mut failures = Vec::new();
    for (engine, authored) in wanted {
        if !["packageManager", "runtime", "cpu", "libc", "os"].contains(&engine.as_str()) {
            return Err(anyhow!(
                "npm error Invalid property \"devEngines.{engine}\""
            ));
        }
        let deps: Vec<&serde_json::Value> = match authored {
            serde_json::Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        if deps.is_empty() {
            continue;
        }
        let current = current_for(engine);
        let current_name = current[0].1.clone();
        let current_version = current.get(1).and_then(|(_, v)| v.clone());
        let mut dep_errors = Vec::new();
        for dep in &deps {
            let Some(dep) = dep.as_object() else {
                return Err(anyhow!(
                    "npm error Invalid non-object value for \"{engine}\""
                ));
            };
            if let Some(prop) = dep
                .keys()
                .find(|k| !["name", "version", "onFail"].contains(&k.as_str()))
            {
                return Err(anyhow!(
                    "npm error Invalid property \"{prop}\" for \"{engine}\""
                ));
            }
            let Some(name) = dep.get("name") else {
                return Err(anyhow!(
                    "npm error Missing \"name\" property for \"{engine}\""
                ));
            };
            let Some(name) = name.as_str() else {
                return Err(anyhow!(
                    "npm error Invalid non-string value for \"name\" within \"{engine}\""
                ));
            };
            let Some(current_name) = current_name.as_deref() else {
                return Err(anyhow!(
                    "npm error Unable to determine \"name\" for \"{engine}\""
                ));
            };
            if let Some(on_fail) = dep.get("onFail") {
                match on_fail.as_str() {
                    Some("ignore" | "warn" | "error" | "download") => {}
                    Some(other) => {
                        return Err(anyhow!(
                            "npm error Invalid onFail value \"{other}\" for \"{engine}\""
                        ))
                    }
                    None => {
                        return Err(anyhow!(
                            "npm error Invalid non-string value for \"onFail\" within \"{engine}\""
                        ))
                    }
                }
            }
            if name != current_name {
                dep_errors.push(format!(
                    "Invalid name \"{name}\" does not match \"{current_name}\" for \"{engine}\""
                ));
                continue;
            }
            if let Some(version) = dep.get("version") {
                let Some(version) = version.as_str() else {
                    return Err(anyhow!(
                        "npm error Invalid non-string value for \"version\" within \"{engine}\""
                    ));
                };
                let Some(current_version) = current_version.as_deref() else {
                    continue;
                };
                let parsed =
                    rnpm_core::semver::Version::parse(current_version.trim_start_matches('v')).ok();
                match rnpm_core::semver::Range::parse(version) {
                    Ok(range) => {
                        if !parsed.is_some_and(|v| range.satisfies(&v)) {
                            dep_errors.push(format!("Invalid semver version \"{version}\" does not match \"{current_version}\" for \"{engine}\""));
                        }
                    }
                    Err(_) if version != current_version => {
                        dep_errors.push(format!("Invalid version \"{version}\" does not match \"{current_version}\" for \"{engine}\""));
                    }
                    Err(_) => {}
                }
            }
        }
        if dep_errors.len() == deps.len() {
            let on_fail = deps
                .last()
                .and_then(|d| d.get("onFail"))
                .and_then(|v| v.as_str())
                .unwrap_or("error");
            if on_fail == "ignore" {
                continue;
            }
            let current = serde_json::Value::Object(
                current
                    .into_iter()
                    .filter_map(|(k, v)| v.map(|v| (k.to_string(), serde_json::Value::String(v))))
                    .collect(),
            );
            failures.push(Failure {
                message: format!("Invalid devEngines.{engine}"),
                errors: dep_errors,
                is_warn: on_fail == "warn",
                current: js_inspect_value(&current),
                required: js_inspect_value(authored),
            });
        }
    }

    let render = |failure: &Failure, first: bool, prefix: &str| -> String {
        let mut lines = Vec::new();
        if first {
            lines.push(
                "The developer of this package has specified the following through devEngines"
                    .to_string(),
            );
        }
        lines.push(failure.message.clone());
        lines.extend(failure.errors.iter().cloned());
        lines.push("{".into());
        lines.push(format!("  current: {},", failure.current));
        lines.push(format!("  required: {}", failure.required));
        lines.push("}".into());
        lines
            .iter()
            .map(|l| format!("{prefix}{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let (errors, warnings): (Vec<_>, Vec<_>) = failures.into_iter().partition(|f| !f.is_warn);
    let shown: Vec<&Failure> = warnings
        .iter()
        .chain(errors.iter().filter(|_| force))
        .collect();
    for (i, failure) in shown.iter().enumerate() {
        eprintln!("{}", render(failure, i == 0, "npm warn EBADDEVENGINES "));
    }
    if !force {
        if let Some(failure) = errors.first() {
            return Err(anyhow!(
                "npm error code EBADDEVENGINES\n{}",
                render(failure, true, "npm error EBADDEVENGINES ")
            ));
        }
    }
    Ok(())
}

/// Check every resolved package's `engines` against the running node/npm.
/// Mismatches warn like npm; with `engine-strict` (and no `--force`) the
/// first one fails with EBADENGINE before anything is installed.
pub fn check_engines(
    lockfile: &LockfileV3,
    base_dir: &Path,
    strict: bool,
    silent: bool,
    platform: &rnpm_solver::Platform,
) -> Result<()> {
    let node_version = rnpm_lifecycle::node_version();
    let npm_version = rnpm_lifecycle::NPM_VERSION;
    let node_semver = rnpm_core::semver::Version::parse(node_version.trim_start_matches('v')).ok();
    let npm_semver = rnpm_core::semver::Version::parse(npm_version).ok();
    let fails = |range: Option<&String>, version: Option<&rnpm_core::semver::Version>| match (
        range, version,
    ) {
        (Some(range), Some(version)) => rnpm_core::semver::Range::parse(range)
            .map(|r| !r.satisfies(version))
            .unwrap_or(false),
        _ => false,
    };
    let skipped = crate::lockfile_platform_skipped_packages(lockfile, platform);
    for (location, pkg) in &lockfile.packages {
        if location.is_empty() || skipped.contains(location) {
            continue;
        }
        let disk_dir = if pkg.link == Some(true) {
            pkg.resolved.as_deref().map(|t| base_dir.join(t))
        } else if !location.contains("node_modules/") {
            Some(base_dir.join(location))
        } else {
            None
        };
        let disk = disk_dir.and_then(|d| Manifest::from_file(d.join("package.json")).ok());
        let engines: Vec<(String, String)> = match &disk {
            Some(m) => m
                .engines
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            None => pkg
                .engines
                .as_ref()
                .and_then(|e| e.as_map())
                .map(|m| m.into_iter().collect())
                .unwrap_or_default(),
        };
        if engines.is_empty() {
            continue;
        }
        let get = |k: &str| engines.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        if !fails(get("node"), node_semver.as_ref()) && !fails(get("npm"), npm_semver.as_ref()) {
            continue;
        }
        let name = disk
            .as_ref()
            .and_then(|m| m.name.clone())
            .or_else(|| pkg.name.clone())
            .or_else(|| top_level_or_nested_name(location))
            .unwrap_or_default();
        let version = disk
            .as_ref()
            .and_then(|m| m.version.clone())
            .or_else(|| pkg.version.clone())
            .unwrap_or_default();
        let pkgid = format!("{name}@{version}");
        let current = vec![
            ("node".to_string(), node_version.clone()),
            ("npm".to_string(), npm_version.to_string()),
        ];
        if strict {
            let json_map = |m: &[(String, String)]| {
                let obj: serde_json::Map<String, serde_json::Value> = m
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                serde_json::Value::Object(obj).to_string()
            };
            return Err(anyhow!(
                "npm error code EBADENGINE\nnpm error engine Unsupported engine\nnpm error engine Not compatible with your version of node/npm: {pkgid}\nnpm error notsup Not compatible with your version of node/npm: {pkgid}\nnpm error notsup Required: {}\nnpm error notsup Actual:   {}",
                json_map(&engines),
                json_map(&current)
            ));
        }
        let is_directory_dep = pkg.link == Some(true)
            || pkg.resolved.as_deref().is_some_and(|r| {
                r.strip_prefix("file:")
                    .is_some_and(|p| base_dir.join(p).is_dir())
            });
        for _ in 0..if is_directory_dep { 2 } else { 1 } {
            if !silent {
                eprintln!(
                    "npm warn EBADENGINE Unsupported engine {{\nnpm warn EBADENGINE   package: {},\nnpm warn EBADENGINE   required: {},\nnpm warn EBADENGINE   current: {}\nnpm warn EBADENGINE }}",
                    js_inspect_str(&pkgid),
                    js_inspect_map(&engines),
                    js_inspect_map(&current)
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_node<'a>(resolved: &'a str, dir: &'a Path) -> ScriptNode<'a> {
        ScriptNode {
            location: "node_modules/dep",
            resolved: Some(resolved),
            lock_name: None,
            in_bundle: false,
            link: false,
            project_dir: dir,
        }
    }

    fn policy(entries: &[(&str, bool)]) -> ScriptPolicy {
        let mut p = ScriptPolicy::default();
        p.entries = p.validate(
            entries.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            "package.json",
        );
        p
    }

    #[test]
    fn registry_identity_comes_from_the_tarball_url() {
        let dir = Path::new(".");
        let node = registry_node("https://registry.npmjs.org/@s/dep/-/dep-1.2.3.tgz", dir);
        assert_eq!(
            node.registry_identity(),
            Some(("@s/dep".to_string(), Some("1.2.3".to_string())))
        );
    }

    #[test]
    fn deny_wins_and_exact_versions_match() {
        let dir = Path::new(".");
        let node = registry_node("https://registry.npmjs.org/dep/-/dep-1.0.0.tgz", dir);
        assert_eq!(policy(&[("dep", true)]).verdict(&node), Some(true));
        assert_eq!(
            policy(&[("dep", true), ("dep@1.0.0", false)]).verdict(&node),
            Some(false)
        );
        assert_eq!(
            policy(&[("dep@1.0.0 || 2.0.0", true)]).verdict(&node),
            Some(true)
        );
        assert_eq!(policy(&[("dep@2.0.0", true)]).verdict(&node), None);
        assert_eq!(policy(&[("other", true)]).verdict(&node), None);
    }

    #[test]
    fn ranges_and_tags_are_dropped_with_warnings() {
        let p = policy(&[("dep@^1.0.0", true), ("dep@latest", true)]);
        assert!(p.entries.is_none());
        assert_eq!(p.warnings.len(), 2);
    }

    #[test]
    fn aliases_and_bundled_never_match() {
        let dir = Path::new(".");
        let node = registry_node("https://registry.npmjs.org/dep/-/dep-1.0.0.tgz", dir);
        assert_eq!(policy(&[("dep@npm:dep@1.0.0", true)]).verdict(&node), None);
        let bundled = ScriptNode {
            in_bundle: true,
            ..node
        };
        assert_eq!(policy(&[("dep", true)]).verdict(&bundled), None);
    }

    #[test]
    fn registry_url_shape_matches_arborist() {
        assert!(is_registry_tarball(
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
        ));
        assert!(is_registry_tarball(
            "Https://registry.npmjs.org/a/-/a-1.0.0.tgz"
        ));
        assert!(is_registry_tarball(
            "Http://registry.npmjs.org/a/-/a-1.0.0.tgz"
        ));
        assert!(is_registry_tarball(
            "https://registry.npmjs.org/%40scope%2Fpkg/-/pkg-1.0.0.tgz"
        ));
        assert!(!is_registry_tarball("https://evil.com/-/a-1.0.0.tgz"));
        assert!(!is_registry_tarball("https://example.com/a.tgz"));
        assert!(!is_registry_tarball("https://evil.com/downloads/-/payload-1.0.0.tgz"));
    }

    #[test]
    fn hoisted_workspace_dep_allowed_under_allow_root_while_transitive_fails() {
        use rnpm_lockfile::{LockfilePackage, LockfileV3};
        use std::collections::{BTreeMap, HashSet};

        let mut workspace_paths = HashSet::new();
        workspace_paths.insert("packages/a".to_string());

        let mut root_declared = HashSet::new();
        root_declared.insert("workspace-a".to_string());
        root_declared.insert("packages/a".to_string());
        root_declared.insert("direct-remote".to_string());
        root_declared.insert("http://example.com/direct-remote.tgz".to_string());

        let mut packages = BTreeMap::new();

        // 1. Root package
        let mut root_deps = BTreeMap::new();
        root_deps.insert("workspace-a".to_string(), "file:packages/a".to_string());
        packages.insert(
            String::new(),
            LockfilePackage {
                dependencies: Some(root_deps),
                ..Default::default()
            },
        );

        // 2. Workspace member packages/a
        let mut ws_deps = BTreeMap::new();
        ws_deps.insert(
            "direct-remote".to_string(),
            "http://example.com/direct-remote.tgz".to_string(),
        );
        ws_deps.insert(
            "transitive-holder".to_string(),
            "^1.0.0".to_string(),
        );
        packages.insert(
            "packages/a".to_string(),
            LockfilePackage {
                dependencies: Some(ws_deps),
                ..Default::default()
            },
        );

        // 3. Hoisted direct workspace dep at top-level node_modules/direct-remote
        packages.insert(
            "node_modules/direct-remote".to_string(),
            LockfilePackage {
                resolved: Some("http://example.com/direct-remote.tgz".to_string()),
                ..Default::default()
            },
        );

        // 4. Transitive holder at top-level node_modules/transitive-holder
        let mut holder_deps = BTreeMap::new();
        holder_deps.insert(
            "transitive-remote".to_string(),
            "http://example.com/transitive-remote.tgz".to_string(),
        );
        packages.insert(
            "node_modules/transitive-holder".to_string(),
            LockfilePackage {
                resolved: Some("https://registry.npmjs.org/transitive-holder/-/transitive-holder-1.0.0.tgz".to_string()),
                dependencies: Some(holder_deps),
                ..Default::default()
            },
        );

        // 5. Hoisted transitive remote at top-level node_modules/transitive-remote
        packages.insert(
            "node_modules/transitive-remote".to_string(),
            LockfilePackage {
                resolved: Some("http://example.com/transitive-remote.tgz".to_string()),
                ..Default::default()
            },
        );

        let lockfile = LockfileV3 {
            name: "test".to_string(),
            version: None,
            lockfile_version: 3,
            requires: None,
            packages,
        };

        let policy = SourcePolicy {
            remote: AllowMode::Root,
            ..Default::default()
        };

        // Must FAIL because node_modules/transitive-remote is a non-root transitive remote dep!
        let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
        assert!(res.is_err(), "Expected transitive remote dep to fail under allow-remote=root");
        let err = res.unwrap_err().to_string();
        assert!(err.contains("EALLOWREMOTE"), "Expected EALLOWREMOTE, got: {err}");
        assert!(err.contains("non-root"), "Expected non-root in error message, got: {err}");

        // Now remove the transitive remote package:
        let mut clean_packages = lockfile.packages.clone();
        clean_packages.remove("node_modules/transitive-remote");
        // Also remove from holder's deps so edge check passes
        if let Some(h) = clean_packages.get_mut("node_modules/transitive-holder") {
            h.dependencies = None;
        }
        let clean_lockfile = LockfileV3 {
            name: "test".to_string(),
            version: None,
            lockfile_version: 3,
            requires: None,
            packages: clean_packages,
        };

        // Must PASS: direct-remote hoisted to node_modules/direct-remote is declared by workspace packages/a!
        let clean_res = check_sources(&clean_lockfile, &root_declared, &workspace_paths, &policy);
        assert!(
            clean_res.is_ok(),
            "Hoisted workspace direct-remote dep must pass allow-remote=root, but failed: {:?}",
            clean_res.err()
        );
    }
}
