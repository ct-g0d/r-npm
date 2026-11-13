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
use rnpm_lifecycle::LifecyclePackageNode;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllowMode {
    #[default]
    All,
    Root,
    None,
}

impl AllowMode {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("none") => AllowMode::None,
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

    fn is_unrestricted(&self) -> bool {
        [self.git, self.remote, self.registry, self.file, self.directory]
            .iter()
            .all(|m| *m == AllowMode::All)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Git,
    Remote,
    Registry,
    File,
    Directory,
}

impl SourceKind {
    fn label(self) -> &'static str {
        match self {
            SourceKind::Git => "git",
            SourceKind::Remote => "remote",
            SourceKind::Registry => "registry",
            SourceKind::File => "file",
            SourceKind::Directory => "directory",
        }
    }
}

fn is_registry_tarball(resolved: &str) -> bool {
    // `<scheme>://<host>/<name>/-/<file>-<digit>...`, as arborist checks.
    let Some(rest) = resolved
        .strip_prefix("https://")
        .or_else(|| resolved.strip_prefix("http://"))
    else {
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
    let file = &path[idx + 3..];
    file.char_indices().any(|(i, c)| {
        c == '-' && file[i + 1..].chars().next().is_some_and(|d| d.is_ascii_digit())
    })
}

fn is_git_spec(spec: &str) -> bool {
    ["git+", "git://", "git@", "github:", "gitlab:", "bitbucket:", "gist:"]
        .iter()
        .any(|p| spec.starts_with(p))
}

fn classify(pkg: &LockfilePackage) -> SourceKind {
    let resolved = pkg.resolved.as_deref().unwrap_or("");
    if pkg.link == Some(true) {
        return SourceKind::Directory;
    }
    if let Some(path) = resolved.strip_prefix("file:") {
        let lower = path.to_ascii_lowercase();
        return if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".tar") {
            SourceKind::File
        } else {
            SourceKind::Directory
        };
    }
    if is_git_spec(resolved) {
        return SourceKind::Git;
    }
    if resolved.is_empty() || is_registry_tarball(resolved) {
        return SourceKind::Registry;
    }
    SourceKind::Remote
}

/// Name a top-level `node_modules/<name>` location refers to.
fn top_level_name(location: &str) -> Option<&str> {
    let rest = location.strip_prefix("node_modules/")?;
    (!rest.contains("/node_modules/")).then_some(rest)
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
    if policy.is_unrestricted() {
        return Ok(());
    }
    for (location, pkg) in &lockfile.packages {
        if location.is_empty() || !location.contains("node_modules/") {
            continue;
        }
        if pkg.link == Some(true)
            && pkg
                .resolved
                .as_deref()
                .is_some_and(|target| workspace_paths.contains(target))
        {
            continue;
        }
        let kind = classify(pkg);
        let mode = match kind {
            SourceKind::Git => policy.git,
            SourceKind::Remote => policy.remote,
            SourceKind::Registry => policy.registry,
            SourceKind::File => policy.file,
            SourceKind::Directory => policy.directory,
        };
        let is_root = top_level_name(location).is_some_and(|n| root_declared.contains(n));
        let allowed = match mode {
            AllowMode::All => true,
            AllowMode::Root => is_root,
            AllowMode::None => false,
        };
        if !allowed {
            let qualifier = if mode == AllowMode::Root { " non-root" } else { "" };
            return Err(anyhow!(
                "npm error code EALLOW{}\nnpm error Fetching{qualifier} packages of type \"{}\" have been disabled",
                kind.label().to_ascii_uppercase(),
                kind.label()
            ));
        }
    }
    Ok(())
}

// -------------------------------------------------------------------------
// allowScripts
// -------------------------------------------------------------------------

/// The effective allowScripts policy plus the strictness flags.
#[derive(Debug, Clone, Default)]
pub struct ScriptPolicy {
    entries: Option<Vec<(String, bool)>>,
    pub strict: bool,
    pub allow_all: bool,
    /// Warnings for policy keys npm drops (ranges, dist-tags).
    pub warnings: Vec<String>,
}

fn is_exact_version_disjunction(spec: &str) -> bool {
    let parts: Vec<&str> = spec.split("||").map(str::trim).collect();
    !parts.is_empty()
        && parts
            .iter()
            .all(|p| !p.is_empty() && rnpm_core::semver::Version::parse(p).is_ok())
}

/// Split a registry-style key into name and raw spec (`""` for bare names).
fn split_name_spec(key: &str) -> (&str, &str) {
    let search_from = usize::from(key.starts_with('@'));
    match key[search_from..].find('@') {
        Some(i) => (&key[..search_from + i], &key[search_from + i + 1..]),
        None => (key, ""),
    }
}

fn is_path_spec(key: &str) -> bool {
    key.starts_with("file:")
        || key.starts_with("./")
        || key.starts_with("../")
        || key.starts_with('/')
        || key.starts_with('~')
        || (key.len() > 2 && key.as_bytes()[1] == b':' && key.as_bytes()[0].is_ascii_alphabetic())
}

fn is_range_like(spec: &str) -> bool {
    rnpm_core::semver::Range::parse(spec).is_ok()
}

impl ScriptPolicy {
    /// Resolve the policy like npm's resolve-allow-scripts.js: the root
    /// package.json `allowScripts` wins over the `.npmrc` `allow-scripts`
    /// list; global installs skip package.json.
    pub fn load(project_dir: &Path, config: &rnpm_config::Config, is_global: bool) -> Self {
        let mut policy = ScriptPolicy {
            strict: config.get_bool("strict-allow-scripts").unwrap_or(false),
            allow_all: config.get_bool("dangerously-allow-all-scripts").unwrap_or(false),
            ..Default::default()
        };
        let mut pkg_entries = None;
        if !is_global {
            let text = std::fs::read_to_string(project_dir.join("package.json")).unwrap_or_default();
            if let Ok(value) =
                serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
            {
                if let Some(obj) = value.get("allowScripts").and_then(|v| v.as_object()) {
                    let entries: Vec<(String, bool)> = obj
                        .iter()
                        .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
                        .collect();
                    if !entries.is_empty() {
                        pkg_entries = Some(entries);
                    }
                }
            }
        }
        let rc_entries = config.get("allow-scripts").and_then(|list| {
            let names: Vec<(String, bool)> = list
                .split([',', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| (s.to_string(), true))
                .collect();
            (!names.is_empty()).then_some(names)
        });
        let pkg = pkg_entries.and_then(|e| policy.validate(e, "package.json"));
        let rc = rc_entries.and_then(|e| policy.validate(e, ".npmrc"));
        policy.entries = match (pkg, rc) {
            (Some(pkg), Some(_)) => {
                policy.warnings.push(
                    ".npmrc allow-scripts setting is being ignored because package.json declares its own allowScripts field"
                        .into(),
                );
                Some(pkg)
            }
            (Some(pkg), None) => Some(pkg),
            (None, rc) => rc,
        };
        policy
    }

    fn validate(&mut self, entries: Vec<(String, bool)>, label: &str) -> Option<Vec<(String, bool)>> {
        let mut kept = Vec::new();
        for (key, value) in entries {
            let registry_like = !is_path_spec(&key)
                && !is_git_spec(&key)
                && !key.starts_with("http://")
                && !key.starts_with("https://");
            if registry_like {
                let (_, spec) = split_name_spec(&key);
                let name_only = spec.is_empty() || spec == "*";
                if !name_only && !spec.starts_with("npm:") {
                    if !is_range_like(spec) {
                        self.warnings.push(format!(
                            "{label}: ignoring \"{key}\" — dist-tag specs (@latest, @next, ...) are not allowed; use exact versions joined by \"||\", or the bare package name, instead"
                        ));
                        continue;
                    }
                    if !is_exact_version_disjunction(spec) {
                        self.warnings.push(format!(
                            "{label}: ignoring \"{key}\" — semver ranges (^, ~, >=, <) are not allowed; use exact versions joined by \"||\" instead"
                        ));
                        continue;
                    }
                }
            }
            kept.push((key, value));
        }
        (!kept.is_empty()).then_some(kept)
    }

    /// `Some(true)` allowed, `Some(false)` denied, `None` unreviewed.
    pub fn verdict(&self, node: &ScriptNode<'_>) -> Option<bool> {
        if node.in_bundle {
            return None;
        }
        let entries = self.entries.as_ref()?;
        let mut allow = false;
        let mut deny = false;
        for (key, value) in entries {
            if node.matches(key, !*value) {
                if *value {
                    allow = true;
                } else {
                    deny = true;
                }
            }
        }
        if deny {
            Some(false)
        } else if allow {
            Some(true)
        } else {
            None
        }
    }
}

/// What the policy matcher knows about one installed dependency.
pub struct ScriptNode<'a> {
    pub location: &'a str,
    pub resolved: Option<&'a str>,
    /// Real package name recorded by the lockfile for aliased entries.
    pub lock_name: Option<&'a str>,
    pub in_bundle: bool,
    pub link: bool,
    pub project_dir: &'a Path,
}

fn normalize_path(path: &Path) -> String {
    let p = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = p.to_string_lossy().replace('\\', "/");
    let s = s.strip_prefix("//?/").unwrap_or(&s).to_string();
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s
    }
}

/// `host/user/repo` identity plus committish for a git spec.
fn git_identity(spec: &str) -> Option<(String, String)> {
    let (body, committish) = spec.split_once('#').unwrap_or((spec, ""));
    let body = body
        .trim_start_matches("git+")
        .trim_start_matches("ssh://")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git://")
        .trim_start_matches("git@");
    let body = if let Some(rest) = body.strip_prefix("github:") {
        format!("github.com/{rest}")
    } else if let Some(rest) = body.strip_prefix("gitlab:") {
        format!("gitlab.com/{rest}")
    } else if let Some(rest) = body.strip_prefix("bitbucket:") {
        format!("bitbucket.org/{rest}")
    } else {
        body.replacen(':', "/", 1)
    };
    let body = body.trim_end_matches('/').trim_end_matches(".git").to_ascii_lowercase();
    (!body.is_empty()).then(|| (body, committish.to_string()))
}

impl ScriptNode<'_> {
    fn is_registry(&self) -> bool {
        !self.link && self.resolved.is_none_or(is_registry_tarball)
    }

    /// Trusted registry identity: from the resolved tarball URL, else the
    /// lockfile/location name with no version.
    fn registry_identity(&self) -> Option<(String, Option<String>)> {
        if let Some(resolved) = self.resolved {
            if let Some(idx) = resolved.find("/-/") {
                let before = &resolved[..idx];
                let path = before.split_once("://").map(|(_, r)| r).unwrap_or(before);
                let name_part = path.split_once('/').map(|(_, n)| n).unwrap_or("");
                let name = name_part.replace("%2f", "/").replace("%2F", "/");
                // The registry path may carry a prefix (e.g. a proxy path);
                // keep the trailing `name` or `@scope/name`.
                let segs: Vec<&str> = name.split('/').collect();
                let name = match segs.as_slice() {
                    [.., scope, n] if scope.starts_with('@') => format!("{scope}/{n}"),
                    [.., n] => (*n).to_string(),
                    [] => String::new(),
                };
                let unscoped = name.rsplit('/').next().unwrap_or(&name);
                let file = resolved[idx + 3..].split(['?', '#']).next().unwrap_or("");
                let version = file
                    .strip_prefix(&format!("{unscoped}-"))
                    .and_then(|v| v.strip_suffix(".tgz"))
                    .map(str::to_string);
                if !name.is_empty() && version.is_some() {
                    return Some((name, version));
                }
            }
        }
        let name = self
            .lock_name
            .map(str::to_string)
            .or_else(|| top_level_or_nested_name(self.location))?;
        Some((name, None))
    }

    fn matches(&self, key: &str, fail_closed: bool) -> bool {
        if is_git_spec(key) {
            let (Some(resolved), Some((key_repo, key_ref))) = (self.resolved, git_identity(key))
            else {
                return false;
            };
            if !is_git_spec(resolved) {
                return false;
            }
            let Some((node_repo, node_ref)) = git_identity(resolved) else {
                return false;
            };
            return key_repo == node_repo && (key_ref.is_empty() || node_ref.starts_with(&key_ref));
        }
        if key.starts_with("http://") || key.starts_with("https://") {
            return self.resolved == Some(key);
        }
        if is_path_spec(key) {
            let key_path = key.strip_prefix("file:").unwrap_or(key);
            let key_abs = normalize_path(&self.project_dir.join(key_path));
            let node_target = self
                .resolved
                .map(|r| r.strip_prefix("file:").unwrap_or(r))
                .map(|r| normalize_path(&self.project_dir.join(r)));
            return node_target.as_deref() == Some(key_abs.as_str());
        }
        let (name, spec) = split_name_spec(key);
        if spec.starts_with("npm:") || !self.is_registry() {
            return false;
        }
        let Some((trusted_name, trusted_version)) = self.registry_identity() else {
            return false;
        };
        if trusted_name != name {
            return false;
        }
        if spec.is_empty() || spec == "*" {
            return true;
        }
        match trusted_version {
            None => fail_closed,
            Some(v) => spec.split("||").map(str::trim).any(|want| want == v),
        }
    }
}

fn top_level_or_nested_name(location: &str) -> Option<String> {
    location
        .rsplit_once("node_modules/")
        .map(|(_, n)| n.to_string())
        .filter(|n| !n.is_empty())
}

/// arborist install-scripts.js: the scripts installing this package runs.
pub fn install_scripts(
    manifest: &Manifest,
    disk_path: &Path,
    registry_source: bool,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for event in ["preinstall", "install", "postinstall"] {
        if let Some(body) = manifest.scripts.get(event).filter(|b| !b.is_empty()) {
            out.push((event.to_string(), body.clone()));
        }
    }
    if !registry_source {
        if let Some(body) = manifest.scripts.get("prepare").filter(|b| !b.is_empty()) {
            out.push(("prepare".to_string(), body.clone()));
        }
    }
    let explicit_gate = manifest.scripts.contains_key("preinstall")
        || manifest.scripts.contains_key("install");
    let gyp_disabled = manifest.extra.get("gypfile") == Some(&serde_json::Value::Bool(false));
    if !explicit_gate && !gyp_disabled && disk_path.join("binding.gyp").is_file() {
        out.retain(|(e, _)| e != "install");
        out.insert(
            out.iter().position(|(e, _)| e == "postinstall").unwrap_or(out.len()),
            ("install".to_string(), "node-gyp rebuild".to_string()),
        );
    }
    out
}

fn node_for<'a>(
    location: &'a str,
    pkg: Option<&'a LockfilePackage>,
    project_dir: &'a Path,
) -> ScriptNode<'a> {
    ScriptNode {
        location,
        resolved: pkg.and_then(|p| p.resolved.as_deref()),
        lock_name: pkg.and_then(|p| p.name.as_deref()),
        in_bundle: pkg.is_some_and(|p| p.is_in_bundle()),
        link: pkg.is_some_and(|p| p.link == Some(true)),
        project_dir,
    }
}

fn label(manifest: &Manifest, location: &str) -> String {
    let name = manifest
        .name
        .clone()
        .or_else(|| top_level_or_nested_name(location))
        .unwrap_or_default();
    match &manifest.version {
        Some(v) if !v.is_empty() => format!("{name}@{v}"),
        _ => name,
    }
}

fn describe(scripts: &[(String, String)]) -> String {
    scripts
        .iter()
        .map(|(e, b)| format!("{e}: {b}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn strict_error(mut unreviewed: Vec<(String, String, Vec<(String, String)>)>) -> anyhow::Error {
    unreviewed.sort_by(|a, b| a.0.cmp(&b.0));
    let lines = unreviewed
        .iter()
        .map(|(_, l, s)| format!("npm error   {l} ({})", describe(s)))
        .collect::<Vec<_>>()
        .join("\n");
    anyhow!(
        "npm error code ESTRICTALLOWSCRIPTS\nnpm error --strict-allow-scripts: {} package(s) have install scripts not covered by allowScripts:\n{lines}\nnpm error Approve them with `npm install-scripts approve`, deny them with `npm install-scripts deny`, or bypass this check with `--dangerously-allow-all-scripts`.",
        unreviewed.len()
    )
}

/// `--strict-allow-scripts` preflight on the resolved tree, before anything
/// is written (npm's strict-allow-scripts-preflight.js). Registry packages not
/// on disk yet are reported with npm's `(install scripts present)` sentinel.
pub fn strict_preflight(
    lockfile: &LockfileV3,
    base_dir: &Path,
    workspace_paths: &HashSet<String>,
    policy: &ScriptPolicy,
    ignore_scripts: bool,
) -> Result<()> {
    if !policy.strict || policy.allow_all || ignore_scripts {
        return Ok(());
    }
    let mut unreviewed = Vec::new();
    for (location, pkg) in &lockfile.packages {
        if location.is_empty() || !location.contains("node_modules/") {
            continue;
        }
        let local_dir = pkg
            .resolved
            .as_deref()
            .and_then(|r| r.strip_prefix("file:"))
            .map(|r| base_dir.join(r))
            .filter(|d| d.is_dir());
        let dir: PathBuf = if pkg.link == Some(true) {
            match pkg.resolved.as_deref() {
                Some(target) if !workspace_paths.contains(target) => base_dir.join(target),
                _ => continue,
            }
        } else if let Some(local) = local_dir {
            local
        } else {
            base_dir.join(location)
        };
        let ident = node_for(location, Some(pkg), base_dir);
        if ident.in_bundle || policy.verdict(&ident).is_some() {
            continue;
        }
        let manifest = Manifest::from_file(dir.join("package.json")).ok();
        let mut scripts = manifest
            .as_ref()
            .map(|m| install_scripts(m, &dir, ident.is_registry()))
            .unwrap_or_default();
        if scripts.is_empty() && pkg.has_install_script() {
            scripts.push(("install".into(), "(install scripts present)".into()));
        }
        if scripts.is_empty() {
            continue;
        }
        let label = manifest
            .as_ref()
            .map(|m| label(m, location))
            .unwrap_or_else(|| {
                let name = pkg
                    .name
                    .clone()
                    .or_else(|| top_level_or_nested_name(location))
                    .unwrap_or_default();
                match &pkg.version {
                    Some(v) => format!("{name}@{v}"),
                    None => name,
                }
            });
        unreviewed.push((location.clone(), label, scripts));
    }
    if unreviewed.is_empty() {
        Ok(())
    } else {
        Err(strict_error(unreviewed))
    }
}

/// Drop dependencies whose scripts are denied, and enforce
/// `--strict-allow-scripts` before any script runs.
pub fn apply_script_policy(
    nodes: Vec<LifecyclePackageNode>,
    lockfile: &LockfileV3,
    project_dir: &Path,
    policy: &ScriptPolicy,
) -> Result<Vec<LifecyclePackageNode>> {
    if policy.allow_all {
        return Ok(nodes);
    }
    let mut kept = Vec::new();
    let mut unreviewed = Vec::new();
    for node in nodes {
        let pkg = lockfile.packages.get(&node.package_path);
        let ident = node_for(&node.package_path, pkg, project_dir);
        match policy.verdict(&ident) {
            Some(false) => continue,
            Some(true) => kept.push(node),
            None => {
                let scripts = install_scripts(&node.manifest, &node.disk_path, ident.is_registry());
                if policy.strict && !scripts.is_empty() && !ident.in_bundle {
                    unreviewed.push((node.package_path.clone(), label(&node.manifest, &node.package_path), scripts));
                }
                kept.push(node);
            }
        }
    }
    if !unreviewed.is_empty() {
        return Err(strict_error(unreviewed));
    }
    Ok(kept)
}

/// The advisory npm prints after reify: installed dependencies with install
/// scripts that the policy neither allows nor denies.
pub fn unreviewed_scripts_warning(
    lockfile: &LockfileV3,
    base_dir: &Path,
    workspace_paths: &HashSet<String>,
    policy: &ScriptPolicy,
    is_global: bool,
) -> Option<String> {
    if policy.allow_all {
        return None;
    }
    let mut found: Vec<(String, String)> = Vec::new();
    let mut names = Vec::new();
    for (location, pkg) in &lockfile.packages {
        if location.is_empty() || !location.contains("node_modules/") {
            continue;
        }
        // A link stands for its target directory; workspaces are skipped.
        let dir: PathBuf = if pkg.link == Some(true) {
            match pkg.resolved.as_deref() {
                Some(target) if !workspace_paths.contains(target) => base_dir.join(target),
                _ => continue,
            }
        } else {
            base_dir.join(location)
        };
        let ident = node_for(location, Some(pkg), base_dir);
        if ident.in_bundle || policy.verdict(&ident).is_some() {
            continue;
        }
        let Ok(manifest) = Manifest::from_file(dir.join("package.json")) else {
            continue;
        };
        let scripts = install_scripts(&manifest, &dir, ident.is_registry());
        if scripts.is_empty() {
            continue;
        }
        let (name, version) = ident
            .registry_identity()
            .filter(|_| ident.is_registry())
            .map(|(n, v)| (n, v.or_else(|| manifest.version.clone())))
            .unwrap_or_else(|| {
                (
                    manifest.name.clone().unwrap_or_else(|| location.to_string()),
                    manifest.version.clone(),
                )
            });
        names.push(name.clone());
        let ver = version.map(|v| format!("@{v}")).unwrap_or_default();
        found.push((location.clone(), format!("  {name}{ver} ({})", describe(&scripts))));
    }
    if found.is_empty() {
        return None;
    }
    let count = found.len();
    let noun = if count == 1 { "package has" } else { "packages have" };
    let mut lines = vec![format!("{count} {noun} install scripts not yet covered by allowScripts:")];
    lines.extend(found.into_iter().map(|(_, l)| l));
    lines.push(String::new());
    if is_global {
        let list = names.join(",");
        lines.push(format!(
            "Run `npm install -g --allow-scripts={list}` to allow these scripts once, or `npm config set allow-scripts={list} --location=global` to allow them for all global installs."
        ));
    } else {
        lines.push(
            "Run `npm install-scripts ls` to review, or `npm install-scripts approve <pkg>` to allow."
                .into(),
        );
    }
    Some(
        lines
            .iter()
            .map(|l| {
                if l.is_empty() {
                    "npm warn install-scripts".to_string()
                } else {
                    format!("npm warn install-scripts {l}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
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
        assert_eq!(policy(&[("dep", true), ("dep@1.0.0", false)]).verdict(&node), Some(false));
        assert_eq!(policy(&[("dep@1.0.0 || 2.0.0", true)]).verdict(&node), Some(true));
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
        let bundled = ScriptNode { in_bundle: true, ..node };
        assert_eq!(policy(&[("dep", true)]).verdict(&bundled), None);
    }

    #[test]
    fn registry_url_shape_matches_arborist() {
        assert!(is_registry_tarball("https://registry.npmjs.org/a/-/a-1.0.0.tgz"));
        assert!(!is_registry_tarball("https://evil.com/-/a-1.0.0.tgz"));
        assert!(!is_registry_tarball("https://example.com/a.tgz"));
    }
}
