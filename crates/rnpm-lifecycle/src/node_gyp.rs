use crate::error::LifecycleError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(1);

/// RAII guard to clean up a staging directory if not committed.
pub struct StagingGuard {
    path: PathBuf,
    committed: bool,
}

impl StagingGuard {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.committed && self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Opportunistically removes old abandoned `.tmp-*` staging directories from prior failed/killed runs.
fn cleanup_stale_staging(node_gyp_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(node_gyp_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with(".tmp-") {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            if elapsed.as_secs() > 1800 {
                                let _ = std::fs::remove_dir_all(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Locates the cache directory to use for rnpm standalone tools (like node-gyp).
pub fn find_cache_dir(_project_root: &Path, config: &rnpm_config::Config) -> PathBuf {
    if let Some(c) = config.get("cache") {
        let trimmed = c.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(c) = std::env::var("npm_config_cache").or_else(|_| std::env::var("NPM_CONFIG_CACHE")) {
        let trimmed = c.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("npm-cache")
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".npm")
    }
}

/// Locates the registry URL from configuration or environment.
pub fn find_registry(config: &rnpm_config::Config) -> String {
    if let Some(reg) = config.get("registry") {
        let trimmed = reg.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(reg) = std::env::var("npm_config_registry").or_else(|_| std::env::var("NPM_CONFIG_REGISTRY")) {
        let trimmed = reg.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "https://registry.npmjs.org/".to_string()
}

/// Checks if offline mode is explicitly requested via environment or configuration.
pub fn is_offline_mode(config: &rnpm_config::Config) -> bool {
    for var in ["npm_config_offline", "NPM_CONFIG_OFFLINE"] {
        if let Ok(val) = std::env::var(var) {
            let val = val.trim().to_ascii_lowercase();
            if val == "true" || val == "1" || val == "yes" {
                return true;
            }
        }
    }
    if let Some(val) = config.get("offline") {
        let val = val.trim().to_ascii_lowercase();
        if val == "true" || val == "1" || val == "yes" {
            return true;
        }
    }
    false
}

/// Finds node-gyp following the npm-independent resolution order:
/// (a) Explicit config (`npm_config_node_gyp` env var, `.npmrc` `node-gyp=<path>`, or explicit option)
/// (b) Local project `node_modules/.bin/node-gyp` (or `node_modules/node-gyp/bin/node-gyp.js`)
/// (c) Standalone `node-gyp` on `PATH`
/// (d) `rnpm`'s own cached standalone `node-gyp` directory (<rnpm_cache>/node-gyp/current/bin/node-gyp.js)
/// (e) Bundled npm `node-gyp` (fallback only if npm is installed alongside Node)
pub fn find_node_gyp(
    project_root: &Path,
    package_dir: &Path,
    config: &rnpm_config::Config,
    explicit_opt: Option<&Path>,
) -> Option<PathBuf> {
    // a. Explicit config override takes precedence over everything else
    if let Some(p) = explicit_opt {
        if !p.as_os_str().is_empty() {
            debug!("Resolved node-gyp via explicit option: {}", p.display());
            return Some(p.to_path_buf());
        }
    }

    if let Ok(v) = std::env::var("npm_config_node_gyp").or_else(|_| std::env::var("NPM_CONFIG_NODE_GYP")) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            debug!("Resolved node-gyp via npm_config_node_gyp env var: {}", trimmed);
            return Some(PathBuf::from(trimmed));
        }
    }

    if let Some(v) = config.get("node-gyp") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            debug!("Resolved node-gyp via .npmrc node-gyp setting: {}", trimmed);
            return Some(PathBuf::from(trimmed));
        }
    }

    // b. Local project node_modules/.bin/node-gyp or node_modules/node-gyp/bin/node-gyp.js
    let mut check_dirs = Vec::new();
    check_dirs.push(package_dir.to_path_buf());
    let mut current = package_dir;
    while let Some(parent) = current.parent() {
        if !check_dirs.contains(&parent.to_path_buf()) {
            check_dirs.push(parent.to_path_buf());
        }
        if parent == project_root {
            break;
        }
        current = parent;
    }
    if !check_dirs.contains(&project_root.to_path_buf()) {
        check_dirs.push(project_root.to_path_buf());
    }

    for dir in check_dirs {
        let bin_dir = dir.join("node_modules").join(".bin");
        if cfg!(windows) {
            let cmd = bin_dir.join("node-gyp.cmd");
            if cmd.is_file() {
                debug!("Resolved node-gyp via local node_modules/.bin/node-gyp.cmd: {}", cmd.display());
                return Some(cmd);
            }
        }
        let sh = bin_dir.join("node-gyp");
        if sh.is_file() {
            debug!("Resolved node-gyp via local node_modules/.bin/node-gyp: {}", sh.display());
            return Some(sh);
        }

        let direct_js = dir.join("node_modules").join("node-gyp").join("bin").join("node-gyp.js");
        if direct_js.is_file() {
            debug!("Resolved node-gyp via local node_modules/node-gyp/bin/node-gyp.js: {}", direct_js.display());
            return Some(direct_js);
        }
    }

#[inline]
fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

fn find_standalone_node_gyp_on_path() -> Option<PathBuf> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    #[allow(clippy::type_complexity)]
    static CACHE: OnceLock<Mutex<Option<(std::ffi::OsString, Option<PathBuf>, Instant)>>> =
        OnceLock::new();

    let path_var = std::env::var_os("PATH")
        .or_else(|| std::env::var_os("Path"))
        .unwrap_or_default();

    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((ref cached_path, ref result, ts)) = *guard {
            if cached_path == &path_var {
                match result {
                    Some(p) if p.is_file() => return Some(p.clone()),
                    None if ts.elapsed() < Duration::from_secs(2) => return None,
                    _ => {}
                }
            }
        }
    }

    let mut found = None;
    for p in std::env::split_paths(&path_var) {
        let s_lossy = p.to_string_lossy();
        let bytes = s_lossy.as_bytes();
        // Skip npm's bundled node-gyp-bin or npm node_modules so we don't confuse bundled with standalone
        if contains_ascii_ci(bytes, b"node_modules\\npm")
            || contains_ascii_ci(bytes, b"node_modules/npm")
            || contains_ascii_ci(bytes, b"npm\\bin\\node-gyp-bin")
            || contains_ascii_ci(bytes, b"npm/bin/node-gyp-bin")
        {
            continue;
        }
        if cfg!(windows) {
            for ext in ["cmd", "exe", "bat"] {
                let candidate = p.join(format!("node-gyp.{ext}"));
                if candidate.is_file() {
                    debug!(
                        "Resolved standalone node-gyp on PATH: {}",
                        candidate.display()
                    );
                    found = Some(candidate);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let candidate = p.join("node-gyp");
        if candidate.is_file() {
            debug!(
                "Resolved standalone node-gyp on PATH: {}",
                candidate.display()
            );
            found = Some(candidate);
            break;
        }
    }

    if let Ok(mut guard) = cache.lock() {
        *guard = Some((path_var, found.clone(), Instant::now()));
    }
    found
}

    // c. Standalone node-gyp on PATH
    if let Some(candidate) = find_standalone_node_gyp_on_path() {
        return Some(candidate);
    }

    // d. rnpm's own cached standalone node-gyp directory (<cache>/node-gyp/current/bin/node-gyp.js)
    let cache_dir = find_cache_dir(project_root, config);
    if let Some(found) = find_cached_standalone_node_gyp(&cache_dir) {
        return Some(found);
    }

    // e. Bundled npm node-gyp (fallback only if npm happens to be installed alongside Node)
    let allow_npm_fallback = config
        .get("node-gyp-fallback-npm")
        .or_else(|| config.get("node-gyp-npm-fallback"))
        .or_else(|| config.get("fallback-npm"))
        .map(|v| v != "false" && v != "0" && v != "no")
        .unwrap_or_else(|| {
            std::env::var("npm_config_node_gyp_fallback_npm")
                .or_else(|_| std::env::var("NPM_CONFIG_NODE_GYP_FALLBACK_NPM"))
                .or_else(|_| std::env::var("RNPM_NODE_GYP_FALLBACK_NPM"))
                .map(|v| v != "false" && v != "0" && v != "no")
                .unwrap_or(true)
        });

    if allow_npm_fallback {
        static BUNDLED_NPM_NODE_GYP: std::sync::OnceLock<Option<PathBuf>> =
            std::sync::OnceLock::new();
        let bundled = BUNDLED_NPM_NODE_GYP.get_or_init(|| {
            crate::node_executable()
                .and_then(|n| n.parent().map(Path::to_path_buf))
                .map(|d| {
                    if cfg!(windows) {
                        d.join("node_modules")
                    } else {
                        d.parent().unwrap_or(&d).join("lib").join("node_modules")
                    }
                })
                .map(|d| {
                    d.join("npm")
                        .join("node_modules")
                        .join("node-gyp")
                        .join("bin")
                        .join("node-gyp.js")
                })
                .filter(|p| p.is_file())
        });
        if let Some(gyp) = bundled {
            debug!("Resolved node-gyp via bundled npm fallback: {}", gyp.display());
            return Some(gyp.clone());
        }
    }

    None
}

fn find_cached_standalone_node_gyp(cache_dir: &Path) -> Option<PathBuf> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    type CachedNodeGypEntry = (PathBuf, Option<PathBuf>, Instant);
    static CACHE: OnceLock<Mutex<Option<CachedNodeGypEntry>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((ref cached_dir, ref result, ts)) = *guard {
            if cached_dir == cache_dir {
                match result {
                    Some(p) if p.is_file() => return Some(p.clone()),
                    None if ts.elapsed() < Duration::from_secs(2) => return None,
                    _ => {}
                }
            }
        }
    }

    let cached_candidates = [
        cache_dir.join("node-gyp").join("current").join("bin").join("node-gyp.js"),
        cache_dir.join("node-gyp").join("current").join("node-gyp.js"),
        cache_dir.join("node-gyp").join("bin").join("node-gyp.js"),
    ];
    let found = cached_candidates.into_iter().find(|c| c.is_file());
    if let Some(ref candidate) = found {
        debug!(
            "Resolved node-gyp via cached standalone directory: {}",
            candidate.display()
        );
    }
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((cache_dir.to_path_buf(), found.clone(), Instant::now()));
    }
    found
}

/// Ensures node-gyp is available, performing on-demand bootstrap from the registry if needed
/// when online, or returning an actionable error if offline and absent.
pub fn ensure_node_gyp(
    project_root: &Path,
    package_dir: &Path,
    config: &rnpm_config::Config,
    explicit_opt: Option<&Path>,
    offline: bool,
    package_name: &str,
) -> Result<PathBuf, LifecycleError> {
    if let Some(path) = find_node_gyp(project_root, package_dir, config, explicit_opt) {
        return Ok(path);
    }

    let is_offline = offline || is_offline_mode(config);
    if is_offline {
        return Err(LifecycleError::NodeGypOfflineAbsent {
            package: package_name.to_string(),
        });
    }

    info!(
        "node-gyp not found locally or in bundled npm. Bootstrapping standalone node-gyp from registry for package '{}'...",
        package_name
    );

    bootstrap_node_gyp(project_root, config).map_err(|e| {
        LifecycleError::ExecutionFailed(format!(
            "Failed to automatically bootstrap node-gyp from registry: {e}"
        ))
    })
}

/// Downloads and unpacks node-gyp and its full production dependency tree from the configured
/// npm registry into `<cache_dir>/node-gyp/current/` via atomic staging and verification.
pub fn bootstrap_node_gyp(
    project_root: &Path,
    config: &rnpm_config::Config,
) -> anyhow::Result<PathBuf> {
    let cache_dir = find_cache_dir(project_root, config);
    let node_gyp_dir = cache_dir.join("node-gyp");
    let target_dir = node_gyp_dir.join("current");
    let registry = find_registry(config);

    std::fs::create_dir_all(&node_gyp_dir)?;
    cleanup_stale_staging(&node_gyp_dir);

    // Create unique temporary staging directory inside <rnpm_cache>/node-gyp/.tmp-<pid>-<rand>
    let pid = std::process::id();
    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging_dir = node_gyp_dir.join(format!(".tmp-{pid}-{nanos}-{counter}"));
    std::fs::create_dir_all(&staging_dir)?;

    let guard = StagingGuard::new(staging_dir.clone());

    // Run async network operations on a dedicated thread with a fresh single-thread runtime
    // to guarantee no nested block_on conflicts with existing tokio runtimes.
    let staging_clone = staging_dir.clone();
    let reg_clone = registry.clone();
    let config_clone = config.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            download_and_unpack_node_gyp_with_config(&reg_clone, &staging_clone, &config_clone).await
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Worker thread panicked during node-gyp bootstrap"))??;

    // Atomically publish into the final target location only after full verification & install succeed
    rnpm_fs::replace_dir_with_retries(&staging_dir, &target_dir, 30)?;
    guard.commit();

    let candidate1 = target_dir.join("bin").join("node-gyp.js");
    if candidate1.is_file() {
        return Ok(candidate1);
    }
    let candidate2 = target_dir.join("node-gyp.js");
    if candidate2.is_file() {
        return Ok(candidate2);
    }

    Ok(candidate1)
}

fn build_bootstrap_client(
    registry: &str,
    config: &rnpm_config::Config,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    let reg_url = reqwest::Url::parse(registry).ok();

    let bypass_proxy = if let Some(ref url) = reg_url {
        config.should_bypass_proxy(url)
    } else {
        registry.contains("127.0.0.1") || registry.contains("localhost")
    };

    if bypass_proxy {
        builder = builder.no_proxy();
    } else {
        let https_proxy = config.https_proxy();
        let http_proxy = config.http_proxy();
        let general_proxy = config.proxy();

        if let Some(https_val) = https_proxy {
            if let Ok(proxy) = reqwest::Proxy::https(https_val) {
                builder = builder.proxy(proxy);
            }
        }
        if let Some(http_val) = http_proxy {
            if let Ok(proxy) = reqwest::Proxy::http(http_val) {
                builder = builder.proxy(proxy);
            }
        }
        if let Some(gen_val) = general_proxy {
            if https_proxy.is_none() && http_proxy.is_none() {
                if let Ok(proxy) = reqwest::Proxy::all(gen_val) {
                    builder = builder.proxy(proxy);
                }
            }
        }
    }
    if config.get_bool("strict-ssl") == Some(false) {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(cafile) = config
        .get("cafile")
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "null")
    {
        let pem = std::fs::read(cafile)
            .map_err(|e| anyhow::anyhow!("Failed to read cafile '{cafile}': {e}"))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| anyhow::anyhow!("Invalid PEM certificate in cafile '{cafile}': {e}"))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(ca_pem) = config
        .get("ca")
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "null")
    {
        let normalized = ca_pem.replace("\\n", "\n");
        if let Ok(certs) = reqwest::Certificate::from_pem_bundle(normalized.as_bytes()) {
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
    }
    Ok(builder.build()?)
}

fn registry_auth_header(registry: &str, config: &rnpm_config::Config) -> Option<String> {
    let url = reqwest::Url::parse(registry).ok()?;
    if let Some(token) = config.npmrc.get_auth_token(&url) {
        return Some(format!("Bearer {token}"));
    }
    if let Some(basic) = config.npmrc.get_basic_auth(&url) {
        return Some(format!("Basic {basic}"));
    }
    None
}

fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(ua), Ok(ub)) => {
            ua.scheme() == ub.scheme()
                && ua.host_str() == ub.host_str()
                && ua.port_or_known_default() == ub.port_or_known_default()
        }
        _ => false,
    }
}

fn get_with_registry_auth(
    client: &reqwest::Client,
    url: &str,
    registry: &str,
    auth_header: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut req = client.get(url);
    if let Some(auth) = auth_header {
        if same_origin(url, registry) {
            req = req.header(reqwest::header::AUTHORIZATION, auth);
        }
    }
    req
}

/// Downloads, integrity-verifies, and unpacks `node-gyp` and its transitive production dependencies
/// into `staging_dir`.
pub async fn download_and_unpack_node_gyp(registry: &str, staging_dir: &Path) -> anyhow::Result<()> {
    download_and_unpack_node_gyp_with_config(registry, staging_dir, &rnpm_config::Config::default()).await
}

/// Downloads, integrity-verifies, and unpacks `node-gyp` and its transitive production dependencies
/// into `staging_dir`, preserving registry authentication, CA certificates, and TLS settings from `config`.
pub async fn download_and_unpack_node_gyp_with_config(
    registry: &str,
    staging_dir: &Path,
    config: &rnpm_config::Config,
) -> anyhow::Result<()> {
    let client = build_bootstrap_client(registry, config)?;
    let auth_header = registry_auth_header(registry, config);

    // 1. Fetch metadata for node-gyp
    let packument = fetch_packument(&client, registry, "node-gyp", auth_header.as_deref()).await?;

    let (chosen_version, version_obj) = if let Some(versions) = packument.get("versions").and_then(|v| v.as_object()) {
        pick_matching_version(versions, packument.get("dist-tags"), "latest")
            .ok_or_else(|| anyhow::anyhow!("No version found for node-gyp in registry metadata"))?
    } else if packument.get("dist").is_some() {
        let v = packument
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Single-version response for 'node-gyp' is missing a valid 'version' field"
                )
            })?;
        if !version_matches_spec(v, "latest") {
            anyhow::bail!(
                "Single-version response for 'node-gyp' has version '{}', which does not satisfy 'latest'",
                v
            );
        }
        (v, &packument)
    } else {
        anyhow::bail!("Invalid node-gyp registry metadata: missing versions and dist");
    };

    let dist = version_obj.get("dist")
        .ok_or_else(|| anyhow::anyhow!("Missing dist object for node-gyp@{}", chosen_version))?;
    let tarball_url = dist.get("tarball").and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing dist.tarball for node-gyp@{}", chosen_version))?;
    let full_tb_url = resolve_url(registry, tarball_url);
    let integrity_opt = dist.get("integrity").and_then(|i| i.as_str());
    let shasum_opt = dist.get("shasum").and_then(|s| s.as_str());

    info!("Downloading node-gyp@{} tarball from '{}'...", chosen_version, full_tb_url);
    let tb_resp = get_with_registry_auth(&client, &full_tb_url, registry, auth_header.as_deref())
        .send()
        .await?;
    if !tb_resp.status().is_success() {
        anyhow::bail!("Failed to download node-gyp tarball from '{}': HTTP {}", full_tb_url, tb_resp.status());
    }
    let tb_bytes = tb_resp.bytes().await?.to_vec();

    // 2. Verify integrity
    verify_tarball_integrity(&tb_bytes, integrity_opt, shasum_opt)
        .map_err(|e| anyhow::anyhow!("node-gyp tarball integrity check failed: {e}"))?;

    // 3. Unpack into staging directory
    unpack_tarball(&tb_bytes, staging_dir)
        .map_err(|e| anyhow::anyhow!("Failed to unpack node-gyp tarball: {e}"))?;

    // 4. Resolve and install full production dependency tree into staging/node_modules
    let mut root_deps = Vec::new();
    if let Some(deps) = version_obj.get("dependencies").and_then(|d| d.as_object()) {
        for (k, v) in deps {
            root_deps.push((k.clone(), v.as_str().unwrap_or("*").to_string()));
        }
    } else {
        let pkg_json = staging_dir.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                    for (k, v) in deps {
                        root_deps.push((k.clone(), v.as_str().unwrap_or("*").to_string()));
                    }
                }
            }
        }
    }

    if !root_deps.is_empty() {
        info!("Installing {} production dependencies for standalone node-gyp...", root_deps.len());
        install_production_dependencies_with_auth(
        &client,
        registry,
        staging_dir,
        root_deps,
        auth_header.as_deref(),
    )
    .await?;
    }

    let c1 = staging_dir.join("bin").join("node-gyp.js");
    let c2 = staging_dir.join("node-gyp.js");
    if !c1.is_file() && !c2.is_file() {
        anyhow::bail!("Unpacked node-gyp archive does not contain bin/node-gyp.js or node-gyp.js");
    }

    Ok(())
}

pub const MAX_NESTING_DEPTH: usize = 16;

/// Counts the number of `node_modules` path segments in `path` relative to `staging_dir`.
pub fn count_node_modules_depth(path: &Path, staging_dir: &Path) -> usize {
    let rel = path.strip_prefix(staging_dir).unwrap_or(path);
    rel.components()
        .filter(|c| c.as_os_str() == "node_modules")
        .count()
}

fn get_installed_pkg_info(package_dir: &Path) -> (Option<String>, Option<String>) {
    let pkg_json = package_dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg_json) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            let name = val.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let ver = val.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
            return (name, ver);
        }
    }
    (None, None)
}

fn directory_matches_pkg_name(dir: &Path, pkg_name: &str) -> bool {
    if let Some((scope, name)) = pkg_name.split_once('/') {
        let dir_name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let parent_name = dir.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()).unwrap_or("");
        dir_name == name && parent_name == scope
    } else {
        dir.file_name().and_then(|s| s.to_str()).unwrap_or("") == pkg_name
    }
}

/// Checks whether a dependency `(job_name, job_spec)` is already satisfied in the ancestor
/// directory chain from `parent_dir` upward to `staging_dir`, matching Node.js resolution order.
pub fn is_ancestor_satisfied(
    job_name: &str,
    job_spec: &str,
    parent_dir: &Path,
    staging_dir: &Path,
) -> anyhow::Result<bool> {
    let mut curr = Some(parent_dir);

    while let Some(dir) = curr {
        if !dir.starts_with(staging_dir) {
            break;
        }

        let is_nm_folder = dir.file_name().and_then(|s| s.to_str()) == Some("node_modules");
        let is_scope_folder = dir
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with('@'));

        if is_nm_folder || is_scope_folder {
            if dir == staging_dir {
                break;
            }
            curr = dir.parent();
            continue;
        }

        // 1. Ancestor's node_modules resolution check:
        // In Node.js module resolution, `dir/node_modules/<job_name>` is checked BEFORE `dir` itself!
        // If ANY ancestor's `node_modules/<name>` exists, it shadows `dir` and all higher ancestors.
        let nm_dir = dir.join("node_modules");
        if nm_dir.is_dir() {
            if let Ok(cand) = package_dir_in_node_modules(&nm_dir, job_name) {
                if cand.exists() {
                    if let Some(ref v) = get_installed_version(&cand) {
                        if version_matches_spec(v, job_spec) {
                            debug!(
                                "Dependency '{}@{}' already satisfied at ancestor {}",
                                job_name, v, cand.display()
                            );
                            return Ok(true);
                        }
                    }
                    // In Node module resolution, an existing cand in a closer node_modules
                    // shadows both `dir` itself and all higher ancestors. If it does not satisfy job_spec,
                    // higher ancestors cannot satisfy this require call.
                    break;
                }
            }
        }

        // 2. Direct self/mutual cycle check:
        // If an ancestor directory itself IS `<name>` with a version satisfying `job.spec` (and was not shadowed
        // by `dir/node_modules/<job_name>`), STOP!
        if dir != staging_dir {
            let (pkg_name_opt, pkg_ver_opt) = get_installed_pkg_info(dir);
            let ver_opt = pkg_ver_opt.or_else(|| get_installed_version(dir));
            let name_matches = pkg_name_opt.as_deref() == Some(job_name)
                || directory_matches_pkg_name(dir, job_name);
            if name_matches {
                if let Some(ref v) = ver_opt {
                    if version_matches_spec(v, job_spec) {
                        debug!(
                            "Dependency '{}@{}' satisfied by ancestor package directory {}",
                            job_name, v, dir.display()
                        );
                        return Ok(true);
                    }
                }
            }
        }

        if dir == staging_dir {
            break;
        }

        curr = dir.parent();
    }

    Ok(false)
}

/// Recursively / transitively resolves and installs production dependencies into `staging_dir/node_modules`.
pub async fn install_production_dependencies(
    client: &reqwest::Client,
    registry: &str,
    staging_dir: &Path,
    root_deps: Vec<(String, String)>,
) -> anyhow::Result<()> {
    install_production_dependencies_with_auth(client, registry, staging_dir, root_deps, None).await
}

async fn install_production_dependencies_with_auth(
    client: &reqwest::Client,
    registry: &str,
    staging_dir: &Path,
    root_deps: Vec<(String, String)>,
    auth_header: Option<&str>,
) -> anyhow::Result<()> {
    struct DepJob {
        name: String,
        spec: String,
        parent_dir: PathBuf,
    }

    let mut queue: std::collections::VecDeque<DepJob> = std::collections::VecDeque::new();
    for (name, spec) in root_deps {
        queue.push_back(DepJob {
            name,
            spec,
            parent_dir: staging_dir.to_path_buf(),
        });
    }

    let mut packument_cache: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    let mut installed_packages: std::collections::HashSet<(PathBuf, String)> = std::collections::HashSet::new();

    while let Some(job) = queue.pop_front() {
        // Walk all ancestor directories from job.parent_dir upward up to staging_dir.
        // If already satisfied -> STOP!
        if is_ancestor_satisfied(&job.name, &job.spec, &job.parent_dir, staging_dir)? {
            debug!(
                "Dependency '{}@{}' already satisfied in ancestor chain; skipping install",
                job.name, job.spec
            );
            continue;
        }

        let top_nm = staging_dir.join("node_modules");
        let top_target = package_dir_in_node_modules(&top_nm, &job.name)?;

        let target_dir = if top_target.exists() {
            // Version conflict at top level! Install nested in <job.parent_dir>/node_modules/<job.name>
            let nested_nm = job.parent_dir.join("node_modules");
            package_dir_in_node_modules(&nested_nm, &job.name)?
        } else {
            top_target
        };

        let depth = count_node_modules_depth(&target_dir, staging_dir);
        if depth > MAX_NESTING_DEPTH {
            anyhow::bail!(
                "Exceeded maximum dependency nesting depth of {} (target: '{}') while resolving '{}@{}'",
                MAX_NESTING_DEPTH,
                target_dir.display(),
                job.name,
                job.spec
            );
        }

        let key = (target_dir.clone(), job.spec.clone());
        if installed_packages.contains(&key) {
            continue;
        }
        installed_packages.insert(key);

        let packument = if let Some(cached) = packument_cache.get(&job.name) {
            cached.clone()
        } else {
            let fetched = fetch_packument(client, registry, &job.name, auth_header).await?;
            packument_cache.insert(job.name.clone(), fetched.clone());
            fetched
        };

        let (chosen_version, version_obj) = if let Some(versions) = packument.get("versions").and_then(|v| v.as_object()) {
            pick_matching_version(versions, packument.get("dist-tags"), &job.spec)
                .ok_or_else(|| anyhow::anyhow!("No matching version found for dependency '{}' satisfying '{}'", job.name, job.spec))?
        } else if packument.get("dist").is_some() {
            let v = packument
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Single-version response for dependency '{}' is missing a valid 'version' field",
                        job.name
                    )
                })?;
            if !version_matches_spec(v, &job.spec) {
                anyhow::bail!(
                    "Single-version response for dependency '{}' has version '{}', which does not satisfy '{}'",
                    job.name,
                    v,
                    job.spec
                );
            }
            (v, &packument)
        } else {
            anyhow::bail!("Invalid packument format for '{}'", job.name);
        };

        let dist = version_obj.get("dist")
            .ok_or_else(|| anyhow::anyhow!("Missing dist object for '{}@{}'", job.name, chosen_version))?;
        let tarball_url = dist.get("tarball").and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing dist.tarball for '{}@{}'", job.name, chosen_version))?;
        let full_tb_url = resolve_url(registry, tarball_url);
        let integrity_opt = dist.get("integrity").and_then(|i| i.as_str());
        let shasum_opt = dist.get("shasum").and_then(|s| s.as_str());

        debug!("Downloading dependency '{}@{}' from '{}'...", job.name, chosen_version, full_tb_url);
        let tb_resp = get_with_registry_auth(client, &full_tb_url, registry, auth_header)
            .send()
            .await?;
        if !tb_resp.status().is_success() {
            anyhow::bail!(
                "Failed to download tarball for '{}@{}' from '{}': HTTP {}",
                job.name,
                chosen_version,
                full_tb_url,
                tb_resp.status()
            );
        }
        let tb_bytes = tb_resp.bytes().await?.to_vec();

        verify_tarball_integrity(&tb_bytes, integrity_opt, shasum_opt)
            .map_err(|e| anyhow::anyhow!("Integrity check failed for dependency '{}@{}': {e}", job.name, chosen_version))?;

        unpack_tarball(&tb_bytes, &target_dir)
            .map_err(|e| anyhow::anyhow!("Failed to unpack dependency '{}@{}': {e}", job.name, chosen_version))?;

        let mut child_deps = Vec::new();
        if let Some(deps) = version_obj.get("dependencies").and_then(|d| d.as_object()) {
            for (k, v) in deps {
                child_deps.push((k.clone(), v.as_str().unwrap_or("*").to_string()));
            }
        } else {
            let pkg_json = target_dir.join("package.json");
            if let Ok(content) = std::fs::read_to_string(&pkg_json) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                        for (k, v) in deps {
                            child_deps.push((k.clone(), v.as_str().unwrap_or("*").to_string()));
                        }
                    }
                }
            }
        }

        for (child_name, child_spec) in child_deps {
            queue.push_back(DepJob {
                name: child_name,
                spec: child_spec,
                parent_dir: target_dir.clone(),
            });
        }
    }

    Ok(())
}

async fn fetch_packument(
    client: &reqwest::Client,
    registry: &str,
    pkg_name: &str,
    auth_header: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let reg_trimmed = registry.trim_end_matches('/');
    let encoded = rnpm_config::encode_package_name(pkg_name);
    let primary_url = format!("{reg_trimmed}/{encoded}");

    let mut resp = get_with_registry_auth(client, &primary_url, registry, auth_header)
        .send()
        .await?;
    if !resp.status().is_success() && pkg_name.contains('/') {
        let fallback_url = format!("{reg_trimmed}/{pkg_name}");
        if let Ok(fallback_resp) =
            get_with_registry_auth(client, &fallback_url, registry, auth_header)
                .send()
                .await
        {
            if fallback_resp.status().is_success() {
                resp = fallback_resp;
            }
        }
    }
    if !resp.status().is_success() {
        let latest_url = format!("{reg_trimmed}/{encoded}/latest");
        if let Ok(latest_resp) =
            get_with_registry_auth(client, &latest_url, registry, auth_header)
                .send()
                .await
        {
            if latest_resp.status().is_success() {
                resp = latest_resp;
            }
        }
    }
    if !resp.status().is_success() {
        anyhow::bail!(
            "Failed to fetch metadata for '{}' from registry '{}': HTTP {}",
            pkg_name,
            registry,
            resp.status()
        );
    }
    let bytes = resp.bytes().await?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse metadata JSON for '{}': {}", pkg_name, e))?;
    Ok(json)
}

fn is_valid_version_entry(key: &str, val: &serde_json::Value) -> bool {
    let key_ver = match rnpm_core::Version::parse(key) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let Some(v_val) = val.get("version") {
        let Some(v_ver) = v_val.as_str() else {
            return false;
        };
        match rnpm_core::Version::parse(v_ver) {
            Ok(v) if v == key_ver => {}
            _ => return false,
        }
    }
    true
}

pub fn pick_matching_version<'a>(
    versions: &'a serde_json::Map<String, serde_json::Value>,
    dist_tags: Option<&serde_json::Value>,
    spec: &str,
) -> Option<(&'a str, &'a serde_json::Value)> {
    let spec = spec.trim();
    // 1. Explicit empty, "*", or "latest" -> resolve latest tag or highest semver
    if spec.is_empty() || spec == "*" || spec == "latest" {
        if let Some(latest_ver) = dist_tags.and_then(|dt| dt.get("latest")).and_then(|v| v.as_str()) {
            if let Some((k, v)) = versions.get_key_value(latest_ver) {
                if is_valid_version_entry(k.as_str(), v) {
                    return Some((k.as_str(), v));
                }
            }
        }
        let mut candidates: Vec<(rnpm_core::Version, &'a str, &'a serde_json::Value)> = Vec::new();
        for (v_str, v_val) in versions {
            if is_valid_version_entry(v_str, v_val) {
                if let Ok(ver) = rnpm_core::Version::parse(v_str) {
                    candidates.push((ver, v_str.as_str(), v_val));
                }
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        return candidates.last().map(|(_, s, v)| (*s, *v));
    }

    // 2. Named dist-tag match (e.g. "next", "beta")
    if let Some(tag_ver) = dist_tags.and_then(|dt| dt.get(spec)).and_then(|v| v.as_str()) {
        if let Some((k, v)) = versions.get_key_value(tag_ver) {
            if is_valid_version_entry(k.as_str(), v) {
                return Some((k.as_str(), v));
            }
        }
    }

    // 3. Valid semver range matching
    if let Ok(range) = rnpm_core::Range::parse(spec) {
        let mut candidates: Vec<(rnpm_core::Version, &'a str, &'a serde_json::Value)> = Vec::new();
        for (v_str, v_val) in versions {
            if is_valid_version_entry(v_str, v_val) {
                if let Ok(ver) = rnpm_core::Version::parse(v_str) {
                    candidates.push((ver, v_str.as_str(), v_val));
                }
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        for (ver, s, v) in candidates.iter().rev() {
            if range.satisfies(ver) {
                return Some((*s, *v));
            }
        }
        // Valid semver range was specified, but no version in metadata satisfies it: NEVER silently fallback!
        return None;
    }

    // 4. Exact version string match fallback
    if let Some((k, v)) = versions.get_key_value(spec) {
        if is_valid_version_entry(k.as_str(), v) {
            return Some((k.as_str(), v));
        }
    }

    None
}

pub fn version_matches_spec(version_str: &str, spec: &str) -> bool {
    let version = match rnpm_core::Version::parse(version_str) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" || spec == "latest" {
        return true;
    }
    if let Ok(range) = rnpm_core::Range::parse(spec) {
        range.satisfies(&version)
    } else {
        version_str == spec
    }
}

fn get_installed_version(package_dir: &Path) -> Option<String> {
    let pkg_json = package_dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(pkg_json) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            return val.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    None
}

/// Validates that a package name is a valid npm package name and contains no path traversal
/// characters (such as `..`, `/` in unscoped names, `\`, `:`, or control characters).
pub fn validate_package_name(pkg_name: &str) -> anyhow::Result<()> {
    let trimmed = pkg_name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Package name cannot be empty");
    }
    if trimmed.len() > 214 {
        anyhow::bail!("Package name '{}' exceeds maximum allowed length of 214 characters", trimmed);
    }
    if trimmed.contains('\\') || trimmed.contains(':') || trimmed.contains('\0') {
        anyhow::bail!("Package name '{}' contains forbidden characters ('\\', ':', or null)", trimmed);
    }
    if trimmed.chars().any(|c| (c as u32) < 0x20 || "<>\"|?*".contains(c)) {
        anyhow::bail!("Package name '{}' contains forbidden filesystem or control characters", trimmed);
    }

    if let Some(scoped) = trimmed.strip_prefix('@') {
        let parts: Vec<&str> = scoped.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!(
                "Scoped package name '{}' must have exactly one '/' separating scope and package name",
                trimmed
            );
        }
        let scope = parts[0];
        let name = parts[1];
        validate_name_segment(scope, true)?;
        validate_name_segment(name, false)?;
    } else {
        if trimmed.contains('/') {
            anyhow::bail!("Unscoped package name '{}' cannot contain '/'", trimmed);
        }
        validate_name_segment(trimmed, false)?;
    }

    Ok(())
}

fn validate_name_segment(segment: &str, is_scope: bool) -> anyhow::Result<()> {
    if segment.is_empty() {
        anyhow::bail!("Package name segment cannot be empty");
    }
    if segment == "." || segment == ".." {
        anyhow::bail!("Package name segment cannot be '.' or '..'");
    }
    if segment.starts_with('.') || segment.starts_with('_') {
        anyhow::bail!("Package name segment '{}' cannot start with '.' or '_'", segment);
    }
    if !segment.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        let kind = if is_scope { "scope" } else { "package" };
        anyhow::bail!("Invalid characters in {} name '{}'", kind, segment);
    }
    Ok(())
}

/// Safely constructs and validates the directory path for `pkg_name` inside `node_modules_dir`.
/// Strictly rejects path traversal, malicious names, and escaping paths.
pub fn package_dir_in_node_modules(node_modules_dir: &Path, pkg_name: &str) -> anyhow::Result<PathBuf> {
    validate_package_name(pkg_name)?;

    let mut target = node_modules_dir.to_path_buf();
    for comp in pkg_name.split('/') {
        target.push(comp);
    }

    // Verify strict containment within node_modules_dir
    let rel = target
        .strip_prefix(node_modules_dir)
        .map_err(|_| anyhow::anyhow!("Package path '{}' escaped node_modules", pkg_name))?;

    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(_) => {}
            _ => anyhow::bail!("Invalid non-normal path component in package path: {:?}", target),
        }
    }

    Ok(target)
}

fn resolve_url(base: &str, target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        let base_trimmed = base.trim_end_matches('/');
        let target_trimmed = target.trim_start_matches('/');
        format!("{base_trimmed}/{target_trimmed}")
    }
}

/// Verifies package tarball integrity against SRI string (`dist.integrity`) or SHA-1 hex (`dist.shasum`).
/// Falls back to `dist.shasum` ONLY when `integrity` is absent. Fails if neither matches or if `dist.integrity` is missing/invalid.
pub fn verify_tarball_integrity(
    tarball_bytes: &[u8],
    integrity_opt: Option<&str>,
    shasum_opt: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(sri) = integrity_opt.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = rnpm_core::Integrity::parse(sri)
            .map_err(|e| anyhow::anyhow!("Invalid dist.integrity '{}': {}", sri, e))?;
        parsed
            .verify(tarball_bytes)
            .map_err(|e| anyhow::anyhow!("Tarball integrity mismatch for '{}': {}", sri, e))?;
        return Ok(());
    }

    if let Some(shasum) = shasum_opt.map(str::trim).filter(|s| !s.is_empty()) {
        let expected_hex = shasum.to_ascii_lowercase();
        if expected_hex.len() != 40 || !expected_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "Invalid dist.shasum '{}': expected 40-character hex string",
                shasum
            );
        }
        let actual_digest = rnpm_core::Algorithm::Sha1.compute_digest(tarball_bytes);
        let actual_hex: String = actual_digest.iter().map(|b| format!("{:02x}", b)).collect();
        if actual_hex != expected_hex {
            anyhow::bail!(
                "Tarball shasum mismatch: expected {}, got {}",
                expected_hex,
                actual_hex
            );
        }
        return Ok(());
    }

    anyhow::bail!("Package metadata missing both dist.integrity and dist.shasum; verification required");
}

/// Unpacks a gzipped tarball into the specified target directory with strict path containment,
/// rejecting directory traversal, absolute paths, Windows drive prefixes, and escaping symlinks/hardlinks.
pub fn unpack_tarball(tarball_bytes: &[u8], target_dir: &Path) -> anyhow::Result<()> {
    rnpm_fs::extract_tar_gz(std::io::Cursor::new(tarball_bytes), target_dir, None)
        .map_err(|e| anyhow::anyhow!("Tarball extraction failed: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = target_dir.join("bin");
        if bin_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&bin_dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let mut perms = meta.permissions();
                        perms.set_mode(perms.mode() | 0o755);
                        let _ = std::fs::set_permissions(entry.path(), perms);
                    }
                }
            }
        }
    }

    Ok(())
}

const NODE_GYP_CMD_SCRIPT: &str = "@ECHO off\r\nIF NOT DEFINED npm_config_node_gyp GOTO no_gyp\r\nSET \"GYP_PATH=%npm_config_node_gyp:\"=%\"\r\nIF /I \"%GYP_PATH:~-3%\"==\".js\" GOTO run_js\r\n\"%GYP_PATH%\" %*\r\nEXIT /B %ERRORLEVEL%\r\n:run_js\r\nnode \"%GYP_PATH%\" %*\r\nEXIT /B %ERRORLEVEL%\r\n:no_gyp\r\nnode \"%~dp0node-gyp.js\" %*\r\nEXIT /B %ERRORLEVEL%\r\n";
const NODE_GYP_SH_SCRIPT: &str = "#!/usr/bin/env sh\nif [ -z \"$npm_config_node_gyp\" ]; then\n  exec node \"$(dirname \"$0\")/node-gyp.js\" \"$@\"\nelse\n  case \"$npm_config_node_gyp\" in\n    *.js) exec node \"$npm_config_node_gyp\" \"$@\" ;;\n    *) exec \"$npm_config_node_gyp\" \"$@\" ;;\n  esac\nfi\n";

#[cfg(unix)]
fn is_private_owned_dir(dir: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return false;
    }
    if meta.uid() != unsafe { libc::geteuid() } {
        return false;
    }
    if (meta.mode() & 0o077) != 0 {
        if std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).is_err() {
            return false;
        }
        let Ok(rechecked) = std::fs::symlink_metadata(dir) else {
            return false;
        };
        if (rechecked.mode() & 0o077) != 0 {
            return false;
        }
    }
    true
}

fn has_valid_shim_file(path: &Path, expected: &[u8], require_exec: bool) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() != expected.len() as u64 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.uid() != unsafe { libc::geteuid() } {
            return false;
        }
        if require_exec && (meta.mode() & 0o777) != 0o755 {
            if std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).is_err() {
                return false;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = require_exec;
    std::fs::read(path).ok().as_deref() == Some(expected)
}

fn write_shim_atomic(target: &Path, content: &[u8], executable: bool) -> std::io::Result<()> {
    static NEXT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if has_valid_shim_file(target, content, executable) {
        return Ok(());
    }
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "shim path has no parent")
    })?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("node-gyp");
    let seq = NEXT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{name}.tmp.{}.{seq}", std::process::id()));
    std::fs::write(&tmp_path, content)?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    let _ = executable;

    match std::fs::rename(&tmp_path, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            if has_valid_shim_file(target, content, executable) {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Creates a dedicated private node-gyp shim directory on disk with strict private permissions
/// (0o700 for the directory, 0o755 for the POSIX shim).
pub fn create_private_node_gyp_shim(dir: &Path) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let cmd_path = dir.join("node-gyp.cmd");
    write_shim_atomic(&cmd_path, NODE_GYP_CMD_SCRIPT.as_bytes(), false)?;

    let sh_path = dir.join("node-gyp");
    write_shim_atomic(&sh_path, NODE_GYP_SH_SCRIPT.as_bytes(), true)?;

    if cfg!(windows) {
        Ok(cmd_path)
    } else {
        Ok(sh_path)
    }
}

fn is_valid_existing_shim_dir(dir: &Path) -> bool {
    #[cfg(unix)]
    if !is_private_owned_dir(dir) {
        return false;
    }
    #[cfg(not(unix))]
    if !dir.is_dir() {
        return false;
    }
    has_valid_shim_file(&dir.join("node-gyp.cmd"), NODE_GYP_CMD_SCRIPT.as_bytes(), false)
        && has_valid_shim_file(&dir.join("node-gyp"), NODE_GYP_SH_SCRIPT.as_bytes(), true)
}

/// Prepares and returns a dedicated privately-owned directory containing standalone `node-gyp` shims
/// (`node-gyp.cmd` on Windows and `node-gyp` on Unix) that forward to `%npm_config_node_gyp%`.
pub fn node_gyp_bin_dir() -> Option<PathBuf> {
    static BIN_DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    BIN_DIR
        .get_or_init(|| {
            #[cfg(unix)]
            let mut dir = std::env::temp_dir().join(format!("rnpm-node-gyp-bin-v1-{}", unsafe { libc::geteuid() }));
            #[cfg(not(unix))]
            let dir = std::env::temp_dir().join("rnpm-node-gyp-bin-v1");
            if is_valid_existing_shim_dir(&dir) {
                return Some(dir);
            }

            if let Err(e) = std::fs::create_dir_all(&dir) {
                warn!("Failed to create private node-gyp-bin directory: {}", e);
                return None;
            }
            #[cfg(unix)]
            if !is_private_owned_dir(&dir) {
                dir = std::env::temp_dir().join(format!(
                    "rnpm-node-gyp-bin-v1-{}-{}",
                    unsafe { libc::geteuid() },
                    std::process::id()
                ));
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    warn!("Failed to create fallback node-gyp-bin directory: {}", e);
                    return None;
                }
            }
            if let Err(e) = create_private_node_gyp_shim(&dir) {
                warn!("Failed to populate private node-gyp-bin directory: {}", e);
                return None;
            }

            Some(dir)
        })
        .clone()
}
