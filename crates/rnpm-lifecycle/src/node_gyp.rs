use crate::error::LifecycleError;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

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

    // c. Standalone node-gyp on PATH
    let path_var = std::env::var_os("PATH").or_else(|| std::env::var_os("Path")).unwrap_or_default();
    for p in std::env::split_paths(&path_var) {
        let s = p.to_string_lossy().to_ascii_lowercase();
        // Skip npm's bundled node-gyp-bin or npm node_modules so we don't confuse bundled with standalone
        if s.contains("node_modules\\npm")
            || s.contains("node_modules/npm")
            || s.contains("npm\\bin\\node-gyp-bin")
            || s.contains("npm/bin/node-gyp-bin")
        {
            continue;
        }
        if cfg!(windows) {
            for ext in ["cmd", "exe", "bat"] {
                let candidate = p.join(format!("node-gyp.{ext}"));
                if candidate.is_file() {
                    debug!("Resolved standalone node-gyp on PATH: {}", candidate.display());
                    return Some(candidate);
                }
            }
        }
        let candidate = p.join("node-gyp");
        if candidate.is_file() {
            debug!("Resolved standalone node-gyp on PATH: {}", candidate.display());
            return Some(candidate);
        }
    }

    // d. rnpm's own cached standalone node-gyp directory (<cache>/node-gyp/current/bin/node-gyp.js)
    let cache_dir = find_cache_dir(project_root, config);
    let cached_candidates = [
        cache_dir.join("node-gyp").join("current").join("bin").join("node-gyp.js"),
        cache_dir.join("node-gyp").join("current").join("node-gyp.js"),
        cache_dir.join("node-gyp").join("bin").join("node-gyp.js"),
    ];
    for candidate in cached_candidates {
        if candidate.is_file() {
            debug!("Resolved node-gyp via cached standalone directory: {}", candidate.display());
            return Some(candidate);
        }
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
        if let Some(gyp) = crate::node_executable()
            .and_then(|n| n.parent().map(Path::to_path_buf))
            .map(|d| {
                if cfg!(windows) {
                    d.join("node_modules")
                } else {
                    d.join("..").join("lib").join("node_modules")
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
        {
            debug!("Resolved node-gyp via bundled npm fallback: {}", gyp.display());
            return Some(gyp);
        }
    }

    None
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

/// Downloads and unpacks node-gyp from the configured npm registry into `<cache_dir>/node-gyp/current/`.
pub fn bootstrap_node_gyp(
    project_root: &Path,
    config: &rnpm_config::Config,
) -> anyhow::Result<PathBuf> {
    let cache_dir = find_cache_dir(project_root, config);
    let target_dir = cache_dir.join("node-gyp").join("current");
    let registry = find_registry(config);

    // Run async network operations on a dedicated thread with a fresh single-thread runtime
    // to guarantee no nested block_on conflicts with existing tokio runtimes.
    let target_clone = target_dir.clone();
    let reg_clone = registry.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            download_and_unpack_node_gyp(&reg_clone, &target_clone).await
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Worker thread panicked during node-gyp bootstrap"))??;

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

async fn download_and_unpack_node_gyp(registry: &str, target_dir: &Path) -> anyhow::Result<()> {
    let mut builder = reqwest::Client::builder();
    if registry.contains("127.0.0.1") || registry.contains("localhost") {
        builder = builder.no_proxy();
    }
    let client = builder.build()?;
    let reg_trimmed = registry.trim_end_matches('/');

    // 1. Fetch metadata or tarball from registry
    let node_gyp_url = format!("{reg_trimmed}/node-gyp");
    let mut resp = client.get(&node_gyp_url).send().await?;
    if !resp.status().is_success() {
        // Try /latest endpoint
        let latest_url = format!("{reg_trimmed}/node-gyp/latest");
        let latest_resp = client.get(&latest_url).send().await?;
        if latest_resp.status().is_success() {
            resp = latest_resp;
        } else {
            anyhow::bail!(
                "Failed to fetch node-gyp from registry at '{}': HTTP {}",
                node_gyp_url,
                resp.status()
            );
        }
    }

    let initial_bytes = resp.bytes().await?;

    let tarball_bytes = if initial_bytes.starts_with(&[0x1f, 0x8b]) {
        // Mock registry or endpoint returned tarball directly
        initial_bytes.to_vec()
    } else {
        // Parsed JSON metadata (packument or version document)
        let json: serde_json::Value = serde_json::from_slice(&initial_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse node-gyp registry response as JSON: {e}"))?;

        let tarball_url = if let Some(tb) = json.get("dist").and_then(|d| d.get("tarball")).and_then(|t| t.as_str()) {
            tb.to_string()
        } else if let Some(latest) = json.get("dist-tags").and_then(|d| d.get("latest")).and_then(|l| l.as_str()) {
            json.get("versions")
                .and_then(|v| v.get(latest))
                .and_then(|m| m.get("dist"))
                .and_then(|d| d.get("tarball"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{reg_trimmed}/node-gyp/-/node-gyp-{latest}.tgz"))
        } else if let Some(versions) = json.get("versions").and_then(|v| v.as_object()) {
            versions
                .values()
                .next_back()
                .and_then(|m| m.get("dist"))
                .and_then(|d| d.get("tarball"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{reg_trimmed}/node-gyp/-/node-gyp.tgz"))
        } else {
            format!("{reg_trimmed}/node-gyp/-/node-gyp.tgz")
        };

        info!("Downloading node-gyp tarball from '{}'...", tarball_url);
        let tb_resp = client.get(&tarball_url).send().await?;
        if !tb_resp.status().is_success() {
            anyhow::bail!(
                "Failed to download node-gyp tarball from '{}': HTTP {}",
                tarball_url,
                tb_resp.status()
            );
        }
        tb_resp.bytes().await?.to_vec()
    };

    // 2. Unpack tarball into target directory
    unpack_tarball(&tarball_bytes, target_dir)
}

/// Unpacks a gzipped tarball into the specified target directory, stripping the `package/` prefix.
pub fn unpack_tarball(tarball_bytes: &[u8], target_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(target_dir)?;
    let gz = flate2::read::GzDecoder::new(tarball_bytes);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let relative = if let Ok(stripped) = path.strip_prefix("package") {
            stripped.to_path_buf()
        } else {
            path
        };

        if relative.as_os_str().is_empty() {
            continue;
        }

        let out_path = target_dir.join(&relative);
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&out_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let rel_str = relative.to_string_lossy().replace('\\', "/");
                if rel_str.starts_with("bin/") || rel_str == "bin" {
                    let _ = std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755));
                }
            }
        }
    }

    Ok(())
}

/// Prepares and returns a dedicated directory containing standalone `node-gyp` shims
/// (`node-gyp.cmd` on Windows and `node-gyp` on Unix) that forward to `%npm_config_node_gyp%`.
pub fn node_gyp_bin_dir() -> Option<PathBuf> {
    static BIN_DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    BIN_DIR
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("rnpm").join("node-gyp-bin");
            if let Err(e) = std::fs::create_dir_all(&dir) {
                warn!("Failed to create node-gyp-bin directory: {}", e);
                return None;
            }

            let cmd_path = dir.join("node-gyp.cmd");
            let cmd_script = "@ECHO off\r\nIF NOT DEFINED npm_config_node_gyp GOTO no_gyp\r\nSET \"GYP_PATH=%npm_config_node_gyp:\"=%\"\r\nIF /I \"%GYP_PATH:~-3%\"==\".js\" GOTO run_js\r\n\"%GYP_PATH%\" %*\r\nEXIT /B %ERRORLEVEL%\r\n:run_js\r\nnode \"%GYP_PATH%\" %*\r\nEXIT /B %ERRORLEVEL%\r\n:no_gyp\r\nnode \"%~dp0node-gyp.js\" %*\r\nEXIT /B %ERRORLEVEL%\r\n";
            let _ = std::fs::write(&cmd_path, cmd_script);

            let sh_path = dir.join("node-gyp");
            let sh_script = "#!/usr/bin/env sh\nif [ -z \"$npm_config_node_gyp\" ]; then\n  exec node \"$(dirname \"$0\")/node-gyp.js\" \"$@\"\nelse\n  case \"$npm_config_node_gyp\" in\n    *.js) exec node \"$npm_config_node_gyp\" \"$@\" ;;\n    *) exec \"$npm_config_node_gyp\" \"$@\" ;;\n  esac\nfi\n";
            let _ = std::fs::write(&sh_path, sh_script);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&sh_path, std::fs::Permissions::from_mode(0o755));
            }

            Some(dir)
        })
        .clone()
}
