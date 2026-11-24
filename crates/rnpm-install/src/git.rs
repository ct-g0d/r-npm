//! Git dependency fetching, commit resolution, caching, and extraction for rnpm.
//!
//! Implements cloning/fetching via git into `<cache_dir>/_git-remotes/<hash>`,
//! checkout/unpacking of committish/branch/tag/sha into `<cache_dir>/_git-checkouts/<hash>/<commit_sha>`,
//! commit SHA resolution for locking and provenance, reading package.json,
//! offline mode handling, and graceful error reporting.

use anyhow::{anyhow, Context, Result};
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_core::spec::PackageTarget;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Result of resolving and checking out a git dependency.
#[derive(Debug, Clone)]
pub struct GitResolved {
    pub commit_sha: String,
    pub resolved_url: String,
    pub checkout_dir: PathBuf,
    pub manifest: Manifest,
}

/// Git remote cache and fetcher.
#[derive(Debug, Clone)]
pub struct GitFetcher {
    cache_dir: PathBuf,
}

impl GitFetcher {
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            cache_dir: cache_dir.to_path_buf(),
        }
    }

    /// Resolve a Git dependency target:
    /// 1. Clones or fetches the remote repo into `<cache_dir>/_git-remotes/<hash>`
    /// 2. Resolves the requested committish/tag/branch/semver to a concrete commit SHA
    /// 3. Checks out or unpacks the tree into `<cache_dir>/_git-checkouts/<hash>/<commit_sha>`
    /// 4. Reads and validates `package.json`
    /// 5. Produces the canonical locked resolved URL (e.g. `git+https://...#<commit_sha>`)
    pub async fn resolve_git_dependency(
        &self,
        target: &PackageTarget,
        offline: bool,
    ) -> Result<GitResolved> {
        let clone_url = target
            .git_clone_url()
            .ok_or_else(|| anyhow!("Target is not a valid git dependency"))?;
        let committish = target.git_committish();

        let remote_dir = self.fetch_or_clone(&clone_url, offline).await?;
        let commit_sha = self
            .resolve_commit_sha(&remote_dir, committish, &clone_url, offline)
            .await?;
        let root_checkout_dir = self
            .checkout_tree(&remote_dir, &commit_sha, &clone_url)
            .await?;

        let checkout_dir = if let Some(subdir) = target.git_subdir() {
            resolve_git_subdir(&root_checkout_dir, subdir)?
        } else {
            root_checkout_dir
        };

        let manifest_path = checkout_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!(
                "package.json not found in git dependency '{}' at commit '{}'",
                clone_url,
                commit_sha
            ));
        }

        let manifest = Manifest::from_file(&manifest_path).with_context(|| {
            format!(
                "Failed to parse package.json from git dependency '{}' at '{}'",
                clone_url,
                manifest_path.display()
            )
        })?;

        let resolved_url = format_git_resolved_url(target, &commit_sha);

        Ok(GitResolved {
            commit_sha,
            resolved_url,
            checkout_dir,
            manifest,
        })
    }

    /// Checkout a git dependency for an already locked target (e.g. during `rnpm ci`).
    pub async fn checkout_git_dependency(
        &self,
        target: &PackageTarget,
        offline: bool,
    ) -> Result<PathBuf> {
        let clone_url = target
            .git_clone_url()
            .ok_or_else(|| anyhow!("Target is not a valid git dependency"))?;
        let committish = target.git_committish();

        let remote_dir = self.fetch_or_clone(&clone_url, offline).await?;
        let commit_sha = self
            .resolve_commit_sha(&remote_dir, committish, &clone_url, offline)
            .await?;
        let root_checkout_dir = self
            .checkout_tree(&remote_dir, &commit_sha, &clone_url)
            .await?;

        let checkout_dir = if let Some(subdir) = target.git_subdir() {
            resolve_git_subdir(&root_checkout_dir, subdir)?
        } else {
            root_checkout_dir
        };

        let manifest_path = checkout_dir.join("package.json");
        if !manifest_path.exists() {
            return Err(anyhow!(
                "package.json not found in git dependency '{}' at commit '{}'",
                clone_url,
                commit_sha
            ));
        }

        Ok(checkout_dir)
    }

    /// Computes the remote cache directory for a given clone URL:
    /// `<cache_dir>/_git-remotes/<hash>` (using a short 16-hex-char hash to prevent Windows MAX_PATH issues).
    pub fn remote_repo_dir(&self, clone_url: &str) -> PathBuf {
        let hash = format!("{:x}", Sha256::digest(clone_url.as_bytes()));
        self.cache_dir.join("_git-remotes").join(&hash[..16])
    }

    /// Computes the checkout cache directory for a given clone URL and commit SHA:
    /// `<cache_dir>/_git-checkouts/<hash>/<commit_sha>` (using shortened keys to prevent Windows MAX_PATH issues).
    pub fn checkout_cache_dir(&self, clone_url: &str, commit_sha: &str) -> PathBuf {
        let hash = format!("{:x}", Sha256::digest(clone_url.as_bytes()));
        let short_sha = if commit_sha.len() > 16 {
            &commit_sha[..16]
        } else {
            commit_sha
        };
        self.cache_dir
            .join("_git-checkouts")
            .join(&hash[..16])
            .join(short_sha)
    }

    /// Fetches or clones the remote git repository into `<cache_dir>/_git-remotes/<hash>`.
    pub async fn fetch_or_clone(&self, clone_url: &str, offline: bool) -> Result<PathBuf> {
        let remote_dir = self.remote_repo_dir(clone_url);
        let normalized_url = normalize_clone_url_for_git(clone_url);

        if remote_dir.exists() {
            if offline {
                debug!(
                    "Using cached git repository for '{}' (offline mode)",
                    clone_url
                );
                return Ok(remote_dir);
            }

            debug!("Updating cached git repository for '{}'", clone_url);
            let remote_dir_str = remote_dir.to_string_lossy();
            let (fetch_ok, _, fetch_err) = run_git_cmd(
                &[
                    "--git-dir",
                    &remote_dir_str,
                    "fetch",
                    "--prune",
                    "--tags",
                    "origin",
                    "+refs/*:refs/*",
                ],
                None,
            )
            .await?;

            if !fetch_ok {
                warn!(
                    "Failed to fetch updates for git repository '{}': {}; continuing with cached refs",
                    clone_url, fetch_err
                );
            }

            return Ok(remote_dir);
        }

        if offline {
            return Err(anyhow!(
                "Cannot clone git dependency '{}' in offline mode: repository is not cached",
                clone_url
            ));
        }

        // pacote resolves the remote refs before attempting a clone. Preserve
        // that command's stderr and status rather than reporting clone errors.
        let ls_remote_url =
            if clone_url.starts_with("file://") || clone_url.starts_with("git+file://") {
                clone_url.strip_prefix("git+").unwrap_or(clone_url).to_string()
            } else {
                normalized_url.clone()
            };
        let args = ["--no-replace-objects", "ls-remote", &ls_remote_url];
        let output = match tokio::process::Command::new("git")
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "")
            .env("SSH_ASKPASS", "")
            .output()
            .await
        {
            Ok(out) => out,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(anyhow!(
                        "npm error code ENOENT\nnpm error syscall spawn git\nnpm error path git\nnpm error spawn git ENOENT"
                    ));
                }
                return Err(e.into());
            }
        };

        if !output.status.success() {
            let scrubbed_url = rnpm_config::scrub_credentials(&ls_remote_url);
            let display_args: Vec<_> = args
                .iter()
                .map(|a| {
                    if *a == ls_remote_url.as_str() || *a == normalized_url.as_str() || *a == clone_url {
                        scrubbed_url.as_str()
                    } else {
                        *a
                    }
                })
                .collect();
            let mut block = format!(
                "npm error code {}\nnpm error An unknown git error occurred\nnpm error command git {}",
                output.status.code().unwrap_or(128),
                display_args.join(" ")
            );
            let raw_stderr = String::from_utf8_lossy(&output.stderr);
            let scrubbed_stderr = rnpm_config::scrub_credentials(&raw_stderr);
            for line in scrubbed_stderr.trim().lines() {
                block.push_str("\nnpm error");
                if !line.is_empty() {
                    block.push(' ');
                    block.push_str(line);
                }
            }
            return Err(anyhow!(block));
        }

        if let Some(parent) = remote_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Cloning git repository '{}'", rnpm_config::scrub_credentials(clone_url));
        let remote_dir_str = remote_dir.to_string_lossy();

        // 1. Try mirror clone
        let mirror_args = build_git_clone_args(&normalized_url, &remote_dir_str, true);
        let (mirror_ok, _, mirror_err) = run_git_cmd(&mirror_args, None).await?;

        if mirror_ok {
            return Ok(remote_dir);
        }

        // 2. Fallback to bare clone if mirror fails
        let _ = safe_remove_dir_all(&remote_dir);
        let bare_args = build_git_clone_args(&normalized_url, &remote_dir_str, false);
        let (bare_ok, _, bare_err) = run_git_cmd(&bare_args, None).await?;

        if bare_ok {
            return Ok(remote_dir);
        }

        let _ = safe_remove_dir_all(&remote_dir);
        let err_msg = if !mirror_err.is_empty() {
            mirror_err
        } else {
            bare_err
        };
        let scrubbed_err = rnpm_config::scrub_credentials(&err_msg);
        let scrubbed_clone = rnpm_config::scrub_credentials(clone_url);
        Err(anyhow!(
            "Failed to clone git repository '{}': {}",
            scrubbed_clone,
            scrubbed_err
        ))
    }

    /// Resolves committish / branch / tag / SHA to a full hexadecimal commit SHA.
    pub async fn resolve_commit_sha(
        &self,
        remote_dir: &Path,
        committish: Option<&str>,
        clone_url: &str,
        offline: bool,
    ) -> Result<String> {
        let remote_dir_str = remote_dir.to_string_lossy();

        // 1. Default to HEAD when committish is omitted or "HEAD"
        let committish_clean = committish.map(|s| s.trim()).filter(|s| !s.is_empty());
        let ref_name = match committish_clean {
            None | Some("HEAD") => {
                let (ok, stdout, _) = run_git_cmd(
                    &["--git-dir", &remote_dir_str, "rev-parse", "HEAD^{commit}"],
                    None,
                )
                .await?;
                if ok && is_valid_hex_sha(&stdout) {
                    return Ok(stdout);
                }

                // Fallback to main or master
                for fallback_ref in &["refs/heads/main^{commit}", "refs/heads/master^{commit}"] {
                    let (ok, stdout, _) = run_git_cmd(
                        &["--git-dir", &remote_dir_str, "rev-parse", fallback_ref],
                        None,
                    )
                    .await?;
                    if ok && is_valid_hex_sha(&stdout) {
                        return Ok(stdout);
                    }
                }

                return Err(anyhow!(
                    "Failed to resolve default HEAD commit in git repository '{}'",
                    clone_url
                ));
            }
            Some(r) => r,
        };

        // 2. Semver range over tags: e.g. semver:^1.0.0
        if let Some(range_str) = ref_name.strip_prefix("semver:") {
            let range = Range::parse(range_str.trim()).map_err(|e| {
                anyhow!("Invalid semver range '{range_str}' in git dependency '{clone_url}': {e}")
            })?;

            let (ok, stdout, stderr) =
                run_git_cmd(&["--git-dir", &remote_dir_str, "tag", "-l"], None).await?;

            if !ok {
                return Err(anyhow!(
                    "Failed to list tags in git repository '{}': {}",
                    clone_url,
                    stderr
                ));
            }

            let mut matching_tags: Vec<(Version, String)> = Vec::new();
            for line in stdout.lines() {
                let tag = line.trim();
                if tag.is_empty() {
                    continue;
                }
                let clean_tag = tag
                    .strip_prefix('v')
                    .or_else(|| tag.strip_prefix('V'))
                    .unwrap_or(tag);
                if let Ok(ver) = clean_tag.parse::<Version>() {
                    if range.satisfies(&ver) {
                        matching_tags.push((ver, tag.to_string()));
                    }
                }
            }

            if matching_tags.is_empty() {
                return Err(anyhow!(
                    "No matching git tag found for semver range '{}' in '{}'",
                    range_str,
                    clone_url
                ));
            }

            matching_tags.sort_by(|a, b| a.0.cmp(&b.0));
            let (_, best_tag) = matching_tags.last().unwrap();
            let tag_ref = format!("refs/tags/{best_tag}^{{commit}}");
            let (ok, sha, stderr) =
                run_git_cmd(&["--git-dir", &remote_dir_str, "rev-parse", &tag_ref], None).await?;

            if ok && is_valid_hex_sha(&sha) {
                return Ok(sha);
            }

            return Err(anyhow!(
                "Failed to resolve commit for git tag '{}' in '{}': {}",
                best_tag,
                clone_url,
                stderr
            ));
        }

        // 3. Concrete branch, tag, or commit SHA
        let candidates = [
            format!("{ref_name}^{{commit}}"),
            format!("refs/tags/{ref_name}^{{commit}}"),
            format!("refs/heads/{ref_name}^{{commit}}"),
            format!("refs/remotes/origin/{ref_name}^{{commit}}"),
            ref_name.to_string(),
        ];

        for candidate in &candidates {
            let (ok, sha, _) = run_git_cmd(
                &["--git-dir", &remote_dir_str, "rev-parse", candidate],
                None,
            )
            .await?;
            if ok && is_valid_hex_sha(&sha) {
                return Ok(sha);
            }
        }

        // 4. If ref not found locally and not offline, try fetching that ref from remote
        if !offline {
            let _ = run_git_cmd(
                &["--git-dir", &remote_dir_str, "fetch", "origin", ref_name],
                None,
            )
            .await;

            for candidate in &candidates {
                let (ok, sha, _) = run_git_cmd(
                    &["--git-dir", &remote_dir_str, "rev-parse", candidate],
                    None,
                )
                .await?;
                if ok && is_valid_hex_sha(&sha) {
                    return Ok(sha);
                }
            }
        }

        Err(anyhow!(
            "Git ref, tag, or commit '{}' not found in repository '{}'",
            ref_name,
            clone_url
        ))
    }

    /// Check out or unpack the tree at `commit_sha` into `<cache_dir>/_git-checkouts/<hash>/<commit_sha>`.
    pub async fn checkout_tree(
        &self,
        remote_dir: &Path,
        commit_sha: &str,
        clone_url: &str,
    ) -> Result<PathBuf> {
        let checkout_dir = self.checkout_cache_dir(clone_url, commit_sha);
        let marker_file = checkout_marker_file(&checkout_dir);
        let done_marker = checkout_dir.with_extension("done");
        let legacy_marker = checkout_dir.join(".rnpm_checkout_done");

        if (marker_file.exists()
            || done_marker.exists()
            || checkout_dir.join("package.json").exists())
            && !checkout_dir.join(".gitmodules").is_file()
        {
            if legacy_marker.exists() {
                let _ = std::fs::remove_file(&legacy_marker);
            }
            debug!(
                "Reusing existing checkout for commit {} at '{}'",
                commit_sha,
                checkout_dir.display()
            );
            return Ok(checkout_dir);
        } else if marker_file.exists() || done_marker.exists() {
            if legacy_marker.exists() {
                let _ = std::fs::remove_file(&legacy_marker);
            }
            debug!(
                "Reusing existing checkout for commit {} at '{}'",
                commit_sha,
                checkout_dir.display()
            );
            return Ok(checkout_dir);
        }

        std::fs::create_dir_all(&checkout_dir).with_context(|| {
            format!(
                "Failed to create git checkout directory '{}'",
                checkout_dir.display()
            )
        })?;

        let is_file_proto = is_file_or_local_git_url(clone_url);

        // 1. Preferred method: git archive (clean, fast, no .git directory overhead)
        let archive_bytes = run_git_archive(remote_dir, commit_sha).await;
        if let Ok(bytes) = archive_bytes {
            let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
            if archive.unpack(&checkout_dir).is_ok()
                && !checkout_dir.join(".gitmodules").is_file()
                && checkout_dir.join("package.json").exists()
            {
                let _ = remove_all_git_metadata(&checkout_dir);
                let _ = std::fs::File::create(&marker_file);
                let _ = std::fs::remove_file(checkout_dir.join(".rnpm_checkout_done"));
                return Ok(checkout_dir);
            }
        }

        // If submodules are present or archive failed, do clone/checkout
        let _ = safe_remove_dir_all(&checkout_dir);
        std::fs::create_dir_all(&checkout_dir)?;

        let remote_dir_str = remote_dir.to_string_lossy();
        let checkout_dir_str = checkout_dir.to_string_lossy();

        let mut clone_args = vec!["-c", "core.longpaths=true"];
        if is_file_proto {
            clone_args.push("-c");
            clone_args.push("protocol.file.allow=always");
        }
        clone_args.extend_from_slice(&[
            "clone",
            "--shared",
            &remote_dir_str,
            &checkout_dir_str,
        ]);

        let (clone_ok, _, _clone_err) = run_git_cmd(&clone_args, None).await?;
        if !clone_ok {
            // Fallback to work-tree checkout if clone --shared fails
            let (checkout_ok, _, checkout_err) = run_git_cmd(
                &[
                    "-c",
                    "core.bare=false",
                    "--git-dir",
                    &remote_dir_str,
                    "--work-tree",
                    &checkout_dir_str,
                    "checkout",
                    "-f",
                    commit_sha,
                ],
                None,
            )
            .await?;

            if !checkout_ok {
                let _ = safe_remove_dir_all(&checkout_dir);
                let _ = std::fs::remove_file(&marker_file);
                return Err(anyhow!(
                    "Failed to checkout git commit '{}' from '{}': {}",
                    commit_sha,
                    rnpm_config::scrub_credentials(clone_url),
                    rnpm_config::scrub_credentials(&checkout_err)
                ));
            }
        } else {
            let (co_ok, _, co_err) = run_git_cmd(
                &["checkout", "-f", commit_sha],
                Some(&checkout_dir),
            )
            .await?;
            if !co_ok {
                let _ = safe_remove_dir_all(&checkout_dir);
                let _ = std::fs::remove_file(&marker_file);
                return Err(anyhow!(
                    "Failed to checkout commit '{}' in '{}': {}",
                    commit_sha,
                    rnpm_config::scrub_credentials(clone_url),
                    rnpm_config::scrub_credentials(&co_err)
                ));
            }
        }

        // Initialize and update submodules recursively if .gitmodules exists
        if checkout_dir.join(".gitmodules").is_file() {
            let mut subm_args = Vec::new();
            if is_file_proto {
                subm_args.push("-c");
                subm_args.push("protocol.file.allow=always");
            }
            subm_args.extend_from_slice(&[
                "submodule",
                "update",
                "--init",
                "--recursive",
            ]);

            let (subm_ok, _, subm_err) = run_git_cmd(&subm_args, Some(&checkout_dir)).await?;
            if !subm_ok {
                let _ = safe_remove_dir_all(&checkout_dir);
                let _ = std::fs::remove_file(&marker_file);
                return Err(anyhow!(
                    "Failed to update git submodules for '{}' at commit '{}': {}",
                    rnpm_config::scrub_credentials(clone_url),
                    commit_sha,
                    rnpm_config::scrub_credentials(&subm_err)
                ));
            }
        }

        // Clean all .git metadata from checkout tree so none leaks into node_modules
        remove_all_git_metadata(&checkout_dir)?;

        // Mark checkout complete outside the package tree
        let _ = std::fs::File::create(&marker_file);
        let _ = std::fs::remove_file(checkout_dir.join(".rnpm_checkout_done"));

        Ok(checkout_dir)
    }
}

/// Validates that a git dependency subdir stays inside the checkout root
/// (rejecting `..` or absolute path traversal), and returns the resolved directory path.
pub fn resolve_git_subdir(root: &Path, subdir: &str) -> Result<PathBuf> {
    let trimmed = subdir.trim();
    if trimmed.is_empty() {
        return Ok(root.to_path_buf());
    }

    let normalized_str = trimmed.replace('\\', "/");
    let clean_str = normalized_str.trim_matches('/');

    let subpath = Path::new(clean_str);
    if subpath.is_absolute()
        || normalized_str.starts_with('/')
        || normalized_str.starts_with('\\')
        || (normalized_str.len() >= 2 && normalized_str.as_bytes()[1] == b':')
    {
        return Err(anyhow!(
            "Path traversal rejected: git subdir '{}' is an absolute path",
            subdir
        ));
    }

    for component in subpath.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(anyhow!(
                    "Path traversal rejected: git subdir '{}' contains directory traversal ('..')",
                    subdir
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(anyhow!(
                    "Path traversal rejected: git subdir '{}' is an absolute path",
                    subdir
                ));
            }
            _ => {}
        }
    }

    let target_path = root.join(subpath);
    let cleaned_target = path_clean::clean(&target_path);
    let cleaned_root = path_clean::clean(root);
    if !cleaned_target.starts_with(&cleaned_root) {
        return Err(anyhow!(
            "Path traversal rejected: git subdir '{}' escapes checkout root",
            subdir
        ));
    }

    Ok(target_path)
}

/// Formats canonical locked resolved URL for lockfile v3.
pub fn format_git_resolved_url(target: &PackageTarget, commit_sha: &str) -> String {
    let base = match target {
        PackageTarget::Git { url, .. } => {
            if let Some(rest) = url.strip_prefix("github:") {
                let repo = rest.trim_end_matches(".git");
                format!("git+ssh://git@github.com/{repo}.git#{commit_sha}")
            } else if url.starts_with("git://") {
                format!("git+{url}#{commit_sha}")
            } else if let Some(idx) = url.find("github.com/") {
                let repo = url[idx + "github.com/".len()..].trim_end_matches(".git");
                format!("git+ssh://git@github.com/{repo}.git#{commit_sha}")
            } else if let Some(rest) = url.strip_prefix("gitlab:") {
                let repo = rest.trim_end_matches(".git");
                format!("git+https://gitlab.com/{repo}.git#{commit_sha}")
            } else if let Some(rest) = url.strip_prefix("bitbucket:") {
                let repo = rest.trim_end_matches(".git");
                format!("git+https://bitbucket.org/{repo}.git#{commit_sha}")
            } else if url.starts_with("git+") {
                format!("{url}#{commit_sha}")
            } else {
                format!("git+{url}#{commit_sha}")
            }
        }
        _ => format!("git#{commit_sha}"),
    };
    if let Some(subdir) = target.git_subdir() {
        format!("{base}::path:{subdir}")
    } else {
        base
    }
}

/// Normalizes clone URL for git command execution on current platform.
pub fn normalize_clone_url_for_git(url: &str) -> String {
    let clean = url.strip_prefix("git+").unwrap_or(url);
    if let Some(rest) = clean.strip_prefix("github:") {
        let repo = rest.trim_end_matches(".git");
        return format!("https://github.com/{repo}.git");
    }
    if clean.starts_with("file://") {
        if let Ok(path) = url::Url::parse(clean).and_then(|u| {
            u.to_file_path()
                .map_err(|_| url::ParseError::RelativeUrlWithoutBase)
        }) {
            return path.to_string_lossy().replace('\\', "/");
        }
    }
    if let Some(rest) = clean.strip_prefix("file://") {
        let rest_trimmed = rest.trim_start_matches('/');
        // If it starts with Windows drive letter (e.g. C: or D:)
        if rest_trimmed.len() >= 2 && rest_trimmed.chars().nth(1) == Some(':') {
            return rest_trimmed.replace('\\', "/");
        }
        #[cfg(windows)]
        {
            if rest.contains(':') {
                return rest.replace('\\', "/");
            }
        }
        #[cfg(not(windows))]
        {
            return format!("/{rest_trimmed}");
        }
    }
    clean.to_string()
}

/// Returns true if the git URL or path refers to a local repository or file:// protocol.
pub fn is_file_or_local_git_url(url: &str) -> bool {
    let trimmed = url.trim();
    let clean = if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("git+"))
    {
        &trimmed[4..]
    } else {
        trimmed
    };
    if clean
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("file:"))
    {
        return true;
    }
    if clean.starts_with("./")
        || clean.starts_with("../")
        || clean.starts_with(".\\")
        || clean.starts_with("..\\")
        || clean.starts_with('/')
        || clean.starts_with('\\')
    {
        return true;
    }
    let bytes = clean.as_bytes();
    if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    Path::new(clean).is_absolute()
}

/// Builds the argument list for git clone.
///
/// Passes `-c protocol.file.allow=always` only when the clone URL is a local or file-based repository.
/// For remote repositories (https://, http://, ssh://, git://), this option is omitted to prevent CVE-2022-39253 file protocol abuse.
pub fn build_git_clone_args<'a>(
    clone_url: &'a str,
    target_dir: &'a str,
    mirror: bool,
) -> Vec<&'a str> {
    let mut args = Vec::new();
    if is_file_or_local_git_url(clone_url) {
        args.push("-c");
        args.push("protocol.file.allow=always");
    }
    args.push("clone");
    args.push("--config");
    args.push("core.longpaths=true");
    if mirror {
        args.push("--mirror");
    } else {
        args.push("--bare");
    }
    args.push(clone_url);
    args.push(target_dir);
    args
}

/// Path to the checkout marker file, placed as a sibling to the checkout directory
/// so that it never leaks into the checked-out package contents.
pub fn checkout_marker_file(checkout_dir: &Path) -> PathBuf {
    if let (Some(parent), Some(name)) = (checkout_dir.parent(), checkout_dir.file_name()) {
        parent.join(format!("{}.rnpm_checkout_done", name.to_string_lossy()))
    } else {
        checkout_dir.with_extension("rnpm_checkout_done")
    }
}

/// Recursively removes all `.git` directories and `.git` files (such as those created by git submodules)
/// and any internal checkout markers from a checkout tree.
pub fn remove_all_git_metadata(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let mut dirs_to_visit = vec![root.to_path_buf()];
    while let Some(current) = dirs_to_visit.pop() {
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let path = entry.path();
                if name == ".git" {
                    if path.is_dir() {
                        let _ = safe_remove_dir_all(&path);
                    } else {
                        let _ = std::fs::remove_file(&path);
                    }
                } else if name == ".rnpm_checkout_done" {
                    let _ = std::fs::remove_file(&path);
                } else if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        dirs_to_visit.push(path);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Raw recursive directory copy that skips `.git` files/directories and `.rnpm_checkout_done`.
pub fn copy_dir_all_raw(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory '{}'", dst.display()))?;

    for entry in std::fs::read_dir(src)
        .with_context(|| format!("Failed to read directory '{}'", src.display()))?
    {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name == ".git" || file_name == ".rnpm_checkout_done" {
            continue;
        }
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(&file_name);
        if ty.is_dir() {
            copy_dir_all_raw(&from, &to)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            {
                let link_target = std::fs::read_link(&from)?;
                let _ = std::os::unix::fs::symlink(&link_target, &to);
            }
            #[cfg(windows)]
            {
                let _ = std::fs::copy(&from, &to);
            }
        } else {
            std::fs::copy(&from, &to).with_context(|| {
                format!("Failed to copy '{}' -> '{}'", from.display(), to.display())
            })?;
        }
    }
    Ok(())
}

fn copy_pack_files_to_dest(source_dir: &Path, manifest: &Manifest, dst: &Path) -> Result<()> {
    if let Ok(files) = rnpm_fs::collect_pack_files(source_dir, manifest) {
        for (rel, file_path) in files {
            if rel == ".rnpm_checkout_done"
                || rel.ends_with("/.rnpm_checkout_done")
                || rel.ends_with("\\.rnpm_checkout_done")
                || file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    == Some(".rnpm_checkout_done")
                || rel == ".git"
                || rel.starts_with(".git/")
                || rel.starts_with(".git\\")
                || rel == "node_modules"
                || rel.starts_with("node_modules/")
                || rel.starts_with("node_modules\\")
            {
                continue;
            }
            let to = dst.join(&rel);
            if let Some(p) = to.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            std::fs::copy(&file_path, &to).with_context(|| {
                format!(
                    "Failed to copy '{}' -> '{}'",
                    file_path.display(),
                    to.display()
                )
            })?;
        }
        return Ok(());
    }

    copy_dir_all_raw_pack(source_dir, dst)
}

/// Raw recursive directory copy for packing fallback that strictly skips:
/// `.git`, `.rnpm_checkout_done`, and `node_modules`.
pub fn copy_dir_all_raw_pack(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory '{}'", dst.display()))?;

    for entry in std::fs::read_dir(src)
        .with_context(|| format!("Failed to read directory '{}'", src.display()))?
    {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str == ".git" || name_str == ".rnpm_checkout_done" || name_str == "node_modules" {
            continue;
        }
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(&file_name);
        if ty.is_dir() {
            copy_dir_all_raw_pack(&from, &to)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            {
                let link_target = std::fs::read_link(&from)?;
                let _ = std::os::unix::fs::symlink(&link_target, &to);
            }
            #[cfg(windows)]
            {
                let _ = std::fs::copy(&from, &to);
            }
        } else {
            std::fs::copy(&from, &to).with_context(|| {
                format!("Failed to copy '{}' -> '{}'", from.display(), to.display())
            })?;
        }
    }
    Ok(())
}

/// Options for materializing git dependencies into node_modules.
#[derive(Debug, Clone, Default)]
pub struct GitMaterializeOptions {
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
    pub registry_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub offline: bool,
    pub prefer_offline: bool,
    pub prefer_online: bool,
    pub strict_sandbox: bool,
    pub git_no_prepare: Vec<String>,
    pub git_prepare_depth: usize,
    pub source_policy_override: Option<crate::policy::SourcePolicy>,
    pub force_non_root_policy: bool,
    pub before_cutoff: Option<i64>,
    pub min_release_age_exclude: Vec<String>,
    pub config_override: Option<rnpm_config::Config>,
}

/// Materializes a git dependency into the destination folder in node_modules,
/// executing the `prepare`-then-`pack` build flow matching npm pacote:
/// 1. Check `package.json` in the checked-out git dependency.
/// 2. If the git package defines `prepare` (or `prepack`/`postpack`) AND `ignore_scripts` is false:
///    - Check recursion depth and visited guards to prevent cyclic/infinite loops.
///    - If `dependencies` or `devDependencies` are declared, install them into the staging directory's
///      `node_modules` using the configured cache/registry/offline settings.
///    - Run `prepack` (if present) and `prepare` (if present) with `PATH` including `<staging>/node_modules/.bin`.
///    - Collect/pack package files (respecting `files`, `.npmignore`, strictly excluding `.git`,
///      `.rnpm_checkout_done`, and `node_modules`) into `dst`.
///    - Run `postpack` (if present) after collection/packing.
/// 3. If no prepare scripts or ignore_scripts is true, directly collect/pack files to `dst`.
pub async fn materialize_git_dependency_with_options(
    src: &Path,
    dst: &Path,
    options: &GitMaterializeOptions,
) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory '{}'", dst.display()))?;

    let manifest_path = src.join("package.json");
    if !manifest_path.is_file() {
        return copy_dir_all_raw_pack(src, dst);
    }

    let manifest = Manifest::from_file(&manifest_path).with_context(|| {
        format!("Failed to parse package.json from '{}'", manifest_path.display())
    })?;

    // Check if the package defines prepare, prepack, or postpack scripts (matching pacote's prepare detection)
    let has_prepare = manifest.scripts.contains_key("prepare")
        || manifest.scripts.contains_key("prepack")
        || manifest.scripts.contains_key("postpack");

    if has_prepare && !options.ignore_scripts {
        let no_prepare_env = std::env::var("_RNPM_NO_PREPARE_").unwrap_or_default();
        let canonical_src = src.canonicalize().unwrap_or_else(|_| src.to_path_buf());
        let src_key = canonical_src.to_string_lossy().to_string();

        // Recursion depth guard to prevent runaway git dependency chains
        const MAX_GIT_PREPARE_DEPTH: usize = 10;
        let env_depth: usize = std::env::var("_RNPM_PREPARE_DEPTH_")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let current_depth = std::cmp::max(options.git_prepare_depth, env_depth);

        if current_depth >= MAX_GIT_PREPARE_DEPTH {
            warn!(
                "Max git dependency prepare recursion depth ({}) reached, skipping prepare for '{}'",
                current_depth, src_key
            );
            return copy_pack_files_to_dest(src, &manifest, dst);
        }

        // Visited set guard to prevent cyclic git dependency loops
        if options.git_no_prepare.iter().any(|s| s == &src_key)
            || no_prepare_env.split('\n').any(|s| s == src_key)
        {
            debug!(
                "Skipping prepare for git dependency '{}', already seen in no_prepare",
                src_key
            );
            return copy_pack_files_to_dest(src, &manifest, dst);
        }

        let staging_parent = src.parent().unwrap_or(src);
        let staging_dir = tempfile::Builder::new()
            .prefix("rnpm-git-prepare-")
            .tempdir_in(staging_parent)
            .or_else(|_| tempfile::tempdir())?;

        copy_dir_all_raw_pack(src, staging_dir.path())?;

        let trusted_config = options
            .config_override
            .clone()
            .unwrap_or_else(|| rnpm_config::Config::load(None).unwrap_or_default());

        let new_no_prepare = if no_prepare_env.is_empty() {
            src_key.clone()
        } else {
            format!("{no_prepare_env}\n{src_key}")
        };

        let mut next_no_prepare = options.git_no_prepare.clone();
        if !next_no_prepare.iter().any(|s| s == &src_key) {
            next_no_prepare.push(src_key.clone());
        }

        let staging_manifest_path = staging_dir.path().join("package.json");
        let staging_manifest = if staging_manifest_path.is_file() {
            Manifest::from_file(&staging_manifest_path).unwrap_or_else(|_| manifest.clone())
        } else {
            manifest.clone()
        };

        // 1. Install preparation dependencies in staging if declared
        let has_deps = !staging_manifest.dependencies.is_empty()
            || !staging_manifest.dev_dependencies.is_empty();

        if has_deps {
            debug!(
                "Installing build dependencies in staging directory '{}' for git dependency '{}'",
                staging_dir.path().display(),
                src_key
            );

            let staging_options = crate::InstallOptions {
                project_dir: staging_dir.path().to_path_buf(),
                cache_dir: options.cache_dir.clone(),
                registry_url: options.registry_url.clone(),
                offline: options.offline,
                prefer_offline: options.prefer_offline,
                prefer_online: options.prefer_online,
                strict_sandbox: options.strict_sandbox,
                foreground_scripts: options.foreground_scripts,
                ignore_scripts: options.ignore_scripts,
                bin_links: true,
                no_package_lock: true,
                package_lock: false,
                audit: false,
                fund: false,
                silent: true,
                git_no_prepare: next_no_prepare.clone(),
                git_prepare_depth: current_depth + 1,
                source_policy_override: options.source_policy_override.clone(),
                force_non_root_policy: true,
                before_cutoff: options.before_cutoff,
                min_release_age_exclude: options.min_release_age_exclude.clone(),
                config_override: Some(trusted_config.clone()),
                ..Default::default()
            };

            let mut installer = crate::Installer::new(staging_options).map_err(|e| {
                anyhow!(
                    "Failed to initialize installer for staging directory of git dependency '{src_key}': {e:#}"
                )
            })?;
            let install_fut: std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<crate::InstallSummary>>>,
            > = Box::pin(installer.install());
            install_fut.await.map_err(|e| {
                anyhow!(
                    "Failed to install build dependencies in staging directory for git dependency '{src_key}': {e:#}"
                )
            })?;
        }

        // Construct PATH with <staging>/node_modules/.bin at front
        let staging_bin = staging_dir.path().join("node_modules").join(".bin");
        let inherited_path = std::env::var_os("PATH")
            .or_else(|| std::env::var_os("Path"))
            .unwrap_or_default();
        let mut paths = vec![staging_bin];
        paths.extend(std::env::split_paths(&inherited_path));
        let staging_path_env = std::env::join_paths(paths)
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // 2. Run prepack (if present) and prepare (if present) BEFORE collecting/packing files
        for &hook in &["prepack", "prepare"] {
            let current_manifest = if staging_manifest_path.is_file() {
                Manifest::from_file(&staging_manifest_path)
                    .unwrap_or_else(|_| staging_manifest.clone())
            } else {
                staging_manifest.clone()
            };

            if let Some(cmd) = current_manifest.scripts.get(hook) {
                let mut ctx = rnpm_lifecycle::LifecycleContext::new_with_config(
                    staging_dir.path(),
                    staging_dir.path(),
                    current_manifest.name.as_deref().unwrap_or("git-pkg"),
                    hook,
                    cmd,
                    trusted_config.clone(),
                );
                ctx.package_version = current_manifest.version.clone();
                ctx.foreground_scripts = options.foreground_scripts;
                ctx.extra_env.insert("_RNPM_NO_PREPARE_".to_string(), new_no_prepare.clone());
                ctx.extra_env.insert(
                    "_RNPM_PREPARE_DEPTH_".to_string(),
                    (current_depth + 1).to_string(),
                );
                if let Some(ref path_val) = staging_path_env {
                    ctx.extra_env.insert("PATH".to_string(), path_val.clone());
                    #[cfg(windows)]
                    ctx.extra_env.insert("Path".to_string(), path_val.clone());
                }

                let status = rnpm_lifecycle::execute_lifecycle_script(&ctx).with_context(|| {
                    format!("Failed to execute '{}' script for git dependency '{}'", hook, src_key)
                })?;

                if !status.success() {
                    return Err(anyhow!(
                        "Git dependency preparation failed: script '{}' exited with code {:?}",
                        hook,
                        status.code()
                    ));
                }
            }
        }

        // 3. Read effective manifest after prepack and prepare
        let effective_manifest = if staging_manifest_path.is_file() {
            Manifest::from_file(&staging_manifest_path)
                .unwrap_or_else(|_| staging_manifest.clone())
        } else {
            staging_manifest
        };

        // 4. Collect/pack the package files into dst BEFORE running postpack
        copy_pack_files_to_dest(staging_dir.path(), &effective_manifest, dst)?;

        // 5. Run postpack (if present) AFTER collection/packing
        if let Some(cmd) = effective_manifest.scripts.get("postpack") {
            let mut ctx = rnpm_lifecycle::LifecycleContext::new_with_config(
                staging_dir.path(),
                staging_dir.path(),
                effective_manifest.name.as_deref().unwrap_or("git-pkg"),
                "postpack",
                cmd,
                trusted_config.clone(),
            );
            ctx.package_version = effective_manifest.version.clone();
            ctx.foreground_scripts = options.foreground_scripts;
            ctx.extra_env.insert("_RNPM_NO_PREPARE_".to_string(), new_no_prepare.clone());
            ctx.extra_env.insert(
                "_RNPM_PREPARE_DEPTH_".to_string(),
                (current_depth + 1).to_string(),
            );
            if let Some(ref path_val) = staging_path_env {
                ctx.extra_env.insert("PATH".to_string(), path_val.clone());
                #[cfg(windows)]
                ctx.extra_env.insert("Path".to_string(), path_val.clone());
            }

            let status = rnpm_lifecycle::execute_lifecycle_script(&ctx).with_context(|| {
                format!("Failed to execute 'postpack' script for git dependency '{}'", src_key)
            })?;

            if !status.success() {
                return Err(anyhow!(
                    "Git dependency preparation failed: script 'postpack' exited with code {:?}",
                    status.code()
                ));
            }
        }

        return Ok(());
    }

    copy_pack_files_to_dest(src, &manifest, dst)
}

pub async fn materialize_git_dependency(
    src: &Path,
    dst: &Path,
    ignore_scripts: bool,
    foreground_scripts: bool,
) -> Result<()> {
    materialize_git_dependency_with_options(
        src,
        dst,
        &GitMaterializeOptions {
            ignore_scripts,
            foreground_scripts,
            ..Default::default()
        },
    )
    .await
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    let manifest_path = src.join("package.json");
    if !manifest_path.is_file() {
        return copy_dir_all_raw_pack(src, dst);
    }
    if let Ok(manifest) = Manifest::from_file(&manifest_path) {
        copy_pack_files_to_dest(src, &manifest, dst)
    } else {
        copy_dir_all_raw_pack(src, dst)
    }
}

/// Safely removes a directory tree, clearing Windows read-only flags and handling long paths if necessary.
pub fn safe_remove_dir_all(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    rnpm_fs::remove_dir_all_safe(path).map_err(|e| std::io::Error::other(e.to_string()))
}

/// Checks whether a string is a valid 40-char (SHA-1) or 64-char (SHA-256) git commit hash.
fn is_valid_hex_sha(s: &str) -> bool {
    let s = s.trim();
    (s.len() == 40 || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Executes git command with sanitized environment variables (non-interactive).
async fn run_git_cmd(args: &[&str], cwd: Option<&Path>) -> Result<(bool, String, String)> {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args([
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "-c",
        "core.longpaths=true",
    ])
    .args(args)
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_ASKPASS", "")
    .env("SSH_ASKPASS", "");

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| anyhow!("Failed to execute 'git {}': {e}", args.join(" ")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok((output.status.success(), stdout, stderr))
}

/// Runs `git archive --format=tar <commit_sha>` and returns binary tarball bytes.
async fn run_git_archive(remote_dir: &Path, commit_sha: &str) -> Result<Vec<u8>> {
    let remote_dir_str = remote_dir.to_string_lossy();
    let mut cmd = tokio::process::Command::new("git");
    cmd.args([
        "-c",
        "core.longpaths=true",
        "--git-dir",
        &remote_dir_str,
        "archive",
        "--format=tar",
        commit_sha,
    ])
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_ASKPASS", "")
    .env("SSH_ASKPASS", "");

    let output = cmd
        .output()
        .await
        .map_err(|e| anyhow!("Failed to execute 'git archive': {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git archive failed: {stderr}"));
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_git_resolved_url() {
        let t1 = PackageTarget::parse("github:user/repo#tag").unwrap();
        assert_eq!(
            format_git_resolved_url(&t1, "1234567890abcdef1234567890abcdef12345678"),
            "git+ssh://git@github.com/user/repo.git#1234567890abcdef1234567890abcdef12345678"
        );

        let t2 = PackageTarget::parse("gitlab:group/project").unwrap();
        assert_eq!(
            format_git_resolved_url(&t2, "abcdef1234567890abcdef1234567890abcdef12"),
            "git+https://gitlab.com/group/project.git#abcdef1234567890abcdef1234567890abcdef12"
        );

        let t3 = PackageTarget::parse("bitbucket:org/repo#main").unwrap();
        assert_eq!(
            format_git_resolved_url(&t3, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            "git+https://bitbucket.org/org/repo.git#deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );

        let t4 = PackageTarget::parse("git+ssh://git@github.com/user/repo.git").unwrap();
        let sha4 = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff";
        assert_eq!(
            format_git_resolved_url(&t4, sha4),
            format!("git+ssh://git@github.com/user/repo.git#{sha4}")
        );

        let t5 = PackageTarget::parse("git://github.com/user/repo.git").unwrap();
        assert_eq!(
            format_git_resolved_url(&t5, "feedfacefeedfacefeedfacefeedfacefeedface"),
            "git+git://github.com/user/repo.git#feedfacefeedfacefeedfacefeedfacefeedface"
        );

        let t6 = PackageTarget::parse("github:user/repo#path:packages/foo").unwrap();
        assert_eq!(
            format_git_resolved_url(&t6, "1234567890abcdef1234567890abcdef12345678"),
            "git+ssh://git@github.com/user/repo.git#1234567890abcdef1234567890abcdef12345678::path:packages/foo"
        );

        let t7 = PackageTarget::parse(
            "git+https://github.com/user/repo.git#v1.0.0::path:packages/bar",
        )
        .unwrap();
        assert_eq!(
            format_git_resolved_url(&t7, "abcdef1234567890abcdef1234567890abcdef12"),
            "git+ssh://git@github.com/user/repo.git#abcdef1234567890abcdef1234567890abcdef12::path:packages/bar"
        );
    }

    #[test]
    fn test_resolve_git_subdir_safety() {
        let root = Path::new("/fake/checkout");
        assert_eq!(
            resolve_git_subdir(root, "packages/foo").unwrap(),
            root.join("packages/foo")
        );
        assert_eq!(
            resolve_git_subdir(root, "./packages/bar/").unwrap(),
            root.join("packages/bar")
        );

        // Reject traversal
        assert!(resolve_git_subdir(root, "../escape").is_err());
        assert!(resolve_git_subdir(root, "packages/../../escape").is_err());
        assert!(resolve_git_subdir(root, "/absolute/path").is_err());
        #[cfg(windows)]
        {
            assert!(resolve_git_subdir(root, "C:\\Windows").is_err());
        }
    }

    #[test]
    fn test_normalize_clone_url_for_git() {
        let local = std::env::temp_dir().join("git space~percent%repo");
        let encoded = url::Url::from_file_path(&local).unwrap();
        assert!(encoded.as_str().contains("%20"));
        assert_eq!(
            normalize_clone_url_for_git("https://github.com/user/repo.git"),
            "https://github.com/user/repo.git"
        );

        // Explicit SSH URLs must be preserved, not rewritten to HTTPS
        assert_eq!(
            normalize_clone_url_for_git("ssh://git@github.com/org/private.git"),
            "ssh://git@github.com/org/private.git"
        );
        assert_eq!(
            normalize_clone_url_for_git("git+ssh://git@github.com/org/private.git"),
            "ssh://git@github.com/org/private.git"
        );
        assert_eq!(
            normalize_clone_url_for_git("git@github.com:org/private.git"),
            "git@github.com:org/private.git"
        );
        assert_eq!(
            normalize_clone_url_for_git("git+git@github.com:org/private.git"),
            "git@github.com:org/private.git"
        );

        // GitHub shorthand must use HTTPS matching pacote/hosted-git-info
        assert_eq!(
            normalize_clone_url_for_git("github:org/repo"),
            "https://github.com/org/repo.git"
        );
        assert_eq!(
            normalize_clone_url_for_git("git+github:org/repo"),
            "https://github.com/org/repo.git"
        );

        // Explicit HTTPS URLs are preserved
        assert_eq!(
            normalize_clone_url_for_git("git+https://github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );

        #[cfg(windows)]
        {
            assert_eq!(
                normalize_clone_url_for_git("file:///C:/Users/test/repo"),
                "C:/Users/test/repo"
            );
            assert_eq!(
                normalize_clone_url_for_git("file://C:/Users/test/repo"),
                "C:/Users/test/repo"
            );
        }
    }

    #[test]
    fn test_hex_sha_validation() {
        assert!(is_valid_hex_sha("1234567890abcdef1234567890abcdef12345678"));
        assert!(is_valid_hex_sha(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ));
        assert!(!is_valid_hex_sha("12345"));
        assert!(!is_valid_hex_sha(
            "1234567890abcdef1234567890abcdef1234567g"
        ));
    }

    #[test]
    fn test_remote_dir_hash_deterministic() {
        let fetcher = GitFetcher::new(Path::new("/fake/cache"));
        let p1 = fetcher.remote_repo_dir("https://github.com/user/repo.git");
        let p2 = fetcher.remote_repo_dir("https://github.com/user/repo.git");
        assert_eq!(p1, p2);
        assert!(p1.to_str().unwrap().contains("_git-remotes"));
    }

    #[test]
    fn test_git_cache_path_length_and_format() {
        let fetcher = GitFetcher::new(Path::new("C:/fake/npm/cache"));
        let url = "https://github.com/extremely-long-organization-name/extremely-long-repository-name-that-would-overflow-max-path.git";
        let remote_p = fetcher.remote_repo_dir(url);
        let key = remote_p.file_name().unwrap().to_str().unwrap();
        // Sized to 16 hex chars (64 bits) to stay well under Windows MAX_PATH (260 chars)
        assert_eq!(key.len(), 16);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(remote_p.starts_with("C:/fake/npm/cache/_git-remotes"));

        let commit = "0123456789abcdef0123456789abcdef01234567";
        let checkout_p = fetcher.checkout_cache_dir(url, commit);
        assert!(checkout_p.starts_with("C:/fake/npm/cache/_git-checkouts"));
        let checkout_commit = checkout_p.file_name().unwrap().to_str().unwrap();
        assert_eq!(checkout_commit.len(), 16);
        assert_eq!(checkout_commit, &commit[..16]);
    }

    #[test]
    fn test_git_checkout_marker_not_leaked_into_package() {
        use tempfile::tempdir;

        // 1. Verify marker file path is a sibling outside checkout_dir
        let cache_dir = Path::new("C:/fake/cache/_git-checkouts/hash123/commit456");
        let marker = checkout_marker_file(cache_dir);
        assert_ne!(marker, cache_dir.join(".rnpm_checkout_done"));
        assert_eq!(marker.parent(), cache_dir.parent());
        assert_eq!(
            marker.file_name().unwrap().to_string_lossy(),
            "commit456.rnpm_checkout_done"
        );

        // 2. Verify copy_dir_all skips .rnpm_checkout_done (with package.json manifest)
        let tmp = tempdir().unwrap();
        let src_with_manifest = tmp.path().join("src_manifest");
        let dst_with_manifest = tmp.path().join("dst_manifest");
        std::fs::create_dir_all(&src_with_manifest).unwrap();
        std::fs::write(
            src_with_manifest.join("package.json"),
            r#"{"name":"test-git-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(src_with_manifest.join("index.js"), "module.exports = 42;").unwrap();
        std::fs::write(src_with_manifest.join(".rnpm_checkout_done"), "").unwrap();
        std::fs::write(src_with_manifest.join(".git"), "gitdir: ...").unwrap();

        copy_dir_all(&src_with_manifest, &dst_with_manifest).unwrap();
        assert!(dst_with_manifest.join("package.json").exists());
        assert!(dst_with_manifest.join("index.js").exists());
        assert!(!dst_with_manifest.join(".rnpm_checkout_done").exists());
        assert!(!dst_with_manifest.join(".git").exists());

        // 3. Verify copy_dir_all skips .rnpm_checkout_done (without package.json manifest fallback)
        let src_no_manifest = tmp.path().join("src_no_manifest");
        let dst_no_manifest = tmp.path().join("dst_no_manifest");
        std::fs::create_dir_all(&src_no_manifest).unwrap();
        std::fs::write(src_no_manifest.join("data.txt"), "hello").unwrap();
        std::fs::write(src_no_manifest.join(".rnpm_checkout_done"), "").unwrap();

        copy_dir_all(&src_no_manifest, &dst_no_manifest).unwrap();
        assert!(dst_no_manifest.join("data.txt").exists());
        assert!(!dst_no_manifest.join(".rnpm_checkout_done").exists());
    }

    #[test]
    fn test_build_git_clone_args_protocol_file_gating() {
        // Remote URLs must NOT have protocol.file.allow=always (prevents CVE-2022-39253)
        let remote_urls = [
            "https://github.com/owner/repo.git",
            "http://github.com/owner/repo.git",
            "git+https://github.com/owner/repo.git",
            "git+http://github.com/owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "git://github.com/owner/repo.git",
        ];
        for url in remote_urls {
            let args = build_git_clone_args(url, "/tmp/dir", true);
            assert!(
                !args.contains(&"protocol.file.allow=always"),
                "Remote URL '{}' must NOT include protocol.file.allow=always",
                url
            );
        }

        // Local / file URLs MUST have protocol.file.allow=always
        let local_urls = [
            "file:///path/to/repo",
            "git+file:///path/to/repo",
            "/var/git/repo",
            "C:/repos/my-repo",
            "C:\\repos\\my-repo",
            "./local-repo",
            "../local-repo",
        ];
        for url in local_urls {
            let args = build_git_clone_args(url, "/tmp/dir", true);
            assert!(
                args.contains(&"protocol.file.allow=always"),
                "Local/file URL '{}' must include protocol.file.allow=always",
                url
            );
        }
    }
}
