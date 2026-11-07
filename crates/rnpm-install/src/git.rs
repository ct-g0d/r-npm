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
        let checkout_dir = self
            .checkout_tree(&remote_dir, &commit_sha, &clone_url)
            .await?;

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
        let checkout_dir = self
            .checkout_tree(&remote_dir, &commit_sha, &clone_url)
            .await?;

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
    /// `<cache_dir>/_git-remotes/<hash>`
    pub fn remote_repo_dir(&self, clone_url: &str) -> PathBuf {
        let hash = format!("{:x}", Sha256::digest(clone_url.as_bytes()));
        self.cache_dir.join("_git-remotes").join(hash)
    }

    /// Computes the checkout cache directory for a given clone URL and commit SHA:
    /// `<cache_dir>/_git-checkouts/<hash>/<commit_sha>`
    pub fn checkout_cache_dir(&self, clone_url: &str, commit_sha: &str) -> PathBuf {
        let hash = format!("{:x}", Sha256::digest(clone_url.as_bytes()));
        self.cache_dir
            .join("_git-checkouts")
            .join(hash)
            .join(commit_sha)
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

        if let Some(parent) = remote_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Cloning git repository '{}'", clone_url);
        let remote_dir_str = remote_dir.to_string_lossy();

        // 1. Try mirror clone
        let (mirror_ok, _, mirror_err) = run_git_cmd(
            &["clone", "--mirror", &normalized_url, &remote_dir_str],
            None,
        )
        .await?;

        if mirror_ok {
            return Ok(remote_dir);
        }

        // 2. Fallback to bare clone if mirror fails
        let _ = safe_remove_dir_all(&remote_dir);
        let (bare_ok, _, bare_err) =
            run_git_cmd(&["clone", "--bare", &normalized_url, &remote_dir_str], None).await?;

        if bare_ok {
            return Ok(remote_dir);
        }

        let _ = safe_remove_dir_all(&remote_dir);
        let err_msg = if !mirror_err.is_empty() {
            mirror_err
        } else {
            bare_err
        };
        Err(anyhow!(
            "Failed to clone git repository '{}': {}",
            clone_url,
            err_msg
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
        if checkout_dir.join("package.json").exists() {
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

        // 1. Preferred method: git archive (clean, fast, no .git directory overhead)
        let archive_bytes = run_git_archive(remote_dir, commit_sha).await;
        if let Ok(bytes) = archive_bytes {
            let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
            if archive.unpack(&checkout_dir).is_ok() && checkout_dir.join("package.json").exists() {
                return Ok(checkout_dir);
            }
        }

        // 2. Fallback method: work-tree checkout
        let remote_dir_str = remote_dir.to_string_lossy();
        let checkout_dir_str = checkout_dir.to_string_lossy();
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
            return Err(anyhow!(
                "Failed to checkout git commit '{}' from '{}': {}",
                commit_sha,
                clone_url,
                checkout_err
            ));
        }

        let git_file = checkout_dir.join(".git");
        if git_file.exists() {
            let _ = std::fs::remove_file(&git_file);
            let _ = safe_remove_dir_all(&git_file);
        }

        Ok(checkout_dir)
    }
}

/// Formats canonical locked resolved URL for lockfile v3.
pub fn format_git_resolved_url(target: &PackageTarget, commit_sha: &str) -> String {
    match target {
        PackageTarget::Git { url, .. } => {
            if let Some(rest) = url.strip_prefix("github:") {
                let repo = rest.trim_end_matches(".git");
                format!("git+https://github.com/{repo}.git#{commit_sha}")
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
    }
}

/// Normalizes clone URL for git command execution on current platform.
pub fn normalize_clone_url_for_git(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("file://") {
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
    url.to_string()
}

/// Recursively copies directory tree from `src` to `dst`, skipping `.git`.
pub fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory '{}'", dst.display()))?;
    for entry in std::fs::read_dir(src)
        .with_context(|| format!("Failed to read directory '{}'", src.display()))?
    {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name == ".git" {
            continue;
        }
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(&file_name);
        if ty.is_dir() {
            copy_dir_all(&from, &to)?;
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

/// Safely removes a directory tree, clearing Windows read-only flags if necessary.
pub fn safe_remove_dir_all(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if std::fs::remove_dir_all(path).is_err() {
        clear_readonly_recursive(path);
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn clear_readonly_recursive(path: &Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = p.symlink_metadata() {
                let mut perms = meta.permissions();
                if perms.readonly() {
                    #[allow(clippy::permissions_set_readonly_false)]
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&p, perms);
                }
            }
            if p.is_dir() {
                clear_readonly_recursive(&p);
            }
        }
    }
}

/// Checks whether a string is a valid 40-char (SHA-1) or 64-char (SHA-256) git commit hash.
fn is_valid_hex_sha(s: &str) -> bool {
    let s = s.trim();
    (s.len() == 40 || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Executes git command with sanitized environment variables (non-interactive).
async fn run_git_cmd(args: &[&str], cwd: Option<&Path>) -> Result<(bool, String, String)> {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args)
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
            "git+https://github.com/user/repo.git#1234567890abcdef1234567890abcdef12345678"
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
    }

    #[test]
    fn test_normalize_clone_url_for_git() {
        assert_eq!(
            normalize_clone_url_for_git("https://github.com/user/repo.git"),
            "https://github.com/user/repo.git"
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
}
