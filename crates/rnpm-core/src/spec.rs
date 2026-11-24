use crate::error::SpecError;
use crate::semver::range::Range;
use crate::semver::version::Version;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageTarget {
    Version(Version),
    Range(Range),
    Tag(String),
    Alias {
        name: String,
        target: Box<PackageTarget>,
    },
    File(PathBuf),
    Workspace(String),
    Git {
        url: String,
        committish: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subdir: Option<String>,
    },
    Url(Url),
}

/// Checks if a string is an SCP-syntax git URL, e.g. `git@github.com:org/repo.git`.
pub fn is_scp_git_url(s: &str) -> bool {
    PackageTarget::is_scp_git_url(s)
}

#[inline]
fn is_git_spec(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    match bytes[0] {
        b'g' => {
            if let Some(rest) = s.strip_prefix("git+") {
                rest.starts_with("ssh://")
                    || rest.starts_with("https://")
                    || rest.starts_with("http://")
                    || rest.starts_with("git://")
                    || rest.starts_with("file://")
                    || rest.starts_with("rsync://")
                    || rest.starts_with("ftp://")
            } else if s.starts_with("git://")
                || s.starts_with("git:")
                || s.starts_with("github:")
                || s.starts_with("gitlab:")
                || s.starts_with("gist:")
            {
                true
            } else {
                PackageTarget::is_scp_git_url(s)
            }
        }
        b's' => {
            if s.starts_with("ssh://") {
                true
            } else {
                PackageTarget::is_scp_git_url(s)
            }
        }
        b'b' => {
            if s.starts_with("bitbucket:") {
                true
            } else {
                PackageTarget::is_scp_git_url(s)
            }
        }
        _ => PackageTarget::is_scp_git_url(s),
    }
}

impl PackageTarget {
    /// Checks if a string is an SCP-syntax git URL, e.g. `git@github.com:org/repo.git`
    /// or `deploy@gitlab.com:org/repo.git`.
    ///
    /// Requires a non-empty SSH user before `@` (preventing scoped packages like `@org/pkg`),
    /// followed by a dotted hostname and colon `:` separating the host from a non-empty repository
    /// path (matching `npm-package-arg`: `/^[^@]+@[^:.]+\.[^:]+:.+$/i`).
    /// This prevents misclassifying registry specs like `git@1.0.0`, `git@npm:other`, or `git@file:./foo` as git URLs.
    pub fn is_scp_git_url(s: &str) -> bool {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes[0] == b'@' || !s.contains(':') {
            return false;
        }

        if let Some((user, rest)) = s.split_once('@') {
            if user.is_empty()
                || user.contains('/')
                || user.contains('\\')
                || user.contains(':')
                || user.chars().any(|c| c.is_whitespace())
            {
                return false;
            }
            if let Some((host, path)) = rest.split_once(':') {
                let valid_host = host
                    .split_once('.')
                    .is_some_and(|(left, right)| !left.is_empty() && !right.is_empty())
                    && !host.contains('/')
                    && !host.contains('\\')
                    && !host.chars().any(|c| c.is_whitespace());
                return valid_host
                    && !path.is_empty()
                    && !path.chars().any(|c| c.is_whitespace());
            }
        }
        false
    }

    pub fn parse(spec: &str) -> Result<Self, SpecError> {
        let trimmed_spec = spec.trim();
        if trimmed_spec.is_empty() || trimmed_spec == "*" {
            return Ok(PackageTarget::Range(
                Range::parse("*").map_err(|e| SpecError::Semver(e.to_string()))?,
            ));
        }

        // Fast path for the ~95% most common semver range and exact version specs:
        // - Ranges starting with '^', '~' (excluding "~/"), '>', '<', '='
        // - Versions and ranges starting with a digit (e.g. "1.2.3", "0.1.0", "1.x")
        //   or 'v' + digit (e.g. "v1.2.3") that contain no protocol/path separators (':', '/', '@')
        let bytes = trimmed_spec.as_bytes();
        let first = bytes[0];
        let is_fast_semver = match first {
            b'^' | b'>' | b'<' | b'=' => true,
            b'~' => !trimmed_spec.starts_with("~/"),
            b'0'..=b'9' => {
                !trimmed_spec.contains(':')
                    && !trimmed_spec.contains('/')
                    && !trimmed_spec.contains('@')
            }
            b'v' if bytes.len() > 1 && bytes[1].is_ascii_digit() => {
                !trimmed_spec.contains(':')
                    && !trimmed_spec.contains('/')
                    && !trimmed_spec.contains('@')
            }
            _ => false,
        };

        if is_fast_semver {
            if let Ok(ver) = Version::parse(trimmed_spec) {
                return Ok(PackageTarget::Version(ver));
            }
            if let Ok(range) = Range::parse(trimmed_spec) {
                return Ok(PackageTarget::Range(range));
            }
        }

        let expanded = expand_github_shorthand(trimmed_spec);
        let s = expanded.as_ref();

        // workspace: protocol specifier (e.g. workspace:*, workspace:^, workspace:~, workspace:^1.0.0)
        if let Some(ws_spec) = s.strip_prefix("workspace:") {
            return Ok(PackageTarget::Workspace(ws_spec.trim().to_string()));
        }

        // file: specifier, or a bare path (npa isFilespec: ^(?:[.]|~\/|[/\\]|[a-zA-Z]:))
        let bytes = s.as_bytes();
        let is_bare_path = s.starts_with('.')
            || s.starts_with("~/")
            || s.starts_with('/')
            || s.starts_with('\\')
            || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
        if s.starts_with("file:") || is_bare_path {
            return Ok(PackageTarget::File(parse_file_path(s)));
        }

        // npm: alias specifier (e.g. npm:foo@^1.0.0 or npm:@scope/foo@~2.0.0)
        if let Some(alias_str) = s.strip_prefix("npm:") {
            return Self::parse_alias(alias_str);
        }

        // Git dependency specifications:
        if is_git_spec(s) {
            let (url_part, committish, subdir) = if let Some(hash_idx) = s.find('#') {
                let u = s[..hash_idx].trim().to_string();
                let (committish, subdir) = parse_git_fragment(&s[hash_idx + 1..]);
                (u, committish, subdir)
            } else {
                (s.trim().to_string(), None, None)
            };
            return Ok(PackageTarget::Git {
                url: url_part,
                committish,
                subdir,
            });
        }

        // Direct HTTP/HTTPS remote tarball URL dependencies:
        // e.g. "https://cdn.example.com/packages/pkg-1.0.0.tgz"
        if s.starts_with("http://") || s.starts_with("https://") {
            let parsed_url = Url::parse(s)
                .map_err(|e| SpecError::InvalidFormat(format!("Invalid URL '{s}': {e}")))?;
            return Ok(PackageTarget::Url(parsed_url));
        }

        // Unsupported protocols (e.g. svn://, ftp://, sftp://, hg+https://, cvs://, etc.)
        if let Some((scheme, _)) = s.split_once("://") {
            return Err(SpecError::UnsupportedProtocol {
                protocol: format!("{scheme}:"),
                spec: s.to_string(),
            });
        }
        for proto in &["cvs:", "svn:", "ftp:", "hg:"] {
            if s.starts_with(proto) {
                return Err(SpecError::UnsupportedProtocol {
                    protocol: proto.to_string(),
                    spec: s.to_string(),
                });
            }
        }

        // Try exact version
        if let Ok(ver) = Version::parse(s) {
            return Ok(PackageTarget::Version(ver));
        }

        // If it looks like a range (starts with range chars or contains digits/dots)
        let is_range_syntax = s.starts_with('^')
            || s.starts_with('~')
            || s.starts_with('>')
            || s.starts_with('<')
            || s.starts_with('=')
            || s.contains("||")
            || s.contains(" - ")
            || (s.bytes().any(|c| c.is_ascii_digit()) && s.contains('.'));

        if is_range_syntax {
            if let Ok(range) = Range::parse(s) {
                return Ok(PackageTarget::Range(range));
            }
        }

        // Dist-tag like "latest", "next", "beta"
        if is_valid_tag(s) {
            Ok(PackageTarget::Tag(s.to_string()))
        } else if let Ok(range) = Range::parse(s) {
            Ok(PackageTarget::Range(range))
        } else {
            Err(SpecError::InvalidFormat(s.to_string()))
        }
    }

    /// Returns the raw git URL and optional committish if this target is a Git dependency.
    pub fn git(&self) -> Option<(&str, Option<&str>)> {
        match self {
            PackageTarget::Git {
                url, committish, ..
            } => Some((url.as_str(), committish.as_deref())),
            _ => None,
        }
    }

    /// Returns the normalized git clone URL for cloning/fetching.
    /// E.g.
    /// - `"github:user/repo"` -> `"https://github.com/user/repo.git"`
    /// - `"gitlab:user/repo"` -> `"https://gitlab.com/user/repo.git"`
    /// - `"bitbucket:user/repo"` -> `"https://bitbucket.org/user/repo.git"`
    /// - `"git+https://..."` -> `"https://..."`
    /// - `"git+ssh://..."` -> `"ssh://..."`
    /// - `"git+file://..."` -> `"file://..."`
    /// - `"git://..."` -> `"git://..."`
    pub fn git_clone_url(&self) -> Option<String> {
        match self {
            PackageTarget::Git { url, .. } => {
                if let Some(rest) = url.strip_prefix("github:") {
                    let repo = rest.trim_end_matches(".git");
                    Some(format!("https://github.com/{repo}.git"))
                } else if let Some(rest) = url.strip_prefix("gitlab:") {
                    let repo = rest.trim_end_matches(".git");
                    Some(format!("https://gitlab.com/{repo}.git"))
                } else if let Some(rest) = url.strip_prefix("bitbucket:") {
                    let repo = rest.trim_end_matches(".git");
                    Some(format!("https://bitbucket.org/{repo}.git"))
                } else if let Some(rest) = url.strip_prefix("gist:") {
                    let clean = rest.trim_end_matches(".git");
                    let id = clean.rsplit('/').next().unwrap_or(clean);
                    Some(format!("https://gist.github.com/{id}.git"))
                } else if let Some(rest) = url.strip_prefix("git+") {
                    Some(rest.to_string())
                } else {
                    Some(url.clone())
                }
            }
            _ => None,
        }
    }

    /// Returns the committish (tag, branch, commit sha, or semver spec) if this is a Git dependency.
    pub fn git_committish(&self) -> Option<&str> {
        match self {
            PackageTarget::Git { committish, .. } => committish.as_deref(),
            _ => None,
        }
    }

    /// Returns the subdirectory path if specified via `#path:<subdir>` or `#<committish>::path:<subdir>`.
    pub fn git_subdir(&self) -> Option<&str> {
        match self {
            PackageTarget::Git { subdir, .. } => subdir.as_deref(),
            _ => None,
        }
    }

    /// Alias for `git_subdir`.
    pub fn git_path(&self) -> Option<&str> {
        self.git_subdir()
    }

    /// Returns the URL reference if this target is a direct HTTP/HTTPS URL dependency.
    pub fn url(&self) -> Option<&Url> {
        match self {
            PackageTarget::Url(u) => Some(u),
            _ => None,
        }
    }

    /// Checks if this target is a Git dependency.
    pub fn is_git(&self) -> bool {
        matches!(self, PackageTarget::Git { .. })
    }

    /// Checks if this target is a direct URL dependency.
    pub fn is_url(&self) -> bool {
        matches!(self, PackageTarget::Url(_))
    }

    /// Returns the file path if this target is a local file or directory.
    pub fn file_path(&self) -> Option<&Path> {
        match self {
            PackageTarget::File(p) => Some(p.as_path()),
            _ => None,
        }
    }

    /// Checks if this target is a local file or directory.
    pub fn is_file(&self) -> bool {
        matches!(self, PackageTarget::File(_))
    }

    /// Checks if this target is a tarball archive (e.g. .tgz, .tar.gz, .tar).
    pub fn is_tarball_archive(&self) -> bool {
        match self {
            PackageTarget::File(p) => {
                if let Some(s) = p.to_str() {
                    s.ends_with(".tgz") || s.ends_with(".tar.gz") || s.ends_with(".tar")
                } else {
                    let s = p.to_string_lossy();
                    s.ends_with(".tgz") || s.ends_with(".tar.gz") || s.ends_with(".tar")
                }
            }
            PackageTarget::Url(u) => {
                let path = u.path();
                path.ends_with(".tgz") || path.ends_with(".tar.gz") || path.ends_with(".tar")
            }
            _ => false,
        }
    }

    fn parse_alias(alias_str: &str) -> Result<Self, SpecError> {
        let trimmed = alias_str.trim();
        if trimmed.is_empty() {
            return Err(SpecError::InvalidAlias(alias_str.to_string()));
        }

        // Could be @scope/pkg@spec or pkg@spec or pkg
        let (name, sub_spec) = split_name_and_spec(trimmed)?;
        let inner_target = if let Some(spec) = sub_spec {
            PackageTarget::parse(spec)?
        } else {
            PackageTarget::Tag("latest".to_string())
        };

        Ok(PackageTarget::Alias {
            name: name.to_string(),
            target: Box::new(inner_target),
        })
    }
}

impl fmt::Display for PackageTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageTarget::Version(v) => write!(f, "{v}"),
            PackageTarget::Range(r) => write!(f, "{r}"),
            PackageTarget::Tag(t) => write!(f, "{t}"),
            PackageTarget::Alias { name, target } => write!(f, "npm:{name}@{target}"),
            PackageTarget::File(p) => write!(f, "file:{}", p.display()),
            PackageTarget::Workspace(w) => write!(f, "workspace:{w}"),
            PackageTarget::Git {
                url,
                committish,
                subdir,
            } => match (committish, subdir) {
                (Some(c), Some(s)) => write!(f, "{url}#{c}::path:{s}"),
                (Some(c), None) => write!(f, "{url}#{c}"),
                (None, Some(s)) => write!(f, "{url}#path:{s}"),
                (None, None) => write!(f, "{url}"),
            },
            PackageTarget::Url(u) => write!(f, "{u}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSpec {
    pub name: String,
    pub target: PackageTarget,
}

impl PackageSpec {
    pub fn new(name: impl Into<String>, target: PackageTarget) -> Self {
        Self {
            name: name.into(),
            target,
        }
    }

    /// Parse a package specifier as provided in CLI arguments or manifests:
    /// e.g. "express", "express@^4.18.0", "@types/node@18.0.0", "foo@npm:bar@^1.0.0", "foo@file:../bar", "foo@workspace:*",
    /// "github:user/repo", "git+https://github.com/org/repo.git#v1.0.0", "https://cdn.example.com/packages/pkg-1.0.0.tgz"
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            return Err(SpecError::Empty);
        }

        let expanded = expand_github_shorthand(trimmed_input);
        let trimmed = expanded.as_ref();

        // Direct "workspace:" specifier without name (e.g. "workspace:*")
        if let Some(ws_str) = trimmed.strip_prefix("workspace:") {
            return Ok(Self {
                name: "workspace".to_string(),
                target: PackageTarget::Workspace(ws_str.trim().to_string()),
            });
        }

        // Direct "file:" specifier without name (e.g. "file:../foo", "file:///abs")
        if trimmed.starts_with("file:") {
            let path = parse_file_path(trimmed);
            let name = extract_path_package_name(&path);
            return Ok(Self {
                name,
                target: PackageTarget::File(path),
            });
        }

        // Direct "npm:" alias without alias name (e.g. "npm:bar@^1.0.0")
        if let Some(alias_str) = trimmed.strip_prefix("npm:") {
            let target = PackageTarget::parse_alias(alias_str)?;
            if let PackageTarget::Alias { ref name, .. } = target {
                return Ok(Self {
                    name: name.clone(),
                    target,
                });
            }
        }

        // Direct Git specifier without name (e.g. "github:user/repo", "git+https://github.com/org/repo.git#v1.0.0")
        if is_git_spec(trimmed) {
            let name = extract_git_repo_name(trimmed);
            let target = PackageTarget::parse(trimmed)?;
            return Ok(Self { name, target });
        }

        // Direct HTTP/HTTPS remote tarball URL without name
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let target = PackageTarget::parse(trimmed)?;
            let name = extract_url_package_name(trimmed);
            return Ok(Self { name, target });
        }

        let (name, spec_opt) = split_name_and_spec(trimmed)?;
        let target = if let Some(spec) = spec_opt {
            PackageTarget::parse(spec)?
        } else {
            PackageTarget::Tag("latest".to_string())
        };

        Ok(Self {
            name: name.to_string(),
            target,
        })
    }

    /// Parse a dependency entry from package.json:
    /// name: "express", spec: "^4.18.2" or "npm:bar@^1.0.0" or "file:../bar"
    pub fn parse_dependency(name: &str, spec: &str) -> Result<Self, SpecError> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(SpecError::InvalidName(name.to_string()));
        }

        let target = PackageTarget::parse(spec)?;
        Ok(Self {
            name: trimmed_name.to_string(),
            target,
        })
    }
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.target)
    }
}

impl FromStr for PackageSpec {
    type Err = SpecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Splits a package string into (name, Option<spec>)
/// Handles scoped packages like "@scope/pkg@1.0.0"
fn split_name_and_spec(input: &str) -> Result<(&str, Option<&str>), SpecError> {
    if input.starts_with('@') {
        // Scoped package
        let slash_idx = input
            .find('/')
            .ok_or_else(|| SpecError::InvalidName(input.to_string()))?;
        let after_slash = &input[slash_idx + 1..];
        if let Some(at_idx) = after_slash.find('@') {
            let full_at_idx = slash_idx + 1 + at_idx;
            let name = &input[..full_at_idx];
            let spec = &input[full_at_idx + 1..];
            if name.is_empty() || spec.is_empty() {
                return Err(SpecError::InvalidFormat(input.to_string()));
            }
            Ok((name, Some(spec)))
        } else {
            Ok((input, None))
        }
    } else {
        // Unscoped package
        if let Some(at_idx) = input.find('@') {
            let name = &input[..at_idx];
            let spec = &input[at_idx + 1..];
            if name.is_empty() || spec.is_empty() {
                return Err(SpecError::InvalidFormat(input.to_string()));
            }
            Ok((name, Some(spec)))
        } else {
            Ok((input, None))
        }
    }
}

fn is_valid_tag(s: &str) -> bool {
    // Dist-tags typically start with letters, e.g. "latest", "next", "beta", "canary"
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn extract_git_repo_name(spec: &str) -> String {
    let clean = spec.split_once('#').map(|(u, _)| u).unwrap_or(spec);
    let clean = clean.trim_end_matches(".git").trim_end_matches('/');
    if let Some(slash_idx) = clean.rfind('/') {
        clean[slash_idx + 1..].to_string()
    } else if let Some(colon_idx) = clean.rfind(':') {
        clean[colon_idx + 1..].to_string()
    } else {
        clean.to_string()
    }
}

fn extract_path_package_name(path: &std::path::Path) -> String {
    if path.is_dir() {
        let pkg_json = path.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(n) = val.get("name").and_then(|v| v.as_str()) {
                    return n.to_string();
                }
            }
        }
    }
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");
    let mut stripped = filename;
    if stripped.ends_with(".tgz") {
        stripped = &stripped[..stripped.len() - 4];
    } else if stripped.ends_with(".tar.gz") {
        stripped = &stripped[..stripped.len() - 7];
    } else if stripped.ends_with(".tar") {
        stripped = &stripped[..stripped.len() - 4];
    }
    if let Some(dash_idx) = stripped.rfind('-') {
        let suffix = &stripped[dash_idx + 1..];
        if suffix
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return stripped[..dash_idx].to_string();
        }
    }
    stripped.to_string()
}

fn extract_url_package_name(url_str: &str) -> String {
    if let Ok(u) = Url::parse(url_str) {
        if u.scheme() == "file" {
            if let Ok(path) = u.to_file_path() {
                return extract_path_package_name(&path);
            }
        }
        if let Some(segments) = u.path_segments() {
            let segs: Vec<&str> = segments.collect();
            // npm registry tarball format: .../[@scope/]pkg/-/pkg-version.tgz
            if let Some(dash_pos) = segs.iter().position(|&s| s == "-") {
                if dash_pos > 0 {
                    if dash_pos >= 2 && segs[dash_pos - 2].starts_with('@') {
                        return format!("{}/{}", segs[dash_pos - 2], segs[dash_pos - 1]);
                    }
                    return segs[dash_pos - 1].to_string();
                }
            }
            if let Some(mut last_seg) = segs.last().copied() {
                if last_seg.ends_with(".tgz") {
                    last_seg = &last_seg[..last_seg.len() - 4];
                } else if last_seg.ends_with(".tar.gz") {
                    last_seg = &last_seg[..last_seg.len() - 7];
                } else if last_seg.ends_with(".tar") {
                    last_seg = &last_seg[..last_seg.len() - 4];
                }
                if let Some(dash_idx) = last_seg.rfind('-') {
                    let suffix = &last_seg[dash_idx + 1..];
                    if suffix
                        .chars()
                        .next()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                    {
                        return last_seg[..dash_idx].to_string();
                    }
                }
                if !last_seg.is_empty() {
                    return last_seg.to_string();
                }
            }
        }
    }
    "unnamed".to_string()
}

/// Normalizes a `file:` path or URL specifier (e.g. `file:./x`, `file:x`, `file:../x`, `file:///abs`, `file://localhost/...`).
pub fn parse_file_path(spec: &str) -> std::path::PathBuf {
    if spec.starts_with("file://") {
        if let Ok(url) = Url::parse(spec) {
            if url.scheme() == "file" {
                if let Ok(file_path) = url.to_file_path() {
                    return path_clean::clean(file_path);
                }
            }
        }
    }

    let path_str = spec.strip_prefix("file:").unwrap_or(spec);

    if path_str.starts_with("///") || path_str.starts_with("//") {
        let trimmed = path_str.trim_start_matches('/');
        #[cfg(windows)]
        {
            if trimmed.len() > 1 && trimmed.as_bytes()[1] == b':' {
                return path_clean::clean(trimmed);
            }
        }
        return path_clean::clean(format!("/{trimmed}"));
    }

    let cleaned = path_clean::clean(path_str);
    if let Ok(stripped) = cleaned.strip_prefix(".") {
        stripped.to_path_buf()
    } else {
        cleaned
    }
}

/// npm-package-arg treats `user/repo[#committish]` as a GitHub dependency
/// (hosted-git-info shorthand: no protocol, scope, path prefix or spaces).
fn expand_github_shorthand(spec: &str) -> Cow<'_, str> {
    if !spec.contains('/') || spec.contains("://") {
        return Cow::Borrowed(spec);
    }

    let (body, committish) = spec.split_once('#').unwrap_or((spec, ""));
    let Some((user, repo)) = body.split_once('/') else {
        return Cow::Borrowed(spec);
    };
    let user_ok = user
        .chars()
        .next()
        .is_some_and(|c| !matches!(c, '@' | '%' | '/' | '.' | '-') && !c.is_whitespace())
        && !user
            .chars()
            .any(|c| matches!(c, ':' | '@' | '%' | '/') || c.is_whitespace());
    let repo_ok = !repo.is_empty()
        && !repo
            .chars()
            .any(|c| matches!(c, '@' | '/' | '%') || c.is_whitespace());
    if user_ok && repo_ok {
        if committish.is_empty() && !spec.contains('#') {
            Cow::Owned(format!("github:{body}"))
        } else {
            Cow::Owned(format!("github:{body}#{committish}"))
        }
    } else {
        Cow::Borrowed(spec)
    }
}

/// Parses git URL fragment into optional committish and optional subdirectory path.
/// Supports npm formats:
/// - `#path:<subdir>`
/// - `#<committish>::path:<subdir>`
/// - `#<committish>`
pub fn parse_git_fragment(fragment: &str) -> (Option<String>, Option<String>) {
    let f = fragment.trim();
    if f.is_empty() {
        return (None, None);
    }

    if let Some((committish_part, subdir_part)) = f.split_once("::path:") {
        let c = committish_part.trim();
        let s = subdir_part.trim();
        let committish = if c.is_empty() {
            None
        } else {
            Some(c.to_string())
        };
        let subdir = if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
        (committish, subdir)
    } else if let Some(subdir_part) = f.strip_prefix("path:") {
        let s = subdir_part.trim();
        let subdir = if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        };
        (None, subdir)
    } else {
        (Some(f.to_string()), None)
    }
}

/// npm-package-arg's `fromURL` check: a dependency spec that is not a file
/// path, `npm:` alias or hosted-git shortcut, yet looks like `scheme:...`, is
/// parsed as a URL, and any scheme other than git or http(s) is rejected.
/// Returns the protocol (with its colon) npm reports as unsupported.
pub fn unsupported_protocol(spec: &str) -> Option<String> {
    let colon_idx = spec.find(':')?;
    let scheme = &spec[..colon_idx];
    if scheme.len() == 1 {
        // A single letter is a Windows drive path, handled as a file spec.
        return None;
    }

    let plain = if let Some(stripped) = scheme.strip_prefix("git+") {
        stripped
    } else if let Some(stripped) = scheme.strip_prefix("GIT+") {
        stripped
    } else {
        scheme
    };

    if plain.is_empty() || !plain.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }

    const ACCEPTED: &[&str] = &[
        "file",
        "npm",
        "github",
        "gitlab",
        "bitbucket",
        "gist",
        "git",
        "git+http",
        "git+https",
        "git+rsync",
        "git+ftp",
        "git+file",
        "git+ssh",
        "ssh",
        "http",
        "https",
    ];

    let is_accepted = ACCEPTED.iter().any(|&acc| acc.eq_ignore_ascii_case(scheme));
    if is_accepted {
        None
    } else {
        Some(format!("{}:", scheme.to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod unsupported_protocol_tests {
    use super::*;
    use crate::semver::{Range, Version};

    #[test]
    fn matches_npa_from_url() {
        for spec in [
            "workspace:*",
            "workspace:^",
            "link:../x",
            "catalog:",
            "portal:../y",
        ] {
            assert!(unsupported_protocol(spec).is_some(), "{spec}");
        }
        assert_eq!(
            unsupported_protocol("patch:a@npm%3A1.0.0#~/p.patch").as_deref(),
            Some("patch:")
        );
        for spec in [
            "^1.0.0",
            "file:../x",
            "npm:a@1",
            "github:u/r",
            "git+ssh://git@h:u/r.git",
            "https://h/x.tgz",
            r"C:\x",
            "latest",
            "u/r",
            "git://h/r.git",
            "ssh://git@github.com/12345/repo.git",
        ] {
            assert_eq!(unsupported_protocol(spec), None, "{spec}");
        }
    }

    #[test]
    fn test_git_spec_parsing_scp_and_ssh() {
        use crate::spec::{PackageSpec, PackageTarget};

        let scp = "git@github.com:12345/repo.git#main";
        let target_scp = PackageTarget::parse(scp).unwrap();
        match &target_scp {
            PackageTarget::Git {
                url,
                committish,
                subdir,
            } => {
                assert_eq!(url, "git@github.com:12345/repo.git");
                assert_eq!(committish.as_deref(), Some("main"));
                assert_eq!(*subdir, None);
            }
            _ => panic!("Expected PackageTarget::Git"),
        }

        let spec_scp = PackageSpec::parse(scp).unwrap();
        assert_eq!(spec_scp.name, "repo");
        assert_eq!(spec_scp.target, target_scp);

        let ssh = "ssh://git@github.com/12345/repo.git#main";
        let target_ssh = PackageTarget::parse(ssh).unwrap();
        match &target_ssh {
            PackageTarget::Git {
                url,
                committish,
                subdir,
            } => {
                assert_eq!(url, "ssh://git@github.com/12345/repo.git");
                assert_eq!(committish.as_deref(), Some("main"));
                assert_eq!(*subdir, None);
            }
            _ => panic!("Expected PackageTarget::Git"),
        }

        let spec_ssh = PackageSpec::parse(ssh).unwrap();
        assert_eq!(spec_ssh.name, "repo");
        assert_eq!(spec_ssh.target, target_ssh);
        assert_eq!(unsupported_protocol(ssh), None);
    }

    #[test]
    fn test_git_package_named_git_vs_scp_url() {
        // Real npm registry specs where package name is "git":
        let spec_ver = PackageSpec::parse("git@1.0.0").unwrap();
        assert_eq!(spec_ver.name, "git");
        assert_eq!(
            spec_ver.target,
            PackageTarget::Version(Version::new(1, 0, 0))
        );

        let spec_range = PackageSpec::parse("git@^2.0.0").unwrap();
        assert_eq!(spec_range.name, "git");
        assert_eq!(
            spec_range.target,
            PackageTarget::Range(Range::parse("^2.0.0").unwrap())
        );

        let spec_tag = PackageSpec::parse("git@latest").unwrap();
        assert_eq!(spec_tag.name, "git");
        assert_eq!(spec_tag.target, PackageTarget::Tag("latest".to_string()));

        // SCP git URL must parse as git dependency with repo name:
        let scp = "git@github.com:12345/repo.git";
        assert!(PackageTarget::is_scp_git_url(scp));
        assert!(!PackageTarget::is_scp_git_url("git@1.0.0"));
        assert!(!PackageTarget::is_scp_git_url("git@^2.0.0"));
        assert!(!PackageTarget::is_scp_git_url("git@latest"));

        let spec_scp = PackageSpec::parse(scp).unwrap();
        assert_eq!(spec_scp.name, "repo");
        match spec_scp.target {
            PackageTarget::Git { url, .. } => {
                assert_eq!(url, "git@github.com:12345/repo.git");
            }
            _ => panic!("Expected PackageTarget::Git"),
        }

        // Non-git SSH users with dotted hostnames parse as SCP git URLs (matching npm-package-arg),
        // while dotless hosts such as `git@npm:other` or `git@file:./foo` do not:
        assert!(PackageTarget::is_scp_git_url(
            "deploy@gitlab.com:org/repo.git"
        ));
        assert!(!PackageTarget::is_scp_git_url("git@npm:other"));
        assert!(!PackageTarget::is_scp_git_url("git@file:./foo"));
        assert!(!PackageTarget::is_scp_git_url(
            "user@localhost:org/repo.git"
        ));
        assert!(!PackageTarget::is_scp_git_url("@org/pkg:foo"));

        let deploy_spec = PackageSpec::parse("deploy@gitlab.com:org/repo.git").unwrap();
        assert_eq!(deploy_spec.name, "repo");
        assert!(matches!(deploy_spec.target, PackageTarget::Git { .. }));
    }
}
