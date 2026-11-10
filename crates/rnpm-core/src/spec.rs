use crate::error::SpecError;
use crate::semver::range::Range;
use crate::semver::version::Version;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
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
    },
    Url(Url),
}

impl PackageTarget {
    pub fn parse(spec: &str) -> Result<Self, SpecError> {
        let s = spec.trim();
        if s.is_empty() || s == "*" {
            return Ok(PackageTarget::Range(
                Range::parse("*").map_err(|e| SpecError::Semver(e.to_string()))?,
            ));
        }

        // workspace: protocol specifier (e.g. workspace:*, workspace:^, workspace:~, workspace:^1.0.0)
        if let Some(ws_spec) = s.strip_prefix("workspace:") {
            return Ok(PackageTarget::Workspace(ws_spec.trim().to_string()));
        }

        // file: specifier
        if s.starts_with("file:") {
            return Ok(PackageTarget::File(parse_file_path(s)));
        }

        // npm: alias specifier (e.g. npm:foo@^1.0.0 or npm:@scope/foo@~2.0.0)
        if let Some(alias_str) = s.strip_prefix("npm:") {
            return Self::parse_alias(alias_str);
        }

        // Git dependency specifications:
        // "github:user/repo", "git+https://github.com/org/repo.git#v1.0.0",
        // "git+ssh://git@github.com/org/repo.git", "git://github.com/org/repo.git",
        // "gitlab:user/repo", "bitbucket:user/repo", "git+file:///path/to/repo"
        let git_prefixes = [
            "git+ssh://",
            "git+https://",
            "git+http://",
            "git+git://",
            "git+file://",
            "git://",
            "github:",
            "gitlab:",
            "bitbucket:",
        ];
        for prefix in git_prefixes {
            if s.starts_with(prefix) {
                let (url_part, committish) = if let Some(hash_idx) = s.find('#') {
                    let u = s[..hash_idx].trim().to_string();
                    let c = s[hash_idx + 1..].trim().to_string();
                    (u, if c.is_empty() { None } else { Some(c) })
                } else {
                    (s.trim().to_string(), None)
                };
                return Ok(PackageTarget::Git {
                    url: url_part,
                    committish,
                });
            }
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
            || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('.'));

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
            PackageTarget::Git { url, committish } => Some((url.as_str(), committish.as_deref())),
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
            name,
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
            PackageTarget::Git { url, committish } => {
                if let Some(c) = committish {
                    write!(f, "{url}#{c}")
                } else {
                    write!(f, "{url}")
                }
            }
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
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }

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
        let git_prefixes = [
            "git+ssh://",
            "git+https://",
            "git+http://",
            "git+git://",
            "git+file://",
            "git://",
            "github:",
            "gitlab:",
            "bitbucket:",
        ];
        for prefix in git_prefixes {
            if trimmed.starts_with(prefix) {
                let name = extract_git_repo_name(trimmed);
                let target = PackageTarget::parse(trimmed)?;
                return Ok(Self { name, target });
            }
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

        Ok(Self { name, target })
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
fn split_name_and_spec(input: &str) -> Result<(String, Option<&str>), SpecError> {
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
            Ok((name.to_string(), Some(spec)))
        } else {
            Ok((input.to_string(), None))
        }
    } else {
        // Unscoped package
        if let Some(at_idx) = input.find('@') {
            let name = &input[..at_idx];
            let spec = &input[at_idx + 1..];
            if name.is_empty() || spec.is_empty() {
                return Err(SpecError::InvalidFormat(input.to_string()));
            }
            Ok((name.to_string(), Some(spec)))
        } else {
            Ok((input.to_string(), None))
        }
    }
}

fn is_valid_tag(s: &str) -> bool {
    // Dist-tags typically start with letters, e.g. "latest", "next", "beta", "canary"
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        && s.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false)
}

fn extract_git_repo_name(spec: &str) -> String {
    let clean = spec.split('#').next().unwrap_or(spec);
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
    if let Ok(url) = Url::parse(spec) {
        if url.scheme() == "file" {
            if let Ok(file_path) = url.to_file_path() {
                return path_clean::clean(file_path);
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
