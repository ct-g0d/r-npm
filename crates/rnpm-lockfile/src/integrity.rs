use rnpm_core::integrity::{Algorithm, Integrity};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

use crate::error::LockfileError;
use crate::model::LockfileV3;

/// Policy configuration for auditing and verifying lockfile integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityPolicy {
    /// Whether to allow unencrypted `http://` tarball URLs (default: false).
    pub allow_insecure_http: bool,

    /// Minimum hash algorithm required for package integrity (default: Some(Algorithm::Sha512)).
    pub min_algorithm: Option<Algorithm>,

    /// Whether every non-link dependency must specify an integrity hash (default: true).
    pub require_integrity: bool,

    /// Allowed registry hostnames or domain suffixes. If non-empty, resolved URLs must match.
    pub allowed_registries: Vec<String>,

    /// Whether transitive dependencies are allowed to use `git:` / `git+` URLs (default: false).
    pub allow_transitive_git: bool,

    /// Whether transitive dependencies are allowed to use `file:` URLs (default: false).
    pub allow_transitive_file: bool,
}

impl Default for IntegrityPolicy {
    fn default() -> Self {
        Self {
            allow_insecure_http: false,
            min_algorithm: Some(Algorithm::Sha512),
            require_integrity: true,
            allowed_registries: Vec::new(),
            allow_transitive_git: false,
            allow_transitive_file: false,
        }
    }
}

impl IntegrityPolicy {
    /// Strict policy: sha512 required, no insecure http, no transitive git/file, require integrity.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Permissive policy: allows sha1/sha256/sha512, allows http, allows transitive git/file.
    pub fn permissive() -> Self {
        Self {
            allow_insecure_http: true,
            min_algorithm: None,
            require_integrity: false,
            allowed_registries: Vec::new(),
            allow_transitive_git: true,
            allow_transitive_file: true,
        }
    }

    pub fn with_allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    pub fn with_min_algorithm(mut self, min_algo: Option<Algorithm>) -> Self {
        self.min_algorithm = min_algo;
        self
    }

    pub fn with_require_sha512(mut self, require: bool) -> Self {
        self.min_algorithm = if require {
            Some(Algorithm::Sha512)
        } else {
            None
        };
        self
    }

    pub fn with_require_integrity(mut self, require: bool) -> Self {
        self.require_integrity = require;
        self
    }

    pub fn with_allowed_registries(mut self, registries: Vec<String>) -> Self {
        self.allowed_registries = registries;
        self
    }

    pub fn with_allow_transitive_git(mut self, allow: bool) -> Self {
        self.allow_transitive_git = allow;
        self
    }

    pub fn with_allow_transitive_file(mut self, allow: bool) -> Self {
        self.allow_transitive_file = allow;
        self
    }
}

/// Checker that audits a LockfileV3 against an IntegrityPolicy.
#[derive(Debug, Clone)]
pub struct LockfileIntegrityChecker {
    policy: IntegrityPolicy,
}

impl LockfileIntegrityChecker {
    pub fn new(policy: IntegrityPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &IntegrityPolicy {
        &self.policy
    }

    pub fn verify(&self, lockfile: &LockfileV3) -> Result<(), LockfileError> {
        verify_lockfile_integrity(lockfile, &self.policy)
    }
}

/// Audits all packages in a LockfileV3 against the provided IntegrityPolicy.
///
/// Checks performed:
/// 1. Missing integrity hashes or weak algorithms (e.g. below min_algorithm).
/// 2. Insecure protocol use (`http://` tarballs when insecure HTTP is disallowed).
/// 3. Lockfile poisoning:
///    - Package name and version mismatched against resolved tarball URL.
///    - Suspicious registry domains or raw IP addresses.
///    - Untrusted `file:` or `git:` injection into transitive dependencies.
pub fn verify_lockfile_integrity(
    lockfile: &LockfileV3,
    policy: &IntegrityPolicy,
) -> Result<(), LockfileError> {
    // Collect direct dependency names from root package (borrowed slices, zero String clones)
    let mut direct_deps: HashSet<&str> = HashSet::new();
    if let Some(root) = lockfile.root_package() {
        let cap = root.dependencies.as_ref().map_or(0, |d| d.len())
            + root.dev_dependencies.as_ref().map_or(0, |d| d.len())
            + root.optional_dependencies.as_ref().map_or(0, |d| d.len())
            + root.peer_dependencies.as_ref().map_or(0, |d| d.len());
        direct_deps.reserve(cap);
        if let Some(ref d) = root.dependencies {
            direct_deps.extend(d.keys().map(String::as_str));
        }
        if let Some(ref d) = root.dev_dependencies {
            direct_deps.extend(d.keys().map(String::as_str));
        }
        if let Some(ref d) = root.optional_dependencies {
            direct_deps.extend(d.keys().map(String::as_str));
        }
        if let Some(ref d) = root.peer_dependencies {
            direct_deps.extend(d.keys().map(String::as_str));
        }
    }

    for (pkg_path, pkg) in &lockfile.packages {
        // Skip root package itself
        if pkg_path.is_empty() {
            continue;
        }

        // Symlinked/workspace packages are local references
        if pkg.link == Some(true) {
            continue;
        }

        // 1. Audit integrity hash presence and strength (zero-allocation validation)
        audit_integrity(pkg_path, pkg, policy)?;

        // 2. Audit resolved URL if present
        if let Some(ref resolved) = pkg.resolved {
            let is_direct = is_direct_dependency(pkg_path, &direct_deps);
            audit_resolved_url(
                pkg_path,
                pkg.name.as_deref(),
                pkg.version.as_deref(),
                resolved,
                is_direct,
                policy,
            )?;
        }
    }

    Ok(())
}

fn audit_integrity(
    pkg_path: &str,
    pkg: &crate::model::LockfilePackage,
    policy: &IntegrityPolicy,
) -> Result<(), LockfileError> {
    match &pkg.integrity {
        None => {
            if policy.require_integrity {
                return Err(LockfileError::MissingIntegrity(pkg_path.to_string()));
            }
        }
        Some(integrity_str) => {
            let strongest = Integrity::strongest_algorithm_str(integrity_str)
                .map_err(|e| {
                    LockfileError::InvalidStructure(format!(
                        "Invalid integrity hash in package '{pkg_path}': {e}"
                    ))
                })?
                .ok_or_else(|| LockfileError::MissingIntegrity(pkg_path.to_string()))?;

            if let Some(min_algo) = policy.min_algorithm {
                if strongest < min_algo {
                    return Err(LockfileError::WeakIntegrity {
                        package: pkg_path.to_string(),
                        algorithm: strongest.to_string(),
                        required: min_algo.to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

#[inline]
fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[inline]
fn host_matches_domain(host_lower: &str, domain_lower: &str) -> bool {
    host_lower == domain_lower
        || (host_lower.len() > domain_lower.len()
            && host_lower.ends_with(domain_lower)
            && host_lower.as_bytes()[host_lower.len() - domain_lower.len() - 1] == b'.')
}

/// Fast path for canonical lowercase ASCII registry URLs without userinfo, ports,
/// IP hosts, percent-encoding, queries, fragments, backslashes, or dot-segments.
/// Any non-trivial URL returns `None` and falls back to full `Url::parse`.
#[inline]
fn try_split_fast_http_url(resolved: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = if let Some(r) = resolved.strip_prefix("https://") {
        ("https", r)
    } else {
        ("http", resolved.strip_prefix("http://")?)
    };

    let slash_idx = rest.find('/')?;
    let host = &rest[..slash_idx];
    let path = &rest[slash_idx..];

    let hb = host.as_bytes();
    if hb.is_empty() || hb.len() > 253 {
        return None;
    }
    let mut last_dot = None;
    let mut prev_dot = true;
    for (i, &b) in hb.iter().enumerate() {
        if b == b'.' {
            if prev_dot {
                return None;
            }
            last_dot = Some(i);
            prev_dot = true;
        } else if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
            if prev_dot && b == b'-' {
                return None;
            }
            prev_dot = false;
        } else {
            return None;
        }
    }
    if prev_dot {
        return None;
    }
    let dot_idx = last_dot?;
    let tld = &hb[dot_idx + 1..];
    if tld.is_empty() || !tld.iter().all(|b| b.is_ascii_lowercase()) {
        return None;
    }

    let pb = path.as_bytes();
    for (i, &b) in pb.iter().enumerate() {
        if !(b.is_ascii_alphanumeric()
            || matches!(b, b'/' | b'-' | b'_' | b'.' | b'@' | b'+' | b'~'))
        {
            return None;
        }
        if b == b'.' && (i == 0 || pb[i - 1] == b'/' || pb[i - 1] == b'.') {
            return None;
        }
    }

    Some((scheme, host, path))
}

fn audit_resolved_url(
    pkg_path: &str,
    declared_name: Option<&str>,
    pkg_version: Option<&str>,
    resolved: &str,
    is_direct: bool,
    policy: &IntegrityPolicy,
) -> Result<(), LockfileError> {
    if let Some((scheme, host_str, url_path)) = try_split_fast_http_url(resolved) {
        if scheme == "http" && !policy.allow_insecure_http {
            return Err(LockfileError::InsecureResolvedUrl {
                package: pkg_path.to_string(),
                url: resolved.to_string(),
            });
        }
        if !policy.allowed_registries.is_empty() {
            check_allowed_registries(pkg_path, host_str, policy)?;
        }
        let pkg_name: Cow<'_, str> = match declared_name {
            Some(n) => Cow::Borrowed(n),
            None => extract_package_name_from_path_cow(pkg_path),
        };
        return audit_tarball_name_and_version(
            pkg_path,
            pkg_name.as_ref(),
            pkg_version,
            url_path,
            resolved,
        );
    }

    let trimmed = resolved.trim();

    // Check for git protocols
    let is_git = starts_with_ignore_ascii_case(trimmed, "git://")
        || starts_with_ignore_ascii_case(trimmed, "git+http://")
        || starts_with_ignore_ascii_case(trimmed, "git+https://")
        || starts_with_ignore_ascii_case(trimmed, "git+ssh://")
        || starts_with_ignore_ascii_case(trimmed, "git+file://")
        || starts_with_ignore_ascii_case(trimmed, "git@");

    if is_git {
        if !is_direct && !policy.allow_transitive_git {
            return Err(LockfileError::PoisonedDependency {
                package: pkg_path.to_string(),
                reason: format!(
                    "Transitive dependency '{pkg_path}' specifies untrusted git source: '{resolved}'"
                ),
            });
        }
        return Ok(());
    }

    // Check for file protocol
    let is_file = starts_with_ignore_ascii_case(trimmed, "file:") || trimmed.starts_with("../");
    if is_file {
        if !is_direct && !policy.allow_transitive_file {
            return Err(LockfileError::PoisonedDependency {
                package: pkg_path.to_string(),
                reason: format!(
                    "Transitive dependency '{pkg_path}' specifies untrusted file source: '{resolved}'"
                ),
            });
        }
        return Ok(());
    }

    // Parse as HTTP/HTTPS URL
    let parsed_url = match Url::parse(resolved) {
        Ok(u) => u,
        Err(_) => {
            // If it's not a valid URL and not git/file, flag suspicious
            return Err(LockfileError::SuspiciousResolution {
                package: pkg_path.to_string(),
                reason: format!("Failed to parse resolved URL: '{resolved}'"),
            });
        }
    };

    // Check insecure HTTP
    if parsed_url.scheme() == "http" && !policy.allow_insecure_http {
        return Err(LockfileError::InsecureResolvedUrl {
            package: pkg_path.to_string(),
            url: resolved.to_string(),
        });
    }

    // Detect URL userinfo spoofing (e.g. https://registry.npmjs.org@evil.com/...)
    if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
        return Err(LockfileError::SuspiciousResolution {
            package: pkg_path.to_string(),
            reason: format!(
                "URL authority userinfo spoofing detected in resolved URL: '{resolved}'"
            ),
        });
    }

    // Check host
    let host_str = match parsed_url.host_str() {
        Some(h) => h,
        None => {
            return Err(LockfileError::SuspiciousResolution {
                package: pkg_path.to_string(),
                reason: format!("Resolved URL has no host: '{resolved}'"),
            });
        }
    };

    // Flag raw IP addresses unless explicitly allowed
    if IpAddr::from_str(host_str).is_ok() {
        let is_allowed = policy.allowed_registries.iter().any(|r| r == host_str);
        if !is_allowed {
            return Err(LockfileError::SuspiciousResolution {
                package: pkg_path.to_string(),
                reason: format!(
                    "Resolved URL points to raw IP address '{host_str}', suspicious domain"
                ),
            });
        }
    }

    // Check allowed_registries filter if configured
    if !policy.allowed_registries.is_empty() {
        check_allowed_registries(pkg_path, host_str, policy)?;
    }

    // Audit package name and version against resolved tarball URL
    let pkg_name: Cow<'_, str> = match declared_name {
        Some(n) => Cow::Borrowed(n),
        None => extract_package_name_from_path_cow(pkg_path),
    };
    audit_tarball_name_and_version(
        pkg_path,
        pkg_name.as_ref(),
        pkg_version,
        parsed_url.path(),
        resolved,
    )?;

    Ok(())
}

fn check_allowed_registries(
    pkg_path: &str,
    host_str: &str,
    policy: &IntegrityPolicy,
) -> Result<(), LockfileError> {
    let host_lower: Cow<'_, str> = if host_str.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host_str.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host_str)
    };
    let matches_allowed = policy.allowed_registries.iter().any(|reg| {
        let reg_lower = reg.to_ascii_lowercase();
        if reg_lower.starts_with("http://") || reg_lower.starts_with("https://") {
            if let Ok(reg_url) = Url::parse(&reg_lower) {
                if let Some(reg_host) = reg_url.host_str() {
                    return host_matches_domain(&host_lower, reg_host);
                }
            }
        }
        host_matches_domain(&host_lower, &reg_lower)
    });

    if !matches_allowed {
        return Err(LockfileError::SuspiciousResolution {
            package: pkg_path.to_string(),
            reason: format!(
                "Host '{host_str}' is not in allowed registries: {:?}",
                policy.allowed_registries
            ),
        });
    }
    Ok(())
}

/// Checks that standard npm registry tarball URLs match the package name and version.
/// E.g. `https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz` or
/// `https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz`.
#[inline]
fn audit_tarball_name_and_version(
    pkg_path: &str,
    pkg_name: &str,
    pkg_version: Option<&str>,
    path: &str,
    resolved: &str,
) -> Result<(), LockfileError> {
    // Check standard npm registry tarball pattern containing `/-/`
    if let Some((prefix, tarball_filename)) = path.split_once("/-/") {
        let expected_unscoped_name = if pkg_name.starts_with('@') {
            if let Some((_, unscoped)) = pkg_name.split_once('/') {
                unscoped
            } else {
                pkg_name
            }
        } else {
            pkg_name
        };

        // 1. Verify prefix matches package name
        let clean_prefix = prefix.trim_start_matches('/');
        let expected_name_trimmed = pkg_name.trim_start_matches('/');
        if !clean_prefix.ends_with(expected_name_trimmed) {
            return Err(LockfileError::PoisonedDependency {
                package: pkg_path.to_string(),
                reason: format!(
                    "Package name '{pkg_name}' mismatches resolved URL path prefix '{prefix}' in '{resolved}'"
                ),
            });
        }

        // 2. Verify tarball filename ends with `.tgz` or `.tar.gz`
        let clean_tarball = tarball_filename
            .strip_suffix(".tgz")
            .or_else(|| tarball_filename.strip_suffix(".tar.gz"));

        if let Some(stem) = clean_tarball {
            // Tarball filename is expected to be `<unscoped_name>-<version>`
            if let Some(expected_ver) = pkg_version {
                let matches_stem = stem.len()
                    == expected_unscoped_name.len() + 1 + expected_ver.len()
                    && stem.starts_with(expected_unscoped_name)
                    && stem.as_bytes()[expected_unscoped_name.len()] == b'-'
                    && stem.ends_with(expected_ver);
                if !matches_stem {
                    return Err(LockfileError::PoisonedDependency {
                        package: pkg_path.to_string(),
                        reason: format!(
                            "Package '{pkg_name}@{expected_ver}' mismatches resolved tarball filename '{tarball_filename}' in '{resolved}'"
                        ),
                    });
                }
            } else if !(stem.len() > expected_unscoped_name.len()
                && stem.starts_with(expected_unscoped_name)
                && stem.as_bytes()[expected_unscoped_name.len()] == b'-')
            {
                return Err(LockfileError::PoisonedDependency {
                    package: pkg_path.to_string(),
                    reason: format!(
                        "Package '{pkg_name}' mismatches resolved tarball filename '{tarball_filename}' in '{resolved}'"
                    ),
                });
            }
        }
    }

    Ok(())
}

#[inline]
fn extract_package_name_from_path_cow(pkg_path: &str) -> Cow<'_, str> {
    match rnpm_core::to_posix_path_cow(pkg_path) {
        Cow::Borrowed(clean) => {
            if let Some(pos) = clean.rfind("node_modules/") {
                Cow::Borrowed(&clean[pos + "node_modules/".len()..])
            } else {
                Cow::Borrowed(clean)
            }
        }
        Cow::Owned(clean) => {
            if let Some(pos) = clean.rfind("node_modules/") {
                Cow::Owned(clean[pos + "node_modules/".len()..].to_string())
            } else {
                Cow::Owned(clean)
            }
        }
    }
}

#[inline]
fn is_direct_dependency(pkg_path: &str, direct_deps: &HashSet<&str>) -> bool {
    let clean_cow = rnpm_core::to_posix_path_cow(pkg_path);
    let clean = clean_cow.trim_end_matches('/');

    if let Some(folder_name) = clean.strip_prefix("node_modules/") {
        if folder_name.contains("node_modules") {
            return false;
        }
        if direct_deps.contains(folder_name) {
            return true;
        }
    }

    false
}
