use rnpm_core::integrity::{Algorithm, Integrity};
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
    // Collect direct dependency names from root package
    let mut direct_deps: HashSet<String> = HashSet::new();
    if let Some(root) = lockfile.root_package() {
        if let Some(ref d) = root.dependencies {
            direct_deps.extend(d.keys().cloned());
        }
        if let Some(ref d) = root.dev_dependencies {
            direct_deps.extend(d.keys().cloned());
        }
        if let Some(ref d) = root.optional_dependencies {
            direct_deps.extend(d.keys().cloned());
        }
        if let Some(ref d) = root.peer_dependencies {
            direct_deps.extend(d.keys().cloned());
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

        // Determine the package's declared or inferred name
        let inferred_name = pkg
            .name
            .clone()
            .unwrap_or_else(|| extract_package_name_from_path(pkg_path));

        // Determine if this package is a direct root dependency or transitive
        let is_direct = is_direct_dependency(pkg_path, &inferred_name, &direct_deps);

        // 1. Audit integrity hash presence and strength
        audit_integrity(pkg_path, pkg, policy)?;

        // 2. Audit resolved URL if present
        if let Some(ref resolved) = pkg.resolved {
            audit_resolved_url(
                pkg_path,
                &inferred_name,
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
            let integrity = Integrity::parse(integrity_str).map_err(|e| {
                LockfileError::InvalidStructure(format!(
                    "Invalid integrity hash in package '{pkg_path}': {e}"
                ))
            })?;

            if let Some(min_algo) = policy.min_algorithm {
                let strongest = integrity
                    .strongest_algorithm()
                    .ok_or_else(|| LockfileError::MissingIntegrity(pkg_path.to_string()))?;

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

fn audit_resolved_url(
    pkg_path: &str,
    pkg_name: &str,
    pkg_version: Option<&str>,
    resolved: &str,
    is_direct: bool,
    policy: &IntegrityPolicy,
) -> Result<(), LockfileError> {
    let lower_trimmed = resolved.trim().to_ascii_lowercase();

    // Check for git protocols
    let is_git = lower_trimmed.starts_with("git://")
        || lower_trimmed.starts_with("git+http://")
        || lower_trimmed.starts_with("git+https://")
        || lower_trimmed.starts_with("git+ssh://")
        || lower_trimmed.starts_with("git+file://")
        || lower_trimmed.starts_with("git@");

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
    let is_file = lower_trimmed.starts_with("file:") || lower_trimmed.starts_with("../");
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
        let host_lower = host_str.to_ascii_lowercase();
        let matches_allowed = policy.allowed_registries.iter().any(|reg| {
            let reg_lower = reg.to_ascii_lowercase();
            if reg_lower.starts_with("http://") || reg_lower.starts_with("https://") {
                if let Ok(reg_url) = Url::parse(&reg_lower) {
                    if let Some(reg_host) = reg_url.host_str() {
                        return host_lower == reg_host
                            || host_lower.ends_with(&format!(".{reg_host}"));
                    }
                }
            }
            host_lower == reg_lower || host_lower.ends_with(&format!(".{reg_lower}"))
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
    }

    // Audit package name and version against resolved tarball URL
    audit_tarball_name_and_version(pkg_path, pkg_name, pkg_version, &parsed_url, resolved)?;

    Ok(())
}

/// Checks that standard npm registry tarball URLs match the package name and version.
/// E.g. `https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz` or
/// `https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz`.
fn audit_tarball_name_and_version(
    pkg_path: &str,
    pkg_name: &str,
    pkg_version: Option<&str>,
    parsed_url: &Url,
    resolved: &str,
) -> Result<(), LockfileError> {
    let path = parsed_url.path();

    // Check standard npm registry tarball pattern containing `/-/`
    if let Some((prefix, tarball_filename)) = path.split_once("/-/") {
        let expected_unscoped_name = if pkg_name.starts_with('@') && pkg_name.contains('/') {
            pkg_name.split('/').nth(1).unwrap_or(pkg_name)
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
                let expected_tarball_stem = format!("{expected_unscoped_name}-{expected_ver}");
                if stem != expected_tarball_stem {
                    return Err(LockfileError::PoisonedDependency {
                        package: pkg_path.to_string(),
                        reason: format!(
                            "Package '{pkg_name}@{expected_ver}' mismatches resolved tarball filename '{tarball_filename}' in '{resolved}'"
                        ),
                    });
                }
            } else if !stem.starts_with(&format!("{expected_unscoped_name}-")) {
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

fn extract_package_name_from_path(pkg_path: &str) -> String {
    let clean = pkg_path.replace('\\', "/");
    let after_nm = if let Some(pos) = clean.rfind("node_modules/") {
        &clean[pos + "node_modules/".len()..]
    } else {
        &clean
    };
    after_nm.to_string()
}

fn is_direct_dependency(
    pkg_path: &str,
    inferred_name: &str,
    direct_deps: &HashSet<String>,
) -> bool {
    let clean = pkg_path.replace('\\', "/");

    // If path contains multiple node_modules segments, it's definitely nested (transitive)
    let nm_count = clean.split("node_modules").count() - 1;
    if nm_count > 1 {
        return false;
    }

    // Direct dependencies are located at `node_modules/<name>` and listed in direct_deps
    let direct_path = format!("node_modules/{inferred_name}");
    if clean == direct_path && direct_deps.contains(inferred_name) {
        return true;
    }

    false
}
