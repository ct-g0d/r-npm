use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolverError {
    #[error("Unresolved dependency '{name}@{spec}': {message}")]
    UnresolvedDependency {
        name: String,
        spec: String,
        message: String,
    },

    #[error("{}", format_peer_conflict(.parent, .peer, .required_spec, .found_version, .found_location, .required_by, .message))]
    PeerConflict {
        parent: String,
        peer: String,
        required_spec: String,
        found_version: Option<String>,
        found_location: Option<String>,
        required_by: Vec<String>,
        message: String,
    },

    #[error("EBADPLATFORM: Unsupported platform for {package}@{version}: wanted {wanted} (current: {current})\n{message}")]
    PlatformIncompatible {
        package: String,
        version: String,
        wanted: String,
        current: String,
        required_by: Vec<String>,
        message: String,
    },

    #[error("Cycle detected during dependency resolution: {0}")]
    CycleDetected(String),

    #[error("Invalid override configuration: {0}")]
    InvalidOverride(String),

    #[error("Core error: {0}")]
    Core(#[from] rnpm_core::CoreError),

    #[error("Spec error: {0}")]
    Spec(#[from] rnpm_core::SpecError),

    #[error("Semver error: {0}")]
    Semver(#[from] rnpm_core::SemverError),

    #[error("Manifest error: {0}")]
    Manifest(#[from] rnpm_core::ManifestError),

    #[error("Lockfile error: {0}")]
    Lockfile(#[from] rnpm_lockfile::LockfileError),

    #[error("Package metadata error for '{0}': {1}")]
    PackageMetadata(String, String),
}

fn format_peer_conflict(
    parent: &str,
    peer: &str,
    required_spec: &str,
    found_version: &Option<String>,
    found_location: &Option<String>,
    required_by: &[String],
    message: &str,
) -> String {
    let mut out = format!("ERESOLVE: Conflicting peer dependency '{peer}' required by '{parent}': {message}\n");
    out.push_str(&format!("  Could not resolve dependency:\n    peer {peer}@\"{required_spec}\" from {parent}\n"));
    match (found_version, found_location) {
        (Some(ver), Some(loc)) => {
            out.push_str(&format!("  Found: {peer}@{ver} at {loc}\n"));
        }
        (Some(ver), None) => {
            out.push_str(&format!("  Found: {peer}@{ver}\n"));
        }
        (None, Some(loc)) => {
            out.push_str(&format!("  Found at: {loc}\n"));
        }
        (None, None) => {}
    }
    if !required_by.is_empty() {
        out.push_str("  Dependency chain:\n    ");
        out.push_str(&required_by.join(" -> "));
        if required_by.last().map(|s| s.as_str()) != Some(parent) {
            out.push_str(&format!(" -> {parent}"));
        }
        out.push('\n');
    }
    out.push_str("  Suggested resolutions:\n");
    out.push_str(&format!("    1. Add an override in package.json: \"overrides\": {{ \"{peer}\": \"...\" }}\n"));
    out.push_str("    2. Run with --legacy-peer-deps to ignore peer dependency requirements\n");
    if let Some(ver) = found_version {
        out.push_str(&format!("    3. Update '{parent}' to a version compatible with '{peer}@{ver}'\n"));
    } else {
        out.push_str(&format!("    3. Install '{peer}' as an explicit dependency in package.json\n"));
    }
    out
}

impl SolverError {
    /// Constructs a rich diagnostic peer conflict error.
    pub fn peer_conflict(
        parent: impl Into<String>,
        peer: impl Into<String>,
        required_spec: impl Into<String>,
        found_version: Option<String>,
        found_location: Option<String>,
        required_by: Vec<String>,
        message: impl Into<String>,
    ) -> Self {
        SolverError::PeerConflict {
            parent: parent.into(),
            peer: peer.into(),
            required_spec: required_spec.into(),
            found_version,
            found_location,
            required_by,
            message: message.into(),
        }
    }

    /// Returns true if this error represents an ERESOLVE peer dependency conflict.
    pub fn is_peer_conflict(&self) -> bool {
        matches!(self, SolverError::PeerConflict { .. })
    }

    /// Constructs a platform incompatibility error.
    pub fn platform_incompatible(
        package: impl Into<String>,
        version: impl Into<String>,
        wanted: impl Into<String>,
        current: impl Into<String>,
        required_by: Vec<String>,
        message: impl Into<String>,
    ) -> Self {
        SolverError::PlatformIncompatible {
            package: package.into(),
            version: version.into(),
            wanted: wanted.into(),
            current: current.into(),
            required_by,
            message: message.into(),
        }
    }

    /// Returns true if this error represents an EBADPLATFORM platform incompatibility.
    pub fn is_platform_incompatible(&self) -> bool {
        matches!(self, SolverError::PlatformIncompatible { .. })
    }

    /// Accessor for peer conflict details: (parent, peer, required_spec, found_version, found_location, required_by, message)
    pub fn peer_conflict_details(
        &self,
    ) -> Option<(&str, &str, &str, Option<&str>, Option<&str>, &[String], &str)> {
        match self {
            SolverError::PeerConflict {
                parent,
                peer,
                required_spec,
                found_version,
                found_location,
                required_by,
                message,
            } => Some((
                parent.as_str(),
                peer.as_str(),
                required_spec.as_str(),
                found_version.as_deref(),
                found_location.as_deref(),
                required_by.as_slice(),
                message.as_str(),
            )),
            _ => None,
        }
    }

    /// Returns structured suggested resolutions for peer conflicts.
    pub fn suggested_resolutions(&self) -> Vec<String> {
        match self {
            SolverError::PeerConflict {
                parent,
                peer,
                found_version,
                ..
            } => {
                let mut suggestions = Vec::new();
                suggestions.push(format!(
                    "Add an override in package.json: \"overrides\": {{ \"{peer}\": \"...\" }}"
                ));
                suggestions.push("Run with --legacy-peer-deps to ignore peer dependency requirements".to_string());
                if let Some(found) = found_version {
                    suggestions.push(format!(
                        "Update '{parent}' to a version compatible with '{peer}@{found}'"
                    ));
                } else {
                    suggestions.push(format!("Install '{peer}' as an explicit dependency in package.json"));
                }
                suggestions
            }
            _ => Vec::new(),
        }
    }
}
