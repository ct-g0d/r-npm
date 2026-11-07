use crate::error::LifecycleError;
use crate::sandbox::check_dangerous_command_patterns;
use std::collections::HashSet;
use std::time::Duration;

/// Policy enforcement level for lifecycle script execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxLevel {
    /// Permissive mode (default): allows script execution without command pattern filtering; honors explicit allowlist and denylist.
    /// Matches standard npm behavior: allows standard native build invocations and legitimate scripts without artificial command blocking.
    #[default]
    Permissive,
    /// Restricted mode (opt-in via --strict-sandbox or config): blocks dangerous command patterns (network calls, obfuscation, sensitive paths); honors allowlist and denylist.
    Restricted,
    /// Strict mode: only explicitly allowlisted packages may execute scripts, blocks all dangerous patterns, enforces strict limits.
    Strict,
    /// Disabled mode: all lifecycle scripts are ignored and skipped entirely (equivalent to --ignore-scripts).
    Disabled,
}

impl SandboxLevel {
    pub fn is_permissive(&self) -> bool {
        matches!(self, Self::Permissive)
    }

    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::Restricted)
    }

    pub fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Comprehensive sandboxing policy governing lifecycle script execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSandboxPolicy {
    /// Security enforcement level.
    pub level: SandboxLevel,

    /// Set of package names explicitly allowed to execute lifecycle scripts.
    /// In Strict mode or when non-empty, only packages in this set are permitted.
    pub allowlist: HashSet<String>,

    /// Set of package names explicitly blocked from executing lifecycle scripts.
    pub denylist: HashSet<String>,

    /// Maximum number of active processes allowed within the process tree (Windows Job Object).
    pub max_active_processes: Option<u32>,

    /// Maximum execution duration for a single script.
    pub max_execution_time: Option<Duration>,
}

impl Default for ScriptSandboxPolicy {
    fn default() -> Self {
        Self::permissive()
    }
}

impl ScriptSandboxPolicy {
    /// Default restricted policy: blocks dangerous patterns, empty allowlist/denylist.
    pub fn restricted() -> Self {
        Self {
            level: SandboxLevel::Restricted,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            max_active_processes: Some(32),
            max_execution_time: None,
        }
    }

    /// Permissive policy: disables dangerous pattern inspection, allows all non-denylisted scripts.
    pub fn permissive() -> Self {
        Self {
            level: SandboxLevel::Permissive,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            max_active_processes: None,
            max_execution_time: None,
        }
    }

    /// Strict policy: requires explicit allowlisting of packages and blocks dangerous patterns.
    pub fn strict() -> Self {
        Self {
            level: SandboxLevel::Strict,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            max_active_processes: Some(16),
            max_execution_time: Some(Duration::from_secs(60)),
        }
    }

    /// Disabled policy: skips all script executions.
    pub fn disabled() -> Self {
        Self {
            level: SandboxLevel::Disabled,
            allowlist: HashSet::new(),
            denylist: HashSet::new(),
            max_active_processes: None,
            max_execution_time: None,
        }
    }

    pub fn with_level(mut self, level: SandboxLevel) -> Self {
        self.level = level;
        self
    }

    pub fn with_allowlist(
        mut self,
        allowlist: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowlist = allowlist.into_iter().map(Into::into).collect();
        self
    }

    pub fn allow_package(mut self, package_name: impl Into<String>) -> Self {
        self.allowlist.insert(package_name.into());
        self
    }

    pub fn with_denylist(mut self, denylist: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.denylist = denylist.into_iter().map(Into::into).collect();
        self
    }

    pub fn deny_package(mut self, package_name: impl Into<String>) -> Self {
        self.denylist.insert(package_name.into());
        self
    }

    pub fn with_max_active_processes(mut self, limit: Option<u32>) -> Self {
        self.max_active_processes = limit;
        self
    }

    pub fn with_max_execution_time(mut self, timeout: Option<Duration>) -> Self {
        self.max_execution_time = timeout;
        self
    }

    /// Validates whether a lifecycle script is permitted to execute according to this policy.
    pub fn check_execution_allowed(
        &self,
        package_name: &str,
        script_cmd: &str,
    ) -> Result<(), LifecycleError> {
        // 1. Check if disabled
        if self.level == SandboxLevel::Disabled {
            return Err(LifecycleError::ScriptsDisabled);
        }

        // 2. Check denylist
        if self.denylist.contains(package_name) {
            return Err(LifecycleError::PackageDenylisted(package_name.to_string()));
        }

        // 3. Check allowlist (in Strict mode, or when allowlist is populated)
        if self.level == SandboxLevel::Strict {
            if !self.allowlist.contains(package_name) {
                return Err(LifecycleError::PackageNotAllowlisted(
                    package_name.to_string(),
                ));
            }
        } else if !self.allowlist.is_empty() && !self.allowlist.contains(package_name) {
            return Err(LifecycleError::PackageNotAllowlisted(
                package_name.to_string(),
            ));
        }

        // 4. Check dangerous command patterns if not permissive
        if self.level != SandboxLevel::Permissive {
            if let Some(reason) = check_dangerous_command_patterns(script_cmd) {
                return Err(LifecycleError::DangerousCommandPattern {
                    package: package_name.to_string(),
                    reason,
                    cmd: script_cmd.to_string(),
                });
            }
        }

        Ok(())
    }
}
