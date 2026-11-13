use rnpm_core::error::{CoreError, IntegrityError, ManifestError, SpecError};
use rnpm_fs::FsError;
use rnpm_lockfile::LockfileError;
use rnpm_registry::RegistryError;
use rnpm_solver::SolverError;

/// Structured diagnostic payload conforming to npm error output standard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub detail: Option<String>,
}

impl Diagnostic {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Format as standard npm error block:
    /// npm error code <CODE>
    /// npm error <message>
    /// npm error <detail>
    pub fn format_npm(&self) -> String {
        if self.message.contains("npm error code ") {
            return self.message.clone();
        }
        let mut out = format!("npm error code {}\nnpm error {}", self.code, self.message);
        if let Some(ref d) = self.detail {
            out.push_str(&format!("\nnpm error {}", d));
        }
        out
    }
}

/// npm's EJSONPARSE block for the current project's package.json.
fn npm_package_json_error() -> Option<String> {
    let text = std::fs::read_to_string(std::env::current_dir().ok()?.join("package.json")).ok()?;
    crate::json_errors::package_json_error(&text)
}

/// Classify an arbitrary error into a structured npm diagnostic with stable error code.
pub fn classify_error(err: &anyhow::Error) -> Diagnostic {
    for cause in err.chain() {
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            if let Some((code, message)) = rnpm_registry::network_errors::diagnostic(http) {
                return Diagnostic::new(code, message);
            }
        }
    }
    let err_str = format!("{:#}", err);

    // If the error string already contains an npm error block, preserve its code and message
    if err_str.contains("npm error code ") {
        if let Some(idx) = err_str.find("npm error code ") {
            let rest = &err_str[idx + "npm error code ".len()..];
            let mut lines = rest.lines();
            let code_line = lines.next().unwrap_or("EUNKNOWN").trim();
            let code: &'static str = match code_line {
                "ERESOLVE" => "ERESOLVE",
                "ETARGET" => "ETARGET",
                "E404" => "E404",
                "E401" => "E401",
                "E403" => "E403",
                "E429" => "E429",
                "EPUBLISHCONFLICT" => "EPUBLISHCONFLICT",
                "ENEEDAUTH" => "ENEEDAUTH",
                "EINTEGRITY" => "EINTEGRITY",
                "ELOCKFILE_DRIFT" => "ELOCKFILE_DRIFT",
                "EUSAGE" => "EUSAGE",
                "EUNSUPPORTEDPROTOCOL" => "EUNSUPPORTEDPROTOCOL",
                "ETARBOMB" => "ETARBOMB",
                "ESECURITY" => "ESECURITY",
                "EJSONPARSE" => "EJSONPARSE",
                "ERR_UNSUPPORTED_COMMAND" => "ERR_UNSUPPORTED_COMMAND",
                "ERR_UNSUPPORTED_FLAG" => "ERR_UNSUPPORTED_FLAG",
                "ENOLOCK" => "ENOLOCK",
                "ENOENT" => "ENOENT",
                "ENOWORKSPACES" => "ENOWORKSPACES",
                "ENOWORKSPACE" => "ENOWORKSPACE",
                "ENOTCACHED" => "ENOTCACHED",
                "ENOTSUP" => "ENOTSUP",
                "ENOMATCH" => "ENOMATCH",
                "FETCH_ERROR" => "FETCH_ERROR",
                "EINVALIDURL" => "EINVALIDURL",
                "ECONNREFUSED" => "ECONNREFUSED",
                "ENOTFOUND" => "ENOTFOUND",
                "ECONNRESET" => "ECONNRESET",
                "ETIMEDOUT" => "ETIMEDOUT",
                _ => "EUNKNOWN",
            };
            if matches!(code, "ECONNREFUSED" | "ENOTFOUND" | "ECONNRESET" | "ETIMEDOUT" | "FETCH_ERROR") {
                return Diagnostic::new(code, &err_str[idx..]);
            }
            let remaining: Vec<String> = lines
                .map(|l| {
                    let trimmed = l.trim();
                    if let Some(stripped) = trimmed.strip_prefix("npm error ") {
                        stripped.to_string()
                    } else if let Some(stripped) = trimmed.strip_prefix("npm error") {
                        stripped.trim_start().to_string()
                    } else {
                        trimmed.to_string()
                    }
                })
                .filter(|l| !l.is_empty())
                .collect();

            if !remaining.is_empty() {
                let message = remaining[0].clone();
                let detail = if remaining.len() > 1 {
                    Some(remaining[1..].join("\nnpm error "))
                } else {
                    None
                };
                return Diagnostic {
                    code,
                    message,
                    detail,
                };
            } else {
                return Diagnostic::new(code, code_line);
            }
        }
    }

    // Direct downcasts for strong typing
    for cause in err.chain() {
        if let Some(solver_err) = cause.downcast_ref::<SolverError>() {
            match solver_err {
                SolverError::UnresolvedDependency { name, spec, message }
                    if message == "No matching version found satisfying constraint" => {
                    return Diagnostic::new("ETARGET", format!("notarget No matching version found for {name}@{spec}."))
                        .with_detail("notarget In most cases you or one of your dependencies are requesting a package version that doesn't exist.");
                }
                SolverError::UnresolvedDependency { message, .. }
                    if message == "Package not found in metadata provider" => {
                    return Diagnostic::new("E404", solver_err.to_string());
                }
                SolverError::PeerConflict { .. } => {
                    return Diagnostic::new("ERESOLVE", solver_err.to_string());
                }
                SolverError::Spec(SpecError::UnsupportedProtocol { protocol, spec }) => {
                    return Diagnostic::new(
                        "EUNSUPPORTEDPROTOCOL",
                        format!("Unsupported URL Type \"{protocol}\": {spec}"),
                    )
                    .with_detail(
                        "Supported protocols are npm registry packages, 'file:', and 'workspace:'.",
                    );
                }
                _ => {}
            }
        }

        if let Some(reg_err) = cause.downcast_ref::<RegistryError>() {
            match reg_err {
                RegistryError::PackageNotFound { package, status } => {
                    return Diagnostic::new(
                        "E404",
                        format!("Package '{package}' not found in registry (HTTP {status})"),
                    );
                }
                RegistryError::VersionNotFound { package, version } => {
                    return Diagnostic::new(
                        "ETARGET",
                        format!("No matching version found for {package}@{version}"),
                    );
                }
                RegistryError::Unauthorized {
                    message,
                    status: _,
                    url,
                } => {
                    return Diagnostic::new(
                    "ENEEDAUTH",
                    format!("This command requires you to be logged in to {url}"),
                )
                .with_detail(if message.is_empty() {
                    "You need to authorize this machine using `npm adduser` or `npm login`".to_string()
                } else {
                    format!("{message}\nYou need to authorize this machine using `npm adduser` or `npm login`")
                });
                }
                RegistryError::Forbidden {
                    message,
                    status: _,
                    url,
                } => {
                    return Diagnostic::new("E403", format!("403 Forbidden - {url}: {message}"));
                }
                RegistryError::PublishConflict {
                    message,
                    status: _,
                    url: _,
                } => {
                    let msg = if message.is_empty()
                        || message
                            .to_ascii_lowercase()
                            .contains("cannot publish over existing")
                    {
                        "Cannot publish over existing version.".to_string()
                    } else {
                        message.clone()
                    };
                    return Diagnostic::new("EPUBLISHCONFLICT", msg)
                        .with_detail("Update the version in package.json before publishing.");
                }
                RegistryError::RateLimited { .. } => {
                    return Diagnostic::new("E429", "Registry rate limit exceeded (HTTP 429)");
                }
                RegistryError::SecurityViolation(msg) => {
                    return Diagnostic::new("ESECURITY", msg);
                }
                _ => {}
            }
        }

        if let Some(fs_err) = cause.downcast_ref::<FsError>() {
            match fs_err {
                FsError::TarBombLimitExceeded { limit_type, detail } => {
                    return Diagnostic::new(
                        "ETARBOMB",
                        format!("Tar bomb resource limit exceeded ({limit_type}): {detail}"),
                    );
                }
                FsError::PathTraversal { path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Path traversal detected in tarball entry: '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::AbsolutePath { path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Absolute path rejected in tarball entry: '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::EscapingSymlink { link, target } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Symlink target '{}' escapes destination for link '{}'",
                            target.display(),
                            link.display()
                        ),
                    );
                }
                FsError::WindowsReservedDeviceName { name, path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Windows reserved device name rejected: '{name}' in path '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::TrailingDotOrSpace { name, path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Trailing dot or space rejected in component '{name}' in path '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::ForbiddenModeBits { mode, path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "SUID/SGID mode bits (0o{mode:o}) forbidden in path '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::ForbiddenSpecialEntry { path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Forbidden special entry (block, character, or fifo) in path '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::ForbiddenSparseFile { path } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Forbidden sparse file in tarball entry: '{}'",
                            path.display()
                        ),
                    );
                }
                FsError::DanglingHardlink { link, target } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Dangling hardlink '{}' targets non-existent entry '{}'",
                            link.display(),
                            target.display()
                        ),
                    );
                }
                FsError::CircularHardlink { link, target } => {
                    return Diagnostic::new(
                        "ESECURITY",
                        format!(
                            "Circular hardlink detected: link '{}' to target '{}'",
                            link.display(),
                            target.display()
                        ),
                    );
                }
                _ => {}
            }
        }

        if let Some(ManifestError::MalformedJson {
            message,
            line,
            column,
        }) = cause.downcast_ref::<ManifestError>()
        {
            if let Some(block) = npm_package_json_error() {
                return Diagnostic::new("EJSONPARSE", block);
            }
            return Diagnostic::new(
                "EJSONPARSE",
                format!("Malformed JSON in manifest: {message} at line {line}, column {column}"),
            );
        }

        if let Some(LockfileError::Json(e)) = cause.downcast_ref::<LockfileError>() {
            return Diagnostic::new(
                "EJSONPARSE",
                format!("Failed to parse package-lock.json: {e}"),
            );
        }

        if let Some(core_err) = cause.downcast_ref::<CoreError>() {
            match core_err {
                CoreError::Spec(SpecError::UnsupportedProtocol { protocol, spec }) => {
                    return Diagnostic::new(
                        "EUNSUPPORTEDPROTOCOL",
                        format!("Unsupported URL Type \"{protocol}\": {spec}"),
                    )
                    .with_detail(
                        "Supported protocols are npm registry packages, 'file:', and 'workspace:'.",
                    );
                }
                CoreError::Integrity(IntegrityError::Mismatch {
                    algorithm,
                    expected,
                    actual,
                }) => {
                    return Diagnostic::new(
                    "EINTEGRITY",
                    format!("Integrity verification failed for {algorithm}: expected '{expected}', actual '{actual}'"),
                );
                }
                CoreError::Manifest(ManifestError::MalformedJson {
                    message,
                    line,
                    column,
                }) => {
                    if let Some(block) = npm_package_json_error() {
                        return Diagnostic::new("EJSONPARSE", block);
                    }
                    return Diagnostic::new(
                        "EJSONPARSE",
                        format!(
                            "Malformed JSON in manifest: {message} at line {line}, column {column}"
                        ),
                    );
                }
                _ => {}
            }
        }
    }

    // Some installer paths erase the solver type when adding context. Recognize
    // only its two precise metadata-failure messages, not arbitrary resolution errors.
    if let Some((_, unresolved)) = err_str.rsplit_once("Unresolved dependency '") {
        if let Some((package_spec, reason)) = unresolved.split_once("': ") {
            match reason {
                "No matching version found satisfying constraint" => {
                    return Diagnostic::new("ETARGET", format!("notarget No matching version found for {package_spec}."))
                        .with_detail("notarget In most cases you or one of your dependencies are requesting a package version that doesn't exist.");
                }
                "Package not found in metadata provider" => {
                    return Diagnostic::new("E404", err_str);
                }
                _ => {}
            }
        }
    }

    // Pattern matching across error strings
    if err_str.contains("Unsupported URL Type") || err_str.contains("Unsupported protocol") {
        Diagnostic::new("EUNSUPPORTEDPROTOCOL", err_str).with_detail(
            "Supported protocols are npm registry packages, 'file:', and 'workspace:'.",
        )
    } else if err_str.contains("ERESOLVE") || err_str.contains("Conflicting peer dependency") {
        Diagnostic::new("ERESOLVE", err_str)
    } else if err_str.contains("ELOCKFILE_DRIFT")
        || err_str.contains("does not match lockfile spec")
        || err_str.contains("missing from package-lock.json")
        || err_str.contains("present in package-lock.json but removed from package.json")
    {
        Diagnostic::new("ELOCKFILE_DRIFT", err_str)
    } else if err_str.contains("Integrity verification failed")
        || err_str.contains("Integrity mismatch")
        || err_str.contains("EINTEGRITY")
    {
        Diagnostic::new("EINTEGRITY", err_str)
    } else if (err_str.contains("Package '") && err_str.contains("' not found in registry"))
        || err_str.contains("HTTP 404")
    {
        Diagnostic::new("E404", err_str)
    } else if (err_str.contains("Version '") && err_str.contains("' not found"))
        || err_str.contains("ETARGET")
    {
        Diagnostic::new("ETARGET", err_str)
    } else if err_str.contains("Authentication failed") || err_str.contains("HTTP 401") {
        Diagnostic::new("E401", err_str)
    } else if err_str.contains("Access forbidden") || err_str.contains("HTTP 403") {
        Diagnostic::new("E403", err_str)
    } else if err_str.contains("rate limit exceeded") || err_str.contains("HTTP 429") {
        Diagnostic::new("E429", err_str)
    } else if err_str.contains("Tar bomb") || err_str.contains("ETARBOMB") {
        Diagnostic::new("ETARBOMB", err_str)
    } else if err_str.contains("Path traversal")
        || err_str.contains("Absolute path rejected")
        || err_str.contains("escapes destination")
        || err_str.contains("reserved device name")
        || err_str.contains("Security violation")
        || err_str.contains("ESECURITY")
    {
        Diagnostic::new("ESECURITY", err_str)
    } else if err_str.contains("Malformed JSON")
        || err_str.contains("EJSONPARSE")
        || err_str.contains("JSON serialization/deserialization error")
        || (err_str.contains("package-lock.json")
            && (err_str.contains("syntax error")
                || err_str.contains("expected")
                || (err_str.contains("line ") && err_str.contains("column "))))
        || (err_str.contains("package.json")
            && (err_str.contains("syntax error")
                || err_str.contains("expected")
                || (err_str.contains("line ") && err_str.contains("column "))))
    {
        Diagnostic::new("EJSONPARSE", err_str)
    } else if err_str.contains("EUSAGE") || err_str.contains("Missing: ") {
        Diagnostic::new("EUSAGE", err_str)
    } else if err_str.contains("ENOLOCK")
        || err_str.contains("requires an existing lockfile")
        || err_str.contains("requires a committed lockfile")
    {
        Diagnostic::new("ENOLOCK", err_str)
    } else if err_str.contains("ENOWORKSPACES") {
        Diagnostic::new("ENOWORKSPACES", err_str)
    } else if err_str.contains("ENOTCACHED") || err_str.contains("only-if-cached") {
        Diagnostic::new("ENOTCACHED", err_str)
    } else if err_str.contains("ENOENT") || err_str.contains("package.json not found") {
        Diagnostic::new("ENOENT", err_str)
    } else if err_str.contains("FETCH_ERROR") {
        Diagnostic::new("FETCH_ERROR", err_str)
    } else {
        Diagnostic::new("EUNKNOWN", err_str)
    }
}

#[cfg(test)]
mod wave2_tests {
    use super::*;

    #[test]
    fn solver_metadata_errors_preserve_npm_error_codes() {
        for (message, code) in [
            ("No matching version found satisfying constraint", "ETARGET"),
            ("Package not found in metadata provider", "E404"),
        ] {
            let error = anyhow::Error::from(SolverError::UnresolvedDependency {
                name: "fixture".into(), spec: "999.0.0".into(), message: message.into(),
            });
            assert_eq!(classify_error(&error).code, code);
        }
        let error = anyhow::Error::from(SolverError::UnresolvedDependency {
            name: "fixture".into(), spec: "999.0.0".into(), message: "network unavailable".into(),
        });
        assert_eq!(classify_error(&error).code, "EUNKNOWN");
    }

    #[test]
    fn string_wrapped_solver_metadata_errors_preserve_npm_error_codes() {
        for (message, code) in [
            ("No matching version found satisfying constraint", "ETARGET"),
            ("Package not found in metadata provider", "E404"),
        ] {
            let error = anyhow::anyhow!("Unresolved dependency 'fixture@999.0.0': {message}")
                .context("Install resolution failed");
            assert_eq!(classify_error(&error).code, code);
        }
        let error = anyhow::anyhow!("Unresolved dependency 'fixture@999.0.0': network unavailable");
        assert_eq!(classify_error(&error).code, "EUNKNOWN");
    }
}
