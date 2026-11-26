/// Canonical list of npm configuration keys from `npm config ls -l --json` in npm 11.20.0.
pub static NPM_CONFIG_KEYS: &[&str] = &[
    "access",
    "all",
    "allow-directory",
    "allow-file",
    "allow-git",
    "allow-remote",
    "allow-same-version",
    "allow-scripts",
    "allow-scripts-pending",
    "allow-scripts-pin",
    "also",
    "audit",
    "audit-level",
    "auth-type",
    "before",
    "bin-links",
    "browser",
    "bypass-2fa",
    "ca",
    "cache",
    "cache-max",
    "cache-min",
    "cafile",
    "call",
    "cert",
    "cidr",
    "color",
    "commit-hooks",
    "cpu",
    "dangerously-allow-all-scripts",
    "depth",
    "description",
    "dev",
    "diff",
    "diff-dst-prefix",
    "diff-ignore-all-space",
    "diff-name-only",
    "diff-no-prefix",
    "diff-src-prefix",
    "diff-text",
    "diff-unified",
    "dry-run",
    "editor",
    "engine-strict",
    "expect-result-count",
    "expect-results",
    "expires",
    "fetch-retries",
    "fetch-retry-factor",
    "fetch-retry-maxtimeout",
    "fetch-retry-mintimeout",
    "fetch-timeout",
    "force",
    "foreground-scripts",
    "format-package-lock",
    "fund",
    "git",
    "git-tag-version",
    "global",
    "global-style",
    "globalconfig",
    "heading",
    "https-proxy",
    "if-present",
    "ignore-scripts",
    "include",
    "include-attestations",
    "include-staged",
    "include-workspace-root",
    "init-author-email",
    "init-author-name",
    "init-author-url",
    "init-license",
    "init-module",
    "init-private",
    "init-type",
    "init-version",
    "init.author.email",
    "init.author.name",
    "init.author.url",
    "init.license",
    "init.module",
    "init.version",
    "install-links",
    "install-strategy",
    "json",
    "key",
    "legacy-bundling",
    "legacy-peer-deps",
    "libc",
    "link",
    "local-address",
    "location",
    "lockfile-version",
    "loglevel",
    "logs-dir",
    "logs-max",
    "long",
    "maxsockets",
    "message",
    "min-release-age",
    "min-release-age-exclude",
    "name",
    "node-gyp",
    "node-options",
    "noproxy",
    "npm-version",
    "offline",
    "omit",
    "omit-lockfile-registry-resolved",
    "only",
    "optional",
    "orgs",
    "orgs-permission",
    "os",
    "otp",
    "pack-destination",
    "package",
    "package-lock",
    "package-lock-only",
    "packages",
    "packages-all",
    "packages-and-scopes-permission",
    "parseable",
    "prefer-dedupe",
    "prefer-offline",
    "prefer-online",
    "prefix",
    "preid",
    "production",
    "progress",
    "provenance",
    "provenance-file",
    "proxy",
    "read-only",
    "rebuild-bundle",
    "registry",
    "replace-registry-host",
    "save",
    "save-bundle",
    "save-dev",
    "save-exact",
    "save-optional",
    "save-peer",
    "save-prefix",
    "save-prod",
    "sbom-format",
    "sbom-type",
    "scope",
    "scopes",
    "script-shell",
    "searchexclude",
    "searchlimit",
    "searchopts",
    "searchstaleness",
    "shell",
    "shrinkwrap",
    "sign-git-commit",
    "sign-git-tag",
    "strict-allow-scripts",
    "strict-peer-deps",
    "strict-ssl",
    "tag",
    "tag-version-prefix",
    "timing",
    "token-description",
    "umask",
    "unicode",
    "update-notifier",
    "usage",
    "user-agent",
    "userconfig",
    "version",
    "versions",
    "viewer",
    "which",
    "workspace",
    "workspaces",
    "workspaces-update",
    "yes",
];

/// Keys in npm that are boolean or commonly toggled without an explicit value.
pub static NPM_BOOLEAN_CONFIG_KEYS: &[&str] = &[
    "all",
    "allow-same-version",
    "allow-scripts-pending",
    "allow-scripts-pin",
    "audit",
    "bin-links",
    "bypass-2fa",
    "color",
    "commit-hooks",
    "dangerously-allow-all-scripts",
    "description",
    "dev",
    "diff-ignore-all-space",
    "diff-name-only",
    "diff-no-prefix",
    "diff-text",
    "dry-run",
    "engine-strict",
    "force",
    "foreground-scripts",
    "format-package-lock",
    "fund",
    "git-tag-version",
    "global",
    "global-style",
    "if-present",
    "ignore-scripts",
    "include-attestations",
    "include-staged",
    "include-workspace-root",
    "init-private",
    "install-links",
    "json",
    "legacy-bundling",
    "legacy-peer-deps",
    "link",
    "long",
    "offline",
    "omit-lockfile-registry-resolved",
    "package-lock",
    "package-lock-only",
    "packages-all",
    "parseable",
    "prefer-dedupe",
    "prefer-offline",
    "prefer-online",
    "production",
    "progress",
    "provenance",
    "read-only",
    "rebuild-bundle",
    "save",
    "save-bundle",
    "save-dev",
    "save-exact",
    "save-optional",
    "save-peer",
    "save-prod",
    "shrinkwrap",
    "sign-git-commit",
    "sign-git-tag",
    "silent",
    "silly",
    "strict-allow-scripts",
    "strict-peer-deps",
    "strict-ssl",
    "timing",
    "unicode",
    "update-notifier",
    "usage",
    "verbose",
    "version",
    "versions",
    "workspaces",
    "workspaces-update",
    "yes",
];

/// Normalize a CLI flag or configuration key name into a caller-provided stack buffer when possible.
fn normalize_key_cow<'a>(key: &'a str, buf: &'a mut [u8; 128]) -> std::borrow::Cow<'a, str> {
    let stripped = key.strip_prefix("--").unwrap_or(key);
    let bytes = stripped.as_bytes();
    if bytes.len() <= buf.len() {
        let mut changed = false;
        for (dst, &b) in buf.iter_mut().zip(bytes.iter()) {
            let nb = if b == b'_' {
                b'-'
            } else {
                b.to_ascii_lowercase()
            };
            if nb != b {
                changed = true;
            }
            *dst = nb;
        }
        if !changed {
            return std::borrow::Cow::Borrowed(stripped);
        }
        // Replacing ASCII '_' -> '-' and A-Z -> a-z preserves UTF-8 validity.
        let s = std::str::from_utf8(&buf[..bytes.len()]).expect("valid UTF-8 after ASCII mapping");
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(normalize_config_key(stripped))
}

/// Normalize a CLI flag or configuration key name to standard kebab-case.
pub fn normalize_config_key(key: &str) -> String {
    let stripped = key.strip_prefix("--").unwrap_or(key);
    let mut out = String::with_capacity(stripped.len());
    for ch in stripped.chars() {
        if ch == '_' {
            out.push('-');
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

/// Returns true if the key is a recognized npm configuration key (or scoped registry/auth token).
pub fn is_known_npm_config_key(key: &str) -> bool {
    let mut buf = [0u8; 128];
    let norm = normalize_key_cow(key, &mut buf);
    let norm_stripped = norm.strip_prefix("no-").unwrap_or(&norm);
    if (norm_stripped.starts_with('@') || norm_stripped.contains(':'))
        && (norm_stripped.ends_with(":registry") || norm_stripped.ends_with("/registry"))
    {
        return true;
    }
    if norm_stripped.starts_with("//") {
        return true;
    }
    NPM_CONFIG_KEYS.binary_search(&norm_stripped).is_ok()
        || NPM_BOOLEAN_CONFIG_KEYS
            .binary_search(&norm_stripped)
            .is_ok()
}

/// Returns true if the flag represents a boolean configuration property in npm.
pub fn is_boolean_npm_config_key(key: &str) -> bool {
    let mut buf = [0u8; 128];
    let norm = normalize_key_cow(key, &mut buf);
    if norm.starts_with("no-") {
        return true;
    }
    NPM_BOOLEAN_CONFIG_KEYS.binary_search(&norm.as_ref()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_key_tables_are_sorted_for_binary_search() {
        assert!(NPM_CONFIG_KEYS.windows(2).all(|w| w[0] < w[1]));
        assert!(NPM_BOOLEAN_CONFIG_KEYS.windows(2).all(|w| w[0] < w[1]));
    }
}
