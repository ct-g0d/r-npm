//! npm 11.20 config defaults (generated from @npmcli/config definitions);
//! environment-dependent defaults are computed in `npm_default`.

pub(crate) const NPM_DEFAULTS: &[(&str, &str)] = &[
    ("_auth", "null"),
    ("access", "null"),
    ("all", "false"),
    ("allow-same-version", "false"),
    ("allow-directory", "all"),
    ("allow-file", "all"),
    ("allow-git", "all"),
    ("allow-remote", "all"),
    ("allow-scripts", ""),
    ("also", "null"),
    ("audit", "true"),
    ("audit-level", "null"),
    ("auth-type", "web"),
    ("before", "null"),
    ("bin-links", "true"),
    ("browser", "null"),
    ("bypass-2fa", "false"),
    ("ca", "null"),
    ("cache-max", "Infinity"),
    ("cache-min", "0"),
    ("cafile", "null"),
    ("call", ""),
    ("cert", "null"),
    ("cidr", "null"),
    ("commit-hooks", "true"),
    ("cpu", "null"),
    ("dangerously-allow-all-scripts", "false"),
    ("depth", "null"),
    ("description", "true"),
    ("dev", "false"),
    ("diff", ""),
    ("diff-ignore-all-space", "false"),
    ("diff-name-only", "false"),
    ("diff-no-prefix", "false"),
    ("diff-dst-prefix", "b/"),
    ("diff-src-prefix", "a/"),
    ("diff-text", "false"),
    ("diff-unified", "3"),
    ("dry-run", "false"),
    ("engine-strict", "false"),
    ("expect-result-count", "null"),
    ("expect-results", "null"),
    ("expires", "null"),
    ("fetch-retries", "2"),
    ("fetch-retry-factor", "10"),
    ("fetch-retry-maxtimeout", "60000"),
    ("fetch-retry-mintimeout", "10000"),
    ("fetch-timeout", "300000"),
    ("force", "false"),
    ("foreground-scripts", "false"),
    ("format-package-lock", "true"),
    ("fund", "true"),
    ("git", "git"),
    ("git-tag-version", "true"),
    ("global", "false"),
    ("global-style", "false"),
    ("https-proxy", "null"),
    ("if-present", "false"),
    ("ignore-scripts", "false"),
    ("include", ""),
    ("include-staged", "false"),
    ("include-workspace-root", "false"),
    ("include-attestations", "false"),
    ("init-author-email", ""),
    ("init-author-name", ""),
    ("init-author-url", ""),
    ("init-license", "ISC"),
    ("init-type", "commonjs"),
    ("init-version", "1.0.0"),
    ("init-private", "false"),
    ("init.author.email", ""),
    ("init.author.name", ""),
    ("init.author.url", ""),
    ("init.license", "ISC"),
    ("init.module", "~/.npm-init.js"),
    ("init.version", "1.0.0"),
    ("install-links", "false"),
    ("install-strategy", "hoisted"),
    ("json", "false"),
    ("key", "null"),
    ("legacy-bundling", "false"),
    ("legacy-peer-deps", "false"),
    ("libc", "null"),
    ("link", "false"),
    ("local-address", "null"),
    ("location", "user"),
    ("lockfile-version", "null"),
    ("loglevel", "notice"),
    ("logs-max", "10"),
    ("long", "false"),
    ("name", "null"),
    ("maxsockets", "15"),
    ("message", "%s"),
    ("min-release-age", "null"),
    ("min-release-age-exclude", ""),
    ("node-options", "null"),
    ("noproxy", ""),
    ("offline", "false"),
    ("omit", ""),
    ("omit-lockfile-registry-resolved", "false"),
    ("only", "null"),
    ("orgs", "null"),
    ("optional", "null"),
    ("os", "null"),
    ("otp", "null"),
    ("package", ""),
    ("package-lock", "true"),
    ("package-lock-only", "false"),
    ("pack-destination", "."),
    ("packages", ""),
    ("parseable", "false"),
    ("allow-scripts-pending", "false"),
    ("allow-scripts-pin", "true"),
    ("prefer-dedupe", "false"),
    ("prefer-offline", "false"),
    ("prefer-online", "false"),
    ("preid", ""),
    ("production", "null"),
    ("progress", "false"),
    ("provenance", "false"),
    ("provenance-file", "null"),
    ("proxy", "null"),
    ("read-only", "false"),
    ("rebuild-bundle", "true"),
    ("registry", "https://registry.npmjs.org/"),
    ("replace-registry-host", "npmjs"),
    ("save", "true"),
    ("save-bundle", "false"),
    ("save-dev", "false"),
    ("save-exact", "false"),
    ("save-optional", "false"),
    ("save-peer", "false"),
    ("save-prefix", "^"),
    ("save-prod", "false"),
    ("sbom-format", "null"),
    ("sbom-type", "library"),
    ("scope", ""),
    ("scopes", "null"),
    ("packages-all", "false"),
    ("packages-and-scopes-permission", "null"),
    ("orgs-permission", "null"),
    ("password", "null"),
    ("token-description", "null"),
    ("searchexclude", ""),
    ("searchlimit", "20"),
    ("searchopts", ""),
    ("searchstaleness", "900"),
    ("shrinkwrap", "true"),
    ("sign-git-commit", "false"),
    ("sign-git-tag", "false"),
    ("strict-peer-deps", "false"),
    ("strict-allow-scripts", "false"),
    ("strict-ssl", "true"),
    ("tag", "latest"),
    ("tag-version-prefix", "v"),
    ("timing", "false"),
    ("umask", "0"),
    ("update-notifier", "true"),
    ("usage", "false"),
    ("version", "false"),
    ("versions", "false"),
    ("which", "null"),
    ("workspace", ""),
    ("workspaces", "null"),
    ("workspaces-update", "true"),
    ("yes", "null"),
];

/// npm's default for a config key, as `npm config get` prints it.
pub fn npm_default(key: &str) -> Option<String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let windows = cfg!(windows);
    let home = || env(if windows { "USERPROFILE" } else { "HOME" }).map(std::path::PathBuf::from);
    let prefix = || crate::find_global_prefix();
    let value = match key {
        "cache" => {
            if windows {
                std::path::PathBuf::from(env("LOCALAPPDATA")?).join("npm-cache")
            } else {
                home()?.join(".npm")
            }
            .display()
            .to_string()
        }
        "prefix" => prefix().display().to_string(),
        "globalconfig" => prefix().join("etc").join("npmrc").display().to_string(),
        "userconfig" => crate::find_user_npmrc()?.display().to_string(),
        "init-module" => home()?.join(".npm-init.js").display().to_string(),
        "user-agent" => {
            "npm/{npm-version} node/{node-version} {platform} {arch} workspaces/{workspaces} {ci}"
                .to_string()
        }
        "npm-version" => "11.20.0".to_string(),
        "node-version" | "tmp" => "undefined".to_string(),
        "logs-dir" | "script-shell" => "null".to_string(),
        "heading" => "npm".to_string(),
        "color" => "true".to_string(),
        "viewer" => if windows { "browser" } else { "man" }.to_string(),
        "unicode" => {
            let utf8 = ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .find_map(|k| env(k))
                .is_some_and(|v| v.to_ascii_lowercase().contains("utf"));
            (if windows { env("WT_SESSION").is_some() } else { utf8 }).to_string()
        }
        "shell" => {
            if windows {
                env("ComSpec").unwrap_or_else(|| "cmd.exe".into())
            } else {
                env("SHELL").unwrap_or_else(|| "/bin/sh".into())
            }
        }
        "editor" => env("EDITOR").or_else(|| env("VISUAL")).unwrap_or_else(|| {
            if windows {
                format!(r"{}\notepad.exe", env("SYSTEMROOT").unwrap_or_else(|| r"C:\WINDOWS".into()))
            } else {
                "vi".into()
            }
        }),
        _ => return NPM_DEFAULTS.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string()),
    };
    Some(value)
}
