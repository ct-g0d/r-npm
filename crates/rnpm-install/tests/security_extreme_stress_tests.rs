#![allow(clippy::field_reassign_with_default)]

//! Security Extreme Borderline Stress & Torture Tests for r-npm.
//!
//! Validates `allow-git`, `allow-remote`, `allow-registry`, `allow-file`,
//! `allow-directory`, and `allowScripts` (`strict-allow-scripts`,
//! `dangerously-allow-all-scripts`, `package.json` vs `.npmrc`).

use std::collections::{BTreeMap, HashSet};
// unused path imports removed
use tempfile::tempdir;

use rnpm_config::Config;
use rnpm_core::manifest::Manifest;
use rnpm_lifecycle::{LifecyclePackageNode, PackageSource};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_install::policy::*;

// =========================================================================
// 1. AllowMode parsing, whitespace & case sensitivity
// =========================================================================

#[test]
fn test_allow_mode_parsing_case_and_whitespace() {
    assert_eq!(AllowMode::parse(Some("none")), AllowMode::None);
    assert_eq!(AllowMode::parse(Some("NONE")), AllowMode::None);
    assert_eq!(AllowMode::parse(Some(" none ")), AllowMode::None);
    assert_eq!(AllowMode::parse(Some("None\n")), AllowMode::None);
    assert_eq!(AllowMode::parse(Some("false")), AllowMode::None);
    assert_eq!(AllowMode::parse(Some("0")), AllowMode::None);

    assert_eq!(AllowMode::parse(Some("root")), AllowMode::Root);
    assert_eq!(AllowMode::parse(Some("ROOT")), AllowMode::Root);
    assert_eq!(AllowMode::parse(Some(" root\t")), AllowMode::Root);

    assert_eq!(AllowMode::parse(Some("all")), AllowMode::All);
    assert_eq!(AllowMode::parse(Some("ALL")), AllowMode::All);
    assert_eq!(AllowMode::parse(Some(" true ")), AllowMode::All);
    assert_eq!(AllowMode::parse(Some("")), AllowMode::All);
    assert_eq!(AllowMode::parse(None), AllowMode::All);
    assert_eq!(AllowMode::parse(Some("unknown")), AllowMode::All);
}

// =========================================================================
// 2. parse_source_kind URL schemes, whitespace, case, npm: aliases
// =========================================================================

#[test]
fn test_parse_source_kind_url_schemes_and_case() {
    // Git schemes
    assert_eq!(parse_source_kind("git+https://github.com/foo/bar.git"), SourceKind::Git);
    assert_eq!(parse_source_kind("GIT+HTTPS://github.com/foo/bar.git"), SourceKind::Git);
    assert_eq!(parse_source_kind(" git+file:///C:/path/repo.git "), SourceKind::Git);
    assert_eq!(parse_source_kind("GIT+FILE://C:/repo.git"), SourceKind::Git);
    assert_eq!(parse_source_kind("ssh://git@github.com/foo/bar.git"), SourceKind::Git);
    assert_eq!(parse_source_kind("git://github.com/foo/bar.git"), SourceKind::Git);
    assert_eq!(parse_source_kind("git@github.com:foo/bar.git"), SourceKind::Git);
    assert_eq!(parse_source_kind("github:user/repo"), SourceKind::Git);
    assert_eq!(parse_source_kind("GITHUB:user/repo"), SourceKind::Git);
    assert_eq!(parse_source_kind("gitlab:user/repo"), SourceKind::Git);
    assert_eq!(parse_source_kind("bitbucket:user/repo"), SourceKind::Git);
    assert_eq!(parse_source_kind("gist:1234567"), SourceKind::Git);
    assert_eq!(parse_source_kind("user/repo"), SourceKind::Git);
    assert_eq!(parse_source_kind("user/repo#main"), SourceKind::Git);
    assert_eq!(parse_source_kind("user/repo#semver:^1.0.0"), SourceKind::Git);

    // Remote HTTP(S) schemes
    assert_eq!(parse_source_kind("http://example.com/foo.tgz"), SourceKind::Remote);
    assert_eq!(parse_source_kind("HTTP://example.com/foo.tgz"), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://example.com/foo.tgz"), SourceKind::Remote);
    assert_eq!(parse_source_kind(" HTTPS://example.com/foo.tgz "), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://example.com/not-tarball"), SourceKind::Remote);

    // File vs Directory
    assert_eq!(parse_source_kind("file:./pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind("FILE:./pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind("file:../pkg.tar.gz"), SourceKind::File);
    assert_eq!(parse_source_kind("file:../pkg.tar"), SourceKind::File);
    assert_eq!(parse_source_kind("./tarballs/pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind(".\\tarballs\\pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind("../pkg.tgz"), SourceKind::File);

    assert_eq!(parse_source_kind("file:./local-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind("FILE:./local-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind("./local-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind(".\\local-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind("../parent-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind("..\\parent-dir"), SourceKind::Directory);
    assert_eq!(parse_source_kind("/absolute/path"), SourceKind::Directory);
    assert_eq!(parse_source_kind("~/home/path"), SourceKind::Directory);

    // Registry
    assert_eq!(parse_source_kind("^1.0.0"), SourceKind::Registry);
    assert_eq!(parse_source_kind("~2.3.4"), SourceKind::Registry);
    assert_eq!(parse_source_kind("1.2.3"), SourceKind::Registry);
    assert_eq!(parse_source_kind("*"), SourceKind::Registry);
    assert_eq!(parse_source_kind("latest"), SourceKind::Registry);
    assert_eq!(parse_source_kind("@scope/pkg"), SourceKind::Registry);
}

#[test]
fn test_parse_source_kind_npm_alias_smuggling_attempts() {
    // Unscoped alias targeting git/remote/file/directory
    assert_eq!(
        parse_source_kind("npm:target@git+https://github.com/evil/repo.git"),
        SourceKind::Git
    );
    assert_eq!(
        parse_source_kind("npm:target@https://evil.com/payload.tgz"),
        SourceKind::Remote
    );
    assert_eq!(
        parse_source_kind("npm:target@file:./local.tgz"),
        SourceKind::File
    );
    assert_eq!(
        parse_source_kind("npm:target@file:./local-dir"),
        SourceKind::Directory
    );
    assert_eq!(
        parse_source_kind("npm:target@./local-dir"),
        SourceKind::Directory
    );
    assert_eq!(
        parse_source_kind("npm:target@github:user/repo"),
        SourceKind::Git
    );

    // Scoped alias targeting git/remote/file/directory
    assert_eq!(
        parse_source_kind("npm:@evil/target@git+https://github.com/evil/repo.git"),
        SourceKind::Git
    );
    assert_eq!(
        parse_source_kind("npm:@evil/target@https://evil.com/payload.tgz"),
        SourceKind::Remote
    );
    assert_eq!(
        parse_source_kind("npm:@evil/target@file:../secret.tgz"),
        SourceKind::File
    );
    assert_eq!(
        parse_source_kind("npm:@evil/target@file:../secret-dir"),
        SourceKind::Directory
    );

    // Case-insensitive alias prefix
    assert_eq!(
        parse_source_kind("NPM:target@git+https://github.com/evil/repo.git"),
        SourceKind::Git
    );
    assert_eq!(
        parse_source_kind("Npm:target@https://evil.com/payload.tgz"),
        SourceKind::Remote
    );

    // Normal registry aliases
    assert_eq!(parse_source_kind("npm:target@^1.0.0"), SourceKind::Registry);
    assert_eq!(parse_source_kind("npm:target"), SourceKind::Registry);
    assert_eq!(parse_source_kind("npm:@scope/target@1.2.3"), SourceKind::Registry);
    assert_eq!(parse_source_kind("npm:@scope/target"), SourceKind::Registry);
}

// =========================================================================
// 3. is_registry_tarball strict validation
// =========================================================================

#[test]
fn test_is_registry_tarball_strict_and_borderline() {
    // Valid standard registry tarballs
    assert!(is_registry_tarball("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("https://registry.npmjs.org/@scope/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("https://registry.npmjs.org/@scope%2ffoo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("http://127.0.0.1:4873/foo/-/foo-0.1.0.tgz"));
    assert!(is_registry_tarball("https://registry.yarnpkg.com/bar/-/bar-2.0.0-beta.1.tgz"));
    assert!(is_registry_tarball("https://custom.repo.com/artifactory/npm/foo/-/foo-1.2.3.tgz?token=xyz#hash"));
    assert!(is_registry_tarball("HTTPS://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));

    // Invalid & forged tarball URLs attempting to masquerade as registry
    assert!(!is_registry_tarball("https://evil.com/-/a-1.0.0.tgz")); // empty package name
    assert!(!is_registry_tarball("https://evil.com/a.tgz")); // no /-/
    assert!(!is_registry_tarball("https://evil.com/downloads/-/payload-1.0.0.tgz")); // name mismatch: downloads vs payload
    assert!(!is_registry_tarball("https://evil.com/foo/-/bar-1.0.0.tgz")); // name mismatch: foo vs bar
    assert!(!is_registry_tarball("https://registry.npmjs.org/@scope/foo/-/bar-1.0.0.tgz")); // name mismatch
    assert!(!is_registry_tarball("https://evil.com/foo/-/foo-1.0.0.tar.gz")); // not .tgz
    assert!(!is_registry_tarball("https://evil.com/foo/-/foo-1.0.0.exe")); // not .tgz
    assert!(!is_registry_tarball("https://evil.com/foo/-/foo-notversion.tgz")); // version doesn't start with digit
    assert!(!is_registry_tarball("ftp://evil.com/foo/-/foo-1.0.0.tgz")); // non-http(s)
}

// =========================================================================
// 4. Source policy enforcement: allow-remote=none, allow-registry=none, etc.
// =========================================================================

#[test]
fn test_registry_tarballs_never_false_positive_on_allow_remote_none() {
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("reg-dep".to_string(), "^1.0.0".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/reg-dep".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/reg-dep/-/reg-dep-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        remote: AllowMode::None, // Strict allow-remote=none!
        ..Default::default()
    };

    let root_declared = HashSet::from(["reg-dep".to_string()]);
    let workspace_paths = HashSet::new();

    // MUST pass: normal registry tarballs are not remote!
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Registry tarball should not fail allow-remote=none: {:?}", res.err());
}

#[test]
fn test_direct_url_tarballs_blocked_under_allow_remote_none() {
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert(
        "direct-url".to_string(),
        "https://registry.npmjs.org/direct-url/-/direct-url-1.0.0.tgz".to_string(),
    );
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/direct-url".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/direct-url/-/direct-url-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        remote: AllowMode::None,
        ..Default::default()
    };

    let root_declared = HashSet::from([
        "direct-url".to_string(),
        "https://registry.npmjs.org/direct-url/-/direct-url-1.0.0.tgz".to_string(),
    ]);
    let workspace_paths = HashSet::new();

    // MUST fail: explicit direct URL tarball is remote!
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Direct URL must fail under allow-remote=none");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWREMOTE"), "Expected EALLOWREMOTE, got: {err}");
}

#[test]
fn test_allow_registry_none_enforcement() {
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("reg-dep".to_string(), "^1.0.0".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/reg-dep".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/reg-dep/-/reg-dep-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        registry: AllowMode::None,
        ..Default::default()
    };

    let root_declared = HashSet::from(["reg-dep".to_string()]);
    let workspace_paths = HashSet::new();

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected allow-registry=none to fail");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWREGISTRY"), "Expected EALLOWREGISTRY, got: {err}");
}

// =========================================================================
// 5. Smuggling via Overrides & Pre-existing Lockfiles (rnpm ci)
// =========================================================================

#[test]
fn test_smuggling_attempt_via_overrides_blocked() {
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("parent".to_string(), "^1.0.0".to_string());

    let mut root_pkg = LockfilePackage {
        dependencies: Some(root_deps),
        ..Default::default()
    };

    // Override attempting to redirect transitive child to git!
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "transitive": "git+https://github.com/evil/repo.git"
        }),
    );
    packages.insert(String::new(), root_pkg);

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        git: AllowMode::None,
        ..Default::default()
    };

    let root_declared = HashSet::from(["parent".to_string()]);
    let workspace_paths = HashSet::new();

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected override with git spec to fail under allow-git=none");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err}");
}

#[test]
fn test_smuggling_attempt_via_nested_overrides_under_allow_git_root() {
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("parent".to_string(), "^1.0.0".to_string());

    let mut root_pkg = LockfilePackage {
        dependencies: Some(root_deps),
        ..Default::default()
    };

    // Nested override rule targeting non-root edge
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "parent": {
                "transitive": "git+https://github.com/evil/repo.git"
            }
        }),
    );
    packages.insert(String::new(), root_pkg);

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        git: AllowMode::Root, // Only root allowed, non-root must fail!
        ..Default::default()
    };

    let root_declared = HashSet::from(["parent".to_string()]);
    let workspace_paths = HashSet::new();

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected nested override to fail under allow-git=root");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err}");
    assert!(err.contains("non-root"), "Expected non-root in message, got: {err}");
}

#[test]
fn test_smuggling_attempt_via_non_node_modules_lockfile_key() {
    let mut packages = BTreeMap::new();
    packages.insert(
        String::new(),
        LockfilePackage::default(),
    );
    // Smuggled non-node_modules package in pre-existing lockfile!
    packages.insert(
        "vendor/evil-lib".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/evil/repo.git".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        git: AllowMode::Root,
        ..Default::default()
    };

    let root_declared = HashSet::new();
    let workspace_paths = HashSet::new();

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected smuggled vendor key to be gated and rejected");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err}");
}

// =========================================================================
// 6. allowScripts Policy Torture Tests
// =========================================================================

#[test]
fn test_allow_scripts_exact_name_vs_range_vs_dist_tag() {
    let temp = tempdir().unwrap();
    let pkg_json = serde_json::json!({
        "name": "test-pkg",
        "allowScripts": {
            "exact-pkg": true,
            "exact-ver@1.2.3": true,
            "disjunction@1.0.0 || 2.0.0": true,
            "@scoped/pkg": true,
            "@scoped/exact@3.0.0": true,
            "denied-pkg": false,
            "denied-ver@1.0.0": false,
            "range-pkg@^1.0.0": true,
            "tilde-pkg@~2.0.0": true,
            "tag-pkg@latest": true,
            "tag-pkg@next": true
        }
    });
    std::fs::write(temp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let config = Config::default();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    // Verify ranges and dist-tags were dropped with warnings
    assert!(policy.warnings.iter().any(|w| w.contains("range-pkg@^1.0.0")));
    assert!(policy.warnings.iter().any(|w| w.contains("tilde-pkg@~2.0.0")));
    assert!(policy.warnings.iter().any(|w| w.contains("tag-pkg@latest")));
    assert!(policy.warnings.iter().any(|w| w.contains("tag-pkg@next")));

    // Verify exact entries remained
    let entries = policy.entries.as_ref().unwrap();
    assert!(entries.iter().any(|(k, v)| k == "exact-pkg" && *v));
    assert!(entries.iter().any(|(k, v)| k == "exact-ver@1.2.3" && *v));
    assert!(entries.iter().any(|(k, v)| k == "@scoped/pkg" && *v));
    assert!(entries.iter().any(|(k, v)| k == "denied-pkg" && !*v));

    // Test verdict on nodes
    let node_exact = ScriptNode {
        location: "node_modules/exact-pkg",
        resolved: Some("https://registry.npmjs.org/exact-pkg/-/exact-pkg-1.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_exact), Some(true));

    let node_ver_match = ScriptNode {
        location: "node_modules/exact-ver",
        resolved: Some("https://registry.npmjs.org/exact-ver/-/exact-ver-1.2.3.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_ver_match), Some(true));

    let node_ver_mismatch = ScriptNode {
        location: "node_modules/exact-ver",
        resolved: Some("https://registry.npmjs.org/exact-ver/-/exact-ver-1.2.4.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_ver_mismatch), None);

    let node_disjunction = ScriptNode {
        location: "node_modules/disjunction",
        resolved: Some("https://registry.npmjs.org/disjunction/-/disjunction-2.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_disjunction), Some(true));

    let node_scoped = ScriptNode {
        location: "node_modules/@scoped/pkg",
        resolved: Some("https://registry.npmjs.org/@scoped/pkg/-/pkg-5.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_scoped), Some(true));

    let node_denied = ScriptNode {
        location: "node_modules/denied-pkg",
        resolved: Some("https://registry.npmjs.org/denied-pkg/-/denied-pkg-1.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_denied), Some(false));
}

#[test]
fn test_allow_scripts_denied_wins_over_allowed() {
    let temp = tempdir().unwrap();
    let pkg_json = serde_json::json!({
        "name": "test-pkg",
        "allowScripts": {
            "conflict-pkg": true,
            "conflict-pkg@1.0.0": false
        }
    });
    std::fs::write(temp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let config = Config::default();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    let node_denied_ver = ScriptNode {
        location: "node_modules/conflict-pkg",
        resolved: Some("https://registry.npmjs.org/conflict-pkg/-/conflict-pkg-1.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    // Deny MUST win over allow!
    assert_eq!(policy.verdict(&node_denied_ver), Some(false));

    let node_allowed_ver = ScriptNode {
        location: "node_modules/conflict-pkg",
        resolved: Some("https://registry.npmjs.org/conflict-pkg/-/conflict-pkg-2.0.0.tgz"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    // Version 2.0.0 was not explicitly denied, so general allow wins
    assert_eq!(policy.verdict(&node_allowed_ver), Some(true));
}

#[test]
fn test_allow_scripts_file_path_matching() {
    let temp = tempdir().unwrap();
    let local_dir = temp.path().join("local-addon");
    std::fs::create_dir_all(&local_dir).unwrap();

    let pkg_json = serde_json::json!({
        "name": "test-pkg",
        "allowScripts": {
            "file:./local-addon": true
        }
    });
    std::fs::write(temp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let config = Config::default();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    let node_resolved_file = ScriptNode {
        location: "node_modules/local-addon",
        resolved: Some("file:local-addon"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_resolved_file), Some(true));

    // Fallback to location when resolved is None (e.g. symlink)
    let node_location_fallback = ScriptNode {
        location: "local-addon",
        resolved: None,
        lock_name: None,
        in_bundle: false,
        link: true,
        project_dir: temp.path(),
    };
    assert_eq!(policy.verdict(&node_location_fallback), Some(true));
}

#[test]
fn test_nested_transitive_package_cannot_inherit_parent_approval_under_strict() {
    let temp = tempdir().unwrap();
    // Only parent-pkg is approved!
    let pkg_json = serde_json::json!({
        "name": "test-pkg",
        "allowScripts": {
            "parent-pkg": true
        }
    });
    std::fs::write(temp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let mut config = Config::default();
    config.npmrc.set("strict-allow-scripts", "true").unwrap();
    let policy = ScriptPolicy::load(temp.path(), &config, false);
    assert!(policy.strict);

    let mut parent_manifest = Manifest::default();
    parent_manifest.name = Some("parent-pkg".to_string());
    parent_manifest.version = Some("1.0.0".to_string());
    parent_manifest.scripts.insert("install".to_string(), "echo parent".to_string());

    let mut child_manifest = Manifest::default();
    child_manifest.name = Some("child-pkg".to_string());
    child_manifest.version = Some("1.0.0".to_string());
    child_manifest.scripts.insert("postinstall".to_string(), "echo child".to_string());

    let nodes = vec![
        LifecyclePackageNode {
            package_path: "node_modules/parent-pkg".to_string(),
            disk_path: temp.path().join("node_modules/parent-pkg"),
            manifest: parent_manifest,
            source: PackageSource::Registry,
            dependencies: vec![],
            optional: false,
        },
        LifecyclePackageNode {
            package_path: "node_modules/parent-pkg/node_modules/child-pkg".to_string(),
            disk_path: temp.path().join("node_modules/parent-pkg/node_modules/child-pkg"),
            manifest: child_manifest,
            source: PackageSource::Registry,
            dependencies: vec![],
            optional: false,
        },
    ];

    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/parent-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/parent-pkg/-/parent-pkg-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/parent-pkg/node_modules/child-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/child-pkg/-/child-pkg-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    // Under strict-allow-scripts, child-pkg MUST trigger ESTRICTALLOWSCRIPTS!
    let res = apply_script_policy(nodes, &lockfile, temp.path(), &policy);
    assert!(res.is_err(), "Expected child-pkg to fail under strict-allow-scripts");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("ESTRICTALLOWSCRIPTS"), "Expected ESTRICTALLOWSCRIPTS, got: {err}");
    assert!(err.contains("child-pkg@1.0.0"), "Error should report unreviewed child package, got: {err}");
}

#[test]
fn test_strict_preflight_blocks_unreviewed_install_scripts_present() {
    let temp = tempdir().unwrap();
    let mut config = Config::default();
    config.npmrc.set("strict-allow-scripts", "true").unwrap();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/unreviewed".to_string(),
        LockfilePackage {
            name: Some("unreviewed".to_string()),
            version: Some("2.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/unreviewed/-/unreviewed-2.0.0.tgz".to_string()),
            has_install_script: Some(true),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let ws = HashSet::new();
    let res = strict_preflight(&lockfile, temp.path(), &ws, &policy, false);
    assert!(res.is_err(), "strict_preflight must fail on unreviewed package with hasInstallScript");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("ESTRICTALLOWSCRIPTS"), "Expected ESTRICTALLOWSCRIPTS, got: {err}");
    assert!(err.contains("unreviewed@2.0.0"), "Expected package name in error, got: {err}");
}

#[test]
fn test_ignore_scripts_and_dangerously_allow_all_bypass_strict() {
    let temp = tempdir().unwrap();

    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/unreviewed".to_string(),
        LockfilePackage {
            name: Some("unreviewed".to_string()),
            version: Some("2.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/unreviewed/-/unreviewed-2.0.0.tgz".to_string()),
            has_install_script: Some(true),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let ws = HashSet::new();

    // 1. With ignore_scripts=true:
    let mut config = Config::default();
    config.npmrc.set("strict-allow-scripts", "true").unwrap();
    let policy = ScriptPolicy::load(temp.path(), &config, false);
    assert!(strict_preflight(&lockfile, temp.path(), &ws, &policy, true).is_ok());

    // 2. With dangerously-allow-all-scripts=true:
    let mut config_all = Config::default();
    config_all.npmrc.set("strict-allow-scripts", "true").unwrap();
    config_all.npmrc.set("dangerously-allow-all-scripts", "true").unwrap();
    let policy_all = ScriptPolicy::load(temp.path(), &config_all, false);
    assert!(policy_all.allow_all);
    assert!(strict_preflight(&lockfile, temp.path(), &ws, &policy_all, false).is_ok());

    let warning = unreviewed_scripts_warning(&lockfile, temp.path(), &ws, &policy_all, false);
    assert!(warning.is_none());
}

#[test]
fn test_unreviewed_scripts_warning_advisory_in_standard_mode() {
    let temp = tempdir().unwrap();
    let config = Config::default(); // Standard mode, neither strict nor allow-all
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    let pkg_dir = temp.path().join("node_modules/advisory-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::json!({
            "name": "advisory-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "echo build"
            }
        })
        .to_string(),
    )
    .unwrap();

    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/advisory-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/advisory-pkg/-/advisory-pkg-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let ws = HashSet::new();

    let warning = unreviewed_scripts_warning(&lockfile, temp.path(), &ws, &policy, false);
    assert!(warning.is_some());
    let w = warning.unwrap();
    assert!(w.contains("1 package has install scripts not yet covered by allowScripts"));
    assert!(w.contains("advisory-pkg@1.0.0"));
    assert!(w.contains("npm install-scripts approve"));
}

#[test]
fn test_nested_transitive_package_prepare_script_non_registry() {
    let temp = tempdir().unwrap();
    let pkg_dir = temp.path().join("git-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("git-pkg".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.scripts.insert("prepare".to_string(), "npm run build".to_string());

    // 1. For a registry source, prepare is NEVER included in install_scripts
    let reg_scripts = install_scripts(&manifest, &pkg_dir, true);
    assert!(reg_scripts.is_empty(), "Registry source should not include prepare script");

    // 2. For a non-registry (e.g. git/dir) source, prepare MUST be included
    let non_reg_scripts = install_scripts(&manifest, &pkg_dir, false);
    assert_eq!(non_reg_scripts.len(), 1);
    assert_eq!(non_reg_scripts[0].0, "prepare");
    assert_eq!(non_reg_scripts[0].1, "npm run build");

    // 3. Under strict-allow-scripts, unreviewed prepare MUST trigger ESTRICTALLOWSCRIPTS
    let mut config = Config::default();
    config.npmrc.set("strict-allow-scripts", "true").unwrap();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    let nodes = vec![
        LifecyclePackageNode {
            package_path: "node_modules/parent/node_modules/git-pkg".to_string(),
            disk_path: pkg_dir,
            manifest,
            source: PackageSource::Git,
            dependencies: vec![],
            optional: false,
        },
    ];

    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/parent/node_modules/git-pkg".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/upstream/git-pkg.git#commit".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let res = apply_script_policy(nodes, &lockfile, temp.path(), &policy);
    assert!(res.is_err(), "Expected unreviewed prepare script to fail under strict-allow-scripts");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("ESTRICTALLOWSCRIPTS"), "Expected ESTRICTALLOWSCRIPTS, got: {err}");
    assert!(err.contains("prepare: npm run build"), "Expected prepare script details in error, got: {err}");
}

#[test]
fn test_binding_gyp_auto_injection_and_gypfile_false_suppression() {
    let temp = tempdir().unwrap();
    let pkg_dir = temp.path().join("native-addon");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(pkg_dir.join("binding.gyp"), "{}").unwrap();

    // 1. Without gypfile: false, auto-injects node-gyp rebuild
    let mut manifest = Manifest::default();
    manifest.name = Some("native-addon".to_string());
    manifest.version = Some("1.0.0".to_string());

    let scripts = install_scripts(&manifest, &pkg_dir, true);
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].0, "install");
    assert_eq!(scripts[0].1, "node-gyp rebuild");

    // 2. With gypfile: false in manifest.extra, auto-injection is suppressed
    manifest.extra.insert("gypfile".to_string(), serde_json::Value::Bool(false));
    let scripts_suppressed = install_scripts(&manifest, &pkg_dir, true);
    assert!(scripts_suppressed.is_empty(), "gypfile: false should suppress node-gyp auto-injection");
}

#[test]
fn test_npmrc_allow_scripts_comma_and_space_separated() {
    let temp = tempdir().unwrap();
    let mut config = Config::default();
    config.npmrc.set("allow-scripts", "pkg-a, pkg-b @scoped/pkg-c pkg-d").unwrap();

    let policy = ScriptPolicy::load(temp.path(), &config, false);
    let entries = policy.entries.as_ref().unwrap();
    let keys: HashSet<String> = entries.iter().map(|(k, _)| k.clone()).collect();

    assert!(keys.contains("pkg-a"));
    assert!(keys.contains("pkg-b"));
    assert!(keys.contains("@scoped/pkg-c"));
    assert!(keys.contains("pkg-d"));
}

#[test]
fn test_package_json_allow_scripts_overrides_npmrc_with_warning() {
    let temp = tempdir().unwrap();
    let pkg_json = serde_json::json!({
        "name": "test-pkg",
        "allowScripts": {
            "from-package-json": true
        }
    });
    std::fs::write(temp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let mut config = Config::default();
    config.npmrc.set("allow-scripts", "from-npmrc").unwrap();

    let policy = ScriptPolicy::load(temp.path(), &config, false);
    let entries = policy.entries.as_ref().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "from-package-json");

    assert!(policy.warnings.iter().any(|w| {
        w.contains(".npmrc allow-scripts setting is being ignored because package.json declares its own allowScripts field")
    }));
}

#[test]
fn test_smuggling_attempt_via_optional_dependencies_blocked() {
    let mut packages = BTreeMap::new();
    let mut root_optional = BTreeMap::new();
    root_optional.insert(
        "opt-git-dep".to_string(),
        "git+https://github.com/evil/opt-repo.git".to_string(),
    );

    packages.insert(
        String::new(),
        LockfilePackage {
            optional_dependencies: Some(root_optional),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let policy = SourcePolicy {
        git: AllowMode::None,
        ..Default::default()
    };

    let root_declared = HashSet::from(["opt-git-dep".to_string()]);
    let workspace_paths = HashSet::new();

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected git spec in optionalDependencies to fail under allow-git=none");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err}");
}

#[tokio::test]
async fn test_rebuild_interaction_with_ignore_scripts() {
    use rnpm_install::rebuild::{execute_rebuild, RebuildOptions};

    let temp = tempdir().unwrap();
    let nm = temp.path().join("node_modules/rebuild-target");
    std::fs::create_dir_all(&nm).unwrap();
    std::fs::write(
        nm.join("package.json"),
        serde_json::json!({
            "name": "rebuild-target",
            "version": "1.0.0",
            "scripts": {
                "install": "echo should not run under ignore-scripts"
            }
        })
        .to_string(),
    )
    .unwrap();

    let options = RebuildOptions {
        project_dir: temp.path().to_path_buf(),
        packages: vec![],
        ignore_scripts: true, // Should skip all rebuild scripts immediately!
        foreground_scripts: false,
        strict_sandbox: false,
    };

    let summary = execute_rebuild(&options).await.unwrap();
    assert!(
        summary.rebuilt_packages.is_empty(),
        "execute_rebuild with ignore_scripts: true must not rebuild any package"
    );
}

// =========================================================================
// 7. Round 2 Regression Tests: Committish Collision, Mixed-Case, %40, Git Shorthand, Windows Paths
// =========================================================================

#[test]
fn test_git_committish_prefix_collision_prevention() {
    let temp = tempdir().unwrap();

    // 1. #main must NOT match #main-exploit
    let node_main_exploit = ScriptNode {
        location: "node_modules/git-dep",
        resolved: Some("git+https://github.com/user/repo.git#main-exploit"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(!node_main_exploit.matches("github:user/repo#main", false));

    // 2. #v1 must NOT match #v10.0.0
    let node_v10 = ScriptNode {
        location: "node_modules/git-dep",
        resolved: Some("git+https://github.com/user/repo.git#v10.0.0"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(!node_v10.matches("github:user/repo#v1", false));

    // 3. Exact non-hex ref MUST match
    let node_main_exact = ScriptNode {
        location: "node_modules/git-dep",
        resolved: Some("git+https://github.com/user/repo.git#main"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(node_main_exact.matches("github:user/repo#main", false));

    // 4. Valid hex SHA prefix (>= 7 chars) MUST match full 40-char SHA
    let full_sha = "7b3f12a0123456789abcdef0123456789abcdef";
    let node_sha = ScriptNode {
        location: "node_modules/git-dep",
        resolved: Some(&format!("git+https://github.com/user/repo.git#{full_sha}")),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(node_sha.matches("github:user/repo#7b3f12a", false));
    assert!(!node_sha.matches("github:user/repo#7b3f12b", false)); // different SHA prefix

    // 5. Short hex ref (< 7 chars) requires exact equality
    assert!(!node_sha.matches("github:user/repo#7b3f12", false));
}

#[test]
fn test_mixed_case_url_schemes_in_is_registry_tarball() {
    assert!(is_registry_tarball("Https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("Http://127.0.0.1:4873/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("hTtPs://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("hTtP://127.0.0.1:4873/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("HTTPS://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("HTTP://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    assert!(is_registry_tarball("http://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
}

#[test]
fn test_percent_40_scope_decoding_in_registry_identity() {
    let temp = tempdir().unwrap();
    let url = "https://registry.npmjs.org/%40scope%2Fpkg/-/pkg-1.0.0.tgz";
    assert!(is_registry_tarball(url));

    let node = ScriptNode {
        location: "node_modules/@scope/pkg",
        resolved: Some(url),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };

    assert_eq!(
        node.registry_identity(),
        Some(("@scope/pkg".to_string(), Some("1.0.0".to_string())))
    );

    // Matching against @scope/pkg policy must succeed
    assert!(node.matches("@scope/pkg", false));
    assert!(node.matches("@scope/pkg@1.0.0", false));
}

#[test]
fn test_git_shorthand_case_insensitivity() {
    let temp = tempdir().unwrap();

    let (repo, committish) = git_identity("GitHub:user/repo#main").unwrap();
    assert_eq!(repo, "github.com/user/repo");
    assert_eq!(committish, "main");

    let (repo_upper, _) = git_identity("GITHUB:user/repo").unwrap();
    assert_eq!(repo_upper, "github.com/user/repo");

    let (repo_gitlab, _) = git_identity("GitLab:user/repo").unwrap();
    assert_eq!(repo_gitlab, "gitlab.com/user/repo");

    let (repo_bb, _) = git_identity("BitBucket:user/repo").unwrap();
    assert_eq!(repo_bb, "bitbucket.org/user/repo");

    let (repo_gist, _) = git_identity("Gist:1234567").unwrap();
    assert_eq!(repo_gist, "gist.github.com/1234567");

    let node = ScriptNode {
        location: "node_modules/my-repo",
        resolved: Some("git+https://github.com/user/repo.git#main"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };

    assert!(node.matches("GitHub:user/repo#main", false));
    assert!(node.matches("GITHUB:user/repo", false));
}

#[test]
fn test_lexical_path_fallback_and_windows_workspace_backslash() {
    let temp = tempdir().unwrap();

    // 1. Lexical normalization matches non-existent path: ./nonexistent/pkg vs nonexistent/pkg
    let p1 = temp.path().join("./nonexistent/pkg");
    let p2 = temp.path().join("nonexistent/pkg");
    assert_eq!(normalize_path(&p1), normalize_path(&p2));

    // 2. Windows backslash in workspace resolved symlink
    let mut packages = BTreeMap::new();
    packages.insert(
        "node_modules/ws-link".to_string(),
        LockfilePackage {
            link: Some(true),
            resolved: Some("packages\\my-ws".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };

    let mut workspace_paths = HashSet::new();
    workspace_paths.insert("packages/my-ws".to_string());

    let mut config = Config::default();
    config.npmrc.set("strict-allow-scripts", "true").unwrap();
    let policy = ScriptPolicy::load(temp.path(), &config, false);

    // strict_preflight MUST recognize "packages\\my-ws" as in workspace_paths and skip checking it as an external package
    assert!(strict_preflight(&lockfile, temp.path(), &workspace_paths, &policy, false).is_ok());
    assert!(unreviewed_scripts_warning(&lockfile, temp.path(), &workspace_paths, &policy, false).is_none());
}

#[test]
fn test_git_identity_non_ascii_prefix_boundary_safety() {
    let temp = tempdir().unwrap();

    // 1. Multi-byte UTF-8 character where byte 5, 7, or 10 lands mid-codepoint.
    // "你好世界" is 12 bytes: [0..3, 3..6, 6..9, 9..12]. Canonicalized as GitHub shorthand to github.com/...
    let (repo_zh, committish_zh) = git_identity("你好世界/repo#main").unwrap();
    assert_eq!(repo_zh, "github.com/你好世界/repo");
    assert_eq!(committish_zh, "main");

    // 2. 4-byte UTF-8 emoji "🦀" (bytes 0..4).
    let (repo_crab, committish_crab) = git_identity("🦀/repo#feat").unwrap();
    assert_eq!(repo_crab, "github.com/🦀/repo");
    assert_eq!(committish_crab, "feat");

    // 3. Accented character "é" (2 bytes).
    let (repo_accent, _) = git_identity("école/projet").unwrap();
    assert_eq!(repo_accent, "github.com/école/projet");

    // 4. Multiple emojis with byte length > 10, crossing 5, 7, and 10 byte boundaries.
    let (repo_multi, _) = git_identity("🚀🎉🔥/tools").unwrap();
    assert_eq!(repo_multi, "github.com/🚀🎉🔥/tools");

    // 5. Cyrillic text with 2-byte characters.
    let (repo_cyr, committish_cyr) = git_identity("git+https://example.com/пользователь/проект#v1.0").unwrap();
    assert_eq!(repo_cyr, "example.com/пользователь/проект");
    assert_eq!(committish_cyr, "v1.0");

    let (repo_git_at, _) = git_identity("git@example.com:пользователь/проект").unwrap();
    assert_eq!(repo_git_at, "example.com/пользователь/проект");

    // 6. ScriptNode matching with non-ASCII git spec and shorthand
    let node = ScriptNode {
        location: "node_modules/unicode-dep",
        resolved: Some("git+https://github.com/用户/仓库.git#main"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(node.matches("用户/仓库#main", false));
    assert!(node.matches("用户/仓库", false));
    assert!(node.matches("github:用户/仓库#main", false));
    assert!(node.matches("git+https://github.com/用户/仓库.git#main", false));
}

#[test]
fn test_utf8_boundary_specs_no_panic() {
    // 1. parse_source_kind on multi-byte UTF-8 specs
    assert_eq!(parse_source_kind("./中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind(".\\中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("/中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("\\中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("~/中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("~\\中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("./中文/pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind(".\\中文\\pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind("npm:中文@./中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("npm:中文@.\\中文"), SourceKind::Directory);
    assert_eq!(parse_source_kind("npm:中文@^1.0.0"), SourceKind::Registry);
    assert_eq!(parse_source_kind("npm:中文"), SourceKind::Registry);

    // 2. check_sources with multi-byte UTF-8 spec in root_declared and lockfile
    let mut root_declared = HashSet::new();
    root_declared.insert("./中文".to_string());
    root_declared.insert(".\\中文".to_string());
    root_declared.insert("npm:中文@./中文".to_string());
    root_declared.insert("chinese-dep".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("chinese-dep".to_string(), "./中文".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/chinese-dep".to_string(),
        LockfilePackage {
            resolved: Some("./中文".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-utf8".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        directory: AllowMode::All,
        remote: AllowMode::None,
        ..Default::default()
    };

    // Must NOT panic and must succeed!
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected check_sources with UTF-8 to succeed, got: {:?}", res.err());
}

#[test]
fn test_nested_npm_aliases_unpacking_and_smuggling_blocking() {
    // 1. Unpacking nested aliases
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar@https://evil.com/payload.tgz"),
        SourceKind::Remote
    );
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar@git+https://evil.com/repo.git"),
        SourceKind::Git
    );
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar@file:./local.tgz"),
        SourceKind::File
    );
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar@./local-dir"),
        SourceKind::Directory
    );
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar@^1.0.0"),
        SourceKind::Registry
    );
    assert_eq!(
        parse_source_kind("npm:foo@npm:bar"),
        SourceKind::Registry
    );
    assert_eq!(
        parse_source_kind("npm:@scope/foo@npm:@scope/bar@git+https://evil.com/repo.git"),
        SourceKind::Git
    );

    // 2. Gating nested alias smuggling attempt under allow-remote=none
    let mut root_declared = HashSet::new();
    root_declared.insert("smuggled".to_string());
    root_declared.insert("npm:foo@npm:bar@https://evil.com/payload.tgz".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("smuggled".to_string(), "npm:foo@npm:bar@https://evil.com/payload.tgz".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/smuggled".to_string(),
        LockfilePackage {
            resolved: Some("https://evil.com/payload.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-nested".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        remote: AllowMode::None,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected nested remote alias to be blocked under allow-remote=none");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWREMOTE"), "Expected EALLOWREMOTE, got: {err}");
}

#[test]
fn test_windows_unc_and_backslash_and_drive_paths() {
    // 1. parse_source_kind with UNC, backslash, and drive paths
    assert_eq!(parse_source_kind(r"\\server\share\pkg"), SourceKind::Directory);
    assert_eq!(parse_source_kind(r"\\server\share\pkg.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind(r"\local\folder"), SourceKind::Directory);
    assert_eq!(parse_source_kind(r"C:\local\folder"), SourceKind::Directory);
    assert_eq!(parse_source_kind(r"c:\local\folder"), SourceKind::Directory);
    assert_eq!(parse_source_kind(r"D:\archive.tgz"), SourceKind::File);
    assert_eq!(parse_source_kind(r"d:\archive.tar.gz"), SourceKind::File);
    assert_eq!(parse_source_kind("C:"), SourceKind::Directory);

    // 2. allow_scripts is_path_spec
    assert!(is_path_spec(r"\\server\share\pkg"));
    assert!(is_path_spec(r"\local\folder"));
    assert!(is_path_spec(r"C:\local\folder"));
    assert!(is_path_spec(r"c:\local\folder"));
    assert!(is_path_spec("file:///C:/Users/foo"));

    // 3. ScriptNode path matching across file:/// and drive letter
    let temp = tempdir().unwrap();
    let node = ScriptNode {
        location: "node_modules/local-dep",
        resolved: Some("file:./local-dep"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(node.matches("./local-dep", false));
    assert!(node.matches("file:./local-dep", false));
    assert!(node.matches(r".\local-dep", false));
}

#[test]
fn test_hosted_git_without_dot_git_and_shorthand_allow_scripts_matching() {
    // 1. Hosted git URLs without .git extension are parsed as Git
    assert_eq!(parse_source_kind("https://github.com/foo/bar"), SourceKind::Git);
    assert_eq!(parse_source_kind("http://github.com/foo/bar"), SourceKind::Git);
    assert_eq!(parse_source_kind("https://gitlab.com/foo/bar"), SourceKind::Git);
    assert_eq!(parse_source_kind("https://bitbucket.org/foo/bar"), SourceKind::Git);
    assert_eq!(parse_source_kind("https://github.com/foo/bar#v1.0.0"), SourceKind::Git);

    // Tarball archives on github are Remote, not Git
    assert_eq!(parse_source_kind("https://github.com/foo/bar/archive/v1.0.0.tar.gz"), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://github.com/foo/bar/releases/download/v1.0.0/foo.tgz"), SourceKind::Remote);

    // 2. ScriptNode::matches for GitHub shorthand and git+ssh normalized matching
    let temp = tempdir().unwrap();
    let full_sha = "0123456789abcdef0123456789abcdef01234567";
    let node = ScriptNode {
        location: "node_modules/git-dep",
        resolved: Some(&format!("git+ssh://git@github.com/foo/bar.git#{full_sha}")),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };

    assert!(node.matches("github:foo/bar", false));
    assert!(node.matches("foo/bar", false));
    assert!(node.matches("git+ssh://git@github.com/foo/bar.git", false));
    assert!(node.matches("git+https://github.com/foo/bar.git", false));
    assert!(node.matches("https://github.com/foo/bar", false));
    assert!(node.matches("github:foo/bar#0123456", false));
    assert!(node.matches("foo/bar#0123456", false));
    assert!(!node.matches("github:foo/bar#wrong", false));
    assert!(!node.matches("github:other/repo", false));
}

#[test]
fn test_lockfile_smuggling_prevention_under_allow_remote_root() {
    let mut root_declared = HashSet::new();
    // package.json declared "innocent": "^1.0.0"
    root_declared.insert("innocent".to_string());
    root_declared.insert("^1.0.0".to_string());

    // Attacker forged lockfile to resolve "innocent" to a remote malicious tarball,
    // and forged root dependencies to declare "innocent": "https://evil.com/malicious.tgz"
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("innocent".to_string(), "https://evil.com/malicious.tgz".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/innocent".to_string(),
        LockfilePackage {
            resolved: Some("https://evil.com/malicious.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-smuggle".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        remote: AllowMode::Root,
        ..Default::default()
    };

    // Must FAIL because innocent was declared as registry ^1.0.0, but forged as remote in lockfile root and resolved!
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected lockfile smuggling of remote dep to fail under allow-remote=root");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWREMOTE"), "Expected EALLOWREMOTE, got: {err}");
}

#[test]
fn test_lockfile_smuggling_prevention_in_workspace_member() {
    let mut root_declared = HashSet::new();
    // Workspace member package.json declared "ws-innocent": "^2.0.0"
    root_declared.insert("ws-innocent".to_string());
    root_declared.insert("^2.0.0".to_string());

    let mut workspace_paths = HashSet::new();
    workspace_paths.insert("packages/sub".to_string());

    // Attacker forged lockfile: packages["packages/sub"].dependencies has "ws-innocent": "https://evil.com/malicious.tgz"
    let mut packages = BTreeMap::new();
    let mut ws_deps = BTreeMap::new();
    ws_deps.insert("ws-innocent".to_string(), "https://evil.com/malicious.tgz".to_string());
    packages.insert(
        "packages/sub".to_string(),
        LockfilePackage {
            dependencies: Some(ws_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "packages/sub/node_modules/ws-innocent".to_string(),
        LockfilePackage {
            resolved: Some("https://evil.com/malicious.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-ws-smuggle".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let policy = SourcePolicy {
        remote: AllowMode::Root,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_err(), "Expected workspace lockfile smuggling to fail under allow-remote=root");
    let err = res.unwrap_err().to_string();
    assert!(err.contains("EALLOWREMOTE"), "Expected EALLOWREMOTE, got: {err}");
}

#[test]
fn test_authored_file_spec_with_windows_slash_matches() {
    let mut root_declared = HashSet::new();
    // package.json authored with forward slashes "./local/tool"
    root_declared.insert("local-tool".to_string());
    root_declared.insert("./local/tool".to_string());

    // Lockfile recorded with Windows backslashes ".\\local\\tool"
    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("local-tool".to_string(), ".\\local\\tool".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/local-tool".to_string(),
        LockfilePackage {
            resolved: Some(".\\local\\tool".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-slash".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        file: AllowMode::Root,
        directory: AllowMode::Root,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected Windows backslash spec in lockfile to match authored forward slash spec, got: {:?}", res.err());
}

#[test]
fn test_hosted_git_without_dot_git_under_allow_git_all_allow_remote_none() {
    let mut root_declared = HashSet::new();
    root_declared.insert("git-pkg".to_string());
    root_declared.insert("https://github.com/user/repo".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("git-pkg".to_string(), "https://github.com/user/repo".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/git-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://github.com/user/repo".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-git".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        git: AllowMode::All,
        remote: AllowMode::None,
        ..Default::default()
    };

    // Must PASS because https://github.com/user/repo is Git, not Remote!
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected https://github.com/user/repo to pass under allow-git=all allow-remote=none, got: {:?}", res.err());
}

#[test]
fn test_single_segment_github_url_classified_as_remote() {
    assert_eq!(parse_source_kind("https://github.com/foo"), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://github.com/foo/bar"), SourceKind::Git);
    assert_eq!(parse_source_kind("https://gist.github.com/12345"), SourceKind::Git);
}

#[test]
fn test_git_identity_mixed_case_git_plus_prefix() {
    let (repo1, ref1) = git_identity("Git+https://github.com/user/repo").unwrap();
    assert_eq!(repo1, "github.com/user/repo");
    assert_eq!(ref1, "");

    let (repo2, ref2) = git_identity("GIT+ssh://git@github.com/user/repo.git#v1.0").unwrap();
    assert_eq!(repo2, "github.com/user/repo");
    assert_eq!(ref2, "v1.0");

    let (repo3, ref3) = git_identity("gIt+https://gitlab.com/group/project#main").unwrap();
    assert_eq!(repo3, "gitlab.com/group/project");
    assert_eq!(ref3, "main");
}

#[test]
fn test_aliased_git_root_spec_matching() {
    let mut root_declared = HashSet::new();
    // package.json declared "my-alias": "npm:foo@github:user/repo#main"
    root_declared.insert("my-alias".to_string());
    root_declared.insert("npm:foo@github:user/repo#main".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    // lockfile declared full git+https URL for the dependency
    root_deps.insert("my-alias".to_string(), "git+https://github.com/user/repo.git#main".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/my-alias".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/user/repo.git#main".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-aliased-git".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        git: AllowMode::Root,
        remote: AllowMode::None,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected aliased git spec to match git identity under allow-git=root, got: {:?}", res.err());
}

#[test]
fn test_hosted_git_zip_archive_and_sha_prefix_matching() {
    // 1. Hosted .zip archive URLs are classified as Remote, not Git
    assert_eq!(parse_source_kind("https://github.com/user/repo/archive/master.zip"), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://bitbucket.org/user/repo/get/master.zip"), SourceKind::Remote);
    assert_eq!(parse_source_kind("https://gitlab.com/user/repo/-/archive/main/repo-main.zip"), SourceKind::Remote);

    // 2. Commit SHA prefix matching in check_sources
    let mut root_declared = HashSet::new();
    root_declared.insert("git-sha-pkg".to_string());
    // Author declared short SHA
    root_declared.insert("github:user/repo#0123456".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    // Lockfile recorded full 40-character SHA
    root_deps.insert("git-sha-pkg".to_string(), "git+https://github.com/user/repo.git#0123456789abcdef0123456789abcdef01234567".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/git-sha-pkg".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/user/repo.git#0123456789abcdef0123456789abcdef01234567".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-git-sha".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        git: AllowMode::Root,
        remote: AllowMode::None,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected SHA prefix matching to succeed under allow-git=root, got: {:?}", res.err());
}

#[test]
fn test_case_insensitive_git_sha_and_windows_backslash_clean_file_path() {
    let temp = tempdir().unwrap();

    // 1. clean_file_path with leading backslash on Windows drive path
    assert_eq!(clean_file_path(r"\C:\projects\pkg"), r"C:\projects\pkg");
    assert_eq!(clean_file_path(r"/C:\projects\pkg"), r"C:\projects\pkg");

    // 2. ScriptNode::matches with uppercase hex commit hash against lowercase in lockfile
    let node = ScriptNode {
        location: "node_modules/my-sha-pkg",
        resolved: Some("git+https://github.com/user/repo.git#1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"),
        lock_name: None,
        in_bundle: false,
        link: false,
        project_dir: temp.path(),
    };
    assert!(node.matches("github:user/repo#1A2B3C4", false));
    assert!(node.matches("user/repo#1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B", false));

    // 3. check_sources with uppercase SHA in package.json and lowercase in lockfile
    let mut root_declared = HashSet::new();
    root_declared.insert("case-pkg".to_string());
    root_declared.insert("github:user/repo#1A2B3C4".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("case-pkg".to_string(), "git+https://github.com/user/repo.git#1a2b3c4".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/case-pkg".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/user/repo.git#1a2b3c4".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-case-sha".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        git: AllowMode::Root,
        remote: AllowMode::None,
        ..Default::default()
    };

    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected case-insensitive git SHA comparison to pass under allow-git=root, got: {:?}", res.err());
}

#[test]
fn test_numeric_org_git_scp_parsing_and_remote_fragment_and_registry_root_smuggling() {
    // 1. Git SCP parsing for numeric orgs like 0xPolygon or 42school
    let (repo_poly, ref_poly) = git_identity("git@github.com:0xPolygon/contracts.git#v1.0").unwrap();
    assert_eq!(repo_poly, "github.com/0xpolygon/contracts");
    assert_eq!(ref_poly, "v1.0");

    let (repo_42, _) = git_identity("git@gitlab.com:42school/lib.git").unwrap();
    assert_eq!(repo_42, "gitlab.com/42school/lib");

    // Real port is preserved/not treated as org
    let (repo_port, _) = git_identity("ssh://git@example.com:2222/group/repo.git").unwrap();
    assert_eq!(repo_port, "example.com:2222/group/repo");

    // 2. Remote URL with fragment declared in package.json matching clean lockfile spec
    let mut root_declared = HashSet::new();
    root_declared.insert("remote-frag-pkg".to_string());
    root_declared.insert("https://example.com/tarball.tgz#sha512-abc123".to_string());

    let mut packages = BTreeMap::new();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("remote-frag-pkg".to_string(), "https://example.com/tarball.tgz".to_string());
    packages.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps),
            ..Default::default()
        },
    );
    packages.insert(
        "node_modules/remote-frag-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://example.com/tarball.tgz".to_string()),
            ..Default::default()
        },
    );

    let lockfile = LockfileV3 {
        name: "test-frag".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages,
    };
    let workspace_paths = HashSet::new();
    let policy = SourcePolicy {
        remote: AllowMode::Root,
        ..Default::default()
    };
    let res = check_sources(&lockfile, &root_declared, &workspace_paths, &policy);
    assert!(res.is_ok(), "Expected remote URL with fragment in package.json to match clean lockfile URL, got: {:?}", res.err());

    // 3. Forged registry root dep injection blocked under allow-registry=root
    let root_declared_empty = HashSet::new(); // package.json declares nothing
    let mut packages_forged = BTreeMap::new();
    let mut root_deps_forged = BTreeMap::new();
    root_deps_forged.insert("injected-registry-pkg".to_string(), "^1.0.0".to_string());
    packages_forged.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_forged),
            ..Default::default()
        },
    );
    packages_forged.insert(
        "node_modules/injected-registry-pkg".to_string(),
        LockfilePackage {
            resolved: Some("https://registry.npmjs.org/injected-registry-pkg/-/injected-registry-pkg-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );
    let lockfile_forged = LockfileV3 {
        name: "test-forged-reg".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_forged,
    };
    let policy_reg_root = SourcePolicy {
        registry: AllowMode::Root,
        ..Default::default()
    };
    let res_forged = check_sources(&lockfile_forged, &root_declared_empty, &workspace_paths, &policy_reg_root);
    assert!(res_forged.is_err(), "Expected undeclared registry package injected into lockfile root to fail under allow-registry=root");
    let err = res_forged.unwrap_err().to_string();
    assert!(err.contains("EALLOWREGISTRY"), "Expected EALLOWREGISTRY, got: {err}");
}

#[test]
fn test_git_tampered_ref_rejected_under_allow_git_root() {
    let workspace_paths = HashSet::new();
    let policy_git_root = SourcePolicy {
        git: AllowMode::Root,
        ..Default::default()
    };

    // 1. package.json declares "github:a/b#v1", lockfile tampered with "github:a/b#evil"
    let mut root_declared_v1 = HashSet::new();
    root_declared_v1.insert("foo".to_string());
    root_declared_v1.insert("github:a/b#v1".to_string());

    let mut packages_tampered = BTreeMap::new();
    let mut root_deps_tampered = BTreeMap::new();
    root_deps_tampered.insert("foo".to_string(), "github:a/b#evil".to_string());
    packages_tampered.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_tampered),
            ..Default::default()
        },
    );
    packages_tampered.insert(
        "node_modules/foo".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/a/b.git#evil".to_string()),
            ..Default::default()
        },
    );
    let lockfile_tampered = LockfileV3 {
        name: "test-tampered-git".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_tampered,
    };

    let res_tampered = check_sources(&lockfile_tampered, &root_declared_v1, &workspace_paths, &policy_git_root);
    assert!(res_tampered.is_err(), "Expected tampered git ref '#evil' to be rejected when package.json declared '#v1'");
    let err = res_tampered.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Expected EALLOWGIT error, got: {err}");

    // 2. package.json declares "github:a/b#v1", lockfile has exact matching "#v1"
    let mut packages_exact = BTreeMap::new();
    let mut root_deps_exact = BTreeMap::new();
    root_deps_exact.insert("foo".to_string(), "github:a/b#v1".to_string());
    packages_exact.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_exact),
            ..Default::default()
        },
    );
    packages_exact.insert(
        "node_modules/foo".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/a/b.git#v1".to_string()),
            ..Default::default()
        },
    );
    let lockfile_exact = LockfileV3 {
        name: "test-exact-git".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_exact,
    };
    let res_exact = check_sources(&lockfile_exact, &root_declared_v1, &workspace_paths, &policy_git_root);
    assert!(res_exact.is_ok(), "Expected exact git ref '#v1' to succeed under allow-git=root, got: {:?}", res_exact.err());

    // 3. package.json declares unpinned "github:a/b", lockfile resolves to full 40-char commit SHA
    let mut root_declared_unpinned = HashSet::new();
    root_declared_unpinned.insert("bar".to_string());
    root_declared_unpinned.insert("github:a/b".to_string());

    let mut packages_unpinned = BTreeMap::new();
    let mut root_deps_unpinned = BTreeMap::new();
    root_deps_unpinned.insert("bar".to_string(), "git+https://github.com/a/b.git#1234567890abcdef1234567890abcdef12345678".to_string());
    packages_unpinned.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_unpinned),
            ..Default::default()
        },
    );
    packages_unpinned.insert(
        "node_modules/bar".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/a/b.git#1234567890abcdef1234567890abcdef12345678".to_string()),
            ..Default::default()
        },
    );
    let lockfile_unpinned = LockfileV3 {
        name: "test-unpinned-git".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_unpinned,
    };
    let res_unpinned = check_sources(&lockfile_unpinned, &root_declared_unpinned, &workspace_paths, &policy_git_root);
    assert!(res_unpinned.is_ok(), "Expected unpinned github:a/b resolving to 40-char SHA to succeed under allow-git=root, got: {:?}", res_unpinned.err());

    // 4. package.json declares unpinned "github:a/b", but lockfile tampered with non-SHA branch/ref "#evil"
    let mut packages_unpinned_tampered = BTreeMap::new();
    let mut root_deps_unpinned_tampered = BTreeMap::new();
    root_deps_unpinned_tampered.insert("bar".to_string(), "github:a/b#evil".to_string());
    packages_unpinned_tampered.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_unpinned_tampered),
            ..Default::default()
        },
    );
    packages_unpinned_tampered.insert(
        "node_modules/bar".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/a/b.git#evil".to_string()),
            ..Default::default()
        },
    );
    let lockfile_unpinned_tampered = LockfileV3 {
        name: "test-unpinned-tampered".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_unpinned_tampered,
    };
    let res_unpinned_tampered = check_sources(&lockfile_unpinned_tampered, &root_declared_unpinned, &workspace_paths, &policy_git_root);
    assert!(res_unpinned_tampered.is_err(), "Expected unpinned github:a/b with tampered non-SHA ref '#evil' to be rejected under allow-git=root");
    let err_unpinned = res_unpinned_tampered.unwrap_err().to_string();
    assert!(err_unpinned.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err_unpinned}");

    // 5. Root dependencies map has untampered "github:a/b#v1", but node_modules/foo.resolved has attacker repo
    let mut packages_resolved_tampered_repo = BTreeMap::new();
    let mut root_deps_ok = BTreeMap::new();
    root_deps_ok.insert("foo".to_string(), "github:a/b#v1".to_string());
    packages_resolved_tampered_repo.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_ok.clone()),
            ..Default::default()
        },
    );
    packages_resolved_tampered_repo.insert(
        "node_modules/foo".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/evil/backdoor.git#evil".to_string()),
            ..Default::default()
        },
    );
    let lockfile_resolved_tampered_repo = LockfileV3 {
        name: "test-resolved-tampered-repo".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_resolved_tampered_repo,
    };
    let res_tampered_repo = check_sources(&lockfile_resolved_tampered_repo, &root_declared_v1, &workspace_paths, &policy_git_root);
    assert!(res_tampered_repo.is_err(), "Expected tampered resolved repo 'evil/backdoor' to be rejected under allow-git=root even if root deps map had '#v1'");
    let err_repo = res_tampered_repo.unwrap_err().to_string();
    assert!(err_repo.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err_repo}");

    // 6. Root dependencies map has untampered "github:a/b#v1", but node_modules/foo.resolved has tampered ref #evil
    let mut packages_resolved_tampered_ref = BTreeMap::new();
    packages_resolved_tampered_ref.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_ok),
            ..Default::default()
        },
    );
    packages_resolved_tampered_ref.insert(
        "node_modules/foo".to_string(),
        LockfilePackage {
            resolved: Some("git+https://github.com/a/b.git#evil".to_string()),
            ..Default::default()
        },
    );
    let lockfile_resolved_tampered_ref = LockfileV3 {
        name: "test-resolved-tampered-ref".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_resolved_tampered_ref,
    };
    let res_tampered_ref = check_sources(&lockfile_resolved_tampered_ref, &root_declared_v1, &workspace_paths, &policy_git_root);
    assert!(res_tampered_ref.is_err(), "Expected tampered resolved ref '#evil' on node_modules/foo to be rejected under allow-git=root even if root deps map had '#v1'");
    let err_ref = res_tampered_ref.unwrap_err().to_string();
    assert!(err_ref.contains("EALLOWGIT"), "Expected EALLOWGIT, got: {err_ref}");

    // 7. Root declares named tag "github:a/b#v1" and lockfile stores normal resolved 40-char commit SHA
    let mut packages_resolved_sha = BTreeMap::new();
    let mut root_deps_v1 = BTreeMap::new();
    root_deps_v1.insert("foo".to_string(), "github:a/b#v1".to_string());
    packages_resolved_sha.insert(
        String::new(),
        LockfilePackage {
            dependencies: Some(root_deps_v1),
            ..Default::default()
        },
    );
    packages_resolved_sha.insert(
        "node_modules/foo".to_string(),
        LockfilePackage {
            resolved: Some("git+ssh://git@github.com/a/b.git#0123456789abcdef0123456789abcdef01234567".to_string()),
            ..Default::default()
        },
    );
    let lockfile_resolved_sha = LockfileV3 {
        name: "test-resolved-sha".to_string(),
        version: None,
        lockfile_version: 3,
        requires: None,
        packages: packages_resolved_sha,
    };
    assert!(
        check_sources(&lockfile_resolved_sha, &root_declared_v1, &workspace_paths, &policy_git_root).is_ok(),
        "Expected named tag github:a/b#v1 with normal resolved 40-char commit SHA to be accepted under allow-git=root"
    );
}
