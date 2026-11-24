//! Comprehensive regression tests for Council Round 1 findings:
//! a) `check_ci_drift` with a dep in both `dependencies` and `optionalDependencies` (Flash 4B-F4).
//! b) `check_ci_drift` with a `link: true` workspace member satisfied by a semver range AND rejecting a mismatched `file:` path (Flash 4B-F2).
//! c) `check_ci_drift` step 5 with `--omit=optional` and `--omit=peer` (Flash 4B-F3).
//! d) `fast_path` fingerprint differentiation for `source_policy_override` (`None`, `Some(None)`, `Some(Root)`, `Some(All)`) (Sol F6 / Neon F10).
//! e) `fast_path` staying valid when a direct optional dep (e.g. `fsevents` with mismatched `os`) is platform-skipped and absent from hidden lockfile (Flash 4B-F1).
//! f) `policy.rs` top-level `overrides` under `--allow-registry=root` / `--allow-git=root` (Neon F4).
//! g) `allow_scripts.rs` numeric-org SCP URLs (`git@github.com:12345/repo.git`) & explicit URL ports (Neon F2).
//! h) `git.rs` credential scrubbing on checkout/submodule errors (Neon F9).

#![allow(clippy::field_reassign_with_default)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use tempfile::tempdir;

use rnpm_core::manifest::{Manifest, PackageWorkspaces};
use rnpm_core::spec::PackageTarget;
use rnpm_install::fast_path::{compute_project_fingerprint, validate_hidden_lockfile};
use rnpm_install::git::GitFetcher;
use rnpm_install::policy::{
    check_sources, git_identity, AllowMode, SourcePolicy,
};
use rnpm_install::{lockfile_node_satisfies_spec, InstallOptions, Installer};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

/// a) `check_ci_drift` with a dep in both `dependencies` and `optionalDependencies` (Flash 4B-F4).
/// Tests:
/// 1. Conflicting ranges: dependencies: "^1.0.0" vs optionalDependencies: "^2.0.0" -> optionalDependencies wins.
/// 2. Negative case: a real missing required production dependency fails run_ci with ELOCKFILE_DRIFT.
/// 3. Negative case: drifted optionalDependencies range fails run_ci with ELOCKFILE_DRIFT.
#[tokio::test]
async fn test_check_ci_drift_dep_in_both_dependencies_and_optional_dependencies() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. Conflicting ranges: package.json declares "dual-dep" with ^1.0.0 in dependencies,
    // but ^2.0.0 in optionalDependencies. In npm 11.20.0, optionalDependencies overrides dependencies,
    // so package-lock.json only has dual-dep in optionalDependencies with ^2.0.0.
    let mut manifest = Manifest::default();
    manifest.name = Some("dual-dep-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dual-dep".to_string(), "^1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("dual-dep".to_string(), "^2.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("dual-dep-app", Some("1.0.0".to_string()));
    let mut opt_deps = BTreeMap::new();
    opt_deps.insert("dual-dep".to_string(), "^2.0.0".to_string());
    lockfile.root_package_mut().unwrap().optional_dependencies = Some(opt_deps);
    lockfile.insert_package(
        "node_modules/dual-dep",
        LockfilePackage {
            version: Some("2.1.0".to_string()),
            resolved: Some("https://registry.npmjs.org/dual-dep/-/dual-dep-2.1.0.tgz".to_string()),
            optional: Some(true),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when optionalDependencies overrides dependencies: {:?}",
        res.err()
    );

    // 2. Negative case: a missing required production dependency must fail run_ci with ELOCKFILE_DRIFT
    manifest
        .dependencies
        .insert("missing-prod-dep".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut failing_installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        ..Default::default()
    })
    .unwrap();

    let fail_res = failing_installer.run_ci().await;
    assert!(
        fail_res.is_err(),
        "run_ci must fail when a required production dependency is missing from lockfile"
    );
    let fail_err = fail_res.unwrap_err().to_string();
    assert!(
        fail_err.contains("ELOCKFILE_DRIFT") && fail_err.contains("missing-prod-dep"),
        "Error should be ELOCKFILE_DRIFT mentioning missing-prod-dep: {fail_err}"
    );

    // 3. Negative case: drifted optionalDependencies range (manifest asks for ^3.0.0, lock has 2.1.0 / ^2.0.0)
    manifest.dependencies.remove("missing-prod-dep");
    manifest
        .optional_dependencies
        .insert("dual-dep".to_string(), "^3.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut opt_drift_installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        ..Default::default()
    })
    .unwrap();

    let opt_drift_res = opt_drift_installer.run_ci().await;
    assert!(
        opt_drift_res.is_err(),
        "run_ci must fail when optionalDependencies range drifts"
    );
    let opt_drift_err = opt_drift_res.unwrap_err().to_string();
    assert!(
        opt_drift_err.contains("ELOCKFILE_DRIFT"),
        "Error should be ELOCKFILE_DRIFT for drifted optionalDependencies: {opt_drift_err}"
    );
}

/// b) `check_ci_drift` with a `link: true` workspace member satisfied by a semver range
/// AND rejecting a mismatched `file:` path, remote git specs, remote tarball URLs,
/// broken links, and supporting trailing slashes and link chains (Flash 4B-F2).
#[tokio::test]
async fn test_check_ci_drift_link_true_workspace_member_and_file_spec() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let ws_dir = project_dir.join("packages").join("my-lib");
    fs::create_dir_all(&ws_dir).unwrap();
    let mut ws_manifest = Manifest::default();
    ws_manifest.name = Some("my-lib".to_string());
    ws_manifest.version = Some("1.2.3".to_string());
    ws_manifest
        .save_to_file(ws_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("root-app", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    root_deps.insert("my-lib".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(root_deps);
    lockfile.root_package_mut().unwrap().workspaces =
        Some(vec!["packages/*".to_string()]);

    // Link node in node_modules
    lockfile.insert_package(
        "node_modules/my-lib",
        LockfilePackage {
            resolved: Some("packages/my-lib".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    // Target workspace package descriptor
    lockfile.insert_package(
        "packages/my-lib",
        LockfilePackage {
            name: Some("my-lib".to_string()),
            version: Some("1.2.3".to_string()),
            ..Default::default()
        },
    );

    let link_pkg = lockfile.packages.get("node_modules/my-lib").unwrap();

    // 1. Semver range: 1.2.3 satisfies ^1.0.0 via dereferencing
    assert!(
        lockfile_node_satisfies_spec(&lockfile, "my-lib", link_pkg, "^1.0.0"),
        "Link package should satisfy ^1.0.0 through its dereferenced target version 1.2.3"
    );
    // 2. Semver range mismatch: 1.2.3 does NOT satisfy ^2.0.0
    assert!(
        !lockfile_node_satisfies_spec(&lockfile, "my-lib", link_pkg, "^2.0.0"),
        "Link package must NOT satisfy ^2.0.0 when target version is 1.2.3"
    );

    // 3. Exact matching file path: file:./packages/my-lib satisfies
    assert!(
        lockfile_node_satisfies_spec(&lockfile, "my-lib", link_pkg, "file:./packages/my-lib"),
        "Link package should satisfy matching file:./packages/my-lib"
    );

    // 4. Mismatched file path: file:./packages/other must be rejected and NOT dereferenced
    assert!(
        !lockfile_node_satisfies_spec(&lockfile, "my-lib", link_pkg, "file:./packages/other"),
        "Link package must REJECT mismatched file:./packages/other"
    );

    // 5. Remote git spec: a local link MUST REJECT arbitrary remote git URLs
    assert!(
        !lockfile_node_satisfies_spec(
            &lockfile,
            "my-lib",
            link_pkg,
            "git+https://github.com/evil/repo.git#main"
        ),
        "Link package must REJECT remote git spec"
    );

    // 6. Remote tarball URL: a local link MUST REJECT remote tarball URLs
    assert!(
        !lockfile_node_satisfies_spec(
            &lockfile,
            "my-lib",
            link_pkg,
            "https://evil.example.com/pkg.tgz"
        ),
        "Link package must REJECT remote tarball URL"
    );

    // 7. Trailing slash on resolved: "packages/my-lib/" must be normalized cleanly
    let link_trailing = LockfilePackage {
        resolved: Some("packages/my-lib/".to_string()),
        link: Some(true),
        ..Default::default()
    };
    assert!(
        lockfile_node_satisfies_spec(&lockfile, "my-lib", &link_trailing, "^1.0.0"),
        "Trailing slash in resolved path must be stripped and satisfy ^1.0.0"
    );
    assert!(
        !lockfile_node_satisfies_spec(&lockfile, "my-lib", &link_trailing, "^2.0.0"),
        "Trailing slash in resolved path must reject mismatching ^2.0.0"
    );

    // 8. Broken link pointing to nonexistent workspace target must return false
    let broken_link = LockfilePackage {
        resolved: Some("packages/nonexistent-target".to_string()),
        link: Some(true),
        ..Default::default()
    };
    assert!(
        !lockfile_node_satisfies_spec(&lockfile, "my-lib", &broken_link, "^1.0.0"),
        "Broken link to nonexistent target must return false and not fall through"
    );

    // 9. Chained link: link-1 -> link-2 -> packages/my-lib
    lockfile.insert_package(
        "node_modules/chain-1",
        LockfilePackage {
            resolved: Some("node_modules/chain-2".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/chain-2",
        LockfilePackage {
            resolved: Some("packages/my-lib".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    let chain1_pkg = lockfile.packages.get("node_modules/chain-1").unwrap();
    assert!(
        lockfile_node_satisfies_spec(&lockfile, "my-lib", chain1_pkg, "^1.0.0"),
        "Chained link must be followed safely to final target and satisfy ^1.0.0"
    );
    assert!(
        !lockfile_node_satisfies_spec(&lockfile, "my-lib", chain1_pkg, "^2.0.0"),
        "Chained link must reject mismatching range ^2.0.0"
    );

    // 10. End-to-end run_ci test with workspace member
    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("root-app".to_string());
    root_manifest.version = Some("1.0.0".to_string());
    root_manifest.workspaces = Some(PackageWorkspaces::List(vec!["packages/*".to_string()]));
    root_manifest
        .dependencies
        .insert("my-lib".to_string(), "^1.0.0".to_string());
    root_manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when workspace link satisfies semver range: {:?}",
        res.err()
    );
}

/// c) `check_ci_drift` step 5 with `--omit=optional` and `--omit=peer` (Flash 4B-F3).
/// In step 5, internal lockfile consistency check must skip omitted packages consistently,
/// and handle non-omitted packages whose dependencies list an optional dep that is absent or platform-skipped.
#[tokio::test]
async fn test_check_ci_drift_step5_omit_optional_and_omit_peer() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. Root package with normal prod dependency
    let mut manifest = Manifest::default();
    manifest.name = Some("step5-omit-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("prod-dep".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("step5-omit-app", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    root_deps.insert("prod-dep".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(root_deps);

    // Valid prod-dep that also lists an optional dep in both dependencies and optionalDependencies
    // where the optional dep is platform-skipped (absent from lockfile)
    let mut prod_deps = BTreeMap::new();
    prod_deps.insert("platform-opt-dep".to_string(), "^1.0.0".to_string());
    let mut prod_opt_deps = BTreeMap::new();
    prod_opt_deps.insert("platform-opt-dep".to_string(), "^1.0.0".to_string());

    lockfile.insert_package(
        "node_modules/prod-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/prod-dep/-/prod-dep-1.0.0.tgz".to_string()),
            dependencies: Some(prod_deps),
            optional_dependencies: Some(prod_opt_deps),
            ..Default::default()
        },
    );

    // Broken optional package with missing transitive dep in lockfile
    let mut broken_opt_deps = BTreeMap::new();
    broken_opt_deps.insert("ghost-missing-dep".to_string(), "^1.0.0".to_string());
    lockfile.insert_package(
        "node_modules/broken-opt",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/broken-opt/-/broken-opt-1.0.0.tgz".to_string()),
            optional: Some(true),
            dependencies: Some(broken_opt_deps),
            ..Default::default()
        },
    );

    // Broken peer package with missing transitive dep in lockfile
    let mut broken_peer_deps = BTreeMap::new();
    broken_peer_deps.insert("ghost-peer-missing-dep".to_string(), "^1.0.0".to_string());
    lockfile.insert_package(
        "node_modules/broken-peer",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/broken-peer/-/broken-peer-1.0.0.tgz".to_string()),
            peer: Some(true),
            dependencies: Some(broken_peer_deps),
            ..Default::default()
        },
    );

    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // With --omit=optional --omit=peer, step 5 must skip broken-opt, broken-peer, and platform-opt-dep!
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        omit_optional: true,
        omit_peer: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci with --omit=optional --omit=peer must skip omitted packages and absent optional deps in step 5: {:?}",
        res.err()
    );

    // Even with omit_optional=false, prod-dep's platform-opt-dep is absent (platform-skipped)
    // and must be handled gracefully without failing as a missing dependency.
    // However, broken-opt has a missing non-optional transitive dependency ("ghost-missing-dep"),
    // which MUST trigger EUSAGE when omit_optional=false.
    let mut failing_installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        dry_run: true,
        omit_optional: false,
        omit_peer: false,
        ..Default::default()
    })
    .unwrap();

    let failing_res = failing_installer.run_ci().await;
    assert!(
        failing_res.is_err(),
        "run_ci without omit flags must fail when lockfile has missing internal dependencies"
    );
    let err_str = failing_res.unwrap_err().to_string();
    assert!(
        err_str.contains("Missing: ghost-missing-dep@^1.0.0")
            || err_str.contains("Missing: ghost-peer-missing-dep@^1.0.0"),
        "Error message should mention missing dependencies: {err_str}"
    );
}

/// d) `fast_path` fingerprint differentiation for `source_policy_override`
/// (`None`, `Some(None)`, `Some(Root)`, `Some(All)`) (Sol F6 / Neon F10).
#[test]
fn test_fast_path_fingerprint_differentiation_source_policy_override() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("fp-fingerprint-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let lockfile = LockfileV3::new("fp-fingerprint-app", Some("1.0.0".to_string()));
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 1. None (no override)
    let opt_none = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        source_policy_override: None,
        ..Default::default()
    };
    let fp_none = compute_project_fingerprint(project_dir, &opt_none).unwrap();

    // 2. Some(None) - all sources set to AllowMode::None
    let opt_some_none = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        source_policy_override: Some(SourcePolicy {
            git: AllowMode::None,
            remote: AllowMode::None,
            registry: AllowMode::None,
            file: AllowMode::None,
            directory: AllowMode::None,
        }),
        ..Default::default()
    };
    let fp_some_none = compute_project_fingerprint(project_dir, &opt_some_none).unwrap();

    // 3. Some(Root) - all sources set to AllowMode::Root
    let opt_some_root = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        source_policy_override: Some(SourcePolicy {
            git: AllowMode::Root,
            remote: AllowMode::Root,
            registry: AllowMode::Root,
            file: AllowMode::Root,
            directory: AllowMode::Root,
        }),
        ..Default::default()
    };
    let fp_some_root = compute_project_fingerprint(project_dir, &opt_some_root).unwrap();

    // 4. Some(All) - all sources set to AllowMode::All
    let opt_some_all = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        source_policy_override: Some(SourcePolicy {
            git: AllowMode::All,
            remote: AllowMode::All,
            registry: AllowMode::All,
            file: AllowMode::All,
            directory: AllowMode::All,
        }),
        ..Default::default()
    };
    let fp_some_all = compute_project_fingerprint(project_dir, &opt_some_all).unwrap();

    let fingerprints = [fp_none, fp_some_none, fp_some_root, fp_some_all];
    let unique_count = fingerprints.iter().collect::<HashSet<_>>().len();
    assert_eq!(
        unique_count, 4,
        "All 4 source_policy_override states must produce distinct fingerprints: {:?}",
        fingerprints
    );
}

/// e) `fast_path` staying valid when a direct optional dep (e.g. `fsevents` with mismatched `os`)
/// is platform-skipped and absent from hidden lockfile (Flash 4B-F1).
/// Tests:
/// 1. Hidden lockfile WITH packages[""]
/// 2. Hidden lockfile WITHOUT packages[""] (triggers package.json fallback at line 388)
/// 3. Negative case: missing non-optional direct dependency returns false.
#[test]
fn test_fast_path_valid_when_direct_optional_dep_platform_skipped_and_absent() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // Manifest declares fsevents as optionalDependency
    let mut manifest = Manifest::default();
    manifest.name = Some("fsevents-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("fsevents".to_string(), "^2.3.2".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let nm = project_dir.join("node_modules");
    fs::create_dir_all(&nm).unwrap();

    // 1. Hidden lockfile WITH packages[""] declaring optionalDependencies
    let mut hidden_lock = LockfileV3::new("fsevents-app", Some("1.0.0".to_string()));
    let mut opt_deps = BTreeMap::new();
    opt_deps.insert("fsevents".to_string(), "^2.3.2".to_string());
    hidden_lock.root_package_mut().unwrap().optional_dependencies = Some(opt_deps);
    let hidden_path = nm.join(".package-lock.json");
    hidden_lock.save_to_file(&hidden_path).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    };

    assert!(
        validate_hidden_lockfile(project_dir, Some(&options)),
        "validate_hidden_lockfile must remain valid with packages[\"\"] when optional dep is absent"
    );

    // 2. Hidden lockfile WITHOUT packages[""] (triggers package.json fallback at line 388)
    let mut hidden_lock_no_root = LockfileV3::new("fsevents-app", Some("1.0.0".to_string()));
    hidden_lock_no_root.packages.remove("");
    hidden_lock_no_root.save_to_file(&hidden_path).unwrap();

    assert!(
        validate_hidden_lockfile(project_dir, Some(&options)),
        "validate_hidden_lockfile must remain valid without packages[\"\"] via package.json fallback"
    );

    // 3. Negative case: manifest has a NON-optional production dependency that is absent from hidden lockfile
    let mut bad_manifest = Manifest::default();
    bad_manifest.name = Some("fsevents-app".to_string());
    bad_manifest.version = Some("1.0.0".to_string());
    bad_manifest
        .dependencies
        .insert("missing-prod".to_string(), "^1.0.0".to_string());
    bad_manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    assert!(
        !validate_hidden_lockfile(project_dir, Some(&options)),
        "validate_hidden_lockfile MUST return false when a required non-optional dependency is missing"
    );
}

/// f) `policy.rs` top-level `overrides` under `--allow-registry=root` / `--allow-git=root` (Neon F4).
#[test]
fn test_policy_top_level_overrides_allow_registry_and_git_root() {
    let mut lockfile = LockfileV3::new("overrides-app", Some("1.0.0".to_string()));
    let root_pkg = lockfile.root_package_mut().unwrap();

    let mut direct_deps = BTreeMap::new();
    direct_deps.insert("direct-dep".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(direct_deps);

    let mut root_declared = HashSet::new();
    root_declared.insert("direct-dep".to_string());
    let workspace_paths = HashSet::new();

    // 1. Direct dep overridden with registry spec under allow-registry=root -> OK
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "direct-dep": "1.0.0"
        }),
    );

    let policy_root_reg = SourcePolicy {
        registry: AllowMode::Root,
        ..Default::default()
    };

    let check1 = check_sources(&lockfile, &root_declared, &workspace_paths, &policy_root_reg);
    assert!(
        check1.is_ok(),
        "Direct root dependency override under allow-registry=root must be allowed: {:?}",
        check1.err()
    );

    // 2. Transitive dep (not declared on root) overridden with registry spec under allow-registry=root -> REJECTED
    let root_pkg = lockfile.root_package_mut().unwrap();
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "transitive-dep": "2.0.0"
        }),
    );

    let check2 = check_sources(&lockfile, &root_declared, &workspace_paths, &policy_root_reg);
    assert!(
        check2.is_err(),
        "Transitive dependency override under allow-registry=root must be rejected"
    );
    let err2 = check2.unwrap_err().to_string();
    assert!(
        err2.contains("EALLOWREGISTRY"),
        "Error should be EALLOWREGISTRY: {err2}"
    );

    // 3. Git override under allow-git=root:
    // When git spec is NOT declared in root_declared -> REJECTED
    let root_pkg = lockfile.root_package_mut().unwrap();
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "direct-dep": "git+https://github.com/attacker/evil.git"
        }),
    );

    let policy_root_git = SourcePolicy {
        git: AllowMode::Root,
        ..Default::default()
    };

    let check3 = check_sources(&lockfile, &root_declared, &workspace_paths, &policy_root_git);
    assert!(
        check3.is_err(),
        "Undeclared git override under allow-git=root must be rejected"
    );
    let err3 = check3.unwrap_err().to_string();
    assert!(
        err3.contains("EALLOWGIT"),
        "Error should be EALLOWGIT: {err3}"
    );

    // 4. Git override matching declared root spec under allow-git=root -> OK
    root_declared.insert("git+https://github.com/org/repo.git#v1.0.0".to_string());
    let root_pkg = lockfile.root_package_mut().unwrap();
    root_pkg.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "direct-dep": "git+https://github.com/org/repo.git#v1.0.0"
        }),
    );

    let check4 = check_sources(&lockfile, &root_declared, &workspace_paths, &policy_root_git);
    assert!(
        check4.is_ok(),
        "Declared git override under allow-git=root must be allowed: {:?}",
        check4.err()
    );
}

/// g) `allow_scripts.rs` numeric-org SCP URLs (`git@github.com:12345/repo.git`) & explicit URL ports (Neon F2).
#[test]
fn test_allow_scripts_numeric_org_scp_and_url_ports() {
    // 1. Numeric-org SCP URL: git@github.com:12345/repo.git
    // Must parse as repo "github.com/12345/repo", NOT treating "12345" as a port!
    let ident1 = git_identity("git@github.com:12345/repo.git");
    assert_eq!(
        ident1,
        Some(("github.com/12345/repo".to_string(), "".to_string())),
        "Numeric organization name in SCP URL must not be misinterpreted as a port"
    );

    // 2. Numeric repo name in SCP URL
    let ident2 = git_identity("git@gitlab.com:org/98765.git");
    assert_eq!(
        ident2,
        Some(("gitlab.com/org/98765".to_string(), "".to_string())),
        "Numeric repository name in SCP URL must be preserved"
    );

    // 3. Explicit port with scheme: ssh://git@github.com:2222/org/repo.git
    let ident3 = git_identity("ssh://git@github.com:2222/org/repo.git");
    assert_eq!(
        ident3,
        Some(("github.com:2222/org/repo".to_string(), "".to_string())),
        "Explicit port with ssh:// scheme must retain host:port/path structure"
    );

    // 4. Explicit port with https:// and commit ref: https://github.com:8443/org/repo.git#v1.0.0
    let ident4 = git_identity("https://github.com:8443/org/repo.git#v1.0.0");
    assert_eq!(
        ident4,
        Some(("github.com:8443/org/repo".to_string(), "v1.0.0".to_string())),
        "Explicit port with https:// scheme and ref must retain ref and host:port"
    );
}

/// h) `git.rs` credential scrubbing on checkout/submodule errors (Neon F9).
#[tokio::test]
async fn test_git_credential_scrubbing_on_errors() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let fetcher = GitFetcher::new(&cache_dir);

    let empty_dir = tmp.path().join("empty_git_dir");
    fs::create_dir_all(&empty_dir).unwrap();

    let sensitive_url = "https://alice:supersecretpass123@github.com/org/repo.git";

    // 1. resolve_commit_sha failure must NOT leak "supersecretpass123"
    let resolve_res = fetcher
        .resolve_commit_sha(&empty_dir, Some("v999.0.0"), sensitive_url, true)
        .await;
    assert!(resolve_res.is_err(), "resolve_commit_sha must fail on empty dir");
    let resolve_err = resolve_res.unwrap_err().to_string();
    assert!(
        !resolve_err.contains("supersecretpass123"),
        "resolve_commit_sha error leaked credentials: {resolve_err}"
    );
    assert!(
        resolve_err.contains("[REDACTED]"),
        "resolve_commit_sha error should contain scrubbed credentials: {resolve_err}"
    );

    // 2. checkout_tree failure must NOT leak "supersecretpass123"
    let checkout_res = fetcher
        .checkout_tree(
            &empty_dir,
            "0123456789abcdef0123456789abcdef01234567",
            sensitive_url,
        )
        .await;
    assert!(checkout_res.is_err(), "checkout_tree must fail on empty dir");
    let checkout_err = checkout_res.unwrap_err().to_string();
    assert!(
        !checkout_err.contains("supersecretpass123"),
        "checkout_tree error leaked credentials: {checkout_err}"
    );
    assert!(
        checkout_err.contains("[REDACTED]"),
        "checkout_tree error should contain scrubbed credentials: {checkout_err}"
    );

    // 3. Missing package.json in cloned checkout (lines 70-74 / 121-127) must scrub credentials
    let commit_sha = "1111222233334444555566667777888899990000";
    let fake_checkout_dir = fetcher.checkout_cache_dir(sensitive_url, commit_sha);
    fs::create_dir_all(&fake_checkout_dir).unwrap();
    // Create the completion marker file outside checkout dir so checkout_tree reuses it
    let marker_file = fake_checkout_dir.with_extension("done");
    fs::write(&marker_file, b"").unwrap();

    let target = PackageTarget::Git {
        url: sensitive_url.to_string(),
        committish: Some(commit_sha.to_string()),
        subdir: None,
    };

    let checkout_dep_res = fetcher.checkout_git_dependency(&target, true).await;
    assert!(
        checkout_dep_res.is_err(),
        "checkout_git_dependency must fail when package.json is missing"
    );
    let checkout_dep_err = checkout_dep_res.unwrap_err().to_string();
    assert!(
        !checkout_dep_err.contains("supersecretpass123"),
        "checkout_git_dependency missing package.json error leaked credentials: {checkout_dep_err}"
    );
    assert!(
        checkout_dep_err.contains("[REDACTED]"),
        "checkout_git_dependency missing package.json error should be scrubbed: {checkout_dep_err}"
    );

    // 4. Invalid package.json in cloned checkout (lines 77-83) must scrub credentials
    fs::write(fake_checkout_dir.join("package.json"), b"{ invalid json content").unwrap();
    let resolve_dep_res = fetcher.resolve_git_dependency(&target, true).await;
    assert!(
        resolve_dep_res.is_err(),
        "resolve_git_dependency must fail when package.json is invalid JSON"
    );
    let resolve_dep_err = resolve_dep_res.unwrap_err().to_string();
    assert!(
        !resolve_dep_err.contains("supersecretpass123"),
        "resolve_git_dependency invalid package.json error leaked credentials: {resolve_dep_err}"
    );
    assert!(
        resolve_dep_err.contains("[REDACTED]"),
        "resolve_git_dependency invalid package.json error should be scrubbed: {resolve_dep_err}"
    );
}
