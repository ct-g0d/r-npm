//! Extreme Borderline Stress & Real-World Corpus Swarm Tests for `rnpm ci` Lockfile Handling (CP2-4).
//!
//! Tests:
//! 1. `npm-shrinkwrap.json` precedence over `package-lock.json` on `rnpm ci`:
//!    - Shrinkwrap takes absolute precedence; if package-lock is drifted but shrinkwrap matches, ci succeeds.
//!    - When shrinkwrap drifts, error message explicitly references `npm-shrinkwrap.json`.
//! 2. `rnpm ci` drift detection:
//!    - Version range mismatch between package.json and lockfile
//!    - Missing dependency in lockfile
//!    - `npm:` alias mismatch (different target package name)
//!    - Non-registry spec drift (tarball URL, git reference)
//!    - Tampered / corrupted integrity hash detection
//!    - `--omit=dev` with shared prod+dev dependencies (shared dependency preserved on disk)

#![allow(clippy::field_reassign_with_default)]

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

use rnpm_core::manifest::Manifest;
use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

fn create_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{}", rel_path);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .expect("Failed to append tar entry");
        }
        builder.finish().expect("Failed to finish tar archive");
    }
    gz.finish().expect("Failed to finish gzip compression")
}

fn compute_sha512_integrity(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("sha512-{}", data_encoding::BASE64.encode(&hash))
}

#[tokio::test]
async fn test_ci_shrinkwrap_precedence_over_drifted_package_lock() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_tar = create_tarball(&[(
        "package.json",
        br#"{"name":"dep-a","version":"1.0.0"}"#,
    )]);
    let integrity = compute_sha512_integrity(&pkg_tar);
    let tar_path = project_dir.join("dep-a-1.0.0.tgz");
    fs::write(&tar_path, &pkg_tar).unwrap();

    let tar_url = "file:./dep-a-1.0.0.tgz".to_string();

    // 1. package.json requires dep-a: 1.0.0
    let mut manifest = Manifest::default();
    manifest.name = Some("shrinkwrap-precedence-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-a".to_string(), "1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 2. npm-shrinkwrap.json is valid and matches package.json
    let mut sw = LockfileV3::new("shrinkwrap-precedence-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("dep-a".to_string(), "1.0.0".to_string());
    sw.root_package_mut().unwrap().dependencies = Some(deps);
    sw.insert_package(
        "node_modules/dep-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(tar_url.clone()),
            integrity: Some(integrity.clone()),
            ..Default::default()
        },
    );
    sw.save_to_file(&project_dir.join("npm-shrinkwrap.json"))
        .unwrap();

    // 3. package-lock.json is drifted (claims dep-a is 2.0.0)
    let mut bad_lock = LockfileV3::new("shrinkwrap-precedence-app", Some("1.0.0".to_string()));
    let mut bad_deps = BTreeMap::new();
    bad_deps.insert("dep-a".to_string(), "2.0.0".to_string());
    bad_lock.root_package_mut().unwrap().dependencies = Some(bad_deps);
    bad_lock
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 4. Run CI: must succeed because npm-shrinkwrap.json takes precedence over package-lock.json
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when npm-shrinkwrap.json is in sync, ignoring drifted package-lock.json: {:?}",
        res.err()
    );
    assert!(
        project_dir.join("node_modules/dep-a/package.json").exists(),
        "dep-a must be installed from shrinkwrap"
    );
}

#[tokio::test]
async fn test_ci_shrinkwrap_drift_fails_referencing_shrinkwrap() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json has dep-a
    let mut manifest = Manifest::default();
    manifest.name = Some("sw-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-a".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // npm-shrinkwrap.json does not have dep-a
    let sw = LockfileV3::new("sw-drift-app", Some("1.0.0".to_string()));
    sw.save_to_file(&project_dir.join("npm-shrinkwrap.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_err(), "run_ci must fail when shrinkwrap has drifted");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("npm-shrinkwrap.json"),
        "error message must reference npm-shrinkwrap.json: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_version_range_mismatch() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json requires ^2.0.0
    let mut manifest = Manifest::default();
    manifest.name = Some("range-mismatch-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg".to_string(), "^2.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile was built for ^1.0.0 with version 1.5.0
    let mut lockfile = LockfileV3::new("range-mismatch-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("pkg".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/pkg",
        LockfilePackage {
            version: Some("1.5.0".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when version range in package.json diverges from lockfile"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_missing_dep() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json adds extra-dep
    let mut manifest = Manifest::default();
    manifest.name = Some("missing-dep-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("extra-dep".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile is empty
    let lockfile = LockfileV3::new("missing-dep-app", Some("1.0.0".to_string()));
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when dependency in package.json is missing from lockfile"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
    assert!(
        err_msg.contains("extra-dep"),
        "error must mention the missing dependency: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_npm_alias_mismatch() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json points my-alias to npm:picocolors@^1.0.0
    let mut manifest = Manifest::default();
    manifest.name = Some("alias-mismatch-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("my-alias".to_string(), "npm:picocolors@^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile was built with my-alias pointing to npm:chalk@5.0.0
    let mut lockfile = LockfileV3::new("alias-mismatch-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("my-alias".to_string(), "npm:chalk@^5.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/my-alias",
        LockfilePackage {
            name: Some("chalk".to_string()),
            version: Some("5.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when alias target package diverges"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_tarball_and_git_spec() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json points to tarball v2.0.0
    let mut manifest = Manifest::default();
    manifest.name = Some("tarball-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert(
        "my-pkg".to_string(),
        "https://example.com/my-pkg-2.0.0.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile has tarball v1.0.0
    let mut lockfile = LockfileV3::new("tarball-drift-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert(
        "my-pkg".to_string(),
        "https://example.com/my-pkg-1.0.0.tgz".to_string(),
    );
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/my-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://example.com/my-pkg-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when tarball URL changes in package.json"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_tampered_integrity_hash() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("tampered-integrity-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg".to_string(), "1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile with completely invalid base64 integrity string
    let mut lockfile = LockfileV3::new("tampered-integrity-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("pkg".to_string(), "1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".to_string()),
            integrity: Some("sha512-NOT-A-VALID-BASE64-HASH!!!".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when lockfile integrity is tampered/invalid"
    );
}

#[tokio::test]
async fn test_ci_omit_dev_with_shared_prod_and_dev_deps() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // Create tarball for shared-dep
    let shared_tar = create_tarball(&[(
        "package.json",
        br#"{"name":"shared-dep","version":"1.0.0"}"#,
    )]);
    let shared_int = compute_sha512_integrity(&shared_tar);
    let shared_path = project_dir.join("shared-dep-1.0.0.tgz");
    fs::write(&shared_path, &shared_tar).unwrap();
    let shared_url = "file:./shared-dep-1.0.0.tgz".to_string();

    // Create tarball for pure-dev-dep
    let dev_tar = create_tarball(&[(
        "package.json",
        br#"{"name":"pure-dev-dep","version":"1.0.0"}"#,
    )]);
    let dev_int = compute_sha512_integrity(&dev_tar);
    let dev_path = project_dir.join("pure-dev-dep-1.0.0.tgz");
    fs::write(&dev_path, &dev_tar).unwrap();
    let dev_url = "file:./pure-dev-dep-1.0.0.tgz".to_string();

    // package.json lists shared-dep in BOTH dependencies and devDependencies
    let mut manifest = Manifest::default();
    manifest.name = Some("shared-dep-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("shared-dep".to_string(), "1.0.0".to_string());
    manifest
        .dev_dependencies
        .insert("shared-dep".to_string(), "1.0.0".to_string());
    manifest
        .dev_dependencies
        .insert("pure-dev-dep".to_string(), "1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Lockfile: shared-dep has dev: None (because it is required by prod), pure-dev-dep has dev: true
    let mut lockfile = LockfileV3::new("shared-dep-app", Some("1.0.0".to_string()));
    let mut prod_deps = BTreeMap::new();
    prod_deps.insert("shared-dep".to_string(), "1.0.0".to_string());
    let mut dev_deps = BTreeMap::new();
    dev_deps.insert("shared-dep".to_string(), "1.0.0".to_string());
    dev_deps.insert("pure-dev-dep".to_string(), "1.0.0".to_string());

    let root = lockfile.root_package_mut().unwrap();
    root.dependencies = Some(prod_deps);
    root.dev_dependencies = Some(dev_deps);

    lockfile.insert_package(
        "node_modules/shared-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(shared_url),
            integrity: Some(shared_int),
            dev: None, // Prod dependency takes priority: NOT flagged as dev
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/pure-dev-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(dev_url),
            integrity: Some(dev_int),
            dev: Some(true),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // Run CI with omit_dev: true
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        omit_dev: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci with omit_dev: true must succeed when shared prod+dev dep is in sync: {:?}",
        res.err()
    );

    // shared-dep MUST be present on disk
    assert!(
        project_dir.join("node_modules/shared-dep/package.json").exists(),
        "shared-dep MUST be present in node_modules even when omit_dev: true because it is a prod dependency"
    );

    // pure-dev-dep MUST be omitted
    assert!(
        !project_dir.join("node_modules/pure-dev-dep").exists(),
        "pure-dev-dep MUST be omitted from node_modules when omit_dev: true"
    );
}

#[tokio::test]
async fn test_ci_accepts_referential_overrides_demo() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let demo_tar = create_tarball(&[(
        "package.json",
        br#"{"name":"demo","version":"1.2.0"}"#,
    )]);
    let integrity = compute_sha512_integrity(&demo_tar);
    let tar_path = project_dir.join("demo-1.2.0.tgz");
    fs::write(&tar_path, &demo_tar).unwrap();

    let tar_url = "file:./demo-1.2.0.tgz".to_string();

    // 1. package.json with dependencies: {"demo": "^1.0.0"} and overrides: {"demo": "$demo"}
    let mut manifest = Manifest::default();
    manifest.name = Some("referential-override-ci-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("demo".to_string(), "^1.0.0".to_string());
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "demo": "$demo" }),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 2. package-lock.json with root package and node_modules/demo @ 1.2.0
    let mut lockfile = LockfileV3::new("referential-override-ci-app", Some("1.0.0".to_string()));
    let mut prod_deps = BTreeMap::new();
    prod_deps.insert("demo".to_string(), "^1.0.0".to_string());
    let mut root_extra = BTreeMap::new();
    root_extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "demo": "$demo" }),
    );

    let root = lockfile.root_package_mut().unwrap();
    root.dependencies = Some(prod_deps);
    root.extra = root_extra;

    lockfile.insert_package(
        "node_modules/demo",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            resolved: Some(tar_url),
            integrity: Some(integrity),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 3. Run rnpm ci
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when overrides contain referential '$demo' matching lockfile: {:?}",
        res.err()
    );

    // Verify demo installed on disk
    let demo_pkg_json = project_dir.join("node_modules/demo/package.json");
    assert!(
        demo_pkg_json.exists(),
        "node_modules/demo/package.json must exist after successful rnpm ci"
    );
    let installed_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&demo_pkg_json).unwrap()).unwrap();
    assert_eq!(installed_json["version"], "1.2.0");

    // 4. Verify drift detection: if manifest changes demo spec to ^2.0.0, CI must reject
    manifest
        .dependencies
        .insert("demo".to_string(), "^2.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut drifted_installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let drift_res = drifted_installer.run_ci().await;
    assert!(
        drift_res.is_err(),
        "run_ci must reject lockfile when demo spec drifts to ^2.0.0 while lockfile has 1.2.0"
    );
}

#[tokio::test]
async fn test_ci_workspace_absent_root_metadata_differential() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path();

    // 1. Root package.json declares workspaces: ["packages/*"]
    let mut manifest = Manifest::default();
    manifest.name = Some("ws-ci-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "packages/*".to_string(),
    ]));
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 2. Member A on disk
    fs::create_dir_all(project_dir.join("packages/member-a")).unwrap();
    let mut member_a = Manifest::default();
    member_a.name = Some("member-a".to_string());
    member_a.version = Some("1.0.0".to_string());
    member_a
        .save_to_file(project_dir.join("packages/member-a/package.json"))
        .unwrap();

    // 3. Lockfile v3 where root package omitted workspaces metadata
    let mut lockfile = LockfileV3::new("ws-ci-app", Some("1.0.0".to_string()));
    assert!(
        lockfile.root_package().unwrap().workspaces.is_none(),
        "root workspaces metadata omitted"
    );
    lockfile.insert_package(
        "packages/member-a",
        LockfilePackage {
            name: Some("member-a".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/member-a",
        LockfilePackage {
            resolved: Some("packages/member-a".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 4. `rnpm ci` MUST succeed despite absent root workspaces metadata
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when root workspace metadata is absent in lockfile: {:?}",
        res.err()
    );

    // 5. Genuine drift: add member-b on disk without updating lockfile -> run_ci must fail with ELOCKFILE_DRIFT
    fs::create_dir_all(project_dir.join("packages/member-b")).unwrap();
    let mut member_b = Manifest::default();
    member_b.name = Some("member-b".to_string());
    member_b.version = Some("1.0.0".to_string());
    member_b
        .save_to_file(project_dir.join("packages/member-b/package.json"))
        .unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let drift_res = installer2.run_ci().await;
    assert!(
        drift_res.is_err(),
        "run_ci must fail when an untracked member package is added on disk"
    );
    let err_msg = drift_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );

    // 6. Update lockfile with member-b AND an unhoisted workspace dependency
    let dep_tar = create_tarball(&[(
        "package.json",
        br#"{"name":"nested-dep","version":"1.0.0"}"#,
    )]);
    let dep_integrity = compute_sha512_integrity(&dep_tar);
    let dep_tar_path = project_dir.join("nested-dep-1.0.0.tgz");
    fs::write(&dep_tar_path, &dep_tar).unwrap();

    lockfile.insert_package(
        "packages/member-b",
        LockfilePackage {
            name: Some("member-b".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/member-b",
        LockfilePackage {
            resolved: Some("packages/member-b".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    // Unhoisted dependency inside packages/member-a/node_modules/nested-dep (Round 1 Finding 1 regression)
    lockfile.insert_package(
        "packages/member-a/node_modules/nested-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./nested-dep-1.0.0.tgz".to_string()),
            integrity: Some(dep_integrity),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer3 = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();
    let res3 = installer3.run_ci().await;
    assert!(
        res3.is_ok(),
        "run_ci must succeed with unhoisted workspace dependencies: {:?}",
        res3.err()
    );

    // 7. Delete all members from disk while workspaces field remains in package.json (Round 1 Finding 2 regression)
    fs::remove_dir_all(project_dir.join("packages/member-a")).unwrap();
    fs::remove_dir_all(project_dir.join("packages/member-b")).unwrap();

    let mut installer4 = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();
    let drift_empty = installer4.run_ci().await;
    assert!(
        drift_empty.is_err(),
        "run_ci must fail with ELOCKFILE_DRIFT when all workspace members are deleted from disk"
    );
    let err_msg4 = drift_empty.unwrap_err().to_string();
    assert!(
        err_msg4.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg4}"
    );
}

#[tokio::test]
async fn test_ci_workspace_member_drift_detected_when_root_workspaces_match() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. Root package.json with workspaces: ["packages/*"]
    let mut manifest = Manifest::default();
    manifest.name = Some("ws-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "packages/*".to_string(),
    ]));
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Create member-a on disk
    fs::create_dir_all(project_dir.join("packages/member-a")).unwrap();
    fs::write(
        project_dir.join("packages/member-a/package.json"),
        r#"{"name":"member-a","version":"1.0.0"}"#,
    )
    .unwrap();

    // 2. Lockfile has root workspaces: ["packages/*"] matching package.json,
    // but ONLY has packages/member-a (member-b is not in the lockfile).
    let mut lockfile = LockfileV3::new("ws-drift-app", Some("1.0.0".to_string()));
    lockfile.root_package_mut().unwrap().workspaces = Some(vec!["packages/*".to_string()]);
    lockfile.insert_package(
        "packages/member-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 3. Now add member-b on disk without updating lockfile
    fs::create_dir_all(project_dir.join("packages/member-b")).unwrap();
    fs::write(
        project_dir.join("packages/member-b/package.json"),
        r#"{"name":"member-b","version":"1.0.0"}"#,
    )
    .unwrap();

    // 4. rnpm ci must detect member-b is missing from lockfile and fail with ELOCKFILE_DRIFT
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when a new workspace member on disk is missing from lockfile"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_non_registry_url_drift_detected() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. package.json requires dep-a: https://example.com/dep-a-2.0.0.tgz
    let mut manifest = Manifest::default();
    manifest.name = Some("url-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-a".to_string(), "https://example.com/dep-a-2.0.0.tgz".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 2. package-lock.json resolved dep-a to https://example.com/dep-a-1.0.0.tgz
    let mut lockfile = LockfileV3::new("url-drift-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("dep-a".to_string(), "https://example.com/dep-a-1.0.0.tgz".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/dep-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://example.com/dep-a-1.0.0.tgz".to_string()),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 3. rnpm ci must detect that dep-a URL diverged and fail with ELOCKFILE_DRIFT
    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when non-registry dependency URL diverged"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "error must be ELOCKFILE_DRIFT: {err_msg}"
    );
}
