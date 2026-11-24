#![allow(clippy::field_reassign_with_default)]

use rnpm_install::fast_path::{compute_project_fingerprint, validate_hidden_lockfile};
use rnpm_install::InstallOptions;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::BTreeMap;
use tempfile::tempdir;

struct TestFixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    opts: InstallOptions,
}

fn setup_warm_fixture() -> TestFixture {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    // 1. Root package.json
    let pkg_json = root.join("package.json");
    std::fs::write(
        &pkg_json,
        serde_json::json!({
            "name": "perf-test-root",
            "version": "1.0.0",
            "dependencies": {
                "@scope/scoped-pkg": "^1.0.0",
                "regular-pkg": "^1.0.0",
                "ws-linked": "^1.0.0"
            },
            "optionalDependencies": {
                "opt-darwin": "^1.0.0"
            }
        })
        .to_string(),
    )
    .unwrap();

    // 2. Scoped package: node_modules/@scope/scoped-pkg
    let scoped_dir = nm.join("@scope").join("scoped-pkg");
    std::fs::create_dir_all(&scoped_dir).unwrap();
    std::fs::write(
        scoped_dir.join("package.json"),
        r#"{"name": "@scope/scoped-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // 3. Regular package: node_modules/regular-pkg with bin and nested node_modules
    let reg_dir = nm.join("regular-pkg");
    std::fs::create_dir_all(&reg_dir).unwrap();
    std::fs::write(
        reg_dir.join("package.json"),
        r#"{"name": "regular-pkg", "version": "1.0.0", "bin": {"regular-cli": "bin/cli.js"}}"#,
    )
    .unwrap();

    let nested_dir = reg_dir.join("node_modules").join("nested-dep");
    std::fs::create_dir_all(&nested_dir).unwrap();
    std::fs::write(
        nested_dir.join("package.json"),
        r#"{"name": "nested-dep", "version": "2.0.0"}"#,
    )
    .unwrap();

    // 4. Workspace member: packages/ws-linked
    let ws_pkg_dir = root.join("packages").join("ws-linked");
    std::fs::create_dir_all(&ws_pkg_dir).unwrap();
    std::fs::write(
        ws_pkg_dir.join("package.json"),
        r#"{"name": "ws-linked", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Junction in node_modules pointing to workspace member
    let ws_link = nm.join("ws-linked");
    rnpm_fs::create_junction(&ws_link, &ws_pkg_dir).unwrap();

    // 5. Bin shims in node_modules/.bin
    let bin_dir = nm.join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(windows)]
    {
        std::fs::write(bin_dir.join("regular-cli.cmd"), "@echo off\n").unwrap();
        std::fs::write(bin_dir.join("regular-cli.ps1"), "# powershell\n").unwrap();
        std::fs::write(bin_dir.join("regular-cli"), "#!/bin/sh\n").unwrap();
    }
    #[cfg(not(windows))]
    {
        std::fs::write(bin_dir.join("regular-cli"), "#!/bin/sh\n").unwrap();
    }

    // 6. Build LockfileV3
    let mut lockfile = LockfileV3::new("perf-test-root", Some("1.0.0".to_string()));

    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("@scope/scoped-pkg".to_string(), "^1.0.0".to_string());
    root_deps.insert("regular-pkg".to_string(), "^1.0.0".to_string());
    root_deps.insert("ws-linked".to_string(), "^1.0.0".to_string());
    let mut root_opt = BTreeMap::new();
    root_opt.insert("opt-darwin".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    root_pkg.optional_dependencies = Some(root_opt);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut scoped_entry = LockfilePackage::default();
    scoped_entry.version = Some("1.0.0".to_string());
    lockfile.packages.insert(
        "node_modules/@scope/scoped-pkg".to_string(),
        scoped_entry,
    );

    let mut reg_entry = LockfilePackage::default();
    reg_entry.version = Some("1.0.0".to_string());
    let mut bins = BTreeMap::new();
    bins.insert("regular-cli".to_string(), "bin/cli.js".to_string());
    reg_entry.bin = Some(rnpm_lockfile::PackageBin::Map(bins));
    lockfile
        .packages
        .insert("node_modules/regular-pkg".to_string(), reg_entry);

    let mut nested_entry = LockfilePackage::default();
    nested_entry.version = Some("2.0.0".to_string());
    lockfile.packages.insert(
        "node_modules/regular-pkg/node_modules/nested-dep".to_string(),
        nested_entry,
    );

    let mut ws_link_entry = LockfilePackage::default();
    ws_link_entry.version = Some("1.0.0".to_string());
    ws_link_entry.link = Some(true);
    ws_link_entry.resolved = Some("packages/ws-linked".to_string());
    lockfile
        .packages
        .insert("node_modules/ws-linked".to_string(), ws_link_entry);

    let mut ws_target_entry = LockfilePackage::default();
    ws_target_entry.version = Some("1.0.0".to_string());
    lockfile
        .packages
        .insert("packages/ws-linked".to_string(), ws_target_entry);

    // Platform-skipped optional package (darwin on win32/linux)
    let mut darwin_entry = LockfilePackage::default();
    darwin_entry.version = Some("1.0.0".to_string());
    darwin_entry.optional = Some(true);
    darwin_entry.os = Some(vec!["darwin".to_string()].into());
    lockfile
        .packages
        .insert("node_modules/opt-darwin".to_string(), darwin_entry);

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(&root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.clone();
    opts.bin_links = true;
    #[cfg(windows)]
    {
        opts.os = Some("win32".to_string());
    }
    #[cfg(not(windows))]
    {
        opts.os = Some("linux".to_string());
    }

    TestFixture {
        _tmp: tmp,
        root,
        opts,
    }
}

#[test]
fn test_warm_tree_fast_path_hit_comprehensive() {
    let fixture = setup_warm_fixture();

    assert!(
        validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Comprehensive warm tree must hit fast path validation cleanly"
    );

    let fp = compute_project_fingerprint(&fixture.root, &fixture.opts).unwrap();
    assert!(!fp.is_empty(), "Fingerprint computation must succeed");
}

#[test]
fn test_fast_path_miss_on_missing_package_directory() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Delete scoped package directory
    let scoped_dir = fixture.root.join("node_modules").join("@scope").join("scoped-pkg");
    std::fs::remove_dir_all(&scoped_dir).unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Missing package directory must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_deleted_package_json() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Delete package.json inside regular-pkg
    let reg_pkg_json = fixture.root.join("node_modules").join("regular-pkg").join("package.json");
    std::fs::remove_file(&reg_pkg_json).unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Deleted package.json inside package must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_deleted_nested_package_json() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Delete package.json inside nested dependency
    let nested_pkg_json = fixture
        .root
        .join("node_modules")
        .join("regular-pkg")
        .join("node_modules")
        .join("nested-dep")
        .join("package.json");
    std::fs::remove_file(&nested_pkg_json).unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Deleted package.json inside nested dependency must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_missing_bin_shim() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Remove the bin shims
    #[cfg(windows)]
    {
        let _ = std::fs::remove_file(fixture.root.join("node_modules").join(".bin").join("regular-cli.cmd"));
        let _ = std::fs::remove_file(fixture.root.join("node_modules").join(".bin").join("regular-cli.ps1"));
        let _ = std::fs::remove_file(fixture.root.join("node_modules").join(".bin").join("regular-cli"));
    }
    #[cfg(not(windows))]
    {
        std::fs::remove_file(fixture.root.join("node_modules").join(".bin").join("regular-cli")).unwrap();
    }

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Missing bin shim must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_tampered_package_json_spec() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Tamper version spec in root package.json from ^1.0.0 to ^2.0.0
    let pkg_json = fixture.root.join("package.json");
    std::fs::write(
        &pkg_json,
        serde_json::json!({
            "name": "perf-test-root",
            "version": "1.0.0",
            "dependencies": {
                "@scope/scoped-pkg": "^1.0.0",
                "regular-pkg": "^2.0.0", // drifted spec!
                "ws-linked": "^1.0.0"
            },
            "optionalDependencies": {
                "opt-darwin": "^1.0.0"
            }
        })
        .to_string(),
    )
    .unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Tampered/drifted dependency version in package.json must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_tampered_package_json_added_dependency() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Add new dependency to root package.json
    let pkg_json = fixture.root.join("package.json");
    std::fs::write(
        &pkg_json,
        serde_json::json!({
            "name": "perf-test-root",
            "version": "1.0.0",
            "dependencies": {
                "@scope/scoped-pkg": "^1.0.0",
                "regular-pkg": "^1.0.0",
                "ws-linked": "^1.0.0",
                "brand-new-dep": "^1.0.0" // newly added!
            },
            "optionalDependencies": {
                "opt-darwin": "^1.0.0"
            }
        })
        .to_string(),
    )
    .unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Newly added dependency in package.json must cause fast path miss"
    );
}

#[test]
fn test_fast_path_miss_on_broken_symlink_or_junction() {
    let fixture = setup_warm_fixture();
    assert!(validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)));

    // Delete workspace target directory to make junction dangling
    let ws_pkg_dir = fixture.root.join("packages").join("ws-linked");
    std::fs::remove_dir_all(&ws_pkg_dir).unwrap();

    assert!(
        !validate_hidden_lockfile(&fixture.root, Some(&fixture.opts)),
        "Broken junction / symlink must cause fast path miss"
    );
}
