#![allow(clippy::field_reassign_with_default)]

use rnpm_install::fast_path::{
    compute_project_fingerprint, enrich_lockfile_from_installed_manifests,
    validate_hidden_lockfile,
};
use rnpm_install::linked::InstallStrategy;
use rnpm_install::InstallOptions;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::BTreeMap;
use tempfile::tempdir;

#[test]
fn test_fast_path_userconfig_and_globalconfig_override_end_to_end() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let pkg_json = root.join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{"name": "test-app", "version": "1.0.0", "dependencies": {}}"#,
    )
    .unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();
    opts.config_override = None; // explicitly None to test fallback config loading

    let base_fp = compute_project_fingerprint(root, &opts).unwrap();

    // 1. Process userconfig override
    let user_npmrc = root.join(".my-user-npmrc");
    std::fs::write(
        &user_npmrc,
        "registry=https://custom-user-registry.internal/\n",
    )
    .unwrap();
    rnpm_config::set_process_userconfig(user_npmrc.clone());

    let user_fp = compute_project_fingerprint(root, &opts).unwrap();
    assert_ne!(
        base_fp, user_fp,
        "Fingerprint must change when process-level userconfig override is set"
    );

    // Edit userconfig file
    std::fs::write(
        &user_npmrc,
        "registry=https://another-user-registry.internal/\n",
    )
    .unwrap();
    let user_updated_fp = compute_project_fingerprint(root, &opts).unwrap();
    assert_ne!(
        user_fp, user_updated_fp,
        "Fingerprint must change when userconfig file content changes on disk"
    );

    // Reset process userconfig
    rnpm_config::set_process_userconfig(root.join(".cleared-user-npmrc"));

    // 2. Process globalconfig override
    let global_npmrc = root.join(".my-global-npmrc");
    std::fs::write(&global_npmrc, "fetch-retries=7\n").unwrap();
    rnpm_config::set_process_globalconfig(global_npmrc.clone());

    let global_fp = compute_project_fingerprint(root, &opts).unwrap();
    assert_ne!(
        base_fp, global_fp,
        "Fingerprint must change when process-level globalconfig override is set"
    );

    // Reset process globalconfig
    rnpm_config::set_process_globalconfig(root.join(".cleared-global-npmrc"));

    // 3. Process CLI overrides
    let mut cli_overrides = BTreeMap::new();
    cli_overrides.insert("offline".to_string(), "true".to_string());
    rnpm_config::set_process_cli_overrides(cli_overrides);

    let cli_fp = compute_project_fingerprint(root, &opts).unwrap();
    assert_ne!(
        base_fp, cli_fp,
        "Fingerprint must change when process-level CLI overrides are set"
    );
    rnpm_config::set_process_cli_overrides(BTreeMap::new());
}

#[test]
fn test_fast_path_missing_bin_shims_triggers_invalidation() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let my_cli_dir = nm.join("my-cli-pkg");
    std::fs::create_dir_all(&my_cli_dir).unwrap();
    std::fs::write(
        my_cli_dir.join("package.json"),
        r#"{"name": "my-cli-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("my-cli-pkg".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut pkg_entry = LockfilePackage::default();
    pkg_entry.version = Some("1.0.0".to_string());
    let mut bins = BTreeMap::new();
    bins.insert("run-my-cli".to_string(), "bin/run.js".to_string());
    pkg_entry.bin = Some(rnpm_lockfile::PackageBin::Map(bins));
    lockfile
        .packages
        .insert("node_modules/my-cli-pkg".to_string(), pkg_entry);

    let bin_dir = nm.join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(windows)]
    let shim_path = bin_dir.join("run-my-cli.cmd");
    #[cfg(not(windows))]
    let shim_path = bin_dir.join("run-my-cli");
    std::fs::write(&shim_path, "@echo off\n").unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();
    opts.bin_links = true;

    // Initially valid
    assert!(
        validate_hidden_lockfile(root, Some(&opts)),
        "Must be valid when bin shim exists in node_modules/.bin"
    );

    // Remove the bin shim file
    std::fs::remove_file(&shim_path).unwrap();
    assert!(
        !validate_hidden_lockfile(root, Some(&opts)),
        "Must be invalid when bin shim is missing and bin_links=true"
    );

    // If bin_links is false, missing bin shim should not invalidate
    opts.bin_links = false;
    assert!(
        validate_hidden_lockfile(root, Some(&opts)),
        "Must be valid when bin_links=false"
    );
}

#[test]
fn test_fast_path_corrupted_package_json_triggers_invalidation() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let pkg_dir = nm.join("corrupted-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    // 0-byte package.json
    std::fs::write(pkg_dir.join("package.json"), b"").unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("corrupted-pkg".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut pkg_entry = LockfilePackage::default();
    pkg_entry.version = Some("1.0.0".to_string());
    lockfile
        .packages
        .insert("node_modules/corrupted-pkg".to_string(), pkg_entry);

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();

    assert!(
        !validate_hidden_lockfile(root, Some(&opts)),
        "Must be invalid when package.json in node_modules is 0 bytes"
    );
}

#[test]
fn test_fast_path_dangling_workspace_junction_triggers_invalidation() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let ws_pkg = root.join("packages").join("local-lib");
    std::fs::create_dir_all(&ws_pkg).unwrap();
    std::fs::write(
        ws_pkg.join("package.json"),
        r#"{"name": "local-lib", "version": "1.0.0"}"#,
    )
    .unwrap();

    let junction = nm.join("local-lib");
    rnpm_fs::create_junction(&junction, &ws_pkg).unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("local-lib".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut link_entry = LockfilePackage::default();
    link_entry.version = Some("1.0.0".to_string());
    link_entry.link = Some(true);
    link_entry.resolved = Some("packages/local-lib".to_string());
    lockfile
        .packages
        .insert("node_modules/local-lib".to_string(), link_entry);

    let mut target_entry = LockfilePackage::default();
    target_entry.version = Some("1.0.0".to_string());
    lockfile
        .packages
        .insert("packages/local-lib".to_string(), target_entry);

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();

    assert!(
        validate_hidden_lockfile(root, Some(&opts)),
        "Must be valid when workspace target exists"
    );

    // Delete workspace target folder -> dangling junction
    std::fs::remove_dir_all(&ws_pkg).unwrap();
    assert!(
        !validate_hidden_lockfile(root, Some(&opts)),
        "Must be invalid when workspace junction target was deleted"
    );
}

#[test]
fn test_fast_path_dev_optional_omission_parity() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    let pkg_dir = nm.join("dev-opt");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "dev-opt", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("dev-opt".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut pkg_entry = LockfilePackage::default();
    pkg_entry.version = Some("1.0.0".to_string());
    pkg_entry.dev_optional = Some(true);
    lockfile
        .packages
        .insert("node_modules/dev-opt".to_string(), pkg_entry);

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    // 1. Under omit_dev=true only: devOptional is NOT omitted
    let mut opts_omit_dev = InstallOptions::default();
    opts_omit_dev.project_dir = root.to_path_buf();
    opts_omit_dev.omit_dev = true;
    opts_omit_dev.omit_optional = false;
    assert!(
        validate_hidden_lockfile(root, Some(&opts_omit_dev)),
        "devOptional package on disk must be valid under omit_dev=true alone"
    );

    // 2. Under omit_optional=true only: devOptional is NOT omitted
    let mut opts_omit_opt = InstallOptions::default();
    opts_omit_opt.project_dir = root.to_path_buf();
    opts_omit_opt.omit_dev = false;
    opts_omit_opt.omit_optional = true;
    assert!(
        validate_hidden_lockfile(root, Some(&opts_omit_opt)),
        "devOptional package on disk must be valid under omit_optional=true alone"
    );

    // 3. Under both omit_dev=true AND omit_optional=true: devOptional IS omitted
    let mut opts_omit_both = InstallOptions::default();
    opts_omit_both.project_dir = root.to_path_buf();
    opts_omit_both.omit_dev = true;
    opts_omit_both.omit_optional = true;
    assert!(
        !validate_hidden_lockfile(root, Some(&opts_omit_both)),
        "devOptional package on disk must be invalid when both omit_dev and omit_optional are true"
    );
}

#[test]
fn test_fast_path_bundle_dependencies_enrichment() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let pkg_dir = root.join("node_modules").join("bundler-tool");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::json!({
            "name": "bundler-tool",
            "version": "1.0.0",
            "bundleDependencies": ["inner-tool"]
        })
        .to_string(),
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut bundler_pkg = LockfilePackage::default();
    bundler_pkg.version = Some("1.0.0".to_string());
    lockfile
        .packages
        .insert("node_modules/bundler-tool".to_string(), bundler_pkg);

    enrich_lockfile_from_installed_manifests(&mut lockfile, root, None);

    let enriched = lockfile
        .packages
        .get("node_modules/bundler-tool")
        .expect("Package should exist");
    match &enriched.bundle_dependencies {
        Some(rnpm_core::manifest::BundledDependencies::List(list)) => {
            assert_eq!(list, &vec!["inner-tool".to_string()]);
        }
        _ => panic!("Expected bundle_dependencies to be enriched as List"),
    }
}

#[test]
fn test_fast_path_linked_mode_rejects_plain_directory() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    // Create root package.json with plain-pkg as a direct dependency
    std::fs::write(
        root.join("package.json"),
        serde_json::json!({
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "plain-pkg": "^1.0.0"
            }
        })
        .to_string(),
    )
    .unwrap();

    // Plain directory (not a junction to store)
    let pkg_dir = nm.join("plain-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "plain-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    let mut root_pkg = LockfilePackage::default();
    let mut root_deps = BTreeMap::new();
    root_deps.insert("plain-pkg".to_string(), "^1.0.0".to_string());
    root_pkg.dependencies = Some(root_deps);
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut pkg_entry = LockfilePackage::default();
    pkg_entry.version = Some("1.0.0".to_string());
    lockfile
        .packages
        .insert("node_modules/plain-pkg".to_string(), pkg_entry);

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();
    opts.install_strategy = InstallStrategy::Linked;

    assert!(
        !validate_hidden_lockfile(root, Some(&opts)),
        "Linked mode must reject top-level package that is a plain directory instead of a junction"
    );
}

#[test]
fn test_fast_path_bin_validation_safe_on_workspace_nested_packages_and_unicode_paths() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    std::fs::create_dir_all(&nm).unwrap();

    // Create root package.json
    std::fs::write(
        root.join("package.json"),
        r#"{"name": "root-app", "version": "1.0.0"}"#,
    )
    .unwrap();

    // A workspace package with a unicode path and a nested dependency containing a binary
    let ws_dep_dir = root.join("packages/日本語/node_modules/inner-tool");
    std::fs::create_dir_all(&ws_dep_dir).unwrap();
    std::fs::write(
        ws_dep_dir.join("package.json"),
        r#"{"name": "inner-tool", "version": "1.0.0", "bin": {"inner-tool": "bin/tool.js"}}"#,
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("root-app", Some("1.0.0".to_string()));
    let root_pkg = LockfilePackage::default();
    lockfile.packages.insert("".to_string(), root_pkg);

    let mut tool_pkg = LockfilePackage::default();
    tool_pkg.version = Some("1.0.0".to_string());
    let mut bin_map = BTreeMap::new();
    bin_map.insert("inner-tool".to_string(), "bin/tool.js".to_string());
    tool_pkg.bin = Some(rnpm_lockfile::PackageBin::Map(bin_map));
    lockfile.packages.insert(
        "packages/日本語/node_modules/inner-tool".to_string(),
        tool_pkg,
    );

    std::thread::sleep(std::time::Duration::from_millis(50));
    lockfile.save_hidden(root).unwrap();

    let mut opts = InstallOptions::default();
    opts.project_dir = root.to_path_buf();
    opts.bin_links = true;

    // Must not panic on UTF-8 path, and must not fail validation looking for inner-tool in root .bin
    assert!(
        validate_hidden_lockfile(root, Some(&opts)),
        "Workspace nested package bin must not trigger UTF-8 slice panic or false cache invalidation at root"
    );
}
