use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use rnpm_core::manifest::Manifest;
use rnpm_lockfile::{LockfilePackage, LockfileV3};

fn setup_cli_test_fixture(dir: &std::path::Path) {
    let mut manifest = Manifest::default();
    manifest.name = Some("cli-fixture-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("chalk".to_string(), "^4.1.2".to_string());
    manifest.dependencies.insert("express".to_string(), "^4.18.2".to_string());
    manifest.dev_dependencies.insert("jest".to_string(), "^29.0.0".to_string());
    manifest.optional_dependencies.insert("fsevents".to_string(), "^2.3.2".to_string());
    manifest.save_to_file(dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("cli-fixture-app", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
        root.dev_dependencies = Some(manifest.dev_dependencies.clone());
        root.optional_dependencies = Some(manifest.optional_dependencies.clone());
    }

    // chalk depends on ansi-styles
    let mut chalk_pkg = LockfilePackage {
        version: Some("4.1.2".to_string()),
        resolved: Some("https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz".to_string()),
        integrity: Some("sha512-chalk".to_string()),
        ..Default::default()
    };
    let mut chalk_deps = BTreeMap::new();
    chalk_deps.insert("ansi-styles".to_string(), "^4.1.0".to_string());
    chalk_pkg.dependencies = Some(chalk_deps);
    lockfile.insert_package("node_modules/chalk", chalk_pkg);

    let ansi_pkg = LockfilePackage {
        version: Some("4.3.0".to_string()),
        resolved: Some("https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz".to_string()),
        integrity: Some("sha512-ansi".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/ansi-styles", ansi_pkg);

    let express_pkg = LockfilePackage {
        version: Some("4.18.2".to_string()),
        resolved: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string()),
        integrity: Some("sha512-express".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/express", express_pkg);

    let jest_pkg = LockfilePackage {
        version: Some("29.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/jest/-/jest-29.0.0.tgz".to_string()),
        integrity: Some("sha512-jest".to_string()),
        dev: Some(true),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/jest", jest_pkg);

    let fsevents_pkg = LockfilePackage {
        version: Some("2.3.2".to_string()),
        resolved: Some("https://registry.npmjs.org/fsevents/-/fsevents-2.3.2.tgz".to_string()),
        integrity: Some("sha512-fsevents".to_string()),
        optional: Some(true),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/fsevents", fsevents_pkg);

    lockfile.save_to_file(&dir.join("package-lock.json")).unwrap();

    let nm = dir.join("node_modules");
    fs::create_dir_all(nm.join("chalk")).unwrap();
    fs::create_dir_all(nm.join("ansi-styles")).unwrap();
    fs::create_dir_all(nm.join("express")).unwrap();
    fs::create_dir_all(nm.join("jest")).unwrap();
    fs::create_dir_all(nm.join("fsevents")).unwrap();
}

#[test]
fn test_cli_uninstall_single_package_and_transitive_pruning() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_cli_test_fixture(project_dir);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("uninstall")
        .arg("chalk")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm uninstall");

    assert!(output.status.success(), "Command failed: {:?}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm: removed 1 package(s)"));

    // Verify package.json
    let manifest = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest.dependencies.contains_key("chalk"));
    assert!(manifest.dependencies.contains_key("express"));

    // Verify package-lock.json
    let lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!lockfile.packages.contains_key("node_modules/chalk"));
    assert!(!lockfile.packages.contains_key("node_modules/ansi-styles"));
    assert!(lockfile.packages.contains_key("node_modules/express"));

    // Verify node_modules deletion
    assert!(!project_dir.join("node_modules").join("chalk").exists());
    assert!(!project_dir.join("node_modules").join("ansi-styles").exists());
    assert!(project_dir.join("node_modules").join("express").exists());
}

#[test]
fn test_cli_uninstall_multiple_packages_and_aliases() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_cli_test_fixture(project_dir);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test 'rm' alias
    let output = Command::new(rnpm_bin)
        .arg("rm")
        .arg("chalk")
        .arg("express")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm rm");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm: removed 2 package(s)"));

    let manifest = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest.dependencies.contains_key("chalk"));
    assert!(!manifest.dependencies.contains_key("express"));

    let lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!lockfile.packages.contains_key("node_modules/chalk"));
    assert!(!lockfile.packages.contains_key("node_modules/express"));
    assert!(!lockfile.packages.contains_key("node_modules/ansi-styles"));
}

#[test]
fn test_cli_uninstall_with_save_dev_and_save_optional_flags() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_cli_test_fixture(project_dir);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Remove dev dependency with --save-dev
    let output_dev = Command::new(rnpm_bin)
        .arg("uninstall")
        .arg("jest")
        .arg("--save-dev")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm uninstall --save-dev");

    assert!(output_dev.status.success());
    let manifest1 = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest1.dev_dependencies.contains_key("jest"));
    assert!(manifest1.dependencies.contains_key("chalk"));

    // 2. Remove optional dependency with -O
    let output_opt = Command::new(rnpm_bin)
        .arg("uninstall")
        .arg("fsevents")
        .arg("-O")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm uninstall -O");

    assert!(output_opt.status.success());
    let manifest2 = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest2.optional_dependencies.contains_key("fsevents"));
    assert!(manifest2.dependencies.contains_key("chalk"));
}

#[test]
fn test_cli_uninstall_requires_package_argument() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("uninstall")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm uninstall without arguments");

    assert!(!output.status.success(), "Uninstall without arguments must exit with error");
}
