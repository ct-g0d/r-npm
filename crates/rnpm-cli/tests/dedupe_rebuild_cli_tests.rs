#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use rnpm_core::manifest::Manifest;
use rnpm_lockfile::{LockfilePackage, LockfileV3};

#[test]
fn test_cli_dedupe_removes_nested_duplicate() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // Setup package.json
    let mut manifest = Manifest::default();
    manifest.name = Some("dedupe-cli-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("parent".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("dep".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    // Create root package-lock.json
    let mut lock = LockfileV3::new("dedupe-cli-app", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/parent",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(BTreeMap::from([("dep".to_string(), "^1.0.0".to_string())])),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/dep",
        LockfilePackage {
            version: Some("1.5.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/parent/node_modules/dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    // Create directories
    let root_dep = project_dir.join("node_modules").join("dep");
    fs::create_dir_all(&root_dep).unwrap();
    fs::write(root_dep.join("package.json"), r#"{"name": "dep", "version": "1.5.0"}"#).unwrap();

    let parent_dir = project_dir.join("node_modules").join("parent");
    let nested_dep = parent_dir.join("node_modules").join("dep");
    fs::create_dir_all(&nested_dep).unwrap();
    fs::write(
        parent_dir.join("package.json"),
        r#"{"name": "parent", "version": "1.0.0", "dependencies": {"dep": "^1.0.0"}}"#,
    ).unwrap();
    fs::write(nested_dep.join("package.json"), r#"{"name": "dep", "version": "1.0.0"}"#).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("dedupe")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm dedupe");

    assert!(output.status.success(), "dedupe failed: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dedupe: removed node_modules/parent/node_modules/dep") || stdout.contains("successfully deduplicated"));

    // Check disk
    assert!(!nested_dep.exists(), "Nested duplicate must be deleted");
    assert!(root_dep.exists(), "Root dependency must remain");

    // Check lockfile
    let updated_lock = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(updated_lock.get_package("node_modules/parent/node_modules/dep").is_none());
    assert!(updated_lock.get_package("node_modules/dep").is_some());
}

#[test]
fn test_cli_dedupe_dry_run() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    fs::write(
        project_dir.join("package.json"),
        r#"{"name": "dry-run-cli", "version": "1.0.0", "dependencies": {"p": "^1.0.0", "d": "^1.0.0"}}"#,
    ).unwrap();

    let root_d = project_dir.join("node_modules").join("d");
    fs::create_dir_all(&root_d).unwrap();
    fs::write(root_d.join("package.json"), r#"{"name": "d", "version": "2.0.0"}"#).unwrap();

    let p = project_dir.join("node_modules").join("p");
    let nested_d = p.join("node_modules").join("d");
    fs::create_dir_all(&nested_d).unwrap();
    fs::write(p.join("package.json"), r#"{"name": "p", "version": "1.0.0", "dependencies": {"d": "^2.0.0"}}"#).unwrap();
    fs::write(nested_d.join("package.json"), r#"{"name": "d", "version": "2.0.0"}"#).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("dedupe")
        .arg("--dry-run")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm dedupe --dry-run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dedupe: would remove") || stdout.contains("dedupe dry-run"));

    // Files must NOT be deleted
    assert!(nested_d.exists(), "Dry-run MUST NOT delete files on disk");
}

#[test]
fn test_cli_find_dupes() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    fs::write(
        project_dir.join("package.json"),
        r#"{"name": "find-dupes-cli", "version": "1.0.0", "dependencies": {"p": "^1.0.0", "d": "^1.0.0"}}"#,
    ).unwrap();

    let root_d = project_dir.join("node_modules").join("d");
    fs::create_dir_all(&root_d).unwrap();
    fs::write(root_d.join("package.json"), r#"{"name": "d", "version": "2.0.0"}"#).unwrap();

    let p = project_dir.join("node_modules").join("p");
    let nested_d = p.join("node_modules").join("d");
    fs::create_dir_all(&nested_d).unwrap();
    fs::write(p.join("package.json"), r#"{"name": "p", "version": "1.0.0", "dependencies": {"d": "^2.0.0"}}"#).unwrap();
    fs::write(nested_d.join("package.json"), r#"{"name": "d", "version": "2.0.0"}"#).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("find-dupes")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm find-dupes");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("find-dupes: duplicate found") || stdout.contains("duplicate package(s) detected"));
    assert!(nested_d.exists());
}

#[test]
fn test_cli_rebuild_runs_scripts() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let marker_file = project_dir.join("cli_rebuild_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_dir = project_dir.join("node_modules").join("built-pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        format!(
            r#"{{"name": "built-pkg", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'rebuilt\\n')\""}}}}"#
        ),
    ).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("rebuild")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm rebuild");

    assert!(output.status.success(), "rebuild failed: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm: rebuilt built-pkg@1.0.0") || stdout.contains("successfully rebuilt"));
    assert!(marker_file.exists());
}

#[test]
fn test_cli_rebuild_selective() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let marker_file = project_dir.join("selective_cli_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let p1 = project_dir.join("node_modules").join("pkg-one");
    let p2 = project_dir.join("node_modules").join("pkg-two");
    fs::create_dir_all(&p1).unwrap();
    fs::create_dir_all(&p2).unwrap();

    fs::write(
        p1.join("package.json"),
        format!(
            r#"{{"name": "pkg-one", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'one\\n')\""}}}}"#
        ),
    ).unwrap();
    fs::write(
        p2.join("package.json"),
        format!(
            r#"{{"name": "pkg-two", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'two\\n')\""}}}}"#
        ),
    ).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("rebuild")
        .arg("pkg-one")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute selective rebuild");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pkg-one"));
    assert!(!stdout.contains("pkg-two"));

    let content = fs::read_to_string(&marker_file).unwrap();
    assert!(content.contains("one"));
    assert!(!content.contains("two"));
}

#[test]
fn test_cli_rebuild_ignore_scripts() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let marker_file = project_dir.join("ignore_cli_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let p1 = project_dir.join("node_modules").join("pkg-ignored");
    fs::create_dir_all(&p1).unwrap();
    fs::write(
        p1.join("package.json"),
        format!(
            r#"{{"name": "pkg-ignored", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'ran\\n')\""}}}}"#
        ),
    ).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("rebuild")
        .arg("--ignore-scripts")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rebuild with --ignore-scripts");

    assert!(output.status.success());
    assert!(!marker_file.exists());
}
