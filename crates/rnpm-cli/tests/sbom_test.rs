#![allow(clippy::field_reassign_with_default)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;
use common::isolated_npm;

use rnpm_core::manifest::Manifest;
use rnpm_lockfile::{LockfilePackage, LockfileV3};

fn setup_test_project(dir: &std::path::Path) {
    let mut manifest = Manifest::default();
    manifest.name = Some("my-sbom-app".to_string());
    manifest.version = Some("2.1.0".to_string());
    manifest
        .extra
        .insert("license".to_string(), Value::String("MIT".to_string()));
    manifest
        .dependencies
        .insert("chalk".to_string(), "^4.1.2".to_string());
    manifest
        .dev_dependencies
        .insert("jest".to_string(), "^29.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("fsevents".to_string(), "^2.3.2".to_string());
    manifest.save_to_file(dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("my-sbom-app", Some("2.1.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
        root.dev_dependencies = Some(manifest.dev_dependencies.clone());
        root.optional_dependencies = Some(manifest.optional_dependencies.clone());
        root.license = Some("MIT".to_string());
    }

    // Production dependency: chalk (depends on ansi-styles)
    let mut chalk_deps = BTreeMap::new();
    chalk_deps.insert("ansi-styles".to_string(), "^4.1.0".to_string());
    let chalk_pkg = LockfilePackage {
        version: Some("4.1.2".to_string()),
        resolved: Some("https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz".to_string()),
        integrity: Some("sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxflJlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==".to_string()),
        license: Some("MIT".to_string()),
        dependencies: Some(chalk_deps),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/chalk", chalk_pkg);

    // Transitive dependency: ansi-styles
    let ansi_pkg = LockfilePackage {
        version: Some("4.3.0".to_string()),
        resolved: Some("https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz".to_string()),
        integrity: Some("sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxflJlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==".to_string()),
        license: Some("MIT".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/ansi-styles", ansi_pkg);

    // Dev dependency: jest
    let mut jest_pkg = LockfilePackage {
        version: Some("29.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/jest/-/jest-29.0.0.tgz".to_string()),
        integrity: Some("sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxflJlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==".to_string()),
        license: Some("MIT".to_string()),
        ..Default::default()
    };
    jest_pkg.set_dev(true);
    lockfile.insert_package("node_modules/jest", jest_pkg);

    // Optional dependency: fsevents
    let mut fsevents_pkg = LockfilePackage {
        version: Some("2.3.2".to_string()),
        resolved: Some("https://registry.npmjs.org/fsevents/-/fsevents-2.3.2.tgz".to_string()),
        integrity: Some("sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxflJlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==".to_string()),
        license: Some("MIT".to_string()),
        ..Default::default()
    };
    fsevents_pkg.set_optional(true);
    lockfile.insert_package("node_modules/fsevents", fsevents_pkg);

    fs::write(
        dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile).unwrap(),
    )
    .unwrap();
}

// Compare complete documents with npm. Only generated UUIDs and timestamps vary.
fn normalize_document(mut value: Value) -> Value {
    for key in ["documentNamespace", "serialNumber"] {
        if let Some(raw) = value.get(key).and_then(Value::as_str) {
            assert!(raw.len() >= 36);
            let (prefix, uuid) = raw.split_at(raw.len() - 36);
            assert_eq!(uuid.chars().filter(|c| *c == '-').count(), 4);
            value[key] = format!("{prefix}<uuid>").into();
        }
    }
    for (parent, key) in [("creationInfo", "created"), ("metadata", "timestamp")] {
        if let Some(time) = value.get_mut(parent).and_then(|v| v.get_mut(key)) {
            let raw = time.as_str().unwrap();
            assert!(raw.contains('T') && raw.ends_with('Z'));
            *time = "<timestamp>".into();
        }
    }
    value
}

fn compare(dir: &std::path::Path, args: &[&str], expected_exit: i32) -> Value {
    let iso = tempdir().unwrap();
    let oracle = isolated_npm(iso.path());
    let mut candidate = Command::new(env!("CARGO_BIN_EXE_rnpm"));
    for (key, value) in oracle.get_envs() {
        if let Some(value) = value { candidate.env(key, value); }
        else { candidate.env_remove(key); }
    }
    let run = |mut cmd: Command| cmd.current_dir(dir).args(args)
        .env("NPM_CONFIG_REGISTRY", "http://127.0.0.1:9/")
        .env("NPM_CONFIG_UPDATE_NOTIFIER", "false").env("NO_COLOR", "1")
        .output().unwrap();
    let npm = run(oracle);
    let rnpm = run(candidate);
    assert_eq!(npm.status.code(), Some(expected_exit), "{}", String::from_utf8_lossy(&npm.stderr));
    assert_eq!(rnpm.status.code(), npm.status.code(), "{}", String::from_utf8_lossy(&rnpm.stderr));
    if expected_exit == 0 {
        assert_eq!(rnpm.stderr, npm.stderr);
        let expected = normalize_document(serde_json::from_slice(&npm.stdout).unwrap());
        let actual = normalize_document(serde_json::from_slice(&rnpm.stdout).unwrap());
        assert_eq!(actual, expected);
        actual
    } else {
        assert_eq!(rnpm.stdout, npm.stdout);
        // Both footers point to different generated diagnostic logs. Compare all
        // preceding error text and verify both include a diagnostic log path.
        let error = |bytes: &[u8]| {
            let text = String::from_utf8(bytes.to_vec()).unwrap().replace("\r\n", "\n");
            let (error, log) = text.split_once("npm error A complete log of this run can be found in: ").unwrap();
            assert!(std::path::Path::new(log.trim()).is_file());
            error.to_string()
        };
        assert_eq!(error(&rnpm.stderr), error(&npm.stderr));
        Value::Null
    }
}

#[test]
fn test_sbom_spdx_explicit_format() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    let doc = compare(tmp.path(), &["sbom", "--sbom-format=spdx", "--package-lock-only"], 0);
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
    assert_eq!(doc["packages"].as_array().unwrap().len(), 5);
    assert!(doc["relationships"].as_array().unwrap().iter().any(|r| r["relationshipType"] == "DESCRIBES"));
}

#[test]
fn test_sbom_cyclonedx_format() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    let doc = compare(tmp.path(), &["sbom", "--sbom-format=cyclonedx", "--sbom-type=application", "--package-lock-only"], 0);
    assert_eq!(doc["components"].as_array().unwrap().len(), 4);
    assert_eq!(doc["metadata"]["component"]["type"], "application");
}

#[test]
fn test_sbom_sbom_type_flag() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    let doc = compare(tmp.path(), &["sbom", "--sbom-format=cyclonedx", "--sbom-type=framework", "--package-lock-only"], 0);
    assert_eq!(doc["metadata"]["component"]["type"], "framework");
}

#[test]
fn test_sbom_omit_flags() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    for (omits, count) in [(vec!["--omit=dev"], 3), (vec!["--omit=optional"], 3), (vec!["--omit=dev", "--omit=optional"], 2)] {
        let mut args = vec!["sbom", "--sbom-format=cyclonedx", "--package-lock-only"];
        args.extend(&omits);
        let doc = compare(tmp.path(), &args, 0);
        assert_eq!(doc["components"].as_array().unwrap().len(), count);
    }
}

#[test]
fn test_sbom_package_lock_only_without_node_modules() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    assert!(!tmp.path().join("node_modules").exists());
    compare(tmp.path(), &["sbom", "--sbom-format=spdx", "--package-lock-only"], 0);
}

#[test]
fn test_sbom_missing_files_error() {
    let tmp = tempdir().unwrap();
    // npm requires a format even when package.json is absent.
    compare(tmp.path(), &["sbom"], 1);
    compare(tmp.path(), &["sbom", "--sbom-format=spdx", "--package-lock-only"], 1);
}

#[test]
fn test_sbom_live_npm_parity() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());
    // A lockfile alone does not satisfy actual-tree missing dependencies.
    compare(tmp.path(), &["sbom", "--sbom-format=cyclonedx"], 1);
}
