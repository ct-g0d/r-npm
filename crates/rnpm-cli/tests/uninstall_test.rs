#![allow(clippy::field_reassign_with_default)]

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
    manifest
        .dependencies
        .insert("chalk".to_string(), "^4.1.2".to_string());
    manifest
        .dependencies
        .insert("express".to_string(), "^4.18.2".to_string());
    manifest
        .dev_dependencies
        .insert("jest".to_string(), "^29.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("fsevents".to_string(), "^2.3.2".to_string());
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
        resolved: Some(
            "https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz".to_string(),
        ),
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

    lockfile
        .save_to_file(&dir.join("package-lock.json"))
        .unwrap();

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

    assert!(
        output.status.success(),
        "Command failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("removed 2 packages"));

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
    assert!(!project_dir
        .join("node_modules")
        .join("ansi-styles")
        .exists());
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
    assert!(stdout.contains("removed 3 packages"));

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

    assert!(
        !output.status.success(),
        "Uninstall without arguments must exit with error"
    );
}

fn normalize_output(text: &str, dir: &std::path::Path) -> String {
    let mut s = text.replace("\r\n", "\n");
    let dir_str = dir.to_string_lossy();
    s = s.replace(&dir_str.to_string(), "<DIR>");
    s = s.replace(&dir_str.replace('\\', "/"), "<DIR>");
    if let Ok(canon) = dir.canonicalize() {
        let canon_str = canon.to_string_lossy();
        s = s.replace(&canon_str.to_string(), "<DIR>");
        s = s.replace(&canon_str.replace('\\', "/"), "<DIR>");
        let unc = canon_str.trim_start_matches(r"\\?\");
        s = s.replace(unc, "<DIR>");
        s = s.replace(&unc.replace('\\', "/"), "<DIR>");
    }

    // Normalize timings like "in 123ms" or "in 1.2s"
    let mut normalized = String::new();
    let mut rest = s.as_str();
    while let Some(idx) = rest.find(" in ") {
        normalized.push_str(&rest[..idx + 4]);
        let after = &rest[idx + 4..];
        let end_num = after.find(|c: char| !c.is_numeric() && c != '.');
        if let Some(num_len) = end_num {
            let suffix = &after[num_len..];
            if let Some(stripped) = suffix.strip_prefix("ms") {
                normalized.push_str("<TIME>");
                rest = stripped;
                continue;
            } else if let Some(stripped) = suffix.strip_prefix('s') {
                normalized.push_str("<TIME>");
                rest = stripped;
                continue;
            }
        }
        normalized.push_str(&rest[idx + 4..idx + 5]);
        rest = &rest[idx + 5..];
    }
    normalized.push_str(rest);

    // Filter log lines
    normalized
        .lines()
        .filter(|line| !line.contains("A complete log of this run can be found in:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[test]
fn test_uninstall_live_npm_parity() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();

    let pkg_json = r#"{
  "name": "test-uninst",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "7.0.0"
  }
}
"#;
    let lock_json = r#"{
  "name": "test-uninst",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "test-uninst",
      "version": "1.0.0",
      "dependencies": {
        "is-number": "7.0.0"
      }
    },
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
      "integrity": "sha512-41Cifkg6e8TylhCSTQAqqWG0MSu0egZnncOS2Z394nV4VU4I9XHvaCz7Au34OBuoIdnH91WD54NypKW/hxbfhA=="
    }
  }
}
"#;
    fs::write(tmp_rnpm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_rnpm.path().join("package-lock.json"), lock_json).unwrap();
    fs::create_dir_all(tmp_rnpm.path().join("node_modules").join("is-number")).unwrap();

    fs::write(tmp_npm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_npm.path().join("package-lock.json"), lock_json).unwrap();
    fs::create_dir_all(tmp_npm.path().join("node_modules").join("is-number")).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_out = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .args(["uninstall", "is-number", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm uninstall failed");

    let npm_res = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "uninstall", "is-number", "--no-audit", "--no-fund"])
        .current_dir(tmp_npm.path())
        .output();

    if let Ok(npm_out) = npm_res {
        if npm_out.status.success() {
            assert_eq!(rnpm_out.status.code(), npm_out.status.code());
            let rnpm_norm_stdout = normalize_output(&String::from_utf8_lossy(&rnpm_out.stdout), tmp_rnpm.path());
            let npm_norm_stdout = normalize_output(&String::from_utf8_lossy(&npm_out.stdout), tmp_npm.path());
            assert_eq!(rnpm_norm_stdout, npm_norm_stdout, "stdout mismatch: rnpm={:?} vs npm={:?}", rnpm_norm_stdout, npm_norm_stdout);

            let rnpm_norm_stderr = normalize_output(&String::from_utf8_lossy(&rnpm_out.stderr), tmp_rnpm.path());
            let npm_norm_stderr = normalize_output(&String::from_utf8_lossy(&npm_out.stderr), tmp_npm.path());
            assert_eq!(rnpm_norm_stderr, npm_norm_stderr, "stderr mismatch: rnpm={:?} vs npm={:?}", rnpm_norm_stderr, npm_norm_stderr);
        }
    }
}

