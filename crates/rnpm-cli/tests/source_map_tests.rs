use std::fs;
use std::path::PathBuf;
use std::process::Command;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::manifest::{Manifest, PackageBin, PackageWorkspaces};
use rnpm_core::semver::{Range, Version};
use rnpm_core::spec::{PackageSpec, PackageTarget};
use rnpm_fs::tarball::{strip_package_prefix, validate_entry_path};
use rnpm_lockfile::LockfileV3;
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_shim::create_shims;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("source-map")
}

#[test]
fn test_source_map_01_cli_dispatch() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test version
    let out = Command::new(rnpm_bin).arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rnpm"));

    // Test help
    let out = Command::new(rnpm_bin).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("High performance Rust implementation of npm workflows"));

    // Test unsupported command
    let out = Command::new(rnpm_bin).arg("publish").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ERR_UNSUPPORTED_COMMAND"));

    // Test unsupported flag
    let out = Command::new(rnpm_bin).args(["install", "--global"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ERR_UNSUPPORTED_FLAG"));
}

#[test]
fn test_source_map_02_config_precedence() {
    let npmrc_path = fixtures_root().join("02-config-precedence").join(".npmrc");
    let content = fs::read_to_string(&npmrc_path).expect("Read 02-config .npmrc");
    assert!(content.contains("registry=https://registry.npmjs.org/"));
    assert!(content.contains("@mycorp:registry="));
    assert!(content.contains("//registry.npmjs.org/:_authToken="));
}

#[test]
fn test_source_map_03_spec_grammar() {
    let cases_path = fixtures_root().join("03-spec-grammar").join("spec-cases.json");
    let val: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cases_path).unwrap()).unwrap();
    let cases = val["cases"].as_array().unwrap();

    for case in cases {
        let input = case["input"].as_str().unwrap();
        let expected_type = case.get("expected_type").and_then(|v| v.as_str());
        let expected_err = case.get("expected_error").and_then(|v| v.as_str());

        match PackageSpec::parse(input) {
            Ok(spec) => {
                assert!(expected_err.is_none(), "Expected error {expected_err:?} for '{input}'");
                match expected_type.unwrap() {
                    "range" => assert!(matches!(spec.target, PackageTarget::Range(_))),
                    "tag" => assert!(matches!(spec.target, PackageTarget::Tag(_))),
                    "version" => assert!(matches!(spec.target, PackageTarget::Version(_))),
                    "alias" => assert!(matches!(spec.target, PackageTarget::Alias { .. })),
                    "directory" | "file" => assert!(matches!(spec.target, PackageTarget::File(_))),
                    "git" => assert!(matches!(spec.target, PackageTarget::Git { .. })),
                    "remote" => assert!(matches!(spec.target, PackageTarget::Url(_))),
                    other => panic!("Unexpected type {other} for {input}"),
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                assert!(expected_err.is_some(), "Unexpected error parsing '{input}': {err_str}");
                if expected_err.unwrap() == "EUNSUPPORTEDPROTOCOL" {
                    assert!(err_str.contains("Unsupported URL Type") || err_str.contains("Unsupported protocol"));
                }
            }
        }
    }
}

#[test]
fn test_source_map_04_arborist_tree() {
    let pkg_json = fixtures_root().join("04-arborist-tree").join("package.json");
    let manifest = Manifest::from_file(&pkg_json).unwrap();
    assert_eq!(manifest.name.as_deref(), Some("fixture-arborist-tree"));
    assert_eq!(manifest.dependencies.get("dep-a").map(|s| s.as_str()), Some("^1.0.0"));
    assert_eq!(manifest.dev_dependencies.get("tool-dev").map(|s| s.as_str()), Some("^3.0.0"));
    assert!(manifest.extra.get("overrides").is_some());
}

#[test]
fn test_source_map_05_pacote_tarball() {
    let pkg_json = fixtures_root().join("05-pacote-tarball").join("package.json");
    let manifest = Manifest::from_file(&pkg_json).unwrap();
    assert_eq!(manifest.name.as_deref(), Some("fixture-pacote-tarball"));
    assert!(manifest.bin.is_some());
    match manifest.bin.unwrap() {
        PackageBin::Map(map) => {
            assert_eq!(map.get("pacote-tool").map(|s| s.as_str()), Some("./bin/tool.js"));
        }
        _ => panic!("Expected PackageBin::Map"),
    }
}

#[test]
fn test_source_map_06_registry_fetch() {
    let packument_path = fixtures_root().join("06-registry-fetch").join("packument.json");
    let content = fs::read_to_string(&packument_path).unwrap();
    let meta: AbbreviatedPackageMetadata = serde_json::from_str(&content).unwrap();
    assert!(meta.validate().is_ok());
    assert_eq!(meta.name, "@mycorp/sample-pkg");
    assert!(meta.versions.contains_key("1.0.0"));
}

#[test]
fn test_source_map_07_cacache_ssri() {
    let integrity_path = fixtures_root().join("07-cacache-ssri").join("integrity-cases.json");
    let val: serde_json::Value = serde_json::from_str(&fs::read_to_string(&integrity_path).unwrap()).unwrap();
    let cases = val["cases"].as_array().unwrap();

    for case in cases {
        let integ_str = case["integrity"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();

        let parsed = Integrity::parse(integ_str);
        if valid {
            let integ = parsed.expect("Valid integrity string");
            if let Some(expected_algo) = case.get("expected_algorithm").and_then(|v| v.as_str()) {
                let strongest = integ.strongest_algorithm().unwrap();
                match expected_algo {
                    "sha512" => assert_eq!(strongest, Algorithm::Sha512),
                    "sha256" => assert_eq!(strongest, Algorithm::Sha256),
                    _ => {}
                }
            }
        } else {
            assert!(parsed.is_err(), "Expected error parsing {integ_str}");
        }
    }
}

#[test]
fn test_source_map_08_lockfile_v3() {
    let lock_path = fixtures_root().join("08-lockfile-v3").join("package-lock.json");
    let lockfile = LockfileV3::load_from_file(&lock_path).unwrap();
    assert_eq!(lockfile.lockfile_version, 3);
    assert!(lockfile.packages.contains_key(""));
    assert!(lockfile.packages.contains_key("node_modules/pkg-sample"));
}

#[test]
fn test_source_map_09_node_semver() {
    let cases_path = fixtures_root().join("09-node-semver").join("semver-cases.json");
    let val: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cases_path).unwrap()).unwrap();
    let cases = val["cases"].as_array().unwrap();

    for case in cases {
        let range_str = case["range"].as_str().unwrap();
        let range = Range::parse(range_str).unwrap();

        for m in case["matches"].as_array().unwrap() {
            let v_str = m.as_str().unwrap();
            let v = Version::parse(v_str).unwrap();
            assert!(range.satisfies(&v), "Expected '{v_str}' to satisfy '{range_str}'");
        }

        for r in case["rejects"].as_array().unwrap() {
            let v_str = r.as_str().unwrap();
            let v = Version::parse(v_str).unwrap();
            assert!(!range.satisfies(&v), "Expected '{v_str}' to NOT satisfy '{range_str}'");
        }
    }
}

#[test]
fn test_source_map_10_lifecycle_scripts() {
    let pkg_json = fixtures_root().join("10-lifecycle-scripts").join("package.json");
    let manifest = Manifest::from_file(&pkg_json).unwrap();
    assert!(manifest.scripts.contains_key("preinstall"));
    assert!(manifest.scripts.contains_key("install"));
    assert!(manifest.scripts.contains_key("postinstall"));
    assert!(manifest.scripts.contains_key("test-env"));
}

#[test]
fn test_source_map_11_cmd_shim() {
    let pkg_json = fixtures_root().join("11-cmd-shim").join("package.json");
    let manifest = Manifest::from_file(&pkg_json).unwrap();
    assert!(manifest.bin.is_some());

    let temp = tempfile::tempdir().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let target_js = temp.path().join("my-cli.js");
    fs::write(&target_js, "#!/usr/bin/env node\nconsole.log('hi');").unwrap();

    create_shims(&bin_dir, "my-cli", "my-package/bin/my-cli.js").unwrap();
    assert!(bin_dir.join("my-cli").exists());
    assert!(bin_dir.join("my-cli.cmd").exists());
    assert!(bin_dir.join("my-cli.ps1").exists());
}

#[test]
fn test_source_map_12_fs_extraction() {
    let pkg_json = fixtures_root().join("12-fs-extraction").join("package.json");
    assert!(pkg_json.exists());

    // Test strip_package_prefix
    assert_eq!(strip_package_prefix(&PathBuf::from("package/index.js")), Some(PathBuf::from("index.js")));
    assert_eq!(strip_package_prefix(&PathBuf::from("package")), None);

    // Test validate_entry_path
    assert!(validate_entry_path(&PathBuf::from("index.js")).is_ok());
    assert!(validate_entry_path(&PathBuf::from("../traversal.js")).is_err());
    assert!(validate_entry_path(&PathBuf::from("CON.txt")).is_err());
}

#[test]
fn test_source_map_13_workspaces() {
    let root_json = fixtures_root().join("13-workspaces").join("package.json");
    let root_manifest = Manifest::from_file(&root_json).unwrap();
    assert!(matches!(root_manifest.workspaces, Some(PackageWorkspaces::List(ref l)) if l == &vec!["packages/*"]));

    let pkg_a = Manifest::from_file(&fixtures_root().join("13-workspaces/packages/pkg-a/package.json")).unwrap();
    assert_eq!(pkg_a.name.as_deref(), Some("pkg-a"));
    assert_eq!(pkg_a.dependencies.get("pkg-b").map(|s| s.as_str()), Some("workspace:*"));

    let pkg_b = Manifest::from_file(&fixtures_root().join("13-workspaces/packages/pkg-b/package.json")).unwrap();
    assert_eq!(pkg_b.name.as_deref(), Some("pkg-b"));
    assert!(pkg_b.scripts.contains_key("build"));
}
