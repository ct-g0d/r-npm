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

#[test]
fn test_sbom_spdx_default_format() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .output()
        .expect("Failed to execute rnpm sbom");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let doc: Value = serde_json::from_str(&stdout).expect("Failed to parse output as JSON");

    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
    assert_eq!(doc["dataLicense"], "CC0-1.0");
    assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
    assert_eq!(doc["name"], "my-sbom-app@2.1.0");

    let describes = doc["documentDescribes"]
        .as_array()
        .expect("documentDescribes array");
    assert_eq!(describes.len(), 1);
    assert_eq!(describes[0], "SPDXRef-Package-my-sbom-app");

    let packages = doc["packages"].as_array().expect("packages array");
    // Root + chalk + ansi-styles + jest + fsevents = 5 packages
    assert_eq!(packages.len(), 5);

    // Verify root package
    let root_pkg = packages
        .iter()
        .find(|p| p["name"] == "my-sbom-app")
        .expect("root package");
    assert_eq!(root_pkg["versionInfo"], "2.1.0");
    assert_eq!(root_pkg["SPDXID"], "SPDXRef-Package-my-sbom-app");
    assert_eq!(root_pkg["packageFileName"], "package.json");
    assert_eq!(root_pkg["downloadLocation"], "NONE");
    assert_eq!(root_pkg["licenseDeclared"], "MIT");

    // Verify chalk package
    let chalk_pkg = packages
        .iter()
        .find(|p| p["name"] == "chalk")
        .expect("chalk package");
    assert_eq!(chalk_pkg["versionInfo"], "4.1.2");
    assert_eq!(
        chalk_pkg["downloadLocation"],
        "https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz"
    );
    assert_eq!(chalk_pkg["licenseDeclared"], "MIT");

    let ext_refs = chalk_pkg["externalRefs"]
        .as_array()
        .expect("externalRefs array");
    assert_eq!(ext_refs[0]["referenceCategory"], "PACKAGE-MANAGER");
    assert_eq!(ext_refs[0]["referenceType"], "purl");
    assert_eq!(ext_refs[0]["referenceLocator"], "pkg:npm/chalk@4.1.2");

    let checksums = chalk_pkg["checksums"].as_array().expect("checksums array");
    assert_eq!(checksums[0]["algorithm"], "SHA512");
    assert_eq!(
        checksums[0]["checksumValue"],
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5f9499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    );

    // Verify relationships
    let relationships = doc["relationships"]
        .as_array()
        .expect("relationships array");
    let describes_rel = relationships
        .iter()
        .find(|r| r["relationshipType"] == "DESCRIBES")
        .expect("DESCRIBES rel");
    assert_eq!(describes_rel["spdxElementId"], "SPDXRef-DOCUMENT");
    assert_eq!(
        describes_rel["relatedSpdxElement"],
        "SPDXRef-Package-my-sbom-app"
    );

    // Child -> Parent relationships (DEPENDENCY_OF)
    let chalk_dep = relationships
        .iter()
        .find(|r| {
            r["spdxElementId"] == "SPDXRef-Package-node-modules-chalk"
                && r["relationshipType"] == "DEPENDENCY_OF"
        })
        .expect("chalk DEPENDENCY_OF root");
    assert_eq!(
        chalk_dep["relatedSpdxElement"],
        "SPDXRef-Package-my-sbom-app"
    );

    let ansi_dep = relationships
        .iter()
        .find(|r| {
            r["spdxElementId"] == "SPDXRef-Package-node-modules-ansi-styles"
                && r["relationshipType"] == "DEPENDENCY_OF"
        })
        .expect("ansi DEPENDENCY_OF chalk");
    assert_eq!(
        ansi_dep["relatedSpdxElement"],
        "SPDXRef-Package-node-modules-chalk"
    );
}

#[test]
fn test_sbom_cyclonedx_format() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--sbom-format=cyclonedx")
        .arg("--sbom-type=application")
        .output()
        .expect("Failed to execute rnpm sbom");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let doc: Value = serde_json::from_str(&stdout).expect("Failed to parse output as JSON");

    assert_eq!(
        doc["$schema"],
        "http://cyclonedx.org/schema/bom-1.5.schema.json"
    );
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.5");
    assert!(doc["serialNumber"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));

    // Metadata
    let metadata = &doc["metadata"];
    assert_eq!(metadata["tools"][0]["name"], "rnpm");
    assert_eq!(metadata["lifecycles"][0]["phase"], "build");
    assert_eq!(metadata["component"]["name"], "my-sbom-app");
    assert_eq!(metadata["component"]["version"], "2.1.0");
    assert_eq!(metadata["component"]["type"], "application");
    assert_eq!(metadata["component"]["purl"], "pkg:npm/my-sbom-app@2.1.0");
    assert_eq!(
        metadata["component"]["bom-ref"],
        "pkg:npm/my-sbom-app@2.1.0"
    );

    // Components (chalk, ansi-styles, jest, fsevents = 4)
    let components = doc["components"].as_array().expect("components array");
    assert_eq!(components.len(), 4);

    let chalk_comp = components
        .iter()
        .find(|c| c["name"] == "chalk")
        .expect("chalk comp");
    assert_eq!(chalk_comp["version"], "4.1.2");
    assert_eq!(chalk_comp["type"], "library");
    assert_eq!(chalk_comp["purl"], "pkg:npm/chalk@4.1.2");
    assert_eq!(chalk_comp["bom-ref"], "pkg:npm/chalk@4.1.2");

    let ext_refs = chalk_comp["externalReferences"]
        .as_array()
        .expect("externalReferences");
    assert_eq!(ext_refs[0]["type"], "distribution");
    assert_eq!(
        ext_refs[0]["url"],
        "https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz"
    );

    let hashes = chalk_comp["hashes"].as_array().expect("hashes");
    assert_eq!(hashes[0]["alg"], "SHA-512");
    assert_eq!(
        hashes[0]["content"],
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5f9499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    );

    // Dependencies
    let dependencies = doc["dependencies"].as_array().expect("dependencies");
    let root_dep = dependencies
        .iter()
        .find(|d| d["ref"] == "pkg:npm/my-sbom-app@2.1.0")
        .expect("root dep link");
    let root_depends_on = root_dep["dependsOn"].as_array().expect("root dependsOn");
    assert!(root_depends_on.contains(&Value::String("pkg:npm/chalk@4.1.2".to_string())));
    assert!(root_depends_on.contains(&Value::String("pkg:npm/jest@29.0.0".to_string())));
    assert!(root_depends_on.contains(&Value::String("pkg:npm/fsevents@2.3.2".to_string())));

    let chalk_dep = dependencies
        .iter()
        .find(|d| d["ref"] == "pkg:npm/chalk@4.1.2")
        .expect("chalk dep link");
    let chalk_depends_on = chalk_dep["dependsOn"].as_array().expect("chalk dependsOn");
    assert_eq!(
        chalk_depends_on,
        &vec![Value::String("pkg:npm/ansi-styles@4.3.0".to_string())]
    );
}

#[test]
fn test_sbom_sbom_type_flag() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--sbom-format=cyclonedx")
        .arg("--sbom-type=framework")
        .output()
        .unwrap();

    assert!(output.status.success());
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(doc["metadata"]["component"]["type"], "framework");
}

#[test]
fn test_sbom_omit_flags() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Omit dev: removes jest
    let output_omit_dev = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--sbom-format=cyclonedx")
        .arg("--omit=dev")
        .output()
        .unwrap();
    let doc_dev: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output_omit_dev.stdout)).unwrap();
    let comps_dev = doc_dev["components"].as_array().unwrap();
    assert_eq!(comps_dev.len(), 3);
    assert!(!comps_dev.iter().any(|c| c["name"] == "jest"));

    // Omit optional: removes fsevents
    let output_omit_opt = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--sbom-format=cyclonedx")
        .arg("--omit=optional")
        .output()
        .unwrap();
    let doc_opt: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output_omit_opt.stdout)).unwrap();
    let comps_opt = doc_opt["components"].as_array().unwrap();
    assert_eq!(comps_opt.len(), 3);
    assert!(!comps_opt.iter().any(|c| c["name"] == "fsevents"));

    // Omit dev and optional: removes both jest and fsevents
    let output_omit_both = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--sbom-format=cyclonedx")
        .arg("--omit=dev,optional")
        .output()
        .unwrap();
    let doc_both: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output_omit_both.stdout)).unwrap();
    let comps_both = doc_both["components"].as_array().unwrap();
    assert_eq!(comps_both.len(), 2);
    assert!(comps_both.iter().any(|c| c["name"] == "chalk"));
    assert!(comps_both.iter().any(|c| c["name"] == "ansi-styles"));
}

#[test]
fn test_sbom_package_lock_only_without_node_modules() {
    let tmp = tempdir().unwrap();
    setup_test_project(tmp.path());

    // Explicitly verify node_modules does not exist
    assert!(!tmp.path().join("node_modules").exists());

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .arg("--package-lock-only")
        .output()
        .unwrap();

    assert!(output.status.success());
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
}

#[test]
fn test_sbom_missing_files_error() {
    let tmp = tempdir().unwrap();
    // Directory is completely empty (no package.json or package-lock.json)

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("sbom")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("package.json not found") || stderr.contains("ENOENT"));
}

#[test]
fn test_sbom_live_npm_parity() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();
    setup_test_project(tmp_rnpm.path());
    setup_test_project(tmp_npm.path());

    let iso = tempdir().unwrap();
    let cache_dir = iso.path().join("cache");
    let prefix_dir = iso.path().join("prefix");
    let appdata = iso.path().join("appdata");
    let localappdata = iso.path().join("localappdata");
    let userconfig = iso.path().join(".npmrc");
    let globalconfig = iso.path().join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(&userconfig, "registry=http://127.0.0.1:9/\n").unwrap();
    std::fs::write(&globalconfig, "").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .env("HOME", iso.path())
        .env("USERPROFILE", iso.path())
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("PREFIX", &prefix_dir)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .arg("sbom")
        .output()
        .expect("rnpm sbom failed");

    let npm_res = isolated_npm(iso.path())
        .arg("sbom")
        .current_dir(tmp_npm.path())
        .env("HOME", iso.path())
        .env("USERPROFILE", iso.path())
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("PREFIX", &prefix_dir)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res {
        if npm_out.status.success() {
            assert_eq!(rnpm_res.status.code(), npm_out.status.code());
            let rnpm_val: Value = serde_json::from_slice(&rnpm_res.stdout).unwrap();
            let npm_val: Value = serde_json::from_slice(&npm_out.stdout).unwrap();

            // Compare top-level SPDX fields
            assert_eq!(rnpm_val["spdxVersion"], npm_val["spdxVersion"]);
            assert_eq!(rnpm_val["dataLicense"], npm_val["dataLicense"]);
            assert_eq!(rnpm_val["SPDXID"], npm_val["SPDXID"]);
            assert_eq!(rnpm_val["name"], npm_val["name"]);
            assert_eq!(rnpm_val["documentDescribes"], npm_val["documentDescribes"]);

            // Both produce 0 stderr
            assert!(rnpm_res.stderr.is_empty());
        }
    }
}

