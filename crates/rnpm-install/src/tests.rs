use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Builder, Header};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::manifest::{Manifest, PackageBin};
use rnpm_fs::junction::{create_junction, is_junction};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use crate::{InstallOptions, Installer, UninstallOptions};

fn setup_fixture_project(dir: &Path) {
    // 1. Root package.json
    let mut manifest = Manifest::default();
    manifest.name = Some("test-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("pkg-b".to_string(), "^2.0.0".to_string());
    manifest.dev_dependencies.insert("pkg-dev".to_string(), "^0.5.0".to_string());
    manifest.optional_dependencies.insert("pkg-opt".to_string(), "^3.0.0".to_string());
    manifest.save_to_file(dir.join("package.json")).unwrap();

    // 2. package-lock.json
    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
        root.dev_dependencies = Some(manifest.dev_dependencies.clone());
        root.optional_dependencies = Some(manifest.optional_dependencies.clone());
    }

    // pkg-a (depends on sub-dep)
    let mut pkg_a = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz".to_string()),
        integrity: Some("sha512-aaa".to_string()),
        ..Default::default()
    };
    let mut a_deps = BTreeMap::new();
    a_deps.insert("sub-dep".to_string(), "^1.0.0".to_string());
    pkg_a.dependencies = Some(a_deps);
    lockfile.insert_package("node_modules/pkg-a", pkg_a);

    // sub-dep
    let sub_dep = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/sub-dep/-/sub-dep-1.0.0.tgz".to_string()),
        integrity: Some("sha512-sub".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/sub-dep", sub_dep);

    // pkg-b
    let pkg_b = LockfilePackage {
        version: Some("2.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/pkg-b/-/pkg-b-2.0.0.tgz".to_string()),
        integrity: Some("sha512-bbb".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/pkg-b", pkg_b);

    // pkg-dev
    let pkg_dev = LockfilePackage {
        version: Some("0.5.0".to_string()),
        resolved: Some("https://registry.npmjs.org/pkg-dev/-/pkg-dev-0.5.0.tgz".to_string()),
        integrity: Some("sha512-dev".to_string()),
        dev: Some(true),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/pkg-dev", pkg_dev);

    // pkg-opt
    let pkg_opt = LockfilePackage {
        version: Some("3.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/pkg-opt/-/pkg-opt-3.0.0.tgz".to_string()),
        integrity: Some("sha512-opt".to_string()),
        optional: Some(true),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/pkg-opt", pkg_opt);

    lockfile.save_to_file(&dir.join("package-lock.json")).unwrap();

    // 3. node_modules layout
    let nm = dir.join("node_modules");
    fs::create_dir_all(nm.join("pkg-a")).unwrap();
    fs::write(nm.join("pkg-a").join("package.json"), r#"{"name":"pkg-a","version":"1.0.0"}"#).unwrap();

    fs::create_dir_all(nm.join("sub-dep")).unwrap();
    fs::write(nm.join("sub-dep").join("package.json"), r#"{"name":"sub-dep","version":"1.0.0"}"#).unwrap();

    fs::create_dir_all(nm.join("pkg-b")).unwrap();
    fs::write(nm.join("pkg-b").join("package.json"), r#"{"name":"pkg-b","version":"2.0.0"}"#).unwrap();

    fs::create_dir_all(nm.join("pkg-dev")).unwrap();
    fs::write(nm.join("pkg-dev").join("package.json"), r#"{"name":"pkg-dev","version":"0.5.0"}"#).unwrap();

    fs::create_dir_all(nm.join("pkg-opt")).unwrap();
    fs::write(nm.join("pkg-opt").join("package.json"), r#"{"name":"pkg-opt","version":"3.0.0"}"#).unwrap();
}

#[test]
fn test_uninstall_single_package_and_transitive_pruning() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_fixture_project(project_dir);

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    };
    let installer = Installer::new(options).unwrap();

    let uninstall_opts = UninstallOptions {
        packages: vec!["pkg-a".to_string()],
        ..Default::default()
    };

    let summary = installer.uninstall(&uninstall_opts).unwrap();
    assert_eq!(summary.removed_packages, vec!["pkg-a".to_string()]);
    // Transitive dependency sub-dep must also be pruned!
    assert!(summary.pruned_dependencies.contains(&"node_modules/sub-dep".to_string()));

    // Verify package.json
    let updated_manifest = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!updated_manifest.dependencies.contains_key("pkg-a"));
    assert!(updated_manifest.dependencies.contains_key("pkg-b"));

    // Verify package-lock.json
    let updated_lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(!updated_lockfile.packages.contains_key("node_modules/sub-dep"));
    assert!(updated_lockfile.packages.contains_key("node_modules/pkg-b"));

    // Verify node_modules deletion
    assert!(!project_dir.join("node_modules").join("pkg-a").exists());
    assert!(!project_dir.join("node_modules").join("sub-dep").exists());
    assert!(project_dir.join("node_modules").join("pkg-b").exists());
}

#[test]
fn test_uninstall_multiple_packages() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_fixture_project(project_dir);

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    };
    let installer = Installer::new(options).unwrap();

    let uninstall_opts = UninstallOptions {
        packages: vec!["pkg-a".to_string(), "pkg-b".to_string()],
        ..Default::default()
    };

    let summary = installer.uninstall(&uninstall_opts).unwrap();
    assert!(summary.removed_packages.contains(&"pkg-a".to_string()));
    assert!(summary.removed_packages.contains(&"pkg-b".to_string()));

    let updated_manifest = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!updated_manifest.dependencies.contains_key("pkg-a"));
    assert!(!updated_manifest.dependencies.contains_key("pkg-b"));
    assert!(updated_manifest.dev_dependencies.contains_key("pkg-dev"));

    let updated_lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-b"));
    assert!(!updated_lockfile.packages.contains_key("node_modules/sub-dep"));
    assert!(updated_lockfile.packages.contains_key("node_modules/pkg-dev"));

    assert!(!project_dir.join("node_modules").join("pkg-a").exists());
    assert!(!project_dir.join("node_modules").join("pkg-b").exists());
    assert!(!project_dir.join("node_modules").join("sub-dep").exists());
    assert!(project_dir.join("node_modules").join("pkg-dev").exists());
}

#[test]
fn test_uninstall_flags_save_dev_and_save_optional() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_fixture_project(project_dir);

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    };
    let installer = Installer::new(options).unwrap();

    // 1. Uninstall pkg-dev with --save-dev
    let uninstall_dev = UninstallOptions {
        packages: vec!["pkg-dev".to_string()],
        save_dev: true,
        ..Default::default()
    };
    let summary_dev = installer.uninstall(&uninstall_dev).unwrap();
    assert_eq!(summary_dev.removed_packages, vec!["pkg-dev".to_string()]);

    let manifest1 = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest1.dev_dependencies.contains_key("pkg-dev"));
    assert!(manifest1.dependencies.contains_key("pkg-a"));
    assert!(manifest1.optional_dependencies.contains_key("pkg-opt"));

    // 2. Uninstall pkg-opt with --save-optional
    let uninstall_opt = UninstallOptions {
        packages: vec!["pkg-opt".to_string()],
        save_optional: true,
        ..Default::default()
    };
    let summary_opt = installer.uninstall(&uninstall_opt).unwrap();
    assert_eq!(summary_opt.removed_packages, vec!["pkg-opt".to_string()]);

    let manifest2 = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!manifest2.optional_dependencies.contains_key("pkg-opt"));
    assert!(manifest2.dependencies.contains_key("pkg-a"));

    // 3. Trying to remove pkg-a with --save-dev should NOT remove it because it is in prod
    let uninstall_wrong_flag = UninstallOptions {
        packages: vec!["pkg-a".to_string()],
        save_dev: true,
        ..Default::default()
    };
    let summary_noop = installer.uninstall(&uninstall_wrong_flag).unwrap();
    assert!(summary_noop.removed_packages.is_empty());

    let manifest3 = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(manifest3.dependencies.contains_key("pkg-a"));
}

#[test]
fn test_uninstall_preserves_shared_dependency() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("shared-test".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("pkg-b".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("shared-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }

    let mut pkg_a = LockfilePackage::default();
    let mut a_deps = BTreeMap::new();
    a_deps.insert("shared-lib".to_string(), "^1.0.0".to_string());
    pkg_a.dependencies = Some(a_deps);
    lockfile.insert_package("node_modules/pkg-a", pkg_a);

    let mut pkg_b = LockfilePackage::default();
    let mut b_deps = BTreeMap::new();
    b_deps.insert("shared-lib".to_string(), "^1.0.0".to_string());
    pkg_b.dependencies = Some(b_deps);
    lockfile.insert_package("node_modules/pkg-b", pkg_b);

    let shared_lib = LockfilePackage {
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/shared-lib", shared_lib);
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    let nm = project_dir.join("node_modules");
    fs::create_dir_all(nm.join("pkg-a")).unwrap();
    fs::create_dir_all(nm.join("pkg-b")).unwrap();
    fs::create_dir_all(nm.join("shared-lib")).unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    // Uninstall pkg-a
    let summary = installer.uninstall(&UninstallOptions {
        packages: vec!["pkg-a".to_string()],
        ..Default::default()
    }).unwrap();

    assert_eq!(summary.removed_packages, vec!["pkg-a".to_string()]);
    // shared-lib must NOT be pruned because pkg-b still depends on it!
    assert!(!summary.pruned_dependencies.contains(&"node_modules/shared-lib".to_string()));

    let updated_lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(updated_lockfile.packages.contains_key("node_modules/shared-lib"));
    assert!(updated_lockfile.packages.contains_key("node_modules/pkg-b"));

    assert!(!nm.join("pkg-a").exists());
    assert!(nm.join("shared-lib").exists());
    assert!(nm.join("pkg-b").exists());
}

#[test]
fn test_uninstall_nested_conflict_dependency() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("nested-test".to_string());
    manifest.dependencies.insert("parent".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("nested-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }

    let mut parent = LockfilePackage::default();
    let mut p_deps = BTreeMap::new();
    p_deps.insert("conflict-child".to_string(), "^2.0.0".to_string());
    parent.dependencies = Some(p_deps);
    lockfile.insert_package("node_modules/parent", parent);

    let child = LockfilePackage {
        version: Some("2.0.0".to_string()),
        ..Default::default()
    };
    lockfile.insert_package("node_modules/parent/node_modules/conflict-child", child);
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    let nested_dir = project_dir.join("node_modules").join("parent").join("node_modules").join("conflict-child");
    fs::create_dir_all(&nested_dir).unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    let summary = installer.uninstall(&UninstallOptions {
        packages: vec!["parent".to_string()],
        ..Default::default()
    }).unwrap();

    assert_eq!(summary.removed_packages, vec!["parent".to_string()]);
    assert!(summary.pruned_dependencies.contains(&"node_modules/parent/node_modules/conflict-child".to_string()));

    assert!(!project_dir.join("node_modules").join("parent").exists());
}

#[test]
fn test_uninstall_scoped_package_and_cleans_empty_scope_dir() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("scope-test".to_string());
    manifest.dependencies.insert("@my-scope/my-lib".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("scope-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package("node_modules/@my-scope/my-lib", LockfilePackage {
        version: Some("1.0.0".to_string()),
        ..Default::default()
    });
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    let scope_pkg_dir = project_dir.join("node_modules").join("@my-scope").join("my-lib");
    fs::create_dir_all(&scope_pkg_dir).unwrap();
    fs::write(scope_pkg_dir.join("index.js"), "module.exports = {};").unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    installer.uninstall(&UninstallOptions {
        packages: vec!["@my-scope/my-lib".to_string()],
        ..Default::default()
    }).unwrap();

    // Verify package is gone AND the empty @my-scope directory is cleanly removed
    assert!(!scope_pkg_dir.exists());
    assert!(!project_dir.join("node_modules").join("@my-scope").exists());
}

#[test]
fn test_uninstall_package_with_bin_shims() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("shim-test".to_string());
    manifest.dependencies.insert("tool-pkg".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("shim-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package("node_modules/tool-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        bin: Some(rnpm_lockfile::PackageBin::Single("./bin/run.js".to_string())),
        ..Default::default()
    });
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    // Setup node_modules/tool-pkg and its manifest declaring bin
    let tool_dir = project_dir.join("node_modules").join("tool-pkg");
    fs::create_dir_all(&tool_dir).unwrap();
    let mut tool_manifest = Manifest::default();
    tool_manifest.name = Some("tool-pkg".to_string());
    tool_manifest.bin = Some(PackageBin::Single("./bin/run.js".to_string()));
    tool_manifest.save_to_file(tool_dir.join("package.json")).unwrap();

    // Setup .bin shims
    let bin_dir = project_dir.join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("tool-pkg"), "#!/usr/bin/env sh").unwrap();
    #[cfg(windows)]
    {
        fs::write(bin_dir.join("tool-pkg.cmd"), "@ECHO off").unwrap();
        fs::write(bin_dir.join("tool-pkg.ps1"), "# powershell shim").unwrap();
    }

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    installer.uninstall(&UninstallOptions {
        packages: vec!["tool-pkg".to_string()],
        ..Default::default()
    }).unwrap();

    // Shims and empty .bin must be gone
    assert!(!bin_dir.join("tool-pkg").exists());
    #[cfg(windows)]
    {
        assert!(!bin_dir.join("tool-pkg.cmd").exists());
        assert!(!bin_dir.join("tool-pkg.ps1").exists());
    }
    assert!(!bin_dir.exists(), "Empty .bin directory should be cleaned up");
    assert!(!tool_dir.exists());
}

#[test]
fn test_uninstall_junction_safety() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("project");
    let external_dir = tmp.path().join("external-repo");
    fs::create_dir_all(&project_dir).unwrap();
    fs::create_dir_all(&external_dir).unwrap();

    // Place precious target files in external repo
    let precious_file = external_dir.join("precious_code.js");
    fs::write(&precious_file, "console.log('valuable code');").unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("junction-test".to_string());
    manifest.dependencies.insert("linked-pkg".to_string(), "file:../external-repo".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut lockfile = LockfileV3::new("junction-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package("node_modules/linked-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        link: Some(true),
        ..Default::default()
    });
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    // Create directory junction/symlink in node_modules pointing to external_dir
    let nm = project_dir.join("node_modules");
    fs::create_dir_all(&nm).unwrap();
    let link_path = nm.join("linked-pkg");
    create_junction(&link_path, &external_dir).unwrap();
    assert!(is_junction(&link_path).unwrap());

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        ..Default::default()
    }).unwrap();

    installer.uninstall(&UninstallOptions {
        packages: vec!["linked-pkg".to_string()],
        ..Default::default()
    }).unwrap();

    // Junction in node_modules is deleted
    assert!(!link_path.exists());

    // CRITICAL SECURITY PROPERTY: Target external directory AND its contents MUST BE PRESERVED!
    assert!(external_dir.exists(), "External target directory must not be deleted");
    assert!(precious_file.exists(), "External files must not be deleted when removing junction");
    assert_eq!(fs::read_to_string(&precious_file).unwrap(), "console.log('valuable code');");
}

#[test]
fn test_uninstall_security_rejects_path_traversal() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("security-test".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    let dangerous_inputs = vec![
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/absolute/path",
        "nested/../../pkg",
    ];

    for dangerous in dangerous_inputs {
        let res = installer.uninstall(&UninstallOptions {
            packages: vec![dangerous.to_string()],
            ..Default::default()
        });
        assert!(res.is_err(), "Must reject path traversal input: {dangerous}");
    }
}

#[test]
fn test_uninstall_deterministic_serialization_preserves_formatting() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_fixture_project(project_dir);

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    }).unwrap();

    installer.uninstall(&UninstallOptions {
        packages: vec!["pkg-a".to_string()],
        ..Default::default()
    }).unwrap();

    // Verify package-lock.json ends with newline and is valid deterministic JSON
    let lockfile_content = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(lockfile_content.ends_with('\n'), "package-lock.json must end with newline");
    let parsed_lock: LockfileV3 = serde_json::from_str(&lockfile_content).unwrap();
    assert_eq!(parsed_lock.lockfile_version, 3);

    // Verify package.json ends with newline
    let manifest_content = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(manifest_content.ends_with('\n'), "package.json must end with newline");
    let parsed_manifest: Manifest = serde_json::from_str(&manifest_content).unwrap();
    assert_eq!(parsed_manifest.name.as_deref(), Some("test-app"));
}


    fn make_tarball(pkg_name: &str, version: &str, deps: &[(&str, &str)]) -> Vec<u8> {
        let mut dep_map = serde_json::Map::new();
        for (d_name, d_range) in deps {
            dep_map.insert(d_name.to_string(), serde_json::Value::String(d_range.to_string()));
        }

        let manifest_json = serde_json::json!({
            "name": pkg_name,
            "version": version,
            "dependencies": dep_map
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest_json).unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gz);
            let mut header = Header::new_gnu();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            let path = "package/package.json";
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, Cursor::new(manifest_bytes)).unwrap();
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[tokio::test]
    async fn test_update_all_dependencies_and_superseded_cleanup() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        // Tarballs
        let pkg_a_100_tar = make_tarball("pkg-a", "1.0.0", &[("trans-old", "^1.0.0")]);
        let pkg_a_110_tar = make_tarball("pkg-a", "1.1.0", &[("trans-new", "^1.0.0")]);
        let trans_old_tar = make_tarball("trans-old", "1.0.0", &[]);
        let trans_new_tar = make_tarball("trans-new", "1.0.0", &[]);

        let a_100_int = Integrity::from_bytes(&pkg_a_100_tar, Algorithm::Sha512).to_string();
        let a_110_int = Integrity::from_bytes(&pkg_a_110_tar, Algorithm::Sha512).to_string();
        let old_int = Integrity::from_bytes(&trans_old_tar, Algorithm::Sha512).to_string();
        let new_int = Integrity::from_bytes(&trans_new_tar, Algorithm::Sha512).to_string();

        let a_100_tar_c = pkg_a_100_tar.clone();
        let a_110_tar_c = pkg_a_110_tar.clone();
        let trans_old_tar_c = trans_old_tar.clone();
        let trans_new_tar_c = trans_new_tar.clone();

        let a_100_int_c = a_100_int.clone();
        let a_110_int_c = a_110_int.clone();
        let old_int_c = old_int.clone();
        let new_int_c = new_int.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{local_addr}/");
        let su1 = server_url.clone();
        let su2 = server_url.clone();
        let su3 = server_url.clone();
        let su4 = server_url.clone();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let a_100_int_c = a_100_int_c.clone();
                            let a_110_int_c = a_110_int_c.clone();
                            let old_int_c = old_int_c.clone();
                            let new_int_c = new_int_c.clone();
                            let a_100_tar_c = a_100_tar_c.clone();
                            let a_110_tar_c = a_110_tar_c.clone();
                            let trans_old_tar_c = trans_old_tar_c.clone();
                            let trans_new_tar_c = trans_new_tar_c.clone();
                            let su1 = su1.clone();
                            let su2 = su2.clone();
                            let su3 = su3.clone();
                            let su4 = su4.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /pkg-a") {
                                        let json = serde_json::json!({
                                            "name": "pkg-a",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "pkg-a",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su1}tarballs/pkg-a-1.0.0.tgz"),
                                                        "integrity": a_100_int_c
                                                    },
                                                    "dependencies": { "trans-old": "^1.0.0" }
                                                },
                                                "1.1.0": {
                                                    "name": "pkg-a",
                                                    "version": "1.1.0",
                                                    "dist": {
                                                        "tarball": format!("{su2}tarballs/pkg-a-1.1.0.tgz"),
                                                        "integrity": a_110_int_c
                                                    },
                                                    "dependencies": { "trans-new": "^1.0.0" }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /trans-old") {
                                        let json = serde_json::json!({
                                            "name": "trans-old",
                                            "dist-tags": { "latest": "1.0.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "trans-old",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su3}tarballs/trans-old-1.0.0.tgz"),
                                                        "integrity": old_int_c
                                                    }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /trans-new") {
                                        let json = serde_json::json!({
                                            "name": "trans-new",
                                            "dist-tags": { "latest": "1.0.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "trans-new",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su4}tarballs/trans-new-1.0.0.tgz"),
                                                        "integrity": new_int_c
                                                    }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/pkg-a-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_100_tar_c)
                                    } else if req_str.contains("GET /tarballs/pkg-a-1.1.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_110_tar_c)
                                    } else if req_str.contains("GET /tarballs/trans-old-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], trans_old_tar_c)
                                    } else if req_str.contains("GET /tarballs/trans-new-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], trans_new_tar_c)
                                    } else {
                                        (404, vec![], b"Not Found".to_vec())
                                    };

                                    let status_text = if status == 200 { "OK" } else { "Not Found" };
                                    let mut response = format!(
                                        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                        body.len()
                                    );
                                    for (k, v) in headers {
                                        response.push_str(&format!("{k}: {v}\r\n"));
                                    }
                                    response.push_str("\r\n");
                                    let _ = stream.write_all(response.as_bytes()).await;
                                    let _ = stream.write_all(&body).await;
                                    let _ = stream.flush().await;
                                }
                            });
                        }
                    }
                }
            }
        });

        // 1. Initial state: package.json has "pkg-a": "^1.0.0"
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0"
            }
        }"#).unwrap();

        // Initial lockfile pinned to 1.0.0 and trans-old
        let mut initial_lock = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        if let Some(root) = initial_lock.root_package_mut() {
            let mut d = BTreeMap::new();
            d.insert("pkg-a".to_string(), "^1.0.0".to_string());
            root.dependencies = Some(d);
        }
        let mut a_entry = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-a-1.0.0.tgz")),
            integrity: Some(a_100_int.clone()),
            ..Default::default()
        };
        let mut a_deps = BTreeMap::new();
        a_deps.insert("trans-old".to_string(), "^1.0.0".to_string());
        a_entry.dependencies = Some(a_deps);
        initial_lock.insert_package("node_modules/pkg-a", a_entry);

        let old_entry = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/trans-old-1.0.0.tgz")),
            integrity: Some(old_int.clone()),
            ..Default::default()
        };
        initial_lock.insert_package("node_modules/trans-old", old_entry);

        let lock_path = project_dir.path().join("package-lock.json");
        initial_lock.save_to_file(&lock_path).unwrap();

        // Dummy initial node_modules/trans-old on disk
        let old_dir = project_dir.path().join("node_modules/trans-old");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("package.json"), "{}").unwrap();

        // 2. Run update (all dependencies)
        let options = InstallOptions {
            project_dir: project_dir.path().to_path_buf(),
            registry_url: Some(server_url.clone()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            offline: false,
            ignore_scripts: true,
            ..Default::default()
        };

        let mut installer = Installer::new(options).unwrap();
        let summary = installer.update(&[]).await.unwrap();

        assert_eq!(summary.packages_updated, 1);
        assert_eq!(summary.updated_packages, vec!["pkg-a"]);
        assert_eq!(summary.old_versions.get("pkg-a"), Some(&"1.0.0".to_string()));
        assert_eq!(summary.new_versions.get("pkg-a"), Some(&"1.1.0".to_string()));

        // Verify lockfile rewritten deterministically
        let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
        let updated_a = updated_lock.get_package("node_modules/pkg-a").unwrap();
        assert_eq!(updated_a.version, Some("1.1.0".to_string()));

        // Verify newly needed dependency trans-new is present in lockfile and node_modules
        assert!(updated_lock.get_package("node_modules/trans-new").is_some());
        assert!(project_dir.path().join("node_modules/trans-new/package.json").exists());

        // Verify superseded orphaned dependency trans-old is removed from lockfile and node_modules
        assert!(updated_lock.get_package("node_modules/trans-old").is_none());
        assert!(!project_dir.path().join("node_modules/trans-old").exists());

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn test_update_specific_package_filter() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        let pkg_a_tar = make_tarball("pkg-a", "1.1.0", &[]);
        let pkg_b_tar = make_tarball("pkg-b", "1.1.0", &[]);
        let a_int = Integrity::from_bytes(&pkg_a_tar, Algorithm::Sha512).to_string();
        let b_int = Integrity::from_bytes(&pkg_b_tar, Algorithm::Sha512).to_string();

        let a_tar_c = pkg_a_tar.clone();
        let b_tar_c = pkg_b_tar.clone();
        let a_int_c = a_int.clone();
        let b_int_c = b_int.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{local_addr}/");
        let su1 = server_url.clone();
        let su2 = server_url.clone();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let a_int_c = a_int_c.clone();
                            let b_int_c = b_int_c.clone();
                            let a_tar_c = a_tar_c.clone();
                            let b_tar_c = b_tar_c.clone();
                            let su1 = su1.clone();
                            let su2 = su2.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /pkg-a") {
                                        let json = serde_json::json!({
                                            "name": "pkg-a",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": { "name": "pkg-a", "version": "1.0.0", "dist": { "tarball": format!("{su1}tarballs/pkg-a.tgz"), "integrity": a_int_c } },
                                                "1.1.0": { "name": "pkg-a", "version": "1.1.0", "dist": { "tarball": format!("{su1}tarballs/pkg-a.tgz"), "integrity": a_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /pkg-b") {
                                        let json = serde_json::json!({
                                            "name": "pkg-b",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": { "name": "pkg-b", "version": "1.0.0", "dist": { "tarball": format!("{su2}tarballs/pkg-b.tgz"), "integrity": b_int_c } },
                                                "1.1.0": { "name": "pkg-b", "version": "1.1.0", "dist": { "tarball": format!("{su2}tarballs/pkg-b.tgz"), "integrity": b_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/pkg-a.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_tar_c)
                                    } else if req_str.contains("GET /tarballs/pkg-b.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], b_tar_c)
                                    } else {
                                        (404, vec![], b"Not Found".to_vec())
                                    };

                                    let status_text = if status == 200 { "OK" } else { "Not Found" };
                                    let mut response = format!(
                                        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                        body.len()
                                    );
                                    for (k, v) in headers {
                                        response.push_str(&format!("{k}: {v}\r\n"));
                                    }
                                    response.push_str("\r\n");
                                    let _ = stream.write_all(response.as_bytes()).await;
                                    let _ = stream.write_all(&body).await;
                                    let _ = stream.flush().await;
                                }
                            });
                        }
                    }
                }
            }
        });

        // package.json defines pkg-a and pkg-b
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "test-multi",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0",
                "pkg-b": "^1.0.0"
            }
        }"#).unwrap();

        // Lockfile has both at 1.0.0
        let mut lock = LockfileV3::new("test-multi", Some("1.0.0".to_string()));
        let mut d = BTreeMap::new();
        d.insert("pkg-a".to_string(), "^1.0.0".to_string());
        d.insert("pkg-b".to_string(), "^1.0.0".to_string());
        lock.root_package_mut().unwrap().dependencies = Some(d);

        lock.insert_package("node_modules/pkg-a", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-a.tgz")),
            integrity: Some(a_int),
            ..Default::default()
        });
        lock.insert_package("node_modules/pkg-b", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-b.tgz")),
            integrity: Some(b_int),
            ..Default::default()
        });
        let lock_path = project_dir.path().join("package-lock.json");
        lock.save_to_file(&lock_path).unwrap();

        let options = InstallOptions {
            project_dir: project_dir.path().to_path_buf(),
            registry_url: Some(server_url.clone()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            offline: false,
            ignore_scripts: true,
            ..Default::default()
        };

        let mut installer = Installer::new(options).unwrap();
        // Update ONLY pkg-a
        let summary = installer.update(&["pkg-a".to_string()]).await.unwrap();

        assert_eq!(summary.packages_updated, 1);
        assert_eq!(summary.updated_packages, vec!["pkg-a"]);

        let reloaded = LockfileV3::load_from_file(&lock_path).unwrap();
        assert_eq!(reloaded.get_package("node_modules/pkg-a").unwrap().version, Some("1.1.0".to_string()));
        // pkg-b remains at 1.0.0!
        assert_eq!(reloaded.get_package("node_modules/pkg-b").unwrap().version, Some("1.0.0".to_string()));

        let _ = tx.send(());
    }


#[tokio::test]
async fn test_workspace_installation_linking_and_lockfile() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    // 1. Root package.json
    let root_json = r#"{
        "name": "my-workspace-monorepo",
        "version": "1.0.0",
        "private": true,
        "workspaces": [
            "packages/*"
        ]
    }"#;
    fs::write(root.join("package.json"), root_json).unwrap();

    // 2. Member A: @mono/lib-a
    let lib_a_dir = root.join("packages").join("lib-a");
    fs::create_dir_all(&lib_a_dir).unwrap();
    let lib_a_json = r#"{
        "name": "@mono/lib-a",
        "version": "1.2.0",
        "bin": {
            "lib-a-tool": "./bin/tool.js"
        }
    }"#;
    fs::write(lib_a_dir.join("package.json"), lib_a_json).unwrap();
    fs::create_dir_all(lib_a_dir.join("bin")).unwrap();
    fs::write(
        lib_a_dir.join("bin").join("tool.js"),
        "#!/usr/bin/env node\nconsole.log('lib-a tool');\n",
    ).unwrap();
    fs::write(
        lib_a_dir.join("index.js"),
        "module.exports = { name: 'lib-a' };\n",
    ).unwrap();

    // 3. Member B: @mono/lib-b depends on @mono/lib-a via workspace:*
    let lib_b_dir = root.join("packages").join("lib-b");
    fs::create_dir_all(&lib_b_dir).unwrap();
    let lib_b_json = r#"{
        "name": "@mono/lib-b",
        "version": "2.0.0",
        "dependencies": {
            "@mono/lib-a": "workspace:*"
        }
    }"#;
    fs::write(lib_b_dir.join("package.json"), lib_b_json).unwrap();
    fs::write(
        lib_b_dir.join("index.js"),
        "const a = require('@mono/lib-a'); module.exports = { a };\n",
    ).unwrap();

    // 4. Member C: app depends on @mono/lib-b via workspace:^ and @mono/lib-a via workspace:~
    let app_dir = root.join("packages").join("app");
    fs::create_dir_all(&app_dir).unwrap();
    let app_json = r#"{
        "name": "my-app",
        "version": "0.1.0",
        "dependencies": {
            "@mono/lib-b": "workspace:^",
            "@mono/lib-a": "workspace:~"
        },
        "bin": {
            "run-app": "./app.js"
        }
    }"#;
    fs::write(app_dir.join("package.json"), app_json).unwrap();
    fs::write(
        app_dir.join("app.js"),
        "#!/usr/bin/env node\nconsole.log('app running');\n",
    ).unwrap();

    // 5. Run Installer
    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();

    // 3 workspace members installed/linked
    assert_eq!(summary.packages_installed, 3);

    // Verify junctions / symlinks exist in root node_modules
    let node_modules = root.join("node_modules");
    let link_a = node_modules.join("@mono").join("lib-a");
    let link_b = node_modules.join("@mono").join("lib-b");
    let link_app = node_modules.join("my-app");

    assert!(link_a.exists(), "Link for @mono/lib-a must exist");
    assert!(link_b.exists(), "Link for @mono/lib-b must exist");
    assert!(link_app.exists(), "Link for my-app must exist");

    assert!(is_junction(&link_a).unwrap(), "Link for @mono/lib-a must be a junction or symlink");
    assert!(is_junction(&link_b).unwrap(), "Link for @mono/lib-b must be a junction or symlink");
    assert!(is_junction(&link_app).unwrap(), "Link for my-app must be a junction or symlink");

    // Test live linking: reading through junction reads target content
    let linked_a_pkg = fs::read_to_string(link_a.join("package.json")).unwrap();
    assert!(linked_a_pkg.contains("@mono/lib-a"));

    // Mutate source file and verify junction immediately sees it without reinstall
    fs::write(lib_a_dir.join("test-sync.txt"), "sync test").unwrap();
    assert!(link_a.join("test-sync.txt").exists(), "Junction must reflect changes immediately");

    // Verify companion shims in node_modules/.bin
    let bin_dir = node_modules.join(".bin");
    #[cfg(windows)]
    {
        assert!(bin_dir.join("lib-a-tool.cmd").exists());
        assert!(bin_dir.join("lib-a-tool.ps1").exists());
        assert!(bin_dir.join("run-app.cmd").exists());
        assert!(bin_dir.join("run-app.ps1").exists());
    }
    #[cfg(not(windows))]
    {
        assert!(bin_dir.join("lib-a-tool").exists());
        assert!(bin_dir.join("run-app").exists());
    }

    // Verify package-lock.json
    let lockfile_path = root.join("package-lock.json");
    assert!(lockfile_path.exists());
    let lockfile = LockfileV3::load_from_file(&lockfile_path).unwrap();

    // Root package contains workspaces
    let root_pkg = lockfile.packages.get("").unwrap();
    assert_eq!(root_pkg.workspaces, Some(vec!["packages/*".to_string()]));

    // Check link entries in lockfile
    let lock_link_a = lockfile.packages.get("node_modules/@mono/lib-a").unwrap();
    assert_eq!(lock_link_a.link, Some(true));
    assert_eq!(lock_link_a.resolved.as_deref(), Some("packages/lib-a"));

    let lock_link_b = lockfile.packages.get("node_modules/@mono/lib-b").unwrap();
    assert_eq!(lock_link_b.link, Some(true));
    assert_eq!(lock_link_b.resolved.as_deref(), Some("packages/lib-b"));

    let lock_link_app = lockfile.packages.get("node_modules/my-app").unwrap();
    assert_eq!(lock_link_app.link, Some(true));
    assert_eq!(lock_link_app.resolved.as_deref(), Some("packages/app"));

    // Check physical entries in lockfile
    let lock_pkg_a = lockfile.packages.get("packages/lib-a").unwrap();
    assert_eq!(lock_pkg_a.version.as_deref(), Some("1.2.0"));

    let lock_pkg_b = lockfile.packages.get("packages/lib-b").unwrap();
    assert_eq!(lock_pkg_b.version.as_deref(), Some("2.0.0"));

    // 6. Test CI installation (run_ci)
    // Remove node_modules completely (clean slate)
    let _ = rnpm_fs::remove_junction(&link_a);
    let _ = rnpm_fs::remove_junction(&link_b);
    let _ = rnpm_fs::remove_junction(&link_app);
    let _ = fs::remove_dir_all(&node_modules);
    assert!(!node_modules.exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 3);

    // Verify links restored in CI run
    assert!(link_a.exists());
    assert!(link_b.exists());
    assert!(link_app.exists());
    assert!(is_junction(&link_a).unwrap());
}

#[tokio::test]
async fn test_workspace_installation_detects_cycles() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let root_json = r#"{
        "name": "cyclic-monorepo",
        "workspaces": ["packages/*"]
    }"#;
    fs::write(root.join("package.json"), root_json).unwrap();

    let p1_dir = root.join("packages").join("pkg-1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(
        p1_dir.join("package.json"),
        r#"{"name": "pkg-1", "version": "1.0.0", "dependencies": {"pkg-2": "workspace:*"}}"#,
    ).unwrap();

    let p2_dir = root.join("packages").join("pkg-2");
    fs::create_dir_all(&p2_dir).unwrap();
    fs::write(
        p2_dir.join("package.json"),
        r#"{"name": "pkg-2", "version": "1.0.0", "dependencies": {"pkg-1": "workspace:*"}}"#,
    ).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Circular workspace dependency detected"),
        "Error message should clearly report circular dependency, got: {err_msg}"
    );
    assert!(err_msg.contains("pkg-1") && err_msg.contains("pkg-2"));
}

#[tokio::test]
async fn test_workspace_installation_missing_member_fails() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let root_json = r#"{
        "name": "missing-monorepo",
        "workspaces": ["packages/*"]
    }"#;
    fs::write(root.join("package.json"), root_json).unwrap();

    let p1_dir = root.join("packages").join("pkg-1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(
        p1_dir.join("package.json"),
        r#"{"name": "pkg-1", "version": "1.0.0", "dependencies": {"missing-pkg": "workspace:*"}}"#,
    ).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_msg = err.to_string();
    assert!(err_msg.contains("missing-pkg"), "Should report missing package: {err_msg}");
}

#[tokio::test]
async fn test_workspace_junction_security_content_preserved() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let target_dir = root.join("source-pkg");
    fs::create_dir_all(&target_dir).unwrap();
    let secret_file = target_dir.join("critical-data.txt");
    fs::write(&secret_file, "precious content").unwrap();

    let link_path = root.join("node_modules").join("linked-pkg");
    fs::create_dir_all(link_path.parent().unwrap()).unwrap();

    rnpm_fs::create_junction(&link_path, &target_dir).unwrap();
    assert!(link_path.exists());
    assert!(secret_file.exists());

    // Safely remove the junction
    rnpm_fs::remove_junction(&link_path).unwrap();
    assert!(!link_path.exists(), "Junction reparse point must be removed");
    assert!(secret_file.exists(), "Target file must NEVER be deleted when removing junction!");
    assert_eq!(fs::read_to_string(&secret_file).unwrap(), "precious content");
}

#[tokio::test]
async fn test_targeted_update_preserves_satisfying_and_unrelated_dependencies() {
    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let pkg_a_110_tar = make_tarball("pkg-a", "1.1.0", &[("dep-shared", "^1.0.0")]);
    let a_110_int = Integrity::from_bytes(&pkg_a_110_tar, Algorithm::Sha512).to_string();
    let a_110_tar_c = pkg_a_110_tar.clone();
    let a_110_int_c = a_110_int.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let server_url = format!("http://{local_addr}/");
    let su = server_url.clone();

    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accept_res = listener.accept() => {
                    if let Ok((mut stream, _)) = accept_res {
                        let a_110_int_c = a_110_int_c.clone();
                        let a_110_tar_c = a_110_tar_c.clone();
                        let su = su.clone();

                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 4096];
                            let n = stream.read(&mut buf).await.unwrap_or(0);
                            if n > 0 {
                                let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                let (status, headers, body) = if req_str.contains("GET /pkg-a") {
                                    let json = serde_json::json!({
                                        "name": "pkg-a",
                                        "dist-tags": { "latest": "1.1.0" },
                                        "versions": {
                                            "1.0.0": {
                                                "name": "pkg-a",
                                                "version": "1.0.0",
                                                "dist": { "tarball": format!("{su}tarballs/pkg-a-1.0.0.tgz"), "integrity": "sha512-old" },
                                                "dependencies": { "dep-shared": "^1.0.0" }
                                            },
                                            "1.1.0": {
                                                "name": "pkg-a",
                                                "version": "1.1.0",
                                                "dist": { "tarball": format!("{su}tarballs/pkg-a-1.1.0.tgz"), "integrity": a_110_int_c },
                                                "dependencies": { "dep-shared": "^1.0.0" }
                                            }
                                        }
                                    });
                                    (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                } else if req_str.contains("GET /tarballs/pkg-a-1.1.0.tgz") {
                                    (200, vec![("Content-Type", String::from("application/octet-stream"))], a_110_tar_c)
                                } else if req_str.contains("GET /dep-shared") {
                                    // Should NOT be called because dep-shared 1.0.0 is already locked and satisfies ^1.0.0!
                                    let json = serde_json::json!({
                                        "name": "dep-shared",
                                        "dist-tags": { "latest": "1.9.9" },
                                        "versions": {
                                            "1.9.9": {
                                                "name": "dep-shared",
                                                "version": "1.9.9",
                                                "dist": { "tarball": format!("{su}tarballs/dep-shared-1.9.9.tgz"), "integrity": "sha512-new" }
                                            }
                                        }
                                    });
                                    (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                } else {
                                    (404, vec![], b"Not Found".to_vec())
                                };

                                let status_text = if status == 200 { "OK" } else { "Not Found" };
                                let mut response = format!(
                                    "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                    body.len()
                                );
                                for (k, v) in headers {
                                    response.push_str(&format!("{k}: {v}\r\n"));
                                }
                                response.push_str("\r\n");
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                let _ = stream.flush().await;
                            }
                        });
                    }
                }
            }
        }
    });

    let pkg_json = project_dir.path().join("package.json");
    std::fs::write(&pkg_json, r#"{
        "name": "targeted-test",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": "^1.0.0",
            "pkg-b": "^1.0.0"
        }
    }"#).unwrap();

    let mut lock = LockfileV3::new("targeted-test", Some("1.0.0".to_string()));
    let mut d = BTreeMap::new();
    d.insert("pkg-a".to_string(), "^1.0.0".to_string());
    d.insert("pkg-b".to_string(), "^1.0.0".to_string());
    lock.root_package_mut().unwrap().dependencies = Some(d);

    let mut a_entry = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some(format!("{server_url}tarballs/pkg-a-1.0.0.tgz")),
        integrity: Some("sha512-old".to_string()),
        ..Default::default()
    };
    let mut a_deps = BTreeMap::new();
    a_deps.insert("dep-shared".to_string(), "^1.0.0".to_string());
    a_entry.dependencies = Some(a_deps);
    lock.insert_package("node_modules/pkg-a", a_entry);

    let b_entry = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some(format!("{server_url}tarballs/pkg-b-1.0.0.tgz")),
        integrity: Some("sha512-pkg-b".to_string()),
        ..Default::default()
    };
    lock.insert_package("node_modules/pkg-b", b_entry);

    let shared_entry = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some(format!("{server_url}tarballs/dep-shared-1.0.0.tgz")),
        integrity: Some("sha512-shared".to_string()),
        ..Default::default()
    };
    lock.insert_package("node_modules/dep-shared", shared_entry);

    let lock_path = project_dir.path().join("package-lock.json");
    lock.save_to_file(&lock_path).unwrap();

    let nm = project_dir.path().join("node_modules");
    fs::create_dir_all(nm.join("pkg-b")).unwrap();
    fs::write(nm.join("pkg-b/package.json"), "{}").unwrap();
    fs::create_dir_all(nm.join("dep-shared")).unwrap();
    fs::write(nm.join("dep-shared/package.json"), "{}").unwrap();

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        registry_url: Some(server_url.clone()),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        offline: false,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    // Targeted update for ONLY pkg-a
    let summary = installer.update(&["pkg-a".to_string()]).await.unwrap();

    assert_eq!(summary.packages_updated, 1);
    assert_eq!(summary.updated_packages, vec!["pkg-a"]);

    let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
    // pkg-a updated to 1.1.0
    assert_eq!(updated_lock.get_package("node_modules/pkg-a").unwrap().version, Some("1.1.0".to_string()));
    // pkg-b is completely UNTOUCHED at 1.0.0
    assert_eq!(updated_lock.get_package("node_modules/pkg-b").unwrap().version, Some("1.0.0".to_string()));
    // dep-shared satisfies ^1.0.0 so it is RETAINED at 1.0.0 without modification
    assert_eq!(updated_lock.get_package("node_modules/dep-shared").unwrap().version, Some("1.0.0".to_string()));

    let _ = tx.send(());
}

#[tokio::test]
async fn test_install_reification_path_containment_and_illegal_package_names() {
    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let illegal_names = [
        "../escaped-pkg",
        "../../root-escape",
        "foo/../../bar",
        "win\\slash\\escape",
        "ads:stream",
        "null\0byte",
    ];

    for bad_name in illegal_names {
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, format!(r#"{{"name": "test-sec", "dependencies": {{"{bad_name}": "1.0.0"}}}}"#)).unwrap();

        let options = InstallOptions {
            project_dir: project_dir.path().to_path_buf(),
            registry_url: Some("https://registry.npmjs.org/".to_string()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            offline: true,
            ignore_scripts: true,
            ..Default::default()
        };

        let mut installer = Installer::new(options).unwrap();
        let res = installer.run().await;
        assert!(res.is_err(), "Expected error for illegal package name '{bad_name}', but succeeded");
    }
}

#[tokio::test]
async fn test_file_directory_dependency_installation_and_ci() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create a local package in ../packages/local-pkg
    let local_pkg_dir = root.join("packages").join("local-pkg");
    fs::create_dir_all(&local_pkg_dir).unwrap();
    let local_manifest = serde_json::json!({
        "name": "local-pkg",
        "version": "2.5.0",
        "bin": {
            "local-cmd": "./bin/run.js"
        }
    });
    fs::write(local_pkg_dir.join("package.json"), serde_json::to_string_pretty(&local_manifest).unwrap()).unwrap();
    fs::create_dir_all(local_pkg_dir.join("bin")).unwrap();
    fs::write(local_pkg_dir.join("bin").join("run.js"), "#!/usr/bin/env node\nconsole.log('hello');\n").unwrap();

    // 2. Create the main app project depending on "file:../packages/local-pkg"
    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();
    let app_manifest = serde_json::json!({
        "name": "app",
        "version": "1.0.0",
        "dependencies": {
            "local-pkg": "file:../packages/local-pkg"
        }
    });
    fs::write(app_dir.join("package.json"), serde_json::to_string_pretty(&app_manifest).unwrap()).unwrap();

    let options = InstallOptions {
        project_dir: app_dir.clone(),
        offline: true,
        ..Default::default()
    };

    // 3. Run install
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // 4. Verify junction / link in node_modules
    let link_path = app_dir.join("node_modules").join("local-pkg");
    assert!(link_path.exists());
    assert!(is_junction(&link_path).unwrap());
    let installed_json = fs::read_to_string(link_path.join("package.json")).unwrap();
    assert!(installed_json.contains("\"version\": \"2.5.0\""));

    // Verify bin shim
    #[cfg(windows)]
    assert!(app_dir.join("node_modules").join(".bin").join("local-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(app_dir.join("node_modules").join(".bin").join("local-cmd").exists());

    // 5. Verify package-lock.json
    let lockfile = LockfileV3::load_from_file(&app_dir.join("package-lock.json")).unwrap();
    let lock_link = lockfile.packages.get("node_modules/local-pkg").expect("Lockfile must contain node_modules/local-pkg");
    assert_eq!(lock_link.link, Some(true));
    assert_eq!(lock_link.resolved.as_deref(), Some("../packages/local-pkg"));

    let lock_target = lockfile.packages.get("../packages/local-pkg").expect("Lockfile must contain physical package info");
    assert_eq!(lock_target.version.as_deref(), Some("2.5.0"));

    // 6. Test CI installation (run_ci)
    let _ = rnpm_fs::remove_junction(&link_path);
    let _ = fs::remove_dir_all(app_dir.join("node_modules"));
    assert!(!app_dir.join("node_modules").exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);
    assert!(link_path.exists());
    assert!(is_junction(&link_path).unwrap());
}

#[tokio::test]
async fn test_file_archive_dependency_installation_and_ci() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create a tarball fixture for "archive-lib" version 3.0.0
    let tarball_bytes = {
        let manifest_json = serde_json::json!({
            "name": "archive-lib",
            "version": "3.0.0",
            "description": "packed tarball dependency"
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest_json).unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gz);
            let mut header = Header::new_gnu();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            let path = "package/package.json";
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, Cursor::new(manifest_bytes)).unwrap();
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    };

    let pkgs_dir = root.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    let tarball_path = pkgs_dir.join("archive-lib-3.0.0.tgz");
    fs::write(&tarball_path, &tarball_bytes).unwrap();

    // 2. Create the main app project depending on "file:./pkgs/archive-lib-3.0.0.tgz"
    let app_manifest = serde_json::json!({
        "name": "archive-app",
        "version": "1.0.0",
        "dependencies": {
            "archive-lib": "file:./pkgs/archive-lib-3.0.0.tgz"
        }
    });
    fs::write(root.join("package.json"), serde_json::to_string_pretty(&app_manifest).unwrap()).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    // 3. Run install
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // 4. Verify extraction in node_modules
    let pkg_dir = root.join("node_modules").join("archive-lib");
    assert!(pkg_dir.exists());
    let pkg_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(pkg_dir.join("package.json")).unwrap()).unwrap();
    assert_eq!(pkg_json["name"], "archive-lib");
    assert_eq!(pkg_json["version"], "3.0.0");

    // 5. Verify package-lock.json
    let lockfile = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    let lock_pkg = lockfile.packages.get("node_modules/archive-lib").expect("Lockfile must contain node_modules/archive-lib");
    assert_eq!(lock_pkg.version.as_deref(), Some("3.0.0"));
    assert_eq!(lock_pkg.resolved.as_deref(), Some("file:./pkgs/archive-lib-3.0.0.tgz"));
    assert!(lock_pkg.integrity.as_ref().unwrap().starts_with("sha512-"));

    // 6. Test CI installation (run_ci)
    fs::remove_dir_all(root.join("node_modules")).unwrap();
    assert!(!root.join("node_modules").exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);
    assert!(pkg_dir.join("package.json").exists());
}

#[tokio::test]
async fn test_workspace_member_lifecycle_prepare_dev_deps_and_ci_topological_execution() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Root package.json with workspaces and root prepare hook
    let root_json = r#"{
        "name": "topo-workspace-root",
        "version": "1.0.0",
        "private": true,
        "workspaces": ["packages/*"],
        "scripts": {
            "prepare": "node -e \"require('fs').appendFileSync(require('path').join(process.env.INIT_CWD, 'order.log'), 'root:prepare' + String.fromCharCode(10))\""
        }
    }"#;
    fs::write(root.join("package.json"), root_json).unwrap();

    // Member A: defines "prepare" lifecycle script (must be discovered via has_scripts)
    let a_dir = root.join("packages").join("pkg-a");
    fs::create_dir_all(&a_dir).unwrap();
    let a_json = r#"{
        "name": "pkg-a",
        "version": "1.0.0",
        "scripts": {
            "prepare": "node -e \"require('fs').appendFileSync(require('path').join(process.env.INIT_CWD, 'order.log'), 'pkg-a:prepare' + String.fromCharCode(10))\""
        }
    }"#;
    fs::write(a_dir.join("package.json"), a_json).unwrap();

    // Member B: depends on pkg-a via devDependencies!
    // Must execute pkg-a BEFORE pkg-b
    let b_dir = root.join("packages").join("pkg-b");
    fs::create_dir_all(&b_dir).unwrap();
    let b_json = r#"{
        "name": "pkg-b",
        "version": "1.0.0",
        "devDependencies": {
            "pkg-a": "workspace:*"
        },
        "scripts": {
            "postinstall": "node -e \"require('fs').appendFileSync(require('path').join(process.env.INIT_CWD, 'order.log'), 'pkg-b:postinstall' + String.fromCharCode(10))\""
        }
    }"#;
    fs::write(b_dir.join("package.json"), b_json).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ignore_scripts: false,
        ..Default::default()
    };

    // 1. Test standard install (installer.run())
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 2);

    let order_file = root.join("order.log");
    assert!(order_file.exists(), "order.log must be created by lifecycle scripts");
    let content = fs::read_to_string(&order_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Verify topological order: pkg-a:prepare -> pkg-b:postinstall -> root:prepare
    assert_eq!(
        lines,
        vec!["pkg-a:prepare", "pkg-b:postinstall", "root:prepare"],
        "Expected pkg-a (prepare) before pkg-b (postinstall) before root (prepare), got: {content}"
    );

    // 2. Test CI install (installer.run_ci())
    fs::remove_file(&order_file).unwrap();
    let _ = rnpm_fs::remove_junction(&root.join("node_modules").join("pkg-a"));
    let _ = rnpm_fs::remove_junction(&root.join("node_modules").join("pkg-b"));
    fs::remove_dir_all(root.join("node_modules")).unwrap();
    assert!(!root.join("node_modules").exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 2);

    assert!(order_file.exists(), "order.log must be created during run_ci");
    let ci_content = fs::read_to_string(&order_file).unwrap();
    let ci_lines: Vec<&str> = ci_content.lines().collect();

    assert_eq!(
        ci_lines,
        vec!["pkg-a:prepare", "pkg-b:postinstall", "root:prepare"],
        "Expected CI topological order pkg-a:prepare -> pkg-b:postinstall -> root:prepare, got: {ci_content}"
    );
}

#[tokio::test]
async fn test_ci_drift_detection_dev_dependencies_mutated() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. Initial package.json with devDependencies
    let mut manifest = Manifest::default();
    manifest.name = Some("dev-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dev_dependencies.insert("dev-tool".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    // 2. Matching lockfile
    let mut lockfile = LockfileV3::new("dev-drift-app", Some("1.0.0".to_string()));
    let mut dev_deps = BTreeMap::new();
    dev_deps.insert("dev-tool".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dev_dependencies = Some(dev_deps);
    lockfile.insert_package("node_modules/dev-tool", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/dev-tool/-/dev-tool-1.0.0.tgz".to_string()),
        integrity: Some("sha512-validhash".to_string()),
        dev: Some(true),
        ..Default::default()
    });
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    // 3. Mutate devDependencies in package.json to ^2.0.0
    manifest.dev_dependencies.insert("dev-tool".to_string(), "^2.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_err(), "run_ci must fail when devDependencies mutated in package.json");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("ELOCKFILE_DRIFT"), "Error must contain ELOCKFILE_DRIFT: {err_msg}");
    assert!(err_msg.contains("EUSAGE"), "Error must contain EUSAGE: {err_msg}");
    assert!(err_msg.contains("dev-tool"), "Error must mention drifted package: {err_msg}");
}

#[tokio::test]
async fn test_ci_drift_detection_dependency_deleted_from_manifest() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. Lockfile has two dependencies: "dep-a" and "dep-b"
    let mut lockfile = LockfileV3::new("dep-drift-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("dep-a".to_string(), "^1.0.0".to_string());
    deps.insert("dep-b".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package("node_modules/dep-a", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/dep-a/-/dep-a-1.0.0.tgz".to_string()),
        integrity: Some("sha512-hasha".to_string()),
        ..Default::default()
    });
    lockfile.insert_package("node_modules/dep-b", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("https://registry.npmjs.org/dep-b/-/dep-b-1.0.0.tgz".to_string()),
        integrity: Some("sha512-hashb".to_string()),
        ..Default::default()
    });
    lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    // 2. package.json has "dep-b" deleted, only contains "dep-a"
    let mut manifest = Manifest::default();
    manifest.name = Some("dep-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("dep-a".to_string(), "^1.0.0".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_err(), "run_ci must fail when dependency deleted from package.json but present in lockfile");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("ELOCKFILE_DRIFT"), "Error must contain ELOCKFILE_DRIFT: {err_msg}");
    assert!(err_msg.contains("EUSAGE"), "Error must contain EUSAGE: {err_msg}");
    assert!(err_msg.contains("dep-b"), "Error must mention removed dependency: {err_msg}");
}

#[tokio::test]
async fn test_ci_migrates_v1_lockfile_and_detects_drift() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // package.json expecting dep-a ^1.0.0 and dep-b ^2.0.0
    let manifest_json = r#"{
        "name": "migrated-app",
        "version": "1.0.0",
        "dependencies": {
            "dep-a": "^1.0.0",
            "dep-b": "^2.0.0"
        }
    }"#;
    fs::write(project_dir.join("package.json"), manifest_json).unwrap();

    // package-lock.json v1 format only having dep-a
    let v1_lockfile = r#"{
        "name": "migrated-app",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "dep-a": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/dep-a/-/dep-a-1.0.0.tgz",
                "integrity": "sha512-placeholder"
            }
        }
    }"#;
    fs::write(project_dir.join("package-lock.json"), v1_lockfile).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_err(), "run_ci must detect missing dep-b after migrating v1 lockfile");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("ELOCKFILE_DRIFT"), "Must emit ELOCKFILE_DRIFT: {err_msg}");
    assert!(err_msg.contains("dep-b"), "Must mention dep-b: {err_msg}");
}

#[tokio::test]
async fn test_ci_junction_safe_node_modules_pruning() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let external_dir = tempdir().unwrap();
    let secret_file = external_dir.path().join("precious-data.txt");
    fs::write(&secret_file, "do not delete me!").unwrap();

    let manifest_json = r#"{
        "name": "junc-ci-app",
        "version": "1.0.0",
        "dependencies": {}
    }"#;
    fs::write(project_dir.join("package.json"), manifest_json).unwrap();

    let lockfile = r#"{
        "name": "junc-ci-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "junc-ci-app",
                "version": "1.0.0",
                "dependencies": {}
            }
        }
    }"#;
    fs::write(project_dir.join("package-lock.json"), lockfile).unwrap();

    // Create pre-existing node_modules containing a junction pointing to external directory
    let node_modules = project_dir.join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();
    let link_path = node_modules.join("external-link");
    rnpm_fs::create_junction(&link_path, external_dir.path()).unwrap();
    assert!(rnpm_fs::is_junction(&link_path).unwrap());

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    installer.run_ci().await.unwrap();

    // Crucial check: external target file was NOT deleted!
    assert!(secret_file.exists(), "External file must be preserved when run_ci cleans node_modules with junctions!");
}

#[tokio::test]
async fn test_ci_security_adversarial_file_path_traversal_rejected() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("sec-traversal-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("malicious-pkg".to_string(), "file:../../secret.tgz".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let valid_hash = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    let traversal_paths = vec![
        "file:../../secret.tgz",
        "file:./pkgs/../../secret.tgz",
        "file:/etc/shadow",
        "file:C:\\secret\\evil.tgz",
        "file:pkgs/evil\0byte.tgz",
    ];

    for bad_resolved in traversal_paths {
        let mut lockfile = LockfileV3::new("sec-traversal-app", Some("1.0.0".to_string()));
        let mut deps = BTreeMap::new();
        deps.insert("malicious-pkg".to_string(), bad_resolved.to_string());
        lockfile.root_package_mut().unwrap().dependencies = Some(deps);
        lockfile.insert_package("node_modules/malicious-pkg", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(bad_resolved.to_string()),
            integrity: Some(valid_hash.to_string()),
            ..Default::default()
        });
        lockfile.save_to_file(&project_dir.join("package-lock.json")).unwrap();

        let mut installer = Installer::new(InstallOptions {
            project_dir: project_dir.to_path_buf(),
            offline: true,
            ..Default::default()
        }).unwrap();

        let res = installer.run_ci().await;
        assert!(res.is_err(), "run_ci must reject adversarial file: traversal path '{bad_resolved}'");
    }
}

#[tokio::test]
async fn test_ci_transitive_package_integrity_verification() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // Create a valid tarball for child-pkg
    let child_tar = make_tarball("child-pkg", "1.0.0", &[]);
    let child_valid_integrity = Integrity::from_bytes(&child_tar, Algorithm::Sha512).to_string();

    let pkgs_dir = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    let child_tar_path = pkgs_dir.join("child-pkg-1.0.0.tgz");
    fs::write(&child_tar_path, &child_tar).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("integrity-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("parent-pkg".to_string(), "file:./pkgs/child-pkg-1.0.0.tgz".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    // 1. Missing or empty integrity on transitive dependency in lockfile
    let mut lock_missing_integrity = LockfileV3::new("integrity-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert("parent-pkg".to_string(), "file:./pkgs/child-pkg-1.0.0.tgz".to_string());
    lock_missing_integrity.root_package_mut().unwrap().dependencies = Some(deps);
    lock_missing_integrity.insert_package("node_modules/parent-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
        integrity: Some(child_valid_integrity.clone()),
        ..Default::default()
    });
    // Transitive package has empty integrity!
    lock_missing_integrity.insert_package("node_modules/child-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
        integrity: Some("   ".to_string()),
        ..Default::default()
    });
    lock_missing_integrity.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_err(), "run_ci must fail when transitive package has empty integrity");

    // 2. Mismatched integrity on transitive dependency
    let mut lock_tampered = LockfileV3::new("integrity-app", Some("1.0.0".to_string()));
    let mut deps2 = BTreeMap::new();
    deps2.insert("parent-pkg".to_string(), "file:./pkgs/child-pkg-1.0.0.tgz".to_string());
    lock_tampered.root_package_mut().unwrap().dependencies = Some(deps2);
    lock_tampered.insert_package("node_modules/parent-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
        integrity: Some(child_valid_integrity.clone()),
        ..Default::default()
    });
    // Tampered integrity!
    let tampered_integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    lock_tampered.insert_package("node_modules/child-pkg", LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
        integrity: Some(tampered_integrity.to_string()),
        ..Default::default()
    });
    lock_tampered.save_to_file(&project_dir.join("package-lock.json")).unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    }).unwrap();

    let res2 = installer2.run_ci().await;
    assert!(res2.is_err(), "run_ci must fail when transitive package integrity verification fails");
    let err_str = res2.unwrap_err().to_string();
    assert!(err_str.to_lowercase().contains("integrity"), "Error must mention integrity: {err_str}");
}

#[tokio::test]
async fn test_ci_and_install_persists_hidden_lockfile() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let tar_bytes = make_tarball("local-dep", "1.0.0", &[]);

    let pkgs = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs).unwrap();
    fs::write(pkgs.join("local-dep-1.0.0.tgz"), &tar_bytes).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("hidden-lock-test".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert("local-dep".to_string(), "file:./pkgs/local-dep-1.0.0.tgz".to_string());
    manifest.save_to_file(project_dir.join("package.json")).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    // 1. Run install
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // Verify hidden lockfile was created in node_modules/.package-lock.json
    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    assert!(hidden_path.exists(), "node_modules/.package-lock.json must exist after install");

    let loaded_hidden = LockfileV3::load_hidden(project_dir).unwrap();
    assert_eq!(loaded_hidden.name, "hidden-lock-test");
    assert!(loaded_hidden.packages.contains_key("node_modules/local-dep"));

    // 2. Remove node_modules and run CI
    fs::remove_dir_all(project_dir.join("node_modules")).unwrap();
    assert!(!hidden_path.exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);

    // Verify hidden lockfile was created after run_ci
    assert!(hidden_path.exists(), "node_modules/.package-lock.json must exist after run_ci");
    let loaded_ci_hidden = LockfileV3::load_hidden(project_dir).unwrap();
    assert_eq!(loaded_ci_hidden.name, "hidden-lock-test");
    assert!(loaded_ci_hidden.packages.contains_key("node_modules/local-dep"));
}

#[test]
fn test_apply_npmrc_to_client_config() {
    use crate::apply_npmrc_to_client_config;
    use rnpm_config::Npmrc;
    use rnpm_registry::client::RegistryClientConfig;
    use std::path::PathBuf;
    use std::time::Duration;

    let mut npmrc = Npmrc::new();
    npmrc.set("strict-ssl", "false").unwrap();
    npmrc.set("proxy", "http://proxy.local:8080").unwrap();
    npmrc.set("https-proxy", "https://proxy.local:8443").unwrap();
    npmrc.set("http-proxy", "http://proxy.local:8080").unwrap();
    npmrc.set("no-proxy", "localhost,127.0.0.1").unwrap();
    npmrc.set("ca", "dummy-ca-pem").unwrap();
    npmrc.set("cafile", "test/cafile.pem").unwrap();
    npmrc.set("cert", "test/client.crt").unwrap();
    npmrc.set("key", "test/client.key").unwrap();
    npmrc.set("fetch-timeout", "45000").unwrap();
    npmrc.set("connect-timeout", "12000").unwrap();

    let mut client_config = RegistryClientConfig::default();
    apply_npmrc_to_client_config(&mut client_config, &npmrc);

    assert!(!client_config.strict_ssl);
    assert_eq!(client_config.proxy.as_deref(), Some("http://proxy.local:8080"));
    assert_eq!(client_config.https_proxy.as_deref(), Some("https://proxy.local:8443"));
    assert_eq!(client_config.http_proxy.as_deref(), Some("http://proxy.local:8080"));
    assert_eq!(client_config.no_proxy.as_deref(), Some("localhost,127.0.0.1"));
    assert_eq!(client_config.ca.as_deref(), Some("dummy-ca-pem"));
    assert_eq!(client_config.cafile, Some(PathBuf::from("test/cafile.pem")));
    assert_eq!(client_config.cert.as_deref(), Some("test/client.crt"));
    assert_eq!(client_config.key.as_deref(), Some("test/client.key"));
    assert_eq!(client_config.timeout, Duration::from_millis(45000));
    assert_eq!(client_config.connect_timeout, Duration::from_millis(12000));
}

#[tokio::test]
async fn test_offline_mode_metadata_cache_miss_enotcached() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let pkg_json = r#"{"name": "test-app", "dependencies": {"uncached-pkg": "^1.0.0"}}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = crate::InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some("https://registry.npmjs.org/".to_string()),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = crate::Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("ENOTCACHED"), "Must contain ENOTCACHED code: {err_str}");
    assert!(
        err_str.contains("only-if-cached") && err_str.contains("--offline"),
        "Must contain offline cache mode explanation: {err_str}"
    );
}

#[tokio::test]
async fn test_offline_mode_tarball_cache_miss_enotcached() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let pkg_json = r#"{"name": "test-app", "dependencies": {"my-cached-pkg": "1.0.0"}}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    // Populate metadata into cache so metadata succeeds, but tarball is not cached
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    let metadata_json = r#"{
        "name": "my-cached-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "my-cached-pkg",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://registry.npmjs.org/my-cached-pkg/-/my-cached-pkg-1.0.0.tgz",
                    "integrity": "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
                }
            }
        }
    }"#;
    cache.put("pacote:packument:my-cached-pkg", metadata_json.as_bytes(), None).unwrap();

    let options = crate::InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some("https://registry.npmjs.org/".to_string()),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = crate::Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("ENOTCACHED"), "Must contain ENOTCACHED code: {err_str}");
    assert!(
        err_str.contains("only-if-cached") && err_str.contains("--offline"),
        "Must contain offline cache mode explanation: {err_str}"
    );
}

#[tokio::test]
async fn test_offline_mode_cache_hit_success() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use sha2::{Digest, Sha512};

    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    // 1. Build test tarball
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        let content = br#"{"name":"offline-pkg","version":"1.0.0"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "package/package.json", &content[..]).unwrap();
        builder.finish().unwrap();
    }
    let tarball_bytes = gz.finish().unwrap();

    let mut hasher = Sha512::new();
    hasher.update(&tarball_bytes);
    let hash = hasher.finalize();
    let integrity_str = format!("sha512-{}", data_encoding::BASE64.encode(&hash));
    let integrity: rnpm_core::integrity::Integrity = integrity_str.parse().unwrap();

    let tarball_url = "https://registry.npmjs.org/offline-pkg/-/offline-pkg-1.0.0.tgz";

    // 2. Populate metadata and tarball into cache
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    let metadata_json = format!(
        r#"{{
            "name": "offline-pkg",
            "dist-tags": {{"latest": "1.0.0"}},
            "versions": {{
                "1.0.0": {{
                    "name": "offline-pkg",
                    "version": "1.0.0",
                    "dist": {{
                        "tarball": "{tarball_url}",
                        "integrity": "{integrity_str}"
                    }}
                }}
            }}
        }}"#
    );
    cache.put("pacote:packument:offline-pkg", metadata_json.as_bytes(), None).unwrap();
    cache.put_with_integrity(tarball_url, &tarball_bytes, Some(&integrity), None).unwrap();

    // 3. Project package.json
    let pkg_json = r#"{"name": "test-app", "dependencies": {"offline-pkg": "^1.0.0"}}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = crate::InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some("https://registry.npmjs.org/".to_string()),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = crate::Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();

    assert_eq!(summary.packages_installed, 1);
    assert_eq!(summary.cache_hits, 1);
    assert_eq!(summary.cache_misses, 0);
    assert!(project_dir.join("node_modules").join("offline-pkg").join("package.json").exists());
}

