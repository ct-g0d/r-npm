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
