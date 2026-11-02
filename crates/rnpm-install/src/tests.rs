use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

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
