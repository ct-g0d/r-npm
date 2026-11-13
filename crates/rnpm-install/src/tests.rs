use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use tar::{Builder, Header};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{InstallOptions, Installer, UninstallOptions};
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::manifest::{Manifest, PackageBin};
use rnpm_fs::junction::{create_junction, is_junction};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

#[test]
fn packument_freshness_honors_http_policy_and_age() {
    let mut entry = rnpm_cache::IndexEntry::new("test".into(), "".into(), "".into(), 0, None);
    assert!(!crate::is_packument_fresh(&entry, false, false));
    for (control, age, expected) in [
        ("public, max-age=300", "0", true),
        ("max-age=0", "0", false),
        ("max-age=300, no-cache", "0", false),
        ("no-store, max-age=300", "0", false),
        ("max-age=300", "400", false),
    ] {
        entry.metadata = Some(serde_json::json!({"response":{"headers":{"cache-control":control,"age":age}}}));
        assert_eq!(crate::is_packument_fresh(&entry, false, false), expected, "{control}, age={age}");
    }
    entry.metadata = Some(serde_json::json!({"response":{"headers":{"cache-control":"max-age=300","date":"Thu, 01 Jan 1970 00:00:00 GMT"}}}));
    assert!(!crate::is_packument_fresh(&entry, false, false));
    assert!(crate::is_packument_fresh(&entry, true, false));
    assert!(crate::is_packument_fresh(&entry, false, true));
}

#[tokio::test]
async fn persistence_failure_waits_for_remaining_jobs() {
    for panic_first in [false, true] {
        let (failed_tx, failed_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed_job = completed.clone();
        let tasks = vec![
            tokio::spawn(async move {
                failed_tx.send(()).unwrap();
                assert!(!panic_first, "persistence panic");
                Err(anyhow::anyhow!("first persistence error"))
            }),
            tokio::spawn(async move {
                release_rx.await.unwrap();
                completed_job.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }),
        ];
        let finish = tokio::spawn(crate::finish_pack_tasks(tasks));
        failed_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            !finish.is_finished(),
            "must not return with a live persistence job"
        );
        release_tx.send(()).unwrap();
        let error = finish.await.unwrap().unwrap_err().to_string();
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(error.contains(if panic_first {
            "pack worker panicked"
        } else {
            "first persistence error"
        }));
    }
}

fn setup_fixture_project(dir: &Path) {
    // 1. Root package.json
    let mut manifest = Manifest::default();
    manifest.name = Some("test-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-b".to_string(), "^2.0.0".to_string());
    manifest
        .dev_dependencies
        .insert("pkg-dev".to_string(), "^0.5.0".to_string());
    manifest
        .optional_dependencies
        .insert("pkg-opt".to_string(), "^3.0.0".to_string());
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

    lockfile
        .save_to_file(&dir.join("package-lock.json"))
        .unwrap();

    // 3. node_modules layout
    let nm = dir.join("node_modules");
    fs::create_dir_all(nm.join("pkg-a")).unwrap();
    fs::write(
        nm.join("pkg-a").join("package.json"),
        r#"{"name":"pkg-a","version":"1.0.0"}"#,
    )
    .unwrap();

    fs::create_dir_all(nm.join("sub-dep")).unwrap();
    fs::write(
        nm.join("sub-dep").join("package.json"),
        r#"{"name":"sub-dep","version":"1.0.0"}"#,
    )
    .unwrap();

    fs::create_dir_all(nm.join("pkg-b")).unwrap();
    fs::write(
        nm.join("pkg-b").join("package.json"),
        r#"{"name":"pkg-b","version":"2.0.0"}"#,
    )
    .unwrap();

    fs::create_dir_all(nm.join("pkg-dev")).unwrap();
    fs::write(
        nm.join("pkg-dev").join("package.json"),
        r#"{"name":"pkg-dev","version":"0.5.0"}"#,
    )
    .unwrap();

    fs::create_dir_all(nm.join("pkg-opt")).unwrap();
    fs::write(
        nm.join("pkg-opt").join("package.json"),
        r#"{"name":"pkg-opt","version":"3.0.0"}"#,
    )
    .unwrap();
}

#[test]
fn test_link_tree_bins_ansi_html() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");
    let bin = nm.join(".bin");
    let ansi_html = nm.join("ansi-html");
    std::fs::create_dir_all(ansi_html.join("bin")).unwrap();
    std::fs::write(
        ansi_html.join("package.json"),
        r#"{"name":"ansi-html","version":"0.0.9","bin":{"ansi-html":"./bin/ansi-html"}}"#,
    )
    .unwrap();
    std::fs::write(
        ansi_html.join("bin/ansi-html"),
        "#!/usr/bin/env node\nconsole.log(1);",
    )
    .unwrap();

    crate::link_tree_bins(
        vec!["node_modules/ansi-html".to_string()],
        None,
        root,
        &bin,
        &nm,
        true,
        None,
    );

    assert!(bin.join("ansi-html").exists(), "bin/ansi-html exists");
    assert!(
        bin.join("ansi-html.cmd").exists(),
        "bin/ansi-html.cmd exists"
    );
    assert!(
        bin.join("ansi-html.ps1").exists(),
        "bin/ansi-html.ps1 exists"
    );
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
    assert!(summary
        .pruned_dependencies
        .contains(&"node_modules/sub-dep".to_string()));

    // Verify package.json
    let updated_manifest = Manifest::from_file(project_dir.join("package.json")).unwrap();
    assert!(!updated_manifest.dependencies.contains_key("pkg-a"));
    assert!(updated_manifest.dependencies.contains_key("pkg-b"));

    // Verify package-lock.json
    let updated_lockfile =
        LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(!updated_lockfile
        .packages
        .contains_key("node_modules/sub-dep"));
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

    let updated_lockfile =
        LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-b"));
    assert!(!updated_lockfile
        .packages
        .contains_key("node_modules/sub-dep"));
    assert!(updated_lockfile
        .packages
        .contains_key("node_modules/pkg-dev"));

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
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-b".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

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
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let nm = project_dir.join("node_modules");
    fs::create_dir_all(nm.join("pkg-a")).unwrap();
    fs::create_dir_all(nm.join("pkg-b")).unwrap();
    fs::create_dir_all(nm.join("shared-lib")).unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    })
    .unwrap();

    // Uninstall pkg-a
    let summary = installer
        .uninstall(&UninstallOptions {
            packages: vec!["pkg-a".to_string()],
            ..Default::default()
        })
        .unwrap();

    assert_eq!(summary.removed_packages, vec!["pkg-a".to_string()]);
    // shared-lib must NOT be pruned because pkg-b still depends on it!
    assert!(!summary
        .pruned_dependencies
        .contains(&"node_modules/shared-lib".to_string()));

    let updated_lockfile =
        LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    assert!(!updated_lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(updated_lockfile
        .packages
        .contains_key("node_modules/shared-lib"));
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
    manifest
        .dependencies
        .insert("parent".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

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
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let nested_dir = project_dir
        .join("node_modules")
        .join("parent")
        .join("node_modules")
        .join("conflict-child");
    fs::create_dir_all(&nested_dir).unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    })
    .unwrap();

    let summary = installer
        .uninstall(&UninstallOptions {
            packages: vec!["parent".to_string()],
            ..Default::default()
        })
        .unwrap();

    assert_eq!(summary.removed_packages, vec!["parent".to_string()]);
    assert!(summary
        .pruned_dependencies
        .contains(&"node_modules/parent/node_modules/conflict-child".to_string()));

    assert!(!project_dir.join("node_modules").join("parent").exists());
}

#[test]
fn test_uninstall_scoped_package_and_cleans_empty_scope_dir() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("scope-test".to_string());
    manifest
        .dependencies
        .insert("@my-scope/my-lib".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("scope-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package(
        "node_modules/@my-scope/my-lib",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let scope_pkg_dir = project_dir
        .join("node_modules")
        .join("@my-scope")
        .join("my-lib");
    fs::create_dir_all(&scope_pkg_dir).unwrap();
    fs::write(scope_pkg_dir.join("index.js"), "module.exports = {};").unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    })
    .unwrap();

    installer
        .uninstall(&UninstallOptions {
            packages: vec!["@my-scope/my-lib".to_string()],
            ..Default::default()
        })
        .unwrap();

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
    manifest
        .dependencies
        .insert("tool-pkg".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("shim-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package(
        "node_modules/tool-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            bin: Some(rnpm_lockfile::PackageBin::Single(
                "./bin/run.js".to_string(),
            )),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // Setup node_modules/tool-pkg and its manifest declaring bin
    let tool_dir = project_dir.join("node_modules").join("tool-pkg");
    fs::create_dir_all(&tool_dir).unwrap();
    let mut tool_manifest = Manifest::default();
    tool_manifest.name = Some("tool-pkg".to_string());
    tool_manifest.bin = Some(PackageBin::Single("./bin/run.js".to_string()));
    tool_manifest
        .save_to_file(tool_dir.join("package.json"))
        .unwrap();

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
    })
    .unwrap();

    installer
        .uninstall(&UninstallOptions {
            packages: vec!["tool-pkg".to_string()],
            ..Default::default()
        })
        .unwrap();

    // Shims and empty .bin must be gone
    assert!(!bin_dir.join("tool-pkg").exists());
    #[cfg(windows)]
    {
        assert!(!bin_dir.join("tool-pkg.cmd").exists());
        assert!(!bin_dir.join("tool-pkg.ps1").exists());
    }
    assert!(
        !bin_dir.exists(),
        "Empty .bin directory should be cleaned up"
    );
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
    manifest.dependencies.insert(
        "linked-pkg".to_string(),
        "file:../external-repo".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lockfile = LockfileV3::new("junction-test", Some("1.0.0".to_string()));
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest.dependencies.clone());
    }
    lockfile.insert_package(
        "node_modules/linked-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // Create directory junction/symlink in node_modules pointing to external_dir
    let nm = project_dir.join("node_modules");
    fs::create_dir_all(&nm).unwrap();
    let link_path = nm.join("linked-pkg");
    create_junction(&link_path, &external_dir).unwrap();
    assert!(is_junction(&link_path).unwrap());

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        ..Default::default()
    })
    .unwrap();

    installer
        .uninstall(&UninstallOptions {
            packages: vec!["linked-pkg".to_string()],
            ..Default::default()
        })
        .unwrap();

    // Junction in node_modules is deleted
    assert!(!link_path.exists());

    // CRITICAL SECURITY PROPERTY: Target external directory AND its contents MUST BE PRESERVED!
    assert!(
        external_dir.exists(),
        "External target directory must not be deleted"
    );
    assert!(
        precious_file.exists(),
        "External files must not be deleted when removing junction"
    );
    assert_eq!(
        fs::read_to_string(&precious_file).unwrap(),
        "console.log('valuable code');"
    );
}

#[test]
fn test_uninstall_security_rejects_path_traversal() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("security-test".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        ..Default::default()
    })
    .unwrap();

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
        assert!(
            res.is_err(),
            "Must reject path traversal input: {dangerous}"
        );
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
    })
    .unwrap();

    installer
        .uninstall(&UninstallOptions {
            packages: vec!["pkg-a".to_string()],
            ..Default::default()
        })
        .unwrap();

    // Verify package-lock.json ends with newline and is valid deterministic JSON
    let lockfile_content = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(
        lockfile_content.ends_with('\n'),
        "package-lock.json must end with newline"
    );
    let parsed_lock: LockfileV3 = serde_json::from_str(&lockfile_content).unwrap();
    assert_eq!(parsed_lock.lockfile_version, 3);

    // Verify package.json ends with newline
    let manifest_content = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(
        manifest_content.ends_with('\n'),
        "package.json must end with newline"
    );
    let parsed_manifest: Manifest = serde_json::from_str(&manifest_content).unwrap();
    assert_eq!(parsed_manifest.name.as_deref(), Some("test-app"));
}

fn make_tarball(pkg_name: &str, version: &str, deps: &[(&str, &str)]) -> Vec<u8> {
    let mut dep_map = serde_json::Map::new();
    for (d_name, d_range) in deps {
        dep_map.insert(
            d_name.to_string(),
            serde_json::Value::String(d_range.to_string()),
        );
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
        builder
            .append(&header, Cursor::new(manifest_bytes))
            .unwrap();
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
    std::fs::write(
        &pkg_json,
        r#"{
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0"
            }
        }"#,
    )
    .unwrap();

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
    assert_eq!(
        summary.old_versions.get("pkg-a"),
        Some(&"1.0.0".to_string())
    );
    assert_eq!(
        summary.new_versions.get("pkg-a"),
        Some(&"1.1.0".to_string())
    );

    // Verify lockfile rewritten deterministically
    let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
    let updated_a = updated_lock.get_package("node_modules/pkg-a").unwrap();
    assert_eq!(updated_a.version, Some("1.1.0".to_string()));

    // Verify newly needed dependency trans-new is present in lockfile and node_modules
    assert!(updated_lock.get_package("node_modules/trans-new").is_some());
    assert!(project_dir
        .path()
        .join("node_modules/trans-new/package.json")
        .exists());

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
    std::fs::write(
        &pkg_json,
        r#"{
            "name": "test-multi",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0",
                "pkg-b": "^1.0.0"
            }
        }"#,
    )
    .unwrap();

    // Lockfile has both at 1.0.0
    let mut lock = LockfileV3::new("test-multi", Some("1.0.0".to_string()));
    let mut d = BTreeMap::new();
    d.insert("pkg-a".to_string(), "^1.0.0".to_string());
    d.insert("pkg-b".to_string(), "^1.0.0".to_string());
    lock.root_package_mut().unwrap().dependencies = Some(d);

    lock.insert_package(
        "node_modules/pkg-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-a.tgz")),
            integrity: Some(a_int),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/pkg-b",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-b.tgz")),
            integrity: Some(b_int),
            ..Default::default()
        },
    );
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
    assert_eq!(
        reloaded.get_package("node_modules/pkg-a").unwrap().version,
        Some("1.1.0".to_string())
    );
    // pkg-b remains at 1.0.0!
    assert_eq!(
        reloaded.get_package("node_modules/pkg-b").unwrap().version,
        Some("1.0.0".to_string())
    );

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
    )
    .unwrap();
    fs::write(
        lib_a_dir.join("index.js"),
        "module.exports = { name: 'lib-a' };\n",
    )
    .unwrap();

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
    )
    .unwrap();

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
    )
    .unwrap();

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

    assert!(
        is_junction(&link_a).unwrap(),
        "Link for @mono/lib-a must be a junction or symlink"
    );
    assert!(
        is_junction(&link_b).unwrap(),
        "Link for @mono/lib-b must be a junction or symlink"
    );
    assert!(
        is_junction(&link_app).unwrap(),
        "Link for my-app must be a junction or symlink"
    );

    // Test live linking: reading through junction reads target content
    let linked_a_pkg = fs::read_to_string(link_a.join("package.json")).unwrap();
    assert!(linked_a_pkg.contains("@mono/lib-a"));

    // Mutate source file and verify junction immediately sees it without reinstall
    fs::write(lib_a_dir.join("test-sync.txt"), "sync test").unwrap();
    assert!(
        link_a.join("test-sync.txt").exists(),
        "Junction must reflect changes immediately"
    );

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
    )
    .unwrap();

    let p2_dir = root.join("packages").join("pkg-2");
    fs::create_dir_all(&p2_dir).unwrap();
    fs::write(
        p2_dir.join("package.json"),
        r#"{"name": "pkg-2", "version": "1.0.0", "dependencies": {"pkg-1": "workspace:*"}}"#,
    )
    .unwrap();

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
    )
    .unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("missing-pkg"),
        "Should report missing package: {err_msg}"
    );
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
    assert!(
        !link_path.exists(),
        "Junction reparse point must be removed"
    );
    assert!(
        secret_file.exists(),
        "Target file must NEVER be deleted when removing junction!"
    );
    assert_eq!(
        fs::read_to_string(&secret_file).unwrap(),
        "precious content"
    );
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
    std::fs::write(
        &pkg_json,
        r#"{
        "name": "targeted-test",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": "^1.0.0",
            "pkg-b": "^1.0.0"
        }
    }"#,
    )
    .unwrap();

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
    assert_eq!(
        updated_lock
            .get_package("node_modules/pkg-a")
            .unwrap()
            .version,
        Some("1.1.0".to_string())
    );
    // pkg-b is completely UNTOUCHED at 1.0.0
    assert_eq!(
        updated_lock
            .get_package("node_modules/pkg-b")
            .unwrap()
            .version,
        Some("1.0.0".to_string())
    );
    // dep-shared satisfies ^1.0.0 so it is RETAINED at 1.0.0 without modification
    assert_eq!(
        updated_lock
            .get_package("node_modules/dep-shared")
            .unwrap()
            .version,
        Some("1.0.0".to_string())
    );

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
        std::fs::write(
            &pkg_json,
            format!(r#"{{"name": "test-sec", "dependencies": {{"{bad_name}": "1.0.0"}}}}"#),
        )
        .unwrap();

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
        assert!(
            res.is_err(),
            "Expected error for illegal package name '{bad_name}', but succeeded"
        );
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
    fs::write(
        local_pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&local_manifest).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(local_pkg_dir.join("bin")).unwrap();
    fs::write(
        local_pkg_dir.join("bin").join("run.js"),
        "#!/usr/bin/env node\nconsole.log('hello');\n",
    )
    .unwrap();

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
    fs::write(
        app_dir.join("package.json"),
        serde_json::to_string_pretty(&app_manifest).unwrap(),
    )
    .unwrap();

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
    assert!(app_dir
        .join("node_modules")
        .join(".bin")
        .join("local-cmd.cmd")
        .exists());
    #[cfg(not(windows))]
    assert!(app_dir
        .join("node_modules")
        .join(".bin")
        .join("local-cmd")
        .exists());

    // 5. Verify package-lock.json
    let lockfile = LockfileV3::load_from_file(&app_dir.join("package-lock.json")).unwrap();
    let lock_link = lockfile
        .packages
        .get("node_modules/local-pkg")
        .expect("Lockfile must contain node_modules/local-pkg");
    assert_eq!(lock_link.link, Some(true));
    assert_eq!(lock_link.resolved.as_deref(), Some("../packages/local-pkg"));

    let lock_target = lockfile
        .packages
        .get("../packages/local-pkg")
        .expect("Lockfile must contain physical package info");
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
            builder
                .append(&header, Cursor::new(manifest_bytes))
                .unwrap();
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
    fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&app_manifest).unwrap(),
    )
    .unwrap();

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
    let pkg_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(pkg_dir.join("package.json")).unwrap()).unwrap();
    assert_eq!(pkg_json["name"], "archive-lib");
    assert_eq!(pkg_json["version"], "3.0.0");

    // 5. Verify package-lock.json
    let lockfile = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    let lock_pkg = lockfile
        .packages
        .get("node_modules/archive-lib")
        .expect("Lockfile must contain node_modules/archive-lib");
    assert_eq!(lock_pkg.version.as_deref(), Some("3.0.0"));
    assert_eq!(
        lock_pkg.resolved.as_deref(),
        Some("file:./pkgs/archive-lib-3.0.0.tgz")
    );
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
    assert!(
        order_file.exists(),
        "order.log must be created by lifecycle scripts"
    );
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

    assert!(
        order_file.exists(),
        "order.log must be created during run_ci"
    );
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
    manifest
        .dev_dependencies
        .insert("dev-tool".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 2. Matching lockfile
    let mut lockfile = LockfileV3::new("dev-drift-app", Some("1.0.0".to_string()));
    let mut dev_deps = BTreeMap::new();
    dev_deps.insert("dev-tool".to_string(), "^1.0.0".to_string());
    lockfile.root_package_mut().unwrap().dev_dependencies = Some(dev_deps);
    lockfile.insert_package(
        "node_modules/dev-tool",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/dev-tool/-/dev-tool-1.0.0.tgz".to_string()),
            integrity: Some("sha512-validhash".to_string()),
            dev: Some(true),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 3. Mutate devDependencies in package.json to ^2.0.0
    manifest
        .dev_dependencies
        .insert("dev-tool".to_string(), "^2.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when devDependencies mutated in package.json"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "Error must contain ELOCKFILE_DRIFT: {err_msg}"
    );
    assert!(
        err_msg.contains("EUSAGE"),
        "Error must contain EUSAGE: {err_msg}"
    );
    assert!(
        err_msg.contains("dev-tool"),
        "Error must mention drifted package: {err_msg}"
    );
}

#[tokio::test]
async fn test_ci_drift_detection_dependency_deleted_from_manifest() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let dep_a_tar = make_tarball("dep-a", "1.0.0", &[]);
    let dep_a_integrity = Integrity::from_bytes(&dep_a_tar, Algorithm::Sha512).to_string();
    let dep_b_tar = make_tarball("dep-b", "1.0.0", &[]);
    let dep_b_integrity = Integrity::from_bytes(&dep_b_tar, Algorithm::Sha512).to_string();

    let pkgs_dir = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    fs::write(pkgs_dir.join("dep-a-1.0.0.tgz"), &dep_a_tar).unwrap();
    fs::write(pkgs_dir.join("dep-b-1.0.0.tgz"), &dep_b_tar).unwrap();

    // 1. Lockfile has two dependencies: "dep-a" and "dep-b"
    let mut lockfile = LockfileV3::new("dep-drift-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert(
        "dep-a".to_string(),
        "file:./pkgs/dep-a-1.0.0.tgz".to_string(),
    );
    deps.insert(
        "dep-b".to_string(),
        "file:./pkgs/dep-b-1.0.0.tgz".to_string(),
    );
    lockfile.root_package_mut().unwrap().dependencies = Some(deps);
    lockfile.insert_package(
        "node_modules/dep-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/dep-a-1.0.0.tgz".to_string()),
            integrity: Some(dep_a_integrity),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/dep-b",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/dep-b-1.0.0.tgz".to_string()),
            integrity: Some(dep_b_integrity),
            ..Default::default()
        },
    );
    lockfile
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // 2. package.json has "dep-b" deleted, only contains "dep-a"
    let mut manifest = Manifest::default();
    manifest.name = Some("dep-drift-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert(
        "dep-a".to_string(),
        "file:./pkgs/dep-a-1.0.0.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    // Per measurement against real npm 11.20.0 (gate CI Case 4):
    // When a dependency is removed from package.json but remains in package-lock.json,
    // npm ci ignores the extraneous package in the lockfile and exits 0.
    // The test verifies rnpm parity with npm 11.20.0.
    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "run_ci must succeed when dependency is deleted from package.json but present in lockfile, matching npm 11.20: {:?}",
        res.err()
    );
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
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must detect missing dep-b after migrating v1 lockfile"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "Must emit ELOCKFILE_DRIFT: {err_msg}"
    );
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
    })
    .unwrap();

    installer.run_ci().await.unwrap();

    // Crucial check: external target file was NOT deleted!
    assert!(
        secret_file.exists(),
        "External file must be preserved when run_ci cleans node_modules with junctions!"
    );
}

#[tokio::test]
async fn test_ci_security_adversarial_file_path_traversal_rejected() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("sec-traversal-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert(
        "malicious-pkg".to_string(),
        "file:../../secret.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

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
        lockfile.insert_package(
            "node_modules/malicious-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                resolved: Some(bad_resolved.to_string()),
                integrity: Some(valid_hash.to_string()),
                ..Default::default()
            },
        );
        lockfile
            .save_to_file(&project_dir.join("package-lock.json"))
            .unwrap();

        let mut installer = Installer::new(InstallOptions {
            project_dir: project_dir.to_path_buf(),
            offline: true,
            ..Default::default()
        })
        .unwrap();

        let res = installer.run_ci().await;
        assert!(
            res.is_err(),
            "run_ci must reject adversarial file: traversal path '{bad_resolved}'"
        );
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
    manifest.dependencies.insert(
        "parent-pkg".to_string(),
        "file:./pkgs/child-pkg-1.0.0.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // 1. Missing or empty integrity on transitive dependency in lockfile
    let mut lock_missing_integrity = LockfileV3::new("integrity-app", Some("1.0.0".to_string()));
    let mut deps = BTreeMap::new();
    deps.insert(
        "parent-pkg".to_string(),
        "file:./pkgs/child-pkg-1.0.0.tgz".to_string(),
    );
    lock_missing_integrity
        .root_package_mut()
        .unwrap()
        .dependencies = Some(deps);
    lock_missing_integrity.insert_package(
        "node_modules/parent-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
            integrity: Some(child_valid_integrity.clone()),
            ..Default::default()
        },
    );
    // Transitive package has empty integrity!
    lock_missing_integrity.insert_package(
        "node_modules/child-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
            integrity: Some("   ".to_string()),
            ..Default::default()
        },
    );
    lock_missing_integrity
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_err(),
        "run_ci must fail when transitive package has empty integrity"
    );

    // 2. Mismatched integrity on transitive dependency
    let mut lock_tampered = LockfileV3::new("integrity-app", Some("1.0.0".to_string()));
    let mut deps2 = BTreeMap::new();
    deps2.insert(
        "parent-pkg".to_string(),
        "file:./pkgs/child-pkg-1.0.0.tgz".to_string(),
    );
    lock_tampered.root_package_mut().unwrap().dependencies = Some(deps2);
    lock_tampered.insert_package(
        "node_modules/parent-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
            integrity: Some(child_valid_integrity.clone()),
            ..Default::default()
        },
    );
    // Tampered integrity!
    let tampered_integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    lock_tampered.insert_package(
        "node_modules/child-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:./pkgs/child-pkg-1.0.0.tgz".to_string()),
            integrity: Some(tampered_integrity.to_string()),
            ..Default::default()
        },
    );
    lock_tampered
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    let res2 = installer2.run_ci().await;
    assert!(
        res2.is_err(),
        "run_ci must fail when transitive package integrity verification fails"
    );
    let err_str = res2.unwrap_err().to_string();
    assert!(
        err_str.to_lowercase().contains("integrity"),
        "Error must mention integrity: {err_str}"
    );
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
    manifest.dependencies.insert(
        "local-dep".to_string(),
        "file:./pkgs/local-dep-1.0.0.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

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
    assert!(
        hidden_path.exists(),
        "node_modules/.package-lock.json must exist after install"
    );

    // Check raw JSON on disk does not have root "" entry and has lockfileVersion 3
    let raw_hidden_json = fs::read_to_string(&hidden_path).unwrap();
    let parsed_hidden: serde_json::Value = serde_json::from_str(&raw_hidden_json).unwrap();
    assert!(
        parsed_hidden.get("packages").unwrap().get("").is_none(),
        "Hidden lockfile node_modules/.package-lock.json must omit the root \"\" entry"
    );
    assert_eq!(
        parsed_hidden
            .get("lockfileVersion")
            .unwrap()
            .as_u64()
            .unwrap(),
        3,
        "Hidden lockfile must enforce lockfileVersion 3"
    );

    let loaded_hidden = LockfileV3::load_hidden(project_dir).unwrap();
    assert_eq!(loaded_hidden.name, "hidden-lock-test");
    assert!(
        !loaded_hidden.packages.contains_key(""),
        "Loaded hidden lockfile must omit root \"\""
    );
    assert!(loaded_hidden
        .packages
        .contains_key("node_modules/local-dep"));

    // 2. Remove node_modules and run CI
    fs::remove_dir_all(project_dir.join("node_modules")).unwrap();
    assert!(!hidden_path.exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);

    // Verify hidden lockfile was created after run_ci
    assert!(
        hidden_path.exists(),
        "node_modules/.package-lock.json must exist after run_ci"
    );
    let raw_ci_hidden_json = fs::read_to_string(&hidden_path).unwrap();
    let parsed_ci_hidden: serde_json::Value = serde_json::from_str(&raw_ci_hidden_json).unwrap();
    assert!(
        parsed_ci_hidden.get("packages").unwrap().get("").is_none(),
        "CI hidden lockfile node_modules/.package-lock.json must omit the root \"\" entry"
    );
    assert_eq!(
        parsed_ci_hidden
            .get("lockfileVersion")
            .unwrap()
            .as_u64()
            .unwrap(),
        3,
        "CI hidden lockfile must enforce lockfileVersion 3"
    );
    let loaded_ci_hidden = LockfileV3::load_hidden(project_dir).unwrap();
    assert_eq!(loaded_ci_hidden.name, "hidden-lock-test");
    assert!(
        !loaded_ci_hidden.packages.contains_key(""),
        "Loaded CI hidden lockfile must omit root \"\""
    );
    assert!(loaded_ci_hidden
        .packages
        .contains_key("node_modules/local-dep"));
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
    npmrc
        .set("https-proxy", "https://proxy.local:8443")
        .unwrap();
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
    assert_eq!(
        client_config.proxy.as_deref(),
        Some("http://proxy.local:8080")
    );
    assert_eq!(
        client_config.https_proxy.as_deref(),
        Some("https://proxy.local:8443")
    );
    assert_eq!(
        client_config.http_proxy.as_deref(),
        Some("http://proxy.local:8080")
    );
    assert_eq!(
        client_config.no_proxy.as_deref(),
        Some("localhost,127.0.0.1")
    );
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
    assert!(
        err_str.contains("ENOTCACHED"),
        "Must contain ENOTCACHED code: {err_str}"
    );
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
    cache
        .put(
            "pacote:packument:my-cached-pkg",
            metadata_json.as_bytes(),
            None,
        )
        .unwrap();

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
    assert!(
        err_str.contains("ENOTCACHED"),
        "Must contain ENOTCACHED code: {err_str}"
    );
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
        builder
            .append_data(&mut header, "package/package.json", &content[..])
            .unwrap();
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
    cache
        .put(
            "pacote:packument:offline-pkg",
            metadata_json.as_bytes(),
            None,
        )
        .unwrap();
    cache
        .put_with_integrity(tarball_url, &tarball_bytes, Some(&integrity), None)
        .unwrap();

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
    assert!(project_dir
        .join("node_modules")
        .join("offline-pkg")
        .join("package.json")
        .exists());
}

#[tokio::test]
async fn test_install_save_flags_and_package_lock_only_matrix() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create two local packages
    let local_pkg_a = root.join("packages").join("pkg-a");
    fs::create_dir_all(&local_pkg_a).unwrap();
    fs::write(
        local_pkg_a.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.2.3"}"#,
    )
    .unwrap();

    let local_pkg_b = root.join("packages").join("pkg-b");
    fs::create_dir_all(&local_pkg_b).unwrap();
    fs::write(
        local_pkg_b.join("package.json"),
        r#"{"name": "pkg-b", "version": "2.0.0"}"#,
    )
    .unwrap();

    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("package.json"),
        r#"{"name": "app", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Test A: --save-dev (-D)
    {
        let opts = InstallOptions {
            project_dir: app_dir.clone(),
            offline: true,
            packages: vec!["pkg-a@file:../packages/pkg-a".to_string()],
            save_dev: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        installer.run().await.unwrap();

        let manifest = Manifest::from_file(app_dir.join("package.json")).unwrap();
        assert!(manifest.dev_dependencies.contains_key("pkg-a"));
        assert!(!manifest.dependencies.contains_key("pkg-a"));
    }

    // Test B: --save-prod (-P) moves from dev_dependencies to dependencies
    {
        let opts = InstallOptions {
            project_dir: app_dir.clone(),
            offline: true,
            packages: vec!["pkg-a@file:../packages/pkg-a".to_string()],
            save_prod: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        installer.run().await.unwrap();

        let manifest = Manifest::from_file(app_dir.join("package.json")).unwrap();
        assert!(manifest.dependencies.contains_key("pkg-a"));
        assert!(!manifest.dev_dependencies.contains_key("pkg-a"));
    }

    // Test C: --save-optional (-O) moves to optional_dependencies
    {
        let opts = InstallOptions {
            project_dir: app_dir.clone(),
            offline: true,
            packages: vec!["pkg-a@file:../packages/pkg-a".to_string()],
            save_optional: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        installer.run().await.unwrap();

        let manifest = Manifest::from_file(app_dir.join("package.json")).unwrap();
        assert!(manifest.optional_dependencies.contains_key("pkg-a"));
        assert!(!manifest.dependencies.contains_key("pkg-a"));
    }

    // Test D: --save-peer moves to peer_dependencies
    {
        let opts = InstallOptions {
            project_dir: app_dir.clone(),
            offline: true,
            packages: vec!["pkg-a@file:../packages/pkg-a".to_string()],
            save_peer: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        installer.run().await.unwrap();

        let manifest = Manifest::from_file(app_dir.join("package.json")).unwrap();
        assert!(manifest.peer_dependencies.contains_key("pkg-a"));
        assert!(!manifest.optional_dependencies.contains_key("pkg-a"));
    }

    // Test E: --no-save does not mutate package.json or write package-lock.json
    {
        let app_no_save_dir = root.join("app-no-save");
        fs::create_dir_all(&app_no_save_dir).unwrap();
        let orig_content = r#"{"name": "app-no-save", "version": "1.0.0"}"#;
        fs::write(app_no_save_dir.join("package.json"), orig_content).unwrap();

        let opts = InstallOptions {
            project_dir: app_no_save_dir.clone(),
            offline: true,
            packages: vec!["pkg-b@file:../packages/pkg-b".to_string()],
            no_save: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        installer.run().await.unwrap();

        let content = fs::read_to_string(app_no_save_dir.join("package.json")).unwrap();
        assert_eq!(content, orig_content);
        assert!(!app_no_save_dir.join("package-lock.json").exists());
        assert!(app_no_save_dir.join("node_modules").join("pkg-b").exists());
    }

    // Test F: --package-lock-only writes package-lock.json without creating node_modules
    {
        let app_lock_only_dir = root.join("app-lock-only");
        fs::create_dir_all(&app_lock_only_dir).unwrap();
        fs::write(
            app_lock_only_dir.join("package.json"),
            r#"{"name": "app-lock-only", "version": "1.0.0"}"#,
        )
        .unwrap();

        let opts = InstallOptions {
            project_dir: app_lock_only_dir.clone(),
            offline: true,
            packages: vec!["pkg-a@file:../packages/pkg-a".to_string()],
            package_lock_only: true,
            ..Default::default()
        };
        let mut installer = Installer::new(opts).unwrap();
        let summary = installer.run().await.unwrap();

        assert_eq!(summary.packages_installed, 0);
        assert!(app_lock_only_dir.join("package-lock.json").exists());
        assert!(!app_lock_only_dir.join("node_modules").exists());
    }
}

#[tokio::test]
async fn test_link_and_unlink_package_flow() {
    use crate::link::{
        link_package, link_package_from_global, unlink_package, unlink_package_from_consumer,
    };
    use rnpm_config::{find_global_bin_dir, find_global_node_modules};

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let global_prefix = root.join("global");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Create a package to link
    let pkg_dir = root.join("tools").join("my-linked-tool");
    fs::create_dir_all(&pkg_dir).unwrap();
    let manifest_content = r#"{
        "name": "my-linked-tool",
        "version": "1.0.0",
        "bin": {
            "my-linked-tool": "./bin/cli.js"
        }
    }"#;
    fs::write(pkg_dir.join("package.json"), manifest_content).unwrap();
    let bin_dir = pkg_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(
        bin_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('linked');\n",
    )
    .unwrap();

    // 2. Run link_package (npm link in package dir)
    let global_link_path = link_package(&pkg_dir, &global_prefix).unwrap();
    assert!(global_link_path.exists());
    assert!(rnpm_fs::is_junction(&global_link_path).unwrap());

    let global_bin = find_global_bin_dir(&global_prefix);
    #[cfg(windows)]
    assert!(global_bin.join("my-linked-tool.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("my-linked-tool").exists());

    // 3. Create consumer project
    let consumer_dir = root.join("consumer");
    fs::create_dir_all(&consumer_dir).unwrap();
    fs::write(
        consumer_dir.join("package.json"),
        r#"{"name": "consumer", "version": "1.0.0"}"#,
    )
    .unwrap();

    // 4. Run link_package_from_global (npm link my-linked-tool in consumer)
    let consumer_link_path =
        link_package_from_global(&consumer_dir, "my-linked-tool", &global_prefix).unwrap();
    assert!(consumer_link_path.exists());
    assert!(rnpm_fs::is_junction(&consumer_link_path).unwrap());

    let local_bin = consumer_dir.join("node_modules").join(".bin");
    #[cfg(windows)]
    assert!(local_bin.join("my-linked-tool.cmd").exists());
    #[cfg(not(windows))]
    assert!(local_bin.join("my-linked-tool").exists());

    // 5. Test consumer unlink (npm unlink my-linked-tool in consumer)
    unlink_package_from_consumer(&consumer_dir, "my-linked-tool").unwrap();
    assert!(!consumer_dir
        .join("node_modules")
        .join("my-linked-tool")
        .exists());
    #[cfg(windows)]
    assert!(!local_bin.join("my-linked-tool.cmd").exists());
    #[cfg(not(windows))]
    assert!(!local_bin.join("my-linked-tool").exists());

    // 6. Test global unlink (npm unlink in linked package dir)
    unlink_package(&pkg_dir, &global_prefix).unwrap();
    let global_nm = find_global_node_modules(&global_prefix);
    assert!(!global_nm.join("my-linked-tool").exists());
    #[cfg(windows)]
    assert!(!global_bin.join("my-linked-tool.cmd").exists());
    #[cfg(not(windows))]
    assert!(!global_bin.join("my-linked-tool").exists());
}

#[tokio::test]
async fn test_global_install_and_uninstall_mode() {
    use rnpm_config::{find_global_bin_dir, find_global_node_modules};

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let global_prefix = root.join("global-env");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Create a local package
    let pkg_dir = root.join("my-global-pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{
            "name": "my-global-pkg",
            "version": "1.0.0",
            "bin": {
                "my-global-bin": "./cli.js"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        pkg_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('global');\n",
    )
    .unwrap();

    let target_spec = format!("my-global-pkg@file:{}", pkg_dir.display());

    // 2. Global install
    let options = InstallOptions {
        project_dir: global_prefix.clone(),
        packages: vec![target_spec],
        is_global: true,
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let global_nm = find_global_node_modules(&global_prefix);
    let installed_pkg = global_nm.join("my-global-pkg");
    assert!(installed_pkg.exists());

    let global_bin = find_global_bin_dir(&global_prefix);
    #[cfg(windows)]
    assert!(global_bin.join("my-global-bin.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("my-global-bin").exists());

    // 3. Global uninstall
    let uninstall_opts = UninstallOptions {
        packages: vec!["my-global-pkg".to_string()],
        is_global: true,
        ..Default::default()
    };
    let un_summary = installer.uninstall(&uninstall_opts).unwrap();
    assert_eq!(un_summary.removed_packages.len(), 1);

    assert!(!installed_pkg.exists());
    #[cfg(windows)]
    assert!(!global_bin.join("my-global-bin.cmd").exists());
    #[cfg(not(windows))]
    assert!(!global_bin.join("my-global-bin").exists());
}

#[tokio::test]
async fn test_global_sequential_installs_preserve_existing_packages_and_shims() {
    use rnpm_config::{find_global_bin_dir, find_global_node_modules};

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let global_prefix = root.join("global-env");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Create local package A with bin "bin-a"
    let pkg_a_dir = root.join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
            "name": "pkg-a",
            "version": "1.0.0",
            "bin": {
                "bin-a": "./cli.js"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        pkg_a_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('pkg-a');\n",
    )
    .unwrap();

    // 2. Create local package C (dependency of B)
    let pkg_c_dir = root.join("pkg-c");
    fs::create_dir_all(&pkg_c_dir).unwrap();
    fs::write(
        pkg_c_dir.join("package.json"),
        r#"{
            "name": "pkg-c",
            "version": "1.0.0",
            "bin": {
                "bin-c": "./cli.js"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        pkg_c_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('pkg-c');\n",
    )
    .unwrap();

    // 3. Create local package B with bin "bin-b" and dependency on package C
    let pkg_b_dir = root.join("pkg-b");
    fs::create_dir_all(&pkg_b_dir).unwrap();
    let pkg_c_spec = format!(
        "file:{}",
        rnpm_core::to_posix_path(&pkg_c_dir.to_string_lossy())
    );
    fs::write(
        pkg_b_dir.join("package.json"),
        format!(
            r#"{{
            "name": "pkg-b",
            "version": "1.0.0",
            "bin": {{
                "bin-b": "./cli.js"
            }},
            "dependencies": {{
                "pkg-c": "{pkg_c_spec}"
            }}
        }}"#
        ),
    )
    .unwrap();
    fs::write(
        pkg_b_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('pkg-b');\n",
    )
    .unwrap();

    let target_spec_a = format!("pkg-a@file:{}", pkg_a_dir.display());
    let target_spec_b = format!("pkg-b@file:{}", pkg_b_dir.display());

    // 4. Install package A globally
    let options_a = InstallOptions {
        project_dir: global_prefix.clone(),
        packages: vec![target_spec_a],
        is_global: true,
        offline: true,
        ..Default::default()
    };
    let mut installer_a = Installer::new(options_a).unwrap();
    let summary_a = installer_a.run().await.unwrap();
    assert_eq!(summary_a.packages_installed, 1);

    let global_nm = find_global_node_modules(&global_prefix);
    let global_bin = find_global_bin_dir(&global_prefix);

    assert!(
        global_nm.join("pkg-a").exists(),
        "pkg-a must be installed in global node_modules"
    );
    #[cfg(windows)]
    assert!(
        global_bin.join("bin-a.cmd").exists(),
        "bin-a shim must exist"
    );
    #[cfg(not(windows))]
    assert!(global_bin.join("bin-a").exists(), "bin-a shim must exist");

    // Root package.json / package-lock.json must NOT exist
    assert!(
        !global_prefix.join("package.json").exists(),
        "global install must not write root package.json"
    );
    assert!(
        !global_prefix.join("package-lock.json").exists(),
        "global install must not write root package-lock.json"
    );

    // 5. Install package B globally in the SAME prefix
    let options_b = InstallOptions {
        project_dir: global_prefix.clone(),
        packages: vec![target_spec_b],
        is_global: true,
        offline: true,
        ..Default::default()
    };
    let mut installer_b = Installer::new(options_b).unwrap();
    let summary_b = installer_b.run().await.unwrap();
    assert!(summary_b.packages_installed >= 1);

    // CRITICAL REQUIREMENT: pkg-a MUST still be present in global node_modules!
    assert!(
        global_nm.join("pkg-a").exists(),
        "pkg-a must be preserved in global node_modules after installing pkg-b"
    );
    #[cfg(windows)]
    assert!(
        global_bin.join("bin-a.cmd").exists(),
        "bin-a shim must still exist after installing pkg-b"
    );
    #[cfg(not(windows))]
    assert!(
        global_bin.join("bin-a").exists(),
        "bin-a shim must still exist after installing pkg-b"
    );

    // pkg-b must be installed
    assert!(global_nm.join("pkg-b").exists(), "pkg-b must be installed");
    #[cfg(windows)]
    assert!(
        global_bin.join("bin-b.cmd").exists(),
        "bin-b shim must exist"
    );
    #[cfg(not(windows))]
    assert!(global_bin.join("bin-b").exists(), "bin-b shim must exist");

    // DEPENDENCY ISOLATION REQUIREMENT:
    // pkg-c is a transitive dependency of pkg-b.
    // It MUST be nested under pkg-b/node_modules/pkg-c and NOT at root global node_modules!
    let nested_pkg_c = global_nm.join("pkg-b").join("node_modules").join("pkg-c");
    assert!(
        nested_pkg_c.exists(),
        "Transitive dependency pkg-c must be nested under pkg-b/node_modules/pkg-c"
    );
    assert!(
        !global_nm.join("pkg-c").exists(),
        "Transitive dependency pkg-c must NOT be flattened into global root node_modules"
    );
    #[cfg(windows)]
    assert!(
        !global_bin.join("bin-c.cmd").exists(),
        "Transitive dependency bin-c must NOT be placed in global bin dir"
    );
    #[cfg(not(windows))]
    assert!(
        !global_bin.join("bin-c").exists(),
        "Transitive dependency bin-c must NOT be placed in global bin dir"
    );

    // Root package.json / package-lock.json must still NOT exist
    assert!(
        !global_prefix.join("package.json").exists(),
        "global install must not write root package.json"
    );
    assert!(
        !global_prefix.join("package-lock.json").exists(),
        "global install must not write root package-lock.json"
    );

    // 6. Global uninstall of pkg-b
    let uninstall_opts = UninstallOptions {
        packages: vec!["pkg-b".to_string()],
        is_global: true,
        ..Default::default()
    };
    let un_summary = installer_b.uninstall(&uninstall_opts).unwrap();
    assert_eq!(un_summary.removed_packages, vec!["pkg-b"]);

    // pkg-b and its nested dependency must be gone
    assert!(!global_nm.join("pkg-b").exists(), "pkg-b must be removed");
    #[cfg(windows)]
    assert!(
        !global_bin.join("bin-b.cmd").exists(),
        "bin-b shim must be removed"
    );
    #[cfg(not(windows))]
    assert!(
        !global_bin.join("bin-b").exists(),
        "bin-b shim must be removed"
    );

    // CRITICAL REQUIREMENT: pkg-a and its shims MUST still be present after uninstalling pkg-b!
    assert!(
        global_nm.join("pkg-a").exists(),
        "pkg-a must be preserved after uninstalling pkg-b"
    );
    #[cfg(windows)]
    assert!(
        global_bin.join("bin-a.cmd").exists(),
        "bin-a shim must be preserved after uninstalling pkg-b"
    );
    #[cfg(not(windows))]
    assert!(
        global_bin.join("bin-a").exists(),
        "bin-a shim must be preserved after uninstalling pkg-b"
    );

    // Root package.json / package-lock.json must still NOT exist
    assert!(
        !global_prefix.join("package.json").exists(),
        "global uninstall must not write root package.json"
    );
    assert!(
        !global_prefix.join("package-lock.json").exists(),
        "global uninstall must not write root package-lock.json"
    );
}

#[tokio::test]
async fn test_global_scoped_package_isolation_and_uninstall() {
    use rnpm_config::{find_global_bin_dir, find_global_node_modules};

    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let global_prefix = root.join("global-scoped-env");
    fs::create_dir_all(&global_prefix).unwrap();

    let pkg_dir = root.join("scoped-tool");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{
            "name": "@my-scope/scoped-tool",
            "version": "2.1.0",
            "bin": {
                "scoped-cmd": "./cli.js"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        pkg_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('scoped');\n",
    )
    .unwrap();

    let target_spec = format!("@my-scope/scoped-tool@file:{}", pkg_dir.display());

    let options = InstallOptions {
        project_dir: global_prefix.clone(),
        packages: vec![target_spec],
        is_global: true,
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let global_nm = find_global_node_modules(&global_prefix);
    let installed_pkg = global_nm.join("@my-scope").join("scoped-tool");
    assert!(installed_pkg.exists());

    let global_bin = find_global_bin_dir(&global_prefix);
    #[cfg(windows)]
    assert!(global_bin.join("scoped-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("scoped-cmd").exists());

    // Uninstall scoped package
    let uninstall_opts = UninstallOptions {
        packages: vec!["@my-scope/scoped-tool".to_string()],
        is_global: true,
        ..Default::default()
    };
    let un_summary = installer.uninstall(&uninstall_opts).unwrap();
    assert_eq!(un_summary.removed_packages, vec!["@my-scope/scoped-tool"]);

    assert!(!installed_pkg.exists());
    assert!(
        !global_nm.join("@my-scope").exists(),
        "Empty @my-scope directory must be cleaned up"
    );
    #[cfg(windows)]
    assert!(!global_bin.join("scoped-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(!global_bin.join("scoped-cmd").exists());
}

#[test]
fn test_find_enclosing_bin_dir_and_target_rel() {
    use crate::{compute_bin_target_rel, find_enclosing_bin_dir};
    use std::path::{Path, PathBuf};

    let root_nm = Path::new("D:/project/node_modules");
    let root_bin = Path::new("D:/project/node_modules/.bin");

    // 1. Root level package
    let root_pkg = Path::new("D:/project/node_modules/bar");
    assert_eq!(
        find_enclosing_bin_dir(root_pkg, root_bin, root_nm),
        root_bin
    );
    assert_eq!(
        compute_bin_target_rel(root_pkg, root_bin, "bin/bar.js"),
        "bar/bin/bar.js"
    );

    // 2. Root level scoped package
    let scoped_pkg = Path::new("D:/project/node_modules/@scope/bar");
    assert_eq!(
        find_enclosing_bin_dir(scoped_pkg, root_bin, root_nm),
        root_bin
    );
    assert_eq!(
        compute_bin_target_rel(scoped_pkg, root_bin, "bin/bar.js"),
        "@scope/bar/bin/bar.js"
    );

    // 3. Nested package inside parent
    let nested_pkg = Path::new("D:/project/node_modules/parent/node_modules/child");
    let expected_nested_bin = PathBuf::from("D:/project/node_modules/parent/node_modules/.bin");
    assert_eq!(
        find_enclosing_bin_dir(nested_pkg, root_bin, root_nm),
        expected_nested_bin
    );
    assert_eq!(
        compute_bin_target_rel(nested_pkg, &expected_nested_bin, "bin/child.js"),
        "child/bin/child.js"
    );

    // 4. Nested scoped package inside parent
    let nested_scoped_pkg = Path::new("D:/project/node_modules/parent/node_modules/@scope/child");
    assert_eq!(
        find_enclosing_bin_dir(nested_scoped_pkg, root_bin, root_nm),
        expected_nested_bin
    );
    assert_eq!(
        compute_bin_target_rel(nested_scoped_pkg, &expected_nested_bin, "bin/child.js"),
        "@scope/child/bin/child.js"
    );

    // 5. Deeply nested package
    let deep_pkg = Path::new("D:/project/node_modules/a/node_modules/b/node_modules/c");
    let expected_deep_bin =
        PathBuf::from("D:/project/node_modules/a/node_modules/b/node_modules/.bin");
    assert_eq!(
        find_enclosing_bin_dir(deep_pkg, root_bin, root_nm),
        expected_deep_bin
    );
    assert_eq!(
        compute_bin_target_rel(deep_pkg, &expected_deep_bin, "bin/c.js"),
        "c/bin/c.js"
    );

    // 6. Workspace member nested node_modules
    let ws_pkg = Path::new("D:/project/packages/foo/node_modules/bar");
    let expected_ws_bin = PathBuf::from("D:/project/packages/foo/node_modules/.bin");
    assert_eq!(
        find_enclosing_bin_dir(ws_pkg, root_bin, root_nm),
        expected_ws_bin
    );
    assert_eq!(
        compute_bin_target_rel(ws_pkg, &expected_ws_bin, "bin/bar.js"),
        "bar/bin/bar.js"
    );

    // 7. Relative paths
    let rel_root_pkg = Path::new("node_modules/bar");
    let rel_root_nm = Path::new("node_modules");
    let rel_root_bin = Path::new("node_modules/.bin");
    assert_eq!(
        find_enclosing_bin_dir(rel_root_pkg, rel_root_bin, rel_root_nm),
        rel_root_bin
    );

    let rel_nested_pkg = Path::new("node_modules/foo/node_modules/bar");
    assert_eq!(
        find_enclosing_bin_dir(rel_nested_pkg, rel_root_bin, rel_root_nm),
        PathBuf::from("node_modules/foo/node_modules/.bin")
    );
    assert_eq!(
        compute_bin_target_rel(
            rel_nested_pkg,
            Path::new("node_modules/foo/node_modules/.bin"),
            "bin/bar.js"
        ),
        "bar/bin/bar.js"
    );
}

#[tokio::test]
async fn test_shrinkwrap_precedence_over_package_lock_on_install() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create a local dependency
    let dep_dir = root.join("dep-pkg");
    fs::create_dir_all(&dep_dir).unwrap();
    let mut dep_manifest = Manifest::default();
    dep_manifest.name = Some("dep-pkg".to_string());
    dep_manifest.version = Some("1.0.0".to_string());
    dep_manifest
        .save_to_file(dep_dir.join("package.json"))
        .unwrap();

    // 2. Create consumer project
    let project_dir = root.join("consumer");
    fs::create_dir_all(&project_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("consumer".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-pkg".to_string(), "file:../dep-pkg".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Create a dummy package-lock.json with an invalid resolved URL that would fail if used
    let mut dummy_lock = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    dummy_lock.insert_package(
        "node_modules/dep-pkg",
        LockfilePackage {
            version: Some("99.99.99".to_string()),
            resolved: Some("https://invalid.example.com/nonexistent.tgz".to_string()),
            integrity: Some("sha512-invalid==".to_string()),
            ..Default::default()
        },
    );
    dummy_lock
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // Create valid npm-shrinkwrap.json
    let mut sw = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    if let Some(root_pkg) = sw.root_package_mut() {
        let mut deps = BTreeMap::new();
        deps.insert("dep-pkg".to_string(), "file:../dep-pkg".to_string());
        root_pkg.dependencies = Some(deps);
    }
    sw.insert_package(
        "node_modules/dep-pkg",
        LockfilePackage {
            resolved: Some("../dep-pkg".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    sw.insert_package(
        "../dep-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    sw.save_to_file(&project_dir.join("npm-shrinkwrap.json"))
        .unwrap();

    let initial_package_lock_content =
        fs::read_to_string(project_dir.join("package-lock.json")).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();

    // Summary lockfile path MUST be npm-shrinkwrap.json
    assert_eq!(
        summary.lockfile_path,
        project_dir.join("npm-shrinkwrap.json")
    );

    // package-lock.json must NOT have been updated or overwritten
    let current_package_lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert_eq!(current_package_lock, initial_package_lock_content);

    // npm-shrinkwrap.json must exist and be valid
    let loaded_sw = LockfileV3::load_from_file(&project_dir.join("npm-shrinkwrap.json")).unwrap();
    assert!(loaded_sw.packages.contains_key("node_modules/dep-pkg"));

    // node_modules/.package-lock.json must omit the root "" package
    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    assert!(hidden_path.exists());
    let raw_hidden = fs::read_to_string(&hidden_path).unwrap();
    let parsed_hidden: serde_json::Value = serde_json::from_str(&raw_hidden).unwrap();
    assert!(parsed_hidden.get("packages").unwrap().get("").is_none());
}

#[tokio::test]
async fn test_shrinkwrap_precedence_over_package_lock_on_ci() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create a local dependency
    let dep_dir = root.join("dep-pkg");
    fs::create_dir_all(&dep_dir).unwrap();
    let mut dep_manifest = Manifest::default();
    dep_manifest.name = Some("dep-pkg".to_string());
    dep_manifest.version = Some("1.0.0".to_string());
    dep_manifest
        .save_to_file(dep_dir.join("package.json"))
        .unwrap();

    // 2. Create consumer project
    let project_dir = root.join("consumer");
    fs::create_dir_all(&project_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("consumer".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-pkg".to_string(), "file:../dep-pkg".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Create a drifted package-lock.json (missing dep-pkg)
    let drifted_lock = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    drifted_lock
        .save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    // Create valid matching npm-shrinkwrap.json
    let mut sw = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    if let Some(root_pkg) = sw.root_package_mut() {
        let mut deps = BTreeMap::new();
        deps.insert("dep-pkg".to_string(), "file:../dep-pkg".to_string());
        root_pkg.dependencies = Some(deps);
    }
    sw.insert_package(
        "node_modules/dep-pkg",
        LockfilePackage {
            resolved: Some("../dep-pkg".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    sw.insert_package(
        "../dep-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    sw.save_to_file(&project_dir.join("npm-shrinkwrap.json"))
        .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    };

    // run_ci MUST succeed because npm-shrinkwrap.json is valid, ignoring the drifted package-lock.json
    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();

    assert_eq!(
        ci_summary.lockfile_path,
        project_dir.join("npm-shrinkwrap.json")
    );
    assert_eq!(ci_summary.packages_installed, 1);

    // Verify hidden lockfile was created in node_modules/.package-lock.json and omits root ""
    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    assert!(hidden_path.exists());
    let raw_hidden = fs::read_to_string(&hidden_path).unwrap();
    let parsed_hidden: serde_json::Value = serde_json::from_str(&raw_hidden).unwrap();
    assert!(parsed_hidden.get("packages").unwrap().get("").is_none());
    assert_eq!(
        parsed_hidden
            .get("lockfileVersion")
            .unwrap()
            .as_u64()
            .unwrap(),
        3
    );
}

#[tokio::test]
async fn test_shrinkwrap_ci_drift_error_reports_shrinkwrap() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let project_dir = root.join("consumer");
    fs::create_dir_all(&project_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("consumer".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-a".to_string(), "^1.0.0".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    // Create npm-shrinkwrap.json that does not have dep-a
    let sw = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    sw.save_to_file(&project_dir.join("npm-shrinkwrap.json"))
        .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    };

    let mut ci_installer = Installer::new(options).unwrap();
    let err = ci_installer.run_ci().await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("ELOCKFILE_DRIFT"),
        "Error must contain ELOCKFILE_DRIFT: {err_msg}"
    );
    assert!(
        err_msg.contains("npm-shrinkwrap.json"),
        "Error message must reference npm-shrinkwrap.json: {err_msg}"
    );
}

#[tokio::test]
async fn test_local_tarball_prepare_hook_runs() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let marker_path = project_dir.join("local_prepare_ran.txt");
    let escaped_marker = marker_path.to_string_lossy().replace('\\', "/");

    let manifest_json = serde_json::json!({
        "name": "local-tarball-prepare",
        "version": "1.0.0",
        "scripts": {
            "prepare": format!("node -e \"require('fs').writeFileSync('{escaped_marker}', 'local tarball prepare ran')\"")
        }
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest_json).unwrap();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        let path = "package/package.json";
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();
        builder
            .append(&header, std::io::Cursor::new(manifest_bytes))
            .unwrap();
        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let pkgs = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs).unwrap();
    fs::write(pkgs.join("dep-1.0.0.tgz"), &tar_bytes).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("consumer-local-prepare".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.dependencies.insert(
        "local-tarball-prepare".to_string(),
        "file:./pkgs/dep-1.0.0.tgz".to_string(),
    );
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    installer.run().await.unwrap();

    assert!(
        marker_path.exists(),
        "LocalTarball dependency prepare script MUST run during install"
    );
    let content = fs::read_to_string(&marker_path).unwrap();
    assert_eq!(content, "local tarball prepare ran");
}

#[test]
fn test_clean_empty_bin_dirs_removes_empty_and_preserves_non_empty() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let nm = root.join("node_modules");

    // 1. Root .bin (empty)
    let root_bin = nm.join(".bin");
    fs::create_dir_all(&root_bin).unwrap();

    // 2. Package A with empty nested .bin
    let pkg_a_bin = nm.join("pkg-a").join("node_modules").join(".bin");
    fs::create_dir_all(&pkg_a_bin).unwrap();

    // 3. Scoped package C with empty nested .bin
    let pkg_c_bin = nm
        .join("@scope")
        .join("pkg-c")
        .join("node_modules")
        .join(".bin");
    fs::create_dir_all(&pkg_c_bin).unwrap();

    // 4. Package B with non-empty nested .bin
    let pkg_b_bin = nm.join("pkg-b").join("node_modules").join(".bin");
    fs::create_dir_all(&pkg_b_bin).unwrap();
    fs::write(pkg_b_bin.join("some-shim.cmd"), "@echo off\n").unwrap();

    // Run clean_empty_bin_dirs
    crate::clean_empty_bin_dirs(&nm);

    // Empty bin dirs must be removed
    assert!(!root_bin.exists(), "Root empty .bin must be removed");
    assert!(
        !pkg_a_bin.exists(),
        "pkg-a empty nested .bin must be removed"
    );
    assert!(
        !pkg_c_bin.exists(),
        "@scope/pkg-c empty nested .bin must be removed"
    );

    // Non-empty bin dir must remain intact
    assert!(
        pkg_b_bin.exists(),
        "pkg-b non-empty nested .bin must be preserved"
    );
    assert!(pkg_b_bin.join("some-shim.cmd").exists());
}

#[tokio::test]
async fn test_run_ci_does_not_create_nested_bin_when_no_bins_declared() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // 1. Create dependency without bin
    let dep_no_bin = root.join("dep-no-bin");
    fs::create_dir_all(&dep_no_bin).unwrap();
    let mut manifest_no_bin = Manifest::default();
    manifest_no_bin.name = Some("dep-no-bin".to_string());
    manifest_no_bin.version = Some("1.0.0".to_string());
    manifest_no_bin
        .save_to_file(dep_no_bin.join("package.json"))
        .unwrap();

    // 2. Create consumer project
    let project_dir = root.join("consumer");
    fs::create_dir_all(&project_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("consumer".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .dependencies
        .insert("dep-no-bin".to_string(), "file:../dep-no-bin".to_string());
    manifest
        .save_to_file(project_dir.join("package.json"))
        .unwrap();

    let mut lock = LockfileV3::new("consumer", Some("1.0.0".to_string()));
    if let Some(root_pkg) = lock.root_package_mut() {
        let mut deps = BTreeMap::new();
        deps.insert("dep-no-bin".to_string(), "file:../dep-no-bin".to_string());
        root_pkg.dependencies = Some(deps);
    }
    lock.insert_package(
        "node_modules/dep-no-bin",
        LockfilePackage {
            resolved: Some("../dep-no-bin".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lock.insert_package(
        "../dep-no-bin",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            bin: None,
            ..Default::default()
        },
    );
    lock.save_to_file(&project_dir.join("package-lock.json"))
        .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    };

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);

    // Verify:
    // No .bin directory inside node_modules/dep-no-bin
    assert!(!project_dir.join("node_modules/dep-no-bin/.bin").exists());
    assert!(!project_dir
        .join("node_modules/dep-no-bin/node_modules/.bin")
        .exists());
    // Also root .bin should NOT exist because dep-no-bin had no bin
    assert!(!project_dir.join("node_modules/.bin").exists());
}

#[tokio::test]
async fn test_upgrade_bin_shim_overwritten() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    fs::create_dir_all(&project_dir).unwrap();

    let local_a_v1 = tmp.path().join("pkg_a_v1");
    fs::create_dir_all(local_a_v1.join("bin")).unwrap();

    // v1: bin "tool" -> "bin/old.js"
    let pkg_v1 = serde_json::json!({
        "name": "pkg-a",
        "version": "1.0.0",
        "bin": {
            "tool": "bin/old.js"
        }
    });
    fs::write(local_a_v1.join("package.json"), pkg_v1.to_string()).unwrap();
    fs::write(
        local_a_v1.join("bin/old.js"),
        "#!/usr/bin/env node\nconsole.log('old');\n",
    )
    .unwrap();

    let root_pkg = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": format!("file:{}", local_a_v1.display().to_string().replace('\\', "/"))
        }
    });
    fs::write(project_dir.join("package.json"), root_pkg.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    installer.install().await.unwrap();

    let bin_dir = project_dir.join("node_modules/.bin");
    let cmd_file = bin_dir.join("tool.cmd");
    assert!(
        cmd_file.exists(),
        ".bin/tool.cmd must exist after v1 install"
    );
    let content_v1 = fs::read_to_string(&cmd_file).unwrap();
    assert!(
        content_v1.contains("old.js"),
        "v1 shim must point to old.js, got:\n{content_v1}"
    );

    // Now upgrade pkg-a to v2 with bin "tool" -> "bin/new.js"
    let local_a_v2 = tmp.path().join("pkg_a_v2");
    fs::create_dir_all(local_a_v2.join("bin")).unwrap();
    let pkg_v2 = serde_json::json!({
        "name": "pkg-a",
        "version": "2.0.0",
        "bin": {
            "tool": "bin/new.js"
        }
    });
    fs::write(local_a_v2.join("package.json"), pkg_v2.to_string()).unwrap();
    fs::write(
        local_a_v2.join("bin/new.js"),
        "#!/usr/bin/env node\nconsole.log('new');\n",
    )
    .unwrap();

    let root_pkg_v2 = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": format!("file:{}", local_a_v2.display().to_string().replace('\\', "/"))
        }
    });
    fs::write(project_dir.join("package.json"), root_pkg_v2.to_string()).unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    installer2.install().await.unwrap();

    assert!(
        cmd_file.exists(),
        ".bin/tool.cmd must exist after v2 upgrade"
    );
    let content_v2 = fs::read_to_string(&cmd_file).unwrap();
    assert!(
        content_v2.contains("new.js"),
        "v2 shim must point to new.js, got:\n{content_v2}"
    );
    assert!(
        !content_v2.contains("old.js"),
        "v2 shim must not point to old.js, got:\n{content_v2}"
    );
}

#[tokio::test]
async fn test_scoped_bin_conflict_precedence() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    fs::create_dir_all(&project_dir).unwrap();

    let local_aa = tmp.path().join("local_aa");
    fs::create_dir_all(&local_aa).unwrap();
    let aa_pkg = serde_json::json!({
        "name": "@aa/tool",
        "version": "1.0.0",
        "bin": {
            "tool": "t.js"
        }
    });
    fs::write(local_aa.join("package.json"), aa_pkg.to_string()).unwrap();
    fs::write(
        local_aa.join("t.js"),
        "#!/usr/bin/env node\nconsole.log('aa');\n",
    )
    .unwrap();

    let local_zz = tmp.path().join("local_zz");
    fs::create_dir_all(&local_zz).unwrap();
    let zz_pkg = serde_json::json!({
        "name": "zz-tool",
        "version": "1.0.0",
        "bin": {
            "tool": "t.js"
        }
    });
    fs::write(local_zz.join("package.json"), zz_pkg.to_string()).unwrap();
    fs::write(
        local_zz.join("t.js"),
        "#!/usr/bin/env node\nconsole.log('zz');\n",
    )
    .unwrap();

    let root_pkg = serde_json::json!({
        "name": "bin-conflict-fixture",
        "version": "1.0.0",
        "dependencies": {
            "@aa/tool": format!("file:{}", local_aa.display().to_string().replace('\\', "/")),
            "zz-tool": format!("file:{}", local_zz.display().to_string().replace('\\', "/"))
        }
    });
    fs::write(project_dir.join("package.json"), root_pkg.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    installer.install().await.unwrap();

    let bin_dir = project_dir.join("node_modules/.bin");
    let cmd_file = bin_dir.join("tool.cmd");
    assert!(cmd_file.exists());
    let content = fs::read_to_string(&cmd_file).unwrap();
    assert!(
        content.contains("@aa/tool") || content.contains(r"@aa\tool"),
        "@aa/tool must win bin conflict over zz-tool, got:\n{content}"
    );
    assert!(
        !content.contains("zz-tool"),
        "zz-tool must lose bin conflict, got:\n{content}"
    );
}

#[tokio::test]
async fn test_stale_shim_removed_on_upgrade() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    fs::create_dir_all(&project_dir).unwrap();

    let local_a_v1 = tmp.path().join("pkg_a_v1");
    fs::create_dir_all(local_a_v1.join("bin")).unwrap();

    // v1 has two bins: "tool1" and "tool2"
    let pkg_v1 = serde_json::json!({
        "name": "pkg-a",
        "version": "1.0.0",
        "bin": {
            "tool1": "bin/t1.js",
            "tool2": "bin/t2.js"
        }
    });
    fs::write(local_a_v1.join("package.json"), pkg_v1.to_string()).unwrap();
    fs::write(local_a_v1.join("bin/t1.js"), "#!/usr/bin/env node\n").unwrap();
    fs::write(local_a_v1.join("bin/t2.js"), "#!/usr/bin/env node\n").unwrap();

    let root_pkg = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": format!("file:{}", local_a_v1.display().to_string().replace('\\', "/"))
        }
    });
    fs::write(project_dir.join("package.json"), root_pkg.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    installer.install().await.unwrap();

    let bin_dir = project_dir.join("node_modules/.bin");
    assert!(bin_dir.join("tool1.cmd").exists());
    assert!(bin_dir.join("tool2.cmd").exists());

    // v2 only has "tool1", "tool2" removed
    let local_a_v2 = tmp.path().join("pkg_a_v2");
    fs::create_dir_all(local_a_v2.join("bin")).unwrap();
    let pkg_v2 = serde_json::json!({
        "name": "pkg-a",
        "version": "2.0.0",
        "bin": {
            "tool1": "bin/t1.js"
        }
    });
    fs::write(local_a_v2.join("package.json"), pkg_v2.to_string()).unwrap();
    fs::write(local_a_v2.join("bin/t1.js"), "#!/usr/bin/env node\n").unwrap();

    let root_pkg_v2 = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": format!("file:{}", local_a_v2.display().to_string().replace('\\', "/"))
        }
    });
    fs::write(project_dir.join("package.json"), root_pkg_v2.to_string()).unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: project_dir.clone(),
        offline: true,
        ..Default::default()
    })
    .unwrap();

    installer2.install().await.unwrap();

    assert!(
        bin_dir.join("tool1.cmd").exists(),
        "tool1 shim must be preserved"
    );
    assert!(
        !bin_dir.join("tool2.cmd").exists(),
        "stale tool2.cmd shim must be removed"
    );
    assert!(
        !bin_dir.join("tool2.ps1").exists(),
        "stale tool2.ps1 shim must be removed"
    );
    assert!(
        !bin_dir.join("tool2").exists(),
        "stale tool2 POSIX shim must be removed"
    );
}

#[test]
fn test_enrich_lockfile_ignores_deprecated_licenses_array() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let nm = project_dir.join("node_modules").join("legacy-pkg");
    fs::create_dir_all(&nm).unwrap();
    let legacy_json = serde_json::json!({
        "name": "legacy-pkg",
        "version": "1.0.0",
        "licenses": [
            { "type": "MIT", "url": "http://example.com" }
        ]
    });
    fs::write(
        nm.join("package.json"),
        serde_json::to_string(&legacy_json).unwrap(),
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-app", Some("1.0.0".to_string()));
    lockfile.insert_package(
        "node_modules/legacy-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    crate::fast_path::enrich_lockfile_from_installed_manifests(&mut lockfile, project_dir, None);

    let pkg = lockfile.packages.get("node_modules/legacy-pkg").unwrap();
    assert_eq!(
        pkg.license, None,
        "Deprecated licenses array must not synthesize a license field, matching npm 11"
    );
}

#[tokio::test]
async fn test_enrich_lockfile_never_makes_network_requests() {
    use rnpm_registry::{http_request_count, reset_http_request_count};

    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    reset_http_request_count();

    let mut lockfile = LockfileV3::new("no-net-app", Some("1.0.0".to_string()));
    lockfile.insert_package(
        "node_modules/nonexistent-package-with-no-license",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let options = InstallOptions {
        project_dir: project_dir.to_path_buf(),
        offline: false,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();

    let before_requests = http_request_count();
    installer
        .enrich_lockfile_from_registry(&mut lockfile)
        .await
        .unwrap();
    let after_requests = http_request_count();

    assert_eq!(
        before_requests, after_requests,
        "enrich_lockfile_from_registry must never make network requests"
    );
}

#[tokio::test]
async fn test_enrich_lockfile_from_cacache_packument() {
    let temp_project = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let cache = rnpm_cache::Cache::new(temp_cache.path()).unwrap();
    let reg_url = "https://registry.npmjs.org";
    let pkg_name = "fsevents";
    let version = "2.3.3";
    let full_url = format!("{reg_url}/{pkg_name}");
    let cacache_key = format!("make-fetch-happen:request-cache:{full_url}");

    let mock_full_packument = serde_json::json!({
        "name": pkg_name,
        "versions": {
            version: {
                "name": pkg_name,
                "version": version,
                "license": "MIT",
                "dist": {
                    "tarball": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                    "integrity": "sha512-test"
                }
            }
        }
    });
    let data = serde_json::to_vec(&mock_full_packument).unwrap();
    cache.put(&cacache_key, &data, None).unwrap();

    let mut lockfile = LockfileV3::new("test", Some("1.0.0".to_string()));
    lockfile.insert_package(
        &format!("node_modules/{pkg_name}"),
        LockfilePackage {
            name: Some(pkg_name.to_string()),
            version: Some(version.to_string()),
            ..Default::default()
        },
    );

    let options = InstallOptions {
        project_dir: temp_project.path().to_path_buf(),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer
        .enrich_lockfile_from_registry(&mut lockfile)
        .await
        .unwrap();

    let pkg = lockfile
        .packages
        .get(&format!("node_modules/{pkg_name}"))
        .unwrap();
    assert_eq!(pkg.license.as_deref(), Some("MIT"));
}

#[tokio::test]
async fn test_enrich_lockfile_with_scoped_package_license_and_libc() {
    let mut lockfile = LockfileV3::new("test", Some("1.0.0".to_string()));
    lockfile.insert_package(
        "node_modules/@next/swc-linux-x64-musl",
        LockfilePackage {
            version: Some("14.2.5".to_string()),
            os: Some(vec!["linux".to_string()]),
            ..Default::default()
        },
    );
    let mut installer = Installer::new(InstallOptions::default()).unwrap();
    installer
        .enrich_lockfile_from_registry(&mut lockfile)
        .await
        .unwrap();

    let pkg = lockfile
        .packages
        .get("node_modules/@next/swc-linux-x64-musl")
        .unwrap();
    if pkg.license.is_some() {
        assert_eq!(pkg.license.as_deref(), Some("MIT"));
        assert_eq!(pkg.libc.as_deref(), Some(&["musl".to_string()][..]));
    }
}

#[tokio::test]
async fn public_lockfile_precedes_root_hooks_and_survives_failure() {
    for hook in ["preinstall", "postinstall", "prepare"] {
        let tmp = tempdir().unwrap();
        let root = tmp.path().join("project");
        fs::create_dir_all(&root).unwrap();
        let script = "node -e \"if(!require('fs').existsSync('package-lock.json'))process.exit(91);process.exit(7)\"";
        let manifest = serde_json::json!({"name":"root-hook-order", "version":"1.0.0", "scripts":{hook:script}});
        fs::write(root.join("package.json"), manifest.to_string()).unwrap();
        let options = InstallOptions {
            project_dir: root.clone(),
            cache_dir: Some(tmp.path().join("cache")),
            offline: true,
            ..Default::default()
        };
        let error = Installer::new(options).unwrap().run().await.unwrap_err();
        let exit = error
            .downcast_ref::<rnpm_lifecycle::ScriptExitError>()
            .unwrap();
        assert_eq!(exit.exit_code, 7, "{hook}: {error:#}");
        let lock: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("package-lock.json")).unwrap()).unwrap();
        assert_eq!(lock["packages"][""]["name"], "root-hook-order");
        assert!(!root.join("node_modules/.package-lock.json").exists());
    }
}

#[tokio::test]
async fn filtered_workspace_reify_keeps_unselected_members_only_in_public_lock() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    for name in ["first", "second"] {
        fs::create_dir_all(root.join("packages").join(name)).unwrap();
        fs::write(
            root.join("packages").join(name).join("package.json"),
            format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }
    let options = InstallOptions {
        project_dir: root.clone(),
        cache_dir: Some(tmp.path().join("cache")),
        workspace: vec!["first".into()],
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let summary = Installer::new(options).unwrap().run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);
    assert!(root.join("node_modules/first/package.json").is_file());
    assert!(!root.join("node_modules/second").exists());
    let public: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("package-lock.json")).unwrap()).unwrap();
    assert!(public["packages"]["packages/first"].get("name").is_none());
    assert!(public["packages"]["packages/second"].is_object());
    let hidden: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("node_modules/.package-lock.json")).unwrap())
            .unwrap();
    assert!(hidden["packages"]["packages/first"].is_object());
    assert!(hidden["packages"].get("packages/second").is_none());
    assert!(hidden["packages"].get("node_modules/second").is_none());
}
