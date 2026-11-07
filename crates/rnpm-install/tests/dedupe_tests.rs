use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

use rnpm_core::manifest::Manifest;
use rnpm_install::dedupe::{
    execute_dedupe, version_matches_range, DedupeActionType, DedupeOptions,
};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

#[test]
fn test_version_matches_range() {
    assert!(version_matches_range("1.2.3", "^1.0.0"));
    assert!(version_matches_range("1.2.3", "~1.2.0"));
    assert!(version_matches_range("2.0.0", ">=1.0.0"));
    assert!(version_matches_range("1.0.0", "*"));
    assert!(version_matches_range("1.0.0", ""));
    assert!(version_matches_range("1.2.0", "1.2.0"));

    assert!(!version_matches_range("2.0.0", "^1.0.0"));
    assert!(!version_matches_range("1.3.0", "~1.2.0"));
    assert!(!version_matches_range("0.9.0", ">=1.0.0"));
}

#[test]
fn test_dedupe_redundant_nested_duplicate_with_root_ancestor() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Setup root package.json: depends on "parent-a" and "shared-pkg"
    let root_pkg = serde_json::json!({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "parent-a": "^1.0.0",
            "shared-pkg": "^1.0.0"
        }
    });
    fs::write(
        root.join("package.json"),
        serde_json::to_string_pretty(&root_pkg).unwrap(),
    )
    .unwrap();

    // Create root node_modules/shared-pkg (v1.2.0)
    let root_shared = root.join("node_modules").join("shared-pkg");
    fs::create_dir_all(&root_shared).unwrap();
    fs::write(
        root_shared.join("package.json"),
        r#"{"name": "shared-pkg", "version": "1.2.0"}"#,
    )
    .unwrap();

    // Create node_modules/parent-a (v1.0.0), which declares dependency "shared-pkg": "^1.0.0"
    let parent_a = root.join("node_modules").join("parent-a");
    fs::create_dir_all(&parent_a).unwrap();
    fs::write(
        parent_a.join("package.json"),
        r#"{"name": "parent-a", "version": "1.0.0", "dependencies": {"shared-pkg": "^1.0.0"}}"#,
    )
    .unwrap();

    // Create redundant nested duplicate: node_modules/parent-a/node_modules/shared-pkg (v1.0.0)
    let nested_shared = parent_a.join("node_modules").join("shared-pkg");
    fs::create_dir_all(&nested_shared).unwrap();
    fs::write(
        nested_shared.join("package.json"),
        r#"{"name": "shared-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Create package-lock.json with both entries
    let mut lock = LockfileV3::new("test-project", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/parent-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(BTreeMap::from([(
                "shared-pkg".to_string(),
                "^1.0.0".to_string(),
            )])),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/shared-pkg",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/parent-a/node_modules/shared-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.save_to_file(&root.join("package-lock.json")).unwrap();

    // Execute dedupe
    let opts = DedupeOptions {
        project_dir: root.to_path_buf(),
        dry_run: false,
        packages: vec![],
    };
    let summary = execute_dedupe(&opts).expect("Dedupe should succeed");

    // Redundant nested copy must be deleted
    assert_eq!(summary.actions.len(), 1);
    assert_eq!(
        summary.actions[0].action_type,
        DedupeActionType::DeleteDuplicate
    );
    assert_eq!(
        summary.actions[0].original_path,
        "node_modules/parent-a/node_modules/shared-pkg"
    );
    assert_eq!(summary.actions[0].target_path, "node_modules/shared-pkg");

    // Filesystem check: nested copy must no longer exist on disk
    assert!(
        !nested_shared.exists(),
        "Nested duplicate must be deleted from disk"
    );
    // Root shared-pkg must remain intact
    assert!(
        root_shared.exists(),
        "Root shared package must be preserved"
    );

    // Lockfile check: nested package must be removed from package-lock.json
    let updated_lock = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    assert!(updated_lock
        .get_package("node_modules/shared-pkg")
        .is_some());
    assert!(updated_lock
        .get_package("node_modules/parent-a/node_modules/shared-pkg")
        .is_none());
}

#[test]
fn test_dedupe_hoist_and_dedupe_when_root_vacant() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Root package depends on "lib-a" and "lib-b"
    fs::write(
        root.join("package.json"),
        r#"{"name": "vacant-root-test", "version": "1.0.0", "dependencies": {"lib-a": "^1.0.0", "lib-b": "^1.0.0"}}"#,
    ).unwrap();

    // lib-a has nested helper@1.2.0
    let lib_a = root.join("node_modules").join("lib-a");
    let lib_a_helper = lib_a.join("node_modules").join("helper");
    fs::create_dir_all(&lib_a_helper).unwrap();
    fs::write(
        lib_a.join("package.json"),
        r#"{"name": "lib-a", "version": "1.0.0", "dependencies": {"helper": "^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        lib_a_helper.join("package.json"),
        r#"{"name": "helper", "version": "1.2.0"}"#,
    )
    .unwrap();

    // lib-b has nested helper@1.0.0
    let lib_b = root.join("node_modules").join("lib-b");
    let lib_b_helper = lib_b.join("node_modules").join("helper");
    fs::create_dir_all(&lib_b_helper).unwrap();
    fs::write(
        lib_b.join("package.json"),
        r#"{"name": "lib-b", "version": "1.0.0", "dependencies": {"helper": "^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        lib_b_helper.join("package.json"),
        r#"{"name": "helper", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Lockfile
    let mut lock = LockfileV3::new("vacant-root-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/lib-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(BTreeMap::from([(
                "helper".to_string(),
                "^1.0.0".to_string(),
            )])),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/lib-a/node_modules/helper",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/lib-b",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(BTreeMap::from([(
                "helper".to_string(),
                "^1.0.0".to_string(),
            )])),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/lib-b/node_modules/helper",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.save_to_file(&root.join("package-lock.json")).unwrap();

    // Execute dedupe
    let opts = DedupeOptions {
        project_dir: root.to_path_buf(),
        dry_run: false,
        packages: vec![],
    };
    let summary = execute_dedupe(&opts).expect("Dedupe should succeed");

    // Should hoist helper@1.2.0 to node_modules/helper and delete the redundant duplicate
    assert!(summary
        .actions
        .iter()
        .any(|a| a.action_type == DedupeActionType::HoistAndDedupe));
    assert!(summary
        .actions
        .iter()
        .any(|a| a.action_type == DedupeActionType::DeleteDuplicate));

    // Filesystem check: node_modules/helper must now exist with v1.2.0
    let root_helper = root.join("node_modules").join("helper");
    assert!(
        root_helper.exists(),
        "Helper must be hoisted to shallowest ancestor level (root node_modules)"
    );
    let hoisted_manifest: Manifest = Manifest::from_file(root_helper.join("package.json")).unwrap();
    assert_eq!(hoisted_manifest.version.as_deref(), Some("1.2.0"));

    // Nested directories must be deleted
    assert!(
        !lib_a_helper.exists(),
        "lib-a nested helper must be deleted"
    );
    assert!(
        !lib_b_helper.exists(),
        "lib-b nested helper must be deleted"
    );

    // Lockfile check
    let updated_lock = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    assert!(updated_lock.get_package("node_modules/helper").is_some());
    assert!(updated_lock
        .get_package("node_modules/lib-a/node_modules/helper")
        .is_none());
    assert!(updated_lock
        .get_package("node_modules/lib-b/node_modules/helper")
        .is_none());
}

#[test]
fn test_dedupe_dry_run_preserves_files_and_lockfile() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    fs::write(
        root.join("package.json"),
        r#"{"name": "dry-run-test", "version": "1.0.0", "dependencies": {"mod-a": "^1.0.0", "common": "^1.0.0"}}"#,
    ).unwrap();

    let root_common = root.join("node_modules").join("common");
    fs::create_dir_all(&root_common).unwrap();
    fs::write(
        root_common.join("package.json"),
        r#"{"name": "common", "version": "1.5.0"}"#,
    )
    .unwrap();

    let mod_a = root.join("node_modules").join("mod-a");
    let nested_common = mod_a.join("node_modules").join("common");
    fs::create_dir_all(&nested_common).unwrap();
    fs::write(
        mod_a.join("package.json"),
        r#"{"name": "mod-a", "version": "1.0.0", "dependencies": {"common": "^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        nested_common.join("package.json"),
        r#"{"name": "common", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut lock = LockfileV3::new("dry-run-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/common",
        LockfilePackage {
            version: Some("1.5.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/mod-a/node_modules/common",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.save_to_file(&root.join("package-lock.json")).unwrap();

    // Run with dry_run = true
    let opts = DedupeOptions {
        project_dir: root.to_path_buf(),
        dry_run: true,
        packages: vec![],
    };
    let summary = execute_dedupe(&opts).expect("Dry run should succeed");

    // Must report deduplication action
    assert_eq!(summary.actions.len(), 1);
    assert_eq!(
        summary.actions[0].action_type,
        DedupeActionType::DeleteDuplicate
    );
    assert_eq!(
        summary.actions[0].original_path,
        "node_modules/mod-a/node_modules/common"
    );

    // Filesystem must NOT be changed in dry-run mode
    assert!(
        nested_common.exists(),
        "Dry-run mode MUST NOT delete nested duplicate files"
    );
    assert!(root_common.exists());

    // Lockfile must NOT be changed in dry-run mode
    let current_lock = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    assert!(current_lock
        .get_package("node_modules/mod-a/node_modules/common")
        .is_some());
}

#[test]
fn test_dedupe_scoped_packages() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    fs::write(
        root.join("package.json"),
        r#"{"name": "scoped-dedupe-test", "version": "1.0.0", "dependencies": {"wrapper": "^1.0.0", "@scope/util": "^1.0.0"}}"#,
    ).unwrap();

    let root_scoped = root.join("node_modules").join("@scope").join("util");
    fs::create_dir_all(&root_scoped).unwrap();
    fs::write(
        root_scoped.join("package.json"),
        r#"{"name": "@scope/util", "version": "1.2.0"}"#,
    )
    .unwrap();

    let wrapper = root.join("node_modules").join("wrapper");
    let nested_scoped = wrapper.join("node_modules").join("@scope").join("util");
    fs::create_dir_all(&nested_scoped).unwrap();
    fs::write(
        wrapper.join("package.json"),
        r#"{"name": "wrapper", "version": "1.0.0", "dependencies": {"@scope/util": "^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        nested_scoped.join("package.json"),
        r#"{"name": "@scope/util", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut lock = LockfileV3::new("scoped-dedupe-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/@scope/util",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/wrapper/node_modules/@scope/util",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.save_to_file(&root.join("package-lock.json")).unwrap();

    let opts = DedupeOptions {
        project_dir: root.to_path_buf(),
        dry_run: false,
        packages: vec![],
    };
    let summary = execute_dedupe(&opts).expect("Scoped dedupe should succeed");

    assert_eq!(summary.actions.len(), 1);
    assert_eq!(summary.actions[0].package_name, "@scope/util");
    assert_eq!(
        summary.actions[0].original_path,
        "node_modules/wrapper/node_modules/@scope/util"
    );

    assert!(!nested_scoped.exists());
    assert!(root_scoped.exists());
}
