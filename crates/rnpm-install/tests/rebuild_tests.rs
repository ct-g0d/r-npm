use std::fs;
use tempfile::tempdir;

use rnpm_install::rebuild::{execute_rebuild, matches_rebuild_filter, RebuildOptions};

#[test]
fn test_matches_rebuild_filter() {
    assert!(matches_rebuild_filter("fsevents", "fsevents", Some("2.3.2"), "node_modules/fsevents"));
    assert!(matches_rebuild_filter("fsevents@2.3.2", "fsevents", Some("2.3.2"), "node_modules/fsevents"));
    assert!(matches_rebuild_filter("node_modules/fsevents", "fsevents", Some("2.3.2"), "node_modules/fsevents"));

    // Scoped package matching
    assert!(matches_rebuild_filter("@scope/native", "@scope/native", Some("1.0.0"), "node_modules/@scope/native"));
    assert!(matches_rebuild_filter("native", "@scope/native", Some("1.0.0"), "node_modules/@scope/native"));
    assert!(matches_rebuild_filter("@scope/native@1.0.0", "@scope/native", Some("1.0.0"), "node_modules/@scope/native"));

    // Non-matching
    assert!(!matches_rebuild_filter("other", "fsevents", Some("2.3.2"), "node_modules/fsevents"));
    assert!(!matches_rebuild_filter("fsevents@1.0.0", "fsevents", Some("2.3.2"), "node_modules/fsevents"));
}

#[tokio::test]
async fn test_rebuild_executes_installed_lifecycle_scripts() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Create marker files
    let marker_file = root.join("rebuild_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_a = root.join("node_modules").join("pkg-a");
    let pkg_b = root.join("node_modules").join("pkg-b");
    fs::create_dir_all(&pkg_a).unwrap();
    fs::create_dir_all(&pkg_b).unwrap();

    // pkg-a has install script
    fs::write(
        pkg_a.join("package.json"),
        format!(
            r#"{{"name": "pkg-a", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a:install\\n')\""}}}}"#
        ),
    ).unwrap();

    // pkg-b has postinstall script
    fs::write(
        pkg_b.join("package.json"),
        format!(
            r#"{{"name": "pkg-b", "version": "2.0.0", "scripts": {{"postinstall": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-b:postinstall\\n')\""}}}}"#
        ),
    ).unwrap();

    let opts = RebuildOptions {
        project_dir: root.to_path_buf(),
        packages: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
    };

    let summary = execute_rebuild(&opts).await.expect("Rebuild should succeed");
    assert_eq!(summary.rebuilt_packages.len(), 2);

    let content = fs::read_to_string(&marker_file).expect("Marker file should be created");
    assert!(content.contains("pkg-a:install"));
    assert!(content.contains("pkg-b:postinstall"));
}

#[tokio::test]
async fn test_rebuild_selective_packages() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let marker_file = root.join("selective_rebuild_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let target_pkg = root.join("node_modules").join("target-pkg");
    let other_pkg = root.join("node_modules").join("other-pkg");
    fs::create_dir_all(&target_pkg).unwrap();
    fs::create_dir_all(&other_pkg).unwrap();

    fs::write(
        target_pkg.join("package.json"),
        format!(
            r#"{{"name": "target-pkg", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'target-rebuilt\\n')\""}}}}"#
        ),
    ).unwrap();

    fs::write(
        other_pkg.join("package.json"),
        format!(
            r#"{{"name": "other-pkg", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'other-rebuilt\\n')\""}}}}"#
        ),
    ).unwrap();

    // Rebuild only target-pkg
    let opts = RebuildOptions {
        project_dir: root.to_path_buf(),
        packages: vec!["target-pkg".to_string()],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
    };

    let summary = execute_rebuild(&opts).await.expect("Selective rebuild should succeed");
    assert_eq!(summary.rebuilt_packages, vec!["target-pkg@1.0.0"]);

    let content = fs::read_to_string(&marker_file).unwrap();
    assert!(content.contains("target-rebuilt"));
    assert!(!content.contains("other-rebuilt"), "other-pkg should NOT be rebuilt");
}

#[tokio::test]
async fn test_rebuild_native_addon_with_binding_gyp() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let native_pkg = root.join("node_modules").join("native-addon");
    fs::create_dir_all(&native_pkg).unwrap();

    // Create binding.gyp file
    fs::write(native_pkg.join("binding.gyp"), "{}").unwrap();

    // package.json without explicit install script
    fs::write(
        native_pkg.join("package.json"),
        r#"{"name": "native-addon", "version": "1.0.0"}"#,
    ).unwrap();

    // Create a mock node-gyp in node_modules/.bin so node-gyp rebuild executes cleanly
    let bin_dir = root.join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let marker_file = root.join("gyp_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let mock_gyp_js = format!(
        "require('fs').writeFileSync('{escaped_marker}', 'node-gyp rebuild invoked'); process.exit(0);"
    );
    let mock_gyp_path = root.join("mock_gyp.js");
    fs::write(&mock_gyp_path, mock_gyp_js).unwrap();

    let escaped_mock_gyp = mock_gyp_path.to_string_lossy().replace('\\', "/");

    #[cfg(windows)]
    {
        fs::write(bin_dir.join("node-gyp.cmd"), format!("@node \"{escaped_mock_gyp}\" %*\n")).unwrap();
        fs::write(bin_dir.join("node-gyp"), format!("#!/bin/sh\nnode \"{escaped_mock_gyp}\" \"$@\"\n")).unwrap();
    }
    #[cfg(not(windows))]
    {
        let script = bin_dir.join("node-gyp");
        fs::write(&script, format!("#!/bin/sh\nnode \"{escaped_mock_gyp}\" \"$@\"\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).unwrap();
        }
    }

    let opts = RebuildOptions {
        project_dir: root.to_path_buf(),
        packages: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
    };

    let summary = execute_rebuild(&opts).await.expect("Native addon rebuild should succeed");
    assert_eq!(summary.rebuilt_packages, vec!["native-addon@1.0.0"]);

    // Verify mock node-gyp rebuild was called
    assert!(marker_file.exists(), "binding.gyp presence must automatically invoke node-gyp rebuild");
    let content = fs::read_to_string(&marker_file).unwrap();
    assert_eq!(content, "node-gyp rebuild invoked");
}

#[tokio::test]
async fn test_rebuild_ignore_scripts_flag() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let marker_file = root.join("ignore_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg = root.join("node_modules").join("any-pkg");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(
        pkg.join("package.json"),
        format!(
            r#"{{"name": "any-pkg", "version": "1.0.0", "scripts": {{"install": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'ran')\""}}}}"#
        ),
    ).unwrap();

    let opts = RebuildOptions {
        project_dir: root.to_path_buf(),
        packages: vec![],
        ignore_scripts: true,
        foreground_scripts: false,
        strict_sandbox: false,
    };

    let summary = execute_rebuild(&opts).await.expect("Rebuild with ignore-scripts should succeed");
    assert_eq!(summary.rebuilt_packages.len(), 0);
    assert!(!marker_file.exists(), "--ignore-scripts must prevent any scripts from running");
}
