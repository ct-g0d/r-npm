use std::fs;
use tempfile::tempdir;
use crate::{Installer, InstallOptions};
use rnpm_fs::is_junction;
use rnpm_lockfile::LockfileV3;

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
