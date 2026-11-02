use crate::*;
use std::path::PathBuf;

#[test]
fn test_is_sensitive_credential_key() {
    assert!(is_sensitive_credential_key("NPM_TOKEN"));
    assert!(is_sensitive_credential_key("_authToken"));
    assert!(is_sensitive_credential_key("//registry.npmjs.org/:_authToken"));
    assert!(is_sensitive_credential_key("npm_config_password"));
    assert!(is_sensitive_credential_key("secret_key"));
    assert!(is_sensitive_credential_key("AUTH_TOKEN"));
    assert!(is_sensitive_credential_key("_auth"));

    // Non-sensitive keys
    assert!(!is_sensitive_credential_key("PATH"));
    assert!(!is_sensitive_credential_key("AUTHOR"));
    assert!(!is_sensitive_credential_key("npm_package_author"));
    assert!(!is_sensitive_credential_key("INIT_CWD"));
    assert!(!is_sensitive_credential_key("NODE_ENV"));
}

#[test]
fn test_build_lifecycle_env_scrubbing() {
    let mut ctx = LifecycleContext::new(
        PathBuf::from("/project"),
        PathBuf::from("/project/node_modules/my-pkg"),
        "my-pkg",
        "postinstall",
        "echo 1",
    );
    ctx.extra_env.insert("npm_config__authToken".to_string(), "leak_token_123".to_string());
    ctx.extra_env.insert("//127.0.0.1:4873/:_authToken".to_string(), "leak_token_456".to_string());
    ctx.extra_env.insert("SAFE_VAR".to_string(), "safe_value".to_string());

    let env = build_lifecycle_env(&ctx);

    assert_eq!(env.get("SAFE_VAR").unwrap(), "safe_value");
    assert_eq!(env.get("npm_lifecycle_event").unwrap(), "postinstall");
    assert_eq!(env.get("npm_package_name").unwrap(), "my-pkg");
    assert_eq!(env.get("INIT_CWD").unwrap(), "/project");

    // Verify sensitive keys are scrubbed
    assert!(!env.contains_key("npm_config__authToken"));
    assert!(!env.contains_key("//127.0.0.1:4873/:_authToken"));
}

#[test]
fn test_execute_lifecycle_script_runs() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "node -e \"process.exit(0)\"",
    );
    let status = execute_lifecycle_script(&ctx).unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_optional_lifecycle_script_failure_isolation() {
    let temp = tempfile::tempdir().unwrap();
    let pkg_dir = temp.path().join("node_modules").join("failing-opt-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let mut failing_manifest = Manifest::default();
    failing_manifest.name = Some("failing-opt-pkg".to_string());
    failing_manifest.version = Some("1.0.0".to_string());
    failing_manifest.scripts.insert("install".to_string(), "node -e \"process.exit(1)\"".to_string());

    let node = LifecyclePackageNode {
        package_path: "node_modules/failing-opt-pkg".to_string(),
        disk_path: pkg_dir.clone(),
        manifest: failing_manifest.clone(),
        source: PackageSource::Registry,
        dependencies: vec![],
        optional: true,
    };

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions {
        root_dir: temp.path().to_path_buf(),
        init_cwd: temp.path().to_path_buf(),
        ignore_scripts: false,
        capture_output: true,
    };

    // When optional is true, script failure is isolated and does NOT fail execution
    let res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(res.is_ok(), "Optional script failure should not fail execute_topological");

    // Contrast with optional = false: MUST fail!
    let non_opt_pkg_dir = temp.path().join("node_modules").join("failing-req-pkg");
    std::fs::create_dir_all(&non_opt_pkg_dir).unwrap();

    let req_node = LifecyclePackageNode {
        package_path: "node_modules/failing-req-pkg".to_string(),
        disk_path: non_opt_pkg_dir,
        manifest: failing_manifest,
        source: PackageSource::Registry,
        dependencies: vec![],
        optional: false,
    };

    let req_res = execute_topological(&[req_node], &root_manifest, &opts).await;
    assert!(req_res.is_err(), "Required script failure MUST fail execute_topological");
}

#[test]
fn test_process_tree_guard_containment() {
    let guard = process_guard::ProcessTreeGuard::new();
    assert!(guard.is_some(), "Job object / process tree guard should be created");

    // Terminate empty guard returns true (or success)
    if let Some(g) = guard {
        assert!(g.terminate(0));
    }
}

#[tokio::test]
async fn test_execute_workspace_scripts_topological() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Set up two workspace packages: lib-a and app (app depends on lib-a)
    let lib_a_dir = root.join("packages").join("lib-a");
    let app_dir = root.join("packages").join("app");
    std::fs::create_dir_all(&lib_a_dir).unwrap();
    std::fs::create_dir_all(&app_dir).unwrap();

    let marker_file = root.join("run_order.txt");

    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("lib-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    // Write "lib-a\n" to marker_file
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");
    manifest_a.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'lib-a\\n')\""),
    );

    let mut manifest_app = Manifest::default();
    manifest_app.name = Some("app".to_string());
    manifest_app.version = Some("2.0.0".to_string());
    manifest_app.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'app\\n')\""),
    );

    let members = vec![
        WorkspaceScriptMember {
            name: "lib-a".to_string(),
            path: lib_a_dir,
            manifest: manifest_a,
        },
        WorkspaceScriptMember {
            name: "app".to_string(),
            path: app_dir,
            manifest: manifest_app,
        },
    ];

    // Topological order: leaf ("lib-a") first, then dependent ("app")
    let topo_order = vec!["lib-a".to_string(), "app".to_string()];

    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        if_present: false,
        filter_members: None,
    };

    let summary = execute_workspace_scripts_topological(root, &members, &topo_order, &opts)
        .await
        .unwrap();

    assert_eq!(summary.executed_packages, vec!["lib-a", "app"]);

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["lib-a", "app"]);
}
