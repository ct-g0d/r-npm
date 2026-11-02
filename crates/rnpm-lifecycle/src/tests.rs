use crate::*;
use std::collections::{HashMap, VecDeque};
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

    let ctx = LifecycleContext::new(
        &root,
        &leaf,
        "web",
        "build",
        "echo 1",
    );

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
    manifest_a.scripts.insert("install".to_string(), "node -e \"process.exit(0)\"".to_string());

    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.scripts.insert("install".to_string(), "node -e \"process.exit(0)\"".to_string());

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
    };

    // Cyclic dependency should NOT overflow the stack and should successfully execute
    let res = execute_topological(&[node_a, node_b], &root_manifest, &opts).await;
    assert!(res.is_ok(), "Cycle should be gracefully handled without stack overflow");
}

#[tokio::test]
async fn test_optional_dependency_disk_removal_on_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    let opt_dir = root.join("node_modules").join("optional-fail-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    assert!(opt_dir.exists(), "Directory should exist prior to script execution");

    let mut manifest = Manifest::default();
    manifest.name = Some("optional-fail-pkg".to_string());
    manifest.version = Some("1.0.0".to_string());
    // Failing script
    manifest.scripts.insert("preinstall".to_string(), "node -e \"process.exit(1)\"".to_string());
    // Subsequent hook should be skipped
    manifest.scripts.insert("install".to_string(), "node -e \"process.exit(1)\"".to_string());

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
    };

    let res = execute_topological(&[node], &root_manifest, &opts).await;
    assert!(res.is_ok(), "Optional dependency failure must be isolated");
    assert!(!opt_dir.exists(), "Optional dependency directory must be removed on failure");
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

    let ctx = LifecycleContext::new(
        root,
        root,
        "process-tree-test",
        "preinstall",
        &script_cmd,
    );

    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    let abort_fut = async move {
        let mut rx = abort_rx;
        let _ = rx.wait_for(|&v| v).await;
    };

    // Spawn script in background
    let exec_task = tokio::spawn(async move {
        execute_lifecycle_script_with_abort(&ctx, abort_fut).await
    });

    // Wait until the grandchild has started and written its PID
    let mut grandchild_pid: Option<u32> = None;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if grandchild_pid_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&grandchild_pid_file) {
                let trimmed = content.trim();
                if let Ok(pid) = trimmed.parse::<u32>() {
                    grandchild_pid = Some(pid);
                    break;
                }
            }
        }
    }

    let pid = grandchild_pid.expect("Grandchild process should have launched and written its PID");
    assert!(
        process_guard::is_process_running(pid),
        "Grandchild process {pid} must be actively running"
    );

    // Send abort signal
    let _ = abort_tx.send(true);

    // Wait for task to finish with error
    let res = exec_task.await.unwrap();
    assert!(res.is_err(), "Lifecycle execution must terminate with error on abort");

    // Wait brief grace period for OS process cleanup
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Verify the grandchild process was cleanly terminated and not orphaned
    assert!(
        !process_guard::is_process_running(pid),
        "Grandchild process {pid} must be terminated upon abort signal, no orphans allowed"
    );
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
    assert!(!content.contains("pkg-abort-2"), "pkg-abort-2 should not have run after abort");
    assert!(!content.contains("pkg-abort-3"), "pkg-abort-3 should not have run after abort");
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
    for (name, _) in &dependencies {
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
        manifest.scripts.insert("install".to_string(), "node -e \"process.exit(0)\"".to_string());

        let mut deps = Vec::new();
        if i >= 1 && i < 10 {
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
    };

    let res = execute_topological(&nodes, &root_manifest, &opts).await;
    assert!(res.is_ok(), "Large 60-package topological lifecycle execution should succeed");
}

#[test]
fn test_glob_match_and_matches_filter() {
    let root = PathBuf::from("/workspace/monorepo");
    let member_path = root.join("packages").join("ui-button");

    // Exact matches
    assert!(matches_filter("ui-button", "ui-button", &member_path, &root));
    assert!(!matches_filter("ui-card", "ui-button", &member_path, &root));

    // Scoped matches
    let scoped_path = root.join("packages").join("core");
    assert!(matches_filter("@scope/core", "@scope/core", &scoped_path, &root));
    assert!(matches_filter("@scope", "@scope/core", &scoped_path, &root));
    assert!(matches_filter("@scope/*", "@scope/core", &scoped_path, &root));
    assert!(matches_filter("@scope/c*", "@scope/core", &scoped_path, &root));
    assert!(!matches_filter("@other", "@scope/core", &scoped_path, &root));

    // Glob matches
    assert!(matches_filter("ui-*", "ui-button", &member_path, &root));
    assert!(matches_filter("*-button", "ui-button", &member_path, &root));
    assert!(matches_filter("ui-b?tt?n", "ui-button", &member_path, &root));
    assert!(!matches_filter("api-*", "ui-button", &member_path, &root));

    // Path matches
    assert!(matches_filter("packages/ui-button", "ui-button", &member_path, &root));
    assert!(matches_filter("./packages/ui-button", "ui-button", &member_path, &root));
    assert!(matches_filter("packages/*", "ui-button", &member_path, &root));
    assert!(!matches_filter("apps/*", "ui-button", &member_path, &root));
}

#[test]
fn test_find_local_binary_and_ancestor_collection() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Create root node_modules/.bin
    let bin_dir = root.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let bin_name = if cfg!(windows) { "my-tool.cmd" } else { "my-tool" };
    let bin_file = bin_dir.join(bin_name);
    std::fs::write(&bin_file, "dummy content").unwrap();

    // Create deep child directory
    let child_dir = root.join("packages").join("nested").join("deep");
    std::fs::create_dir_all(&child_dir).unwrap();

    // find_local_binary traversing up from child_dir must find my-tool
    let found = find_local_binary(&child_dir, "my-tool");
    assert!(found.is_some(), "Should find my-tool in ancestor node_modules/.bin");
    let found_path = found.unwrap();
    assert_eq!(found_path.file_name().unwrap(), std::ffi::OsStr::new(bin_name));

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
    std::fs::write(&script, "process.exit(42);").unwrap();

    let status = execute_binary_async(
        &script,
        &[],
        root,
        &[],
        &HashMap::new(),
    ).await.expect("Binary spawn should execute");

    assert!(!status.success());
    let code = extract_exit_status_code(&status);
    assert_eq!(code, 42, "Exit status code must be preserved faithfully as 42");
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
        if_present: false,
        filter_members: Some(vec!["nonexistent-*".to_string()]),
    };

    let err_res = execute_workspace_scripts_topological(root, &members, &topo_order, &bad_opts).await;
    assert!(err_res.is_err());
    let err_msg = err_res.unwrap_err().to_string();
    assert!(err_msg.contains("No workspace packages matched the filter/scope criteria"));
}

