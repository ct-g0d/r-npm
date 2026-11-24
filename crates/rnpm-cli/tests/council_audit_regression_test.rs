use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_implicit_restart_runs_stop_start_lifecycle_in_process_with_poisoned_npm() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // package.json has stop and start, but NO restart
    let pkg_json = serde_json::json!({
        "name": "implicit-restart-app",
        "version": "1.0.0",
        "scripts": {
            "stop": "node -e \"require('fs').writeFileSync('stopped.txt', 'stopped')\"",
            "start": "node -e \"require('fs').writeFileSync('started.txt', 'started')\""
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    // Create a fake bin directory with a poisoned npm executable that fails if called
    let fake_bin_dir = tmp.path().join("fake_bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();

    #[cfg(windows)]
    {
        fs::write(
            fake_bin_dir.join("npm.cmd"),
            "@echo off\r\necho poisoned > poisoned.txt\r\nexit /b 1\r\n",
        )
        .unwrap();
        fs::write(
            fake_bin_dir.join("npm.bat"),
            "@echo off\r\necho poisoned > poisoned.txt\r\nexit /b 1\r\n",
        )
        .unwrap();
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = fake_bin_dir.join("npm");
        fs::write(&p, "#!/bin/sh\necho poisoned > poisoned.txt\nexit 1\n").unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&p, perms).unwrap();
    }

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let poisoned_path = format!(
        "{}{}{}",
        fake_bin_dir.display(),
        if cfg!(windows) { ";" } else { ":" },
        orig_path
    );

    let out = Command::new(rnpm_bin)
        .arg("restart")
        .env("PATH", &poisoned_path)
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm restart");

    assert!(
        out.status.success(),
        "rnpm restart should succeed in-process; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        tmp.path().join("stopped.txt").exists(),
        "stopped.txt must exist from in-process stop execution"
    );
    assert!(
        tmp.path().join("started.txt").exists(),
        "started.txt must exist from in-process start execution"
    );
    assert!(
        !tmp.path().join("poisoned.txt").exists(),
        "poisoned npm on PATH must NOT have been called"
    );
}

#[test]
fn test_prefix_applies_to_test_start_restart_stop_and_dev_engines_check() {
    let tmp = tempdir().unwrap();
    let sub = tmp.path().join("sub");
    fs::create_dir_all(&sub).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let sub_pkg = serde_json::json!({
        "name": "sub-pkg",
        "version": "1.0.0",
        "scripts": {
            "test": "node -e \"require('fs').writeFileSync('sub-test.txt', 'ok')\"",
            "start": "node -e \"require('fs').writeFileSync('sub-start.txt', 'ok')\"",
            "stop": "node -e \"require('fs').writeFileSync('sub-stop.txt', 'ok')\"",
            "restart": "node -e \"require('fs').writeFileSync('sub-restart.txt', 'ok')\""
        }
    });
    fs::write(sub.join("package.json"), sub_pkg.to_string()).unwrap();

    // 1. --prefix applies to test
    let out = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "test"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub test");
    assert!(
        out.status.success(),
        "test stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sub.join("sub-test.txt").exists());

    // 2. --prefix applies to start
    let out = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "start"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub start");
    assert!(
        out.status.success(),
        "start stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sub.join("sub-start.txt").exists());

    // 3. --prefix applies to stop
    let out = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "stop"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub stop");
    assert!(
        out.status.success(),
        "stop stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sub.join("sub-stop.txt").exists());

    // 4. --prefix applies to restart
    let out = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "restart"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub restart");
    assert!(
        out.status.success(),
        "restart stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sub.join("sub-restart.txt").exists());

    // 5. devEngines check sees the prefixed package.json for test and run
    let sub_pkg_incompatible_engines = serde_json::json!({
        "name": "sub-pkg",
        "version": "1.0.0",
        "devEngines": {
            "runtime": {
                "name": "node",
                "version": "^0.0.1"
            }
        },
        "scripts": {
            "test": "node -e \"require('fs').writeFileSync('sub-test-should-fail.txt', 'fail')\"",
            "custom": "node -e \"require('fs').writeFileSync('sub-custom-should-fail.txt', 'fail')\""
        }
    });
    fs::write(
        sub.join("package.json"),
        sub_pkg_incompatible_engines.to_string(),
    )
    .unwrap();

    let out_engines = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "test"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub test with devEngines");

    assert!(
        !out_engines.status.success(),
        "rnpm --prefix ./sub test should fail due to incompatible devEngines"
    );
    let stderr = String::from_utf8_lossy(&out_engines.stderr);
    assert!(
        stderr.contains("EBADENGINE") || stderr.contains("devEngines") || stderr.contains("node"),
        "stderr should mention devEngines / EBADENGINE failure; got:\n{stderr}"
    );
    assert!(
        !sub.join("sub-test-should-fail.txt").exists(),
        "script must not have run when devEngines failed"
    );

    // rnpm --prefix ./sub run custom must ALSO fail checking ./sub's devEngines
    let out_run_engines = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "run", "custom"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub run custom with devEngines");

    assert!(
        !out_run_engines.status.success(),
        "rnpm --prefix ./sub run custom should fail due to incompatible devEngines in prefix"
    );
    let stderr_run = String::from_utf8_lossy(&out_run_engines.stderr);
    assert!(
        stderr_run.contains("EBADENGINE") || stderr_run.contains("devEngines") || stderr_run.contains("node"),
        "run stderr should mention devEngines failure; got:\n{stderr_run}"
    );
    assert!(
        !sub.join("sub-custom-should-fail.txt").exists(),
        "custom script must not have run when devEngines failed"
    );

    // 6. rnpm pkg get name --prefix ./sub must not double-join ./sub/sub
    let out_pkg = Command::new(rnpm_bin)
        .args(["pkg", "get", "name", "--prefix", "./sub"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm pkg get name --prefix ./sub");

    assert!(
        out_pkg.status.success(),
        "rnpm pkg get name --prefix ./sub must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out_pkg.stderr)
    );
    let pkg_name_out = String::from_utf8_lossy(&out_pkg.stdout).trim().to_string();
    assert_eq!(pkg_name_out, "\"sub-pkg\"");
    assert!(
        !sub.join("sub").exists(),
        "must not create or expect nested ./sub/sub directory"
    );
}

#[test]
fn test_run_filter_scope_workspace_root_bypasses_ultra_fast_path() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let root_pkg = serde_json::json!({
        "name": "root-monorepo",
        "version": "1.0.0",
        "workspaces": ["packages/*"],
        "scripts": {
            "build": "node -e \"require('fs').writeFileSync('root-built.txt', 'yes')\""
        }
    });
    fs::write(tmp.path().join("package.json"), root_pkg.to_string()).unwrap();

    let pkg_a = tmp.path().join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a).unwrap();
    let pkg_a_manifest = serde_json::json!({
        "name": "pkg-a",
        "version": "1.0.0",
        "scripts": {
            "build": "node -e \"require('fs').writeFileSync('pkg-a-built.txt', 'yes')\""
        }
    });
    fs::write(pkg_a.join("package.json"), pkg_a_manifest.to_string()).unwrap();

    // 1. --workspace-root build runs root script
    let out_ws_root = Command::new(rnpm_bin)
        .args(["run", "--workspace-root", "build"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm run --workspace-root build");
    assert!(
        out_ws_root.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_ws_root.stderr)
    );
    assert!(
        tmp.path().join("root-built.txt").exists(),
        "root-built.txt must exist when run with --workspace-root"
    );

    // 1b. --workspace-root build invoked from inside child package directory (packages/pkg-a) runs root script
    fs::remove_file(tmp.path().join("root-built.txt")).unwrap();
    let out_ws_child = Command::new(rnpm_bin)
        .args(["run", "--workspace-root", "build"])
        .current_dir(&pkg_a)
        .output()
        .expect("Failed to run rnpm run --workspace-root build from child package dir");
    assert!(
        out_ws_child.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_ws_child.stderr)
    );
    assert!(
        tmp.path().join("root-built.txt").exists(),
        "root-built.txt must exist when run with --workspace-root from child package dir"
    );
    assert!(
        !pkg_a.join("pkg-a-built.txt").exists(),
        "pkg-a script must not run when --workspace-root is specified"
    );

    // 2. --filter pkg-a build runs in pkg-a
    let out_filter = Command::new(rnpm_bin)
        .args(["run", "--filter", "pkg-a", "build"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm run --filter pkg-a build");
    assert!(
        out_filter.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_filter.stderr)
    );
    assert!(
        pkg_a.join("pkg-a-built.txt").exists(),
        "pkg-a-built.txt must exist when run with --filter"
    );

    // 3. --scope=pkg-a build runs in pkg-a
    fs::remove_file(pkg_a.join("pkg-a-built.txt")).unwrap();
    let out_scope = Command::new(rnpm_bin)
        .args(["run", "--scope=pkg-a", "build"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm run --scope=pkg-a build");
    assert!(
        out_scope.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_scope.stderr)
    );
    assert!(
        pkg_a.join("pkg-a-built.txt").exists(),
        "pkg-a-built.txt must exist when run with --scope="
    );
}

#[test]
fn test_shrinkwrap_ignores_stale_hidden_lockfile_survives_symlink_cycle_and_omits_dev_deps() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "shrinkwrap-test-app",
        "version": "1.0.0",
        "dependencies": {
            "real-dep": "^1.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let nm = tmp.path().join("node_modules");
    fs::create_dir_all(&nm).unwrap();

    // Create a stale hidden lockfile (.package-lock.json) with an obsolete dependency
    let stale_lock = serde_json::json!({
        "name": "stale-app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "stale-app",
                "version": "1.0.0",
                "dependencies": {
                    "obsolete-dep": "^0.5.0"
                }
            },
            "node_modules/obsolete-dep": {
                "version": "0.5.0"
            }
        }
    });
    fs::write(nm.join(".package-lock.json"), stale_lock.to_string()).unwrap();

    // Create real-dep in node_modules with both dependencies and devDependencies
    let real_dep_dir = nm.join("real-dep");
    fs::create_dir_all(&real_dep_dir).unwrap();
    let real_dep_pkg = serde_json::json!({
        "name": "real-dep",
        "version": "1.2.3",
        "dependencies": {
            "nested-dep": "^2.0.0"
        },
        "devDependencies": {
            "ignored-dev-dep": "^3.0.0"
        }
    });
    fs::write(real_dep_dir.join("package.json"), real_dep_pkg.to_string()).unwrap();

    // Create a node_modules symlink/junction cycle: real-dep/node_modules -> nm
    let nested_nm = real_dep_dir.join("node_modules");
    rnpm_fs::create_junction(&nested_nm, &nm).expect("failed to create cycle junction");

    // Create a diamond structure:
    // node_modules/shared-pkg (with manifest)
    // node_modules/dep-a/node_modules/shared -> node_modules/shared-pkg
    // node_modules/dep-b/node_modules/shared -> node_modules/shared-pkg
    let shared_pkg_dir = nm.join("shared-pkg");
    fs::create_dir_all(&shared_pkg_dir).unwrap();
    let shared_pkg = serde_json::json!({
        "name": "shared-pkg",
        "version": "1.0.0"
    });
    fs::write(shared_pkg_dir.join("package.json"), shared_pkg.to_string()).unwrap();

    let dep_a_dir = nm.join("dep-a");
    let dep_a_nm = dep_a_dir.join("node_modules");
    fs::create_dir_all(&dep_a_nm).unwrap();
    let dep_a_pkg = serde_json::json!({
        "name": "dep-a",
        "version": "1.0.0"
    });
    fs::write(dep_a_dir.join("package.json"), dep_a_pkg.to_string()).unwrap();
    rnpm_fs::create_junction(&dep_a_nm.join("shared"), &shared_pkg_dir)
        .expect("failed to create dep-a diamond junction");

    let dep_b_dir = nm.join("dep-b");
    let dep_b_nm = dep_b_dir.join("node_modules");
    fs::create_dir_all(&dep_b_nm).unwrap();
    let dep_b_pkg = serde_json::json!({
        "name": "dep-b",
        "version": "1.0.0"
    });
    fs::write(dep_b_dir.join("package.json"), dep_b_pkg.to_string()).unwrap();
    rnpm_fs::create_junction(&dep_b_nm.join("shared"), &shared_pkg_dir)
        .expect("failed to create dep-b diamond junction");

    let out = Command::new(rnpm_bin)
        .arg("shrinkwrap")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm shrinkwrap");

    assert!(
        out.status.success(),
        "shrinkwrap should succeed without hanging or recursion error; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let shrinkwrap_path = tmp.path().join("npm-shrinkwrap.json");
    assert!(shrinkwrap_path.exists());

    let content = fs::read_to_string(&shrinkwrap_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    let packages = parsed["packages"].as_object().unwrap();

    // 1. Stale hidden lockfile was ignored: obsolete-dep is NOT present
    assert!(
        !packages.contains_key("node_modules/obsolete-dep"),
        "stale hidden lockfile package must not be present"
    );

    // 2. real-dep was populated from node_modules
    let real_dep_node = packages
        .get("node_modules/real-dep")
        .expect("node_modules/real-dep must be populated");
    assert_eq!(real_dep_node["version"], "1.2.3");
    assert_eq!(real_dep_node["dependencies"]["nested-dep"], "^2.0.0");

    // 3. devDependencies on node_modules/* MUST BE OMITTED in lockfile v3
    assert!(
        real_dep_node.get("devDependencies").is_none(),
        "devDependencies on installed node_modules/real-dep must be omitted"
    );

    // 4. Diamond structure: dep-a/node_modules/shared and dep-b/node_modules/shared
    // both link to shared-pkg. Neither must be omitted due to monotonic visited set.
    assert!(
        packages.contains_key("node_modules/dep-a/node_modules/shared"),
        "dep-a diamond branch must be present in packages"
    );
    assert!(
        packages.contains_key("node_modules/dep-b/node_modules/shared"),
        "dep-b diamond branch must be present in packages"
    );
    assert!(
        packages.contains_key("node_modules/shared-pkg"),
        "shared-pkg target must be present in packages"
    );
}

#[test]
fn test_config_report_handles_unicode_env_var_crossing_byte_11() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    fs::write(
        tmp.path().join("package.json"),
        serde_json::json!({
            "name": "unicode-env-test",
            "version": "1.0.0"
        })
        .to_string(),
    )
    .unwrap();

    // "npm_test_" is 9 bytes. "🦀" is 4 bytes (bytes 9..13).
    // Byte 11 is in the middle of "🦀", which would panic under naive byte slicing (&var[..11]).
    let out = Command::new(rnpm_bin)
        .args(["config", "list", "--json"])
        .env("npm_test_🦀_foo", "bar")
        .env("💖_npm_config_var", "123")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm config list --json");

    assert!(
        out.status.success(),
        "config list must not panic on multi-byte unicode env vars; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_query_workspace_does_not_match_non_workspace_file_package() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Root package has a file: dependency on packages/local-pkg, but does NOT declare "workspaces"!
    let root_pkg = serde_json::json!({
        "name": "query-test-app",
        "version": "1.0.0",
        "dependencies": {
            "local-pkg": "file:packages/local-pkg"
        }
    });
    fs::write(tmp.path().join("package.json"), root_pkg.to_string()).unwrap();

    let local_pkg_dir = tmp.path().join("packages").join("local-pkg");
    fs::create_dir_all(&local_pkg_dir).unwrap();
    let local_pkg = serde_json::json!({
        "name": "local-pkg",
        "version": "1.0.0"
    });
    fs::write(local_pkg_dir.join("package.json"), local_pkg.to_string()).unwrap();

    let nm_local = tmp.path().join("node_modules").join("local-pkg");
    fs::create_dir_all(nm_local.parent().unwrap()).unwrap();
    let _ = rnpm_fs::create_junction(&nm_local, &local_pkg_dir);
    if !nm_local.join("package.json").exists() {
        fs::write(nm_local.join("package.json"), local_pkg.to_string()).unwrap();
    }

    // Query :workspace should NOT match local-pkg because it is NOT a workspace member
    let out_ws = Command::new(rnpm_bin)
        .args(["query", ":workspace"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm query :workspace");

    assert!(
        out_ws.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_ws.stderr)
    );
    let parsed_ws: Vec<serde_json::Value> = serde_json::from_slice(&out_ws.stdout).unwrap();
    assert!(
        parsed_ws.is_empty(),
        ":workspace selector should not match non-workspace file: dependency, got: {:?}",
        parsed_ws
    );

    // Query local-pkg directly should find it, with is_workspace = false
    let out_pkg = Command::new(rnpm_bin)
        .args(["query", "local-pkg"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm query local-pkg");

    assert!(
        out_pkg.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_pkg.stderr)
    );
    let parsed_pkg: Vec<serde_json::Value> = serde_json::from_slice(&out_pkg.stdout).unwrap();
    assert_eq!(
        parsed_pkg.len(),
        1,
        "local-pkg should be found by name selector"
    );
    assert_eq!(parsed_pkg[0]["name"], "local-pkg");
    assert_ne!(
        parsed_pkg[0].get("is_workspace"),
        Some(&serde_json::Value::Bool(true)),
        "local-pkg must not be flagged as a workspace"
    );
}
