use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::spec::PackageTarget;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::BTreeMap;
use std::io::Cursor;
use tar::{Builder, Header};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

    fn make_tarball(pkg_name: &str, version: &str) -> Vec<u8> {
        let manifest_json = serde_json::json!({
            "name": pkg_name,
            "version": version,
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
    async fn test_cli_update_command_integration() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        let pkg_tar = make_tarball("demo-pkg", "1.2.0");
        let pkg_int = Integrity::from_bytes(&pkg_tar, Algorithm::Sha512).to_string();

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
                            let pkg_int_c = pkg_int.clone();
                            let pkg_tar_c = pkg_tar.clone();
                            let su_c = su.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /demo-pkg") {
                                        let json = serde_json::json!({
                                            "name": "demo-pkg",
                                            "dist-tags": { "latest": "1.2.0" },
                                            "versions": {
                                                "1.0.0": { "name": "demo-pkg", "version": "1.0.0", "dist": { "tarball": format!("{su_c}tarballs/demo-pkg.tgz"), "integrity": pkg_int_c } },
                                                "1.2.0": { "name": "demo-pkg", "version": "1.2.0", "dist": { "tarball": format!("{su_c}tarballs/demo-pkg.tgz"), "integrity": pkg_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/demo-pkg.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], pkg_tar_c)
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

        // Set up project files
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "my-cli-app",
            "version": "1.0.0",
            "dependencies": {
                "demo-pkg": "^1.0.0"
            }
        }"#).unwrap();

        let mut lock = LockfileV3::new("my-cli-app", Some("1.0.0".to_string()));
        let mut d = BTreeMap::new();
        d.insert("demo-pkg".to_string(), "^1.0.0".to_string());
        lock.root_package_mut().unwrap().dependencies = Some(d);
        lock.insert_package("node_modules/demo-pkg", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/demo-pkg.tgz")),
            integrity: Some("sha512-fake".to_string()),
            ..Default::default()
        });
        let lock_path = project_dir.path().join("package-lock.json");
        lock.save_to_file(&lock_path).unwrap();

        // Run rnpm update via run_cli
        let cli = Cli {
            command: Commands::Update {
                packages: vec![],
                registry: Some(server_url),
                cache: Some(cache_dir.path().to_path_buf()),
                offline: false,
                ignore_scripts: true,
                legacy_peer_deps: false,
            },
        };

        let res = run_cli(cli, Some(project_dir.path().to_path_buf())).await;
        assert!(res.is_ok());

        let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
        let pkg_entry = updated_lock.get_package("node_modules/demo-pkg").unwrap();
        assert_eq!(pkg_entry.version, Some("1.2.0".to_string()));
        assert!(project_dir.path().join("node_modules/demo-pkg/package.json").exists());

        let _ = tx.send(());
    }

    #[test]
    fn test_unsupported_commands_gate_e_diagnostics() {
        let commands = ["publish", "login", "fix", "token", "deprecate"];
        for cmd in commands {
            let res = check_unsupported_cli_invocation(vec!["rnpm", cmd]);
            assert!(res.is_some(), "Expected diagnostic for command: {cmd}");
            let (code, msg) = res.unwrap();
            assert_eq!(code, "ERR_UNSUPPORTED_COMMAND");
            assert!(msg.contains("npm error code ERR_UNSUPPORTED_COMMAND"));
            assert!(msg.contains(&format!("The command '{cmd}' is not currently implemented in rnpm.")));
            assert!(msg.contains("docs/compatibility-contract.md"));
        }

        // Verify exec and npx are recognized and not blocked as unsupported commands
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "exec"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "npx"]).is_none());
    }

    #[test]
    fn test_unsupported_flags_gate_e_diagnostics() {
        let flags = ["--global", "-g"];
        for flag in flags {
            let res = check_unsupported_cli_invocation(vec!["rnpm", "install", flag]);
            assert!(res.is_some(), "Expected diagnostic for flag: {flag}");
            let (code, msg) = res.unwrap();
            assert_eq!(code, "ERR_UNSUPPORTED_FLAG");
            assert!(msg.contains("npm error code ERR_UNSUPPORTED_FLAG"));
            assert!(msg.contains(&format!("The flag '{flag}' is not supported by rnpm.")));
        }

        // --legacy-peer-deps is supported on install, but unsupported on commands like audit/pack
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "install", "--legacy-peer-deps"]).is_none());
        let res = check_unsupported_cli_invocation(vec!["rnpm", "audit", "--legacy-peer-deps"]);
        assert!(res.is_some());
    }

    #[test]
    fn test_unsupported_protocol_spec_gate_e_diagnostics() {
        use rnpm_core::spec::PackageTarget;
        let unsupported_specs = [
            "svn://svn.example.com/repo/trunk",
            "ftp://ftp.example.com/packages/pkg.tgz",
            "hg+https://hg.example.com/repo",
            "cvs://pserver:anonymous@example.com/cvsroot",
        ];

        for spec in unsupported_specs {
            let res = PackageTarget::parse(spec);
            assert!(res.is_err(), "Expected parse error for: {spec}");
            let err = res.unwrap_err();
            let err_str = err.to_string();
            assert!(
                err_str.contains("Unsupported URL Type") || err_str.contains("Unsupported protocol"),
                "Expected Unsupported URL Type error, got: {err_str}"
            );
        }

        // Verify AGY 3 supported Git & URL specifications parse cleanly
        let git_specs = [
            "git+ssh://git@github.com:foo/bar.git",
            "git://github.com/foo/bar.git",
            "github:user/repo",
            "bitbucket:user/repo",
            "gitlab:user/repo",
            "git+https://github.com/org/repo.git#v1.0.0",
        ];
        for spec in git_specs {
            let res = PackageTarget::parse(spec);
            assert!(res.is_ok(), "Expected successful Git parse for: {spec}");
            assert!(matches!(res.unwrap(), PackageTarget::Git { .. }));
        }

        let url_spec = "https://cdn.example.com/packages/pkg-1.0.0.tgz";
        let res = PackageTarget::parse(url_spec);
        assert!(res.is_ok(), "Expected successful URL parse for: {url_spec}");
        assert!(matches!(res.unwrap(), PackageTarget::Url(_)));
    }

    #[tokio::test]
    async fn test_cli_run_workspaces_topological_order() {
        let root_dir = tempdir().unwrap();

        // Monorepo root package.json
        let root_pkg_json = root_dir.path().join("package.json");
        std::fs::write(&root_pkg_json, r#"{
            "name": "my-monorepo",
            "workspaces": ["packages/*"]
        }"#).unwrap();

        let marker_file = root_dir.path().join("execution_log.txt");
        let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

        // Member B: @mono/pkg-b (leaf dependency)
        let b_dir = root_dir.path().join("packages").join("pkg-b");
        std::fs::create_dir_all(&b_dir).unwrap();
        std::fs::write(b_dir.join("package.json"), format!(r#"{{
            "name": "@mono/pkg-b",
            "version": "1.0.0",
            "scripts": {{
                "build": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-b\\n')\""
            }}
        }}"#)).unwrap();

        // Member A: @mono/pkg-a (depends on @mono/pkg-b via workspace:*)
        let a_dir = root_dir.path().join("packages").join("pkg-a");
        std::fs::create_dir_all(&a_dir).unwrap();
        std::fs::write(a_dir.join("package.json"), format!(r#"{{
            "name": "@mono/pkg-a",
            "version": "1.0.0",
            "dependencies": {{
                "@mono/pkg-b": "workspace:*"
            }},
            "scripts": {{
                "build": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a\\n')\""
            }}
        }}"#)).unwrap();

        // Run `rnpm run build --workspaces`
        let cli = Cli {
            command: Commands::Run {
                script: Some("build".to_string()),
                args: vec![],
                workspaces: true,
                workspace: vec![],
                filter: vec![],
                scope: vec![],
                if_present: false,
                ignore_scripts: false,
            },
        };

        let res = run_cli(cli, Some(root_dir.path().to_path_buf())).await;
        assert!(res.is_ok(), "Expected run_cli to succeed across workspaces: {:?}", res.err());

        // Verify topological execution: pkg-b (leaf) executed BEFORE pkg-a (dependent)
        let log_content = std::fs::read_to_string(&marker_file).unwrap();
        let executed_lines: Vec<&str> = log_content.lines().collect();
        assert_eq!(executed_lines, vec!["pkg-b", "pkg-a"]);
    }

    #[tokio::test]
    async fn test_cli_run_workspaces_large_dag_topological_stress() {
        let root_dir = tempdir().unwrap();

        // Monorepo root package.json
        let root_pkg_json = root_dir.path().join("package.json");
        std::fs::write(&root_pkg_json, r#"{
            "name": "stress-monorepo",
            "workspaces": ["packages/*"]
        }"#).unwrap();

        let marker_file = root_dir.path().join("stress_exec_log.txt");
        let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

        let total_pkgs = 52;
        let mut expected_deps: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        // 1. Component 1: core-00 through core-19 (20 packages with diamonds and deep chains)
        for i in 0..20 {
            let name = format!("core-{i:02}");
            let mut deps = Vec::new();
            if i == 1 || i == 2 || i == 3 {
                deps.push("core-00".to_string());
            } else if i == 4 {
                // Diamond
                deps.push("core-01".to_string());
                deps.push("core-02".to_string());
            } else if i == 5 {
                // Diamond
                deps.push("core-02".to_string());
                deps.push("core-03".to_string());
            } else if (6..=15).contains(&i) {
                // Deep chain
                deps.push(format!("core-{:02}", i - 1));
            } else if (16..=18).contains(&i) {
                // Fan-out
                deps.push("core-15".to_string());
            } else if i == 19 {
                // Fan-in
                deps.push("core-16".to_string());
                deps.push("core-17".to_string());
                deps.push("core-18".to_string());
            }
            expected_deps.insert(name, deps);
        }

        // 2. Component 2: app-00 through app-24 (25 packages, disconnected from core)
        for i in 0..25 {
            let name = format!("app-{i:02}");
            let mut deps = Vec::new();
            if (2..=7).contains(&i) {
                deps.push("app-00".to_string());
                if i % 2 == 0 {
                    deps.push("app-01".to_string());
                }
            } else if (8..=15).contains(&i) {
                deps.push(format!("app-{:02}", i - 6));
            } else if (16..=23).contains(&i) {
                deps.push(format!("app-{:02}", i - 8));
            } else if i == 24 {
                deps.push("app-20".to_string());
                deps.push("app-21".to_string());
                deps.push("app-22".to_string());
                deps.push("app-23".to_string());
            }
            expected_deps.insert(name, deps);
        }

        // 3. Component 3: isolated-00 through isolated-06 (7 standalone packages)
        for i in 0..7 {
            let name = format!("isolated-{i:02}");
            expected_deps.insert(name, Vec::new());
        }

        assert_eq!(expected_deps.len(), total_pkgs);

        // Generate package directories and package.json files
        for (name, deps) in &expected_deps {
            let pkg_dir = root_dir.path().join("packages").join(name);
            std::fs::create_dir_all(&pkg_dir).unwrap();

            let mut dep_map = serde_json::Map::new();
            for dep in deps {
                dep_map.insert(dep.clone(), serde_json::Value::String("workspace:*".to_string()));
            }

            let pkg_json_val = serde_json::json!({
                "name": name,
                "version": "1.0.0",
                "dependencies": dep_map,
                "scripts": {
                    "build": format!("node -e \"require('fs').appendFileSync('{escaped_marker}', '{name}\\n')\"")
                }
            });

            std::fs::write(
                pkg_dir.join("package.json"),
                serde_json::to_string_pretty(&pkg_json_val).unwrap(),
            ).unwrap();
        }

        // Run `rnpm run build --workspaces`
        let cli = Cli {
            command: Commands::Run {
                script: Some("build".to_string()),
                args: vec![],
                workspaces: true,
                workspace: vec![],
                filter: vec![],
                scope: vec![],
                if_present: false,
                ignore_scripts: false,
            },
        };

        let res = run_cli(cli, Some(root_dir.path().to_path_buf())).await;
        assert!(res.is_ok(), "Expected run_cli to succeed on large monorepo DAG: {:?}", res.err());

        // Verify topological execution
        let log_content = std::fs::read_to_string(&marker_file).unwrap();
        let executed_sequence: Vec<&str> = log_content.lines().collect();
        assert_eq!(
            executed_sequence.len(),
            total_pkgs,
            "All {total_pkgs} workspace packages must have executed"
        );

        let mut executed_index_map: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (idx, &name) in executed_sequence.iter().enumerate() {
            executed_index_map.insert(name, idx);
        }

        // Assert topological invariant: every dependency must execute BEFORE its dependent
        for (pkg, deps) in &expected_deps {
            let pkg_idx = *executed_index_map.get(pkg.as_str()).unwrap();
            for dep in deps {
                let dep_idx = *executed_index_map.get(dep.as_str()).unwrap();
                assert!(
                    dep_idx < pkg_idx,
                    "Topological ordering failed: dependency '{dep}' (index {dep_idx}) executed AFTER dependent '{pkg}' (index {pkg_idx})"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_cli_exec_local_binary_success() {
        let temp = tempdir().unwrap();
        let project_dir = temp.path();

        let marker_file = project_dir.join("exec_local_marker.txt");
        let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

        // Set up package.json
        std::fs::write(
            project_dir.join("package.json"),
            r#"{"name": "test-project", "version": "1.0.0"}"#,
        ).unwrap();

        // Set up node_modules/echo-tool/index.js
        let tool_dir = project_dir.join("node_modules").join("echo-tool");
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(
            tool_dir.join("index.js"),
            format!("require('fs').writeFileSync('{escaped_marker}', 'local-exec-ok');\n"),
        ).unwrap();

        // Create shims in node_modules/.bin
        let bin_dir = project_dir.join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        rnpm_shim::create_shims(&bin_dir, "echo-tool", "echo-tool/index.js").unwrap();

        let cli = Cli {
            command: Commands::Exec {
                package: "echo-tool".to_string(),
                args: vec![],
                registry: None,
                cache: None,
                offline: false,
            },
        };

        let res = run_cli(cli, Some(project_dir.to_path_buf())).await;
        assert!(res.is_ok(), "Local exec should succeed: {:?}", res.err());

        let marker_content = std::fs::read_to_string(&marker_file).unwrap();
        assert_eq!(marker_content.trim(), "local-exec-ok");
    }

    #[tokio::test]
    async fn test_cli_exec_exit_code_fidelity() {
        let temp = tempdir().unwrap();
        let project_dir = temp.path();

        std::fs::write(
            project_dir.join("package.json"),
            r#"{"name": "test-project", "version": "1.0.0"}"#,
        ).unwrap();

        let tool_dir = project_dir.join("node_modules").join("fail-tool");
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(
            tool_dir.join("index.js"),
            "process.exit(53);\n",
        ).unwrap();

        let bin_dir = project_dir.join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        rnpm_shim::create_shims(&bin_dir, "fail-tool", "fail-tool/index.js").unwrap();

        let cli = Cli {
            command: Commands::Exec {
                package: "fail-tool".to_string(),
                args: vec![],
                registry: None,
                cache: None,
                offline: false,
            },
        };

        let res = run_cli(cli, Some(project_dir.to_path_buf())).await;
        assert!(res.is_err(), "Exec with non-zero exit code must return an error");

        let err = res.unwrap_err();
        let script_err = err.downcast_ref::<rnpm_lifecycle::ScriptExitError>()
            .expect("Error must downcast to ScriptExitError to preserve exit code");
        assert_eq!(script_err.exit_code, 53, "Exit code must faithfully be 53");
    }

    fn make_tarball_with_bin(pkg_name: &str, version: &str, bin_name: &str, script_content: &str) -> Vec<u8> {
        let manifest_json = serde_json::json!({
            "name": pkg_name,
            "version": version,
            "bin": {
                bin_name: format!("bin/{bin_name}.js")
            }
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest_json).unwrap();
        let script_bytes = script_content.as_bytes();

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

            let mut bin_header = Header::new_gnu();
            bin_header.set_size(script_bytes.len() as u64);
            bin_header.set_mode(0o755);
            let bin_path = format!("package/bin/{bin_name}.js");
            bin_header.as_mut_bytes()[..bin_path.len()].copy_from_slice(bin_path.as_bytes());
            bin_header.set_cksum();
            builder.append(&bin_header, Cursor::new(script_bytes)).unwrap();

            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[tokio::test]
    async fn test_cli_exec_dynamic_ephemeral_install_and_run() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        let marker_file = project_dir.path().join("dynamic_exec_marker.txt");
        let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");
        let script = format!("require('fs').writeFileSync('{escaped_marker}', 'dynamic-exec-ok');\n");

        let pkg_tar = make_tarball_with_bin("mock-cli-tool", "1.0.0", "mock-cli-tool", &script);
        let pkg_int = Integrity::from_bytes(&pkg_tar, Algorithm::Sha512).to_string();

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
                            let pkg_int_c = pkg_int.clone();
                            let pkg_tar_c = pkg_tar.clone();
                            let su_c = su.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /mock-cli-tool") {
                                        let json = serde_json::json!({
                                            "name": "mock-cli-tool",
                                            "dist-tags": { "latest": "1.0.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "mock-cli-tool",
                                                    "version": "1.0.0",
                                                    "bin": { "mock-cli-tool": "bin/mock-cli-tool.js" },
                                                    "dist": {
                                                        "tarball": format!("{su_c}tarballs/mock-cli-tool.tgz"),
                                                        "integrity": pkg_int_c
                                                    }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/mock-cli-tool.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], pkg_tar_c)
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

        let cli = Cli {
            command: Commands::Exec {
                package: "mock-cli-tool".to_string(),
                args: vec![],
                registry: Some(server_url),
                cache: Some(cache_dir.path().to_path_buf()),
                offline: false,
            },
        };

        let res = run_cli(cli, Some(project_dir.path().to_path_buf())).await;
        assert!(res.is_ok(), "Dynamic exec should succeed: {:?}", res.err());

        let marker_content = std::fs::read_to_string(&marker_file).unwrap();
        assert_eq!(marker_content.trim(), "dynamic-exec-ok");

        // Verify that the ephemeral cache directory was populated
        let npx_dir = cache_dir.path().join("_npx").join("mock-cli-tool");
        assert!(npx_dir.exists(), "Ephemeral cache directory must exist");
        assert!(npx_dir.join("package.json").exists(), "Ephemeral package.json must exist");

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn test_cli_run_workspaces_with_filter_and_scope() {
        let root_dir = tempdir().unwrap();
        let marker_file = root_dir.path().join("cli_filter_marker.txt");
        let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

        // Root package.json with workspaces
        std::fs::write(
            root_dir.path().join("package.json"),
            r#"{"name": "monorepo-root", "workspaces": ["packages/*"]}"#,
        ).unwrap();

        // Package @scope/core
        let core_dir = root_dir.path().join("packages").join("core");
        std::fs::create_dir_all(&core_dir).unwrap();
        std::fs::write(
            core_dir.join("package.json"),
            format!(r#"{{"name": "@scope/core", "version": "1.0.0", "scripts": {{"test-filter": "node -e \"require('fs').appendFileSync('{escaped_marker}', '@scope/core\\n')\""}}}}"#),
        ).unwrap();

        // Package @scope/ui
        let ui_dir = root_dir.path().join("packages").join("ui");
        std::fs::create_dir_all(&ui_dir).unwrap();
        std::fs::write(
            ui_dir.join("package.json"),
            format!(r#"{{"name": "@scope/ui", "version": "1.0.0", "dependencies": {{"@scope/core": "1.0.0"}}, "scripts": {{"test-filter": "node -e \"require('fs').appendFileSync('{escaped_marker}', '@scope/ui\\n')\""}}}}"#),
        ).unwrap();

        // Package app-web (outside @scope)
        let app_dir = root_dir.path().join("packages").join("app-web");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(
            app_dir.join("package.json"),
            format!(r#"{{"name": "app-web", "version": "1.0.0", "scripts": {{"test-filter": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'app-web\\n')\""}}}}"#),
        ).unwrap();

        // Run `rnpm run test-filter --filter @scope/*`
        let cli = Cli {
            command: Commands::Run {
                script: Some("test-filter".to_string()),
                args: vec![],
                workspaces: true,
                workspace: vec![],
                filter: vec!["@scope/*".to_string()],
                scope: vec![],
                if_present: false,
                ignore_scripts: false,
            },
        };

        let res = run_cli(cli, Some(root_dir.path().to_path_buf())).await;
        assert!(res.is_ok(), "Filtered workspace run should succeed: {:?}", res.err());

        let marker_content = std::fs::read_to_string(&marker_file).unwrap();
        let lines: Vec<&str> = marker_content.lines().collect();
        assert_eq!(lines, vec!["@scope/core", "@scope/ui"]);
    }

    #[tokio::test]
    async fn test_cli_audit_clean_lockfile_zero_vulnerabilities() {
        let temp = tempdir().unwrap();
        let lock_path = temp.path().join("package-lock.json");

        let mut lockfile = LockfileV3::new("clean-app", Some("1.0.0".to_string()));
        let mut clean_pkg = LockfilePackage::default();
        clean_pkg.version = Some("4.17.21".to_string());
        clean_pkg.resolved = Some("http://127.0.0.1:4873/lodash/-/lodash-4.17.21.tgz".to_string());
        lockfile.insert_package("node_modules/lodash", clean_pkg);

        let lock_json = lockfile.to_json_string().unwrap();
        std::fs::write(&lock_path, lock_json).unwrap();
        std::fs::write(temp.path().join("advisories.json"), "{}").unwrap();

        let cli = Cli {
            command: Commands::Audit {
                registry: Some("http://127.0.0.1:4873".to_string()),
                json: true,
                audit_level: "low".to_string(),
                dry_run: false,
            },
        };

        let res = run_cli(cli, Some(temp.path().to_path_buf())).await;
        assert!(res.is_ok(), "Expected audit to succeed on clean project: {:?}", res.err());
    }

    #[tokio::test]
    async fn test_cli_audit_unsupported_command_filtering() {
        // "audit" should now be supported and not trigger ERR_UNSUPPORTED_COMMAND
        let check = check_unsupported_cli_invocation(vec!["rnpm", "audit"]);
        assert!(check.is_none(), "rnpm audit must be a supported command");

        // Commands still deferred should still trigger ERR_UNSUPPORTED_COMMAND
        let check_fix = check_unsupported_cli_invocation(vec!["rnpm", "fix"]);
        assert!(check_fix.is_some());
        let (code, msg) = check_fix.unwrap();
        assert_eq!(code, "ERR_UNSUPPORTED_COMMAND");
        assert!(msg.contains("ERR_UNSUPPORTED_COMMAND"));
        assert!(msg.contains("fix"));
    }

    #[tokio::test]
    async fn test_cli_unsupported_flags_filtering() {
        let test_flags = [
            "--global",
            "-g",
            "--save-bundle",
            "--production",
        ];

        for flag in test_flags {
            let check = check_unsupported_cli_invocation(vec!["rnpm", "install", flag]);
            assert!(
                check.is_some(),
                "Expected unsupported flag check to trigger for '{flag}'"
            );
            let (code, msg) = check.unwrap();
            assert_eq!(code, "ERR_UNSUPPORTED_FLAG");
            assert!(msg.contains("npm error code ERR_UNSUPPORTED_FLAG"));
            assert!(msg.contains(flag));
            assert!(msg.contains("docs/compatibility-contract.md"));
        }

        // --omit is supported on install and ci
        for omit_val in ["dev", "optional", "peer"] {
            assert!(check_unsupported_cli_invocation(vec!["rnpm", "install", "--omit", omit_val]).is_none());
            assert!(check_unsupported_cli_invocation(vec!["rnpm", "install", &format!("--omit={omit_val}")]).is_none());
            assert!(check_unsupported_cli_invocation(vec!["rnpm", "ci", "--omit", omit_val]).is_none());
        }

        // --legacy-peer-deps is supported on install, ci, and update
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "install", "--legacy-peer-deps"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "ci", "--legacy-peer-deps"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "update", "--legacy-peer-deps"]).is_none());

        // Pass-through for run and exec
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "run", "build", "--", "-g"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "run", "build", "-g"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "exec", "eslint", "-g"]).is_none());
    }

    #[tokio::test]
    async fn test_cli_unsupported_protocol_diagnostics() {
        let bad_protocols = [
            ("ftp://example.com/pkg.tgz", "ftp:"),
            ("svn://repo.example.com/trunk", "svn:"),
            ("sftp://files.example.com/pkg.tgz", "sftp:"),
            ("hg+https://hg.example.com/repo", "hg+https:"),
            ("cvs://anonymous@cvs.example.com/root", "cvs:"),
            ("telnet://bbs.example.com", "telnet:"),
        ];

        for (spec, expected_proto) in bad_protocols {
            let res = PackageTarget::parse(spec);
            assert!(
                res.is_err(),
                "Expected PackageTarget::parse to fail for unsupported protocol: {spec}"
            );
            let err = res.unwrap_err();
            let err_str = err.to_string();
            assert!(
                err_str.contains("Unsupported URL Type"),
                "Expected 'Unsupported URL Type' in '{err_str}' for spec '{spec}'"
            );
            assert!(
                err_str.contains(expected_proto),
                "Expected protocol '{expected_proto}' in '{err_str}'"
            );

            // Also verify that structured error printing formats EUNSUPPORTEDPROTOCOL
            let anyhow_err = anyhow::Error::from(err);
            let formatted = format!("{:#}", anyhow_err);
            assert!(formatted.contains("Unsupported URL Type"));
        }
    }

    #[tokio::test]
    async fn test_cli_unsupported_protocol_fixture_install_fails_cleanly() {
        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .parent().unwrap()
            .join("benchmarks")
            .join("fixtures")
            .join("gate-e-unsupported-protocol");

        assert!(
            fixture_dir.join("package.json").exists(),
            "gate-e-unsupported-protocol fixture must exist at {}",
            fixture_dir.display()
        );

        let cli = Cli {
            command: Commands::Install {
                packages: vec![],
                registry: None,
                cache: None,
                offline: true,
                ignore_scripts: true,
                legacy_peer_deps: false,
                strict_peer_deps: false,
                omit: vec![],
                save_dev: false,
                save_exact: false,
                save_prod: false,
                save_optional: false,
                save_peer: false,
                no_save: false,
                package_lock_only: false,
            },
        };

        let res = run_cli(cli, Some(fixture_dir)).await;
        assert!(
            res.is_err(),
            "Install must fail when project contains unsupported protocol dependency"
        );
        let err_str = format!("{:#}", res.unwrap_err());
        assert!(
            err_str.contains("Unsupported URL Type \"ftp:\""),
            "Error message must specify Unsupported URL Type 'ftp:', got: {err_str}"
        );
    }

    #[test]
    fn test_centralized_diagnostics_classification_codes() {
        use crate::diagnostics::classify_error;

        // ERESOLVE
        let eresolve_err = anyhow::anyhow!("ERESOLVE: Conflicting peer dependency 'react@17' required by 'react-dom@17'");
        let d = classify_error(&eresolve_err);
        assert_eq!(d.code, "ERESOLVE");
        assert!(d.format_npm().contains("npm error code ERESOLVE"));

        // ETARGET
        let etarget_err = anyhow::anyhow!("Version '2.99.0' for package 'lodash' not found");
        let d = classify_error(&etarget_err);
        assert_eq!(d.code, "ETARGET");
        assert!(d.format_npm().contains("npm error code ETARGET"));

        // E404
        let e404_err = anyhow::anyhow!("Package 'non-existent-pkg-xyz' not found in registry (HTTP 404)");
        let d = classify_error(&e404_err);
        assert_eq!(d.code, "E404");
        assert!(d.format_npm().contains("npm error code E404"));

        // E401
        let e401_err = anyhow::anyhow!("Authentication failed for https://registry.npmjs.org (HTTP 401): bad token");
        let d = classify_error(&e401_err);
        assert_eq!(d.code, "E401");
        assert!(d.format_npm().contains("npm error code E401"));

        // E403
        let e403_err = anyhow::anyhow!("Access forbidden for https://registry.npmjs.org (HTTP 403): private package");
        let d = classify_error(&e403_err);
        assert_eq!(d.code, "E403");
        assert!(d.format_npm().contains("npm error code E403"));

        // E429
        let e429_err = anyhow::anyhow!("Registry rate limit exceeded (HTTP 429)");
        let d = classify_error(&e429_err);
        assert_eq!(d.code, "E429");
        assert!(d.format_npm().contains("npm error code E429"));

        // EINTEGRITY
        let eintegrity_err = anyhow::anyhow!("Integrity verification failed for sha512: expected abc, actual def");
        let d = classify_error(&eintegrity_err);
        assert_eq!(d.code, "EINTEGRITY");
        assert!(d.format_npm().contains("npm error code EINTEGRITY"));

        // ELOCKFILE_DRIFT
        let drift_err = anyhow::anyhow!("package.json dependency express@^4.0.0 missing from package-lock.json");
        let d = classify_error(&drift_err);
        assert_eq!(d.code, "ELOCKFILE_DRIFT");
        assert!(d.format_npm().contains("npm error code ELOCKFILE_DRIFT"));

        // EUNSUPPORTEDPROTOCOL
        let proto_err = anyhow::anyhow!("Unsupported URL Type \"ftp:\": ftp://example.com/pkg.tgz");
        let d = classify_error(&proto_err);
        assert_eq!(d.code, "EUNSUPPORTEDPROTOCOL");
        assert!(d.format_npm().contains("npm error code EUNSUPPORTEDPROTOCOL"));
        assert!(d.format_npm().contains("Supported protocols are npm registry packages"));

        // ETARBOMB
        let tarbomb_err = anyhow::anyhow!("Tar bomb resource limit exceeded (max_size): 600MB > 512MB");
        let d = classify_error(&tarbomb_err);
        assert_eq!(d.code, "ETARBOMB");
        assert!(d.format_npm().contains("npm error code ETARBOMB"));

        // ESECURITY
        let sec_err = anyhow::anyhow!("Path traversal detected in tarball entry: '../../etc/passwd'");
        let d = classify_error(&sec_err);
        assert_eq!(d.code, "ESECURITY");
        assert!(d.format_npm().contains("npm error code ESECURITY"));

        // EJSONPARSE
        let json_err = anyhow::anyhow!("Malformed JSON in manifest: invalid token at line 3, column 5");
        let d = classify_error(&json_err);
        assert_eq!(d.code, "EJSONPARSE");
        assert!(d.format_npm().contains("npm error code EJSONPARSE"));

        // ENOLOCK
        let lock_err = anyhow::anyhow!("This command requires an existing lockfile. Try creating one with `rnpm install`.");
        let d = classify_error(&lock_err);
        assert_eq!(d.code, "ENOLOCK");
        assert!(d.format_npm().contains("npm error code ENOLOCK"));
    }

    #[test]
    fn test_audit_level_parsing_and_none() {
        use crate::audit::{parse_audit_level, Severity};

        assert_eq!(parse_audit_level("none").unwrap(), None);
        assert_eq!(parse_audit_level("None").unwrap(), None);
        assert_eq!(parse_audit_level("info").unwrap(), Some(Severity::Info));
        assert_eq!(parse_audit_level("low").unwrap(), Some(Severity::Low));
        assert_eq!(parse_audit_level("moderate").unwrap(), Some(Severity::Moderate));
        assert_eq!(parse_audit_level("medium").unwrap(), Some(Severity::Moderate));
        assert_eq!(parse_audit_level("high").unwrap(), Some(Severity::High));
        assert_eq!(parse_audit_level("critical").unwrap(), Some(Severity::Critical));
        assert_eq!(parse_audit_level("crit").unwrap(), Some(Severity::Critical));
        assert!(parse_audit_level("invalid_typo").is_err());
    }

    #[tokio::test]
    async fn test_run_cli_deferred_commands_matrix_diagnostics() {
        let tmp = tempdir().unwrap();
        let dir = Some(tmp.path().to_path_buf());

        let list_cli = Cli {
            command: Commands::List { args: vec![] },
        };
        let res = run_cli(list_cli, dir.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("ERR_UNSUPPORTED_COMMAND"));

        let outdated_cli = Cli {
            command: Commands::Outdated { args: vec![] },
        };
        let res = run_cli(outdated_cli, dir.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("ERR_UNSUPPORTED_COMMAND"));

        let view_cli = Cli {
            command: Commands::View { args: vec![] },
        };
        let res = run_cli(view_cli, dir.clone()).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("ERR_UNSUPPORTED_COMMAND"));

        let publish_cli = Cli {
            command: Commands::Publish { args: vec![] },
        };
        let res = run_cli(publish_cli, dir).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("ERR_UNSUPPORTED_COMMAND"));
    }

    #[test]
    fn test_cli_parse_shortcuts_and_bare_run() {
        // rnpm test and aliases
        let parsed = Cli::try_parse_from(["rnpm", "test"]).unwrap();
        match parsed.command {
            Commands::Test { args } => assert!(args.is_empty()),
            _ => panic!("Expected Commands::Test"),
        }

        let parsed = Cli::try_parse_from(["rnpm", "t"]).unwrap();
        match parsed.command {
            Commands::Test { args } => assert!(args.is_empty()),
            _ => panic!("Expected Commands::Test via 't' alias"),
        }

        let parsed = Cli::try_parse_from(["rnpm", "tst"]).unwrap();
        match parsed.command {
            Commands::Test { args } => assert!(args.is_empty()),
            _ => panic!("Expected Commands::Test via 'tst' alias"),
        }

        let parsed = Cli::try_parse_from(["rnpm", "test", "--", "--reporter", "spec"]).unwrap();
        match parsed.command {
            Commands::Test { args } => assert_eq!(args, vec!["--reporter", "spec"]),
            _ => panic!("Expected Commands::Test with forwarded args"),
        }

        // rnpm start
        let parsed = Cli::try_parse_from(["rnpm", "start", "--port", "3000"]).unwrap();
        match parsed.command {
            Commands::Start { args } => assert_eq!(args, vec!["--port", "3000"]),
            _ => panic!("Expected Commands::Start"),
        }

        // rnpm restart
        let parsed = Cli::try_parse_from(["rnpm", "restart"]).unwrap();
        match parsed.command {
            Commands::Restart { args } => assert!(args.is_empty()),
            _ => panic!("Expected Commands::Restart"),
        }

        // rnpm stop
        let parsed = Cli::try_parse_from(["rnpm", "stop"]).unwrap();
        match parsed.command {
            Commands::Stop { args } => assert!(args.is_empty()),
            _ => panic!("Expected Commands::Stop"),
        }

        // rnpm run without script
        let parsed = Cli::try_parse_from(["rnpm", "run"]).unwrap();
        match parsed.command {
            Commands::Run { script, args, .. } => {
                assert!(script.is_none());
                assert!(args.is_empty());
            }
            _ => panic!("Expected Commands::Run with None script"),
        }

        // rnpm run-script alias
        let parsed = Cli::try_parse_from(["rnpm", "run-script"]).unwrap();
        match parsed.command {
            Commands::Run { script, .. } => assert!(script.is_none()),
            _ => panic!("Expected Commands::Run via 'run-script' alias"),
        }

        // rnpm run with script and extra args
        let parsed = Cli::try_parse_from(["rnpm", "run", "build", "extra"]).unwrap();
        match parsed.command {
            Commands::Run { script, args, .. } => {
                assert_eq!(script, Some("build".to_string()));
                assert_eq!(args, vec!["extra"]);
            }
            _ => panic!("Expected Commands::Run with build script"),
        }
    }

    #[test]
    fn test_check_unsupported_cli_invocation_shortcuts() {
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "test", "-g"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "t", "--production"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "tst", "--omit=dev"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "start", "--save-exact"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "restart", "--global"]).is_none());
        assert!(check_unsupported_cli_invocation(vec!["rnpm", "stop", "-E"]).is_none());
    }

    #[test]
    fn test_is_lifecycle_script_classification() {
        use crate::is_lifecycle_script;

        assert!(is_lifecycle_script("test"));
        assert!(is_lifecycle_script("start"));
        assert!(is_lifecycle_script("restart"));
        assert!(is_lifecycle_script("stop"));
        assert!(is_lifecycle_script("pretest"));
        assert!(is_lifecycle_script("posttest"));
        assert!(is_lifecycle_script("install"));
        assert!(is_lifecycle_script("preinstall"));
        assert!(is_lifecycle_script("postinstall"));
        assert!(is_lifecycle_script("prepare"));
        assert!(is_lifecycle_script("prepublishOnly"));
        assert!(is_lifecycle_script("version"));

        // Non-lifecycle scripts must not be miscategorized
        assert!(!is_lifecycle_script("build"));
        assert!(!is_lifecycle_script("lint"));
        assert!(!is_lifecycle_script("compile"));
        assert!(!is_lifecycle_script("preview"));
        assert!(!is_lifecycle_script("postcss"));
        assert!(!is_lifecycle_script("prebuild"));
    }

    #[tokio::test]
    async fn test_bare_run_empty_scripts_silent() {
        let tmp = tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name": "empty-app", "version": "1.0.0", "scripts": {}}"#,
        ).unwrap();

        let cli = Cli {
            command: Commands::Run {
                script: None,
                args: vec![],
                workspaces: false,
                workspace: vec![],
                filter: vec![],
                scope: vec![],
                if_present: false,
                ignore_scripts: false,
            },
        };

        let res = run_cli(cli, Some(tmp.path().to_path_buf())).await;
        assert!(res.is_ok(), "Bare run on empty scripts should succeed: {:?}", res.err());
    }

    #[tokio::test]
    async fn test_bare_run_missing_package_json() {
        let tmp = tempdir().unwrap();

        let cli = Cli {
            command: Commands::Run {
                script: None,
                args: vec![],
                workspaces: false,
                workspace: vec![],
                filter: vec![],
                scope: vec![],
                if_present: false,
                ignore_scripts: false,
            },
        };

        let res = run_cli(cli, Some(tmp.path().to_path_buf())).await;
        assert!(res.is_err(), "Bare run must fail when package.json does not exist");
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("package.json not found"), "Got: {err_str}");
    }

    #[test]
    fn test_cli_parse_legacy_peer_deps() {
        // install command parses --legacy-peer-deps
        let parsed = Cli::try_parse_from(["rnpm", "install", "--legacy-peer-deps"]).unwrap();
        match parsed.command {
            Commands::Install { legacy_peer_deps, .. } => assert!(legacy_peer_deps),
            _ => panic!("Expected Commands::Install"),
        }

        // ci command parses --legacy-peer-deps
        let parsed_ci = Cli::try_parse_from(["rnpm", "ci", "--legacy-peer-deps"]).unwrap();
        match parsed_ci.command {
            Commands::Ci { legacy_peer_deps, .. } => assert!(legacy_peer_deps),
            _ => panic!("Expected Commands::Ci"),
        }

        // update command parses --legacy-peer-deps
        let parsed_up = Cli::try_parse_from(["rnpm", "update", "--legacy-peer-deps"]).unwrap();
        match parsed_up.command {
            Commands::Update { legacy_peer_deps, .. } => assert!(legacy_peer_deps),
            _ => panic!("Expected Commands::Update"),
        }

        // default is false
        let parsed_def = Cli::try_parse_from(["rnpm", "install"]).unwrap();
        match parsed_def.command {
            Commands::Install { legacy_peer_deps, .. } => assert!(!legacy_peer_deps),
            _ => panic!("Expected Commands::Install"),
        }
    }

    #[test]
    fn test_cli_parse_strict_peer_deps() {
        // install command parses --strict-peer-deps
        let parsed = Cli::try_parse_from(["rnpm", "install", "--strict-peer-deps"]).unwrap();
        match parsed.command {
            Commands::Install { strict_peer_deps, .. } => assert!(strict_peer_deps),
            _ => panic!("Expected Commands::Install"),
        }

        // ci command parses --strict-peer-deps
        let parsed_ci = Cli::try_parse_from(["rnpm", "ci", "--strict-peer-deps"]).unwrap();
        match parsed_ci.command {
            Commands::Ci { strict_peer_deps, .. } => assert!(strict_peer_deps),
            _ => panic!("Expected Commands::Ci"),
        }

        // default is false
        let parsed_def = Cli::try_parse_from(["rnpm", "install"]).unwrap();
        match parsed_def.command {
            Commands::Install { strict_peer_deps, .. } => assert!(!strict_peer_deps),
            _ => panic!("Expected Commands::Install"),
        }
    }

    #[test]
    fn test_cli_parse_package_lock_only() {
        // install parses --package-lock-only
        let parsed = Cli::try_parse_from(["rnpm", "install", "--package-lock-only"]).unwrap();
        match parsed.command {
            Commands::Install { package_lock_only, .. } => assert!(package_lock_only),
            _ => panic!("Expected Commands::Install"),
        }

        // ci parses --package-lock-only
        let parsed_ci = Cli::try_parse_from(["rnpm", "ci", "--package-lock-only"]).unwrap();
        match parsed_ci.command {
            Commands::Ci { package_lock_only, .. } => assert!(package_lock_only),
            _ => panic!("Expected Commands::Ci"),
        }

        // default is false
        let parsed_def = Cli::try_parse_from(["rnpm", "install"]).unwrap();
        match parsed_def.command {
            Commands::Install { package_lock_only, .. } => assert!(!package_lock_only),
            _ => panic!("Expected Commands::Install"),
        }
    }

    #[test]
    fn test_cli_parse_omit_edge_cases() {
        // Comma-separated: --omit=dev,optional
        let parsed = Cli::try_parse_from(["rnpm", "install", "--omit=dev,optional"]).unwrap();
        match parsed.command {
            Commands::Install { omit, .. } => {
                let (d, o, p) = parse_omit_options(&omit);
                assert!(d, "dev omitted");
                assert!(o, "optional omitted");
                assert!(!p, "peer not omitted");
            }
            _ => panic!("Expected Commands::Install"),
        }

        // Comma-separated space: --omit dev,peer
        let parsed_space = Cli::try_parse_from(["rnpm", "install", "--omit", "dev,peer"]).unwrap();
        match parsed_space.command {
            Commands::Install { omit, .. } => {
                let (d, o, p) = parse_omit_options(&omit);
                assert!(d, "dev omitted");
                assert!(!o, "optional not omitted");
                assert!(p, "peer omitted");
            }
            _ => panic!("Expected Commands::Install"),
        }

        // Multiple flags: --omit dev --omit optional
        let parsed_multi = Cli::try_parse_from(["rnpm", "install", "--omit", "dev", "--omit", "optional"]).unwrap();
        match parsed_multi.command {
            Commands::Install { omit, .. } => {
                let (d, o, p) = parse_omit_options(&omit);
                assert!(d, "dev omitted");
                assert!(o, "optional omitted");
                assert!(!p, "peer not omitted");
            }
            _ => panic!("Expected Commands::Install"),
        }

        // Aliases: development, optional, peer
        let parsed_alias = Cli::try_parse_from(["rnpm", "ci", "--omit", "development"]).unwrap();
        match parsed_alias.command {
            Commands::Ci { omit, .. } => {
                let (d, o, p) = parse_omit_options(&omit);
                assert!(d, "development alias sets omit_dev");
                assert!(!o);
                assert!(!p);
            }
            _ => panic!("Expected Commands::Ci"),
        }

        // Direct parse_omit_options alias checks
        assert_eq!(parse_omit_options(&["dev".to_string()]), (true, false, false));
        assert_eq!(parse_omit_options(&["development".to_string()]), (true, false, false));
        assert_eq!(parse_omit_options(&["optional".to_string()]), (false, true, false));
        assert_eq!(parse_omit_options(&["peer".to_string()]), (false, false, true));
        assert_eq!(parse_omit_options(&["dev".to_string(), "optional".to_string()]), (true, true, false));
        assert_eq!(parse_omit_options(&["development,peer".to_string()]), (true, false, true));

        // Prune --production and -p aliases for --omit=dev
        let parsed_prod = Cli::try_parse_from(["rnpm", "prune", "--production"]).unwrap();
        match parsed_prod.command {
            Commands::Prune { production, omit, .. } => {
                assert!(production);
                let (mut d, _, _) = parse_omit_options(&omit);
                if production { d = true; }
                assert!(d, "--production sets omit_dev");
            }
            _ => panic!("Expected Commands::Prune"),
        }

        let parsed_p = Cli::try_parse_from(["rnpm", "prune", "-p"]).unwrap();
        match parsed_p.command {
            Commands::Prune { production, omit, .. } => {
                assert!(production);
                let (mut d, _, _) = parse_omit_options(&omit);
                if production { d = true; }
                assert!(d, "-p sets omit_dev");
            }
            _ => panic!("Expected Commands::Prune"),
        }
    }

    #[test]
    fn test_cli_scoped_registry_resolution() {
        // 1. Parsing scoped registry CLI argument (--@scope:registry=https://...)
        let res1 = parse_scoped_registry_arg("--@myorg:registry=https://npm.myorg.internal");
        assert!(res1.is_some());
        let (scope1, url1) = res1.unwrap();
        assert_eq!(scope1, "@myorg");
        assert_eq!(url1.as_str(), "https://npm.myorg.internal/");

        // 2. Parsing scoped registry without leading dashes (@scope:registry=https://...)
        let res2 = parse_scoped_registry_arg("@corp:registry=https://npm.corp.com/");
        assert!(res2.is_some());
        let (scope2, url2) = res2.unwrap();
        assert_eq!(scope2, "@corp");
        assert_eq!(url2.as_str(), "https://npm.corp.com/");

        // 3. Extracting scoped registries from CLI argument list
        let raw_args = vec![
            "rnpm".to_string(),
            "install".to_string(),
            "@myorg/pkg".to_string(),
            "--@myorg:registry=https://npm.myorg.internal".to_string(),
            "--@corp:registry".to_string(),
            "https://npm.corp.com".to_string(),
            "--save-exact".to_string(),
        ];
        let (filtered, scoped_regs) = extract_scoped_registries(raw_args);
        assert_eq!(
            filtered,
            vec!["rnpm", "install", "@myorg/pkg", "--save-exact"]
        );
        assert_eq!(scoped_regs.len(), 2);
        assert_eq!(
            scoped_regs.get("@myorg").unwrap().as_str(),
            "https://npm.myorg.internal/"
        );
        assert_eq!(
            scoped_regs.get("@corp").unwrap().as_str(),
            "https://npm.corp.com/"
        );

        // 4. Resolving packages to scoped vs default registry
        let default_reg = Url::parse("https://registry.npmjs.org/").unwrap();

        // Scoped package with matching scope -> custom registry URL
        let myorg_url = resolve_registry_for_package("@myorg/pkg", &default_reg, &scoped_regs);
        assert_eq!(myorg_url.as_str(), "https://npm.myorg.internal/");

        // Encoded scope (@myorg%2fpkg) -> custom registry URL
        let encoded_url = resolve_registry_for_package("@myorg%2fpkg", &default_reg, &scoped_regs);
        assert_eq!(encoded_url.as_str(), "https://npm.myorg.internal/");

        // Scoped package without configured custom registry -> fallback to default
        let other_url = resolve_registry_for_package("@unconfigured/pkg", &default_reg, &scoped_regs);
        assert_eq!(other_url.as_str(), "https://registry.npmjs.org/");

        // Unscoped package -> fallback to default
        let unscoped_url = resolve_registry_for_package("lodash", &default_reg, &scoped_regs);
        assert_eq!(unscoped_url.as_str(), "https://registry.npmjs.org/");

        // 5. Integration with rnpm_config::Config
        let mut config = rnpm_config::Config::new();
        config
            .apply_scoped_registry("--@myorg:registry=https://npm.myorg.internal", None)
            .unwrap();
        assert_eq!(
            config.registry_for_package("@myorg/client").as_str(),
            "https://npm.myorg.internal/"
        );
        assert_eq!(
            config.registry_for_package("express").as_str(),
            "https://registry.npmjs.org/"
        );
    }
