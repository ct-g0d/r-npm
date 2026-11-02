use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_core::integrity::{Algorithm, Integrity};
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
<<<<<<< HEAD
        let commands = ["publish", "login", "audit", "token", "deprecate"];
=======
        let commands = ["publish", "login", "fix", "token", "exec"];
>>>>>>> t3/feat-agy5-audit-real-corpus
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
        let flags = ["--legacy-peer-deps", "--global", "-g"];
        for flag in flags {
            let res = check_unsupported_cli_invocation(vec!["rnpm", "install", flag]);
            assert!(res.is_some(), "Expected diagnostic for flag: {flag}");
            let (code, msg) = res.unwrap();
            assert_eq!(code, "ERR_UNSUPPORTED_FLAG");
            assert!(msg.contains("npm error code ERR_UNSUPPORTED_FLAG"));
            assert!(msg.contains(&format!("The flag '{flag}' is not supported by rnpm.")));
        }
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
                err_str.contains("Unsupported protocol"),
                "Expected UnsupportedProtocol error, got: {err_str}"
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
                script: "build".to_string(),
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
                script: "build".to_string(),
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
                script: "test-filter".to_string(),
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
        let (code, _) = check_fix.unwrap();
        assert_eq!(code, "ERR_UNSUPPORTED_COMMAND");
    }
}
