use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_install::{InstallOptions, Installer};

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{}", rel_path);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .expect("Failed to append tar entry");
        }
        builder.finish().expect("Failed to finish tar archive");
    }
    gz.finish().expect("Failed to finish gzip compression")
}

fn compute_ssri(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("sha512-{}", data_encoding::BASE64.encode(&hash))
}

struct TestRegistryServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestRegistryServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)>
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();

                                    let (status, headers, body) = match handler_clone(&path, &base_url) {
                                        Some(resp) => resp,
                                        None => (404, vec![("Content-Type", "text/plain".to_string())], b"Not Found".to_vec()),
                                    };

                                    let status_text = match status {
                                        200 => "OK",
                                        404 => "Not Found",
                                        500 => "Internal Server Error",
                                        _ => "Response",
                                    };

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

        Self {
            addr,
            _shutdown: tx,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

#[tokio::test]
async fn test_nested_node_modules_bin_shortcuts_install_and_ci() {
    // Packages in diamond conflict:
    // root -> direct-lib@1.0.0, parent-lib@1.0.0
    // direct-lib@1.0.0 -> tool-pkg@^1.0.0
    // parent-lib@1.0.0 -> tool-pkg@^2.0.0
    // tool-pkg@1.0.0 has bin: tool-cli -> bin/cli.js
    // tool-pkg@2.0.0 has bin: tool-cli -> bin/cli.js

    let direct_lib_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"direct-lib","version":"1.0.0","dependencies":{"tool-pkg":"^1.0.0"}}"#,
        ),
        ("index.js", b"module.exports = 'direct-lib';"),
    ]);
    let direct_lib_integrity = compute_ssri(&direct_lib_tarball);

    let parent_lib_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"parent-lib","version":"1.0.0","dependencies":{"tool-pkg":"^2.0.0"}}"#,
        ),
        ("index.js", b"module.exports = 'parent-lib';"),
    ]);
    let parent_lib_integrity = compute_ssri(&parent_lib_tarball);

    let tool_1_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"tool-pkg","version":"1.0.0","bin":{"tool-cli":"./bin/cli.js"}}"#,
        ),
        (
            "bin/cli.js",
            b"#!/usr/bin/env node\nconsole.log('tool v1.0.0');\n",
        ),
    ]);
    let tool_1_integrity = compute_ssri(&tool_1_tarball);

    let tool_2_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"tool-pkg","version":"2.0.0","bin":{"tool-cli":"./bin/cli.js"}}"#,
        ),
        (
            "bin/cli.js",
            b"#!/usr/bin/env node\nconsole.log('tool v2.0.0');\n",
        ),
    ]);
    let tool_2_integrity = compute_ssri(&tool_2_tarball);

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/direct-lib" => {
            let json = serde_json::json!({
                "name": "direct-lib",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "direct-lib",
                        "version": "1.0.0",
                        "dependencies": { "tool-pkg": "^1.0.0" },
                        "dist": {
                            "tarball": format!("{base_url}/direct-lib/-/direct-lib-1.0.0.tgz"),
                            "integrity": direct_lib_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                json.to_string().into_bytes(),
            ))
        }
        "/parent-lib" => {
            let json = serde_json::json!({
                "name": "parent-lib",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "parent-lib",
                        "version": "1.0.0",
                        "dependencies": { "tool-pkg": "^2.0.0" },
                        "dist": {
                            "tarball": format!("{base_url}/parent-lib/-/parent-lib-1.0.0.tgz"),
                            "integrity": parent_lib_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                json.to_string().into_bytes(),
            ))
        }
        "/tool-pkg" => {
            let json = serde_json::json!({
                "name": "tool-pkg",
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "tool-pkg",
                        "version": "1.0.0",
                        "bin": { "tool-cli": "./bin/cli.js" },
                        "dist": {
                            "tarball": format!("{base_url}/tool-pkg/-/tool-pkg-1.0.0.tgz"),
                            "integrity": tool_1_integrity
                        }
                    },
                    "2.0.0": {
                        "name": "tool-pkg",
                        "version": "2.0.0",
                        "bin": { "tool-cli": "./bin/cli.js" },
                        "dist": {
                            "tarball": format!("{base_url}/tool-pkg/-/tool-pkg-2.0.0.tgz"),
                            "integrity": tool_2_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                json.to_string().into_bytes(),
            ))
        }
        p if p.ends_with("/direct-lib-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            direct_lib_tarball.clone(),
        )),
        p if p.ends_with("/parent-lib-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            parent_lib_tarball.clone(),
        )),
        p if p.ends_with("/tool-pkg-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            tool_1_tarball.clone(),
        )),
        p if p.ends_with("/tool-pkg-2.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            tool_2_tarball.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "nested-bin-test",
        "version": "1.0.0",
        "dependencies": {
            "direct-lib": "^1.0.0",
            "parent-lib": "^1.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let options = InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    };

    // 1. Run full install
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 4);

    let node_modules = temp_proj.path().join("node_modules");
    assert!(node_modules.join("direct-lib").exists());
    assert!(node_modules.join("parent-lib").exists());

    // tool-pkg@1.0.0 is hoisted to root node_modules, tool-pkg@2.0.0 is nested under parent-lib
    let root_tool = node_modules.join("tool-pkg");
    assert!(root_tool.exists());

    let nested_nm = node_modules.join("parent-lib").join("node_modules");
    let nested_tool = nested_nm.join("tool-pkg");
    assert!(
        nested_tool.exists(),
        "Conflicting tool-pkg v2 must be nested under parent-lib/node_modules"
    );

    // Root .bin should have tool-cli
    let root_bin = node_modules.join(".bin");
    assert!(root_bin.exists());
    #[cfg(windows)]
    {
        assert!(root_bin.join("tool-cli.cmd").exists());
        assert!(root_bin.join("tool-cli.ps1").exists());
    }
    #[cfg(not(windows))]
    {
        assert!(root_bin.join("tool-cli").exists());
    }

    // Nested .bin MUST exist at parent-lib/node_modules/.bin
    let nested_bin = nested_nm.join(".bin");
    assert!(
        nested_bin.exists(),
        "Nested .bin directory must exist at parent-lib/node_modules/.bin"
    );
    #[cfg(windows)]
    {
        assert!(
            nested_bin.join("tool-cli.cmd").exists(),
            "tool-cli.cmd must exist in nested .bin"
        );
        assert!(
            nested_bin.join("tool-cli.ps1").exists(),
            "tool-cli.ps1 must exist in nested .bin"
        );
    }
    #[cfg(not(windows))]
    {
        assert!(
            nested_bin.join("tool-cli").exists(),
            "tool-cli must exist in nested .bin"
        );
    }

    // Check shim contents in nested .bin points to ../tool-pkg/bin/cli.js
    #[cfg(windows)]
    {
        let cmd_content = std::fs::read_to_string(nested_bin.join("tool-cli.cmd")).unwrap();
        assert!(
            cmd_content.contains(r"..\tool-pkg\bin\cli.js"),
            "Nested CMD shim must point to ..\\tool-pkg\\bin\\cli.js, got:\n{cmd_content}"
        );
    }
    let posix_content = std::fs::read_to_string(nested_bin.join("tool-cli")).unwrap();
    assert!(
        posix_content.contains("../tool-pkg/bin/cli.js"),
        "Nested POSIX shim must point to ../tool-pkg/bin/cli.js, got:\n{posix_content}"
    );

    // 2. Wipe node_modules and run CI install (run_ci)
    std::fs::remove_dir_all(&node_modules).unwrap();
    assert!(!node_modules.exists());

    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 4);

    // Verify both root and nested .bin exist after run_ci
    assert!(root_bin.exists(), "Root .bin must exist after run_ci");
    assert!(nested_bin.exists(), "Nested .bin must exist after run_ci");

    #[cfg(windows)]
    {
        assert!(
            nested_bin.join("tool-cli.cmd").exists(),
            "tool-cli.cmd must exist in nested .bin after run_ci"
        );
        assert!(
            nested_bin.join("tool-cli.ps1").exists(),
            "tool-cli.ps1 must exist in nested .bin after run_ci"
        );
        let ci_cmd = std::fs::read_to_string(nested_bin.join("tool-cli.cmd")).unwrap();
        assert!(ci_cmd.contains(r"..\tool-pkg\bin\cli.js"));
    }
    #[cfg(not(windows))]
    {
        assert!(
            nested_bin.join("tool-cli").exists(),
            "tool-cli must exist in nested .bin after run_ci"
        );
    }
}
