use rnpm_core::Manifest;
use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::LockfileV3;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct MockInstallServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockInstallServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str, &str) -> (u16, Vec<(&'static str, String)>, Vec<u8>)
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
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        let Ok((mut socket, _)) = accept_res else { break; };
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let n = socket.read(&mut buf).await.unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let first_line = req.lines().next().unwrap_or("");
                            let mut parts = first_line.split_whitespace();
                            let method = parts.next().unwrap_or("GET");
                            let path = parts.next().unwrap_or("/");

                            // Extract accept header
                            let mut accept_hdr = "";
                            for line in req.lines() {
                                if let Some(stripped) = line.strip_prefix("accept: ") {
                                    accept_hdr = stripped.trim();
                                    break;
                                } else if let Some(stripped) = line.strip_prefix("Accept: ") {
                                    accept_hdr = stripped.trim();
                                    break;
                                }
                            }

                            let (status, headers, body) = handler(method, path, accept_hdr);
                            let status_text = match status {
                                200 => "OK",
                                304 => "Not Modified",
                                404 => "Not Found",
                                _ => "Custom",
                            };

                            let mut resp = format!(
                                "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                body.len()
                            );
                            for (k, v) in headers {
                                resp.push_str(&format!("{k}: {v}\r\n"));
                            }
                            resp.push_str("\r\n");

                            let _ = socket.write_all(resp.as_bytes()).await;
                            let _ = socket.write_all(&body).await;
                        });
                    }
                }
            }
        });

        Self {
            addr,
            _shutdown: tx,
        }
    }
}

#[test]
fn test_manifest_from_file_readonly_in_pipeline() {
    let tmp = tempdir().unwrap();
    let pkg_json = tmp.path().join("package.json");
    let content = r#"{
        "name": "perf-test-app",
        "version": "1.2.3",
        "dependencies": {
            "foo": "^1.0.0"
        },
        "scripts": {
            "test": "echo test"
        },
        "bin": {
            "perf-cli": "./bin/perf.js"
        }
    }"#;
    std::fs::write(&pkg_json, content).unwrap();

    let manifest = Manifest::from_file_readonly(&pkg_json).expect("failed to parse readonly");
    assert_eq!(manifest.name.as_deref(), Some("perf-test-app"));
    assert_eq!(manifest.version.as_deref(), Some("1.2.3"));
    assert!(manifest.dependencies.contains_key("foo"));
    assert!(manifest.scripts.contains_key("test"));
    assert_eq!(manifest.bin_entries().len(), 1);
    // Verified: readonly does not build raw_json DOM
    assert!(manifest.raw_json.is_none());
}

#[test]
fn test_lockfile_from_json_str_readonly_in_pipeline() {
    let lockfile_json = r#"{
        "name": "perf-test-app",
        "version": "1.2.3",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "perf-test-app",
                "version": "1.2.3",
                "dependencies": {
                    "foo": "^1.0.0"
                }
            },
            "node_modules/foo": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                "integrity": "sha512-testintegrity"
            }
        }
    }"#;

    let lockfile = LockfileV3::from_json_str_readonly(lockfile_json).expect("failed to parse readonly");
    assert_eq!(lockfile.lockfile_version, 3);
    assert_eq!(lockfile.packages.len(), 2);
    let foo = lockfile.packages.get("node_modules/foo").unwrap();
    assert_eq!(foo.version.as_deref(), Some("1.0.0"));
    assert_eq!(foo.resolved.as_deref(), Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
}

#[tokio::test]
async fn test_full_metadata_accept_header_sent_on_ideal_tree_packument_fetch() {
    let saw_full_accept = Arc::new(AtomicBool::new(false));
    let saw_flag = Arc::clone(&saw_full_accept);

    let server = MockInstallServer::start(move |_method, path, accept| {
        if path.contains("test-pkg") {
            if accept.contains("application/json")
                && !accept.contains("application/vnd.npm.install-v1+json")
            {
                saw_flag.store(true, Ordering::SeqCst);
            }
            let packument = r#"{
                "name": "test-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "time": { "1.0.0": "2024-01-01T00:00:00.000Z" },
                "versions": {
                    "1.0.0": {
                        "name": "test-pkg",
                        "version": "1.0.0",
                        "license": "MIT",
                        "dist": {
                            "tarball": "http://127.0.0.1/test-pkg-1.0.0.tgz",
                            "shasum": "0000000000000000000000000000000000000000"
                        }
                    }
                }
            }"#;
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.as_bytes().to_vec(),
            )
        } else {
            (404, vec![], b"not found".to_vec())
        }
    })
    .await;

    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().to_path_buf();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{"name":"test","dependencies":{"test-pkg":"^1.0.0"}}"#,
    )
    .unwrap();

    let opts = InstallOptions {
        project_dir,
        registry_url: Some(format!("http://127.0.0.1:{}", server.addr.port())),
        dry_run: true,
        ..Default::default()
    };

    let mut installer = Installer::new(opts).unwrap();
    let _ = installer.run().await;

    assert!(
        saw_full_accept.load(Ordering::SeqCst),
        "Expected full application/json Accept header (matching npm 11.20.0 buildIdealTree fullMetadata: true) so license/libc/workspaces/time metadata is preserved"
    );
}
