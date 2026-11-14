use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::{LockfilePackage, LockfileV3};

/// Constructs an npm-compatible .tgz archive with files rooted in `package/`.
fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{}", rel_path);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .expect("Failed to append tar entry");
        }
        builder.finish().expect("Failed to finish tar archive");
    }
    gz.finish().expect("Failed to finish gzip compression")
}

/// Compute standard npm SSRI string (`sha512-...`)
fn compute_ssri(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("sha512-{}", data_encoding::BASE64.encode(&hash))
}

/// In-memory mock registry server for tests.
struct TestRegistryServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    pub requested_paths: Arc<Mutex<Vec<String>>>,
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
        let requested_paths = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = requested_paths.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let reqs_clone = reqs.clone();
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                                    reqs_clone.lock().await.push(path.clone());

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
            requested_paths,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

#[tokio::test]
async fn test_ci_omit_dev_retains_shared_production_dependency() {
    let project = ci_omit_dev_fixture().await;
    assert!(
        project.path().join("node_modules/shared/package.json").is_file(),
        "A direct dev dependency also reached from production must follow the lockfile flags"
    );
}

#[tokio::test]
async fn test_ci_omit_dev_does_not_link_omitted_package_bins() {
    let project = ci_omit_dev_fixture().await;
    let modules = project.path().join("node_modules");
    assert!(!modules.join("devtool").exists());
    for name in ["devtool", "devtool.cmd", "devtool.ps1"] {
        assert!(!modules.join(".bin").join(name).exists(), "Omitted package must not create a dangling {name} shim");
    }
}

async fn ci_omit_dev_fixture() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let manifest = serde_json::json!({
        "name": "shared-production", "version": "1.0.0",
        "dependencies": { "prod": "1.0.0" },
        "devDependencies": { "shared": "1.0.0", "devtool": "1.0.0" }
    });
    std::fs::write(project.path().join("package.json"), manifest.to_string()).unwrap();
    let mut archives = std::collections::BTreeMap::new();
    for name in ["prod", "shared", "devtool"] {
        let mut package = serde_json::json!({ "name": name, "version": "1.0.0", "license": "MIT" });
        if name == "prod" { package["dependencies"] = serde_json::json!({ "shared": "1.0.0" }); }
        if name == "devtool" { package["bin"] = serde_json::json!({ "devtool": "cli.js" }); }
        let bytes = package.to_string().into_bytes();
        archives.insert(name.to_string(), create_test_tarball(&[("package.json", &bytes), ("cli.js", b"#!/usr/bin/env node\n")]));
    }
    let served = archives.clone();
    let server = TestRegistryServer::start(move |request, _| {
        let name = request.trim_start_matches('/').trim_end_matches(".tgz");
        served.get(name).map(|bytes| (200, vec![("Content-Type", "application/octet-stream".into())], bytes.clone()))
    }).await;
    let parsed = rnpm_core::manifest::Manifest::from_file(project.path().join("package.json")).unwrap();
    let mut lock = LockfileV3::from_manifest(&parsed);
    for (name, bytes) in archives {
        let mut entry = LockfilePackage {
            version: Some("1.0.0".into()), resolved: Some(format!("{}/{name}.tgz", server.url())),
            integrity: Some(compute_ssri(&bytes)), license: Some("MIT".into()),
            ..Default::default()
        };
        if name == "prod" { entry.dependencies = Some(std::collections::BTreeMap::from([("shared".into(), "1.0.0".into())])); }
        if name == "devtool" {
            entry.dev = Some(true);
            entry.bin = Some(rnpm_lockfile::PackageBin::Map(std::collections::BTreeMap::from([("devtool".into(), "cli.js".into())])));
        }
        lock.insert_package(&format!("node_modules/{name}"), entry);
    }
    lock.save_to_file(&project.path().join("package-lock.json")).unwrap();
    let mut installer = Installer::new(InstallOptions {
        project_dir: project.path().to_path_buf(), cache_dir: Some(cache.path().to_path_buf()),
        registry_url: Some(server.url()), omit_dev: true, ignore_scripts: true,
        ..Default::default()
    }).unwrap();
    installer.run_ci().await.unwrap();
    project
}

#[tokio::test]
async fn test_platform_skipped_scoped_optional_does_not_create_scope_directory() {
    let server = TestRegistryServer::start(|request, base| {
        if request.ends_with(".tgz") {
            panic!("Platform-skipped optional tarball must never be downloaded");
        }
        let metadata = serde_json::json!({
            "name": "@foreign/native", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {
                "name": "@foreign/native", "version": "1.0.0", "os": ["never-platform"],
                "dist": { "tarball": format!("{base}/native.tgz") }
            } }
        });
        Some((200, vec![("Content-Type", "application/json".into())], metadata.to_string().into_bytes()))
    }).await;
    let project = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("package.json"), serde_json::json!({
        "name": "optional-scope", "version": "1.0.0",
        "optionalDependencies": { "@foreign/native": "1.0.0" }
    }).to_string()).unwrap();
    let mut installer = Installer::new(InstallOptions {
        project_dir: project.path().to_path_buf(),
        cache_dir: Some(cache.path().to_path_buf()),
        registry_url: Some(server.url()),
        ignore_scripts: true,
        ..Default::default()
    }).unwrap();
    installer.run().await.unwrap();
    let lock = LockfileV3::load_from_file(&project.path().join("package-lock.json")).unwrap();
    assert!(lock.packages.contains_key("node_modules/@foreign/native"));
    assert!(
        !project.path().join("node_modules/@foreign").exists(),
        "Skipping every package in a scope must not leave an empty directory"
    );
}

#[tokio::test]
async fn test_platform_skipping_incompatible_os_or_cpu() {
    let normal_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"normal-pkg","version":"1.0.0"}"#,
        ),
        ("index.js", b"module.exports = 'normal';"),
    ]);
    let normal_integrity = compute_ssri(&normal_tarball);

    let darwin_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"darwin-pkg","version":"1.0.0","os":["darwin"],"cpu":["arm64"]}"#,
        ),
        ("index.js", b"module.exports = 'darwin';"),
    ]);
    let darwin_integrity = compute_ssri(&darwin_tarball);

    let normal_tarball_clone = normal_tarball.clone();
    let darwin_tarball_clone = darwin_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/normal-pkg" => {
            let json = serde_json::json!({
                "name": "normal-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "normal-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/normal-pkg/-/normal-pkg-1.0.0.tgz"),
                            "integrity": normal_integrity
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
        "/darwin-pkg" => {
            let json = serde_json::json!({
                "name": "darwin-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "darwin-pkg",
                        "version": "1.0.0",
                        "os": ["darwin"],
                        "cpu": ["arm64"],
                        "dist": {
                            "tarball": format!("{base_url}/darwin-pkg/-/darwin-pkg-1.0.0.tgz"),
                            "integrity": darwin_integrity
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
        p if p.ends_with("/normal-pkg-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            normal_tarball_clone.clone(),
        )),
        p if p.ends_with("/darwin-pkg-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            darwin_tarball_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let reg_url = server.url();

    // Setup temporary project directory
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "test-platform-skipping",
        "version": "1.0.0",
        "dependencies": {
            "normal-pkg": "^1.0.0"
        },
        "optionalDependencies": {
            "darwin-pkg": "^1.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    let is_darwin_arm64 = cfg!(target_os = "macos") && cfg!(target_arch = "aarch64");
    let expected_installed = if is_darwin_arm64 { 2 } else { 1 };
    assert_eq!(summary.packages_installed, expected_installed);

    // Verify normal-pkg was installed
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("normal-pkg")
        .exists());
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("normal-pkg")
        .join("index.js")
        .exists());

    // Verify darwin-pkg was SKIPPED on non-darwin-arm64 host
    if !is_darwin_arm64 {
        assert!(
            !temp_proj
                .path()
                .join("node_modules")
                .join("darwin-pkg")
                .exists(),
            "darwin-pkg must not be extracted on non-macos platform"
        );

        // Verify darwin-pkg tarball was NEVER requested from the registry!
        let paths = server.requested_paths.lock().await;
        let downloaded_darwin = paths.iter().any(|p| p.contains("darwin-pkg-1.0.0.tgz"));
        assert!(
            !downloaded_darwin,
            "darwin-pkg tarball must NEVER be downloaded"
        );
    } else {
        assert!(
            temp_proj
                .path()
                .join("node_modules")
                .join("darwin-pkg")
                .exists(),
            "darwin-pkg must be extracted on macos arm64 platform"
        );
    }
}

#[tokio::test]
async fn test_optional_download_failure_isolation() {
    let normal_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"good-pkg","version":"1.0.0"}"#)]);
    let normal_integrity = compute_ssri(&normal_tarball);
    let normal_tarball_clone = normal_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/good-pkg" => {
                let json = serde_json::json!({
                    "name": "good-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "good-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/good-pkg/-/good-pkg-1.0.0.tgz"),
                                "integrity": normal_integrity
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
            "/bad-dl-pkg" => {
                let json = serde_json::json!({
                    "name": "bad-dl-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "bad-dl-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/bad-dl-pkg/-/missing-404.tgz"),
                                "integrity": "sha512-dummy"
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
            p if p.ends_with("/good-pkg-1.0.0.tgz") => Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                normal_tarball_clone.clone(),
            )),
            // missing-404.tgz returns 404
            p if p.ends_with("/missing-404.tgz") => Some((
                404,
                vec![("Content-Type", "text/plain".to_string())],
                b"Tarball Not Found".to_vec(),
            )),
            _ => None,
        }
    })
    .await;

    let reg_url = server.url();
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    // 1. Optional dependency download failure is isolated -> install SUCCEEDS
    let root_pkg_json = serde_json::json!({
        "name": "test-opt-dl-failure",
        "version": "1.0.0",
        "dependencies": {
            "good-pkg": "^1.0.0"
        },
        "optionalDependencies": {
            "bad-dl-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url.clone()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run().await;
    assert!(
        res.is_ok(),
        "Installation must succeed despite optional download failure"
    );
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("good-pkg")
        .exists());
    assert!(!temp_proj
        .path()
        .join("node_modules")
        .join("bad-dl-pkg")
        .exists());

    // 2. Contrast: required dependency download failure MUST fail install!
    let temp_proj_req = tempfile::tempdir().unwrap();
    let root_req_json = serde_json::json!({
        "name": "test-req-dl-failure",
        "version": "1.0.0",
        "dependencies": {
            "bad-dl-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj_req.path().join("package.json"),
        root_req_json.to_string(),
    )
    .unwrap();

    let mut req_installer = Installer::new(InstallOptions {
        project_dir: temp_proj_req.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let req_res = req_installer.run().await;
    assert!(
        req_res.is_err(),
        "Required dependency download failure MUST fail install"
    );
}

#[tokio::test]
async fn test_optional_ssri_failure_isolation() {
    let normal_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"valid-pkg","version":"1.0.0"}"#)]);
    let normal_integrity = compute_ssri(&normal_tarball);

    let corrupt_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"corrupt-pkg","version":"1.0.0"}"#,
    )]);
    // Intentionally wrong integrity hash!
    let fake_integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    let normal_tarball_clone = normal_tarball.clone();
    let corrupt_tarball_clone = corrupt_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/valid-pkg" => {
            let json = serde_json::json!({
                "name": "valid-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "valid-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/valid-pkg/-/valid-pkg-1.0.0.tgz"),
                            "integrity": normal_integrity
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
        "/corrupt-pkg" => {
            let json = serde_json::json!({
                "name": "corrupt-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "corrupt-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/corrupt-pkg/-/corrupt-pkg-1.0.0.tgz"),
                            "integrity": fake_integrity
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
        p if p.ends_with("/valid-pkg-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            normal_tarball_clone.clone(),
        )),
        p if p.ends_with("/corrupt-pkg-1.0.0.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            corrupt_tarball_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let reg_url = server.url();
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    // 1. Optional dependency SSRI verification failure is caught & isolated
    let root_pkg_json = serde_json::json!({
        "name": "test-opt-ssri-failure",
        "version": "1.0.0",
        "dependencies": {
            "valid-pkg": "^1.0.0"
        },
        "optionalDependencies": {
            "corrupt-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url.clone()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run().await;
    assert!(
        res.is_ok(),
        "Installation must succeed despite optional SSRI mismatch"
    );
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("valid-pkg")
        .exists());
    assert!(!temp_proj
        .path()
        .join("node_modules")
        .join("corrupt-pkg")
        .exists());

    // 2. Contrast: required dependency SSRI mismatch MUST fail install!
    let temp_proj_req = tempfile::tempdir().unwrap();
    let root_req_json = serde_json::json!({
        "name": "test-req-ssri-failure",
        "version": "1.0.0",
        "dependencies": {
            "corrupt-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj_req.path().join("package.json"),
        root_req_json.to_string(),
    )
    .unwrap();

    let mut req_installer = Installer::new(InstallOptions {
        project_dir: temp_proj_req.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let req_res = req_installer.run().await;
    assert!(
        req_res.is_err(),
        "Required dependency SSRI mismatch MUST fail install"
    );
}

#[tokio::test]
async fn test_optional_lifecycle_failure_isolation() {
    let normal_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"clean-pkg","version":"1.0.0"}"#)]);
    let normal_integrity = compute_ssri(&normal_tarball);

    let failing_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"failing-native-pkg","version":"1.0.0","scripts":{"install":"node -e \"process.exit(1)\""}}"#),
    ]);
    let failing_integrity = compute_ssri(&failing_tarball);

    let normal_tarball_clone = normal_tarball.clone();
    let failing_tarball_clone = failing_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/clean-pkg" => {
                let json = serde_json::json!({
                    "name": "clean-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "clean-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/clean-pkg/-/clean-pkg-1.0.0.tgz"),
                                "integrity": normal_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            "/failing-native-pkg" => {
                let json = serde_json::json!({
                    "name": "failing-native-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "failing-native-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/failing-native-pkg/-/failing-native-pkg-1.0.0.tgz"),
                                "integrity": failing_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            p if p.ends_with("/clean-pkg-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], normal_tarball_clone.clone()))
            }
            p if p.ends_with("/failing-native-pkg-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], failing_tarball_clone.clone()))
            }
            _ => None,
        }
    }).await;

    let reg_url = server.url();
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    // 1. Optional dependency native build lifecycle failure is caught & isolated
    let root_pkg_json = serde_json::json!({
        "name": "test-opt-lifecycle-failure",
        "version": "1.0.0",
        "dependencies": {
            "clean-pkg": "^1.0.0"
        },
        "optionalDependencies": {
            "failing-native-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url.clone()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run().await;
    assert!(
        res.is_ok(),
        "Installation must succeed despite optional lifecycle build script failure"
    );
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("clean-pkg")
        .exists());

    // 2. Contrast: required dependency build script failure MUST fail install!
    let temp_proj_req = tempfile::tempdir().unwrap();
    let root_req_json = serde_json::json!({
        "name": "test-req-lifecycle-failure",
        "version": "1.0.0",
        "dependencies": {
            "failing-native-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj_req.path().join("package.json"),
        root_req_json.to_string(),
    )
    .unwrap();

    let mut req_installer = Installer::new(InstallOptions {
        project_dir: temp_proj_req.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let req_res = req_installer.run().await;
    assert!(
        req_res.is_err(),
        "Required dependency lifecycle script failure MUST fail install"
    );
}

#[tokio::test]
async fn test_ci_optional_platform_skipping_and_isolation() {
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    // Setup package.json
    let root_pkg_json = serde_json::json!({
        "name": "test-ci-project",
        "version": "1.0.0",
        "dependencies": {
            "good-pkg": "1.0.0"
        },
        "optionalDependencies": {
            "other-os-pkg": "1.0.0"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let normal_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"good-pkg","version":"1.0.0"}"#)]);
    let normal_integrity = compute_ssri(&normal_tarball);

    let server = TestRegistryServer::start(move |path, _base_url| {
        if path.ends_with("/good-pkg-1.0.0.tgz") {
            Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                normal_tarball.clone(),
            ))
        } else {
            None
        }
    })
    .await;

    let reg_url = server.url();

    // Create package-lock.json with an optional dependency targeting another OS
    let mut lockfile = LockfileV3::new("test-ci-project", Some("1.0.0".to_string()));
    if let Some(root_pkg) = lockfile.root_package_mut() {
        let mut deps = std::collections::BTreeMap::new();
        deps.insert("good-pkg".to_string(), "1.0.0".to_string());
        root_pkg.dependencies = Some(deps);

        let mut opt_deps = std::collections::BTreeMap::new();
        opt_deps.insert("other-os-pkg".to_string(), "1.0.0".to_string());
        root_pkg.optional_dependencies = Some(opt_deps);
    }

    lockfile.insert_package(
        "node_modules/good-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{}/good-pkg-1.0.0.tgz", reg_url)),
            integrity: Some(normal_integrity),
            ..Default::default()
        },
    );

    // Incompatible platform optional package in lockfile
    let mut skipped_child_deps = std::collections::BTreeMap::new();
    skipped_child_deps.insert("other-os-child".to_string(), "1.0.0".to_string());
    lockfile.insert_package(
        "node_modules/other-os-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("http://invalid-url-should-never-be-called.local/other.tgz".to_string()),
            integrity: Some("sha512-dummy".to_string()),
            optional: Some(true),
            os: Some(vec!["non_existent_os_xyz".to_string()]),
            cpu: Some(vec!["non_existent_cpu_xyz".to_string()]),
            dependencies: Some(skipped_child_deps),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/other-os-pkg/node_modules/other-os-child",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("http://invalid-url-should-never-be-called.local/child.tgz".to_string()),
            integrity: Some("sha512-dummy-child".to_string()),
            optional: Some(true),
            ..Default::default()
        },
    );

    lockfile
        .save_to_file(&temp_proj.path().join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(
        res.is_ok(),
        "CI install must succeed and skip incompatible optional dependency"
    );
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("good-pkg")
        .exists());
    assert!(!temp_proj
        .path()
        .join("node_modules")
        .join("other-os-pkg")
        .exists());
    assert!(!temp_proj
        .path()
        .join("node_modules")
        .join("other-os-pkg")
        .join("node_modules")
        .join("other-os-child")
        .exists());
}

#[tokio::test]
async fn test_optional_corrupted_tarball_bytes_isolation() {
    let good_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"good-pkg","version":"1.0.0"}"#)]);
    let good_integrity = compute_ssri(&good_tarball);

    // Corrupted binary payload (not valid gzip)
    let corrupt_bytes = vec![0x1F, 0x8B, 0x08, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let corrupt_integrity = compute_ssri(&corrupt_bytes);

    let good_clone = good_tarball.clone();
    let corrupt_clone = corrupt_bytes.clone();

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/good-pkg" => {
                let json = serde_json::json!({
                    "name": "good-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "good-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/good-pkg/-/good-pkg-1.0.0.tgz"),
                                "integrity": good_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            "/corrupt-tarball-pkg" => {
                let json = serde_json::json!({
                    "name": "corrupt-tarball-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "corrupt-tarball-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/corrupt-tarball-pkg/-/corrupt-tarball-pkg-1.0.0.tgz"),
                                "integrity": corrupt_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            p if p.ends_with("/good-pkg-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], good_clone.clone()))
            }
            p if p.ends_with("/corrupt-tarball-pkg-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], corrupt_clone.clone()))
            }
            _ => None,
        }
    }).await;

    let reg_url = server.url();

    // 1. When optional: extraction error is isolated, install succeeds
    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "test-opt-corrupt-tarball",
        "version": "1.0.0",
        "dependencies": {
            "good-pkg": "^1.0.0"
        },
        "optionalDependencies": {
            "corrupt-tarball-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url.clone()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res = installer.run().await;
    assert!(
        res.is_ok(),
        "Installation must succeed despite optional corrupted tarball"
    );
    assert!(temp_proj
        .path()
        .join("node_modules")
        .join("good-pkg")
        .exists());
    assert!(!temp_proj
        .path()
        .join("node_modules")
        .join("corrupt-tarball-pkg")
        .exists());

    // 2. When required: extraction error must fail install
    let temp_proj_req = tempfile::tempdir().unwrap();
    let root_req_json = serde_json::json!({
        "name": "test-req-corrupt-tarball",
        "version": "1.0.0",
        "dependencies": {
            "corrupt-tarball-pkg": "^1.0.0"
        }
    });
    std::fs::write(
        temp_proj_req.path().join("package.json"),
        root_req_json.to_string(),
    )
    .unwrap();

    let mut installer_req = Installer::new(InstallOptions {
        project_dir: temp_proj_req.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let res_req = installer_req.run().await;
    assert!(
        res_req.is_err(),
        "Required dependency corrupted tarball extraction must fail installation"
    );
}

#[tokio::test]
async fn test_ci_optional_wasm32_package_and_transitive_deps_skipped_on_win32_x64() {
    let sharp_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"sharp","version":"0.33.5"}"#)]);
    let sharp_integrity = compute_ssri(&sharp_tarball);

    let color_tarball =
        create_test_tarball(&[("package.json", br#"{"name":"color","version":"4.2.3"}"#)]);
    let color_integrity = compute_ssri(&color_tarball);

    let win64_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@img/sharp-win32-x64","version":"0.33.5"}"#,
    )]);
    let win64_integrity = compute_ssri(&win64_tarball);

    let wasm_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@img/sharp-wasm32","version":"0.33.5"}"#,
    )]);
    let wasm_integrity = compute_ssri(&wasm_tarball);

    let emnapi_tarball = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@emnapi/runtime","version":"1.2.2"}"#,
    )]);
    let emnapi_integrity = compute_ssri(&emnapi_tarball);

    let s_tar = sharp_tarball.clone();
    let c_tar = color_tarball.clone();
    let w_tar = win64_tarball.clone();
    let wasm_tar = wasm_tarball.clone();
    let em_tar = emnapi_tarball.clone();

    let server = TestRegistryServer::start(move |path, _base_url| match path {
        p if p.ends_with("/sharp-0.33.5.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            s_tar.clone(),
        )),
        p if p.ends_with("/color-4.2.3.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            c_tar.clone(),
        )),
        p if p.ends_with("/sharp-win32-x64-0.33.5.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            w_tar.clone(),
        )),
        p if p.ends_with("/sharp-wasm32-0.33.5.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            wasm_tar.clone(),
        )),
        p if p.ends_with("/emnapi-runtime-1.2.2.tgz") => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            em_tar.clone(),
        )),
        _ => None,
    })
    .await;

    let reg_url = server.url();

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "test-ci-wasm32",
        "version": "1.0.0",
        "dependencies": {
            "sharp": "0.33.5"
        }
    });
    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut lockfile = LockfileV3::new("test-ci-wasm32", Some("1.0.0".to_string()));
    if let Some(root_pkg) = lockfile.root_package_mut() {
        let mut deps = std::collections::BTreeMap::new();
        deps.insert("sharp".to_string(), "0.33.5".to_string());
        root_pkg.dependencies = Some(deps);
    }

    // sharp node_modules entry
    let mut sharp_deps = std::collections::BTreeMap::new();
    sharp_deps.insert("color".to_string(), "4.2.3".to_string());
    let mut sharp_opt_deps = std::collections::BTreeMap::new();
    sharp_opt_deps.insert("@img/sharp-wasm32".to_string(), "0.33.5".to_string());
    sharp_opt_deps.insert("@img/sharp-win32-x64".to_string(), "0.33.5".to_string());

    lockfile.insert_package(
        "node_modules/sharp",
        LockfilePackage {
            version: Some("0.33.5".to_string()),
            resolved: Some(format!("{}/sharp-0.33.5.tgz", reg_url)),
            integrity: Some(sharp_integrity),
            dependencies: Some(sharp_deps),
            optional_dependencies: Some(sharp_opt_deps),
            ..Default::default()
        },
    );

    // color entry (prod dependency of sharp)
    lockfile.insert_package(
        "node_modules/color",
        LockfilePackage {
            version: Some("4.2.3".to_string()),
            resolved: Some(format!("{}/color-4.2.3.tgz", reg_url)),
            integrity: Some(color_integrity),
            ..Default::default()
        },
    );

    // @img/sharp-win32-x64 entry (compatible optional dependency on win32 x64)
    lockfile.insert_package(
        "node_modules/@img/sharp-win32-x64",
        LockfilePackage {
            version: Some("0.33.5".to_string()),
            resolved: Some(format!("{}/sharp-win32-x64-0.33.5.tgz", reg_url)),
            integrity: Some(win64_integrity),
            os: Some(vec!["win32".to_string()]),
            cpu: Some(vec!["x64".to_string()]),
            optional: Some(true),
            ..Default::default()
        },
    );

    // @img/sharp-wasm32 entry (incompatible optional dependency with cpu: ["wasm32"])
    let mut wasm_deps = std::collections::BTreeMap::new();
    wasm_deps.insert("@emnapi/runtime".to_string(), "1.2.2".to_string());
    lockfile.insert_package(
        "node_modules/@img/sharp-wasm32",
        LockfilePackage {
            version: Some("0.33.5".to_string()),
            resolved: Some(format!("{}/sharp-wasm32-0.33.5.tgz", reg_url)),
            integrity: Some(wasm_integrity),
            cpu: Some(vec!["wasm32".to_string()]),
            optional: Some(true),
            dependencies: Some(wasm_deps),
            ..Default::default()
        },
    );

    // @emnapi/runtime entry (transitive dependency ONLY required by @img/sharp-wasm32)
    lockfile.insert_package(
        "node_modules/@emnapi/runtime",
        LockfilePackage {
            version: Some("1.2.2".to_string()),
            resolved: Some(format!("{}/emnapi-runtime-1.2.2.tgz", reg_url)),
            integrity: Some(emnapi_integrity),
            optional: Some(true),
            ..Default::default()
        },
    );

    lockfile
        .save_to_file(&temp_proj.path().join("package-lock.json"))
        .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(reg_url),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        os: Some("win32".to_string()),
        cpu: Some("x64".to_string()),
        ..Default::default()
    })
    .unwrap();

    let res = installer.run_ci().await;
    assert!(res.is_ok(), "CI run failed: {:?}", res.err());

    let nm = temp_proj.path().join("node_modules");

    // sharp and its compatible optional win32-x64 dependency AND its regular dependency 'color' MUST exist
    assert!(nm.join("sharp").exists(), "sharp should be installed");
    assert!(nm.join("color").exists(), "color should be installed");
    assert!(
        nm.join("@img").join("sharp-win32-x64").exists(),
        "@img/sharp-win32-x64 should be installed on win32 x64"
    );

    // Incompatible wasm32 package MUST NOT be installed
    assert!(
        !nm.join("@img").join("sharp-wasm32").exists(),
        "@img/sharp-wasm32 must be skipped on win32 x64"
    );

    // Transitive dependency only needed by wasm32 MUST NOT be installed
    assert!(
        !nm.join("@emnapi").join("runtime").exists(),
        "@emnapi/runtime must be skipped when parent wasm32 package is skipped"
    );

    // Verify neither wasm32 nor emnapi was ever fetched
    let requested = server.requested_paths.lock().await;
    assert!(
        !requested.iter().any(|p| p.contains("sharp-wasm32")),
        "@img/sharp-wasm32 should not be downloaded"
    );
    assert!(
        !requested.iter().any(|p| p.contains("emnapi-runtime")),
        "@emnapi/runtime should not be downloaded"
    );
}
