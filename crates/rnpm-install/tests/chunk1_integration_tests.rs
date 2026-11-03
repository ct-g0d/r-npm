use std::net::SocketAddr;
use std::sync::Arc;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::LockfileV3;

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
        F: Fn(&str, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)> + Send + Sync + 'static,
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
async fn test_nested_conflict_diamond_reification_and_lockfile() {
    // dep-a (1.0.0) -> shared@^1.0.0
    let dep_a_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"dep-a","version":"1.0.0","dependencies":{"shared-lib":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'dep-a';"),
    ]);
    let dep_a_integrity = compute_ssri(&dep_a_tarball);

    // dep-b (1.0.0) -> shared@^2.0.0
    let dep_b_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"dep-b","version":"1.0.0","dependencies":{"shared-lib":"^2.0.0"}}"#),
        ("index.js", b"module.exports = 'dep-b';"),
    ]);
    let dep_b_integrity = compute_ssri(&dep_b_tarball);

    // shared-lib 1.0.0
    let shared_1_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"shared-lib","version":"1.0.0"}"#),
        ("index.js", b"module.exports = 'shared-1';"),
    ]);
    let shared_1_integrity = compute_ssri(&shared_1_tarball);

    // shared-lib 2.0.0
    let shared_2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"shared-lib","version":"2.0.0"}"#),
        ("index.js", b"module.exports = 'shared-2';"),
    ]);
    let shared_2_integrity = compute_ssri(&shared_2_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/dep-a" => {
                let json = serde_json::json!({
                    "name": "dep-a",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "dep-a",
                            "version": "1.0.0",
                            "dependencies": { "shared-lib": "^1.0.0" },
                            "dist": {
                                "tarball": format!("{base_url}/dep-a/-/dep-a-1.0.0.tgz"),
                                "integrity": dep_a_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            "/dep-b" => {
                let json = serde_json::json!({
                    "name": "dep-b",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "dep-b",
                            "version": "1.0.0",
                            "dependencies": { "shared-lib": "^2.0.0" },
                            "dist": {
                                "tarball": format!("{base_url}/dep-b/-/dep-b-1.0.0.tgz"),
                                "integrity": dep_b_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            "/shared-lib" => {
                let json = serde_json::json!({
                    "name": "shared-lib",
                    "dist-tags": { "latest": "2.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "shared-lib",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/shared-lib/-/shared-lib-1.0.0.tgz"),
                                "integrity": shared_1_integrity
                            }
                        },
                        "2.0.0": {
                            "name": "shared-lib",
                            "version": "2.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/shared-lib/-/shared-lib-2.0.0.tgz"),
                                "integrity": shared_2_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            p if p.ends_with("/dep-a-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], dep_a_tarball.clone()))
            }
            p if p.ends_with("/dep-b-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], dep_b_tarball.clone()))
            }
            p if p.ends_with("/shared-lib-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], shared_1_tarball.clone()))
            }
            p if p.ends_with("/shared-lib-2.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], shared_2_tarball.clone()))
            }
            _ => None,
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "diamond-conflict-test",
        "version": "1.0.0",
        "dependencies": {
            "dep-a": "^1.0.0",
            "dep-b": "^1.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    ).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 4);

    let node_modules = temp_proj.path().join("node_modules");
    assert!(node_modules.join("dep-a").exists());
    assert!(node_modules.join("dep-b").exists());

    // Both versions of shared-lib must be reified: one hoisted at root, one nested in conflict
    let root_shared = node_modules.join("shared-lib");
    assert!(root_shared.exists());

    let nested_shared_in_b = node_modules.join("dep-b").join("node_modules").join("shared-lib");
    let nested_shared_in_a = node_modules.join("dep-a").join("node_modules").join("shared-lib");
    assert!(nested_shared_in_b.exists() || nested_shared_in_a.exists(), "One conflicting shared-lib must be nested");

    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    assert!(lockfile.packages.contains_key("node_modules/dep-a"));
    assert!(lockfile.packages.contains_key("node_modules/dep-b"));
    assert!(lockfile.packages.contains_key("node_modules/shared-lib"));
    assert!(
        lockfile.packages.contains_key("node_modules/dep-b/node_modules/shared-lib")
            || lockfile.packages.contains_key("node_modules/dep-a/node_modules/shared-lib")
    );
}

#[tokio::test]
async fn test_npm_alias_installation_and_lockfile() {
    let real_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"actual-lib","version":"1.0.0"}"#),
        ("index.js", b"module.exports = 'actual-lib';"),
    ]);
    let real_integrity = compute_ssri(&real_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/actual-lib" => {
                let json = serde_json::json!({
                    "name": "actual-lib",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "actual-lib",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/actual-lib/-/actual-lib-1.0.0.tgz"),
                                "integrity": real_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            p if p.ends_with("/actual-lib-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], real_tarball.clone()))
            }
            _ => None,
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "alias-test",
        "version": "1.0.0",
        "dependencies": {
            "my-custom-alias": "npm:actual-lib@^1.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    ).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // Directory node_modules/my-custom-alias must exist
    let alias_dir = temp_proj.path().join("node_modules").join("my-custom-alias");
    assert!(alias_dir.exists());
    assert!(alias_dir.join("index.js").exists());

    // Lockfile v3 must record node_modules/my-custom-alias with name: "actual-lib"
    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    let entry = lockfile.packages.get("node_modules/my-custom-alias").expect("Lockfile entry for alias");
    assert_eq!(entry.name.as_deref(), Some("actual-lib"));
    assert_eq!(entry.version.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn test_root_overrides_applied_and_copied_to_lockfile() {
    let pkg_100_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"dep-pkg","version":"1.0.0"}"#),
        ("index.js", b"module.exports = '1.0.0';"),
    ]);
    let pkg_100_integrity = compute_ssri(&pkg_100_tarball);

    let pkg_200_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"dep-pkg","version":"2.0.0"}"#),
        ("index.js", b"module.exports = '2.0.0';"),
    ]);
    let pkg_200_integrity = compute_ssri(&pkg_200_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/dep-pkg" => {
                let json = serde_json::json!({
                    "name": "dep-pkg",
                    "dist-tags": { "latest": "2.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "dep-pkg",
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/dep-pkg/-/dep-pkg-1.0.0.tgz"),
                                "integrity": pkg_100_integrity
                            }
                        },
                        "2.0.0": {
                            "name": "dep-pkg",
                            "version": "2.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/dep-pkg/-/dep-pkg-2.0.0.tgz"),
                                "integrity": pkg_200_integrity
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            p if p.ends_with("/dep-pkg-1.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg_100_tarball.clone()))
            }
            p if p.ends_with("/dep-pkg-2.0.0.tgz") => {
                Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg_200_tarball.clone()))
            }
            _ => None,
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "overrides-test",
        "version": "1.0.0",
        "dependencies": {
            "dep-pkg": "^1.0.0"
        },
        "overrides": {
            "dep-pkg": "2.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    ).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // Verify that version 2.0.0 was installed because of override
    let pkg_json = std::fs::read_to_string(
        temp_proj.path().join("node_modules").join("dep-pkg").join("package.json")
    ).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&pkg_json).unwrap();
    assert_eq!(parsed["version"], "2.0.0");

    // Verify that overrides field is copied into root lockfile descriptor
    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    let root_pkg = lockfile.packages.get("").expect("Root package entry");
    let overrides_extra = root_pkg.extra.get("overrides").expect("Overrides in root lockfile descriptor");
    assert_eq!(overrides_extra["dep-pkg"], "2.0.0");
}

#[tokio::test]
async fn test_required_platform_incompatibility_fails_ebadplatform() {
    let server = TestRegistryServer::start(move |path, _| {
        match path {
            "/incompatible-pkg" => {
                let json = serde_json::json!({
                    "name": "incompatible-pkg",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": "incompatible-pkg",
                            "version": "1.0.0",
                            "os": ["nonexistent_os_matrix_999"],
                            "dist": {
                                "tarball": "http://example.com/incompatible-pkg.tgz",
                                "integrity": "sha512-test"
                            }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
            }
            _ => None,
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "platform-fail-test",
        "version": "1.0.0",
        "dependencies": {
            "incompatible-pkg": "^1.0.0"
        }
    });

    std::fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    ).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    }).unwrap();

    let res = installer.run().await;
    assert!(res.is_err(), "Required platform incompatibility must fail");
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("EBADPLATFORM"),
        "Error must contain EBADPLATFORM, got: {err_str}"
    );
}

#[tokio::test]
async fn test_workspace_cyclic_dev_dependencies_install_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Root package.json
    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "cyclic-dev-root",
            "workspaces": ["packages/*"]
        }"#,
    ).unwrap();

    let packages_dir = root.join("packages");
    let pkg_a_dir = packages_dir.join("pkg-a");
    let pkg_b_dir = packages_dir.join("pkg-b");
    std::fs::create_dir_all(&pkg_a_dir).unwrap();
    std::fs::create_dir_all(&pkg_b_dir).unwrap();

    // pkg-a devDepends on pkg-b
    std::fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
            "name": "pkg-a",
            "version": "1.0.0",
            "devDependencies": {
                "pkg-b": "workspace:*"
            }
        }"#,
    ).unwrap();

    // pkg-b devDepends on pkg-a (cycle in devDependencies only)
    std::fs::write(
        pkg_b_dir.join("package.json"),
        r#"{
            "name": "pkg-b",
            "version": "1.0.0",
            "devDependencies": {
                "pkg-a": "workspace:*"
            }
        }"#,
    ).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.expect("Cyclic workspace devDependencies must install successfully");
    assert_eq!(summary.packages_installed, 2);

    assert!(root.join("node_modules").join("pkg-a").exists());
    assert!(root.join("node_modules").join("pkg-b").exists());
}

#[tokio::test]
async fn test_workspace_cyclic_production_dependencies_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "cyclic-prod-root",
            "workspaces": ["packages/*"]
        }"#,
    ).unwrap();

    let packages_dir = root.join("packages");
    let pkg_a_dir = packages_dir.join("pkg-a");
    let pkg_b_dir = packages_dir.join("pkg-b");
    std::fs::create_dir_all(&pkg_a_dir).unwrap();
    std::fs::create_dir_all(&pkg_b_dir).unwrap();

    // pkg-a production depends on pkg-b
    std::fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
            "name": "pkg-a",
            "version": "1.0.0",
            "dependencies": {
                "pkg-b": "workspace:*"
            }
        }"#,
    ).unwrap();

    // pkg-b production depends on pkg-a (cycle in production dependencies)
    std::fs::write(
        pkg_b_dir.join("package.json"),
        r#"{
            "name": "pkg-b",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "workspace:*"
            }
        }"#,
    ).unwrap();

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let res = installer.run().await;
    assert!(res.is_err(), "Cyclic production dependencies must fail");
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("Circular workspace dependency detected"),
        "Error must mention circular workspace dependency, got: {err_str}"
    );
}
