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

struct TestMockRegistry {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestMockRegistry {
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
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 8192];
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
                                        304 => "Not Modified",
                                        404 => "Not Found",
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

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Integration test verifying `min-release-age` and `min-release-age-exclude`:
/// - Non-excluded packages skip versions newer than the cutoff (falling back to an older version).
/// - Packages matching `min-release-age-exclude` (glob `@scope/*` or exact name) are exempt
///   and resolve to their newest version.
/// - Exemption applies to both `min-release-age` and `--before` filters.
#[tokio::test]
async fn test_min_release_age_and_exclude_resolution() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let project_dir = tmp.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    // Package 1: pkg-normal (unscoped, not excluded)
    // 1.0.0 is old (published 2026-11-01), 2.0.0 is new (published today 2026-11-22)
    let tgz_normal_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-normal","version":"1.0.0"}"#,
    )]);
    let int_normal_100 = compute_ssri(&tgz_normal_100);

    let tgz_normal_200 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-normal","version":"2.0.0"}"#,
    )]);
    let int_normal_200 = compute_ssri(&tgz_normal_200);

    // Package 2: @myorg/pkg-excluded (scoped, excluded by @myorg/*)
    let tgz_excluded_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@myorg/pkg-excluded","version":"1.0.0"}"#,
    )]);
    let int_excluded_100 = compute_ssri(&tgz_excluded_100);

    let tgz_excluded_200 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@myorg/pkg-excluded","version":"2.0.0"}"#,
    )]);
    let int_excluded_200 = compute_ssri(&tgz_excluded_200);

    // Package 3: pkg-exact-excluded (unscoped, excluded by exact name)
    let tgz_exact_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-exact-excluded","version":"1.0.0"}"#,
    )]);
    let int_exact_100 = compute_ssri(&tgz_exact_100);

    let tgz_exact_200 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-exact-excluded","version":"2.0.0"}"#,
    )]);
    let int_exact_200 = compute_ssri(&tgz_exact_200);

    // Now timestamp for test: today's date in RFC3339
    let old_publish_time = "2026-11-01T00:00:00.000Z";
    let new_publish_time = "2026-11-22T12:00:00.000Z";

    let server = TestMockRegistry::start(move |path, base_url| {
        // Tarball routes
        if path.ends_with("/pkg-normal-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_normal_100.clone()));
        }
        if path.ends_with("/pkg-normal-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_normal_200.clone()));
        }
        if path.ends_with("/pkg-excluded-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_excluded_100.clone()));
        }
        if path.ends_with("/pkg-excluded-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_excluded_200.clone()));
        }
        if path.ends_with("/pkg-exact-excluded-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_exact_100.clone()));
        }
        if path.ends_with("/pkg-exact-excluded-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_exact_200.clone()));
        }

        // Packument: pkg-normal
        if path == "/pkg-normal" {
            let json = serde_json::json!({
                "name": "pkg-normal",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": old_publish_time,
                    "modified": new_publish_time,
                    "1.0.0": old_publish_time,
                    "2.0.0": new_publish_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-normal",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-normal/-/pkg-normal-1.0.0.tgz"),
                            "integrity": int_normal_100
                        }
                    },
                    "2.0.0": {
                        "name": "pkg-normal",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-normal/-/pkg-normal-2.0.0.tgz"),
                            "integrity": int_normal_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }

        // Packument: @myorg/pkg-excluded
        if path == "/@myorg%2fpkg-excluded" || path == "/@myorg/pkg-excluded" {
            let json = serde_json::json!({
                "name": "@myorg/pkg-excluded",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": old_publish_time,
                    "modified": new_publish_time,
                    "1.0.0": old_publish_time,
                    "2.0.0": new_publish_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "@myorg/pkg-excluded",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/@myorg/pkg-excluded/-/pkg-excluded-1.0.0.tgz"),
                            "integrity": int_excluded_100
                        }
                    },
                    "2.0.0": {
                        "name": "@myorg/pkg-excluded",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/@myorg/pkg-excluded/-/pkg-excluded-2.0.0.tgz"),
                            "integrity": int_excluded_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }

        // Packument: pkg-exact-excluded
        if path == "/pkg-exact-excluded" {
            let json = serde_json::json!({
                "name": "pkg-exact-excluded",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": old_publish_time,
                    "modified": new_publish_time,
                    "1.0.0": old_publish_time,
                    "2.0.0": new_publish_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-exact-excluded",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-exact-excluded/-/pkg-exact-excluded-1.0.0.tgz"),
                            "integrity": int_exact_100
                        }
                    },
                    "2.0.0": {
                        "name": "pkg-exact-excluded",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-exact-excluded/-/pkg-exact-excluded-2.0.0.tgz"),
                            "integrity": int_exact_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }

        None
    }).await;

    let registry_url = server.url();

    // Write .npmrc with min-release-age = 7 days and min-release-age-exclude
    let npmrc_content = format!(
        "registry={registry_url}/\nmin-release-age=7\nmin-release-age-exclude[]=@myorg/*\nmin-release-age-exclude[]=pkg-exact-excluded\n"
    );
    std::fs::write(project_dir.join(".npmrc"), npmrc_content).unwrap();

    let manifest_json = serde_json::json!({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "pkg-normal": ">=1.0.0",
            "@myorg/pkg-excluded": ">=1.0.0",
            "pkg-exact-excluded": ">=1.0.0"
        }
    });
    std::fs::write(project_dir.join("package.json"), manifest_json.to_string()).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("{registry_url}/")),
        cache_dir: Some(cache_dir.clone()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    installer
        .install()
        .await
        .expect("Installation must succeed");

    // Verify pkg-normal resolved to 1.0.0 because 2.0.0 was published < 7 days ago
    let normal_pkg_json = project_dir
        .join("node_modules")
        .join("pkg-normal")
        .join("package.json");
    assert!(normal_pkg_json.exists(), "pkg-normal must be installed");
    let normal_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&normal_pkg_json).unwrap()).unwrap();
    assert_eq!(
        normal_json.get("version").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "pkg-normal must resolve to 1.0.0 (skipping 2.0.0 due to min-release-age=7)"
    );

    // Verify @myorg/pkg-excluded resolved to 2.0.0 (exempted via glob @myorg/*)
    let excluded_pkg_json = project_dir
        .join("node_modules")
        .join("@myorg")
        .join("pkg-excluded")
        .join("package.json");
    assert!(excluded_pkg_json.exists(), "@myorg/pkg-excluded must be installed");
    let excluded_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&excluded_pkg_json).unwrap()).unwrap();
    assert_eq!(
        excluded_json.get("version").and_then(|v| v.as_str()),
        Some("2.0.0"),
        "@myorg/pkg-excluded must resolve to newest 2.0.0 (exempt from min-release-age)"
    );

    // Verify pkg-exact-excluded resolved to 2.0.0 (exempted via exact name)
    let exact_pkg_json = project_dir
        .join("node_modules")
        .join("pkg-exact-excluded")
        .join("package.json");
    assert!(exact_pkg_json.exists(), "pkg-exact-excluded must be installed");
    let exact_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&exact_pkg_json).unwrap()).unwrap();
    assert_eq!(
        exact_json.get("version").and_then(|v| v.as_str()),
        Some("2.0.0"),
        "pkg-exact-excluded must resolve to newest 2.0.0 (exempt from min-release-age)"
    );
}

/// Integration test verifying `--before` parity with `min-release-age-exclude`:
/// A package exempted by `min-release-age-exclude` is also exempt from the `before` filter.
#[tokio::test]
async fn test_before_filter_with_min_release_age_exclude_parity() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let project_dir = tmp.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let tgz_normal_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-normal","version":"1.0.0"}"#,
    )]);
    let int_normal_100 = compute_ssri(&tgz_normal_100);

    let tgz_normal_200 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"pkg-normal","version":"2.0.0"}"#,
    )]);
    let int_normal_200 = compute_ssri(&tgz_normal_200);

    let tgz_excluded_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@myorg/pkg-excluded","version":"1.0.0"}"#,
    )]);
    let int_excluded_100 = compute_ssri(&tgz_excluded_100);

    let tgz_excluded_200 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"@myorg/pkg-excluded","version":"2.0.0"}"#,
    )]);
    let int_excluded_200 = compute_ssri(&tgz_excluded_200);

    let old_publish_time = "2026-11-01T00:00:00.000Z";
    let new_publish_time = "2026-11-22T12:00:00.000Z";

    let server = TestMockRegistry::start(move |path, base_url| {
        if path.ends_with("/pkg-normal-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_normal_100.clone()));
        }
        if path.ends_with("/pkg-normal-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_normal_200.clone()));
        }
        if path.ends_with("/pkg-excluded-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_excluded_100.clone()));
        }
        if path.ends_with("/pkg-excluded-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_excluded_200.clone()));
        }

        if path == "/pkg-normal" {
            let json = serde_json::json!({
                "name": "pkg-normal",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": old_publish_time,
                    "modified": new_publish_time,
                    "1.0.0": old_publish_time,
                    "2.0.0": new_publish_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-normal",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-normal/-/pkg-normal-1.0.0.tgz"),
                            "integrity": int_normal_100
                        }
                    },
                    "2.0.0": {
                        "name": "pkg-normal",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/pkg-normal/-/pkg-normal-2.0.0.tgz"),
                            "integrity": int_normal_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }

        if path == "/@myorg%2fpkg-excluded" || path == "/@myorg/pkg-excluded" {
            let json = serde_json::json!({
                "name": "@myorg/pkg-excluded",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": old_publish_time,
                    "modified": new_publish_time,
                    "1.0.0": old_publish_time,
                    "2.0.0": new_publish_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "@myorg/pkg-excluded",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/@myorg/pkg-excluded/-/pkg-excluded-1.0.0.tgz"),
                            "integrity": int_excluded_100
                        }
                    },
                    "2.0.0": {
                        "name": "@myorg/pkg-excluded",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/@myorg/pkg-excluded/-/pkg-excluded-2.0.0.tgz"),
                            "integrity": int_excluded_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }

        None
    }).await;

    let registry_url = server.url();

    // Set --before cutoff to 2026-11-10 (between 1.0.0 and 2.0.0)
    let npmrc_content = format!(
        "registry={registry_url}/\nbefore=2026-11-10T00:00:00.000Z\nmin-release-age-exclude[]=@myorg/*\n"
    );
    std::fs::write(project_dir.join(".npmrc"), npmrc_content).unwrap();

    let manifest_json = serde_json::json!({
        "name": "test-before-project",
        "version": "1.0.0",
        "dependencies": {
            "pkg-normal": ">=1.0.0",
            "@myorg/pkg-excluded": ">=1.0.0"
        }
    });
    std::fs::write(project_dir.join("package.json"), manifest_json.to_string()).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("{registry_url}/")),
        cache_dir: Some(cache_dir.clone()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    installer
        .install()
        .await
        .expect("Installation must succeed");

    // pkg-normal should be restricted by --before to 1.0.0
    let normal_pkg_json = project_dir
        .join("node_modules")
        .join("pkg-normal")
        .join("package.json");
    let normal_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&normal_pkg_json).unwrap()).unwrap();
    assert_eq!(
        normal_json.get("version").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "pkg-normal must resolve to 1.0.0 under --before filter"
    );

    // @myorg/pkg-excluded should bypass --before and resolve to 2.0.0
    let excluded_pkg_json = project_dir
        .join("node_modules")
        .join("@myorg")
        .join("pkg-excluded")
        .join("package.json");
    let excluded_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&excluded_pkg_json).unwrap()).unwrap();
    assert_eq!(
        excluded_json.get("version").and_then(|v| v.as_str()),
        Some("2.0.0"),
        "@myorg/pkg-excluded must resolve to 2.0.0 (exempt from --before via min-release-age-exclude)"
    );
}
