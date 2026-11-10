use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_cache::index::IndexEntry;
use rnpm_cache::Cache;
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

/// Regression test: A cached packument older than 300s whose registry copy has
/// a newer matching version must revalidate against the registry and resolve to
/// the newer version rather than trusting stale cached metadata forever.
#[tokio::test]
async fn test_stale_cached_packument_resolves_to_newer_version_from_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let project_dir = tmp.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "test-reval-pkg";

    // Build tarball for 1.0.1
    let tgz_101 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"test-reval-pkg","version":"1.0.1"}"#,
    )]);
    let integrity_101 = compute_ssri(&tgz_101);

    // Build tarball for 1.0.0
    let tgz_100 = create_test_tarball(&[(
        "package.json",
        br#"{"name":"test-reval-pkg","version":"1.0.0"}"#,
    )]);
    let integrity_100 = compute_ssri(&tgz_100);

    let tgz_101_clone = tgz_101.clone();
    let tgz_100_clone = tgz_100.clone();
    let int_101_clone = integrity_101.clone();
    let int_100_clone = integrity_100.clone();

    // Start mock registry that serves the FRESH packument with 1.0.0 and 1.0.1
    let server = TestMockRegistry::start(move |path, base_url| {
        if path == format!("/{}", pkg_name) {
            let json = serde_json::json!({
                "name": pkg_name,
                "dist-tags": { "latest": "1.0.1" },
                "versions": {
                    "1.0.0": {
                        "name": pkg_name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                            "integrity": int_100_clone
                        }
                    },
                    "1.0.1": {
                        "name": pkg_name,
                        "version": "1.0.1",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.1.tgz"),
                            "integrity": int_101_clone
                        }
                    }
                }
            });
            let body = json.to_string().into_bytes();
            Some((
                200,
                vec![
                    ("Content-Type", "application/json".to_string()),
                    ("ETag", "\"etag-v101\"".to_string()),
                ],
                body,
            ))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.1.tgz") {
            Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                tgz_101_clone.clone(),
            ))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.0.tgz") {
            Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                tgz_100_clone.clone(),
            ))
        } else {
            None
        }
    })
    .await;

    let registry_url = server.url();

    // 1. Pre-seed the cache with an OLD packument that ONLY contains version 1.0.0
    let cache = Cache::new(&cache_dir).unwrap();
    let stale_json = serde_json::json!({
        "name": pkg_name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg_name,
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{registry_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                    "integrity": integrity_100
                }
            }
        }
    });
    let stale_bytes = stale_json.to_string().into_bytes();

    let entry = cache
        .put_packument_with_accept(
            &registry_url,
            pkg_name,
            Some("application/vnd.npm.install-v1+json"),
            &stale_bytes,
            Some(serde_json::json!({ "etag": "\"etag-v100\"" })),
        )
        .unwrap();

    // Manually rewrite the index entry file so its `time` is 500 seconds ago (stale > 300s TTL)
    let index_path = IndexEntry::path_for_key(&cache_dir, &entry.key);
    assert!(index_path.exists());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let stale_time_ms = now_ms.saturating_sub(500_000); // 500s ago

    let stale_index_entry = IndexEntry {
        key: entry.key.clone(),
        integrity: entry.integrity.clone(),
        sha512_hex: entry.sha512_hex.clone(),
        size: entry.size,
        time: stale_time_ms,
        metadata: Some(serde_json::json!({ "etag": "\"etag-v100\"" })),
    };
    let index_content = format!(
        "\t{}\n",
        serde_json::to_string(&stale_index_entry).unwrap()
    );
    std::fs::write(&index_path, index_content).unwrap();

    // 2. Setup project manifest with ^1.0.0 dependency and no lockfile
    let manifest_json = serde_json::json!({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            pkg_name: "^1.0.0"
        }
    });
    std::fs::write(
        project_dir.join("package.json"),
        manifest_json.to_string(),
    )
    .unwrap();

    // 3. Configure Installer pointing to mock registry and custom cache
    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(registry_url.clone()),
        cache_dir: Some(cache_dir.clone()),
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.install().await.expect("Installation must succeed");

    // 4. Verify that 1.0.1 was resolved and installed, NOT stale 1.0.0
    let installed_pkg_json = project_dir
        .join("node_modules")
        .join(pkg_name)
        .join("package.json");
    assert!(
        installed_pkg_json.exists(),
        "Installed package.json must exist in node_modules"
    );
    let installed_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&installed_pkg_json).unwrap()).unwrap();
    assert_eq!(
        installed_json.get("version").and_then(|v| v.as_str()),
        Some("1.0.1"),
        "Package must resolve to new version 1.0.1 from registry, not stale 1.0.0 from cache"
    );

    // Also check lockfile v3
    let lockfile_path = project_dir.join("package-lock.json");
    assert!(lockfile_path.exists());
    let lockfile: rnpm_lockfile::LockfileV3 =
        rnpm_lockfile::LockfileV3::load_from_file(&lockfile_path).unwrap();
    let pkg_key = format!("node_modules/{pkg_name}");
    let locked_pkg = lockfile
        .packages
        .get(&pkg_key)
        .expect("Lockfile must contain package");
    assert_eq!(
        locked_pkg.version.as_deref(),
        Some("1.0.1"),
        "Lockfile must record version 1.0.1"
    );

    assert!(
        summary.timing.is_some(),
        "Summary must contain timing metrics"
    );
    let timing = summary.timing.unwrap();
    assert!(
        timing.http_requests >= 1,
        "At least one HTTP request must have been issued for revalidation"
    );
}
