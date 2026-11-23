use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_cache::Cache;
use rnpm_install::{InstallOptions, Installer};

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn create_tarball(name: &str, version: &str) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        let content = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let content_bytes = content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(content_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", content_bytes)
            .unwrap();
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn compute_integrity(bytes: &[u8]) -> (String, rnpm_core::integrity::Integrity) {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    let integrity_str = format!("sha512-{}", data_encoding::BASE64.encode(&hash));
    let integrity: rnpm_core::integrity::Integrity = integrity_str.parse().unwrap();
    (integrity_str, integrity)
}

struct MockRegistryServer {
    addr: SocketAddr,
    request_count: Arc<AtomicUsize>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockRegistryServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.thread_handle.take() {
            let _ = h.join();
        }
    }
}

impl MockRegistryServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str, &[(String, String)], &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)>
            + Send
            + Sync
            + 'static,
    {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let request_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&request_count);

        let thread_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                addr_tx.send(addr).unwrap();

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept_res = listener.accept() => {
                            if let Ok((mut stream, _)) = accept_res {
                                count_clone.fetch_add(1, Ordering::SeqCst);
                                let handler_clone = Arc::clone(&handler);
                                let base_url = format!("http://{}", addr);

                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 8192];
                                    let n = stream.read(&mut buf).await.unwrap_or(0);
                                    if n > 0 {
                                        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                        let first_line = req_str.lines().next().unwrap_or("");
                                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                                        let method = parts.first().copied().unwrap_or("GET");
                                        let path = parts.get(1).copied().unwrap_or("/");

                                        let mut headers_vec = Vec::new();
                                        for line in req_str.lines().skip(1) {
                                            if line.is_empty() {
                                                break;
                                            }
                                            if let Some((k, v)) = line.split_once(':') {
                                                headers_vec.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                                            }
                                        }

                                        let (status, headers, body) = match handler_clone(method, path, &headers_vec, &base_url) {
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
                                        if !body.is_empty() {
                                            let _ = stream.write_all(&body).await;
                                        }
                                        let _ = stream.flush().await;
                                    }
                                });
                            }
                        }
                    }
                }
            });
        });

        let addr = addr_rx.recv().unwrap();

        Self {
            addr,
            request_count,
            shutdown_tx: Some(shutdown_tx),
            thread_handle: Some(thread_handle),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// 1. Test offline mode with direct tarball URLs:
/// - Uncached tarball in offline mode fails with ENOTCACHED and 0 network requests.
/// - Cached tarball in offline mode installs cleanly with 0 network requests.
#[tokio::test]
async fn test_offline_direct_url_cached_vs_uncached() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let tarball_bytes = create_tarball("direct-pkg", "1.0.0");
    let (_integrity_str, integrity) = compute_integrity(&tarball_bytes);

    let tgz_clone = tarball_bytes.clone();
    let server = MockRegistryServer::start(move |_method, path, _headers, _base| {
        if path == "/tarballs/direct-pkg-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_clone.clone()))
        } else {
            None
        }
    });

    let tarball_url = format!("{}/tarballs/direct-pkg-1.0.0.tgz", server.url());

    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"direct-pkg":"{tarball_url}"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    // Case A: Uncached tarball in offline mode -> must fail with ENOTCACHED
    let options_uncached = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir.clone()),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer_uncached = Installer::new(options_uncached).unwrap();
    let err = installer_uncached.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("ENOTCACHED") || err_str.contains("only-if-cached") || err_str.contains("offline"),
        "Uncached direct URL in offline mode must report cache miss: {err_str}"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "Offline cache miss must never touch the network"
    );

    // Case B: Pre-populate cache with tarball -> offline install must succeed!
    let cache = Cache::new(&cache_dir).unwrap();
    cache
        .put_with_integrity(&tarball_url, &tarball_bytes, Some(&integrity), None)
        .unwrap();

    let options_cached = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir.clone()),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer_cached = Installer::new(options_cached).unwrap();
    let report = installer_cached.run().await.expect("Offline install with cached tarball must succeed");
    assert!(
        project_dir.join("node_modules").join("direct-pkg").join("package.json").exists(),
        "Cached package must be extracted into node_modules"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "Offline install with cached tarball must make 0 HTTP requests"
    );
    let _ = report;
}

/// 2. Test offline mode with missing packument returns ENOTCACHED:
#[tokio::test]
async fn test_offline_missing_packument_returns_enotcached() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let server = MockRegistryServer::start(|_method, _path, _headers, _base| None);

    let pkg_json = r#"{"name":"test-app","dependencies":{"missing-dep":"^1.0.0"}}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("ENOTCACHED") || err_str.contains("offline") || err_str.contains("only-if-cached"),
        "Missing packument in offline mode must report offline/ENOTCACHED: {err_str}"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "Offline missing packument must make 0 HTTP requests"
    );
}

/// 3. Test prefer-offline uses cached packument and tarball without hitting the network:
#[tokio::test]
async fn test_prefer_offline_skips_network_when_cached() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "prefer-offline-pkg";
    let tgz_bytes = create_tarball(pkg_name, "1.0.0");
    let (integrity_str, integrity) = compute_integrity(&tgz_bytes);

    let server = MockRegistryServer::start(|_method, _path, _headers, _base| {
        panic!("prefer-offline must NOT hit the network when packument is cached");
    });
    let registry_url = server.url();
    let tarball_url = format!("{registry_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz");

    // Pre-populate packument in cache
    let cache = Cache::new(&cache_dir).unwrap();
    let packument_json = serde_json::json!({
        "name": pkg_name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg_name,
                "version": "1.0.0",
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity_str
                }
            }
        }
    });
    cache
        .put_packument_with_accept(
            &registry_url,
            pkg_name,
            Some("application/json"),
            packument_json.to_string().as_bytes(),
            None,
        )
        .unwrap();

    // Pre-populate tarball in cache
    cache
        .put_with_integrity(&tarball_url, &tgz_bytes, Some(&integrity), None)
        .unwrap();

    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"{pkg_name}":"^1.0.0"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(registry_url),
        cache_dir: Some(cache_dir),
        prefer_offline: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("prefer-offline install must succeed using cache");

    assert!(
        project_dir.join("node_modules").join(pkg_name).join("package.json").exists(),
        "Package must be installed into node_modules"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "prefer-offline with cached metadata must make 0 HTTP requests"
    );
}

/// 4. Test prefer-online revalidates stale ETag against registry:
#[tokio::test]
async fn test_prefer_online_revalidates_and_handles_304() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "prefer-online-pkg";
    let tgz_bytes = create_tarball(pkg_name, "1.0.0");
    let (integrity_str, integrity) = compute_integrity(&tgz_bytes);
    let int_str_clone = integrity_str.clone();

    let tgz_clone = tgz_bytes.clone();
    let server = MockRegistryServer::start(move |_method, path, headers, base_url| {
        if path == format!("/{pkg_name}") {
            let if_none_match = headers
                .iter()
                .find(|(k, _)| k == "if-none-match")
                .map(|(_, v)| v.as_str());

            if if_none_match == Some("\"etag-v100\"") {
                // Server responds 304 Not Modified when revalidated with matching ETag
                Some((304, vec![("ETag", "\"etag-v100\"".to_string())], Vec::new()))
            } else {
                // Unconditional response
                let json = serde_json::json!({
                    "name": pkg_name,
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": pkg_name,
                            "version": "1.0.0",
                            "dist": {
                                "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                                "integrity": int_str_clone
                            }
                        }
                    }
                });
                Some((
                    200,
                    vec![
                        ("Content-Type", "application/json".to_string()),
                        ("ETag", "\"etag-v100\"".to_string()),
                    ],
                    json.to_string().into_bytes(),
                ))
            }
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_clone.clone()))
        } else {
            None
        }
    });

    let registry_url = server.url();
    let tarball_url = format!("{registry_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz");

    // Pre-populate packument in cache with ETag
    let cache = Cache::new(&cache_dir).unwrap();
    let packument_json = serde_json::json!({
        "name": pkg_name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg_name,
                "version": "1.0.0",
                "dist": {
                    "tarball": tarball_url,
                    "integrity": integrity_str
                }
            }
        }
    });
    cache
        .put_packument_with_accept(
            &registry_url,
            pkg_name,
            Some("application/json"),
            packument_json.to_string().as_bytes(),
            Some(serde_json::json!({ "etag": "\"etag-v100\"" })),
        )
        .unwrap();

    // Pre-populate tarball in cache
    cache
        .put_with_integrity(&tarball_url, &tgz_bytes, Some(&integrity), None)
        .unwrap();

    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"{pkg_name}":"^1.0.0"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(registry_url),
        cache_dir: Some(cache_dir),
        prefer_online: true,
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("prefer-online with 304 revalidation must succeed");

    assert!(
        project_dir.join("node_modules").join(pkg_name).join("package.json").exists(),
        "Package must be installed into node_modules"
    );
    assert!(
        server.request_count.load(Ordering::SeqCst) >= 1,
        "prefer-online must revalidate with the registry"
    );
}

/// 5. Test `--before` boundary timestamps:
/// - 1.0.0 published at 2026-11-01T12:00:00.000Z
/// - 2.0.0 published at 2026-11-01T12:00:00.001Z (exact +1 millisecond)
/// - `--before 2026-11-01T12:00:00.000Z` includes 1.0.0 and filters out 2.0.0!
#[tokio::test]
async fn test_before_boundary_timestamps_exact_millisecond() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "boundary-test-pkg";
    let tgz_100 = create_tarball(pkg_name, "1.0.0");
    let (int_100, _) = compute_integrity(&tgz_100);
    let tgz_200 = create_tarball(pkg_name, "2.0.0");
    let (int_200, _) = compute_integrity(&tgz_200);

    let time_100 = "2026-11-01T12:00:00.000Z";
    let time_200 = "2026-11-01T12:00:00.001Z";

    let tgz_100_clone = tgz_100.clone();
    let tgz_200_clone = tgz_200.clone();
    let server = MockRegistryServer::start(move |_method, path, _headers, base_url| {
        if path == format!("/{pkg_name}") {
            let json = serde_json::json!({
                "name": pkg_name,
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": time_100,
                    "modified": time_200,
                    "1.0.0": time_100,
                    "2.0.0": time_200
                },
                "versions": {
                    "1.0.0": {
                        "name": pkg_name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                            "integrity": int_100
                        }
                    },
                    "2.0.0": {
                        "name": pkg_name,
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-2.0.0.tgz"),
                            "integrity": int_200
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_100_clone.clone()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-2.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_200_clone.clone()))
        } else {
            None
        }
    });

    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"{pkg_name}":"*"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let cutoff_ms = rnpm_config::date::parse_js_date(time_100).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir),
        before_cutoff: Some(cutoff_ms),
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("Install with exact millisecond boundary cutoff must succeed");

    let installed_pkg_json = project_dir.join("node_modules").join(pkg_name).join("package.json");
    let content = std::fs::read_to_string(&installed_pkg_json).unwrap();
    assert!(
        content.contains("\"version\":\"1.0.0\""),
        "Must install 1.0.0 because 2.0.0 was published 1ms after cutoff: {content}"
    );
}

/// 6. Test `--before` with epoch cutoff, future date cutoff, and missing time object:
#[tokio::test]
async fn test_before_epoch_future_and_missing_time() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "time-variations-pkg";
    let tgz_100 = create_tarball(pkg_name, "1.0.0");
    let (int_100, _) = compute_integrity(&tgz_100);
    let tgz_200 = create_tarball(pkg_name, "2.0.0");
    let (int_200, _) = compute_integrity(&tgz_200);

    let tgz_100_clone = tgz_100.clone();
    let tgz_200_clone = tgz_200.clone();

    // Serve packument without "time" object
    let server = MockRegistryServer::start(move |_method, path, _headers, base_url| {
        if path == format!("/{pkg_name}") {
            let json = serde_json::json!({
                "name": pkg_name,
                "dist-tags": { "latest": "2.0.0" },
                // NO "time" object at all!
                "versions": {
                    "1.0.0": {
                        "name": pkg_name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                            "integrity": int_100
                        }
                    },
                    "2.0.0": {
                        "name": pkg_name,
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-2.0.0.tgz"),
                            "integrity": int_200
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-2.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_200_clone.clone()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_100_clone.clone()))
        } else {
            None
        }
    });

    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"{pkg_name}":"*"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    // With cutoff set, missing "time" should be handled gracefully without error
    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir),
        before_cutoff: Some(1000000000), // Some cutoff
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("Missing time object must be handled gracefully");

    let installed_pkg_json = project_dir.join("node_modules").join(pkg_name).join("package.json");
    assert!(installed_pkg_json.exists(), "Package must be installed even when time metadata is absent");
}

/// 7. Test min-release-age-exclude with scoped wildcard `@scope/*` and exact package names:
#[tokio::test]
async fn test_min_release_age_exclude_scope_and_exact() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    // Package 1: @mycorp/exempt-tool (excluded by @mycorp/*)
    let tgz_exempt = create_tarball("@mycorp/exempt-tool", "2.0.0");
    let (int_exempt, _) = compute_integrity(&tgz_exempt);

    // Package 2: exact-exempt (excluded by exact name)
    let tgz_exact = create_tarball("exact-exempt", "2.0.0");
    let (int_exact, _) = compute_integrity(&tgz_exact);

    // Package 3: standard-dep (NOT excluded -> restricted to 1.0.0)
    let tgz_std_100 = create_tarball("standard-dep", "1.0.0");
    let (int_std_100, _) = compute_integrity(&tgz_std_100);
    let tgz_std_200 = create_tarball("standard-dep", "2.0.0");
    let (int_std_200, _) = compute_integrity(&tgz_std_200);

    let old_time = "2026-10-01T00:00:00.000Z";
    let new_time = "2026-11-23T12:00:00.000Z";

    let server = MockRegistryServer::start(move |_method, path, _headers, base_url| {
        if path == "/@mycorp%2fexempt-tool" || path == "/@mycorp/exempt-tool" {
            let json = serde_json::json!({
                "name": "@mycorp/exempt-tool",
                "dist-tags": { "latest": "2.0.0" },
                "time": { "2.0.0": new_time },
                "versions": {
                    "2.0.0": {
                        "name": "@mycorp/exempt-tool",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/@mycorp/exempt-tool/-/exempt-tool-2.0.0.tgz"),
                            "integrity": int_exempt
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }
        if path.ends_with("/exempt-tool-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_exempt.clone()));
        }

        if path == "/exact-exempt" {
            let json = serde_json::json!({
                "name": "exact-exempt",
                "dist-tags": { "latest": "2.0.0" },
                "time": { "2.0.0": new_time },
                "versions": {
                    "2.0.0": {
                        "name": "exact-exempt",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/exact-exempt/-/exact-exempt-2.0.0.tgz"),
                            "integrity": int_exact
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }
        if path.ends_with("/exact-exempt-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_exact.clone()));
        }

        if path == "/standard-dep" {
            let json = serde_json::json!({
                "name": "standard-dep",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "1.0.0": old_time,
                    "2.0.0": new_time
                },
                "versions": {
                    "1.0.0": {
                        "name": "standard-dep",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/standard-dep/-/standard-dep-1.0.0.tgz"),
                            "integrity": int_std_100
                        }
                    },
                    "2.0.0": {
                        "name": "standard-dep",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/standard-dep/-/standard-dep-2.0.0.tgz"),
                            "integrity": int_std_200
                        }
                    }
                }
            });
            return Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()));
        }
        if path.ends_with("/standard-dep-1.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_std_100.clone()));
        }
        if path.ends_with("/standard-dep-2.0.0.tgz") {
            return Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_std_200.clone()));
        }

        None
    });

    let pkg_json = r#"{
        "name": "test-app",
        "dependencies": {
            "@mycorp/exempt-tool": "*",
            "exact-exempt": "*",
            "standard-dep": "*"
        }
    }"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let cutoff_ms = rnpm_config::date::parse_js_date("2026-11-01T00:00:00.000Z").unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir),
        before_cutoff: Some(cutoff_ms),
        min_release_age_exclude: vec!["@mycorp/*".to_string(), "exact-exempt".to_string()],
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("Install with min-release-age-exclude must succeed");

    // Verify @mycorp/exempt-tool resolved to 2.0.0 (exempt)
    let exempt_json = std::fs::read_to_string(
        project_dir.join("node_modules").join("@mycorp").join("exempt-tool").join("package.json")
    ).unwrap();
    assert!(exempt_json.contains("\"version\":\"2.0.0\""));

    // Verify exact-exempt resolved to 2.0.0 (exempt)
    let exact_json = std::fs::read_to_string(
        project_dir.join("node_modules").join("exact-exempt").join("package.json")
    ).unwrap();
    assert!(exact_json.contains("\"version\":\"2.0.0\""));

    // Verify standard-dep resolved to 1.0.0 (not exempt, filtered by cutoff)
    let std_json = std::fs::read_to_string(
        project_dir.join("node_modules").join("standard-dep").join("package.json")
    ).unwrap();
    assert!(std_json.contains("\"version\":\"1.0.0\""));
}

/// 8. Test dist-tags ('latest' / 'beta') dynamically filtered by --before cutoff date:
#[tokio::test]
async fn test_dist_tags_filtered_by_before_date() {
    let _guard = TEST_MUTEX.lock().await;
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let pkg_name = "dist-tag-filtered-pkg";
    let tgz_100 = create_tarball(pkg_name, "1.0.0");
    let (int_100, _) = compute_integrity(&tgz_100);
    let tgz_200 = create_tarball(pkg_name, "2.0.0");
    let (int_200, _) = compute_integrity(&tgz_200);

    let time_100 = "2025-01-01T00:00:00.000Z";
    let time_200 = "2026-11-20T00:00:00.000Z";

    let tgz_100_clone = tgz_100.clone();
    let tgz_200_clone = tgz_200.clone();
    let server = MockRegistryServer::start(move |_method, path, _headers, base_url| {
        if path == format!("/{pkg_name}") {
            let json = serde_json::json!({
                "name": pkg_name,
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "1.0.0": time_100,
                    "2.0.0": time_200
                },
                "versions": {
                    "1.0.0": {
                        "name": pkg_name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-1.0.0.tgz"),
                            "integrity": int_100
                        }
                    },
                    "2.0.0": {
                        "name": pkg_name,
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/{pkg_name}/-/{pkg_name}-2.0.0.tgz"),
                            "integrity": int_200
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], json.to_string().into_bytes()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-1.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_100_clone.clone()))
        } else if path == format!("/{pkg_name}/-/{pkg_name}-2.0.0.tgz") {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], tgz_200_clone.clone()))
        } else {
            None
        }
    });

    // Request dependency as "latest"
    let pkg_json = format!(
        r#"{{"name":"test-app","dependencies":{{"{pkg_name}":"latest"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let cutoff_ms = rnpm_config::date::parse_js_date("2025-06-01T00:00:00.000Z").unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(server.url()),
        cache_dir: Some(cache_dir),
        before_cutoff: Some(cutoff_ms),
        ignore_scripts: true,
        ..Default::default()
    };
    let mut installer = Installer::new(options).unwrap();
    installer.run().await.expect("Install filtering dist-tags by date must succeed");

    let installed_json = std::fs::read_to_string(
        project_dir.join("node_modules").join(pkg_name).join("package.json")
    ).unwrap();
    assert!(
        installed_json.contains("\"version\":\"1.0.0\""),
        "'latest' dist-tag pointing to 2.0.0 must be rewritten to 1.0.0 because of --before: {installed_json}"
    );
}
