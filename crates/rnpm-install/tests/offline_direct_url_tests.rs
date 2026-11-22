use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_install::{InstallOptions, Installer};

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

struct MockHttpServer {
    addr: SocketAddr,
    request_count: Arc<AtomicUsize>,
    tarball_request_count: Arc<AtomicUsize>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockHttpServer {
    async fn start(tarball_path: String, tarball_bytes: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&request_count);
        let tarball_request_count = Arc::new(AtomicUsize::new(0));
        let tarball_count_clone = Arc::clone(&tarball_request_count);
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            count_clone.fetch_add(1, Ordering::SeqCst);
                            let t_path = tarball_path.clone();
                            let t_bytes = tarball_bytes.clone();
                            let t_count_clone = Arc::clone(&tarball_count_clone);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]);
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                                    if path == t_path {
                                        t_count_clone.fetch_add(1, Ordering::SeqCst);
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                            t_bytes.len()
                                        );
                                        let _ = stream.write_all(response.as_bytes()).await;
                                        let _ = stream.write_all(&t_bytes).await;
                                    } else {
                                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        let _ = stream.write_all(response.as_bytes()).await;
                                    }
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
            request_count,
            tarball_request_count,
            _shutdown: tx,
        }
    }
}

#[tokio::test]
async fn test_offline_direct_url_manifest_cache_miss_enotcached() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let tarball_bytes = create_tarball("direct-tarball-pkg", "1.0.0");
    let server = MockHttpServer::start("/tarballs/direct-tarball-pkg-1.0.0.tgz".to_string(), tarball_bytes).await;
    let tarball_url = format!("http://{}/tarballs/direct-tarball-pkg-1.0.0.tgz", server.addr);

    let pkg_json = format!(
        r#"{{"name": "test-app", "dependencies": {{"direct-tarball-pkg": "{tarball_url}"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("http://{}/", server.addr)),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();

    assert!(
        err_str.contains("ENOTCACHED"),
        "Error should contain ENOTCACHED code: {err_str}"
    );
    assert!(
        err_str.contains("cache mode is 'only-if-cached' but no cached response is available"),
        "Error should explain only-if-cached miss: {err_str}"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "--offline cache miss must make zero HTTP requests"
    );
}

#[tokio::test]
async fn test_offline_direct_url_manifest_cache_hit_success() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let tarball_bytes = create_tarball("direct-tarball-pkg", "1.0.0");
    let (_integrity_str, integrity) = compute_integrity(&tarball_bytes);
    let server = MockHttpServer::start("/tarballs/direct-tarball-pkg-1.0.0.tgz".to_string(), tarball_bytes.clone()).await;
    let tarball_url = format!("http://{}/tarballs/direct-tarball-pkg-1.0.0.tgz", server.addr);

    // Pre-populate tarball into cache
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    cache
        .put_with_integrity(&tarball_url, &tarball_bytes, Some(&integrity), None)
        .unwrap();

    let pkg_json = format!(
        r#"{{"name": "test-app", "dependencies": {{"direct-tarball-pkg": "{tarball_url}"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("http://{}/", server.addr)),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();

    assert_eq!(summary.packages_installed, 1);
    assert_eq!(summary.cache_hits, 1);
    assert!(
        project_dir
            .join("node_modules")
            .join("direct-tarball-pkg")
            .join("package.json")
            .exists(),
        "Package must be installed into node_modules"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "--offline cache hit must make zero HTTP requests"
    );
}

#[tokio::test]
async fn test_offline_direct_url_cli_arg_cache_miss_enotcached() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let tarball_bytes = create_tarball("direct-tarball-pkg", "1.0.0");
    let server = MockHttpServer::start("/tarballs/direct-tarball-pkg-1.0.0.tgz".to_string(), tarball_bytes).await;
    let tarball_url = format!("http://{}/tarballs/direct-tarball-pkg-1.0.0.tgz", server.addr);

    let pkg_json = r#"{"name": "test-app"}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("http://{}/", server.addr)),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        packages: vec![tarball_url.clone()],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();

    assert!(
        err_str.contains("ENOTCACHED"),
        "Error should contain ENOTCACHED code: {err_str}"
    );
    assert!(
        err_str.contains("cache mode is 'only-if-cached' but no cached response is available"),
        "Error should explain only-if-cached miss: {err_str}"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "--offline CLI arg cache miss must make zero HTTP requests"
    );
}

#[tokio::test]
async fn test_offline_direct_url_cli_arg_cache_hit_success() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let tarball_bytes = create_tarball("direct-tarball-pkg", "1.0.0");
    let (_integrity_str, integrity) = compute_integrity(&tarball_bytes);
    let server = MockHttpServer::start("/tarballs/direct-tarball-pkg-1.0.0.tgz".to_string(), tarball_bytes.clone()).await;
    let tarball_url = format!("http://{}/tarballs/direct-tarball-pkg-1.0.0.tgz", server.addr);

    // Pre-populate tarball into cache
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    cache
        .put_with_integrity(&tarball_url, &tarball_bytes, Some(&integrity), None)
        .unwrap();

    let pkg_json = r#"{"name": "test-app"}"#;
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("http://{}/", server.addr)),
        cache_dir: Some(cache_dir),
        offline: true,
        ignore_scripts: true,
        packages: vec![tarball_url.clone()],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();

    assert_eq!(summary.packages_installed, 1);
    assert!(
        project_dir
            .join("node_modules")
            .join("direct-tarball-pkg")
            .join("package.json")
            .exists(),
        "Package must be installed into node_modules"
    );
    assert_eq!(
        server.request_count.load(Ordering::SeqCst),
        0,
        "--offline CLI arg cache hit must make zero HTTP requests"
    );
}

#[tokio::test]
async fn test_prefer_online_direct_url_fetches_from_server_even_when_cached() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_dir).unwrap();

    let tarball_bytes = create_tarball("direct-tarball-pkg", "1.0.0");
    let (_integrity_str, integrity) = compute_integrity(&tarball_bytes);
    let server = MockHttpServer::start(
        "/tarballs/direct-tarball-pkg-1.0.0.tgz".to_string(),
        tarball_bytes.clone(),
    )
    .await;
    let tarball_url = format!("http://{}/tarballs/direct-tarball-pkg-1.0.0.tgz", server.addr);

    // Pre-populate tarball into cache
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    cache
        .put_with_integrity(&tarball_url, &tarball_bytes, Some(&integrity), None)
        .unwrap();

    let pkg_json = format!(
        r#"{{"name": "test-app", "dependencies": {{"direct-tarball-pkg": "{tarball_url}"}}}}"#
    );
    std::fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        registry_url: Some(format!("http://{}/", server.addr)),
        cache_dir: Some(cache_dir),
        offline: false,
        prefer_online: true,
        ignore_scripts: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();

    assert_eq!(summary.packages_installed, 1);
    assert!(
        project_dir
            .join("node_modules")
            .join("direct-tarball-pkg")
            .join("package.json")
            .exists(),
        "Package must be installed into node_modules"
    );
    assert!(
        server.tarball_request_count.load(Ordering::SeqCst) > 0,
        "--prefer-online must fetch tarball from the server even when pre-populated in cache"
    );
}
