use rnpm_registry::{
    AbbreviatedPackageMetadata, RegistryClient, RegistryClientConfig, RegistryError, TarballStream,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

/// Test TCP server for custom Byzantine and Slowloris network mocking.
struct TestHttpServer {
    addr: SocketAddr,
    shutdown: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    received_requests: Arc<Mutex<Vec<String>>>,
    #[allow(dead_code)]
    connection_count: Arc<AtomicUsize>,
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.shutdown.lock() {
            if let Some(tx) = lock.take() {
                let _ = tx.send(());
            }
        }
    }
}

impl TestHttpServer {
    async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(tokio::net::TcpStream, usize, Arc<Mutex<Vec<String>>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let received_requests = Arc::new(Mutex::new(Vec::new()));
        let connection_count = Arc::new(AtomicUsize::new(0));

        let reqs_store = received_requests.clone();
        let conn_store = connection_count.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((stream, _)) = accept_res {
                            let h = handler.clone();
                            let conn_idx = conn_store.fetch_add(1, Ordering::SeqCst);
                            let reqs = reqs_store.clone();
                            tokio::spawn(async move {
                                h(stream, conn_idx, reqs).await;
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown: Arc::new(std::sync::Mutex::new(Some(tx))),
            received_requests,
            connection_count,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn host_key(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }
}

// =========================================================================
// 1. Byzantine Packument & Validation Tests
// =========================================================================

#[tokio::test]
async fn test_byzantine_malformed_json_syntax() {
    let server = TestHttpServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

        // Malformed, truncated JSON
        let body = r#"{"name": "malformed-pkg", "dist-tags": {"latest": "1.0.0", "versions"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .get_package_metadata("malformed-pkg")
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::Json(_)),
        "Expected JSON error, got: {err:?}"
    );
}

#[tokio::test]
async fn test_byzantine_corrupted_surrogates() {
    let server = TestHttpServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

        // Corrupted unpaired surrogate \ud800 in JSON string
        let body = r#"{"name": "corrupt-\ud800-pkg", "dist-tags": {}, "versions": {}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .get_package_metadata("corrupt-pkg")
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::Json(_)),
        "Expected JSON parse error for corrupted surrogate, got: {err:?}"
    );
}

#[tokio::test]
async fn test_byzantine_duplicate_version_keys() {
    let server = TestHttpServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

        let body = r#"{
            "name": "dup-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "dup-pkg",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/dup-pkg/-/dup-pkg-1.0.0.tgz" }
                },
                "1.0.0": {
                    "name": "dup-pkg",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://evil.com/dup-pkg-1.0.0.tgz" }
                }
            }
        }"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("dup-pkg").await.unwrap_err();
    assert!(
        matches!(err, RegistryError::Json(_)),
        "Duplicate version keys must be rejected during JSON deserialization: {err:?}"
    );
    let err_str = err.to_string();
    assert!(
        err_str.contains("duplicate version key '1.0.0'"),
        "Error string was: {err_str}"
    );
}

#[tokio::test]
async fn test_byzantine_spoofed_dist_tags() {
    let server = TestHttpServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

        let body = r#"{
            "name": "spoofed-pkg",
            "dist-tags": { "latest": "9.9.9" },
            "versions": {
                "1.0.0": {
                    "name": "spoofed-pkg",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/spoofed-pkg/-/spoofed-pkg-1.0.0.tgz" }
                }
            }
        }"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .get_package_metadata("spoofed-pkg")
        .await
        .unwrap_err();
    assert!(
        err.is_malformed_metadata(),
        "Expected MalformedMetadata for spoofed dist-tags, got: {err:?}"
    );
    assert!(err
        .to_string()
        .contains("points to non-existent version '9.9.9'"));
}

#[tokio::test]
async fn test_byzantine_mismatched_version_key_and_package_name() {
    // 1. Mismatched version key
    let json_ver_mismatch = r#"{
        "name": "mismatch-pkg",
        "versions": {
            "2.0.0": {
                "name": "mismatch-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "https://registry.npmjs.org/mismatch-pkg/-/mismatch-pkg-1.0.0.tgz" }
            }
        }
    }"#;
    let meta1: AbbreviatedPackageMetadata = serde_json::from_str(json_ver_mismatch).unwrap();
    let err1 = meta1.validate().unwrap_err();
    assert!(err1.is_malformed_metadata());
    assert!(err1.to_string().contains("does not match version field"));

    // 2. Mismatched package name
    let json_name_mismatch = r#"{
        "name": "legit-pkg",
        "versions": {
            "1.0.0": {
                "name": "impostor-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "https://registry.npmjs.org/legit-pkg/-/legit-pkg-1.0.0.tgz" }
            }
        }
    }"#;
    let meta2: AbbreviatedPackageMetadata = serde_json::from_str(json_name_mismatch).unwrap();
    let err2 = meta2.validate().unwrap_err();
    assert!(err2.is_malformed_metadata());
    assert!(err2.to_string().contains("does not match packument name"));
}

#[tokio::test]
async fn test_byzantine_malicious_tarball_schemes() {
    let malicious_urls = [
        "file:///etc/passwd",
        "data:text/plain;base64,evil",
        "javascript:alert(1)",
        "ftp://evil.com/payload.tgz",
    ];

    let client = RegistryClient::new().unwrap();

    for url in malicious_urls {
        // Direct bytes download must reject scheme
        let err_bytes = client.download_tarball_bytes(url).await.unwrap_err();
        assert!(
            matches!(err_bytes, RegistryError::SecurityViolation(_)),
            "Expected SecurityViolation for scheme '{url}', got: {err_bytes:?}"
        );

        // Direct file download must reject scheme
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("out.tgz");
        let err_file = client
            .download_tarball_to_file(url, &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err_file, RegistryError::SecurityViolation(_)),
            "Expected SecurityViolation for to_file with '{url}', got: {err_file:?}"
        );

        // TarballStream must reject scheme
        let err_stream = client.download_tarball_stream(url).await.unwrap_err();
        assert!(
            matches!(err_stream, RegistryError::SecurityViolation(_)),
            "Expected SecurityViolation for stream with '{url}', got: {err_stream:?}"
        );

        // Metadata validation must reject scheme
        let json = format!(
            r#"{{
            "name": "scheme-test",
            "versions": {{
                "1.0.0": {{
                    "name": "scheme-test",
                    "version": "1.0.0",
                    "dist": {{ "tarball": "{url}" }}
                }}
            }}
        }}"#
        );
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(&json).unwrap();
        let err_meta = meta.validate().unwrap_err();
        assert!(err_meta.is_malformed_metadata());
    }
}

#[tokio::test]
async fn test_byzantine_crlf_header_injection_sanitization() {
    // 1. In metadata name
    let json1 = r#"{"name": "pkg\r\nSet-Cookie: evil=true", "versions": {}}"#;
    let meta1: AbbreviatedPackageMetadata = serde_json::from_str(json1).unwrap();
    assert!(meta1.validate().unwrap_err().is_malformed_metadata());

    // 2. In dist-tag
    let json2 = r#"{"name": "pkg", "dist-tags": {"latest\r\n": "1.0.0"}, "versions": {}}"#;
    let meta2: AbbreviatedPackageMetadata = serde_json::from_str(json2).unwrap();
    assert!(meta2.validate().unwrap_err().is_malformed_metadata());

    // 3. In version
    let json3 = r#"{
        "name": "pkg",
        "versions": {
            "1.0.0\r\n": {
                "name": "pkg",
                "version": "1.0.0\r\n",
                "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz" }
            }
        }
    }"#;
    let meta3: AbbreviatedPackageMetadata = serde_json::from_str(json3).unwrap();
    assert!(meta3.validate().unwrap_err().is_malformed_metadata());

    // 4. In tarball URL
    let json4 = r#"{
        "name": "pkg",
        "versions": {
            "1.0.0": {
                "name": "pkg",
                "version": "1.0.0",
                "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz\r\nEvil: true" }
            }
        }
    }"#;
    let meta4: AbbreviatedPackageMetadata = serde_json::from_str(json4).unwrap();
    assert!(meta4.validate().unwrap_err().is_malformed_metadata());
}

// =========================================================================
// 2. Auth Token Leak Prevention Tests
// =========================================================================

#[tokio::test]
async fn test_byzantine_auth_token_leak_prevention_cross_origin_tarball() {
    // Untrusted CDN server hosting tarball
    let cdn_server = TestHttpServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

        let body = b"legitimate-tarball-bytes-on-cross-origin-cdn";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
    })
    .await;

    let cdn_url = format!("{}tarball/pkg-1.0.0.tgz", cdn_server.url());

    // Registry server
    let cdn_url_clone = cdn_url.clone();
    let registry_server = TestHttpServer::start(move |mut stream, _, reqs| {
        let tarball_target = cdn_url_clone.clone();
        async move {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            reqs.lock().await.push(String::from_utf8_lossy(&buf[..n]).to_string());

            let body = format!(
                r#"{{
                    "name": "remote-tarball-pkg",
                    "dist-tags": {{ "latest": "1.0.0" }},
                    "versions": {{
                        "1.0.0": {{
                            "name": "remote-tarball-pkg",
                            "version": "1.0.0",
                            "dist": {{ "tarball": "{tarball_target}" }}
                        }}
                    }}
                }}"#
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let secret_token = "npm_super_secret_registry_token_99999";
    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(registry_server.host_key());

    let config = RegistryClientConfig {
        default_registry: registry_server.url(),
        auth_token: Some(secret_token.to_string()),
        trusted_hosts,
        timeout: Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Fetch metadata from registry (should send auth token to registry)
    let meta = client
        .get_package_metadata("remote-tarball-pkg")
        .await
        .unwrap();
    let tarball_target = &meta.versions.get("1.0.0").unwrap().dist.tarball;
    assert_eq!(tarball_target, &cdn_url);

    // Verify registry server received auth token
    {
        let reg_reqs = registry_server.received_requests.lock().await;
        assert_eq!(reg_reqs.len(), 1);
        assert!(
            reg_reqs[0]
                .to_lowercase()
                .contains(&format!("authorization: bearer {secret_token}").to_lowercase()),
            "Registry request must include authorization header"
        );
    }

    // 2. Download tarball from cross-origin CDN host
    let tarball_bytes = client.download_tarball_bytes(tarball_target).await.unwrap();
    assert_eq!(
        tarball_bytes,
        b"legitimate-tarball-bytes-on-cross-origin-cdn"
    );

    // CRITICAL SECURITY ASSERTION:
    // Untrusted CDN server must NEVER receive registry auth token!
    {
        let cdn_reqs = cdn_server.received_requests.lock().await;
        assert_eq!(cdn_reqs.len(), 1);
        assert!(
            !cdn_reqs[0].to_lowercase().contains("authorization"),
            "Cross-origin tarball host must NOT receive authorization header! Got: {}",
            cdn_reqs[0]
        );
    }

    // 3. Download tarball to file
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("pkg-1.0.0.tgz");
    let written = client
        .download_tarball_to_file(tarball_target, &dest_file)
        .await
        .unwrap();
    assert_eq!(written, tarball_bytes.len() as u64);
    assert_eq!(std::fs::read(&dest_file).unwrap(), tarball_bytes);

    {
        let cdn_reqs = cdn_server.received_requests.lock().await;
        assert_eq!(cdn_reqs.len(), 2);
        assert!(
            !cdn_reqs[1].to_lowercase().contains("authorization"),
            "Cross-origin tarball host for file download must NOT receive authorization header! Got: {}",
            cdn_reqs[1]
        );
    }
}

// =========================================================================
// 3. Slowloris & Streaming Hardening Tests
// =========================================================================

#[tokio::test]
async fn test_slowloris_metadata_chunk_idle_timeout() {
    // Server starts sending headers, sends 1 byte, then sleeps longer than chunk_idle_timeout
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.flush().await;

        // Send 1 byte chunk
        let chunk1 = "1\r\n{\r\n";
        let _ = stream.write_all(chunk1.as_bytes()).await;
        let _ = stream.flush().await;

        // Slowloris pause: sleep 400ms (client timeout is 100ms)
        tokio::time::sleep(Duration::from_millis(400)).await;

        let chunk2 = "1\r\n}\r\n";
        let _ = stream.write_all(chunk2.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        chunk_idle_timeout: Duration::from_millis(100),
        timeout: Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("slow-pkg").await.unwrap_err();
    assert!(
        err.is_slowloris_timeout() || err.is_timeout(),
        "Expected SlowlorisTimeout, got: {err:?}"
    );
}

#[tokio::test]
async fn test_slowloris_tarball_bytes_drip_feed_timeout() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.flush().await;

        // Send 1 byte
        let _ = stream.write_all(b"1\r\nX\r\n").await;
        let _ = stream.flush().await;

        // Drip feed delay exceeding timeout (100ms)
        tokio::time::sleep(Duration::from_millis(400)).await;

        let _ = stream.write_all(b"1\r\nY\r\n").await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        chunk_idle_timeout: Duration::from_millis(100),
        timeout: Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}slow-tarball.tgz", server.url());
    let err = client.download_tarball_bytes(&tar_url).await.unwrap_err();
    assert!(
        err.is_slowloris_timeout() || err.is_timeout(),
        "Expected SlowlorisTimeout, got: {err:?}"
    );
}

#[tokio::test]
async fn test_slowloris_tarball_to_file_drip_feed_timeout_and_temp_cleanup() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.flush().await;

        let _ = stream.write_all(b"4\r\nABCD\r\n").await;
        let _ = stream.flush().await;

        // Drip-feed delay: sleep 400ms when timeout is 100ms
        tokio::time::sleep(Duration::from_millis(400)).await;

        let _ = stream.write_all(b"4\r\nEFGH\r\n").await;
        let _ = stream.flush().await;
    })
    .await;

    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("drip.tgz");
    let part_path = temp_dir.path().join("drip.tgz.part");

    let config = RegistryClientConfig {
        default_registry: server.url(),
        chunk_idle_timeout: Duration::from_millis(100),
        timeout: Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}drip.tgz", server.url());
    let err = client
        .download_tarball_to_file(&tar_url, &dest_path)
        .await
        .unwrap_err();
    assert!(
        err.is_slowloris_timeout() || err.is_timeout(),
        "Expected SlowlorisTimeout, got: {err:?}"
    );

    // Atomic write assertion: Neither dest_path nor temp .part file should remain on failure!
    assert!(
        !dest_path.exists(),
        "Destination file must NOT exist after failed download"
    );
    assert!(
        !part_path.exists(),
        "Temporary .part file must be cleaned up after failed download"
    );
}

#[tokio::test]
async fn test_slowloris_metadata_size_limit_exceeded_header() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let resp =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{}";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_metadata_size: 1024, // 1 KB limit
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("huge-pkg").await.unwrap_err();
    assert!(
        err.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded from Content-Length header, got: {err:?}"
    );
}

#[tokio::test]
async fn test_slowloris_metadata_size_limit_exceeded_streaming() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.flush().await;

        // Send 10 chunks of 256 bytes (2560 bytes total)
        let chunk_data = "x".repeat(256);
        for _ in 0..10 {
            let chunk_str = format!("{:x}\r\n{}\r\n", chunk_data.len(), chunk_data);
            if stream.write_all(chunk_str.as_bytes()).await.is_err() {
                break;
            }
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_metadata_size: 512, // 512 bytes limit
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .get_package_metadata("stream-flood-pkg")
        .await
        .unwrap_err();
    assert!(
        err.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded from stream chunk accumulation, got: {err:?}"
    );
}

#[tokio::test]
async fn test_slowloris_tarball_size_limit_exceeded_header() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1000000000\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_package_size: 1024, // 1 KB limit
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}huge.tgz", server.url());
    let err_bytes = client.download_tarball_bytes(&tar_url).await.unwrap_err();
    assert!(
        err_bytes.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded for download_tarball_bytes, got: {err_bytes:?}"
    );

    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("huge.tgz");
    let err_file = client
        .download_tarball_to_file(&tar_url, &dest_file)
        .await
        .unwrap_err();
    assert!(
        err_file.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded for download_tarball_to_file, got: {err_file:?}"
    );
    assert!(!dest_file.exists());
}

#[tokio::test]
async fn test_slowloris_tarball_endless_stream_exceeded_aborts() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.flush().await;

        let chunk_payload = vec![0x42u8; 512];
        loop {
            let chunk_hdr = format!("{:x}\r\n", chunk_payload.len());
            if stream.write_all(chunk_hdr.as_bytes()).await.is_err() {
                break;
            }
            if stream.write_all(&chunk_payload).await.is_err() {
                break;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                break;
            }
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_package_size: 1024, // 1 KB max package size
        timeout: Duration::from_secs(5),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}endless.tgz", server.url());

    // 1. download_tarball_bytes aborts
    let err_bytes = client.download_tarball_bytes(&tar_url).await.unwrap_err();
    assert!(
        err_bytes.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded on endless stream bytes, got: {err_bytes:?}"
    );

    // 2. download_tarball_to_file aborts and cleans up temp .part file
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("endless.tgz");
    let part_file = temp_dir.path().join("endless.tgz.part");

    let err_file = client
        .download_tarball_to_file(&tar_url, &dest_file)
        .await
        .unwrap_err();
    assert!(
        err_file.is_size_limit_exceeded(),
        "Expected SizeLimitExceeded on endless stream to file, got: {err_file:?}"
    );
    assert!(!dest_file.exists(), "Target file must not exist");
    assert!(
        !part_file.exists(),
        "Temporary .part file must be cleaned up"
    );
}

#[tokio::test]
async fn test_slowloris_content_length_mismatch_tarball() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        // Content-Length says 100 bytes, but we only send 40 bytes and close connection
        let body = b"1234567890123456789012345678901234567890"; // 40 bytes
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
        // Drop stream abruptly
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}short.tgz", server.url());

    // 1. Bytes check
    let err_bytes = client.download_tarball_bytes(&tar_url).await.unwrap_err();
    assert!(
        err_bytes.is_content_length_mismatch() || matches!(err_bytes, RegistryError::Http(_)),
        "Expected ContentLengthMismatch or Http EOF error, got: {err_bytes:?}"
    );

    // 2. File check
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("short.tgz");
    let part_file = temp_dir.path().join("short.tgz.part");

    let err_file = client
        .download_tarball_to_file(&tar_url, &dest_file)
        .await
        .unwrap_err();
    assert!(
        err_file.is_content_length_mismatch() || matches!(err_file, RegistryError::Http(_)),
        "Expected ContentLengthMismatch or Http EOF error, got: {err_file:?}"
    );
    assert!(!dest_file.exists());
    assert!(!part_file.exists());
}

#[tokio::test]
async fn test_tarball_stream_concurrency_permit_retention() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let body = b"tarball-stream-payload";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_concurrent_requests: 1, // Only 1 concurrent request allowed
        timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tar_url = format!("{}stream.tgz", server.url());

    // Before acquiring stream, 1 permit is available
    assert_eq!(client.semaphore().available_permits(), 1);

    // Acquire stream
    let mut tar_stream: TarballStream = client.download_tarball_stream(&tar_url).await.unwrap();

    // While stream is alive, permit MUST remain held (available permits == 0)
    assert_eq!(
        client.semaphore().available_permits(),
        0,
        "Permit must be held by active TarballStream"
    );

    // Read chunk through TarballStream
    let chunk = tar_stream.chunk().await.unwrap().unwrap();
    assert_eq!(&chunk[..], b"tarball-stream-payload");

    // Permit is still held
    assert_eq!(client.semaphore().available_permits(), 0);

    // Drop stream
    drop(tar_stream);

    // Permit is now released back to semaphore!
    assert_eq!(
        client.semaphore().available_permits(),
        1,
        "Permit must be released when TarballStream is dropped"
    );
}

#[tokio::test]
async fn test_security_redirect_loop_detected() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        // Redirect back to /loop
        let resp = "HTTP/1.1 302 Found\r\nLocation: /loop\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .download_tarball_bytes(&format!("{}loop", server.url()))
        .await
        .unwrap_err();
    match err {
        RegistryError::SecurityViolation(msg) => {
            assert!(
                msg.contains("Redirect loop detected"),
                "Expected 'Redirect loop detected', got: {msg}"
            );
        }
        other => panic!("Expected RegistryError::SecurityViolation, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_security_redirect_to_unsupported_scheme() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let resp =
            "HTTP/1.1 302 Found\r\nLocation: file:///etc/passwd\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .download_tarball_bytes(&format!("{}leak", server.url()))
        .await
        .unwrap_err();
    match err {
        RegistryError::SecurityViolation(msg) => {
            assert!(
                msg.contains("Redirect to unsupported scheme"),
                "Expected 'Redirect to unsupported scheme', got: {msg}"
            );
        }
        other => panic!("Expected RegistryError::SecurityViolation, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_security_redirect_crlf_injection() {
    let server = TestHttpServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        // Raw bytes with CRLF in Location header value (if sent as bytes)
        let resp = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/evil\r\nX-Injected: true\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .download_tarball_bytes(&format!("{}crlf", server.url()))
        .await
        .unwrap_err();
    match err {
        RegistryError::SecurityViolation(_) | RegistryError::Http(_) => {
            // Expected either security violation or reqwest parser rejection of invalid header
        }
        other => {
            panic!("Expected SecurityViolation or Http error on CRLF in Location, got: {other:?}")
        }
    }
}
