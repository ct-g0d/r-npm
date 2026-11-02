use rnpm_registry::{
    AbbreviatedPackageMetadata, BytesFetchResult, CircuitBreakerState, MetadataFetchResult,
    RegistryClient, RegistryClientConfig, RegistryError, TarballFetchResult, NPM_INSTALL_V1_JSON,
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

/// Simple mock HTTP server for integration tests.
struct MockHttpServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    received_requests: Arc<Mutex<Vec<String>>>,
}

impl MockHttpServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let received_requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = received_requests.clone();
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
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    reqs_clone.lock().await.push(req_str.clone());

                                    let (status, headers, body) = handler_clone(&req_str);
                                    let status_text = match status {
                                        200 => "OK",
                                        302 => "Found",
                                        401 => "Unauthorized",
                                        404 => "Not Found",
                                        429 => "Too Many Requests",
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
            shutdown: tx,
            received_requests,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

#[tokio::test]
async fn test_mock_fetch_abbreviated_metadata() {
    let mock_json = r#"{
        "name": "is-odd",
        "dist-tags": { "latest": "3.0.1" },
        "versions": {
            "3.0.1": {
                "name": "is-odd",
                "version": "3.0.1",
                "dist": {
                    "tarball": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz",
                    "integrity": "sha512-test"
                }
            }
        }
    }"#;

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /is-odd") {
            assert!(
                req.contains(&format!("accept: {NPM_INSTALL_V1_JSON}"))
                    || req.contains(&format!("Accept: {NPM_INSTALL_V1_JSON}")),
                "Request should contain abbreviated metadata accept header"
            );
            (
                200,
                vec![("Content-Type", "application/json".into())],
                mock_json.as_bytes().to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-agent".into(),
        auth_token: None,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = RegistryClient::with_config(config).unwrap();
    let meta: AbbreviatedPackageMetadata = client.get_package_metadata("is-odd").await.unwrap();

    assert_eq!(meta.name, "is-odd");
    assert_eq!(meta.dist_tags.get("latest"), Some(&"3.0.1".to_string()));
    assert!(meta.versions.contains_key("3.0.1"));

    server.stop();
}

#[tokio::test]
async fn test_mock_scoped_package_encoding() {
    let mock_json = r#"{
        "name": "@scope/mypkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {}
    }"#;

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /@scope%2fmypkg") {
            (
                200,
                vec![("Content-Type", "application/json".into())],
                mock_json.as_bytes().to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-agent".into(),
        auth_token: None,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = RegistryClient::with_config(config).unwrap();
    let meta = client.get_package_metadata("@scope/mypkg").await.unwrap();
    assert_eq!(meta.name, "@scope/mypkg");

    server.stop();
}

#[tokio::test]
async fn test_mock_streaming_tarball_download() {
    let tarball_content = b"fake tarball compressed content 123456789";

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /download/pkg.tgz") {
            (
                200,
                vec![("Content-Type", "application/octet-stream".into())],
                tarball_content.to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-agent".into(),
        auth_token: None,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = RegistryClient::with_config(config).unwrap();
    let tarball_url = format!("{}download/pkg.tgz", server.url());
    let downloaded = client.download_tarball_bytes(&tarball_url).await.unwrap();
    assert_eq!(downloaded, tarball_content);

    server.stop();
}

#[tokio::test]
async fn test_security_auth_header_stripped_on_cross_host_redirect() {
    // Target CDN server on separate port
    let cdn_server = MockHttpServer::start(|_req| {
        (200, vec![], b"downloaded from cdn".to_vec())
    })
    .await;

    let cdn_url = cdn_server.url();

    // Registry server that issues 302 redirect to cdn_url
    let registry_server = MockHttpServer::start(move |req| {
        if req.contains("GET /redirect-to-cdn") {
            // Check that incoming request had auth header
            assert!(
                req.contains("authorization: Bearer secret-npm-token")
                    || req.contains("Authorization: Bearer secret-npm-token"),
                "Registry must receive the auth header"
            );
            (302, vec![("Location", cdn_url.to_string())], vec![])
        } else {
            (404, vec![], vec![])
        }
    })
    .await;

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(registry_server.addr.to_string());

    let config = RegistryClientConfig {
        default_registry: registry_server.url(),
        user_agent: "test-agent".into(),
        auth_token: Some("secret-npm-token".into()),
        trusted_hosts,
        timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = RegistryClient::with_config(config).unwrap();
    let initial_url = format!("{}redirect-to-cdn", registry_server.url());

    let bytes = client.download_tarball_bytes(&initial_url).await.unwrap();
    assert_eq!(bytes, b"downloaded from cdn");

    // CRITICAL SECURITY ASSERTION:
    // Verify that the CDN server NEVER received the Authorization header!
    let cdn_requests = {
        let guard = cdn_server.received_requests.lock().await;
        guard.clone()
    };
    assert!(!cdn_requests.is_empty());
    for req in cdn_requests.iter() {
        assert!(
            !req.to_lowercase().contains("authorization"),
            "CDN received unauthorized token! Security leak! Request was: {req}"
        );
    }

    registry_server.stop();
    cdn_server.stop();
}

#[tokio::test]
async fn test_security_auth_header_retained_on_same_host_redirect() {
    let server = MockHttpServer::start(|req| {
        if req.contains("GET /step1") {
            assert!(
                req.to_lowercase().contains("authorization: bearer secret-npm-token"),
                "Step 1 must have auth"
            );
            (302, vec![("Location", "/step2".into())], vec![])
        } else if req.contains("GET /step2") {
            assert!(
                req.to_lowercase().contains("authorization: bearer secret-npm-token"),
                "Step 2 on same host must retain auth"
            );
            (200, vec![], b"same host ok".to_vec())
        } else {
            (404, vec![], vec![])
        }
    })
    .await;

    let mut trusted = HashSet::new();
    trusted.insert(server.addr.to_string());

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-agent".into(),
        auth_token: Some("secret-npm-token".into()),
        trusted_hosts: trusted,
        timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let client = RegistryClient::with_config(config).unwrap();
    let initial_url = format!("{}step1", server.url());
    let bytes = client.download_tarball_bytes(&initial_url).await.unwrap();
    assert_eq!(bytes, b"same host ok");

    server.stop();
}

#[tokio::test]
async fn test_error_handling() {
    let server = MockHttpServer::start(|req| {
        if req.contains("GET /not-found") {
            (404, vec![], b"{\"error\":\"Not found\"}".to_vec())
        } else if req.contains("GET /unauth") {
            (401, vec![], b"{\"error\":\"Unauthorized\"}".to_vec())
        } else if req.contains("GET /forbidden") {
            (403, vec![], b"{\"error\":\"Forbidden\"}".to_vec())
        } else if req.contains("GET /rate-limit") {
            (
                429,
                vec![("Retry-After", "30".into())],
                b"Too many requests".to_vec(),
            )
        } else {
            (500, vec![], b"Internal server error".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test".into(),
        auth_token: None,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 404
    let err = client.get_package_metadata("not-found").await.unwrap_err();
    assert!(matches!(err, rnpm_registry::RegistryError::PackageNotFound { .. }));
    assert_eq!(err.status_code(), Some(404));
    assert!(err.is_not_found());

    // 401
    let err = client.get_package_metadata("unauth").await.unwrap_err();
    assert!(matches!(err, rnpm_registry::RegistryError::Unauthorized { .. }));
    assert_eq!(err.status_code(), Some(401));
    assert!(err.is_unauthorized());
    assert!(err.is_auth_error());

    // 403
    let err = client.get_package_metadata("forbidden").await.unwrap_err();
    assert!(matches!(err, rnpm_registry::RegistryError::Forbidden { .. }));
    assert_eq!(err.status_code(), Some(403));
    assert!(err.is_forbidden());
    assert!(err.is_auth_error());

    // 429
    let err = client.get_package_metadata("rate-limit").await.unwrap_err();
    match &err {
        rnpm_registry::RegistryError::RateLimited { retry_after } => {
            assert_eq!(*retry_after, Some(30));
        }
        other => panic!("Expected RateLimited, got {other:?}"),
    }
    assert_eq!(err.status_code(), Some(429));
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_after(), Some(30));

    // Tarball download structured diagnostics
    let err_tar_404 = client
        .download_tarball_bytes(&format!("{}not-found.tgz", server.url()))
        .await
        .unwrap_err();
    assert_eq!(err_tar_404.status_code(), Some(404));
    assert!(err_tar_404.is_not_found());

    let err_tar_401 = client
        .download_tarball_bytes(&format!("{}unauth.tgz", server.url()))
        .await
        .unwrap_err();
    assert_eq!(err_tar_401.status_code(), Some(401));
    assert!(err_tar_401.is_unauthorized());

    let err_tar_403 = client
        .download_tarball_bytes(&format!("{}forbidden.tgz", server.url()))
        .await
        .unwrap_err();
    assert_eq!(err_tar_403.status_code(), Some(403));
    assert!(err_tar_403.is_forbidden());

    let err_tar_429 = client
        .download_tarball_bytes(&format!("{}rate-limit.tgz", server.url()))
        .await
        .unwrap_err();
    assert_eq!(err_tar_429.status_code(), Some(429));
    assert!(err_tar_429.is_rate_limited());
    assert_eq!(err_tar_429.retry_after(), Some(30));

    server.stop();
}

#[tokio::test]
async fn test_concurrent_metadata_and_tarball_fetching() {
    let pkg_a_json = r#"{
        "name": "pkg-a",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "pkg-a",
                "version": "1.0.0",
                "dist": { "tarball": "pkg-a.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;
    let pkg_b_json = r#"{
        "name": "pkg-b",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": "pkg-b",
                "version": "2.0.0",
                "dist": { "tarball": "pkg-b.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /pkg-a") {
            (200, vec![("Content-Type", "application/json".into())], pkg_a_json.as_bytes().to_vec())
        } else if req.contains("GET /pkg-b") {
            (200, vec![("Content-Type", "application/json".into())], pkg_b_json.as_bytes().to_vec())
        } else if req.contains("GET /tarballs/pkg-a.tgz") {
            (200, vec![("Content-Type", "application/octet-stream".into())], b"bytes-a".to_vec())
        } else if req.contains("GET /tarballs/pkg-b.tgz") {
            (200, vec![("Content-Type", "application/octet-stream".into())], b"bytes-b".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-concurrent".into(),
        auth_token: None,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        max_concurrent_requests: 4,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // Test concurrent metadata fetch
    let metas = client.get_package_metadata_concurrent(&["pkg-a", "pkg-b"]).await;
    assert_eq!(metas.len(), 2);
    assert_eq!(metas[0].as_ref().unwrap().name, "pkg-a");
    assert_eq!(metas[1].as_ref().unwrap().name, "pkg-b");

    // Test concurrent tarball fetch
    let url_a = format!("{}tarballs/pkg-a.tgz", server.url());
    let url_b = format!("{}tarballs/pkg-b.tgz", server.url());
    let tarballs = client.download_tarballs_concurrent(&[&url_a, &url_b]).await;
    assert_eq!(tarballs.len(), 2);
    assert_eq!(tarballs[0].as_ref().unwrap(), b"bytes-a");
    assert_eq!(tarballs[1].as_ref().unwrap(), b"bytes-b");

    server.stop();
}

#[tokio::test]
async fn test_retry_backoff_on_503_recovers() {
    let mock_json = r#"{
        "name": "flakey-503-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "flakey-503-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "pkg.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /flakey-503-pkg") {
            let attempt = counter_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                // First attempt: 503 Service Unavailable
                (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec())
            } else {
                // Second attempt: succeeds with 200 OK
                (200, vec![("Content-Type", "application/json".into())], mock_json.as_bytes().to_vec())
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-retry-503".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(10),
        max_retry_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("flakey-503-pkg").await.unwrap();
    assert_eq!(meta.name, "flakey-503-pkg");
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 2, "Must have retried and succeeded on attempt 2");

    server.stop();
}

#[tokio::test]
async fn test_retry_backoff_on_429_recovers() {
    let mock_json = r#"{
        "name": "flakey-429-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "flakey-429-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "pkg.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /flakey-429-pkg") {
            let attempt = counter_clone.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                // First attempt: 429 Too Many Requests with 0-second Retry-After
                (429, vec![("Retry-After", "0".into())], b"Too Many Requests".to_vec())
            } else {
                // Second attempt: succeeds
                (200, vec![("Content-Type", "application/json".into())], mock_json.as_bytes().to_vec())
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-retry-429".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(10),
        max_retry_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("flakey-429-pkg").await.unwrap();
    assert_eq!(meta.name, "flakey-429-pkg");
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 2, "Must have retried on 429 and succeeded on attempt 2");

    server.stop();
}

#[tokio::test]
async fn test_retry_backoff_exceeds_max_retries_fails() {
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /persistently-503-pkg") {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-retry-exhaust".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("persistently-503-pkg").await.unwrap_err();
    assert_eq!(err.status_code(), Some(503));
    // Attempt 0 + 2 retries = 3 total requests
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 3);

    server.stop();
}

#[tokio::test]
async fn test_etag_304_conditional_metadata_and_tarball() {
    let mock_json = r#"{
        "name": "cached-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "cached-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "cached-pkg.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;
    let tarball_data = b"cached-tarball-binary-payload-999";

    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /cached-pkg") {
            if req.to_lowercase().contains("if-none-match: \"pkg-etag-v1\"") {
                // 304 Not Modified
                (304, vec![("ETag", "\"pkg-etag-v1\"".into())], vec![])
            } else {
                (
                    200,
                    vec![
                        ("Content-Type", "application/json".into()),
                        ("ETag", "\"pkg-etag-v1\"".into()),
                    ],
                    mock_json.as_bytes().to_vec(),
                )
            }
        } else if req.contains("GET /tarballs/cached-pkg.tgz") {
            if req.to_lowercase().contains("if-none-match: \"tarball-etag-v1\"") {
                // 304 Not Modified
                (304, vec![("ETag", "\"tarball-etag-v1\"".into())], vec![])
            } else {
                (
                    200,
                    vec![
                        ("Content-Type", "application/octet-stream".into()),
                        ("ETag", "\"tarball-etag-v1\"".into()),
                    ],
                    tarball_data.to_vec(),
                )
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-etag".into(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Initial metadata fetch (unconditional)
    let meta_res1 = client.get_package_metadata_conditional("cached-pkg", None).await.unwrap();
    assert!(meta_res1.is_fresh());
    assert!(matches!(meta_res1, MetadataFetchResult::Fresh { .. }));
    assert_eq!(meta_res1.etag(), Some("\"pkg-etag-v1\""));
    assert_eq!(meta_res1.metadata().unwrap().name, "cached-pkg");

    // 2. Conditional metadata fetch with matching ETag (HTTP 304 Not Modified)
    let meta_res2 = client
        .get_package_metadata_conditional("cached-pkg", Some("\"pkg-etag-v1\""))
        .await
        .unwrap();
    assert!(meta_res2.is_not_modified());
    assert!(matches!(meta_res2, MetadataFetchResult::NotModified { .. }));
    assert_eq!(meta_res2.etag(), Some("\"pkg-etag-v1\""));
    assert!(meta_res2.metadata().is_none());

    // 3. Conditional metadata fetch with stale ETag (HTTP 200 Fresh)
    let meta_res3 = client
        .get_package_metadata_conditional("cached-pkg", Some("\"stale-etag-v0\""))
        .await
        .unwrap();
    assert!(meta_res3.is_fresh());
    assert_eq!(meta_res3.etag(), Some("\"pkg-etag-v1\""));

    // 4. Tarball conditional fetch (unconditional -> 200 Fresh)
    let tar_url = format!("{}tarballs/cached-pkg.tgz", server.url());
    let tar_res1 = client.download_tarball_bytes_conditional(&tar_url, None).await.unwrap();
    assert!(tar_res1.is_fresh());
    assert_eq!(tar_res1.bytes(), Some(tarball_data.as_slice()));
    assert_eq!(tar_res1.etag(), Some("\"tarball-etag-v1\""));

    // 5. Tarball conditional fetch with matching ETag (HTTP 304 Not Modified)
    let tar_res2 = client
        .download_tarball_bytes_conditional(&tar_url, Some("\"tarball-etag-v1\""))
        .await
        .unwrap();
    assert!(tar_res2.is_not_modified());
    assert!(matches!(tar_res2, BytesFetchResult::NotModified { .. }));
    assert_eq!(tar_res2.etag(), Some("\"tarball-etag-v1\""));
    assert!(tar_res2.bytes().is_none());

    // 6. Tarball response conditional fetch
    let stream_res1 = client.download_tarball_conditional(&tar_url, None).await.unwrap();
    assert!(stream_res1.is_modified());
    assert!(matches!(stream_res1, TarballFetchResult::Modified { .. }));
    assert_eq!(stream_res1.etag(), Some("\"tarball-etag-v1\""));

    let stream_res2 = client.download_tarball_conditional(&tar_url, Some("\"tarball-etag-v1\"")).await.unwrap();
    assert!(stream_res2.is_not_modified());
    assert!(matches!(stream_res2, TarballFetchResult::NotModified { .. }));
    assert_eq!(stream_res2.etag(), Some("\"tarball-etag-v1\""));

    server.stop();
}

#[tokio::test]
async fn test_semaphore_bounded_worker_pool_socket_exhaustion_prevention() {
    let current_concurrency = Arc::new(AtomicUsize::new(0));
    let peak_concurrency = Arc::new(AtomicUsize::new(0));

    let cur = current_concurrency.clone();
    let peak = peak_concurrency.clone();

    let server = MockHttpServer::start(move |_req| {
        let active = cur.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(active, Ordering::SeqCst);
        // Small delay to simulate network latency and test concurrency ceiling
        std::thread::sleep(Duration::from_millis(25));
        cur.fetch_sub(1, Ordering::SeqCst);

        (
            200,
            vec![("Content-Type", "application/octet-stream".into())],
            b"tarball payload bytes".to_vec(),
        )
    })
    .await;

    // Strict semaphore limit of 3 concurrent requests
    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-semaphore-concurrency".into(),
        timeout: Duration::from_secs(10),
        max_concurrent_requests: 3,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let test_url = format!("{}tarball.tgz", server.url());
    let urls: Vec<String> = (0..12).map(|_| test_url.clone()).collect();

    // Trigger 12 downloads concurrently
    let results = client.download_tarballs_concurrent(&urls).await;
    assert_eq!(results.len(), 12);
    for res in results {
        assert_eq!(res.unwrap(), b"tarball payload bytes");
    }

    let observed_peak = peak_concurrency.load(Ordering::SeqCst);
    assert!(
        observed_peak <= 3,
        "Peak concurrency {observed_peak} exceeded semaphore limit of 3! Socket pool violated bounding!"
    );

    server.stop();
}

/// Helper raw TCP server for injecting low-level socket and stream faults.
struct FaultInjectionTcpServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FaultInjectionTcpServer {
    async fn start<F, Fut>(action: F) -> Self
    where
        F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let action = Arc::new(action);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    res = listener.accept() => {
                        if let Ok((stream, _)) = res {
                            let act = action.clone();
                            tokio::spawn(async move {
                                act(stream).await;
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown: tx,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

// =========================================================================
// Network Fault Injection Tests
// =========================================================================

#[tokio::test]
async fn test_network_fault_dropped_socket_mid_download_bytes() {
    // Server starts sending 200 OK with Content-Length: 50000, writes 64 bytes, then drops socket
    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let header = "HTTP/1.1 200 OK\r\nContent-Length: 50000\r\nContent-Type: application/octet-stream\r\n\r\n";
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(b"initial 64 bytes of chunked payload before socket drop...12345678").await;
        let _ = stream.flush().await;
        // Abruptly drop the stream (TCP FIN/RST without completing body)
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-drop".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}faulty.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected download to fail when socket drops prematurely");
    let err = res.unwrap_err();
    assert!(
        err.is_decode() || matches!(err, RegistryError::Http(_)),
        "Expected HTTP/decode error on dropped socket, got: {err:?}"
    );

    server.stop();
}

#[tokio::test]
async fn test_network_fault_dropped_socket_mid_download_to_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("partial_download.tgz");

    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let header = "HTTP/1.1 200 OK\r\nContent-Length: 30000\r\nContent-Type: application/octet-stream\r\n\r\n";
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(b"some partial bytes written to disk").await;
        let _ = stream.flush().await;
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-drop-file".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}faulty-file.tgz", server.url());
    let res = client.download_tarball_to_file(&tarball_url, &dest_file).await;
    assert!(res.is_err(), "Expected file download to fail when socket is severed mid-stream");

    server.stop();
}

#[tokio::test]
async fn test_network_fault_corrupted_chunked_stream_invalid_hex() {
    // Server replies with Transfer-Encoding: chunked, but sends invalid hex size
    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\nZZZZ_INVALID_HEX\r\nPayload\r\n0\r\n\r\n";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-chunk-hex".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}corrupted-chunk.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected error on invalid chunk hex length");

    server.stop();
}

#[tokio::test]
async fn test_network_fault_corrupted_chunked_stream_premature_truncation() {
    // Server announces 100 bytes (hex 64), sends only 10 bytes, then severs connection
    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n64\r\n1234567890";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-chunk-trunc".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}truncated-chunk.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected decode error on truncated chunk body");

    server.stop();
}

#[tokio::test]
async fn test_network_fault_corrupted_chunked_stream_malformed_terminator() {
    // Server sends valid chunk but corrupts chunk CRLF terminator
    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n5\r\nhelloCORRUPTED_NO_CRLF";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-chunk-term".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}bad-term.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected error on malformed chunk terminator");

    server.stop();
}

#[tokio::test]
async fn test_network_fault_request_timeout() {
    // Server accepts connection but hangs without writing response headers
    let server = FaultInjectionTcpServer::start(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        // Sleep longer than client timeout
        tokio::time::sleep(Duration::from_millis(600)).await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-fault-timeout".into(),
        timeout: Duration::from_millis(80),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let res = client.get_package_metadata("timeout-pkg").await;
    assert!(res.is_err(), "Expected request to timeout");
    let err = res.unwrap_err();
    assert!(err.is_timeout(), "Expected error.is_timeout() to be true, got: {err:?}");

    server.stop();
}

#[tokio::test]
async fn test_network_fault_connect_timeout() {
    // TEST-NET-1 (192.0.2.1:81) is guaranteed non-routable, causing connect attempt to timeout
    let non_routable_url = Url::parse("http://192.0.2.1:81/").unwrap();
    let config = RegistryClientConfig {
        default_registry: non_routable_url,
        user_agent: "test-fault-connect-timeout".into(),
        connect_timeout: Duration::from_millis(60),
        timeout: Duration::from_millis(150),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let res = client.get_package_metadata("connect-timeout-pkg").await;
    assert!(res.is_err(), "Expected connect timeout error");
    let err = res.unwrap_err();
    assert!(
        err.is_timeout() || err.is_connect(),
        "Expected timeout or connect error, got: {err:?}"
    );
}

#[tokio::test]
async fn test_network_fault_dns_resolution_failure() {
    // RFC 2606 / 6761 reserved .invalid domain is guaranteed to fail DNS resolution
    let unresolvable_url = Url::parse("http://nonexistent-rnpm-dns-fault-test.invalid/").unwrap();
    let config = RegistryClientConfig {
        default_registry: unresolvable_url,
        user_agent: "test-dns-failure".into(),
        timeout: Duration::from_secs(2),
        max_retries: 1,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(10),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let res = client.get_package_metadata("dns-failure-pkg").await;
    assert!(res.is_err(), "Expected DNS resolution to fail");
    let err = res.unwrap_err();
    assert!(
        err.is_connect() || matches!(err, RegistryError::Http(_)),
        "Expected connection error on DNS failure, got: {err:?}"
    );
}

// =========================================================================
// Circuit Breaker & Chaotic Retry Resiliency Tests
// =========================================================================

#[tokio::test]
async fn test_chaotic_retry_oscillating_429_503_recovers() {
    let mock_json = r#"{
        "name": "chaotic-recovering-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "chaotic-recovering-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "pkg.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    // Oscillates: attempt 0 -> 429, attempt 1 -> 503, attempt 2 -> 200 OK
    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /chaotic-recovering-pkg") {
            let attempt = counter_clone.fetch_add(1, Ordering::SeqCst);
            match attempt {
                0 => (429, vec![("Retry-After", "0".into())], b"Too Many Requests".to_vec()),
                1 => (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec()),
                _ => (200, vec![("Content-Type", "application/json".into())], mock_json.as_bytes().to_vec()),
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-chaotic-recovering".into(),
        timeout: Duration::from_secs(5),
        max_retries: 3,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("chaotic-recovering-pkg").await.unwrap();
    assert_eq!(meta.name, "chaotic-recovering-pkg");
    assert_eq!(
        attempt_counter.load(Ordering::SeqCst),
        3,
        "Must have navigated chaotic 429 -> 503 oscillation and succeeded on attempt 3"
    );

    server.stop();
}

#[tokio::test]
async fn test_chaotic_retry_oscillating_exceeds_max_retries_fails() {
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    // Oscillates indefinitely between 429 and 503
    let server = MockHttpServer::start(move |req| {
        if req.contains("GET /chaotic-exhaust-pkg") {
            let attempt = counter_clone.fetch_add(1, Ordering::SeqCst);
            if attempt % 2 == 0 {
                (429, vec![("Retry-After", "0".into())], b"Too Many Requests".to_vec())
            } else {
                (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec())
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-chaotic-exhaust".into(),
        timeout: Duration::from_secs(5),
        max_retries: 3,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(30),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("chaotic-exhaust-pkg").await.unwrap_err();
    assert!(
        err.is_rate_limited() || err.status_code() == Some(503),
        "Expected rate limit or 503 status code when chaotic retries are exhausted"
    );
    // 1 initial + 3 retries = 4 attempts total
    assert_eq!(attempt_counter.load(Ordering::SeqCst), 4);

    server.stop();
}

#[tokio::test]
async fn test_circuit_breaker_trips_under_consecutive_failures() {
    let request_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = request_counter.clone();

    let server = MockHttpServer::start(move |_req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec())
    })
    .await;

    let host_str = server.addr.to_string();

    // Circuit breaker configured: threshold 2 consecutive failures, 100ms reset timeout
    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-circuit-breaker".into(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        circuit_breaker_enabled: true,
        circuit_breaker_failure_threshold: 2,
        circuit_breaker_reset_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // Request 1: fails with 503 (consecutive failures = 1)
    let res1 = client.get_package_metadata("pkg1").await;
    assert!(res1.is_err());
    assert_eq!(client.circuit_state(&host_str).await, CircuitBreakerState::Closed);

    // Request 2: fails with 503 (consecutive failures = 2 -> trips circuit to OPEN)
    let res2 = client.get_package_metadata("pkg2").await;
    assert!(res2.is_err());
    assert_eq!(client.circuit_state(&host_str).await, CircuitBreakerState::Open);

    let requests_before_fast_fail = request_counter.load(Ordering::SeqCst);
    assert_eq!(requests_before_fast_fail, 2);

    // Request 3: Circuit is OPEN -> fails fast with ZERO network requests!
    let res3 = client.get_package_metadata("pkg3").await;
    assert!(res3.is_err());
    let err3 = res3.unwrap_err();
    assert!(
        err3.is_circuit_breaker_open(),
        "Expected CircuitBreakerOpen error on fast-fail, got: {err3:?}"
    );

    // Assert that the server received NO new request for Request 3
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        requests_before_fast_fail,
        "Circuit breaker must prevent requests from hitting the network while OPEN"
    );

    server.stop();
}

#[tokio::test]
async fn test_circuit_breaker_half_open_probe_and_recovery() {
    let mock_json = r#"{
        "name": "healthy-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "healthy-pkg",
                "version": "1.0.0",
                "dist": { "tarball": "pkg.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let should_succeed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succ_clone = should_succeed.clone();

    let server = MockHttpServer::start(move |_req| {
        if succ_clone.load(Ordering::SeqCst) {
            (200, vec![("Content-Type", "application/json".into())], mock_json.as_bytes().to_vec())
        } else {
            (503, vec![("Retry-After", "0".into())], b"Service Unavailable".to_vec())
        }
    })
    .await;

    let host_str = server.addr.to_string();

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-circuit-recovery".into(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        circuit_breaker_enabled: true,
        circuit_breaker_failure_threshold: 1,
        circuit_breaker_reset_timeout: Duration::from_millis(60),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Initial request fails and immediately trips circuit
    let _ = client.get_package_metadata("unhealthy").await;
    assert_eq!(client.circuit_state(&host_str).await, CircuitBreakerState::Open);

    // 2. Wait for reset timeout to elapse
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Verify circuit transitioned to HalfOpen
    assert_eq!(client.circuit_state(&host_str).await, CircuitBreakerState::HalfOpen);

    // 3. Remote server is now healthy
    should_succeed.store(true, Ordering::SeqCst);

    // 4. Probe request in HalfOpen state succeeds and resets circuit to Closed
    let meta = client.get_package_metadata("healthy-pkg").await.unwrap();
    assert_eq!(meta.name, "healthy-pkg");
    assert_eq!(client.circuit_state(&host_str).await, CircuitBreakerState::Closed);

    // 5. Subsequent request succeeds normally
    let meta2 = client.get_package_metadata("healthy-pkg").await.unwrap();
    assert_eq!(meta2.name, "healthy-pkg");

    server.stop();
}

#[tokio::test]
async fn test_circuit_breaker_retry_after_budget_breaker() {
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = attempt_counter.clone();

    // Server returns 429 with 1 hour Retry-After
    let server = MockHttpServer::start(move |_req| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
        (429, vec![("Retry-After", "3600".into())], b"Rate limit exceeded".to_vec())
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "test-budget-breaker".into(),
        timeout: Duration::from_secs(2),
        max_retries: 3,
        max_retry_backoff: Duration::from_secs(2),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client.get_package_metadata("budget-breaker-pkg").await.unwrap_err();
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_after(), Some(3600));

    // Must break immediately on attempt 0 without retrying because 3600s > max_retry_backoff (2s)
    assert_eq!(
        attempt_counter.load(Ordering::SeqCst),
        1,
        "Client must break immediately when Retry-After exceeds backoff budget"
    );

    server.stop();
}

// =========================================================================
// Scoped Registry Routing & Security Edge Case Tests
// =========================================================================

#[tokio::test]
async fn test_scoped_registry_routing_mixed_case_and_unicode_spoofing() {
    let mock_json_corp = r#"{
        "name": "@corp/widget",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "@corp/widget",
                "version": "1.0.0",
                "dist": { "tarball": "corp.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    let mock_json_public = r#"{
        "name": "public-pkg",
        "dist-tags": { "latest": "2.0.0" },
        "versions": {
            "2.0.0": {
                "name": "public-pkg",
                "version": "2.0.0",
                "dist": { "tarball": "pub.tgz", "integrity": "sha512-test" }
            }
        }
    }"#;

    // Server 1: Default public registry
    let public_server = MockHttpServer::start(move |req| {
        if req.contains("GET /public-pkg") {
            (200, vec![("Content-Type", "application/json".into())], mock_json_public.as_bytes().to_vec())
        } else {
            (404, vec![], b"Not Found in Public".to_vec())
        }
    })
    .await;

    // Server 2: Private @corp registry
    let corp_server = MockHttpServer::start(move |req| {
        if req.contains("GET /@corp%2fwidget") {
            (200, vec![("Content-Type", "application/json".into())], mock_json_corp.as_bytes().to_vec())
        } else {
            (404, vec![], b"Not Found in Corp".to_vec())
        }
    })
    .await;

    let mut scoped_registries = std::collections::BTreeMap::new();
    scoped_registries.insert("@corp".to_string(), corp_server.url());

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(public_server.addr.to_string());
    trusted_hosts.insert(corp_server.addr.to_string());

    let config = RegistryClientConfig {
        default_registry: public_server.url(),
        user_agent: "test-scoped-routing".into(),
        timeout: Duration::from_secs(5),
        scoped_registries,
        trusted_hosts,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Scoped package resolves to private corp server
    let corp_meta = client.get_package_metadata("@corp/widget").await.unwrap();
    assert_eq!(corp_meta.name, "@corp/widget");

    // 2. Mixed-case scope correctly routes to @corp server
    assert_eq!(
        client.registry_for_package("@CORP/widget"),
        &corp_server.url()
    );
    assert_eq!(
        client.registry_for_package("@Corp/Widget"),
        &corp_server.url()
    );
    assert_eq!(
        client.registry_for_package("@cOrP%2fwidget"),
        &corp_server.url()
    );

    // 3. Unscoped package routes to default public server
    let pub_meta = client.get_package_metadata("public-pkg").await.unwrap();
    assert_eq!(pub_meta.name, "public-pkg");

    // 4. Unicode Cyrillic homoglyph spoofing: '@соrр/widget' (Cyrillic 'о', 'р')
    // Must NOT match '@corp' and must route to default public server (where it returns 404)
    let cyrillic_spoof = "@\u{0441}\u{043E}r\u{0440}/widget";
    assert_eq!(
        client.registry_for_package(cyrillic_spoof),
        &public_server.url(),
        "Spoofed Unicode scope must never route to private registry!"
    );

    public_server.stop();
    corp_server.stop();
}
