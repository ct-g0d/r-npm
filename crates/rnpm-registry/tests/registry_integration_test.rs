use rnpm_registry::{
    AbbreviatedPackageMetadata, RegistryClient, RegistryClientConfig, NPM_INSTALL_V1_JSON,
};
use std::collections::HashSet;
use std::net::SocketAddr;
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
async fn test_security_auth_header_stripped_on_multi_hop_redirect() {
    // CDN server that receives request from registry and redirects back
    let cdn_server = MockHttpServer::start(|_req| {
        (200, vec![], b"downloaded from cdn".to_vec())
    })
    .await;
    let cdn_url = cdn_server.url();

    // Registry server issuing redirect
    let registry_server = MockHttpServer::start(move |req| {
        if req.contains("GET /initial-tarball") {
            assert!(
                req.contains("authorization: Bearer secret-multi-token")
                    || req.contains("Authorization: Bearer secret-multi-token"),
                "Initial request must have auth"
            );
            (302, vec![("Location", cdn_url.to_string())], vec![])
        } else {
            (404, vec![], vec![])
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: registry_server.url(),
        user_agent: "test-multihop".into(),
        auth_token: Some("secret-multi-token".into()),
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let initial_url = format!("{}initial-tarball", registry_server.url());
    let bytes = client.download_tarball_bytes(&initial_url).await.unwrap();
    assert_eq!(bytes, b"downloaded from cdn");

    let cdn_reqs = {
        let guard = cdn_server.received_requests.lock().await;
        guard.clone()
    };
    for req in cdn_reqs.iter() {
        assert!(
            !req.to_lowercase().contains("authorization"),
            "CDN must not receive authorization header! Got: {req}"
        );
    }

    registry_server.stop();
    cdn_server.stop();
}

#[tokio::test]
async fn test_security_disallowed_redirect_scheme() {
    let registry_server = MockHttpServer::start(|req| {
        if req.contains("GET /bad-redirect") {
            (302, vec![("Location", "file:///etc/passwd".into())], vec![])
        } else {
            (404, vec![], vec![])
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: registry_server.url(),
        user_agent: "test-scheme".into(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let err = client
        .download_tarball_bytes(&format!("{}bad-redirect", registry_server.url()))
        .await
        .unwrap_err();

    assert!(matches!(err, rnpm_registry::RegistryError::SecurityViolation(_)));
    assert!(err.to_string().contains("Disallowed redirect scheme"));

    registry_server.stop();
}

#[tokio::test]
async fn test_security_auth_not_sent_to_untrusted_initial_url() {
    let untrusted_server = MockHttpServer::start(|_req| {
        (200, vec![], b"untrusted content".to_vec())
    })
    .await;

    // Config default registry is npmjs.org, but we request from untrusted_server
    let config = RegistryClientConfig {
        default_registry: Url::parse("https://registry.npmjs.org/").unwrap(),
        user_agent: "test-untrusted".into(),
        auth_token: Some("secret-user-token".into()),
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let bytes = client
        .download_tarball_bytes(&format!("{}tarball.tgz", untrusted_server.url()))
        .await
        .unwrap();
    assert_eq!(bytes, b"untrusted content");

    let reqs = {
        let guard = untrusted_server.received_requests.lock().await;
        guard.clone()
    };
    for req in reqs.iter() {
        assert!(
            !req.to_lowercase().contains("authorization"),
            "Untrusted third-party server must NOT receive auth header! Got: {req}"
        );
    }

    untrusted_server.stop();
}

#[tokio::test]
async fn test_scoped_registry_routing_and_auth() {
    let scoped_json = r#"{
        "name": "@myorg/scoped-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {}
    }"#;

    let scoped_server = MockHttpServer::start(move |req| {
        if req.contains("GET /@myorg%2fscoped-pkg") {
            assert!(
                req.to_lowercase().contains("authorization: bearer github-secret-token"),
                "Scoped registry must receive scoped auth token: {req}"
            );
            (
                200,
                vec![("Content-Type", "application/json".into())],
                scoped_json.as_bytes().to_vec(),
            )
        } else {
            (404, vec![], vec![])
        }
    })
    .await;

    let mut auth_tokens = std::collections::BTreeMap::new();
    let scoped_host = scoped_server.addr.to_string();
    auth_tokens.insert(format!("//{scoped_host}/"), "github-secret-token".to_string());

    let mut scoped_registries = std::collections::BTreeMap::new();
    scoped_registries.insert("@myorg".to_string(), scoped_server.url());

    let config = RegistryClientConfig {
        default_registry: Url::parse("https://registry.npmjs.org/").unwrap(),
        user_agent: "test-scoped".into(),
        auth_token: Some("default-npm-token".into()),
        auth_tokens,
        scoped_registries,
        trusted_hosts: HashSet::new(),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("@myorg/scoped-pkg").await.unwrap();
    assert_eq!(meta.name, "@myorg/scoped-pkg");

    scoped_server.stop();
}
