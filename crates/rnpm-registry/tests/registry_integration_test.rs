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
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 404
    let err = client.get_package_metadata("not-found").await.unwrap_err();
    assert!(matches!(err, rnpm_registry::RegistryError::PackageNotFound { .. }));

    // 401
    let err = client.get_package_metadata("unauth").await.unwrap_err();
    assert!(matches!(err, rnpm_registry::RegistryError::Unauthorized { .. }));

    // 429
    let err = client.get_package_metadata("rate-limit").await.unwrap_err();
    match err {
        rnpm_registry::RegistryError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(30));
        }
        other => panic!("Expected RateLimited, got {other:?}"),
    }

    server.stop();
}
