#![allow(clippy::field_reassign_with_default)]

use rnpm_registry::{
    create_publish_payload, PublishPayloadOptions, PublishTarballData, RegistryClient,
    RegistryClientConfig, RegistryError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

/// Recorded HTTP request for assertions.
#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json_body(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Mock HTTP server for publishing and auth tests.
struct PublishMockServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    pub recorded_requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl PublishMockServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> (u16, Vec<(&'static str, String)>, Vec<u8>)
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let recorded_requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = recorded_requests.clone();
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
                                let mut buffer = Vec::new();
                                let mut temp = [0u8; 4096];
                                let mut header_end = None;
                                let mut content_len = 0;

                                while let Ok(n) = stream.read(&mut temp).await {
                                    if n == 0 {
                                        break;
                                    }
                                    buffer.extend_from_slice(&temp[..n]);

                                    if header_end.is_none() {
                                        if let Some(idx) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                            header_end = Some(idx + 4);
                                            let header_text = String::from_utf8_lossy(&buffer[..idx]);
                                            for line in header_text.lines() {
                                                if let Some((k, v)) = line.split_once(':') {
                                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                                        content_len = v.trim().parse::<usize>().unwrap_or(0);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if let Some(end) = header_end {
                                        if buffer.len() >= end + content_len {
                                            break;
                                        }
                                    }
                                }

                                if let Some(end) = header_end {
                                    let header_text = String::from_utf8_lossy(&buffer[..end - 4]);
                                    let mut lines = header_text.lines();
                                    let req_line = lines.next().unwrap_or_default();
                                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                                    let method = parts.first().copied().unwrap_or("GET").to_string();
                                    let path = parts.get(1).copied().unwrap_or("/").to_string();

                                    let mut headers = Vec::new();
                                    for line in lines {
                                        if let Some((k, v)) = line.split_once(':') {
                                            headers.push((k.trim().to_string(), v.trim().to_string()));
                                        }
                                    }

                                    let body = buffer[end..end + content_len].to_vec();
                                    let req = RecordedRequest {
                                        method,
                                        path,
                                        headers,
                                        body,
                                    };

                                    reqs_clone.lock().await.push(req.clone());

                                    let (status, resp_headers, resp_body) = handler_clone(&req);
                                    let status_text = match status {
                                        200 => "OK",
                                        201 => "Created",
                                        401 => "Unauthorized",
                                        403 => "Forbidden",
                                        409 => "Conflict",
                                        _ => "Response",
                                    };

                                    let mut resp = format!(
                                        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                        resp_body.len()
                                    );
                                    for (k, v) in resp_headers {
                                        resp.push_str(&format!("{k}: {v}\r\n"));
                                    }
                                    resp.push_str("\r\n");

                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.write_all(&resp_body).await;
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
            recorded_requests,
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
async fn test_publish_unscoped_success() {
    let server = PublishMockServer::start(|req| {
        if req.method == "PUT" && req.path == "/test-package" {
            (200, vec![("Content-Type", "application/json".into())], b"{\"ok\":true}".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();
    let mut config = RegistryClientConfig::default();
    config.default_registry = server_url.clone();
    config.auth_token = Some("secret-token-123".into());
    config.trusted_hosts.insert(server_url.host_str().unwrap().to_ascii_lowercase());

    let client = RegistryClient::with_config(config).unwrap();

    let manifest = serde_json::json!({
        "name": "test-package",
        "version": "1.0.0",
        "description": "A package for testing",
    });
    let tarball_bytes = b"gzip compressed tarball bytes";
    let tarball = PublishTarballData {
        filename: "test-package-1.0.0.tgz",
        bytes: tarball_bytes,
        shasum: "abcdef1234567890",
        integrity: "sha512-testintegrity==",
    };
    let opts = PublishPayloadOptions {
        name: "test-package",
        version: "1.0.0",
        description: Some("A package for testing"),
        tag: "latest",
        access: Some("public"),
        manifest: &manifest,
        tarball,
        registry_url: &server_url,
        provenance_attestation: None,
    };
    let payload = create_publish_payload(&opts);

    let res = client.publish_to(&server_url, "test-package", &payload, Some("123456")).await;
    assert!(res.is_ok(), "Publish should succeed: {:?}", res.err());

    let reqs = server.recorded_requests.lock().await;
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/test-package");
    assert_eq!(req.header("authorization"), Some("Bearer secret-token-123"));
    assert_eq!(req.header("npm-otp"), Some("123456"));
    assert_eq!(req.header("content-type"), Some("application/json"));

    let doc = req.json_body();
    assert_eq!(doc["_id"], "test-package");
    assert_eq!(doc["name"], "test-package");
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    assert_eq!(doc["versions"]["1.0.0"]["dist"]["shasum"], "abcdef1234567890");
    assert_eq!(doc["versions"]["1.0.0"]["dist"]["integrity"], "sha512-testintegrity==");
    assert_eq!(doc["_attachments"]["test-package-1.0.0.tgz"]["length"], tarball_bytes.len());
    drop(reqs);

    server.stop();
}

#[tokio::test]
async fn test_publish_scoped_success() {
    let server = PublishMockServer::start(|req| {
        if req.method == "PUT" && req.path == "/@my-scope%2fmy-pkg" {
            (200, vec![("Content-Type", "application/json".into())], b"{\"ok\":true}".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();
    let mut config = RegistryClientConfig::default();
    config.default_registry = server_url.clone();
    config.auth_token = Some("scoped-token-xyz".into());
    config.trusted_hosts.insert(server_url.host_str().unwrap().to_ascii_lowercase());

    let client = RegistryClient::with_config(config).unwrap();

    let manifest = serde_json::json!({
        "name": "@my-scope/my-pkg",
        "version": "2.0.0",
    });
    let tarball_bytes = b"scoped tarball bytes";
    let tarball = PublishTarballData {
        filename: "my-scope-my-pkg-2.0.0.tgz",
        bytes: tarball_bytes,
        shasum: "112233445566",
        integrity: "sha512-scopedinteg==",
    };
    let opts = PublishPayloadOptions {
        name: "@my-scope/my-pkg",
        version: "2.0.0",
        description: None,
        tag: "beta",
        access: Some("restricted"),
        manifest: &manifest,
        tarball,
        registry_url: &server_url,
        provenance_attestation: None,
    };
    let payload = create_publish_payload(&opts);

    let res = client.publish_to(&server_url, "@my-scope/my-pkg", &payload, None).await;
    assert!(res.is_ok(), "Publish scoped should succeed: {:?}", res.err());

    let reqs = server.recorded_requests.lock().await;
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/@my-scope%2fmy-pkg");
    assert_eq!(req.header("authorization"), Some("Bearer scoped-token-xyz"));
    assert_eq!(req.header("npm-otp"), None);

    let doc = req.json_body();
    assert_eq!(doc["_id"], "@my-scope/my-pkg");
    assert_eq!(doc["dist-tags"]["beta"], "2.0.0");
    assert_eq!(doc["access"], "restricted");
    drop(reqs);

    server.stop();
}

#[tokio::test]
async fn test_publish_error_diagnostics_conflict_and_auth() {
    let server = PublishMockServer::start(|req| {
        if req.path == "/pkg-conflict" {
            (409, vec![], b"cannot publish over existing version".to_vec())
        } else if req.path == "/pkg-unauth" {
            (401, vec![], b"need auth".to_vec())
        } else if req.path == "/pkg-forbidden" {
            (403, vec![], b"forbidden".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();
    let mut config = RegistryClientConfig::default();
    config.default_registry = server_url.clone();
    config.auth_token = Some("test-token".into());
    config.trusted_hosts.insert(server_url.host_str().unwrap().to_ascii_lowercase());

    let client = RegistryClient::with_config(config).unwrap();
    let dummy_payload = serde_json::json!({ "name": "dummy" });

    // 1. Conflict 409 -> PublishConflict
    let err_conflict = client.publish_to(&server_url, "pkg-conflict", &dummy_payload, None).await.unwrap_err();
    match err_conflict {
        RegistryError::PublishConflict { status, message, .. } => {
            assert_eq!(status, 409);
            assert!(message.contains("cannot publish over existing version"));
        }
        other => panic!("Expected PublishConflict, got: {other:?}"),
    }

    // 2. Unauthorized 401 -> Unauthorized
    let err_unauth = client.publish_to(&server_url, "pkg-unauth", &dummy_payload, None).await.unwrap_err();
    match err_unauth {
        RegistryError::Unauthorized { status, .. } => {
            assert_eq!(status, 401);
        }
        other => panic!("Expected Unauthorized, got: {other:?}"),
    }

    // 3. Forbidden 403 -> Forbidden
    let err_forbid = client.publish_to(&server_url, "pkg-forbidden", &dummy_payload, None).await.unwrap_err();
    match err_forbid {
        RegistryError::Forbidden { status, .. } => {
            assert_eq!(status, 403);
        }
        other => panic!("Expected Forbidden, got: {other:?}"),
    }

    server.stop();
}

#[tokio::test]
async fn test_whoami_success_and_error() {
    let server = PublishMockServer::start(|req| {
        if req.path == "/-/whoami" {
            if req.header("authorization") == Some("Bearer valid-token") {
                (200, vec![("Content-Type", "application/json".into())], b"{\"username\":\"alice\"}".to_vec())
            } else {
                (401, vec![], b"unauthorized".to_vec())
            }
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();

    // 1. With valid auth token
    let mut config = RegistryClientConfig::default();
    config.default_registry = server_url.clone();
    config.auth_token = Some("valid-token".into());
    config.trusted_hosts.insert(server_url.host_str().unwrap().to_ascii_lowercase());

    let client = RegistryClient::with_config(config).unwrap();
    let username = client.whoami(Some(&server_url)).await.unwrap();
    assert_eq!(username, "alice");

    // 2. Without auth token -> returns Unauthorized immediately
    let mut config_no_token = RegistryClientConfig::default();
    config_no_token.default_registry = server_url.clone();
    let client_no_token = RegistryClient::with_config(config_no_token).unwrap();
    let err = client_no_token.whoami(Some(&server_url)).await.unwrap_err();
    assert!(err.is_unauthorized());

    server.stop();
}

#[tokio::test]
async fn test_ping_success() {
    let server = PublishMockServer::start(|req| {
        if req.path == "/-/ping" {
            (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();
    let client = RegistryClient::new().unwrap();
    let duration = client.ping(Some(&server_url)).await.unwrap();
    assert!(duration.as_millis() < 5000);

    server.stop();
}

#[tokio::test]
async fn test_token_list_and_revoke() {
    let server = PublishMockServer::start(|req| {
        if req.method == "GET" && req.path == "/-/npm/v1/tokens" {
            let body = serde_json::json!({
                "objects": [
                    { "id": "tok_123", "token": "npm_abc", "created": "2026-01-01", "readonly": false }
                ]
            });
            (200, vec![("Content-Type", "application/json".into())], serde_json::to_vec(&body).unwrap())
        } else if req.method == "DELETE" && req.path == "/-/npm/v1/tokens/token/tok_123" {
            (200, vec![], b"".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    }).await;

    let server_url = server.url();
    let mut config = RegistryClientConfig::default();
    config.default_registry = server_url.clone();
    config.auth_token = Some("my-token".into());
    config.trusted_hosts.insert(server_url.host_str().unwrap().to_ascii_lowercase());

    let client = RegistryClient::with_config(config).unwrap();

    let tokens = client.token_list(Some(&server_url)).await.unwrap();
    assert_eq!(tokens["objects"][0]["id"], "tok_123");

    let revoke_res = client.token_revoke(Some(&server_url), "tok_123").await;
    assert!(revoke_res.is_ok());

    server.stop();
}
