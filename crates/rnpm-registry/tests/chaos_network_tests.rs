use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_registry::{
    format_http_date, CircuitBreakerState, RegistryClient, RegistryClientConfig, RegistryError,
};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

/// Raw in-process TCP server for chaos engineering and fault injection tests.
struct RawChaosServer {
    addr: SocketAddr,
    shutdown: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    connection_count: Arc<AtomicUsize>,
    received_requests: Arc<Mutex<Vec<String>>>,
}

impl Drop for RawChaosServer {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.shutdown.lock() {
            if let Some(tx) = lock.take() {
                let _ = tx.send(());
            }
        }
    }
}

impl RawChaosServer {
    async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(tokio::net::TcpStream, usize, Arc<Mutex<Vec<String>>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let connection_count = Arc::new(AtomicUsize::new(0));
        let received_requests = Arc::new(Mutex::new(Vec::new()));

        let conn_counter = connection_count.clone();
        let req_store = received_requests.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((stream, _)) = accept_res {
                            let h = handler.clone();
                            let conn_idx = conn_counter.fetch_add(1, Ordering::SeqCst);
                            let reqs = req_store.clone();
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
            connection_count,
            received_requests,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn host_key(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    fn stop(&self) {
        if let Ok(mut lock) = self.shutdown.lock() {
            if let Some(tx) = lock.take() {
                let _ = tx.send(());
            }
        }
    }
}

// =========================================================================
// 1. Abrupt Connection Drop Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_abrupt_connection_drop_stream_retry_tarball_bytes_recovers() {
    let full_payload = vec![0x42u8; 5000];
    let payload_clone = full_payload.clone();

    // Attempt 0: sends HTTP 200 OK, sends 100 bytes, then abruptly drops socket
    // Attempt 1: sends HTTP 200 OK, sends complete 5000 bytes
    let server = RawChaosServer::start(move |mut stream, attempt, _| {
        let payload = payload_clone.clone();
        async move {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;

            if attempt == 0 {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                // Send only 100 bytes
                let _ = stream.write_all(&payload[..100]).await;
                let _ = stream.flush().await;
                // Abruptly drop socket mid-download
                drop(stream);
            } else {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload).await;
                let _ = stream.flush().await;
            }
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-drop-bytes-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}package.tgz", server.url());
    let downloaded = client.download_tarball_bytes(&tarball_url).await.unwrap();

    assert_eq!(downloaded.len(), 5000);
    assert_eq!(downloaded, full_payload);
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        2,
        "Should have retried stream download on second connection"
    );

    server.stop();
}

#[tokio::test]
async fn test_chaos_abrupt_connection_drop_stream_retry_tarball_to_file_recovers() {
    let full_payload = vec![0x77u8; 8192];
    let payload_clone = full_payload.clone();

    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("recovered_tarball.tgz");

    let server = RawChaosServer::start(move |mut stream, attempt, _| {
        let payload = payload_clone.clone();
        async move {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;

            if attempt == 0 {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload[..100]).await;
                let _ = stream.flush().await;
                drop(stream);
            } else {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload).await;
                let _ = stream.flush().await;
            }
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-drop-file-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}package-file.tgz", server.url());
    let written = client
        .download_tarball_to_file(&tarball_url, &dest_file)
        .await
        .unwrap();

    assert_eq!(written, 8192);
    let disk_bytes = std::fs::read(&dest_file).unwrap();
    assert_eq!(disk_bytes.len(), 8192);
    assert_eq!(disk_bytes, full_payload);
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        2,
        "File download must retry and succeed on attempt 2"
    );

    server.stop();
}

#[tokio::test]
async fn test_chaos_abrupt_connection_drop_exhausts_retries_fails() {
    // Drops socket on all attempts after sending 100 bytes
    let server = RawChaosServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let header = "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nContent-Type: application/octet-stream\r\n\r\n";
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&vec![0xAA; 100]).await;
        let _ = stream.flush().await;
        drop(stream);
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-drop-exhaust-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}unreliable.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected error after retries exhausted");
    let err = res.unwrap_err();
    assert!(
        err.is_decode() || matches!(err, RegistryError::Http(_)),
        "Expected HTTP/decode error, got: {err:?}"
    );

    // Initial attempt + 2 retries = 3 connections
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 3);

    server.stop();
}

// =========================================================================
// 2. Chunked Transfer Corruption Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_chunked_premature_eof_recovers() {
    let server = RawChaosServer::start(|mut stream, attempt, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        if attempt == 0 {
            // Premature EOF: announces 100 bytes (0x64), sends 20 bytes, abruptly terminates
            let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n64\r\n12345678901234567890";
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
            drop(stream);
        } else {
            // Valid chunked response on retry
            let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-chunked-eof-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}chunked-premature.tgz", server.url());
    let bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();
    assert_eq!(bytes, b"hello");
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 2);

    server.stop();
}

#[tokio::test]
async fn test_chaos_chunked_invalid_hex_encoding_fails() {
    let server = RawChaosServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        // Invalid hex chunk size
        let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\nNOT_VALID_HEX\r\npayload\r\n0\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-chunked-hex-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}chunked-invalid-hex.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected failure on invalid chunk encoding");

    server.stop();
}

// =========================================================================
// 3. Truncated Gzip Tarball Response Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_truncated_gzip_tarball_stream_recovery() {
    // Generate valid gzip compressed archive payload
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    let sample_payload = b"tarball payload index.js package.json valid gzip bytes 1234567890";
    gz.write_all(sample_payload).unwrap();
    let valid_gzip = gz.finish().unwrap();
    assert!(valid_gzip.len() > 30);

    let gz_clone = valid_gzip.clone();

    let server = RawChaosServer::start(move |mut stream, attempt, _| {
        let valid_gz = gz_clone.clone();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            if attempt == 0 {
                // Send gzip header and first 25 bytes of stream, then close abruptly
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    valid_gz.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&valid_gz[..25]).await;
                let _ = stream.flush().await;
                drop(stream);
            } else {
                // Send complete valid gzip payload
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    valid_gz.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&valid_gz).await;
                let _ = stream.flush().await;
            }
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-gzip-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}package-gzip.tgz", server.url());
    let downloaded_bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();

    // Verify gzip decompress succeeds cleanly
    let mut decoder = GzDecoder::new(&downloaded_bytes[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, sample_payload);
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        2,
        "Should have recovered gzip download on attempt 2"
    );

    server.stop();
}

#[tokio::test]
async fn test_chaos_truncated_gzip_tarball_persistent_truncation_fails() {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(b"sample data").unwrap();
    let valid_gzip = gz.finish().unwrap();

    let server = RawChaosServer::start(move |mut stream, _, _| {
        let valid_gz = valid_gzip.clone();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                valid_gz.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&valid_gz[..15]).await;
            let _ = stream.flush().await;
            drop(stream);
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-gzip-fail-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 1,
        initial_retry_backoff: Duration::from_millis(5),
        max_retry_backoff: Duration::from_millis(15),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}broken-gzip.tgz", server.url());
    let res = client.download_tarball_bytes(&tarball_url).await;
    assert!(res.is_err(), "Expected error when gzip truncation persists");

    server.stop();
}

// =========================================================================
// 4. HTTP 429 Throttling with Retry-After Header Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_http_429_integer_seconds_eventual_success() {
    let metadata_json = r#"{"name":"throttled-int-pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;

    let server = RawChaosServer::start(move |mut stream, attempt, _| async move {
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        if attempt == 0 {
            // Rate limit: 429 with Retry-After: 1
            let resp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        } else {
            // Eventual success: 200 OK
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                metadata_json.len(),
                metadata_json
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-int-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        max_retry_backoff: Duration::from_secs(3),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("throttled-int-pkg").await.unwrap();
    assert_eq!(meta.name, "throttled-int-pkg");
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 2);

    server.stop();
}

#[tokio::test]
async fn test_chaos_http_429_http_date_eventual_success() {
    let metadata_json = r#"{"name":"throttled-date-pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;

    let server = RawChaosServer::start(move |mut stream, attempt, _| async move {
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        if attempt == 0 {
            // Formulate HTTP-date 1 second into future
            let target_time = std::time::SystemTime::now() + Duration::from_secs(1);
            let date_str = format_http_date(target_time);
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {date_str}\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        } else {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                metadata_json.len(),
                metadata_json
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-date-test".into(),
        timeout: Duration::from_secs(6),
        max_retries: 2,
        max_retry_backoff: Duration::from_secs(3),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("throttled-date-pkg").await.unwrap();
    assert_eq!(meta.name, "throttled-date-pkg");
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 2);

    server.stop();
}

#[tokio::test]
async fn test_chaos_http_429_budget_exceeded_fails_fast() {
    // Server requests 60 seconds of Retry-After delay
    let server = RawChaosServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let resp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    // Client allows maximum backoff of only 2 seconds
    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-budget-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 3,
        max_retry_backoff: Duration::from_secs(2),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let res = client.get_package_metadata("budget-exceeded-pkg").await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.is_rate_limited(), "Expected rate limit error");
    assert_eq!(err.retry_after(), Some(60));
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        1,
        "Should immediately reject without spinning retries when budget exceeded"
    );

    server.stop();
}

#[tokio::test]
async fn test_chaos_http_429_http_date_budget_exceeded_fails_fast() {
    let server = RawChaosServer::start(|mut stream, _, _| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        // HTTP-date 120 seconds in future
        let future_time = std::time::SystemTime::now() + Duration::from_secs(120);
        let date_str = format_http_date(future_time);
        let resp = format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {date_str}\r\nContent-Length: 0\r\n\r\n"
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-date-budget-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 3,
        max_retry_backoff: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let res = client.get_package_metadata("budget-date-pkg").await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.is_rate_limited());
    let parsed_wait = err.retry_after().expect("should have parsed Retry-After");
    assert!(parsed_wait >= 115 && parsed_wait <= 125);
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 1);

    server.stop();
}

// =========================================================================
// 5. Authentication Token Leakage Protection Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_auth_token_leakage_untrusted_redirect_strips_auth() {
    // server_trusted (origin 1) -> redirects to server_untrusted (origin 2)
    let server_untrusted = RawChaosServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
        reqs.lock().await.push(req_str);

        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nuntrusted body";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let untrusted_url = server_untrusted.url();

    let server_trusted = RawChaosServer::start(move |mut stream, _, reqs| {
        let target = untrusted_url.clone();
        async move {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
            reqs.lock().await.push(req_str);

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}download/pkg.tgz\r\nContent-Length: 0\r\n\r\n",
                target
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let secret_token = "secret-super-token-12345";
    let config = RegistryClientConfig {
        default_registry: server_trusted.url(),
        user_agent: "chaos-auth-leak-test".into(),
        auth_token: Some(secret_token.into()),
        // Untrusted server is NOT in trusted_hosts!
        trusted_hosts: HashSet::from([server_trusted.host_key()]),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}initial/pkg.tgz", server_trusted.url());
    let bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();
    assert_eq!(bytes, b"untrusted body");

    // Verify Server 1 (trusted) DID receive the Authorization header
    {
        let reqs_trusted = server_trusted.received_requests.lock().await;
        assert_eq!(reqs_trusted.len(), 1);
        assert!(
            reqs_trusted[0].to_lowercase().contains(&format!("authorization: bearer {secret_token}").to_lowercase()),
            "Initial request to trusted origin must contain authorization token"
        );
    }

    // Verify Server 2 (untrusted) DID NOT receive the Authorization header
    {
        let reqs_untrusted = server_untrusted.received_requests.lock().await;
        assert_eq!(reqs_untrusted.len(), 1);
        assert!(
            !reqs_untrusted[0].to_lowercase().contains("authorization"),
            "Redirect to untrusted origin MUST strip Authorization header to prevent credential theft! Got: {}",
            reqs_untrusted[0]
        );
    }

    server_trusted.stop();
    server_untrusted.stop();
}

#[tokio::test]
async fn test_chaos_auth_token_leakage_trusted_redirect_retains_auth() {
    let server_dest = RawChaosServer::start(|mut stream, _, reqs| async move {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
        reqs.lock().await.push(req_str);

        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\ntrusted body";
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
    })
    .await;

    let dest_url = server_dest.url();

    let server_initial = RawChaosServer::start(move |mut stream, _, reqs| {
        let target = dest_url.clone();
        async move {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
            reqs.lock().await.push(req_str);

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}download/trusted.tgz\r\nContent-Length: 0\r\n\r\n",
                target
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    })
    .await;

    let secret_token = "secret-trusted-cluster-token";
    let config = RegistryClientConfig {
        default_registry: server_initial.url(),
        user_agent: "chaos-auth-retain-test".into(),
        auth_token: Some(secret_token.into()),
        // Explicitly trust server_dest host and port!
        trusted_hosts: HashSet::from([
            server_initial.host_key(),
            server_dest.host_key(),
            "127.0.0.1".into(),
        ]),
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}initial/trusted.tgz", server_initial.url());
    let bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();
    assert_eq!(bytes, b"trusted body");

    // Verify Server Dest (trusted) DID retain the Authorization header
    {
        let reqs_dest = server_dest.received_requests.lock().await;
        assert_eq!(reqs_dest.len(), 1);
        assert!(
            reqs_dest[0].to_lowercase().contains(&format!("authorization: bearer {secret_token}").to_lowercase()),
            "Redirect to trusted target must retain Authorization header! Got: {}",
            reqs_dest[0]
        );
    }

    server_initial.stop();
    server_dest.stop();
}

// =========================================================================
// 6. Circuit Breaker Transition Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_circuit_breaker_transitions_open_fast_fail_and_half_open_recovery() {
    let mode = Arc::new(AtomicUsize::new(0)); // 0: fail with 500, 1: succeed with 200
    let mode_clone = mode.clone();
    let mock_json = r#"{"name":"circuit-recovering-pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;

    let server = RawChaosServer::start(move |mut stream, _, _| {
        let m = mode_clone.clone();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            if m.load(Ordering::SeqCst) == 0 {
                // Fail with HTTP 500
                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 17\r\n\r\nserver down error";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
            } else {
                // Recover with HTTP 200 OK
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    mock_json.len(),
                    mock_json
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
            }
        }
    })
    .await;

    let host = server.host_key();
    let reset_timeout = Duration::from_millis(150);

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-circuit-breaker-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 0,
        circuit_breaker_enabled: true,
        circuit_breaker_failure_threshold: 3,
        circuit_breaker_reset_timeout: reset_timeout,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Initial state: Closed
    assert_eq!(client.circuit_state(&host).await, CircuitBreakerState::Closed);

    // 2. Accumulate failures up to threshold (3 consecutive failures)
    for i in 1..=3 {
        let res = client.get_package_metadata("circuit-recovering-pkg").await;
        assert!(res.is_err(), "Request {i} must fail with 500");
    }

    // 3. State transitions to Open
    assert_eq!(
        client.circuit_state(&host).await,
        CircuitBreakerState::Open,
        "Circuit must trip to Open after reaching failure threshold"
    );
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 3);

    // 4. Fast-fail check: Inbound request fails immediately without sending any network request
    let fast_fail_res = client.get_package_metadata("circuit-recovering-pkg").await;
    assert!(fast_fail_res.is_err());
    let err = fast_fail_res.unwrap_err();
    assert!(
        err.is_circuit_breaker_open(),
        "Expected is_circuit_breaker_open() == true, got: {err:?}"
    );
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        3,
        "Fast fail must NOT dispatch any request over the network!"
    );

    // 5. Half-Open transition: Wait for reset timeout to elapse
    tokio::time::sleep(reset_timeout + Duration::from_millis(30)).await;
    assert_eq!(
        client.circuit_state(&host).await,
        CircuitBreakerState::HalfOpen,
        "Circuit must transition to HalfOpen after reset timeout expires"
    );

    // 6. Server recovers: probe request succeeds
    mode.store(1, Ordering::SeqCst);
    let probe_res = client.get_package_metadata("circuit-recovering-pkg").await.unwrap();
    assert_eq!(probe_res.name, "circuit-recovering-pkg");
    assert_eq!(
        server.connection_count.load(Ordering::SeqCst),
        4,
        "Probe request was dispatched to server"
    );

    // 7. Successful probe closes the circuit breaker
    assert_eq!(
        client.circuit_state(&host).await,
        CircuitBreakerState::Closed,
        "Successful probe must close the circuit breaker"
    );

    // 8. Subsequent requests flow normally
    let subsequent_res = client.get_package_metadata("circuit-recovering-pkg").await.unwrap();
    assert_eq!(subsequent_res.name, "circuit-recovering-pkg");
    assert_eq!(server.connection_count.load(Ordering::SeqCst), 5);

    server.stop();
}
