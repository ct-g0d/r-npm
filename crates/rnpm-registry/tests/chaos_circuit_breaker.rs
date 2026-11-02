use rnpm_registry::{CircuitBreakerState, RegistryClient, RegistryClientConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// Low-level TCP Mock Server for granular chaos and fault injection.
struct ChaosTcpServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl ChaosTcpServer {
    async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(tokio::net::TcpStream, usize) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let conn_counter = Arc::new(AtomicUsize::new(0));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    res = listener.accept() => {
                        if let Ok((stream, _)) = res {
                            let h = handler.clone();
                            let conn_idx = conn_counter.fetch_add(1, Ordering::SeqCst);
                            tokio::spawn(async move {
                                h(stream, conn_idx).await;
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown: shutdown_tx,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

/// Standard Mock HTTP Server for HTTP-level state testing.
struct MockHttpServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    request_counter: Arc<AtomicUsize>,
}

impl MockHttpServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, usize) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let request_counter = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let req_cnt = request_counter.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let h = handler.clone();
                            let cnt = req_cnt.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_idx = cnt.fetch_add(1, Ordering::SeqCst);
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = h(&req_str, req_idx);

                                    let status_text = match status {
                                        200 => "OK",
                                        429 => "Too Many Requests",
                                        503 => "Service Unavailable",
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
            shutdown: shutdown_tx,
            request_counter,
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
// 1. 503 Flapping & Circuit Breaker State Machine Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_503_flapping_circuit_breaker_state_transitions() {
    let mode_503 = Arc::new(AtomicBool::new(true));
    let mode_clone = mode_503.clone();

    let server = MockHttpServer::start(move |_req, _idx| {
        if mode_clone.load(Ordering::SeqCst) {
            (503, vec![("Retry-After", "0".into())], b"Service Flapping 503".to_vec())
        } else {
            let body = r#"{"name":"recovered-pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;
            (200, vec![("Content-Type", "application/json".into())], body.as_bytes().to_vec())
        }
    }).await;

    let host_key = server.addr.to_string();

    // Circuit breaker config: trip on 2 consecutive failures, 120ms cooldown
    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-circuit-breaker-test".into(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        circuit_breaker_enabled: true,
        circuit_breaker_failure_threshold: 2,
        circuit_breaker_reset_timeout: Duration::from_millis(120),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    // 1. Initial State: Closed
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Closed);

    // 2. Failure #1: 503 Service Unavailable -> State remains Closed
    let res1 = client.get_package_metadata("pkg-a").await;
    assert!(res1.is_err());
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Closed);
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 1);

    // 3. Failure #2: 503 Service Unavailable -> consecutive failures == threshold (2) -> Trips to Open
    let res2 = client.get_package_metadata("pkg-b").await;
    assert!(res2.is_err());
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Open);
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 2);

    // 4. Fast Failure in Open state: Requests fail fast WITHOUT network roundtrips
    for i in 0..5 {
        let res_fast = client.get_package_metadata(&format!("pkg-fast-{i}")).await;
        assert!(res_fast.is_err());
        let err = res_fast.unwrap_err();
        assert!(err.is_circuit_breaker_open(), "Expected circuit breaker open error");
    }
    // Verify server received ZERO additional requests during the Open period
    assert_eq!(
        server.request_counter.load(Ordering::SeqCst),
        2,
        "Circuit breaker Open state MUST fail fast with 0 network calls"
    );

    // 5. Cooldown: Wait for reset timeout (120ms) to elapse
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Transition from Open -> HalfOpen
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::HalfOpen);

    // 6. HalfOpen Flap-Back Test: If probe fails, immediately trips back to Open
    let res_probe_fail = client.get_package_metadata("probe-fail").await;
    assert!(res_probe_fail.is_err());
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Open);
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 3);

    // Another fast-fail check
    let res_fast2 = client.get_package_metadata("fast-fail-after-flap").await;
    assert!(res_fast2.unwrap_err().is_circuit_breaker_open());
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 3);

    // 7. Second Cooldown: Wait for cooldown again
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::HalfOpen);

    // Server recovers to healthy
    mode_503.store(false, Ordering::SeqCst);

    // 8. Probe Success in HalfOpen: Transitions back to Closed
    let meta = client.get_package_metadata("recovered-pkg").await.unwrap();
    assert_eq!(meta.name, "recovered-pkg");
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Closed);
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 4);

    // 9. Subsequent requests succeed cleanly in Closed state
    let meta2 = client.get_package_metadata("recovered-pkg").await.unwrap();
    assert_eq!(meta2.name, "recovered-pkg");
    assert_eq!(client.circuit_state(&host_key).await, CircuitBreakerState::Closed);
    assert_eq!(server.request_counter.load(Ordering::SeqCst), 5);

    server.stop();
}

// =========================================================================
// 2. Premature Connection Abort & Transient Recovery Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_premature_connection_abort_truncated_tarball_recovery() {
    let full_payload = b"TARBALL_BINARY_STREAM_FULL_VERIFIED_PAYLOAD_1234567890_XYZ";
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    // Chaos server:
    // Conn 0: sends HTTP 200 OK + Content-Length for full payload, but sends only 12 bytes and drops connection (RST/FIN)
    // Conn 1: sends full complete response
    let server = ChaosTcpServer::start(move |mut stream, conn_idx| {
        let attempts_inner = attempts_clone.clone();
        let payload = full_payload.to_vec();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            attempts_inner.fetch_add(1, Ordering::SeqCst);

            if conn_idx == 0 {
                // Prematurely truncated response
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload[..12]).await; // truncated!
                let _ = stream.flush().await;
                // Abruptly sever connection mid-stream
                drop(stream);
            } else {
                // Successful retry
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload).await;
                let _ = stream.flush().await;
            }
        }
    }).await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-truncation-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(20),
        max_retry_backoff: Duration::from_millis(80),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let start = Instant::now();
    let tarball_url = format!("{}tarball.tgz", server.url());
    let downloaded_bytes = client.download_tarball_bytes(&tarball_url).await.unwrap();

    assert_eq!(downloaded_bytes, full_payload);
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "Client must have retried after premature disconnect");
    assert!(start.elapsed() >= Duration::from_millis(20), "Client must have observed exponential backoff");

    server.stop();
}

#[tokio::test]
async fn test_chaos_premature_connection_abort_truncated_metadata_recovery() {
    let mock_json = r#"{"name":"resilient-pkg","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"resilient-pkg","version":"1.0.0","dist":{"tarball":"pkg.tgz","integrity":"sha512-test"}}}}"#;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    // Server truncates JSON on conn 0, then provides complete JSON on conn 1
    let server = ChaosTcpServer::start(move |mut stream, conn_idx| {
        let attempts_inner = attempts_clone.clone();
        let json_bytes = mock_json.as_bytes().to_vec();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            attempts_inner.fetch_add(1, Ordering::SeqCst);

            if conn_idx == 0 {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                    json_bytes.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                // Send only half of the json body, cutting off abruptly
                let _ = stream.write_all(&json_bytes[..25]).await;
                let _ = stream.flush().await;
                drop(stream);
            } else {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                    json_bytes.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&json_bytes).await;
                let _ = stream.flush().await;
            }
        }
    }).await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-meta-truncation-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(20),
        max_retry_backoff: Duration::from_millis(80),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let meta = client.get_package_metadata("resilient-pkg").await.unwrap();
    assert_eq!(meta.name, "resilient-pkg");
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "Metadata request must recover cleanly from body truncation");

    server.stop();
}

#[tokio::test]
async fn test_chaos_premature_connection_abort_download_to_file_recovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_file = temp_dir.path().join("resilient-download.tgz");
    let full_content = b"STREAMING_TO_FILE_CONTENT_LONG_STREAM_1234567890_ABCDEFGHIJ";

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    let server = ChaosTcpServer::start(move |mut stream, conn_idx| {
        let attempts_inner = attempts_clone.clone();
        let payload = full_content.to_vec();
        async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            attempts_inner.fetch_add(1, Ordering::SeqCst);

            if conn_idx == 0 {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&payload[..15]).await;
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
    }).await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-file-truncation-test".into(),
        timeout: Duration::from_secs(3),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(20),
        max_retry_backoff: Duration::from_millis(80),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let tarball_url = format!("{}stream-file.tgz", server.url());
    let written = client.download_tarball_to_file(&tarball_url, &dest_file).await.unwrap();
    assert_eq!(written, full_content.len() as u64);

    let on_disk = tokio::fs::read(&dest_file).await.unwrap();
    assert_eq!(on_disk, full_content);
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "File streaming must recover cleanly from mid-stream abort");

    server.stop();
}

// =========================================================================
// 3. HTTP 429 Rate Limiting with Retry-After Header Parsing Tests
// =========================================================================

#[tokio::test]
async fn test_chaos_429_rate_limit_retry_after_parsing_and_delayed_recovery() {
    let mock_json = r#"{"name":"rate-limited-pkg","dist-tags":{"latest":"1.0.0"},"versions":{}}"#;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    let server = MockHttpServer::start(move |_req, _idx| {
        let attempt = attempts_clone.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            // First attempt: return HTTP 429 with 1 second Retry-After
            (429, vec![("Retry-After", "1".into())], b"Rate limited. Please wait 1 second.".to_vec())
        } else {
            // Second attempt: succeeds
            (200, vec![("Content-Type", "application/json".into())], mock_json.as_bytes().to_vec())
        }
    }).await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-test".into(),
        timeout: Duration::from_secs(5),
        max_retries: 2,
        initial_retry_backoff: Duration::from_millis(10),
        max_retry_backoff: Duration::from_secs(3), // Budget allows 1s delay
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let start = Instant::now();
    let meta = client.get_package_metadata("rate-limited-pkg").await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(meta.name, "rate-limited-pkg");
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "Client should have retried after 429");
    assert!(
        elapsed >= Duration::from_millis(900),
        "Client must respect the 1s Retry-After header delay; elapsed was: {:?}",
        elapsed
    );

    server.stop();
}

#[tokio::test]
async fn test_chaos_429_rate_limit_exceeds_budget_fails_fast() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = attempts.clone();

    // Server returns 429 with Retry-After: 60 (seconds)
    let server = MockHttpServer::start(move |_req, _idx| {
        attempts_clone.fetch_add(1, Ordering::SeqCst);
        (429, vec![("Retry-After", "60".into())], b"Rate limit: 60s cooldown".to_vec())
    }).await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        user_agent: "chaos-429-budget-test".into(),
        timeout: Duration::from_secs(2),
        max_retries: 3,
        max_retry_backoff: Duration::from_secs(2), // 60s exceeds budget of 2s
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let start = Instant::now();
    let res = client.get_package_metadata("over-budget-pkg").await;
    let elapsed = start.elapsed();

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_after(), Some(60));
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "Must NOT retry when Retry-After exceeds budget");
    assert!(elapsed < Duration::from_millis(500), "Must fail fast immediately");

    server.stop();
}
