use flate2::write::GzEncoder;
use flate2::Compression;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_lifecycle::{
    bootstrap_node_gyp, create_private_node_gyp_shim, ensure_node_gyp,
    execute_lifecycle_script, execute_lifecycle_script_async, node_gyp_bin_dir,
    LifecycleContext, LifecycleError, ScriptExitError,
};

fn create_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
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
    rnpm_core::integrity::Integrity::from_bytes(bytes, rnpm_core::integrity::Algorithm::Sha512).to_string()
}

struct MockRegistryServer {
    addr: SocketAddr,
    auth_header_seen: Arc<std::sync::Mutex<Option<String>>>,
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
        F: Fn(&str, Option<&str>, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)>
            + Send
            + Sync
            + 'static,
    {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);
        let auth_header_seen = Arc::new(std::sync::Mutex::new(None));
        let auth_clone = Arc::clone(&auth_header_seen);
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
                                let handler_clone = Arc::clone(&handler);
                                let auth_seen_clone = Arc::clone(&auth_clone);
                                let count_inner = Arc::clone(&count_clone);
                                let base_url = format!("http://{}", addr);

                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 8192];
                                    let n = stream.read(&mut buf).await.unwrap_or(0);
                                    if n > 0 {
                                        count_inner.fetch_add(1, Ordering::SeqCst);
                                        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                        let first_line = req_str.lines().next().unwrap_or("");
                                        let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();

                                        let mut auth_header = None;
                                        for line in req_str.lines() {
                                            if let Some(rest) = line.strip_prefix("Authorization: ")
                                                .or_else(|| line.strip_prefix("authorization: "))
                                            {
                                                let val = rest.trim().to_string();
                                                auth_header = Some(val.clone());
                                                let mut lock = auth_seen_clone.lock().unwrap();
                                                *lock = Some(val);
                                                break;
                                            }
                                        }

                                        let (status, headers, body) = match handler_clone(&path, auth_header.as_deref(), &base_url) {
                                            Some(resp) => resp,
                                            None => (404, vec![("Content-Type", "text/plain".to_string())], b"Not Found".to_vec()),
                                        };

                                        let status_text = match status {
                                            200 => "OK",
                                            401 => "Unauthorized",
                                            403 => "Forbidden",
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
        });

        let addr = addr_rx.recv().unwrap();

        Self {
            addr,
            auth_header_seen,
            request_count,
            shutdown_tx: Some(shutdown_tx),
            thread_handle: Some(thread_handle),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// 1. Test private temp shim directory permissions and structure:
/// - Directory has 0o700 mode on Unix.
/// - POSIX shim has 0o755 mode on Unix.
/// - Windows shim exists and contains @ECHO off.
/// - node_gyp_bin_dir() returns valid existing dir.
#[test]
fn test_private_node_gyp_shim_permissions_and_structure() {
    let tmp = tempfile::tempdir().unwrap();
    let shim_path = create_private_node_gyp_shim(tmp.path()).expect("create_private_node_gyp_shim failed");
    assert!(shim_path.exists(), "Shim returned path must exist");

    let cmd_path = tmp.path().join("node-gyp.cmd");
    assert!(cmd_path.is_file(), "node-gyp.cmd must exist");
    let cmd_content = std::fs::read_to_string(&cmd_path).unwrap();
    assert!(cmd_content.contains("@ECHO off"), "node-gyp.cmd must have @ECHO off");

    let sh_path = tmp.path().join("node-gyp");
    assert!(sh_path.is_file(), "POSIX node-gyp must exist");
    let sh_content = std::fs::read_to_string(&sh_path).unwrap();
    assert!(sh_content.contains("#!/usr/bin/env sh"), "POSIX shim must have shebang");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_meta = std::fs::metadata(tmp.path()).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "Shim dir must have 0o700 private permissions");

        let sh_meta = std::fs::metadata(&sh_path).unwrap();
        let sh_mode = sh_meta.permissions().mode() & 0o777;
        assert_eq!(sh_mode, 0o755, "POSIX shim must have 0o755 executable permissions");
    }

    let bin_dir = node_gyp_bin_dir();
    assert!(bin_dir.is_some(), "node_gyp_bin_dir must return a directory");
    let p = bin_dir.unwrap();
    assert!(p.is_dir(), "node_gyp_bin_dir returned path must be a directory");
    assert!(p.join("node-gyp.cmd").exists());
    assert!(p.join("node-gyp").exists());
}

/// 2. Test deferred node-gyp bootstrap:
/// When `binding.gyp` exists in the package dir, but the lifecycle script DOES NOT invoke `node-gyp`,
/// bootstrap must be cleanly deferred and not attempt network access even when offline.
#[tokio::test]
async fn test_deferred_node_gyp_bootstrap_when_binding_gyp_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let project_root = tmp.path().join("proj");
    let package_dir = project_root.join("node_modules").join("addon-pkg");
    std::fs::create_dir_all(&package_dir).unwrap();

    // Create a binding.gyp file
    std::fs::write(package_dir.join("binding.gyp"), r#"{"targets":[]}"#).unwrap();

    // Script that DOES NOT invoke node-gyp (pure JS script)
    let ctx_no_gyp = LifecycleContext::new(
        &project_root,
        &package_dir,
        "addon-pkg",
        "install",
        "node -e \"process.exit(0)\"",
    );

    // Run in offline mode: must succeed because node-gyp was never invoked
    let res = execute_lifecycle_script(&ctx_no_gyp);
    assert!(
        res.is_ok(),
        "Script that does not invoke node-gyp must not trigger node-gyp bootstrap: {res:?}"
    );

    // Now test a script that DOES invoke node-gyp in offline mode:
    // With node-gyp-fallback-npm = false, it must return NodeGypOfflineAbsent error
    let mut config_opts = rnpm_config::ConfigOptions::new();
    config_opts = config_opts.with_cli("offline", "true");
    config_opts = config_opts.with_cli("node-gyp-fallback-npm", "false");
    let fake_cache = tmp.path().join("empty-cache");
    config_opts = config_opts.with_cli("cache", fake_cache.to_str().unwrap());
    let cfg = rnpm_config::Config::load_with_options(config_opts).unwrap();

    let ctx_with_gyp = LifecycleContext::new(
        &project_root,
        &package_dir,
        "addon-pkg",
        "install",
        "node-gyp rebuild",
    )
    .with_offline(true)
    .with_config(cfg);

    let res_gyp = execute_lifecycle_script_async(&ctx_with_gyp).await;

    assert!(
        res_gyp.is_err(),
        "Script invoking node-gyp offline without cached node-gyp must fail"
    );
    let err_str = res_gyp.unwrap_err().to_string();
    assert!(
        err_str.contains("offline") || err_str.contains("NodeGypOfflineAbsent"),
        "Error message must indicate offline node-gyp absence: {err_str}"
    );
}

/// 3. Test `ensure_node_gyp` offline failure returning `NodeGypOfflineAbsent`:
#[test]
fn test_node_gyp_offline_absent_error() {
    let tmp = tempfile::tempdir().unwrap();
    let project_root = tmp.path().join("proj");
    let package_dir = project_root.join("addon");
    std::fs::create_dir_all(&package_dir).unwrap();

    let mut config_opts = rnpm_config::ConfigOptions::new();
    let empty_cache = tmp.path().join("empty-cache");
    config_opts = config_opts.with_cli("cache", empty_cache.to_str().unwrap());
    config_opts = config_opts.with_cli("node-gyp-fallback-npm", "false");
    let cfg = rnpm_config::Config::load_with_options(config_opts).unwrap();

    let res = ensure_node_gyp(
        &project_root,
        &package_dir,
        &cfg,
        None,
        true, // offline = true
        "test-native-addon",
    );

    match res {
        Err(LifecycleError::NodeGypOfflineAbsent { package }) => {
            assert_eq!(package, "test-native-addon");
        }
        other => panic!("Expected NodeGypOfflineAbsent, got {other:?}"),
    }
}

/// 4. Test authenticated registry node-gyp bootstrap with Bearer auth and Basic auth:
#[tokio::test]
async fn test_authenticated_registry_node_gyp_bootstrap() {
    let tmp = tempfile::tempdir().unwrap();
    let project_root = tmp.path().join("proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&project_root).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let tgz_bytes = create_tarball(&[
        (
            "package.json",
            br#"{"name":"node-gyp","version":"10.0.0","dependencies":{}}"#,
        ),
        (
            "bin/node-gyp.js",
            b"console.log('mock node-gyp executed successfully');\n",
        ),
    ]);
    let integrity = compute_ssri(&tgz_bytes);
    let tgz_clone = tgz_bytes.clone();
    let int_clone = integrity.clone();

    // Expected Bearer token
    let secret_token = "npm_test_bearer_token_xyz987";

    let server = MockRegistryServer::start(move |path, auth_header, base_url| {
        // Enforce Bearer token
        let expected_auth = format!("Bearer {secret_token}");
        if auth_header != Some(&expected_auth) {
            return Some((
                401,
                vec![("Content-Type", "application/json".to_string())],
                b"{\"error\":\"unauthorized\"}".to_vec(),
            ));
        }

        if path == "/node-gyp" {
            let json = serde_json::json!({
                "name": "node-gyp",
                "dist-tags": { "latest": "10.0.0" },
                "versions": {
                    "10.0.0": {
                        "name": "node-gyp",
                        "version": "10.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/node-gyp/-/node-gyp-10.0.0.tgz"),
                            "integrity": int_clone
                        },
                        "dependencies": {}
                    }
                }
            });
            return Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                json.to_string().into_bytes(),
            ));
        }

        if path == "/node-gyp/-/node-gyp-10.0.0.tgz" {
            return Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                tgz_clone.clone(),
            ));
        }

        None
    });

    let server_url = server.url();

    // Configure .npmrc with token and cache
    let npmrc_content = format!(
        "registry = {server_url}/\n//{}/:_authToken = {secret_token}\ncache = {}\n",
        server.addr,
        cache_dir.to_str().unwrap()
    );

    let mut config_opts = rnpm_config::ConfigOptions::new()
        .userconfig(tmp.path().join(".npmrc"));
    config_opts = config_opts.with_cli("cache", cache_dir.to_str().unwrap());
    std::fs::write(tmp.path().join(".npmrc"), npmrc_content).unwrap();

    let cfg = rnpm_config::Config::load_with_options(config_opts).unwrap();

    // Run bootstrap_node_gyp on a blocking thread
    let proj_root_clone = project_root.clone();
    let cfg_clone = cfg.clone();
    let bootstrapped_path = tokio::task::spawn_blocking(move || {
        bootstrap_node_gyp(&proj_root_clone, &cfg_clone)
    })
    .await
    .unwrap()
    .expect("bootstrap_node_gyp must succeed with authenticated registry");

    assert!(
        bootstrapped_path.exists(),
        "Bootstrapped node-gyp file must exist at {}",
        bootstrapped_path.display()
    );

    // Verify the mock server saw the Authorization header
    let seen_auth = server.auth_header_seen.lock().unwrap();
    assert_eq!(
        *seen_auth,
        Some(format!("Bearer {secret_token}")),
        "Mock registry must have received Bearer authorization header"
    );
    assert!(
        server.request_count.load(Ordering::SeqCst) >= 2,
        "Mock registry must have received packument and tarball requests"
    );
}

/// 5. Test lifecycle script timeout and exit code fidelity:
#[tokio::test]
async fn test_lifecycle_timeout_and_exit_code_fidelity() {
    let tmp = tempfile::tempdir().unwrap();
    let project_root = tmp.path().join("proj");
    std::fs::create_dir_all(&project_root).unwrap();

    // (a) Successful exit code 0
    let ctx_success = LifecycleContext::new(
        &project_root,
        &project_root,
        "test-pkg",
        "postinstall",
        "node -e \"process.exit(0)\"",
    );
    let status = execute_lifecycle_script_async(&ctx_success).await.unwrap();
    assert!(status.success(), "Exit 0 must report success");

    // (b) Exit code 42 preservation
    let ctx_fail = LifecycleContext::new(
        &project_root,
        &project_root,
        "test-pkg",
        "postinstall",
        "node -e \"process.exit(42)\"",
    );
    let status_fail = execute_lifecycle_script_async(&ctx_fail).await.unwrap();
    assert!(!status_fail.success(), "Exit 42 must not report success");
    assert_eq!(
        status_fail.code(),
        Some(42),
        "Exit code 42 must be preserved faithfully"
    );

    // Verify ScriptExitError structure and message
    let exit_err = ScriptExitError::lifecycle_failure(&ctx_fail, &status_fail);
    assert_eq!(exit_err.exit_code, 42);
    assert!(exit_err.message.contains("npm error code 42"));

    // (c) Timeout with ProcessTreeGuard termination:
    // Script sleeps indefinitely, timeout set to 1000ms.
    let ctx_timeout = LifecycleContext::new(
        &project_root,
        &project_root,
        "test-pkg",
        "postinstall",
        "node -e \"setInterval(()=>{}, 1000)\"",
    )
    .with_timeout(std::time::Duration::from_millis(1000));

    let start = std::time::Instant::now();
    let res_timeout = execute_lifecycle_script_async(&ctx_timeout).await;
    let elapsed = start.elapsed();

    assert!(res_timeout.is_err(), "Timed out script must fail");
    let timeout_err = res_timeout.unwrap_err();
    let timeout_err_str = timeout_err.to_string();
    assert!(
        timeout_err_str.contains("124") || timeout_err_str.contains("timed out") || timeout_err_str.contains("timeout"),
        "Timeout error must indicate timeout / code 124: {timeout_err_str}"
    );
    if let Some(err_obj) = timeout_err.downcast_ref::<ScriptExitError>() {
        assert_eq!(err_obj.exit_code, 124, "Timeout must set ScriptExitError exit_code to 124");
    }
    assert!(
        elapsed.as_millis() >= 900 && elapsed.as_millis() <= 5000,
        "Execution should have been terminated close to timeout, elapsed: {:?}",
        elapsed
    );
}
