use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct RecordedReq {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedReq {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

struct TestMockRegistry {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    pub requests: Arc<Mutex<Vec<RecordedReq>>>,
}

impl TestMockRegistry {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedReq) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = requests.clone();
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
                                    let req = RecordedReq {
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
            requests,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

fn rnpm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rnpm"))
}

fn isolated_rnpm(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(rnpm_bin());
    let fake_home = dir.join(".fake_home");
    let fake_appdata = fake_home.join("AppData").join("Roaming");
    let fake_localappdata = fake_home.join("AppData").join("Local");
    let fake_global = dir.join(".fake_global");
    let _ = std::fs::create_dir_all(&fake_home);
    let _ = std::fs::create_dir_all(&fake_appdata);
    let _ = std::fs::create_dir_all(&fake_localappdata);
    let _ = std::fs::create_dir_all(&fake_global);

    cmd.current_dir(dir);
    cmd.env("USERPROFILE", &fake_home);
    cmd.env("HOME", &fake_home);
    cmd.env("APPDATA", &fake_appdata);
    cmd.env("LOCALAPPDATA", &fake_localappdata);
    cmd.env("PREFIX", &fake_global);
    cmd.env("NPM_CONFIG_PREFIX", &fake_global);
    cmd.env("NPM_CONFIG_USERCONFIG", fake_home.join(".npmrc"));
    cmd.env("NPM_CONFIG_GLOBALCONFIG", fake_global.join("etc").join("npmrc"));
    cmd.env("NPM_CONFIG_CACHE", fake_home.join(".npm-cache"));
    cmd
}

#[test]
fn test_cli_publish_dry_run() {
    let tmp = tempdir().unwrap();
    let pkg_dir = tmp.path();

    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "dry-run-pkg",
            "version": "1.2.3",
            "description": "Test dry run publication",
            "main": "index.js"
        }))
        .unwrap(),
    )
    .unwrap();

    std::fs::write(pkg_dir.join("index.js"), "console.log('hello');").unwrap();

    // 1. Text notices output
    let output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--dry-run")
        .output()
        .expect("failed to run rnpm publish");

    assert!(
        output.status.success(),
        "Dry run publish must succeed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("+ dry-run-pkg@1.2.3"),
        "Expected package name and version in stdout: {stdout}"
    );
    assert!(
        stderr.contains("npm notice package: dry-run-pkg@1.2.3"),
        "Expected package notice: {stderr}"
    );
    assert!(
        stderr.contains("npm notice shasum:"),
        "Expected shasum notice: {stderr}"
    );
    assert!(
        stderr.contains("npm notice integrity:"),
        "Expected integrity notice: {stderr}"
    );

    // 2. JSON mode output
    let json_output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--dry-run")
        .arg("--json")
        .output()
        .expect("failed to run rnpm publish --json");

    assert!(json_output.status.success());
    let json_str = String::from_utf8_lossy(&json_output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("Valid JSON");
    assert_eq!(parsed["id"], "dry-run-pkg@1.2.3");
    assert_eq!(parsed["name"], "dry-run-pkg");
    assert_eq!(parsed["version"], "1.2.3");
    assert_eq!(parsed["dryRun"], true);
    assert!(parsed["shasum"].is_string());
    assert!(parsed["integrity"].is_string());
}

#[test]
fn test_cli_login_persists_registry_token_without_echoing_secret() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    let output = isolated_rnpm(&project)
        .args([
            "login",
            "--registry",
            "https://registry.example.test/",
            "--scope",
            "@acme",
        ])
        .env("USERPROFILE", &home)
        .env("HOME", &home)
        .env("NPM_CONFIG_USERCONFIG", home.join(".npmrc"))
        .env("NPM_TOKEN", "secret-login-token")
        .output()
        .expect("failed to run rnpm login");

    assert!(
        output.status.success(),
        "login failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let npmrc = std::fs::read_to_string(home.join(".npmrc")).unwrap();
    assert!(npmrc.contains("//registry.example.test/:_authToken=secret-login-token"));
    assert!(npmrc.contains("@acme:registry=https://registry.example.test/"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-login-token"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-login-token"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_publish_lifecycle_hooks_sequence() {
    let server = TestMockRegistry::start(|req| {
        if req.method == "PUT" && req.path == "/lifecycle-test-pkg" {
            (
                200,
                vec![("Content-Type", "application/json".into())],
                b"{\"ok\":true}".to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let server_url = server.url();
    let tmp = tempdir().unwrap();
    let pkg_dir = tmp.path();

    // Setup node script that appends its argument to lifecycle.log
    let logger_js = "require('fs').appendFileSync('lifecycle.log', process.argv[2] + '\\n');";
    std::fs::write(pkg_dir.join("logger.js"), logger_js).unwrap();

    let manifest = serde_json::json!({
        "name": "lifecycle-test-pkg",
        "version": "1.0.0",
        "scripts": {
            "prepublishOnly": "node logger.js prepublishOnly",
            "prepack": "node logger.js prepack",
            "postpack": "node logger.js postpack",
            "publish": "node logger.js publish",
            "postpublish": "node logger.js postpublish"
        }
    });

    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Create .npmrc with auth token
    let host = server.addr.to_string();
    let npmrc_content = format!("//{host}/:_authToken=secret-lifecycle-token\n");
    std::fs::write(pkg_dir.join(".npmrc"), npmrc_content).unwrap();

    let output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .expect("failed to run rnpm publish");

    assert!(
        output.status.success(),
        "Publish must succeed: stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_content =
        std::fs::read_to_string(pkg_dir.join("lifecycle.log")).expect("lifecycle.log must exist");
    let recorded_lines: Vec<&str> = log_content.lines().collect();

    assert_eq!(
        recorded_lines,
        vec![
            "prepublishOnly",
            "prepack",
            "postpack",
            "publish",
            "postpublish"
        ],
        "Lifecycle hooks must execute in exact npm sequence!"
    );

    // Verify PUT request reached mock server
    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "PUT");
    assert_eq!(reqs[0].path, "/lifecycle-test-pkg");
    assert_eq!(
        reqs[0].header("authorization"),
        Some("Bearer secret-lifecycle-token")
    );
    drop(reqs);

    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_publish_prepack_failure_halts_before_packaging() {
    let server = TestMockRegistry::start(|_| (200, vec![], b"{\"ok\":true}".to_vec())).await;

    let tmp = tempdir().unwrap();
    let pkg_dir = tmp.path();

    let manifest = serde_json::json!({
        "name": "fail-pkg",
        "version": "1.0.0",
        "scripts": {
            "prepack": "node -e \"process.exit(42)\""
        }
    });
    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    let output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--registry")
        .arg(server.url())
        .output()
        .expect("failed to execute publish");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(42));

    // Verify server received 0 PUT requests
    let reqs = server.requests.lock().await;
    assert_eq!(
        reqs.len(),
        0,
        "No network request should occur if prepack fails"
    );
    drop(reqs);

    server.stop();
}

#[test]
fn test_cli_publish_ignore_scripts_bypasses_failing_hooks() {
    let tmp = tempdir().unwrap();
    let pkg_dir = tmp.path();

    let manifest = serde_json::json!({
        "name": "ignore-scripts-pkg",
        "version": "1.0.0",
        "scripts": {
            "prepublishOnly": "node -e \"process.exit(1)\"",
            "prepack": "node -e \"process.exit(1)\""
        }
    });
    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    let output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--dry-run")
        .arg("--ignore-scripts")
        .output()
        .expect("failed to execute publish");

    assert!(
        output.status.success(),
        "ignore-scripts must bypass failing lifecycle scripts"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("+ ignore-scripts-pkg@1.0.0"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_publish_http_put_payload_headers_and_auth() {
    let server = TestMockRegistry::start(|req| {
        if req.method == "PUT" && req.path == "/@cool%2fawesome-lib" {
            (
                200,
                vec![("Content-Type", "application/json".into())],
                b"{\"ok\":true}".to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let server_url = server.url();
    let tmp = tempdir().unwrap();
    let pkg_dir = tmp.path();

    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "@cool/awesome-lib",
            "version": "3.5.0",
            "description": "An awesome scoped library",
            "main": "lib.js"
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("lib.js"), "module.exports = 42;").unwrap();

    let host = server.addr.to_string();
    std::fs::write(
        pkg_dir.join(".npmrc"),
        format!("//{host}/:_authToken=npm_super_token_999\n"),
    )
    .unwrap();

    let output = isolated_rnpm(pkg_dir)
        .arg("publish")
        .arg("--registry")
        .arg(&server_url)
        .arg("--tag")
        .arg("rc")
        .arg("--access=public")
        .arg("--otp")
        .arg("654321")
        .output()
        .expect("failed to run publish");

    assert!(
        output.status.success(),
        "Publish must succeed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(req.method, "PUT");
    assert_eq!(req.path, "/@cool%2fawesome-lib");
    assert_eq!(
        req.header("authorization"),
        Some("Bearer npm_super_token_999")
    );
    assert_eq!(req.header("npm-otp"), Some("654321"));
    assert_eq!(req.header("content-type"), Some("application/json"));

    let doc = req.json();
    assert_eq!(doc["_id"], "@cool/awesome-lib");
    assert_eq!(doc["name"], "@cool/awesome-lib");
    assert_eq!(doc["description"], "An awesome scoped library");
    assert_eq!(doc["dist-tags"]["rc"], "3.5.0");
    assert_eq!(doc["access"], "public");

    let version_entry = &doc["versions"]["3.5.0"];
    assert_eq!(version_entry["name"], "@cool/awesome-lib");
    assert_eq!(version_entry["version"], "3.5.0");
    assert!(version_entry["dist"]["shasum"].is_string());
    assert!(version_entry["dist"]["integrity"]
        .as_str()
        .unwrap()
        .starts_with("sha512-"));
    assert_eq!(
        version_entry["dist"]["tarball"],
        format!("{server_url}@cool%2fawesome-lib/-/cool-awesome-lib-3.5.0.tgz")
    );

    let attachment = &doc["_attachments"]["cool-awesome-lib-3.5.0.tgz"];
    assert_eq!(attachment["content_type"], "application/octet-stream");
    assert!(attachment["data"].as_str().unwrap().len() > 10);
    assert!(attachment["shasum"].is_string());
    assert!(attachment["integrity"]
        .as_str()
        .unwrap()
        .starts_with("sha512-"));
    drop(reqs);

    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_publish_error_codes_diagnostics() {
    let server = TestMockRegistry::start(|req| {
        if req.path == "/conflict-pkg" {
            (
                409,
                vec![],
                b"cannot publish over existing version".to_vec(),
            )
        } else if req.path == "/unauth-pkg" {
            (401, vec![], b"authorization required".to_vec())
        } else if req.path == "/forbidden-pkg" {
            (403, vec![], b"user does not have permission".to_vec())
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let server_url = server.url();
    let host = server.addr.to_string();

    // 1. Conflict 409 -> EPUBLISHCONFLICT
    let tmp1 = tempdir().unwrap();
    std::fs::write(
        tmp1.path().join("package.json"),
        serde_json::to_string(&serde_json::json!({ "name": "conflict-pkg", "version": "1.0.0" }))
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp1.path().join(".npmrc"),
        format!("//{host}/:_authToken=tok\n"),
    )
    .unwrap();

    let out1 = isolated_rnpm(tmp1.path())
        .arg("publish")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(!out1.status.success());
    let err1 = String::from_utf8_lossy(&out1.stderr);
    assert!(
        err1.contains("npm error code EPUBLISHCONFLICT"),
        "Expected EPUBLISHCONFLICT in: {err1}"
    );
    assert!(err1.contains("Cannot publish over existing version."));

    // 2. Unauthorized 401 -> ENEEDAUTH
    let tmp2 = tempdir().unwrap();
    std::fs::write(
        tmp2.path().join("package.json"),
        serde_json::to_string(&serde_json::json!({ "name": "unauth-pkg", "version": "1.0.0" }))
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp2.path().join(".npmrc"),
        format!("//{host}/:_authToken=bad-tok\n"),
    )
    .unwrap();

    let out2 = isolated_rnpm(tmp2.path())
        .arg("publish")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(!out2.status.success());
    let err2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        err2.contains("npm error code ENEEDAUTH"),
        "Expected ENEEDAUTH in: {err2}"
    );

    // 3. Forbidden 403 -> E403
    let tmp3 = tempdir().unwrap();
    std::fs::write(
        tmp3.path().join("package.json"),
        serde_json::to_string(&serde_json::json!({ "name": "forbidden-pkg", "version": "1.0.0" }))
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp3.path().join(".npmrc"),
        format!("//{host}/:_authToken=tok\n"),
    )
    .unwrap();

    let out3 = isolated_rnpm(tmp3.path())
        .arg("publish")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(!out3.status.success());
    let err3 = String::from_utf8_lossy(&out3.stderr);
    assert!(
        err3.contains("npm error code E403"),
        "Expected E403 in: {err3}"
    );

    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_whoami_and_ping() {
    let server = TestMockRegistry::start(|req| {
        if req.path == "/-/whoami" {
            if req.header("authorization") == Some("Bearer test-token-whoami") {
                (
                    200,
                    vec![("Content-Type", "application/json".into())],
                    b"{\"username\":\"ferris_rustacean\"}".to_vec(),
                )
            } else {
                (401, vec![], b"unauthorized".to_vec())
            }
        } else if req.path == "/-/ping" {
            (
                200,
                vec![("Content-Type", "application/json".into())],
                b"{}".to_vec(),
            )
        } else {
            (404, vec![], b"Not Found".to_vec())
        }
    })
    .await;

    let server_url = server.url();
    let host = server.addr.to_string();

    let tmp = tempdir().unwrap();
    std::fs::write(
        tmp.path().join(".npmrc"),
        format!("//{host}/:_authToken=test-token-whoami\n"),
    )
    .unwrap();

    // 1. whoami text
    let whoami_out = isolated_rnpm(tmp.path())
        .arg("whoami")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(
        whoami_out.status.success(),
        "whoami must succeed: {}",
        String::from_utf8_lossy(&whoami_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&whoami_out.stdout);
    assert_eq!(stdout.trim(), "ferris_rustacean");

    // 2. whoami JSON
    let whoami_json = isolated_rnpm(tmp.path())
        .arg("whoami")
        .arg("--registry")
        .arg(&server_url)
        .arg("--json")
        .output()
        .unwrap();

    assert!(whoami_json.status.success());
    let json_str = String::from_utf8_lossy(&whoami_json.stdout);
    assert_eq!(json_str.trim(), "\"ferris_rustacean\"");

    // 3. whoami without token fails with ENEEDAUTH
    let empty_dir = tempdir().unwrap();
    let unauth_whoami = isolated_rnpm(empty_dir.path())
        .arg("whoami")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(!unauth_whoami.status.success());
    let unauth_err = String::from_utf8_lossy(&unauth_whoami.stderr);
    assert!(
        unauth_err.contains("npm error code ENEEDAUTH"),
        "Missing token must emit ENEEDAUTH: {unauth_err}"
    );

    // 4. ping
    let ping_out = isolated_rnpm(tmp.path())
        .arg("ping")
        .arg("--registry")
        .arg(&server_url)
        .output()
        .unwrap();

    assert!(ping_out.status.success(), "ping must succeed");
    let ping_err = String::from_utf8_lossy(&ping_out.stderr);
    assert!(ping_err.contains("npm notice PING"));
    assert!(ping_err.contains("npm notice PONG"));

    // 5. ping JSON
    let ping_json = isolated_rnpm(tmp.path())
        .arg("ping")
        .arg("--registry")
        .arg(&server_url)
        .arg("--json")
        .output()
        .unwrap();

    assert!(ping_json.status.success());
    let ping_json_str = String::from_utf8_lossy(&ping_json.stdout);
    let ping_val: serde_json::Value = serde_json::from_str(&ping_json_str).unwrap();
    assert_eq!(ping_val["registry"], server_url);
    assert!(ping_val["time"].is_number());

    server.stop();
}

#[test]
fn test_cli_auth_helpers_login_and_logout() {
    let tmp = tempdir().unwrap();
    let home = tmp.path().join("home");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    // 1. Non-interactive login requires an explicit credential source.
    let login_out = isolated_rnpm(&project)
        .arg("login")
        .env("USERPROFILE", &home)
        .env("HOME", &home)
        .env("NPM_CONFIG_USERCONFIG", home.join(".npmrc"))
        .output()
        .unwrap();

    assert!(!login_out.status.success());
    let login_err = String::from_utf8_lossy(&login_out.stderr);
    assert!(login_err.contains("npm error code ENEEDAUTH"));

    // 2. logout with existing token removes token from .npmrc
    let local_npmrc = project.join(".npmrc");
    std::fs::write(
        &local_npmrc,
        "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_sample123\n",
    )
    .unwrap();

    let logout_out = isolated_rnpm(&project)
        .arg("logout")
        .env("USERPROFILE", &home)
        .env("HOME", &home)
        .env("NPM_CONFIG_USERCONFIG", home.join(".npmrc"))
        .output()
        .unwrap();

    assert!(logout_out.status.success());
    let logout_str = String::from_utf8_lossy(&logout_out.stdout);
    assert!(logout_str.contains("successfully logged out"));

    let remaining_content = std::fs::read_to_string(&local_npmrc).unwrap();
    assert!(!remaining_content.contains("npm_sample123"));
}
