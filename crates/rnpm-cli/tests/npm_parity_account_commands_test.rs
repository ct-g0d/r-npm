use std::collections::BTreeMap;
use std::net::SocketAddr;
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
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RecordedReq {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

struct TestMockServer {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub requests: Arc<Mutex<Vec<RecordedReq>>>,
}

impl Drop for TestMockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl TestMockServer {
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
                    _ = &mut rx => break,
                    res = listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            let handler_c = handler.clone();
                            let reqs_c = reqs.clone();
                            tokio::spawn(async move {
                                let mut buffer = Vec::new();
                                let mut temp = [0u8; 4096];
                                let mut header_end = None;
                                let mut content_len = 0;

                                while let Ok(n) = stream.read(&mut temp).await {
                                    if n == 0 { break; }
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

                                    let mut headers = BTreeMap::new();
                                    for line in lines {
                                        if let Some((k, v)) = line.split_once(':') {
                                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                                        }
                                    }

                                    let body = buffer[end..end + content_len].to_vec();
                                    let req = RecordedReq {
                                        method,
                                        path,
                                        headers,
                                        body,
                                    };

                                    reqs_c.lock().await.push(req.clone());

                                    let (status, resp_headers, resp_body) = handler_c(&req);
                                    let status_text = match status {
                                        200 => "OK",
                                        201 => "Created",
                                        401 => "Unauthorized",
                                        403 => "Forbidden",
                                        404 => "Not Found",
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
            shutdown: Some(tx),
            requests,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

fn isolated_rnpm(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rnpm"));
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
    cmd.env("NPM_CONFIG_UNICODE", "true");
    cmd.env("npm_config_audit", "false");
    cmd.env("npm_config_fund", "false");
    cmd
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_profile_set_malformed_get_fails_with_fetch_error_and_zero_post() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/-/npm/v1/user") {
            (200, vec![("content-type", "application/json".to_string())], b"not-json-data".to_vec())
        } else {
            (500, vec![], b"unexpected request".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    std::fs::write(
        &npmrc_path,
        format!("registry = {}\n//{}/:_authToken = dummy-token\n", server.url(), server.addr),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["profile", "set", "fullname", "Alice"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(!output.status.success(), "profile set must fail on malformed GET");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error code FETCH_ERROR"),
        "stderr must contain 'npm error code FETCH_ERROR', got:\n{stderr}"
    );
    assert!(
        stderr.contains("npm error errno FETCH_ERROR"),
        "stderr must contain 'npm error errno FETCH_ERROR', got:\n{stderr}"
    );

    // Verify zero POST requests were made
    let reqs = server.requests.lock().await;
    let post_requests: Vec<_> = reqs.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(post_requests.len(), 0, "No POST requests must be issued when GET fails");
    assert_eq!(reqs.len(), 1, "Exactly one GET request must have occurred");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_org_ls_unauthenticated_public_roster() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    // Only registry configured, NO credentials
    std::fs::write(&npmrc_path, format!("registry = {}\n", server.url())).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "org ls without credentials must succeed against public roster: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alice - owner"), "stdout must contain alice - owner: {stdout}");

    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0].header("authorization").is_none(),
        "Wire request must NOT send an Authorization header when unauthenticated"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_org_ls_encoded_password_sends_decoded_basic_auth() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    // //HOST:PORT/:username=user and //HOST:PORT/:_password=cGFzcw== (base64 of "pass")
    std::fs::write(
        &npmrc_path,
        format!(
            "registry = {}\n//{}/:username = user\n//{}/:_password = cGFzcw==\n",
            server.url(),
            server.addr,
            server.addr,
        ),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "org ls must succeed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alice - owner"));

    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].header("authorization"),
        Some("Basic dXNlcjpwYXNz"),
        "Wire request must send Basic dXNlcjpwYXNz (user:pass decoded from cGFzcw==)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_auth_scoping_path_basic_over_root_bearer() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/nested/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    // Root bearer token vs nested basic token
    std::fs::write(
        &npmrc_path,
        format!(
            "registry = {}nested/\n//{}/:_authToken = root-dummy\n//{}/nested/:_auth = dXNlcjpwYXNz\n",
            server.url(),
            server.addr,
            server.addr,
        ),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "org ls must succeed: {}", String::from_utf8_lossy(&output.stderr));
    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].header("authorization"),
        Some("Basic dXNlcjpwYXNz"),
        "Path-scoped Basic auth must take priority over root Bearer auth"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_auth_scoping_parent_path_walk() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/nested/deeper/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    // Only /nested/ path has auth, requesting /nested/deeper/
    std::fs::write(
        &npmrc_path,
        format!(
            "registry = {}nested/deeper/\n//{}/nested/:_auth = dXNlcjpwYXNz\n",
            server.url(),
            server.addr,
        ),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "org ls must succeed with parent path auth: {}", String::from_utf8_lossy(&output.stderr));
    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].header("authorization"),
        Some("Basic dXNlcjpwYXNz"),
        "Parent path scope /nested/ must match /nested/deeper/ registry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_auth_scoping_port_isolation_no_leak() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    // Token configured for portless 127.0.0.1, but server runs on explicit port
    std::fs::write(
        &npmrc_path,
        format!(
            "registry = {}\n//127.0.0.1/:_authToken = portless-dummy\n",
            server.url(),
        ),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "org ls must succeed: {}", String::from_utf8_lossy(&output.stderr));
    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0].header("authorization").is_none(),
        "Portless credential must NOT be leaked to server on different port"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_org_ls_silent_and_output_formats() {
    let server = TestMockServer::start(|req| {
        if req.method == "GET" && req.path.contains("/-/org/acme/user") {
            let body = b"{\"alice\":\"owner\",\"bob\":\"developer\"}".to_vec();
            (200, vec![("content-type", "application/json".to_string())], body)
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    std::fs::write(&npmrc_path, format!("registry = {}\n", server.url())).unwrap();

    // 1. --silent must produce completely empty stdout
    let work_dir = tmp.path().to_path_buf();
    let out_silent = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "ls", "acme", "--silent"])
            .output()
            .unwrap()
    }).await.unwrap();
    assert!(out_silent.status.success());
    assert!(
        out_silent.stdout.is_empty(),
        "--silent stdout must be completely empty, got: {}",
        String::from_utf8_lossy(&out_silent.stdout)
    );

    // 2. --json must produce valid JSON
    let work_dir2 = tmp.path().to_path_buf();
    let out_json = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir2)
            .args(["org", "ls", "acme", "--json"])
            .output()
            .unwrap()
    }).await.unwrap();
    assert!(out_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&out_json.stdout).unwrap();
    assert_eq!(json_val["alice"], "owner");
    assert_eq!(json_val["bob"], "developer");

    // 3. --parseable must produce tab-delimited output
    let work_dir3 = tmp.path().to_path_buf();
    let out_parse = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir3)
            .args(["org", "ls", "acme", "--parseable"])
            .output()
            .unwrap()
    }).await.unwrap();
    assert!(out_parse.status.success());
    let parse_str = String::from_utf8_lossy(&out_parse.stdout);
    assert!(parse_str.contains("alice\towner"), "Must contain tab delimiter: {parse_str}");
    assert!(parse_str.contains("bob\tdeveloper"), "Must contain tab delimiter: {parse_str}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_org_rm_delete200_then_get403_fails_with_no_success() {
    let server = TestMockServer::start(|req| {
        if req.method == "DELETE" && req.path.contains("/-/org/acme/user") {
            (200, vec![("content-type", "application/json".to_string())], b"{\"user\":\"alice\"}".to_vec())
        } else if req.method == "GET" && req.path.contains("/-/org/acme/user") {
            (403, vec![("content-type", "application/json".to_string())], b"{\"message\":\"forbidden roster\"}".to_vec())
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    std::fs::write(
        &npmrc_path,
        format!("registry = {}\n//{}/:_authToken = dummy\n", server.url(), server.addr),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["org", "rm", "acme", "alice"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(!output.status.success(), "org rm must fail when follow-up GET is 403");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.is_empty(), "stdout must not contain false success, got: {stdout}");
    assert!(stderr.contains("npm error code E403"), "stderr must contain E403, got: {stderr}");

    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "DELETE");
    assert_eq!(reqs[1].method, "GET");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_team_create_body_and_stdout() {
    let server = TestMockServer::start(|req| {
        if req.method == "PUT" && req.path.contains("/-/org/acme/team") {
            (201, vec![("content-type", "application/json".to_string())], b"{\"team\":\"dev\"}".to_vec())
        } else {
            (404, vec![], b"not found".to_vec())
        }
    }).await;

    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    std::fs::write(
        &npmrc_path,
        format!("registry = {}\n//{}/:_authToken = dummy\n", server.url(), server.addr),
    ).unwrap();

    let work_dir = tmp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        isolated_rnpm(&work_dir)
            .args(["team", "create", "@acme:dev"])
            .output()
            .unwrap()
    }).await.unwrap();

    assert!(output.status.success(), "team create must succeed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("+@acme:dev"), "stdout must match npm format +@acme:dev: {stdout}");

    let reqs = server.requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "PUT");
    let json_body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(json_body, serde_json::json!({"name": "dev"}));
}
