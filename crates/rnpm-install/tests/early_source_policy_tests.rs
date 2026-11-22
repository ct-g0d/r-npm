use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use flate2::write::GzEncoder;
use flate2::Compression;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use rnpm_install::{InstallOptions, Installer};

struct CountingServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    pub requested_paths: Arc<Mutex<Vec<String>>>,
}

impl CountingServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)>
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let requested_paths = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = requested_paths.clone();
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
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                                    reqs_clone.lock().await.push(path.clone());

                                    let (status, headers, body) = match handler_clone(&path, &base_url) {
                                        Some(resp) => resp,
                                        None => (404, vec![("Content-Type", "text/plain".to_string())], b"Not Found".to_vec()),
                                    };

                                    let status_text = match status {
                                        200 => "OK",
                                        404 => "Not Found",
                                        500 => "Internal Server Error",
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
                                }
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            _shutdown: tx,
            requested_paths,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    async fn request_count(&self) -> usize {
        self.requested_paths.lock().await.len()
    }
}

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
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

fn setup_test_project(
    dir: &Path,
    manifest_deps: &serde_json::Value,
    npmrc_content: &str,
) {
    let pkg_json = serde_json::json!({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": manifest_deps
    });
    std::fs::write(dir.join("package.json"), pkg_json.to_string()).unwrap();
    std::fs::write(dir.join(".npmrc"), npmrc_content).unwrap();
}

static GIT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct DummyGitGuard {
    _temp_dir: tempfile::TempDir,
    sentinel_path: PathBuf,
    original_path: String,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl DummyGitGuard {
    fn new() -> Self {
        let lock = GIT_TEST_MUTEX.lock().unwrap();
        let temp_dir = tempdir().unwrap();
        let sentinel_path = temp_dir.path().join("git_invoked.txt");
        let original_path = std::env::var("PATH").unwrap_or_default();

        if cfg!(windows) {
            // Compile a small git.exe that marks invocation and exits with failure
            let marker_escaped = sentinel_path.to_str().unwrap().replace('\\', "\\\\");
            let src = format!(
                r#"fn main() {{ let _ = std::fs::write("{}", "invoked"); std::process::exit(99); }}"#,
                marker_escaped
            );
            let src_file = temp_dir.path().join("fake_git.rs");
            std::fs::write(&src_file, src).unwrap();
            let status = std::process::Command::new("rustc")
                .arg(&src_file)
                .arg("-o")
                .arg(temp_dir.path().join("git.exe"))
                .status()
                .expect("Failed to compile dummy git.exe");
            assert!(status.success(), "Failed to build dummy git.exe");
        } else {
            let sh_path = temp_dir.path().join("git");
            let script = format!(
                "#!/bin/sh\necho invoked > \"{}\"\nexit 99\n",
                sentinel_path.display()
            );
            std::fs::write(&sh_path, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&sh_path, std::fs::Permissions::from_mode(0o755));
            }
        }

        let new_path = format!("{};{}", temp_dir.path().display(), original_path);
        std::env::set_var("PATH", new_path);

        Self {
            _temp_dir: temp_dir,
            sentinel_path,
            original_path,
            _lock: lock,
        }
    }

    fn was_invoked(&self) -> bool {
        self.sentinel_path.exists()
    }
}

impl Drop for DummyGitGuard {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.original_path);
    }
}

// -----------------------------------------------------------------------------
// Test 1: allow-remote=none blocks direct manifest URL dep with ZERO HTTP requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_none_blocks_manifest_dep_zero_http_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let pkg = create_test_tarball(&[("package.json", br#"{"name":"remote-pkg","version":"1.0.0"}"#)]);
        Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let remote_url = format!("{}/remote-pkg.tgz", server.url());
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "remote-pkg": remote_url
        }),
        "allow-remote=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-remote=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "Error message should contain EALLOWREMOTE, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"remote\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    // ZERO HTTP requests must have hit the server!
    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the remote server"
    );
}

// -----------------------------------------------------------------------------
// Test 2: allow-remote=none blocks CLI argument with ZERO HTTP requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_none_blocks_cli_arg_zero_http_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let pkg = create_test_tarball(&[("package.json", br#"{"name":"cli-remote","version":"1.0.0"}"#)]);
        Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({}),
        "allow-remote=none\n",
    );

    let remote_url = format!("{}/cli-remote.tgz", server.url());
    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        packages: vec![remote_url],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-remote=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "Error message should contain EALLOWREMOTE, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"remote\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    // ZERO HTTP requests must have hit the server!
    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the remote server"
    );
}

// -----------------------------------------------------------------------------
// Test 3: allow-git=none blocks direct manifest git dep with ZERO git fetches
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_git_none_blocks_manifest_dep_zero_git_fetches() {
    let server = CountingServer::start(|_path, _base_url| None).await;
    let git_guard = DummyGitGuard::new();

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let git_url = format!("git+http://127.0.0.1:{}/repo.git", server.port());
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "git-dep": git_url
        }),
        "allow-git=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-git=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWGIT"),
        "Error message should contain EALLOWGIT, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"git\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    // ZERO HTTP requests were sent to the server for git
    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to git server"
    );

    // ZERO git subprocesses were spawned!
    assert!(
        !git_guard.was_invoked(),
        "ZERO git subprocess fetches should occur when allow-git=none"
    );
}

// -----------------------------------------------------------------------------
// Test 4: allow-git=none blocks CLI argument with ZERO git fetches
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_git_none_blocks_cli_arg_zero_git_fetches() {
    let server = CountingServer::start(|_path, _base_url| None).await;
    let git_guard = DummyGitGuard::new();

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({}),
        "allow-git=none\n",
    );

    let git_url = format!("git+http://127.0.0.1:{}/cli-git.git", server.port());
    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        packages: vec![git_url],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-git=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWGIT"),
        "Error message should contain EALLOWGIT, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"git\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    // ZERO HTTP requests and ZERO git subprocesses
    assert_eq!(server.request_count().await, 0);
    assert!(
        !git_guard.was_invoked(),
        "ZERO git subprocess fetches should occur when allow-git=none"
    );
}

// -----------------------------------------------------------------------------
// Test 5: allow-remote=root allows root but blocks transitive URL with ZERO requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_root_allows_root_blocks_transitive() {
    let server_addr_cell: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cell_clone = server_addr_cell.clone();

    let server = CountingServer::start(move |path, base_url| {
        if path == "/root-pkg.tgz" {
            let transitive_url = format!("{base_url}/transitive-pkg.tgz");
            let manifest = serde_json::json!({
                "name": "root-pkg",
                "version": "1.0.0",
                "dependencies": {
                    "transitive-pkg": transitive_url
                }
            });
            let pkg = create_test_tarball(&[
                ("package.json", manifest.to_string().as_bytes())
            ]);
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
        } else if path == "/transitive-pkg.tgz" {
            let manifest = serde_json::json!({
                "name": "transitive-pkg",
                "version": "1.0.0"
            });
            let pkg = create_test_tarball(&[
                ("package.json", manifest.to_string().as_bytes())
            ]);
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
        } else {
            None
        }
    }).await;

    *cell_clone.lock().await = Some(server.url());

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let root_url = format!("{}/root-pkg.tgz", server.url());
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "root-pkg": root_url
        }),
        "allow-remote=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive remote dep");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "Error message should contain EALLOWREMOTE, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"remote\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    // Root tarball was downloaded, but transitive tarball was NEVER requested!
    let reqs = server.requested_paths.lock().await;
    assert!(
        reqs.iter().any(|r| r.ends_with("root-pkg.tgz")),
        "Root package tarball should have been fetched"
    );
    assert!(
        !reqs.iter().any(|r| r.ends_with("transitive-pkg.tgz")),
        "Transitive package tarball must NEVER be fetched, but was in: {reqs:?}"
    );
}

// -----------------------------------------------------------------------------
// Test 6: allow-file=none and allow-directory=none early rejection
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_file_and_directory_none() {
    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let tgz_path = project_dir.path().join("local.tgz");
    std::fs::write(&tgz_path, b"fake-archive").unwrap();

    // 1. allow-file=none
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "local-pkg": "file:./local.tgz"
        }),
        "allow-file=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("EALLOWFILE"), "Got: {err}");
    assert!(err.contains("Fetching packages of type \"file\" have been disabled"));

    // 2. allow-directory=none
    let dir_pkg = project_dir.path().join("local-dir");
    std::fs::create_dir_all(&dir_pkg).unwrap();
    std::fs::write(
        dir_pkg.join("package.json"),
        r#"{"name":"local-dir","version":"1.0.0"}"#,
    ).unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "local-dir": "file:./local-dir"
        }),
        "allow-directory=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("EALLOWDIRECTORY"), "Got: {err}");
    assert!(err.contains("Fetching packages of type \"directory\" have been disabled"));
}

fn run_git_cmd(dir: &Path, args: &[&str]) {
    let _lock = GIT_TEST_MUTEX.lock().unwrap();
    let _ = std::fs::write(dir.join(".empty_gitconfig"), "");
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join(".empty_gitconfig"))
        .status()
        .expect("Failed to execute git command");
    assert!(status.success(), "Git command failed: git {:?}", args);
}

// -----------------------------------------------------------------------------
// Test 7: allow-git=root allows root git dep, blocks transitive git with ZERO fetches
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_git_root_allows_root_blocks_transitive() {
    let server = CountingServer::start(|_path, _base_url| None).await;

    let root_git_dir = tempdir().unwrap();
    let root_path = root_git_dir.path();
    run_git_cmd(root_path, &["init"]);
    run_git_cmd(root_path, &["config", "user.name", "Tester"]);
    run_git_cmd(root_path, &["config", "user.email", "tester@example.com"]);

    let transitive_url = format!("git+http://127.0.0.1:{}/transitive.git", server.port());
    let manifest = serde_json::json!({
        "name": "root-git-pkg",
        "version": "1.0.0",
        "dependencies": {
            "transitive-git": transitive_url
        }
    });
    std::fs::write(root_path.join("package.json"), manifest.to_string()).unwrap();
    std::fs::write(root_path.join("index.js"), "module.exports = 'root git';\n").unwrap();
    run_git_cmd(root_path, &["add", "."]);
    run_git_cmd(root_path, &["commit", "-m", "Initial commit"]);

    let root_git_url = format!("git+file://{}", root_path.to_str().unwrap().replace('\\', "/"));

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "root-git-pkg": root_git_url
        }),
        "allow-git=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive git dep");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("EALLOWGIT"), "Got: {err}");
    assert!(
        err.contains("Fetching non-root packages of type \"git\" have been disabled"),
        "Got: {err}"
    );

    // ZERO git fetch requests (like /info/refs or .git) to the server!
    let reqs = server.requested_paths.lock().await;
    assert!(
        !reqs.iter().any(|r| r.contains(".git") || r.contains("git-upload-pack")),
        "Transitive git repo was never fetched by git subprocess! Reqs: {reqs:?}"
    );
}

// -----------------------------------------------------------------------------
// Test 8: Direct tarball URLs with /-/ are Remote (NOT registry): blocked by allow-remote=none (manifest)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_none_blocks_registry_like_tarball_url_manifest() {
    let server = CountingServer::start(|_path, _base_url| {
        let pkg = create_test_tarball(&[("package.json", br#"{"name":"foo","version":"1.0.0"}"#)]);
        Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let remote_url = format!("{}/foo/-/foo-1.0.0.tgz", server.url());
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "foo": remote_url
        }),
        "allow-remote=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-remote=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "Direct tarball URL with /-/ must be classified as Remote and fail with EALLOWREMOTE, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"remote\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the server"
    );
}

// -----------------------------------------------------------------------------
// Test 9: Direct tarball URLs with /-/ are Remote (NOT registry): blocked by allow-remote=none (CLI)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_none_blocks_registry_like_tarball_url_cli() {
    let server = CountingServer::start(|_path, _base_url| {
        let pkg = create_test_tarball(&[("package.json", br#"{"name":"foo","version":"1.0.0"}"#)]);
        Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({}),
        "allow-remote=none\n",
    );

    let remote_url = format!("{}/foo/-/foo-1.0.0.tgz", server.url());
    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        packages: vec![remote_url],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-remote=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "CLI direct tarball URL with /-/ must be classified as Remote, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"remote\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the server"
    );
}

// -----------------------------------------------------------------------------
// Test 10: allow-registry=none blocks manifest registry dep with ZERO requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_none_blocks_manifest_dep_zero_packument_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let packument = serde_json::json!({
            "name": "foo",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "foo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "http://127.0.0.1/foo/-/foo-1.0.0.tgz"
                    }
                }
            }
        });
        Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "foo": "^1.0.0"
        }),
        "allow-registry=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-registry=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"registry\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the registry server"
    );
}

// -----------------------------------------------------------------------------
// Test 11: allow-registry=none blocks CLI registry dep with ZERO requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_none_blocks_cli_dep_zero_packument_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let packument = serde_json::json!({
            "name": "foo",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "foo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "http://127.0.0.1/foo/-/foo-1.0.0.tgz"
                    }
                }
            }
        });
        Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({}),
        "allow-registry=none\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        packages: vec!["foo@^1.0.0".to_string()],
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail with allow-registry=none");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching packages of type \"registry\" have been disabled"),
        "Error message should match exact npm text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the registry server"
    );
}

// -----------------------------------------------------------------------------
// Test 12: allow-registry=root blocks transitive registry dep with ZERO packument requests
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_blocks_transitive_registry_dep_zero_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let packument = serde_json::json!({
            "name": "transitive-reg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "transitive-reg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "http://127.0.0.1/transitive-reg/-/transitive-reg-1.0.0.tgz"
                    }
                }
            }
        });
        Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    // Create a local directory package `local-pkg` that has a transitive registry dep
    let local_pkg_dir = project_dir.path().join("local-pkg");
    std::fs::create_dir_all(&local_pkg_dir).unwrap();
    std::fs::write(
        local_pkg_dir.join("package.json"),
        serde_json::json!({
            "name": "local-pkg",
            "version": "1.0.0",
            "dependencies": {
                "transitive-reg": "^1.0.0"
            }
        }).to_string(),
    ).unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "local-pkg": "file:./local-pkg"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive registry dep");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"registry\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the registry server"
    );
}

// -----------------------------------------------------------------------------
// Test 13: allow-remote=root: requester edge check, NOT package name match
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_remote_root_requester_edge_not_fooled_by_same_name_root_dep() {
    let server = CountingServer::start(|_path, _base_url| {
        let pkg = create_test_tarball(&[("package.json", br#"{"name":"bar","version":"2.0.0"}"#)]);
        Some((200, vec![("Content-Type", "application/octet-stream".to_string())], pkg))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    // Root project declares:
    // 1. "bar": "file:./bar" (a root file dependency named "bar")
    // 2. "local-a": "file:./local-a"
    // "local-a" has a transitive dependency "bar": "http://.../bar.tgz".
    // Even though root declares a package named "bar", the transitive edge for "bar"
    // comes from "local-a", NOT root! So allow-remote=root MUST reject it!
    let bar_dir = project_dir.path().join("bar");
    std::fs::create_dir_all(&bar_dir).unwrap();
    std::fs::write(
        bar_dir.join("package.json"),
        r#"{"name":"bar","version":"1.0.0"}"#,
    ).unwrap();

    let remote_bar_url = format!("{}/bar/-/bar-2.0.0.tgz", server.url());
    let local_a_dir = project_dir.path().join("local-a");
    std::fs::create_dir_all(&local_a_dir).unwrap();
    std::fs::write(
        local_a_dir.join("package.json"),
        serde_json::json!({
            "name": "local-a",
            "version": "1.0.0",
            "dependencies": {
                "bar": remote_bar_url
            }
        }).to_string(),
    ).unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "bar": "file:./bar",
            "local-a": "file:./local-a"
        }),
        "allow-remote=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive remote dep 'bar'");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREMOTE"),
        "Error message should contain EALLOWREMOTE, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"remote\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    assert_eq!(
        server.request_count().await,
        0,
        "Transitive bar.tgz must NEVER be fetched over HTTP!"
    );
}

// -----------------------------------------------------------------------------
// Test 14: allow-git=root: requester edge check, NOT package name match
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_git_root_requester_edge_not_fooled_by_same_name_root_dep() {
    let server = CountingServer::start(|_path, _base_url| None).await;
    let git_guard = DummyGitGuard::new();

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    // Root declares "bar": "file:./bar" and "local-a": "file:./local-a"
    // "local-a" declares "bar": "git+http://.../bar.git"
    // Even though root declares a package named "bar", the transitive edge is non-root!
    let bar_dir = project_dir.path().join("bar");
    std::fs::create_dir_all(&bar_dir).unwrap();
    std::fs::write(
        bar_dir.join("package.json"),
        r#"{"name":"bar","version":"1.0.0"}"#,
    ).unwrap();

    let git_bar_url = format!("git+http://127.0.0.1:{}/bar.git", server.port());
    let local_a_dir = project_dir.path().join("local-a");
    std::fs::create_dir_all(&local_a_dir).unwrap();
    std::fs::write(
        local_a_dir.join("package.json"),
        serde_json::json!({
            "name": "local-a",
            "version": "1.0.0",
            "dependencies": {
                "bar": git_bar_url
            }
        }).to_string(),
    ).unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "bar": "file:./bar",
            "local-a": "file:./local-a"
        }),
        "allow-git=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive git dep 'bar'");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWGIT"),
        "Error message should contain EALLOWGIT, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"git\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    assert_eq!(server.request_count().await, 0);
    assert!(
        !git_guard.was_invoked(),
        "Transitive git repo was never fetched by git subprocess!"
    );
}

// -----------------------------------------------------------------------------
// Test 15: allow-registry=root: root declares foo as file:, transitive declares foo as registry
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_cross_kind_name_collision_zero_requests() {
    let server = CountingServer::start(|_path, _base_url| {
        let packument = serde_json::json!({
            "name": "foo",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "foo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "http://127.0.0.1/foo/-/foo-1.0.0.tgz"
                    }
                }
            }
        });
        Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    // Root declares:
    // 1. "foo": "file:./local-foo" (root declares foo as a FILE dependency, NOT registry)
    // 2. "holder": "file:./local-holder"
    // "holder" declares a transitive dependency on "foo": "^1.0.0" from the registry!
    // Under allow-registry=root, because foo is NOT declared by root as a registry package,
    // the transitive registry request for foo must fail with EALLOWREGISTRY and ZERO packument HTTP requests!
    let local_foo = project_dir.path().join("local-foo");
    std::fs::create_dir_all(&local_foo).unwrap();
    std::fs::write(
        local_foo.join("package.json"),
        r#"{"name":"foo","version":"1.0.0"}"#,
    ).unwrap();

    let local_holder = project_dir.path().join("local-holder");
    std::fs::create_dir_all(&local_holder).unwrap();
    std::fs::write(
        local_holder.join("package.json"),
        serde_json::json!({
            "name": "holder",
            "version": "1.0.0",
            "dependencies": {
                "foo": "^1.0.0"
            }
        }).to_string(),
    ).unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "foo": "file:./local-foo",
            "holder": "file:./local-holder"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive registry dep 'foo'");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"registry\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    // ZERO HTTP packument requests must have hit the server for 'foo'!
    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the registry server for 'foo'"
    );
}

// -----------------------------------------------------------------------------
// Test 16: allow-registry=root: root declares reg-parent: ^1.0.0 AND foo: ^1.0.0 (both registry).
// reg-parent depends on foo: ^2.0.0.
// Under allow-registry=root, even though foo is declared at root (and cached in metadata_cache),
// the solver edge for reg-parent -> foo@^2.0.0 passes is_root=false.
// The solver edge in RegistryPackageProvider must reject with EALLOWREGISTRY, and zero transitive fetches occur.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_solver_edge_transitive_collision_rejected() {
    let server = CountingServer::start(|path, base_url| {
        if path == "/reg-parent" {
            let packument = serde_json::json!({
                "name": "reg-parent",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "reg-parent",
                        "version": "1.0.0",
                        "dependencies": {
                            "foo": "^2.0.0"
                        },
                        "dist": {
                            "tarball": format!("{base_url}/reg-parent/-/reg-parent-1.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else if path == "/foo" {
            let packument = serde_json::json!({
                "name": "foo",
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "foo",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/foo/-/foo-1.0.0.tgz")
                        }
                    },
                    "2.0.0": {
                        "name": "foo",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/foo/-/foo-2.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else {
            None
        }
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    // Root declares:
    // 1. "reg-parent": "^1.0.0" (registry)
    // 2. "foo": "^1.0.0" (registry)
    // No custom targets (file: or git:) exist, so populate_custom_target_metadata
    // does not inspect child manifests. The rejection occurs purely at the solver edge!
    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "reg-parent": "^1.0.0",
            "foo": "^1.0.0"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive registry dep foo@^2.0.0 from reg-parent");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"registry\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    // Exactly 2 root packument requests were made: /reg-parent and /foo.
    // Zero transitive requests were made.
    assert_eq!(
        server.request_count().await,
        2,
        "Exactly 2 root HTTP packument requests should have been made (/reg-parent, /foo)"
    );
}

// -----------------------------------------------------------------------------
// Test 17: allow-registry=root: root declares reg-parent: ^1.0.0 which depends on bar: ^1.0.0.
// Under allow-registry=root, bar is not declared at root.
// When reg-parent is solved, the solver edge for bar: ^1.0.0 passes is_root=false.
// The solver edge in RegistryPackageProvider must reject with EALLOWREGISTRY,
// and ZERO HTTP requests for /bar must ever hit the registry server!
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_solver_edge_transitive_zero_requests() {
    let server = CountingServer::start(|path, base_url| {
        if path == "/reg-parent" {
            let packument = serde_json::json!({
                "name": "reg-parent",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "reg-parent",
                        "version": "1.0.0",
                        "dependencies": {
                            "bar": "^1.0.0"
                        },
                        "dist": {
                            "tarball": format!("{base_url}/reg-parent/-/reg-parent-1.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else if path == "/bar" {
            let packument = serde_json::json!({
                "name": "bar",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "bar",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/bar/-/bar-1.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else {
            None
        }
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "reg-parent": "^1.0.0"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_err(), "Expected install to fail on transitive registry dep bar@^1.0.0");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Error message should contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"registry\" have been disabled"),
        "Error message should match exact non-root text, got: {err_msg}"
    );

    // 1 request for /reg-parent was made, and ZERO requests for /bar!
    let reqs = server.requested_paths.lock().await.clone();
    assert_eq!(reqs.len(), 1, "Only 1 HTTP request should have occurred (/reg-parent)");
    assert_eq!(reqs[0], "/reg-parent");
    assert!(
        !reqs.contains(&"/bar".to_string()),
        "ZERO HTTP requests should have been made to the registry server for 'bar'"
    );
}

// -----------------------------------------------------------------------------
// Test 18: allow-registry=root: root declares npm: alias "my-foo": "npm:foo@^1.0.0".
// Under allow-registry=root, the underlying package "foo" must be recognized in
// root_registry_declared so the solver can fetch and install "foo" successfully.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_npm_alias_succeeds() {
    let foo_tgz = create_test_tarball(&[("package.json", br#"{"name":"foo","version":"1.0.0"}"#)]);
    let foo_tgz_bytes = Arc::new(foo_tgz);

    let server = CountingServer::start(move |path, base_url| {
        if path == "/foo" {
            let packument = serde_json::json!({
                "name": "foo",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "foo",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/foo/-/foo-1.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else if path == "/foo/-/foo-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], (*foo_tgz_bytes).clone()))
        } else {
            None
        }
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "my-foo": "npm:foo@^1.0.0"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_ok(), "Expected install of aliased root registry dep to succeed: {:?}", result.err());

    let reqs = server.requested_paths.lock().await.clone();
    let alias_requests = reqs.iter().filter(|p| p.starts_with("/my-foo") || p.as_str() == "/my-foo").count();
    assert_eq!(alias_requests, 0, "ZERO HTTP requests must be sent to /my-foo, but got: {:?}", reqs);

    let installed_pkg_json = project_dir.path().join("node_modules").join("my-foo").join("package.json");
    assert!(installed_pkg_json.exists(), "node_modules/my-foo/package.json should exist");
    let content = std::fs::read_to_string(&installed_pkg_json).unwrap();
    assert!(content.contains("\"name\": \"foo\"") || content.contains("\"name\":\"foo\""), "Content should match foo");
}

// -----------------------------------------------------------------------------
// Test 19: Finding #4 regression test: allow-registry=root with npm: alias
// Asserts that when root declares "my-alias": "npm:real-pkg@^1.0.0":
// 1. ZERO HTTP requests are ever sent to /my-alias (alias_requests == 0).
// 2. ONLY /real-pkg is fetched and installed cleanly under node_modules/my-alias.
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_allow_registry_root_npm_alias_zero_requests_to_alias_name() {
    let real_pkg_tgz = create_test_tarball(&[("package.json", br#"{"name":"real-pkg","version":"1.0.0"}"#)]);
    let real_pkg_tgz_bytes = Arc::new(real_pkg_tgz);

    let server = CountingServer::start(move |path, base_url| {
        if path == "/real-pkg" {
            let packument = serde_json::json!({
                "name": "real-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "real-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{base_url}/real-pkg/-/real-pkg-1.0.0.tgz")
                        }
                    }
                }
            });
            Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
        } else if path == "/real-pkg/-/real-pkg-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], (*real_pkg_tgz_bytes).clone()))
        } else {
            None
        }
    }).await;

    let project_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    setup_test_project(
        project_dir.path(),
        &serde_json::json!({
            "my-alias": "npm:real-pkg@^1.0.0"
        }),
        "allow-registry=root\n",
    );

    let options = InstallOptions {
        project_dir: project_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        registry_url: Some(server.url()),
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let result = installer.install().await;

    assert!(result.is_ok(), "Expected install of aliased root registry dep to succeed: {:?}", result.err());

    let reqs = server.requested_paths.lock().await.clone();
    let alias_requests = reqs.iter().filter(|p| p.starts_with("/my-alias") || p.as_str() == "/my-alias").count();
    assert_eq!(alias_requests, 0, "ZERO HTTP requests must be sent to /my-alias, but got: {:?}", reqs);

    let real_pkg_requests = reqs.iter().filter(|p| p.as_str() == "/real-pkg").count();
    assert!(real_pkg_requests >= 1, "Expected packument request for /real-pkg, got: {:?}", reqs);

    let installed_pkg_json = project_dir.path().join("node_modules").join("my-alias").join("package.json");
    assert!(installed_pkg_json.exists(), "node_modules/my-alias/package.json should exist");
    let content = std::fs::read_to_string(&installed_pkg_json).unwrap();
    assert!(content.contains("\"name\": \"real-pkg\"") || content.contains("\"name\":\"real-pkg\""), "Content should match real-pkg");
}
