use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

mod common;
use common::isolated_npm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct RecordedReq {
    method: String,
    path: String,
    has_auth: bool,
}

fn normalize_output(text: &str) -> String {
    let mut in_notice = false;
    text.replace("\r\n", "\n")
        .lines()
        .filter(|line| {
            if line.contains("A complete log of this run can be found in:") {
                return false;
            }
            if line.contains("New major version of npm available!") {
                in_notice = true;
                return false;
            }
            if in_notice {
                if line.starts_with("npm notice") {
                    return false;
                } else {
                    in_notice = false;
                }
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_logout_parity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let recorded = Arc::new(Mutex::new(Vec::<RecordedReq>::new()));
    let recorded_clone = recorded.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        let rec = recorded_clone.clone();
                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut temp = [0u8; 4096];
                            let mut header_end = None;
                            let mut content_len = 0;

                            while let Ok(n) = stream.read(&mut temp).await {
                                if n == 0 {
                                    break;
                                }
                                buf.extend_from_slice(&temp[..n]);
                                if header_end.is_none() {
                                    if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                        header_end = Some(idx + 4);
                                        let header_text = String::from_utf8_lossy(&buf[..idx]);
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
                                    if buf.len() >= end + content_len {
                                        break;
                                    }
                                }
                            }

                            if let Some(end) = header_end {
                                let header_text = String::from_utf8_lossy(&buf[..end - 4]);
                                let first_line = header_text.lines().next().unwrap_or_default();
                                let parts: Vec<&str> = first_line.split_whitespace().collect();
                                let method = parts.first().copied().unwrap_or("GET").to_string();
                                let path = parts.get(1).copied().unwrap_or("/").to_string();
                                let has_auth = header_text.to_ascii_lowercase().contains("authorization: bearer fake-token");

                                rec.lock().await.push(RecordedReq {
                                    method: method.clone(),
                                    path: path.clone(),
                                    has_auth,
                                });

                                let body = b"{\"ok\":true}";
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                                let _ = stream.write_all(body).await;
                                let _ = stream.flush().await;
                            }
                        });
                    }
                }
            }
        }
    });

    let tmp = tempdir().unwrap();
    let iso = tmp.path().join("iso");
    let cache_dir = iso.join("cache");
    let prefix_dir = iso.join("prefix");
    let appdata = iso.join("appdata");
    let localappdata = iso.join("localappdata");
    let userconfig_npm = iso.join(".npmrc.npm");
    let userconfig_rnpm = iso.join(".npmrc.rnpm");
    let globalconfig = iso.join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    let initial_rc = format!("//{addr}/:_authToken=fake-token\nregistry=http://{addr}/\n");
    std::fs::write(&userconfig_npm, &initial_rc).unwrap();
    std::fs::write(&userconfig_rnpm, &initial_rc).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Run live npm logout
    let npm_logout = isolated_npm()
        .args([
            "logout",
            "--registry",
            &format!("http://{addr}/"),
            "--no-update-notifier",
        ])
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig_npm)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig_npm)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    // 2. Run rnpm logout
    let rnpm_logout = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig_rnpm)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig_rnpm)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["logout", "--registry", &format!("http://{addr}/")])
        .output()
        .expect("rnpm logout failed");

    if let Ok(npm_out) = npm_logout {
        assert_eq!(rnpm_logout.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_logout.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_logout.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_logout.status.success());
    }

    // Verify token was deleted from .npmrc
    let rnpm_rc_content = std::fs::read_to_string(&userconfig_rnpm).unwrap();
    assert!(!rnpm_rc_content.contains("_authToken"));

    // Verify requests sent to mock registry
    let reqs = recorded.lock().await;
    let delete_reqs: Vec<_> = reqs.iter().filter(|r| r.method == "DELETE").collect();
    // At least 1 (or 2 if npm also ran) DELETE request to /-/user/token/fake-token
    assert!(!delete_reqs.is_empty());
    for req in &delete_reqs {
        assert_eq!(req.path, "/-/user/token/fake-token");
        assert!(req.has_auth);
    }

    let _ = tx.send(());
}
