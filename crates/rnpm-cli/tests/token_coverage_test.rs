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
async fn test_cli_token_parity() {
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

                                if method == "GET" && path.starts_with("/-/npm/v1/tokens") {
                                    let doc = serde_json::json!({
                                        "objects": [
                                            {
                                                "key": "1234567890",
                                                "token": "abcdef",
                                                "name": "ci-token",
                                                "created": "2026-01-01T00:00:00.000Z",
                                                "readonly": false,
                                                "cidr_whitelist": null
                                            }
                                        ],
                                        "urls": { "next": null }
                                    });
                                    let body = serde_json::to_vec(&doc).unwrap();
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        body.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.write_all(&body).await;
                                    let _ = stream.flush().await;
                                } else {
                                    let body = b"{\"ok\":true}";
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        body.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.write_all(body).await;
                                    let _ = stream.flush().await;
                                }
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
    let userconfig = iso.join(".npmrc");
    let globalconfig = iso.join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(
        &userconfig,
        format!("//{addr}/:_authToken=fake-token\nregistry=http://{addr}/\n"),
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Test token list
    let rnpm_list = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["token", "list", "--registry", &format!("http://{addr}/")])
        .output()
        .expect("rnpm token list failed");

    let npm_list = isolated_npm(&iso)
        .args([
            "token",
            "list",
            "--registry",
            &format!("http://{addr}/"),
            "--no-update-notifier",
        ])
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_list {
        assert_eq!(
            rnpm_list.status.code(),
            npm_out.status.code(),
            "Exit code mismatch on token list!\nrnpm stdout: {}\nrnpm stderr: {}\nnpm stdout: {}\nnpm stderr: {}",
            String::from_utf8_lossy(&rnpm_list.stdout),
            String::from_utf8_lossy(&rnpm_list.stderr),
            String::from_utf8_lossy(&npm_out.stdout),
            String::from_utf8_lossy(&npm_out.stderr),
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_list.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_list.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_list.status.success());
    }

    // 2. Test token revoke
    let rnpm_revoke = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["token", "revoke", "123456", "--registry", &format!("http://{addr}/")])
        .output()
        .expect("rnpm token revoke failed");

    let npm_revoke = isolated_npm(&iso)
        .args([
            "token",
            "revoke",
            "123456",
            "--registry",
            &format!("http://{addr}/"),
            "--no-update-notifier",
        ])
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_revoke {
        assert_eq!(
            rnpm_revoke.status.code(),
            npm_out.status.code(),
            "Exit code mismatch on token revoke!\nrnpm stdout: {}\nrnpm stderr: {}\nnpm stdout: {}\nnpm stderr: {}",
            String::from_utf8_lossy(&rnpm_revoke.stdout),
            String::from_utf8_lossy(&rnpm_revoke.stderr),
            String::from_utf8_lossy(&npm_out.stdout),
            String::from_utf8_lossy(&npm_out.stderr),
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_revoke.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_revoke.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_revoke.status.success());
    }

    let _ = tx.send(());
}
