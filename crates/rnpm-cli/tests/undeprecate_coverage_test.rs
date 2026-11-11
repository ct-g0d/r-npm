use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

mod common;
use common::isolated_npm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct RecordedReq {
    method: String,
    path: String,
    body: serde_json::Value,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_undeprecate_mock() {
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
                                let body_bytes = &buf[end..end + content_len];
                                let json_val = serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null);

                                rec.lock().await.push(RecordedReq {
                                    method: method.clone(),
                                    path: path.clone(),
                                    body: json_val,
                                });

                                if path.starts_with("/sample-pkg") && method == "GET" {
                                    let doc = serde_json::json!({
                                        "_id": "sample-pkg",
                                        "name": "sample-pkg",
                                        "versions": {
                                            "1.0.0": {
                                                "name": "sample-pkg",
                                                "version": "1.0.0",
                                                "deprecated": "old deprecation"
                                            }
                                        }
                                    });
                                    let body = serde_json::to_vec(&doc).unwrap();
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        body.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.write_all(&body).await;
                                    let _ = stream.flush().await;
                                } else if path.starts_with("/sample-pkg") && method == "PUT" {
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
        format!(
            "//{addr}/:_authToken=fake-token\nregistry=http://{addr}/\n"
        ),
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args([
            "undeprecate",
            "sample-pkg@1.0.0",
            "--registry",
            &format!("http://{addr}/"),
        ])
        .output()
        .expect("rnpm undeprecate failed");

    let rnpm_reqs = {
        let mut l = recorded.lock().await;
        let v = l.clone();
        l.clear();
        v
    };

    let npm_res = isolated_npm()
        .args([
            "undeprecate",
            "sample-pkg@1.0.0",
            "--registry",
            &format!("http://{addr}/"),
        ])
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    let npm_reqs: Vec<RecordedReq> = recorded
        .lock()
        .await
        .iter()
        .filter(|r| r.path != "/npm")
        .cloned()
        .collect();

    let _ = tx.send(());

    assert_eq!(rnpm_reqs.len(), 2, "rnpm should send GET then PUT");
    assert_eq!(rnpm_reqs[0].method, "GET");
    assert_eq!(rnpm_reqs[0].path.split('?').next().unwrap(), "/sample-pkg");
    assert_eq!(rnpm_reqs[1].method, "PUT");
    assert_eq!(rnpm_reqs[1].path.split('?').next().unwrap(), "/sample-pkg");
    assert_eq!(
        rnpm_reqs[1].body["versions"]["1.0.0"]["deprecated"],
        "",
        "deprecated key should be empty string"
    );

    if let Ok(npm_out) = npm_res {
        assert_eq!(npm_reqs.len(), 2, "npm should send GET then PUT");
        assert_eq!(npm_reqs[0].method, "GET");
        assert_eq!(npm_reqs[0].path.split('?').next().unwrap(), "/sample-pkg");
        assert_eq!(npm_reqs[1].method, "PUT");
        assert_eq!(npm_reqs[1].path.split('?').next().unwrap(), "/sample-pkg");
        assert_eq!(
            npm_reqs[1].body["versions"]["1.0.0"]["deprecated"],
            "",
            "deprecated key should be empty string"
        );

        assert_eq!(rnpm_res.status.code(), npm_out.status.code());
        assert_eq!(
            String::from_utf8_lossy(&rnpm_res.stdout).trim(),
            String::from_utf8_lossy(&npm_out.stdout).trim()
        );
        assert_eq!(
            String::from_utf8_lossy(&rnpm_res.stderr).trim(),
            String::from_utf8_lossy(&npm_out.stderr).trim()
        );
    } else {
        assert!(rnpm_res.status.success());
    }
}
