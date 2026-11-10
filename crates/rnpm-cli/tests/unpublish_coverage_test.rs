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
}

fn normalize_output(text: &str) -> String {
    text.replace("\r\n", "\n")
        .lines()
        .filter(|line| {
            !line.contains("A complete log of this run can be found in:")
                && !line.contains("New major version of npm available")
                && !line.contains("Changelog:")
                && !line.contains("To update run:")
                && line.trim() != "npm notice"
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_unpublish_dry_run_parity() {
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

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Case 1: unpublish --dry-run --force sample-pkg
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["unpublish", "sample-pkg", "--dry-run", "--force"])
        .output()
        .expect("rnpm unpublish failed");

    let npm_res = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "unpublish",
            "sample-pkg",
            "--dry-run",
            "--force",
            "--no-update-notifier",
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res {
        assert_eq!(rnpm_res.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_res.status.success());
    }

    // Case 2: unpublish --dry-run sample-pkg@1.0.0
    let rnpm_res_v = Command::new(rnpm_bin)
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["unpublish", "sample-pkg@1.0.0", "--dry-run"])
        .output()
        .expect("rnpm unpublish failed");

    let npm_res_v = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "unpublish",
            "sample-pkg@1.0.0",
            "--dry-run",
            "--no-update-notifier",
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res_v {
        assert_eq!(rnpm_res_v.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res_v.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res_v.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_res_v.status.success());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_unpublish_mock_registry() {
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

                            while let Ok(n) = stream.read(&mut temp).await {
                                if n == 0 {
                                    break;
                                }
                                buf.extend_from_slice(&temp[..n]);
                                if header_end.is_none() {
                                    if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                        header_end = Some(idx + 4);
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

                                rec.lock().await.push(RecordedReq {
                                    method: method.clone(),
                                    path: path.clone(),
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args([
            "unpublish",
            "sample-pkg@1.0.0",
            "--registry",
            &format!("http://{addr}/"),
        ])
        .output()
        .expect("rnpm unpublish failed");

    let _ = tx.send(());

    assert!(rnpm_res.status.success());
    assert_eq!(
        String::from_utf8_lossy(&rnpm_res.stdout).trim(),
        "- sample-pkg@1.0.0"
    );

    let reqs = recorded.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "DELETE");
    assert_eq!(reqs[0].path, "/sample-pkg/1.0.0");
}
