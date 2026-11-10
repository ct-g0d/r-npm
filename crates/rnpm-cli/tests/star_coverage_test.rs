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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_star_probe() {
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
                            let mut buf = [0u8; 4096];
                            let n = stream.read(&mut buf).await.unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);

                            let first_line = req.lines().next().unwrap_or_default();
                            let parts: Vec<&str> = first_line.split_whitespace().collect();
                            let method = parts.first().copied().unwrap_or("GET").to_string();
                            let path = parts.get(1).copied().unwrap_or("/").to_string();

                            rec.lock().await.push(RecordedReq {
                                method: method.clone(),
                                path: path.clone(),
                            });

                            if path.contains("whoami") {
                                let doc = serde_json::json!({ "username": "testuser" });
                                let body = serde_json::to_vec(&doc).unwrap();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                let _ = stream.flush().await;
                            } else if path.starts_with("/sample-pkg") && method == "GET" {
                                let doc = serde_json::json!({
                                    "_id": "sample-pkg",
                                    "name": "sample-pkg",
                                    "users": { "otheruser": true }
                                });
                                let body = serde_json::to_vec(&doc).unwrap();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                let _ = stream.flush().await;
                            } else if path.contains("stars") || path.contains("starred") {
                                let doc = serde_json::json!(["sample-pkg"]);
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

    let npm_star = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "star",
            "sample-pkg",
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(out) = npm_star {
        println!("npm star status: {:?}", out.status.code());
        println!("npm star stdout: {:?}", String::from_utf8_lossy(&out.stdout));
        println!("npm star stderr: {:?}", String::from_utf8_lossy(&out.stderr));
    }

    let npm_unstar = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "unstar",
            "sample-pkg",
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(out) = npm_unstar {
        println!("npm unstar status: {:?}", out.status.code());
        println!("npm unstar stdout: {:?}", String::from_utf8_lossy(&out.stdout));
        println!("npm unstar stderr: {:?}", String::from_utf8_lossy(&out.stderr));
    }

    let npm_stars = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "stars",
            "testuser",
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
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(out) = npm_stars {
        println!("npm stars status: {:?}", out.status.code());
        println!("npm stars stdout: {:?}", String::from_utf8_lossy(&out.stdout));
        println!("npm stars stderr: {:?}", String::from_utf8_lossy(&out.stderr));
    }

    let reqs = recorded.lock().await;
    for (i, r) in reqs.iter().enumerate() {
        println!("req[{i}]: {} {}", r.method, r.path);
    }

    let _ = tx.send(());
}
