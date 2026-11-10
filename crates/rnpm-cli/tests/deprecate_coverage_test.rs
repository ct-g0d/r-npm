use std::process::Command;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_deprecate_mock() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            let n = stream.read(&mut buf).await.unwrap_or(0);
                            let req = String::from_utf8_lossy(&buf[..n]);

                            if req.starts_with("GET /sample-pkg") {
                                let doc = serde_json::json!({
                                    "_id": "sample-pkg",
                                    "name": "sample-pkg",
                                    "versions": {
                                        "1.0.0": {
                                            "name": "sample-pkg",
                                            "version": "1.0.0"
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
                            } else if req.starts_with("PUT /sample-pkg") {
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
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "deprecate",
            "sample-pkg@1.0.0",
            "Use version 2 instead",
            "--registry",
            &format!("http://{addr}/"),
        ])
        .output()
        .expect("deprecate failed");

    let _ = tx.send(());

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}
