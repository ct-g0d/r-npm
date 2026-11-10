use std::process::Command;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_token_list_mock() {
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
                            let _ = stream.read(&mut buf).await;
                            let token_json = serde_json::json!({
                                "objects": [
                                    {
                                        "id": "tok_12345",
                                        "token": "npm_test123",
                                        "created": "2026-01-01T00:00:00Z",
                                        "readonly": false
                                    }
                                ]
                            });
                            let body = serde_json::to_vec(&token_json).unwrap();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            let _ = stream.write_all(&body).await;
                            let _ = stream.flush().await;
                        });
                    }
                }
            }
        }
    });

    let tmp = tempdir().unwrap();
    std::fs::write(
        tmp.path().join(".npmrc"),
        format!("//{addr}/:_authToken=test-token-val\n"),
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "token",
            "--registry",
            &format!("http://{addr}/"),
            "--json",
            "list",
        ])
        .output()
        .expect("token list failed");

    let _ = tx.send(());

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tok_12345"));
}
