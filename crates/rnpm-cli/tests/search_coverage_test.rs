use std::process::Command;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cli_search() {
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
                            let search_json = serde_json::json!({
                                "objects": [
                                    {
                                        "package": {
                                            "name": "foo-pkg",
                                            "version": "1.0.0",
                                            "description": "A package for testing search",
                                            "date": "2024-01-01T12:00:00.000Z",
                                            "publisher": { "username": "alice" },
                                            "maintainers": [
                                                { "username": "alice" },
                                                { "username": "bob" }
                                            ],
                                            "keywords": ["test", "search"]
                                        }
                                    }
                                ],
                                "total": 1
                            });
                            let body = serde_json::to_vec(&search_json).unwrap();
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
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Test --json format (must be JSON array of packages)
    let json_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "search",
            "foo",
            "--registry",
            &format!("http://{addr}/"),
            "--json",
        ])
        .output()
        .expect("search --json failed");

    assert!(json_out.status.success(), "stderr: {}", String::from_utf8_lossy(&json_out.stderr));
    let json_val: serde_json::Value = serde_json::from_slice(&json_out.stdout)
        .expect("must be valid JSON array");
    assert!(json_val.is_array());
    assert_eq!(json_val[0]["name"], "foo-pkg");

    // 2. Test default text format (must match npm 11 block format)
    let text_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "search",
            "foo",
            "--registry",
            &format!("http://{addr}/"),
        ])
        .output()
        .expect("search text failed");

    let _ = tx.send(());

    assert!(text_out.status.success(), "stderr: {}", String::from_utf8_lossy(&text_out.stderr));
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(stdout.contains("foo-pkg\nA package for testing search\nVersion 1.0.0 published 2024-01-01 by alice\nMaintainers: alice bob\nKeywords: test search\nhttps://npm.im/foo-pkg"));
}
