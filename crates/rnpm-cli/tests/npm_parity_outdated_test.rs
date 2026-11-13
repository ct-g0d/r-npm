use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outdated_column_layout_and_json_parity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                if stream.read(&mut request).await.unwrap() == 0 { return; }
                let body = serde_json::json!({"name":"is-number","dist-tags":{"latest":"7.0.0"},"versions":{
                    "6.0.0":{"name":"is-number","version":"6.0.0","dist":{"tarball":format!("http://{address}/6.tgz")}},
                    "7.0.0":{"name":"is-number","version":"7.0.0","dist":{"tarball":format!("http://{address}/7.tgz")}}
                }}).to_string();
                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            });
        }
    });
    let tmp = tempdir().unwrap();
    let isolated = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "6.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let run = |oracle: bool, args: &[&str]| {
        let npm = common::isolated_npm(isolated.path());
        let mut command = if oracle {
            npm
        } else {
            let mut command = Command::new(rnpm_bin);
            for (key, value) in npm.get_envs() {
                if let Some(value) = value {
                    command.env(key, value);
                } else {
                    command.env_remove(key);
                }
            }
            command
        };
        command
            .current_dir(tmp.path())
            .args(args)
            .env("NPM_CONFIG_REGISTRY", format!("http://{address}/"))
            .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
            .env("NO_COLOR", "1")
            .env_remove("NPM_TOKEN")
            .env_remove("NODE_AUTH_TOKEN")
            .output()
            .unwrap()
    };

    // 1. Tabular layout
    let npm_out = run(true, &["outdated"]);
    let rnpm_out = run(false, &["outdated"]);
    assert_eq!(npm_out.status.code(), Some(1));
    assert_eq!(rnpm_out.status.code(), Some(1));
    assert_eq!(rnpm_out.stdout, npm_out.stdout);
    let stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2);
    assert_eq!(
        lines[0],
        "Package    Current  Wanted  Latest  Location  Depended by"
    );
    assert_eq!(
        lines[1],
        format!(
            "is-number  MISSING   6.0.0   7.0.0  -         {}",
            tmp.path().file_name().unwrap().to_string_lossy()
        )
    );

    // 2. JSON output: missing packages must omit 'current' and 'location'
    let npm_json_out = run(true, &["outdated", "--json"]);
    let rnpm_json_out = run(false, &["outdated", "--json"]);
    assert_eq!(npm_json_out.status.code(), Some(1));
    assert_eq!(rnpm_json_out.status.code(), Some(1));
    let json_val: serde_json::Value = serde_json::from_slice(&rnpm_json_out.stdout)
        .expect("rnpm outdated --json must output valid JSON");
    assert_eq!(
        json_val,
        serde_json::from_slice::<serde_json::Value>(&npm_json_out.stdout).unwrap()
    );
    let is_number = json_val
        .get("is-number")
        .expect("must have is-number entry");
    assert_eq!(
        is_number.get("wanted").and_then(|v| v.as_str()),
        Some("6.0.0")
    );
    assert_eq!(
        is_number.get("latest").and_then(|v| v.as_str()),
        Some("7.0.0")
    );
    assert_eq!(
        is_number.get("dependent").and_then(|v| v.as_str()),
        tmp.path().file_name().unwrap().to_str()
    );
    assert!(
        is_number.get("current").is_none(),
        "current must be omitted when MISSING"
    );
    assert!(
        is_number.get("location").is_none(),
        "location must be omitted when MISSING"
    );
    server.abort();
}
