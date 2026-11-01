use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::collections::BTreeMap;
use std::io::Cursor;
use tar::{Builder, Header};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

    fn make_tarball(pkg_name: &str, version: &str) -> Vec<u8> {
        let manifest_json = serde_json::json!({
            "name": pkg_name,
            "version": version,
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest_json).unwrap();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gz);
            let mut header = Header::new_gnu();
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            let path = "package/package.json";
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, Cursor::new(manifest_bytes)).unwrap();
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[tokio::test]
    async fn test_cli_update_command_integration() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        let pkg_tar = make_tarball("demo-pkg", "1.2.0");
        let pkg_int = Integrity::from_bytes(&pkg_tar, Algorithm::Sha512).to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{local_addr}/");
        let su = server_url.clone();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let pkg_int_c = pkg_int.clone();
                            let pkg_tar_c = pkg_tar.clone();
                            let su_c = su.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /demo-pkg") {
                                        let json = serde_json::json!({
                                            "name": "demo-pkg",
                                            "dist-tags": { "latest": "1.2.0" },
                                            "versions": {
                                                "1.0.0": { "name": "demo-pkg", "version": "1.0.0", "dist": { "tarball": format!("{su_c}tarballs/demo-pkg.tgz"), "integrity": pkg_int_c } },
                                                "1.2.0": { "name": "demo-pkg", "version": "1.2.0", "dist": { "tarball": format!("{su_c}tarballs/demo-pkg.tgz"), "integrity": pkg_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/demo-pkg.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], pkg_tar_c)
                                    } else {
                                        (404, vec![], b"Not Found".to_vec())
                                    };

                                    let status_text = if status == 200 { "OK" } else { "Not Found" };
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
                                    let _ = stream.flush().await;
                                }
                            });
                        }
                    }
                }
            }
        });

        // Set up project files
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "my-cli-app",
            "version": "1.0.0",
            "dependencies": {
                "demo-pkg": "^1.0.0"
            }
        }"#).unwrap();

        let mut lock = LockfileV3::new("my-cli-app", Some("1.0.0".to_string()));
        let mut d = BTreeMap::new();
        d.insert("demo-pkg".to_string(), "^1.0.0".to_string());
        lock.root_package_mut().unwrap().dependencies = Some(d);
        lock.insert_package("node_modules/demo-pkg", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/demo-pkg.tgz")),
            integrity: Some("sha512-fake".to_string()),
            ..Default::default()
        });
        let lock_path = project_dir.path().join("package-lock.json");
        lock.save_to_file(&lock_path).unwrap();

        // Run rnpm update via run_cli
        let cli = Cli {
            command: Commands::Update {
                packages: vec![],
                registry: Some(server_url),
                cache: Some(cache_dir.path().to_path_buf()),
                offline: false,
                ignore_scripts: true,
            },
        };

        let res = run_cli(cli, Some(project_dir.path().to_path_buf())).await;
        assert!(res.is_ok());

        let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
        let pkg_entry = updated_lock.get_package("node_modules/demo-pkg").unwrap();
        assert_eq!(pkg_entry.version, Some("1.2.0".to_string()));
        assert!(project_dir.path().join("node_modules/demo-pkg/package.json").exists());

        let _ = tx.send(());
    }
