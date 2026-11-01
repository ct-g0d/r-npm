use super::*;
use std::collections::BTreeMap;
use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use std::io::Cursor;
use tar::{Builder, Header};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

    fn make_tarball(pkg_name: &str, version: &str, deps: &[(&str, &str)]) -> Vec<u8> {
        let mut dep_map = serde_json::Map::new();
        for (d_name, d_range) in deps {
            dep_map.insert(d_name.to_string(), serde_json::Value::String(d_range.to_string()));
        }

        let manifest_json = serde_json::json!({
            "name": pkg_name,
            "version": version,
            "dependencies": dep_map
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
    async fn test_update_all_dependencies_and_superseded_cleanup() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        // Tarballs
        let pkg_a_100_tar = make_tarball("pkg-a", "1.0.0", &[("trans-old", "^1.0.0")]);
        let pkg_a_110_tar = make_tarball("pkg-a", "1.1.0", &[("trans-new", "^1.0.0")]);
        let trans_old_tar = make_tarball("trans-old", "1.0.0", &[]);
        let trans_new_tar = make_tarball("trans-new", "1.0.0", &[]);

        let a_100_int = Integrity::from_bytes(&pkg_a_100_tar, Algorithm::Sha512).to_string();
        let a_110_int = Integrity::from_bytes(&pkg_a_110_tar, Algorithm::Sha512).to_string();
        let old_int = Integrity::from_bytes(&trans_old_tar, Algorithm::Sha512).to_string();
        let new_int = Integrity::from_bytes(&trans_new_tar, Algorithm::Sha512).to_string();

        let a_100_tar_c = pkg_a_100_tar.clone();
        let a_110_tar_c = pkg_a_110_tar.clone();
        let trans_old_tar_c = trans_old_tar.clone();
        let trans_new_tar_c = trans_new_tar.clone();

        let a_100_int_c = a_100_int.clone();
        let a_110_int_c = a_110_int.clone();
        let old_int_c = old_int.clone();
        let new_int_c = new_int.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{local_addr}/");
        let su1 = server_url.clone();
        let su2 = server_url.clone();
        let su3 = server_url.clone();
        let su4 = server_url.clone();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let a_100_int_c = a_100_int_c.clone();
                            let a_110_int_c = a_110_int_c.clone();
                            let old_int_c = old_int_c.clone();
                            let new_int_c = new_int_c.clone();
                            let a_100_tar_c = a_100_tar_c.clone();
                            let a_110_tar_c = a_110_tar_c.clone();
                            let trans_old_tar_c = trans_old_tar_c.clone();
                            let trans_new_tar_c = trans_new_tar_c.clone();
                            let su1 = su1.clone();
                            let su2 = su2.clone();
                            let su3 = su3.clone();
                            let su4 = su4.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /pkg-a") {
                                        let json = serde_json::json!({
                                            "name": "pkg-a",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "pkg-a",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su1}tarballs/pkg-a-1.0.0.tgz"),
                                                        "integrity": a_100_int_c
                                                    },
                                                    "dependencies": { "trans-old": "^1.0.0" }
                                                },
                                                "1.1.0": {
                                                    "name": "pkg-a",
                                                    "version": "1.1.0",
                                                    "dist": {
                                                        "tarball": format!("{su2}tarballs/pkg-a-1.1.0.tgz"),
                                                        "integrity": a_110_int_c
                                                    },
                                                    "dependencies": { "trans-new": "^1.0.0" }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /trans-old") {
                                        let json = serde_json::json!({
                                            "name": "trans-old",
                                            "dist-tags": { "latest": "1.0.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "trans-old",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su3}tarballs/trans-old-1.0.0.tgz"),
                                                        "integrity": old_int_c
                                                    }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /trans-new") {
                                        let json = serde_json::json!({
                                            "name": "trans-new",
                                            "dist-tags": { "latest": "1.0.0" },
                                            "versions": {
                                                "1.0.0": {
                                                    "name": "trans-new",
                                                    "version": "1.0.0",
                                                    "dist": {
                                                        "tarball": format!("{su4}tarballs/trans-new-1.0.0.tgz"),
                                                        "integrity": new_int_c
                                                    }
                                                }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/pkg-a-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_100_tar_c)
                                    } else if req_str.contains("GET /tarballs/pkg-a-1.1.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_110_tar_c)
                                    } else if req_str.contains("GET /tarballs/trans-old-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], trans_old_tar_c)
                                    } else if req_str.contains("GET /tarballs/trans-new-1.0.0.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], trans_new_tar_c)
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

        // 1. Initial state: package.json has "pkg-a": "^1.0.0"
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0"
            }
        }"#).unwrap();

        // Initial lockfile pinned to 1.0.0 and trans-old
        let mut initial_lock = LockfileV3::new("test-project", Some("1.0.0".to_string()));
        if let Some(root) = initial_lock.root_package_mut() {
            let mut d = BTreeMap::new();
            d.insert("pkg-a".to_string(), "^1.0.0".to_string());
            root.dependencies = Some(d);
        }
        let mut a_entry = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-a-1.0.0.tgz")),
            integrity: Some(a_100_int.clone()),
            ..Default::default()
        };
        let mut a_deps = BTreeMap::new();
        a_deps.insert("trans-old".to_string(), "^1.0.0".to_string());
        a_entry.dependencies = Some(a_deps);
        initial_lock.insert_package("node_modules/pkg-a", a_entry);

        let old_entry = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/trans-old-1.0.0.tgz")),
            integrity: Some(old_int.clone()),
            ..Default::default()
        };
        initial_lock.insert_package("node_modules/trans-old", old_entry);

        let lock_path = project_dir.path().join("package-lock.json");
        initial_lock.save_to_file(&lock_path).unwrap();

        // Dummy initial node_modules/trans-old on disk
        let old_dir = project_dir.path().join("node_modules/trans-old");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("package.json"), "{}").unwrap();

        // 2. Run update (all dependencies)
        let options = InstallOptions {
            project_dir: project_dir.path().to_path_buf(),
            registry_url: Some(server_url.clone()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            offline: false,
            ignore_scripts: true,
        };

        let mut installer = Installer::new(options).unwrap();
        let summary = installer.update(&[]).await.unwrap();

        assert_eq!(summary.packages_updated, 1);
        assert_eq!(summary.updated_packages, vec!["pkg-a"]);
        assert_eq!(summary.old_versions.get("pkg-a"), Some(&"1.0.0".to_string()));
        assert_eq!(summary.new_versions.get("pkg-a"), Some(&"1.1.0".to_string()));

        // Verify lockfile rewritten deterministically
        let updated_lock = LockfileV3::load_from_file(&lock_path).unwrap();
        let updated_a = updated_lock.get_package("node_modules/pkg-a").unwrap();
        assert_eq!(updated_a.version, Some("1.1.0".to_string()));

        // Verify newly needed dependency trans-new is present in lockfile and node_modules
        assert!(updated_lock.get_package("node_modules/trans-new").is_some());
        assert!(project_dir.path().join("node_modules/trans-new/package.json").exists());

        // Verify superseded orphaned dependency trans-old is removed from lockfile and node_modules
        assert!(updated_lock.get_package("node_modules/trans-old").is_none());
        assert!(!project_dir.path().join("node_modules/trans-old").exists());

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn test_update_specific_package_filter() {
        let project_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();

        let pkg_a_tar = make_tarball("pkg-a", "1.1.0", &[]);
        let pkg_b_tar = make_tarball("pkg-b", "1.1.0", &[]);
        let a_int = Integrity::from_bytes(&pkg_a_tar, Algorithm::Sha512).to_string();
        let b_int = Integrity::from_bytes(&pkg_b_tar, Algorithm::Sha512).to_string();

        let a_tar_c = pkg_a_tar.clone();
        let b_tar_c = pkg_b_tar.clone();
        let a_int_c = a_int.clone();
        let b_int_c = b_int.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{local_addr}/");
        let su1 = server_url.clone();
        let su2 = server_url.clone();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let a_int_c = a_int_c.clone();
                            let b_int_c = b_int_c.clone();
                            let a_tar_c = a_tar_c.clone();
                            let b_tar_c = b_tar_c.clone();
                            let su1 = su1.clone();
                            let su2 = su2.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = if req_str.contains("GET /pkg-a") {
                                        let json = serde_json::json!({
                                            "name": "pkg-a",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": { "name": "pkg-a", "version": "1.0.0", "dist": { "tarball": format!("{su1}tarballs/pkg-a.tgz"), "integrity": a_int_c } },
                                                "1.1.0": { "name": "pkg-a", "version": "1.1.0", "dist": { "tarball": format!("{su1}tarballs/pkg-a.tgz"), "integrity": a_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /pkg-b") {
                                        let json = serde_json::json!({
                                            "name": "pkg-b",
                                            "dist-tags": { "latest": "1.1.0" },
                                            "versions": {
                                                "1.0.0": { "name": "pkg-b", "version": "1.0.0", "dist": { "tarball": format!("{su2}tarballs/pkg-b.tgz"), "integrity": b_int_c } },
                                                "1.1.0": { "name": "pkg-b", "version": "1.1.0", "dist": { "tarball": format!("{su2}tarballs/pkg-b.tgz"), "integrity": b_int_c } }
                                            }
                                        });
                                        (200, vec![("Content-Type", String::from("application/json"))], serde_json::to_vec(&json).unwrap())
                                    } else if req_str.contains("GET /tarballs/pkg-a.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], a_tar_c)
                                    } else if req_str.contains("GET /tarballs/pkg-b.tgz") {
                                        (200, vec![("Content-Type", String::from("application/octet-stream"))], b_tar_c)
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

        // package.json defines pkg-a and pkg-b
        let pkg_json = project_dir.path().join("package.json");
        std::fs::write(&pkg_json, r#"{
            "name": "test-multi",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "^1.0.0",
                "pkg-b": "^1.0.0"
            }
        }"#).unwrap();

        // Lockfile has both at 1.0.0
        let mut lock = LockfileV3::new("test-multi", Some("1.0.0".to_string()));
        let mut d = BTreeMap::new();
        d.insert("pkg-a".to_string(), "^1.0.0".to_string());
        d.insert("pkg-b".to_string(), "^1.0.0".to_string());
        lock.root_package_mut().unwrap().dependencies = Some(d);

        lock.insert_package("node_modules/pkg-a", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-a.tgz")),
            integrity: Some(a_int),
            ..Default::default()
        });
        lock.insert_package("node_modules/pkg-b", LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(format!("{server_url}tarballs/pkg-b.tgz")),
            integrity: Some(b_int),
            ..Default::default()
        });
        let lock_path = project_dir.path().join("package-lock.json");
        lock.save_to_file(&lock_path).unwrap();

        let options = InstallOptions {
            project_dir: project_dir.path().to_path_buf(),
            registry_url: Some(server_url.clone()),
            cache_dir: Some(cache_dir.path().to_path_buf()),
            offline: false,
            ignore_scripts: true,
        };

        let mut installer = Installer::new(options).unwrap();
        // Update ONLY pkg-a
        let summary = installer.update(&["pkg-a".to_string()]).await.unwrap();

        assert_eq!(summary.packages_updated, 1);
        assert_eq!(summary.updated_packages, vec!["pkg-a"]);

        let reloaded = LockfileV3::load_from_file(&lock_path).unwrap();
        assert_eq!(reloaded.get_package("node_modules/pkg-a").unwrap().version, Some("1.1.0".to_string()));
        // pkg-b remains at 1.0.0!
        assert_eq!(reloaded.get_package("node_modules/pkg-b").unwrap().version, Some("1.0.0".to_string()));

        let _ = tx.send(());
    }
