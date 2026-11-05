use std::net::SocketAddr;
use std::sync::Arc;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::LockfileV3;

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{}", rel_path);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .expect("Failed to append tar entry");
        }
        builder.finish().expect("Failed to finish tar archive");
    }
    gz.finish().expect("Failed to finish gzip compression")
}

fn compute_ssri(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("sha512-{}", data_encoding::BASE64.encode(&hash))
}

struct TestRegistryServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestRegistryServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();

                                    let (status, headers, body) = match handler_clone(&path, &base_url) {
                                        Some(resp) => resp,
                                        None => (404, vec![("Content-Type", "text/plain".to_string())], b"Not Found".to_vec()),
                                    };

                                    let status_text = match status {
                                        200 => "OK",
                                        404 => "Not Found",
                                        500 => "Internal Server Error",
                                        _ => "Response",
                                    };

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

        Self {
            addr,
            _shutdown: tx,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

#[tokio::test]
async fn test_default_peer_resolution_auto_installs_matching_peer() {
    let peer_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"1.0.0"}"#),
        ("index.js", b"module.exports = 'pkg-peer-v1';"),
    ]);
    let peer_integrity = compute_ssri(&peer_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'pkg-parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-peer","version":"1.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-1.0.0.tgz","integrity":"{peer_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-peer-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer_tarball.clone()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-parent-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_tarball.clone()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-peer-auto-install",
        "version": "1.0.0",
        "dependencies": {
            "pkg-parent": "^1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        legacy_peer_deps: false,
        strict_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 2);

    // Verify both packages exist in node_modules
    assert!(temp_proj.path().join("node_modules").join("pkg-parent").join("index.js").exists());
    assert!(temp_proj.path().join("node_modules").join("pkg-peer").join("index.js").exists());

    // Verify lockfile v3 records pkg-peer with peer: true
    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    let peer_lock = lockfile.get_package("node_modules/pkg-peer").expect("pkg-peer in lockfile");
    assert_eq!(peer_lock.peer, Some(true));
}

#[tokio::test]
async fn test_peer_dependency_conflict_fails_with_eresolve_by_default() {
    let peer1_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"1.0.0"}"#),
    ]);
    let peer1_integrity = compute_ssri(&peer1_tarball);

    let peer2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"2.0.0"}"#),
    ]);
    let peer2_integrity = compute_ssri(&peer2_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"2.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-peer","version":"1.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-1.0.0.tgz","integrity":"{peer1_integrity}"}}}},"2.0.0":{{"name":"pkg-peer","version":"2.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-2.0.0.tgz","integrity":"{peer2_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-peer-conflict-default",
        "version": "1.0.0",
        "dependencies": {
            "pkg-peer": "2.0.0",
            "pkg-parent": "1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    // Default mode: legacy_peer_deps: false, strict_peer_deps: false
    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        legacy_peer_deps: false,
        strict_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("ERESOLVE"), "Default peer resolution must fail with ERESOLVE on unresolvable peer conflict, got: {err_str}");
    assert!(err_str.contains("Conflicting peer dependency 'pkg-peer'"));
}

#[tokio::test]
async fn test_strict_peer_deps_fails_on_peer_conflict() {
    let peer2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"2.0.0"}"#),
    ]);
    let peer2_integrity = compute_ssri(&peer2_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"2.0.0"}},"versions":{{"2.0.0":{{"name":"pkg-peer","version":"2.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-2.0.0.tgz","integrity":"{peer2_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-strict-peer-fail",
        "version": "1.0.0",
        "dependencies": {
            "pkg-peer": "2.0.0",
            "pkg-parent": "1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        strict_peer_deps: true,
        legacy_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("ERESOLVE"), "strict_peer_deps must fail with ERESOLVE on peer conflict");
}

#[tokio::test]
async fn test_legacy_peer_deps_bypasses_peer_conflict() {
    let peer2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"2.0.0"}"#),
        ("index.js", b"module.exports = 'pkg-peer-v2';"),
    ]);
    let peer2_integrity = compute_ssri(&peer2_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'pkg-parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"2.0.0"}},"versions":{{"2.0.0":{{"name":"pkg-peer","version":"2.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-2.0.0.tgz","integrity":"{peer2_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-peer-2.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer2_tarball.clone()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-parent-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_tarball.clone()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-legacy-peer-bypass",
        "version": "1.0.0",
        "dependencies": {
            "pkg-peer": "2.0.0",
            "pkg-parent": "1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        legacy_peer_deps: true,
        strict_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.expect("legacy_peer_deps must succeed despite conflicting peer dependency");
    assert_eq!(summary.packages_installed, 2);

    assert!(temp_proj.path().join("node_modules").join("pkg-parent").join("index.js").exists());
    assert!(temp_proj.path().join("node_modules").join("pkg-peer").join("index.js").exists());

    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    let peer_entry = lockfile.get_package("node_modules/pkg-peer").unwrap();
    assert_eq!(peer_entry.version, Some("2.0.0".to_string()));
}

#[tokio::test]
async fn test_omit_peer_resolves_lockfile_but_omits_disk_extraction() {
    let peer_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"1.0.0"}"#),
        ("index.js", b"module.exports = 'pkg-peer';"),
    ]);
    let peer_integrity = compute_ssri(&peer_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'pkg-parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-peer","version":"1.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-1.0.0.tgz","integrity":"{peer_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-peer-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer_tarball.clone()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-parent-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_tarball.clone()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-omit-peer-decoupled",
        "version": "1.0.0",
        "dependencies": {
            "pkg-parent": "^1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        omit_peer: true,
        legacy_peer_deps: false,
        strict_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    // Only pkg-parent is written to disk! pkg-peer must be omitted from node_modules
    assert!(temp_proj.path().join("node_modules").join("pkg-parent").join("index.js").exists());
    assert!(
        !temp_proj.path().join("node_modules").join("pkg-peer").exists(),
        "pkg-peer must NOT be extracted to disk when omit_peer is true"
    );

    // BUT lockfile v3 still contains pkg-peer!
    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    assert!(lockfile.packages.contains_key("node_modules/pkg-peer"), "Lockfile must contain pkg-peer even with omit_peer: true");
    let peer_entry = lockfile.get_package("node_modules/pkg-peer").unwrap();
    assert_eq!(peer_entry.peer, Some(true));
}

#[tokio::test]
async fn test_omit_peer_does_not_mask_peer_conflict() {
    let peer1_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"1.0.0"}"#),
    ]);
    let peer1_integrity = compute_ssri(&peer1_tarball);

    let peer2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"2.0.0"}"#),
        ("index.js", b"module.exports = 'pkg-peer-v2';"),
    ]);
    let peer2_integrity = compute_ssri(&peer2_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'pkg-parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"2.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-peer","version":"1.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-1.0.0.tgz","integrity":"{peer1_integrity}"}}}},"2.0.0":{{"name":"pkg-peer","version":"2.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-2.0.0.tgz","integrity":"{peer2_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-parent-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_tarball.clone()))
        } else if path == "/tarballs/pkg-peer-2.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer2_tarball.clone()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-omit-peer-conflict",
        "version": "1.0.0",
        "dependencies": {
            "pkg-peer": "2.0.0",
            "pkg-parent": "1.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    // omit_peer is true, but legacy_peer_deps is false -> MUST FAIL WITH ERESOLVE!
    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        omit_peer: true,
        legacy_peer_deps: false,
        ..Default::default()
    }).unwrap();

    let err = installer.run().await.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("ERESOLVE"),
        "omit_peer must not mask peer conflicts; expected ERESOLVE, got: {err_str}"
    );

    // Now, if legacy_peer_deps: true is explicitly provided along with omit_peer, it MUST succeed
    let mut legacy_installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        omit_peer: true,
        legacy_peer_deps: true,
        ..Default::default()
    }).unwrap();

    let summary = legacy_installer.run().await.expect("omit_peer + legacy_peer_deps must succeed");
    assert!(summary.packages_installed > 0);
}

#[tokio::test]
async fn test_peer_conflict_resolved_by_manifest_overrides() {
    let peer2_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-peer","version":"2.0.0"}"#),
        ("index.js", b"module.exports = 'pkg-peer-v2';"),
    ]);
    let peer2_integrity = compute_ssri(&peer2_tarball);

    let parent_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-parent","version":"1.0.0","peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'pkg-parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/pkg-peer" {
            let body = format!(
                r#"{{"name":"pkg-peer","dist-tags":{{"latest":"2.0.0"}},"versions":{{"2.0.0":{{"name":"pkg-peer","version":"2.0.0","dist":{{"tarball":"{base_url}/tarballs/pkg-peer-2.0.0.tgz","integrity":"{peer2_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-peer-2.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer2_tarball.clone()))
        } else if path == "/pkg-parent" {
            let body = format!(
                r#"{{"name":"pkg-parent","dist-tags":{{"latest":"1.0.0"}},"versions":{{"1.0.0":{{"name":"pkg-parent","version":"1.0.0","peerDependencies":{{"pkg-peer":"^1.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/pkg-parent-1.0.0.tgz","integrity":"{parent_integrity}"}}}}}}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/pkg-parent-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_tarball.clone()))
        } else {
            None
        }
    }).await;

    let temp_proj = tempfile::tempdir().unwrap();
    let temp_cache = tempfile::tempdir().unwrap();

    let root_pkg_json = r#"{
        "name": "test-peer-override",
        "version": "1.0.0",
        "dependencies": {
            "pkg-peer": "2.0.0",
            "pkg-parent": "1.0.0"
        },
        "overrides": {
            "pkg-peer": "2.0.0"
        }
    }"#;
    std::fs::write(temp_proj.path().join("package.json"), root_pkg_json).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        offline: false,
        ..Default::default()
    }).unwrap();

    let summary = installer.run().await.expect("Overrides must resolve peer dependency conflict under default peer resolution");
    assert_eq!(summary.packages_installed, 2);

    assert!(temp_proj.path().join("node_modules").join("pkg-parent").join("index.js").exists());
    assert!(temp_proj.path().join("node_modules").join("pkg-peer").join("index.js").exists());
}
