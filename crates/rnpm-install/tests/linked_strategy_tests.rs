use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_fs::junction::{is_junction, junction_points_to};
use rnpm_install::{InstallOptions, InstallStrategy, Installer};
use rnpm_lockfile::LockfileV3;
use rnpm_registry::client::RegistryClient;

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{}", rel_path);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
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
        F: Fn(&str, &str) -> Option<(u16, Vec<(&'static str, String)>, Vec<u8>)>
            + Send
            + Sync
            + 'static,
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
async fn test_linked_install_creates_junctions_to_global_store() {
    let pkg_b_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-b","version":"2.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'b-v2';"),
    ]);
    let pkg_b_integrity = compute_ssri(&pkg_b_tarball);

    let pkg_a_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-a","version":"1.0.0","dependencies":{"pkg-b":"^2.0.0"}}"#,
        ),
        (
            "index.js",
            b"module.exports = require('pkg-b') + '-from-a';",
        ),
    ]);
    let pkg_a_integrity = compute_ssri(&pkg_a_tarball);

    let b_tar_clone = pkg_b_tarball.clone();
    let a_tar_clone = pkg_a_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/pkg-a" => {
            let packument = serde_json::json!({
                "name": "pkg-a",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-a",
                        "version": "1.0.0",
                        "dependencies": { "pkg-b": "^2.0.0" },
                        "dist": {
                            "tarball": format!("{}/pkg-a-1.0.0.tgz", base_url),
                            "integrity": pkg_a_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-b" => {
            let packument = serde_json::json!({
                "name": "pkg-b",
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "2.0.0": {
                        "name": "pkg-b",
                        "version": "2.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-b-2.0.0.tgz", base_url),
                            "integrity": pkg_b_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-a-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            a_tar_clone.clone(),
        )),
        "/pkg-b-2.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            b_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "linked-demo-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": "^1.0.0"
        }
    });

    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ignore_scripts: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    assert!(summary.packages_installed > 0);

    let node_modules = temp_proj.path().join("node_modules");
    let pkg_a_link = node_modules.join("pkg-a");

    // 1. node_modules/pkg-a must be an NTFS junction or symlink
    assert!(pkg_a_link.exists(), "node_modules/pkg-a must exist");
    assert!(
        is_junction(&pkg_a_link).unwrap(),
        "node_modules/pkg-a must be an NTFS junction"
    );

    // 2. Read package.json through the junction
    let a_manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(pkg_a_link.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(a_manifest["name"], "pkg-a");
    assert_eq!(a_manifest["version"], "1.0.0");

    // 3. Verify files are stored in global linked store
    let store_dir = temp_store.path().join("linked");
    assert!(
        store_dir.exists(),
        "Global linked store directory must exist"
    );

    // 4. Verify package-lock.json exists and lists dependencies
    let lockfile = LockfileV3::load_from_file(&temp_proj.path().join("package-lock.json")).unwrap();
    assert!(lockfile.packages.contains_key("node_modules/pkg-a"));
}

#[tokio::test]
async fn test_linked_ci_with_bin_execution() {
    let cli_tool_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{
            "name": "my-cli-tool",
            "version": "1.2.3",
            "bin": { "my-tool": "./bin/run.js" }
        }"#,
        ),
        ("bin/run.js", b"console.log('HELLO_FROM_LINKED_BIN');"),
    ]);
    let cli_tool_integrity = compute_ssri(&cli_tool_tarball);
    let cli_tar_clone = cli_tool_tarball.clone();

    let server = TestRegistryServer::start(move |path, _base_url| match path {
        "/my-cli-tool-1.2.3.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            cli_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "linked-bin-app",
        "version": "1.0.0",
        "dependencies": {
            "my-cli-tool": "^1.2.3"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "linked-bin-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "linked-bin-app",
                "version": "1.0.0",
                "dependencies": {
                    "my-cli-tool": "^1.2.3"
                }
            },
            "node_modules/my-cli-tool": {
                "version": "1.2.3",
                "resolved": format!("{}/my-cli-tool-1.2.3.tgz", server.url()),
                "integrity": cli_tool_integrity,
                "bin": {
                    "my-tool": "./bin/run.js"
                }
            }
        }
    });
    fs::write(
        temp_proj.path().join("package-lock.json"),
        lockfile_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run_ci().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let node_modules = temp_proj.path().join("node_modules");
    let tool_link = node_modules.join("my-cli-tool");
    assert!(
        is_junction(&tool_link).unwrap(),
        "my-cli-tool in node_modules must be an NTFS junction"
    );

    // Verify .bin shim creation
    let bin_dir = node_modules.join(".bin");
    assert!(bin_dir.join("my-tool.cmd").exists() || bin_dir.join("my-tool").exists());

    // Execute bin shim using node (if node is available)
    if let Ok(output) = std::process::Command::new("node")
        .arg(tool_link.join("bin/run.js"))
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("HELLO_FROM_LINKED_BIN"),
            "Script execution via junction failed: {stdout}"
        );
    }
}

#[test]
fn test_cross_directory_junction_and_target_access() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let target_dir = dir_a.path().join("store-package");
    fs::create_dir_all(&target_dir).unwrap();
    fs::write(target_dir.join("data.txt"), "TARGET_DATA_123").unwrap();

    let link_dir = dir_b
        .path()
        .join("linked-node-modules")
        .join("package-link");
    rnpm_install::create_or_replace_junction(&link_dir, &target_dir).unwrap();

    assert!(is_junction(&link_dir).unwrap());
    let read_back = fs::read_to_string(link_dir.join("data.txt")).unwrap();
    assert_eq!(read_back, "TARGET_DATA_123");
}

#[test]
fn test_cross_volume_junction_simulation() {
    // If both C: and D: volumes are accessible on this Windows system, verify cross-volume junction
    let c_dir = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);
    let d_dir = if Path::new("D:\\").exists() {
        Some(PathBuf::from("D:\\npm-rust\\target\\tmp_cross_test"))
    } else {
        None
    };

    if let (Some(c_root), Some(d_root)) = (c_dir, d_dir) {
        let store_dir = c_root.join("rnpm_test_cross_volume_store");
        let proj_dir = d_root.join("rnpm_test_cross_volume_proj");

        let _ = fs::create_dir_all(&store_dir);
        let _ = fs::create_dir_all(&proj_dir);

        let target = store_dir.join("payload");
        let link = proj_dir.join("junction_link");

        let _ = fs::create_dir_all(&target);
        let _ = fs::write(target.join("file.txt"), "CROSS_VOLUME_SUCCESS");

        if let Ok(()) = rnpm_install::create_or_replace_junction(&link, &target) {
            assert!(is_junction(&link).unwrap());
            let read_res = fs::read_to_string(link.join("file.txt")).unwrap();
            assert_eq!(read_res, "CROSS_VOLUME_SUCCESS");
            let _ = rnpm_fs::junction::remove_junction(&link);
        }

        let _ = fs::remove_dir_all(&store_dir);
        let _ = fs::remove_dir_all(&proj_dir);
    }
}

#[tokio::test]
async fn test_native_addon_fallback_to_per_project_copy() {
    let addon_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{
            "name": "native-addon",
            "version": "1.0.0",
            "scripts": { "install": "node-gyp rebuild" }
        }"#,
        ),
        ("binding.gyp", b"{}"),
        ("index.js", b"module.exports = 'native';"),
    ]);
    let addon_integrity = compute_ssri(&addon_tarball);
    let addon_tar_clone = addon_tarball.clone();

    let server = TestRegistryServer::start(move |path, _base_url| match path {
        "/native-addon-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            addon_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "native-addon-app",
        "version": "1.0.0",
        "dependencies": {
            "native-addon": "1.0.0"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "native-addon-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "native-addon-app",
                "version": "1.0.0",
                "dependencies": {
                    "native-addon": "1.0.0"
                }
            },
            "node_modules/native-addon": {
                "version": "1.0.0",
                "resolved": format!("{}/native-addon-1.0.0.tgz", server.url()),
                "integrity": addon_integrity,
                "hasInstallScript": true
            }
        }
    });
    fs::write(
        temp_proj.path().join("package-lock.json"),
        lockfile_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        ignore_scripts: true,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run_ci().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let node_modules = temp_proj.path().join("node_modules");
    let addon_dir = node_modules.join("native-addon");
    assert!(
        addon_dir.exists(),
        "native-addon directory must exist in node_modules"
    );

    // Native addon must fall back to a per-project directory copy, NOT a junction
    assert!(
        !is_junction(&addon_dir).unwrap(),
        "Native addon must not be a junction (must be a per-project copy)"
    );
    assert!(addon_dir.join("binding.gyp").exists());
}

#[test]
fn test_compute_deps_hash_integrity_and_versions() {
    use rnpm_install::compute_deps_hash;
    use std::collections::BTreeMap;

    // 1. Identical inputs produce identical hashes
    let mut deps1 = BTreeMap::new();
    deps1.insert(
        "foo".to_string(),
        ("1.0.0".to_string(), Some("sha512-abc1".to_string())),
    );
    deps1.insert(
        "bar".to_string(),
        ("2.0.0".to_string(), Some("sha512-xyz2".to_string())),
    );

    let mut deps2 = BTreeMap::new();
    deps2.insert(
        "foo".to_string(),
        ("1.0.0".to_string(), Some("sha512-abc1".to_string())),
    );
    deps2.insert(
        "bar".to_string(),
        ("2.0.0".to_string(), Some("sha512-xyz2".to_string())),
    );

    assert_eq!(compute_deps_hash(&deps1), compute_deps_hash(&deps2));

    // 2. Differing integrity hashes produce differing deps hashes
    let mut deps_diff_integ = BTreeMap::new();
    deps_diff_integ.insert(
        "foo".to_string(),
        ("1.0.0".to_string(), Some("sha512-DIFFERENT".to_string())),
    );
    deps_diff_integ.insert(
        "bar".to_string(),
        ("2.0.0".to_string(), Some("sha512-xyz2".to_string())),
    );

    assert_ne!(
        compute_deps_hash(&deps1),
        compute_deps_hash(&deps_diff_integ)
    );

    // 3. Differing versions produce differing deps hashes
    let mut deps_diff_ver = BTreeMap::new();
    deps_diff_ver.insert(
        "foo".to_string(),
        ("1.0.1".to_string(), Some("sha512-abc1".to_string())),
    );
    deps_diff_ver.insert(
        "bar".to_string(),
        ("2.0.0".to_string(), Some("sha512-xyz2".to_string())),
    );

    assert_ne!(compute_deps_hash(&deps1), compute_deps_hash(&deps_diff_ver));

    // 4. Differing dependency names produce differing deps hashes
    let mut deps_diff_name = BTreeMap::new();
    deps_diff_name.insert(
        "foo-alt".to_string(),
        ("1.0.0".to_string(), Some("sha512-abc1".to_string())),
    );
    deps_diff_name.insert(
        "bar".to_string(),
        ("2.0.0".to_string(), Some("sha512-xyz2".to_string())),
    );

    assert_ne!(
        compute_deps_hash(&deps1),
        compute_deps_hash(&deps_diff_name)
    );
}

#[tokio::test]
async fn test_linked_install_and_ci_workspaces() {
    let pkg_b_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-b","version":"1.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'b';"),
    ]);
    let pkg_b_integrity = compute_ssri(&pkg_b_tarball);
    let b_tar_clone = pkg_b_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/pkg-b" => {
            let packument = serde_json::json!({
                "name": "pkg-b",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-b",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-b-1.0.0.tgz", base_url),
                            "integrity": pkg_b_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-b-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            b_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    // Setup monorepo with workspace package 'pkg-a'
    let root_pkg_json = serde_json::json!({
        "name": "workspace-monorepo",
        "version": "1.0.0",
        "workspaces": ["packages/*"],
        "dependencies": {
            "pkg-b": "^1.0.0"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let pkg_a_dir = temp_proj.path().join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    let pkg_a_json = serde_json::json!({
        "name": "pkg-a",
        "version": "1.0.0",
        "dependencies": {}
    });
    fs::write(pkg_a_dir.join("package.json"), pkg_a_json.to_string()).unwrap();
    fs::write(
        pkg_a_dir.join("index.js"),
        "module.exports = 'local-pkg-a';",
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    assert!(summary.packages_installed > 0);

    let node_modules = temp_proj.path().join("node_modules");
    let pkg_a_link = node_modules.join("pkg-a");
    let pkg_b_link = node_modules.join("pkg-b");

    // 1. Workspace member pkg-a must be an NTFS junction linking to local packages/pkg-a
    assert!(pkg_a_link.exists(), "node_modules/pkg-a must exist");
    assert!(
        is_junction(&pkg_a_link).unwrap(),
        "node_modules/pkg-a must be an NTFS junction"
    );
    let a_content = fs::read_to_string(pkg_a_link.join("index.js")).unwrap();
    assert_eq!(a_content, "module.exports = 'local-pkg-a';");

    // 2. Registry dependency pkg-b must be an NTFS junction linking to store
    assert!(pkg_b_link.exists(), "node_modules/pkg-b must exist");
    assert!(
        is_junction(&pkg_b_link).unwrap(),
        "node_modules/pkg-b must be an NTFS junction"
    );

    // 3. Test CI execution with workspaces
    let mut ci_installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert!(ci_summary.packages_installed > 0);
    assert!(
        is_junction(&node_modules.join("pkg-a")).unwrap(),
        "pkg-a must remain junction in CI"
    );
}

#[tokio::test]
async fn test_stale_junction_and_hoisted_to_linked_cleanup() {
    let pkg_a_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-a","version":"1.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'a';"),
    ]);
    let pkg_a_integrity = compute_ssri(&pkg_a_tarball);
    let a_tar_clone = pkg_a_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/pkg-a" => {
            let packument = serde_json::json!({
                "name": "pkg-a",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-a",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-a-1.0.0.tgz", base_url),
                            "integrity": pkg_a_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-a-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            a_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let node_modules = temp_proj.path().join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();

    // 1. Simulate switching from hoisted to linked:
    // Create an old hoisted directory for pkg-a (normal dir, not junction)
    let hoisted_pkg_a = node_modules.join("pkg-a");
    fs::create_dir_all(&hoisted_pkg_a).unwrap();
    fs::write(
        hoisted_pkg_a.join("package.json"),
        r#"{"name":"pkg-a","version":"0.9.0"}"#,
    )
    .unwrap();

    // Create an old hoisted transitive package that is no longer in the graph
    let hoisted_transitive = node_modules.join("old-transitive");
    fs::create_dir_all(&hoisted_transitive).unwrap();
    fs::write(
        hoisted_transitive.join("package.json"),
        r#"{"name":"old-transitive","version":"1.0.0"}"#,
    )
    .unwrap();

    // Create a stale junction that was removed
    let stale_target = tempdir().unwrap();
    let stale_link = node_modules.join("stale-junction");
    rnpm_install::create_or_replace_junction(&stale_link, stale_target.path()).unwrap();
    assert!(is_junction(&stale_link).unwrap());

    // Project declares only pkg-a
    let root_pkg_json = serde_json::json!({
        "name": "cleanup-demo-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": "^1.0.0"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    assert!(summary.packages_installed > 0);

    // Verify old hoisted transitive package was removed
    assert!(
        !hoisted_transitive.exists(),
        "Old hoisted transitive directory must be cleaned up"
    );

    // Verify stale junction was removed
    assert!(
        !stale_link.exists(),
        "Stale junction must be unlinked and removed"
    );

    // Verify pkg-a is now an NTFS junction pointing to store (not the old directory)
    assert!(
        is_junction(&node_modules.join("pkg-a")).unwrap(),
        "pkg-a must now be an NTFS junction"
    );
}

#[tokio::test]
async fn test_linked_wiring_optional_and_peer_dependencies() {
    let pkg_dep_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-dep","version":"1.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'dep';"),
    ]);
    let pkg_dep_integrity = compute_ssri(&pkg_dep_tarball);
    let dep_tar_clone = pkg_dep_tarball.clone();

    let pkg_opt_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-opt","version":"1.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'opt';"),
    ]);
    let pkg_opt_integrity = compute_ssri(&pkg_opt_tarball);
    let opt_tar_clone = pkg_opt_tarball.clone();

    let pkg_peer_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"pkg-peer","version":"1.0.0","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'peer';"),
    ]);
    let pkg_peer_integrity = compute_ssri(&pkg_peer_tarball);
    let peer_tar_clone = pkg_peer_tarball.clone();

    let pkg_root_dep_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"pkg-root-dep","version":"1.0.0","dependencies":{"pkg-dep":"^1.0.0"},"optionalDependencies":{"pkg-opt":"^1.0.0"},"peerDependencies":{"pkg-peer":"^1.0.0"}}"#),
        ("index.js", b"module.exports = 'root-dep';"),
    ]);
    let pkg_root_dep_integrity = compute_ssri(&pkg_root_dep_tarball);
    let root_dep_tar_clone = pkg_root_dep_tarball.clone();

    let server = TestRegistryServer::start(move |path, base_url| match path {
        "/pkg-root-dep" => {
            let packument = serde_json::json!({
                "name": "pkg-root-dep",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-root-dep",
                        "version": "1.0.0",
                        "dependencies": { "pkg-dep": "^1.0.0" },
                        "optionalDependencies": { "pkg-opt": "^1.0.0" },
                        "peerDependencies": { "pkg-peer": "^1.0.0" },
                        "dist": {
                            "tarball": format!("{}/pkg-root-dep-1.0.0.tgz", base_url),
                            "integrity": pkg_root_dep_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-dep" => {
            let packument = serde_json::json!({
                "name": "pkg-dep",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-dep",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-dep-1.0.0.tgz", base_url),
                            "integrity": pkg_dep_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-opt" => {
            let packument = serde_json::json!({
                "name": "pkg-opt",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-opt",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-opt-1.0.0.tgz", base_url),
                            "integrity": pkg_opt_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-peer" => {
            let packument = serde_json::json!({
                "name": "pkg-peer",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "pkg-peer",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("{}/pkg-peer-1.0.0.tgz", base_url),
                            "integrity": pkg_peer_integrity
                        }
                    }
                }
            });
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                packument.to_string().into_bytes(),
            ))
        }
        "/pkg-root-dep-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            root_dep_tar_clone.clone(),
        )),
        "/pkg-dep-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            dep_tar_clone.clone(),
        )),
        "/pkg-opt-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            opt_tar_clone.clone(),
        )),
        "/pkg-peer-1.0.0.tgz" => Some((
            200,
            vec![("Content-Type", "application/octet-stream".to_string())],
            peer_tar_clone.clone(),
        )),
        _ => None,
    })
    .await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "opt-peer-wiring-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-root-dep": "^1.0.0",
            "pkg-peer": "^1.0.0"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    assert!(summary.packages_installed > 0);

    // Locate pkg-root-dep in global store and inspect its internal node_modules
    let store_root = temp_store.path().join("linked");
    let mut found_pkg_root_dep = false;
    for entry in fs::read_dir(&store_root).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("pkg-root-dep@1.0.0-") {
            found_pkg_root_dep = true;
            let inner_nm = entry.path().join("node_modules");
            // Must have junctions for dependencies (pkg-dep), optionalDependencies (pkg-opt), and peerDependencies (pkg-peer)
            assert!(
                inner_nm.join("pkg-dep").exists(),
                "pkg-dep junction must exist inside store entry node_modules"
            );
            assert!(
                is_junction(&inner_nm.join("pkg-dep")).unwrap(),
                "pkg-dep must be an NTFS junction"
            );

            assert!(
                inner_nm.join("pkg-opt").exists(),
                "pkg-opt junction must exist inside store entry node_modules"
            );
            assert!(
                is_junction(&inner_nm.join("pkg-opt")).unwrap(),
                "pkg-opt must be an NTFS junction"
            );

            assert!(
                inner_nm.join("pkg-peer").exists(),
                "pkg-peer junction must exist inside store entry node_modules"
            );
            assert!(
                is_junction(&inner_nm.join("pkg-peer")).unwrap(),
                "pkg-peer must be an NTFS junction"
            );
        }
    }
    assert!(
        found_pkg_root_dep,
        "pkg-root-dep entry must exist in global linked store"
    );
}

#[test]
fn test_transitive_hashing_and_poisoning_prevention() {
    use rnpm_install::{compute_transitive_deps_hashes, DepGraphNode};
    use std::collections::{BTreeMap, HashMap};

    // 1. Same package name and version, but different resolved URL or integrity
    let mut g1 = HashMap::new();
    g1.insert(
        "node_modules/lodash".to_string(),
        DepGraphNode {
            id: "node_modules/lodash".to_string(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            resolved_url: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string(),
            integrity: Some("sha512-good-integrity".to_string()),
            dependencies: BTreeMap::new(),
        },
    );

    let mut g2 = HashMap::new();
    g2.insert(
        "node_modules/lodash".to_string(),
        DepGraphNode {
            id: "node_modules/lodash".to_string(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            resolved_url: "https://adversarial.example.com/lodash.tgz".to_string(),
            integrity: Some("sha512-different-integrity".to_string()),
            dependencies: BTreeMap::new(),
        },
    );

    let h1 = compute_transitive_deps_hashes(&g1);
    let h2 = compute_transitive_deps_hashes(&g2);
    assert_ne!(
        h1["node_modules/lodash"], h2["node_modules/lodash"],
        "Differing resolved URL/integrity must yield different store hashes (prevent store poisoning)"
    );

    // 2. Transitive dependency tree difference propagates to parent
    let mut g3_tree_a = HashMap::new();
    g3_tree_a.insert(
        "node_modules/parent".to_string(),
        DepGraphNode {
            id: "node_modules/parent".to_string(),
            name: "parent".to_string(),
            version: "1.0.0".to_string(),
            resolved_url: "https://reg.org/parent-1.0.0.tgz".to_string(),
            integrity: Some("sha512-parent".to_string()),
            dependencies: BTreeMap::from([("child".to_string(), "node_modules/child".to_string())]),
        },
    );
    g3_tree_a.insert(
        "node_modules/child".to_string(),
        DepGraphNode {
            id: "node_modules/child".to_string(),
            name: "child".to_string(),
            version: "1.0.0".to_string(),
            resolved_url: "https://reg.org/child-1.0.0.tgz".to_string(),
            integrity: Some("sha512-child-v1".to_string()),
            dependencies: BTreeMap::from([(
                "grandchild".to_string(),
                "node_modules/grandchild".to_string(),
            )]),
        },
    );
    g3_tree_a.insert(
        "node_modules/grandchild".to_string(),
        DepGraphNode {
            id: "node_modules/grandchild".to_string(),
            name: "grandchild".to_string(),
            version: "1.0.0".to_string(),
            resolved_url: "https://reg.org/grandchild-1.0.0.tgz".to_string(),
            integrity: Some("sha512-gc-v1".to_string()),
            dependencies: BTreeMap::new(),
        },
    );

    let mut g3_tree_b = g3_tree_a.clone();
    g3_tree_b.insert(
        "node_modules/grandchild".to_string(),
        DepGraphNode {
            id: "node_modules/grandchild".to_string(),
            name: "grandchild".to_string(),
            version: "2.0.0".to_string(), // Grandchild version changed deeper down!
            resolved_url: "https://reg.org/grandchild-2.0.0.tgz".to_string(),
            integrity: Some("sha512-gc-v2".to_string()),
            dependencies: BTreeMap::new(),
        },
    );

    let h3_a = compute_transitive_deps_hashes(&g3_tree_a);
    let h3_b = compute_transitive_deps_hashes(&g3_tree_b);

    assert_ne!(h3_a["node_modules/child"], h3_b["node_modules/child"]);
    assert_ne!(
        h3_a["node_modules/parent"], h3_b["node_modules/parent"],
        "Deeper grandchild divergence must propagate transitively up to parent"
    );

    // 3. Cyclic dependency handling (A -> B -> A)
    let mut g_cycle = HashMap::new();
    g_cycle.insert(
        "node_modules/cycle-a".to_string(),
        DepGraphNode {
            id: "node_modules/cycle-a".to_string(),
            name: "cycle-a".to_string(),
            version: "1.0.0".to_string(),
            resolved_url: "https://reg.org/cycle-a.tgz".to_string(),
            integrity: Some("sha512-a".to_string()),
            dependencies: BTreeMap::from([(
                "cycle-b".to_string(),
                "node_modules/cycle-b".to_string(),
            )]),
        },
    );
    g_cycle.insert(
        "node_modules/cycle-b".to_string(),
        DepGraphNode {
            id: "node_modules/cycle-b".to_string(),
            name: "cycle-b".to_string(),
            version: "1.0.0".to_string(),
            resolved_url: "https://reg.org/cycle-b.tgz".to_string(),
            integrity: Some("sha512-b".to_string()),
            dependencies: BTreeMap::from([(
                "cycle-a".to_string(),
                "node_modules/cycle-a".to_string(),
            )]),
        },
    );

    let h_cycle = compute_transitive_deps_hashes(&g_cycle);
    assert!(h_cycle.contains_key("node_modules/cycle-a"));
    assert!(h_cycle.contains_key("node_modules/cycle-b"));
    assert_ne!(
        h_cycle["node_modules/cycle-a"],
        h_cycle["node_modules/cycle-b"]
    );

    // If one node in cycle changes integrity, all nodes in cycle get different hashes
    let mut g_cycle_mut = g_cycle.clone();
    g_cycle_mut
        .get_mut("node_modules/cycle-b")
        .unwrap()
        .integrity = Some("sha512-b-mutated".to_string());
    let h_cycle_mut = compute_transitive_deps_hashes(&g_cycle_mut);

    assert_ne!(
        h_cycle["node_modules/cycle-a"],
        h_cycle_mut["node_modules/cycle-a"]
    );
    assert_ne!(
        h_cycle["node_modules/cycle-b"],
        h_cycle_mut["node_modules/cycle-b"]
    );
}

#[test]
fn test_stale_junction_updated_to_new_target() {
    let dir = tempdir().unwrap();
    let old_target = dir
        .path()
        .join("store/pkg-a@1.0.0-OLDHASH/node_modules/pkg-a");
    let new_target = dir
        .path()
        .join("store/pkg-a@1.0.0-NEWHASH/node_modules/pkg-a");
    let link = dir.path().join("project/node_modules/pkg-a");

    fs::create_dir_all(&old_target).unwrap();
    fs::create_dir_all(&new_target).unwrap();
    fs::write(old_target.join("version.txt"), "old-v1").unwrap();
    fs::write(new_target.join("version.txt"), "new-v2").unwrap();

    // 1. Initial junction points to old_target
    rnpm_install::create_or_replace_junction(&link, &old_target).unwrap();
    assert!(is_junction(&link).unwrap());
    assert!(rnpm_fs::junction_points_to(&link, &old_target));
    assert!(!rnpm_fs::junction_points_to(&link, &new_target));
    assert_eq!(
        fs::read_to_string(link.join("version.txt")).unwrap(),
        "old-v1"
    );

    // 2. Stale junction is verified and updated to new_target
    if !rnpm_fs::junction_points_to(&link, &new_target) {
        rnpm_install::create_or_replace_junction(&link, &new_target).unwrap();
    }
    assert!(is_junction(&link).unwrap());
    assert!(rnpm_fs::junction_points_to(&link, &new_target));
    assert!(!rnpm_fs::junction_points_to(&link, &old_target));
    assert_eq!(
        fs::read_to_string(link.join("version.txt")).unwrap(),
        "new-v2"
    );

    // Old target files remain intact
    assert_eq!(
        fs::read_to_string(old_target.join("version.txt")).unwrap(),
        "old-v1"
    );
}

#[tokio::test]
async fn test_store_entry_marker_omitted_when_dependency_target_missing() {
    let tmp = tempdir().unwrap();
    let store_root = tmp.path().join("store");
    let cache_dir = tmp.path().join("cache");
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    let registry_client = RegistryClient::new().unwrap();

    // Create a valid tarball fixture for parent-pkg
    let parent_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"parent-pkg","version":"1.0.0","dependencies":{"missing-dep":"1.0.0"}}"#,
        ),
        ("index.js", b"module.exports = 'parent';"),
    ]);
    let parent_integrity = compute_ssri(&parent_tarball);
    let resolved_url = "https://registry.example.com/parent-pkg-1.0.0.tgz";
    cache
        .put_with_integrity(
            resolved_url,
            &parent_tarball,
            Some(&parent_integrity.parse().unwrap()),
            None,
        )
        .unwrap();

    let store_entry = store_root.join("parent-pkg@1.0.0-123456789abc");
    let pkg_store = store_entry.join("node_modules/parent-pkg");

    let mut dependencies = BTreeMap::new();
    // Non-existent target for missing-dep
    dependencies.insert(
        "missing-dep".to_string(),
        (
            "missing-dep".to_string(),
            "1.0.0".to_string(),
            "nonexistenthash".to_string(),
        ),
    );

    let plan = rnpm_install::StorePackagePlan {
        name: "parent-pkg".to_string(),
        version: "1.0.0".to_string(),
        resolved_url: resolved_url.to_string(),
        integrity: Some(parent_integrity),
        deps_hash: "123456789abc".to_string(),
        store_entry_dir: store_entry.clone(),
        pkg_store_dir: pkg_store.clone(),
        dependencies,
        is_optional: false,
        has_install_script: false,
    };

    let _ = rnpm_install::materialize_store_packages(&[plan], &cache, &registry_client, true).await;

    // Because missing-dep target did not exist, .rnpm-materialized marker MUST NOT be written
    // and failed store entry MUST be cleaned up!
    let marker = store_entry.join(".rnpm-materialized");
    assert!(
        !marker.exists(),
        "Marker must NOT be written when dependency targets fail to wire"
    );
    assert!(
        !store_entry.exists(),
        "Failed entry must be cleaned up when dependency targets fail to wire"
    );
}

#[tokio::test]
async fn test_linked_install_eslint_tree_store_junctions_and_verification() {
    // 1. Build tarballs for eslint-like package hierarchy:
    // ms@2.1.3 (leaf)
    let ms_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"ms","version":"2.1.3","dependencies":{}}"#,
        ),
        ("index.js", b"module.exports = 'ms-2.1.3';"),
    ]);
    let ms_integrity = compute_ssri(&ms_tarball);

    // fast-deep-equal@3.1.3 (leaf)
    let fde_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"fast-deep-equal","version":"3.1.3","dependencies":{}}"#,
        ),
        (
            "index.js",
            b"module.exports = function equal() { return true; };",
        ),
    ]);
    let fde_integrity = compute_ssri(&fde_tarball);

    // acorn@8.11.3 (leaf)
    let acorn_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"acorn","version":"8.11.3","dependencies":{}}"#,
        ),
        (
            "index.js",
            b"module.exports = { parse: function() { return {}; } };",
        ),
    ]);
    let acorn_integrity = compute_ssri(&acorn_tarball);

    // debug@4.3.4 (depends on ms)
    let debug_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"debug","version":"4.3.4","dependencies":{"ms":"^2.1.2"}}"#),
        ("index.js", b"const ms = require('ms'); module.exports = function(name) { return name + ':' + ms; };"),
    ]);
    let debug_integrity = compute_ssri(&debug_tarball);

    // ajv@6.12.6 (depends on fast-deep-equal)
    let ajv_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"ajv","version":"6.12.6","dependencies":{"fast-deep-equal":"^3.1.1"}}"#),
        ("index.js", b"const equal = require('fast-deep-equal'); module.exports = function Ajv() { return { equal }; };"),
    ]);
    let ajv_integrity = compute_ssri(&ajv_tarball);

    // espree@9.6.1 (depends on acorn)
    let espree_tarball = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"espree","version":"9.6.1","dependencies":{"acorn":"^8.9.0"}}"#,
        ),
        (
            "index.js",
            b"const acorn = require('acorn'); module.exports = { parse: acorn.parse };",
        ),
    ]);
    let espree_integrity = compute_ssri(&espree_tarball);

    // @eslint/eslintrc@2.1.4 (scoped package, depends on ajv, debug, espree)
    let eslintrc_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"@eslint/eslintrc","version":"2.1.4","dependencies":{"ajv":"^6.12.4","debug":"^4.3.2","espree":"^9.6.1"}}"#),
        ("index.js", b"const debug = require('debug')('eslintrc'); const ajv = require('ajv'); const espree = require('espree'); module.exports = { debug, ajv, espree };"),
    ]);
    let eslintrc_integrity = compute_ssri(&eslintrc_tarball);

    // eslint@8.57.0 (top-level package, depends on @eslint/eslintrc and espree)
    let eslint_tarball = create_test_tarball(&[
        ("package.json", br#"{"name":"eslint","version":"8.57.0","dependencies":{"@eslint/eslintrc":"^2.1.4","espree":"^9.6.1"}}"#),
        ("index.js", b"const rc = require('@eslint/eslintrc'); const espree = require('espree'); module.exports = { ESLint: function() { return { rc, espree }; } };"),
    ]);
    let eslint_integrity = compute_ssri(&eslint_tarball);

    // Clones for server closure
    let (ms_t, fde_t, acorn_t, debug_t, ajv_t, espree_t, eslintrc_t, eslint_t) = (
        ms_tarball.clone(),
        fde_tarball.clone(),
        acorn_tarball.clone(),
        debug_tarball.clone(),
        ajv_tarball.clone(),
        espree_tarball.clone(),
        eslintrc_tarball.clone(),
        eslint_tarball.clone(),
    );

    let server = TestRegistryServer::start(move |path, base_url| {
        match path {
            "/ms" => {
                let packument = serde_json::json!({
                    "name": "ms",
                    "dist-tags": { "latest": "2.1.3" },
                    "versions": {
                        "2.1.3": {
                            "name": "ms", "version": "2.1.3", "dependencies": {},
                            "dist": { "tarball": format!("{}/ms-2.1.3.tgz", base_url), "integrity": ms_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/fast-deep-equal" => {
                let packument = serde_json::json!({
                    "name": "fast-deep-equal",
                    "dist-tags": { "latest": "3.1.3" },
                    "versions": {
                        "3.1.3": {
                            "name": "fast-deep-equal", "version": "3.1.3", "dependencies": {},
                            "dist": { "tarball": format!("{}/fast-deep-equal-3.1.3.tgz", base_url), "integrity": fde_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/acorn" => {
                let packument = serde_json::json!({
                    "name": "acorn",
                    "dist-tags": { "latest": "8.11.3" },
                    "versions": {
                        "8.11.3": {
                            "name": "acorn", "version": "8.11.3", "dependencies": {},
                            "dist": { "tarball": format!("{}/acorn-8.11.3.tgz", base_url), "integrity": acorn_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/debug" => {
                let packument = serde_json::json!({
                    "name": "debug",
                    "dist-tags": { "latest": "4.3.4" },
                    "versions": {
                        "4.3.4": {
                            "name": "debug", "version": "4.3.4", "dependencies": { "ms": "^2.1.2" },
                            "dist": { "tarball": format!("{}/debug-4.3.4.tgz", base_url), "integrity": debug_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/ajv" => {
                let packument = serde_json::json!({
                    "name": "ajv",
                    "dist-tags": { "latest": "6.12.6" },
                    "versions": {
                        "6.12.6": {
                            "name": "ajv", "version": "6.12.6", "dependencies": { "fast-deep-equal": "^3.1.1" },
                            "dist": { "tarball": format!("{}/ajv-6.12.6.tgz", base_url), "integrity": ajv_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/espree" => {
                let packument = serde_json::json!({
                    "name": "espree",
                    "dist-tags": { "latest": "9.6.1" },
                    "versions": {
                        "9.6.1": {
                            "name": "espree", "version": "9.6.1", "dependencies": { "acorn": "^8.9.0" },
                            "dist": { "tarball": format!("{}/espree-9.6.1.tgz", base_url), "integrity": espree_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            p if p == "/@eslint/eslintrc" || p == "/@eslint%2feslintrc" || p == "/@eslint%2Feslintrc" => {
                let packument = serde_json::json!({
                    "name": "@eslint/eslintrc",
                    "dist-tags": { "latest": "2.1.4" },
                    "versions": {
                        "2.1.4": {
                            "name": "@eslint/eslintrc", "version": "2.1.4",
                            "dependencies": { "ajv": "^6.12.4", "debug": "^4.3.2", "espree": "^9.6.1" },
                            "dist": { "tarball": format!("{}/eslintrc-2.1.4.tgz", base_url), "integrity": eslintrc_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/eslint" => {
                let packument = serde_json::json!({
                    "name": "eslint",
                    "dist-tags": { "latest": "8.57.0" },
                    "versions": {
                        "8.57.0": {
                            "name": "eslint", "version": "8.57.0",
                            "dependencies": { "@eslint/eslintrc": "^2.1.4", "espree": "^9.6.1" },
                            "dist": { "tarball": format!("{}/eslint-8.57.0.tgz", base_url), "integrity": eslint_integrity }
                        }
                    }
                });
                Some((200, vec![("Content-Type", "application/json".to_string())], packument.to_string().into_bytes()))
            }
            "/ms-2.1.3.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], ms_t.clone())),
            "/fast-deep-equal-3.1.3.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], fde_t.clone())),
            "/acorn-8.11.3.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], acorn_t.clone())),
            "/debug-4.3.4.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], debug_t.clone())),
            "/ajv-6.12.6.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], ajv_t.clone())),
            "/espree-9.6.1.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], espree_t.clone())),
            "/eslintrc-2.1.4.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], eslintrc_t.clone())),
            "/eslint-8.57.0.tgz" => Some((200, vec![("Content-Type", "application/octet-stream".to_string())], eslint_t.clone())),
            _ => None,
        }
    }).await;

    let temp_proj = tempdir().unwrap();
    let temp_cache = tempdir().unwrap();
    let temp_store = tempdir().unwrap();

    let root_pkg_json = serde_json::json!({
        "name": "my-eslint-app",
        "version": "1.0.0",
        "dependencies": {
            "eslint": "^8.57.0"
        }
    });
    fs::write(
        temp_proj.path().join("package.json"),
        root_pkg_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.run().await.unwrap();
    assert!(summary.packages_installed > 0);

    let store_dir = temp_store.path().join("linked");

    // Helper to find store entry for a package name
    let find_store_entry = |pkg_name: &str| -> (PathBuf, PathBuf) {
        if pkg_name.starts_with('@') {
            let mut parts = pkg_name.split('/');
            let scope = parts.next().unwrap();
            let sub = parts.next().unwrap();
            let scope_dir = store_dir.join(scope);
            for entry in fs::read_dir(&scope_dir).unwrap().flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&format!("{sub}@")) {
                    let entry_dir = entry.path();
                    let pkg_dir = entry_dir.join("node_modules").join(pkg_name);
                    return (entry_dir, pkg_dir);
                }
            }
        } else {
            for entry in fs::read_dir(&store_dir).unwrap().flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&format!("{pkg_name}@")) {
                    let entry_dir = entry.path();
                    let pkg_dir = entry_dir.join("node_modules").join(pkg_name);
                    return (entry_dir, pkg_dir);
                }
            }
        }
        panic!("Store entry for {pkg_name} not found in {store_dir:?}");
    };

    let (eslint_entry, eslint_pkg) = find_store_entry("eslint");
    let (eslintrc_entry, eslintrc_pkg) = find_store_entry("@eslint/eslintrc");
    let (espree_entry, espree_pkg) = find_store_entry("espree");
    let (ajv_entry, ajv_pkg) = find_store_entry("ajv");
    let (debug_entry, debug_pkg) = find_store_entry("debug");
    let (acorn_entry, acorn_pkg) = find_store_entry("acorn");
    let (fde_entry, fde_pkg) = find_store_entry("fast-deep-equal");
    let (ms_entry, ms_pkg) = find_store_entry("ms");

    // 1. Verify all store entries have .rnpm-materialized marker
    for entry in &[
        &eslint_entry,
        &eslintrc_entry,
        &espree_entry,
        &ajv_entry,
        &debug_entry,
        &acorn_entry,
        &fde_entry,
        &ms_entry,
    ] {
        assert!(
            entry.join(".rnpm-materialized").exists(),
            "Entry {:?} must have .rnpm-materialized",
            entry
        );
    }

    // 2. Verify junctions in eslint/node_modules:
    // eslint declares @eslint/eslintrc and espree
    let eslint_nm = eslint_entry.join("node_modules");
    let eslint_eslintrc_link = eslint_nm.join("@eslint/eslintrc");
    let eslint_espree_link = eslint_nm.join("espree");

    assert!(
        is_junction(&eslint_eslintrc_link).unwrap(),
        "eslint/node_modules/@eslint/eslintrc must be a junction"
    );
    assert!(
        junction_points_to(&eslint_eslintrc_link, &eslintrc_pkg),
        "eslint/node_modules/@eslint/eslintrc junction must point to @eslint/eslintrc package store dir"
    );

    assert!(
        is_junction(&eslint_espree_link).unwrap(),
        "eslint/node_modules/espree must be a junction"
    );
    assert!(
        junction_points_to(&eslint_espree_link, &espree_pkg),
        "eslint/node_modules/espree junction must point to espree package store dir"
    );

    // 3. Verify junctions in @eslint/eslintrc/node_modules:
    // @eslint/eslintrc declares ajv, debug, espree
    let eslintrc_nm = eslintrc_entry.join("node_modules");
    let eslintrc_ajv_link = eslintrc_nm.join("ajv");
    let eslintrc_debug_link = eslintrc_nm.join("debug");
    let eslintrc_espree_link = eslintrc_nm.join("espree");

    assert!(
        is_junction(&eslintrc_ajv_link).unwrap(),
        "@eslint/eslintrc/node_modules/ajv must be a junction"
    );
    assert!(
        junction_points_to(&eslintrc_ajv_link, &ajv_pkg),
        "@eslint/eslintrc/node_modules/ajv junction must point to ajv package store dir"
    );

    assert!(
        is_junction(&eslintrc_debug_link).unwrap(),
        "@eslint/eslintrc/node_modules/debug must be a junction"
    );
    assert!(
        junction_points_to(&eslintrc_debug_link, &debug_pkg),
        "@eslint/eslintrc/node_modules/debug junction must point to debug package store dir"
    );

    assert!(
        is_junction(&eslintrc_espree_link).unwrap(),
        "@eslint/eslintrc/node_modules/espree must be a junction"
    );
    assert!(
        junction_points_to(&eslintrc_espree_link, &espree_pkg),
        "@eslint/eslintrc/node_modules/espree junction must point to espree package store dir"
    );

    // 4. Verify junctions in debug/node_modules:
    // debug declares ms
    let debug_nm = debug_entry.join("node_modules");
    let debug_ms_link = debug_nm.join("ms");
    assert!(
        is_junction(&debug_ms_link).unwrap(),
        "debug/node_modules/ms must be a junction"
    );
    assert!(
        junction_points_to(&debug_ms_link, &ms_pkg),
        "debug/node_modules/ms junction must point to ms package store dir"
    );

    // 5. Verify junctions in ajv/node_modules:
    // ajv declares fast-deep-equal
    let ajv_nm = ajv_entry.join("node_modules");
    let ajv_fde_link = ajv_nm.join("fast-deep-equal");
    assert!(
        is_junction(&ajv_fde_link).unwrap(),
        "ajv/node_modules/fast-deep-equal must be a junction"
    );
    assert!(
        junction_points_to(&ajv_fde_link, &fde_pkg),
        "ajv/node_modules/fast-deep-equal junction must point to fast-deep-equal package store dir"
    );

    // 6. Verify junctions in espree/node_modules:
    // espree declares acorn
    let espree_nm = espree_entry.join("node_modules");
    let espree_acorn_link = espree_nm.join("acorn");
    assert!(
        is_junction(&espree_acorn_link).unwrap(),
        "espree/node_modules/acorn must be a junction"
    );
    assert!(
        junction_points_to(&espree_acorn_link, &acorn_pkg),
        "espree/node_modules/acorn junction must point to acorn package store dir"
    );

    // 7. Verify top-level project node_modules/eslint junction
    let proj_eslint_link = temp_proj.path().join("node_modules").join("eslint");
    assert!(
        is_junction(&proj_eslint_link).unwrap(),
        "project node_modules/eslint must be a junction"
    );
    assert!(
        junction_points_to(&proj_eslint_link, &eslint_pkg),
        "project node_modules/eslint must point to eslint package store dir"
    );

    // 8. Test CI workflow reproducibility
    let mut ci_installer = Installer::new(InstallOptions {
        project_dir: temp_proj.path().to_path_buf(),
        registry_url: Some(server.url()),
        cache_dir: Some(temp_cache.path().to_path_buf()),
        store_dir: Some(temp_store.path().join("linked")),
        install_strategy: InstallStrategy::Linked,
        offline: false,
        ..Default::default()
    })
    .unwrap();

    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert!(ci_summary.packages_installed > 0);
    assert!(is_junction(&proj_eslint_link).unwrap());
    assert!(junction_points_to(&eslintrc_debug_link, &debug_pkg));
}
