//! Extreme stress tests for workspace and monorepo scenarios against npm 11.20.0 parity.
//!
//! Covers:
//! - Deep diamond version conflicts across 3+ workspaces (hoisted vs nested placement)
//! - Cyclic workspace-to-workspace dependencies (2-node and 3-node cycles)
//! - Overrides ($ref, scoped overrides, nested parent->child overrides) interacting with peerDependencies
//! - Negated workspace globs (["packages/*", "!packages/excluded"]), nested workspaces, duplicate workspace names, missing version
//! - Install strategies (--install-strategy=hoisted|nested|shallow|linked) with workspaces and --omit=dev

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rnpm_install::{InstallOptions, InstallStrategy, Installer};
use rnpm_lockfile::LockfileV3;
use rnpm_solver::hoisting::PlacementStrategy;
use rnpm_solver::overrides::Overrides;
use rnpm_solver::peer::PeerContext;

// =========================================================================
// In-Memory Gzip/Tarball & Test Registry Helpers (100% Offline & Isolated)
// =========================================================================

fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{rel_path}");
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
                            let base_url = format!("http://{addr}");
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

fn create_file_package(dir: &Path, name: &str, version: &str, extra_fields: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let pkg_json = format!(
        r#"{{
            "name": "{name}",
            "version": "{version}"
            {extra_fields}
        }}"#
    );
    std::fs::write(dir.join("package.json"), pkg_json).unwrap();
    std::fs::write(
        dir.join("index.js"),
        format!("module.exports = '{name}@{version}';"),
    )
    .unwrap();
}

// =========================================================================
// 1. Deep Diamond Version Conflicts Across 3+ Workspaces
// =========================================================================

#[tokio::test]
async fn test_workspace_deep_diamond_version_conflict_across_three_workspaces() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Create external file: packages representing shared-pkg v1.0.0 and v2.0.0
    let pkgs_dir = root.join("external_pkgs");
    let shared_v1_dir = pkgs_dir.join("shared-v1");
    let shared_v2_dir = pkgs_dir.join("shared-v2");
    create_file_package(&shared_v1_dir, "shared-pkg", "1.0.0", "");
    create_file_package(&shared_v2_dir, "shared-pkg", "2.0.0", "");

    let shared_v1_posix = rnpm_core::to_posix_path(&shared_v1_dir.to_string_lossy());
    let shared_v2_posix = rnpm_core::to_posix_path(&shared_v2_dir.to_string_lossy());

    // Root package.json defining 3 workspaces: ws-alpha, ws-beta, ws-gamma
    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "diamond-workspace-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let packages_dir = root.join("packages");
    let ws_alpha = packages_dir.join("ws-alpha");
    let ws_beta = packages_dir.join("ws-beta");
    let ws_gamma = packages_dir.join("ws-gamma");

    // ws-alpha depends on shared-pkg 1.0.0
    create_file_package(
        &ws_alpha,
        "ws-alpha",
        "1.0.0",
        &format!(r#","dependencies": {{ "shared-pkg": "file:{shared_v1_posix}" }}"#),
    );

    // ws-beta depends on shared-pkg 2.0.0 (conflicts with alpha and gamma)
    create_file_package(
        &ws_beta,
        "ws-beta",
        "1.0.0",
        &format!(r#","dependencies": {{ "shared-pkg": "file:{shared_v2_posix}" }}"#),
    );

    // ws-gamma depends on shared-pkg 1.0.0 (shares same version as alpha)
    create_file_package(
        &ws_gamma,
        "ws-gamma",
        "1.0.0",
        &format!(r#","dependencies": {{ "shared-pkg": "file:{shared_v1_posix}" }}"#),
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("Diamond workspace install must succeed");
    assert!(summary.packages_installed >= 3);

    // Root node_modules must contain workspace symlinks/links
    assert!(root.join("node_modules").join("ws-alpha").exists());
    assert!(root.join("node_modules").join("ws-beta").exists());
    assert!(root.join("node_modules").join("ws-gamma").exists());

    // Either root has shared-pkg v1.0.0 hoisted and ws-beta has v2.0.0 nested,
    // or root has v2.0.0 and alpha/gamma nest v1.0.0. Both versions must exist in the tree!
    let root_shared = root.join("node_modules").join("shared-pkg");
    let beta_nested_shared = ws_beta.join("node_modules").join("shared-pkg");
    let alpha_nested_shared = ws_alpha.join("node_modules").join("shared-pkg");

    assert!(root_shared.exists(), "shared-pkg should be hoisted to root node_modules");
    assert!(
        beta_nested_shared.exists() || alpha_nested_shared.exists(),
        "The conflicting diamond version must be cleanly nested under its workspace"
    );

    // Verify lockfile was generated and valid
    let lockfile_path = root.join("package-lock.json");
    assert!(lockfile_path.exists());
    let lockfile = LockfileV3::load_from_file(&lockfile_path).unwrap();
    assert!(lockfile.packages.contains_key("node_modules/ws-alpha"));
    assert!(lockfile.packages.contains_key("node_modules/ws-beta"));
    assert!(lockfile.packages.contains_key("node_modules/ws-gamma"));
}

// =========================================================================
// 2. Cyclic Workspace-to-Workspace Dependencies (2-node and 3-node)
// =========================================================================

#[tokio::test]
async fn test_workspace_two_node_cyclic_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "cyclic-2node-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let pkg_a = root.join("packages").join("pkg-a");
    let pkg_b = root.join("packages").join("pkg-b");

    create_file_package(
        &pkg_a,
        "pkg-a",
        "1.0.0",
        r#","dependencies": { "pkg-b": "^1.0.0" }"#,
    );
    create_file_package(
        &pkg_b,
        "pkg-b",
        "1.0.0",
        r#","dependencies": { "pkg-a": "^1.0.0" }"#,
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("2-node cyclic workspace dependencies must install without error");
    assert_eq!(summary.packages_installed, 2);

    assert!(root.join("node_modules").join("pkg-a").exists());
    assert!(root.join("node_modules").join("pkg-b").exists());

    let lockfile = LockfileV3::load_from_file(&root.join("package-lock.json")).unwrap();
    assert!(lockfile.packages.contains_key("node_modules/pkg-a"));
    assert!(lockfile.packages.contains_key("node_modules/pkg-b"));
}

#[tokio::test]
async fn test_workspace_three_node_cyclic_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "cyclic-3node-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let node1 = root.join("packages").join("node-1");
    let node2 = root.join("packages").join("node-2");
    let node3 = root.join("packages").join("node-3");

    // node-1 -> node-2 -> node-3 -> node-1
    create_file_package(
        &node1,
        "node-1",
        "1.0.0",
        r#","dependencies": { "node-2": "^1.0.0" }"#,
    );
    create_file_package(
        &node2,
        "node-2",
        "1.0.0",
        r#","dependencies": { "node-3": "^1.0.0" }"#,
    );
    create_file_package(
        &node3,
        "node-3",
        "1.0.0",
        r#","dependencies": { "node-1": "^1.0.0" }"#,
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("3-node cyclic workspace dependencies must install successfully");
    assert_eq!(summary.packages_installed, 3);

    assert!(root.join("node_modules").join("node-1").exists());
    assert!(root.join("node_modules").join("node-2").exists());
    assert!(root.join("node_modules").join("node-3").exists());
}

// =========================================================================
// 3. Overrides ($ref, Scoped, Nested) Interacting with Peers & Dependencies
// =========================================================================

#[test]
fn test_overrides_ref_and_nested_scope_resolution() {
    let mut root_deps = BTreeMap::new();
    root_deps.insert("pinned-foo".to_string(), "1.2.3".to_string());
    root_deps.insert("pinned-bar".to_string(), "2.0.0".to_string());

    let json = serde_json::json!({
        "target-a": "$pinned-foo",
        "ws-a > target-b": "$pinned-bar",
        "ws-a > mid-pkg > target-c": "3.1.4",
        "foo@>=1.0.0 > target-d": "4.0.0"
    });

    let overrides = Overrides::from_json_value(Some(&json), root_deps);

    // Global reference override
    let resolved_a = overrides.resolve_override("target-a", "^1.0.0", &[]).unwrap();
    assert_eq!(resolved_a, Some("1.2.3".to_string()));

    // Scoped reference override under ws-a
    let resolved_b = overrides
        .resolve_override("target-b", "^1.0.0", &["diamond-root", "ws-a"])
        .unwrap();
    assert_eq!(resolved_b, Some("2.0.0".to_string()));

    // Outside ws-a, target-b has no override
    let resolved_b_outside = overrides
        .resolve_override("target-b", "^1.0.0", &["diamond-root", "ws-other"])
        .unwrap();
    assert_eq!(resolved_b_outside, None);

    // Deep nested override: ws-a > mid-pkg > target-c
    let resolved_c = overrides
        .resolve_override("target-c", "^1.0.0", &["diamond-root", "ws-a", "mid-pkg"])
        .unwrap();
    assert_eq!(resolved_c, Some("3.1.4".to_string()));

    // Range comparator in arrow syntax
    let resolved_d = overrides
        .resolve_override("target-d", "^1.0.0", &["diamond-root", "foo"])
        .unwrap();
    assert_eq!(resolved_d, Some("4.0.0".to_string()));
}

#[tokio::test]
async fn test_workspace_overrides_interacting_with_peer_dependencies() {
    let peer_v17 = create_test_tarball(&[
        ("package.json", br#"{"name":"react","version":"17.0.2"}"#),
        ("index.js", b"module.exports = 'react-17';"),
    ]);
    let peer_v18 = create_test_tarball(&[
        ("package.json", br#"{"name":"react","version":"18.2.0"}"#),
        ("index.js", b"module.exports = 'react-18';"),
    ]);
    let parent_pkg = create_test_tarball(&[
        (
            "package.json",
            br#"{"name":"react-widget","version":"1.0.0","peerDependencies":{"react":"^17.0.0"}}"#,
        ),
        ("index.js", b"module.exports = 'widget';"),
    ]);

    let v17_ssri = compute_ssri(&peer_v17);
    let v18_ssri = compute_ssri(&peer_v18);
    let parent_ssri = compute_ssri(&parent_pkg);

    let server = TestRegistryServer::start(move |path, base_url| {
        if path == "/react" {
            let body = format!(
                r#"{{"name":"react","dist-tags":{{"latest":"18.2.0"}},"versions":{{
                    "17.0.2":{{"name":"react","version":"17.0.2","dist":{{"tarball":"{base_url}/tarballs/react-17.0.2.tgz","integrity":"{v17_ssri}"}}}},
                    "18.2.0":{{"name":"react","version":"18.2.0","dist":{{"tarball":"{base_url}/tarballs/react-18.2.0.tgz","integrity":"{v18_ssri}"}}}}
                }}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/react-17.0.2.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer_v17.clone()))
        } else if path == "/tarballs/react-18.2.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], peer_v18.clone()))
        } else if path == "/react-widget" {
            let body = format!(
                r#"{{"name":"react-widget","dist-tags":{{"latest":"1.0.0"}},"versions":{{
                    "1.0.0":{{"name":"react-widget","version":"1.0.0","peerDependencies":{{"react":"^17.0.0"}},"dist":{{"tarball":"{base_url}/tarballs/react-widget-1.0.0.tgz","integrity":"{parent_ssri}"}}}}
                }}}}"#
            );
            Some((200, vec![("Content-Type", "application/json".to_string())], body.into_bytes()))
        } else if path == "/tarballs/react-widget-1.0.0.tgz" {
            Some((200, vec![("Content-Type", "application/octet-stream".to_string())], parent_pkg.clone()))
        } else {
            None
        }
    }).await;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Root manifest specifies overrides: { "react": "18.2.0" }
    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "override-peer-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "overrides": {
                "react": "18.2.0"
            }
        }"#,
    )
    .unwrap();

    let ws_a = root.join("packages").join("ws-app");
    create_file_package(
        &ws_a,
        "ws-app",
        "1.0.0",
        r#","dependencies": { "react-widget": "^1.0.0" }"#,
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        registry_url: Some(server.url()),
        offline: false,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("Override of peerDependency must succeed without ERESOLVE error");
    assert!(summary.packages_installed >= 2);

    // Verify react 18.2.0 was installed because of the override
    let react_pkg_path = root.join("node_modules").join("react").join("package.json");
    assert!(react_pkg_path.exists());
    let react_content = std::fs::read_to_string(&react_pkg_path).unwrap();
    assert!(react_content.contains("18.2.0"));
}

// =========================================================================
// 4. Negated Workspace Globs, Nested Workspaces, Missing Version
// =========================================================================

#[tokio::test]
async fn test_workspace_negated_globs_and_excluded_directories() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Negated glob: include packages/* but exclude packages/excluded and packages/ignored-*
    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "negated-glob-root",
            "version": "1.0.0",
            "workspaces": [
                "packages/*",
                "!packages/excluded",
                "!packages/ignored-*"
            ]
        }"#,
    )
    .unwrap();

    let packages_dir = root.join("packages");
    let inc1 = packages_dir.join("included-a");
    let inc2 = packages_dir.join("included-b");
    let exc1 = packages_dir.join("excluded");
    let exc2 = packages_dir.join("ignored-testing");

    create_file_package(&inc1, "included-a", "1.0.0", "");
    create_file_package(&inc2, "included-b", "1.0.0", "");
    create_file_package(&exc1, "excluded", "1.0.0", "");
    create_file_package(&exc2, "ignored-testing", "1.0.0", "");

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 2);

    assert!(root.join("node_modules").join("included-a").exists());
    assert!(root.join("node_modules").join("included-b").exists());
    assert!(!root.join("node_modules").join("excluded").exists());
    assert!(!root.join("node_modules").join("ignored-testing").exists());
}

#[tokio::test]
async fn test_workspace_nested_workspaces_discovery_and_linking() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Monorepo with explicit nested workspace pattern
    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "nested-ws-root",
            "version": "1.0.0",
            "workspaces": [
                "packages/parent-ws",
                "packages/parent-ws/nested-child"
            ]
        }"#,
    )
    .unwrap();

    let parent_ws = root.join("packages").join("parent-ws");
    let nested_child = parent_ws.join("nested-child");

    create_file_package(&parent_ws, "parent-ws", "1.0.0", "");
    create_file_package(
        &nested_child,
        "nested-child",
        "2.0.0",
        r#","dependencies": { "parent-ws": "^1.0.0" }"#,
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("Nested workspace install must succeed");
    assert_eq!(summary.packages_installed, 2);

    assert!(root.join("node_modules").join("parent-ws").exists());
    assert!(root.join("node_modules").join("nested-child").exists());
}

#[tokio::test]
async fn test_workspace_missing_version_field_defaults_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "missing-ver-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let ws_no_ver = root.join("packages").join("pkg-no-ver");
    std::fs::create_dir_all(&ws_no_ver).unwrap();
    // package.json WITHOUT a version field!
    std::fs::write(
        ws_no_ver.join("package.json"),
        r#"{ "name": "pkg-no-ver" }"#,
    )
    .unwrap();

    let ws_consumer = root.join("packages").join("pkg-consumer");
    create_file_package(
        &ws_consumer,
        "pkg-consumer",
        "1.0.0",
        r#","dependencies": { "pkg-no-ver": "*" }"#,
    );

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let mut installer = Installer::new(options).unwrap();
    let summary = installer
        .run()
        .await
        .expect("Workspace without version field must link cleanly with * constraint");
    assert_eq!(summary.packages_installed, 2);

    assert!(root.join("node_modules").join("pkg-no-ver").exists());
    assert!(root.join("node_modules").join("pkg-consumer").exists());
}

#[tokio::test]
async fn test_workspace_duplicate_names_returns_error() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "dup-names-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let dir1 = root.join("packages").join("folder-one");
    let dir2 = root.join("packages").join("folder-two");
    // Both folders declare the EXACT SAME package name
    create_file_package(&dir1, "duplicate-pkg-name", "1.0.0", "");
    create_file_package(&dir2, "duplicate-pkg-name", "2.0.0", "");

    let options = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        ..Default::default()
    };

    let installer_res = Installer::new(options);
    if let Ok(mut installer) = installer_res {
        let run_res = installer.run().await;
        assert!(run_res.is_err(), "Duplicate workspace package name must return error");
    }
}

// =========================================================================
// 5. Install Strategies (--install-strategy=hoisted|nested|shallow|linked) & --omit=dev
// =========================================================================

#[tokio::test]
async fn test_workspace_install_strategies_and_omit_dev() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // External file package for production and dev dependencies
    let prod_ext = root.join("external_pkgs").join("prod-dep");
    let dev_ext = root.join("external_pkgs").join("dev-dep");
    create_file_package(&prod_ext, "prod-dep", "1.0.0", "");
    create_file_package(&dev_ext, "dev-dep", "1.0.0", "");

    let prod_posix = rnpm_core::to_posix_path(&prod_ext.to_string_lossy());
    let dev_posix = rnpm_core::to_posix_path(&dev_ext.to_string_lossy());

    std::fs::write(
        root.join("package.json"),
        r#"{
            "name": "strategy-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"]
        }"#,
    )
    .unwrap();

    let ws_a = root.join("packages").join("app-a");
    create_file_package(
        &ws_a,
        "app-a",
        "1.0.0",
        &format!(
            r#","dependencies": {{ "prod-dep": "file:{prod_posix}" }}, "devDependencies": {{ "dev-dep": "file:{dev_posix}" }}"#
        ),
    );

    // Test 1: Install with omit_dev: true
    let options_omit_dev = InstallOptions {
        project_dir: root.to_path_buf(),
        offline: true,
        omit_dev: true,
        install_strategy: InstallStrategy::Hoisted,
        ..Default::default()
    };

    let mut installer = Installer::new(options_omit_dev).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 2); // app-a and prod-dep, NOT dev-dep

    assert!(root.join("node_modules").join("app-a").exists());
    assert!(root.join("node_modules").join("prod-dep").exists());
    assert!(!root.join("node_modules").join("dev-dep").exists());

    // Test 2: Verify PlacementStrategy enum supports Linked variant
    assert_eq!(PlacementStrategy::default(), PlacementStrategy::Hoisted);
    let linked = PlacementStrategy::Linked;
    assert_ne!(linked, PlacementStrategy::Nested);
    assert_ne!(linked, PlacementStrategy::Shallow);
}

// =========================================================================
// 6. Deep Cyclic & Alias Peer Context Torture
// =========================================================================

#[test]
fn test_peer_context_cycle_detection_extreme_depth() {
    let mut ctx = PeerContext::new();

    // 4-node cycle: A -> B -> C -> D -> A
    ctx.enter("a", "b");
    ctx.enter("b", "c");
    ctx.enter("c", "d");
    assert!(!ctx.is_cycle("a", "d"));
    assert!(ctx.is_cycle("d", "a"));

    let path = ctx.find_cycle_path("d", "a").unwrap();
    assert_eq!(path, vec!["d", "a", "b", "c", "d"]);

    // Disjoint branches do not trigger false cycles
    ctx.enter("x", "y");
    ctx.enter("y", "z");
    assert!(!ctx.is_cycle("z", "a"));
    assert!(!ctx.is_cycle("a", "x"));

    // Alias peer cycle detection
    ctx.enter_with_alias("react-dom", Some("rd"), "my-react", Some("react"));
    assert!(ctx.is_cycle_with_alias("react", Some("my-react"), "react-dom", Some("rd")));

    // Self cycle
    assert!(ctx.is_cycle("z", "z"));
    assert_eq!(ctx.find_cycle_path("z", "z"), Some(vec!["z".to_string(), "z".to_string()]));
}
