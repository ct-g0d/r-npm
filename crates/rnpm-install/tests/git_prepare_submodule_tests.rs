use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Builder, Header};

use rnpm_install::{InstallOptions, Installer};

fn compute_ssri(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("sha512-{}", data_encoding::BASE64.encode(&hash))
}

struct CountingServer {
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    pub requested_paths: Arc<Mutex<Vec<String>>>,
}

impl CountingServer {
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
        let requested_paths = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = requested_paths.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let reqs_clone = reqs.clone();
                            let base_url = format!("http://{}", addr);
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let first_line = req_str.lines().next().unwrap_or("");
                                    let path = first_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                                    reqs_clone.lock().await.push(path.clone());

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
            requested_paths,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn request_count(&self) -> usize {
        self.requested_paths.lock().await.len()
    }
}

fn build_mock_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{rel_path}");
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn run_git(dir: &Path, args: &[&str]) {
    let _ = std::fs::write(dir.join(".empty_gitconfig"), "");
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join(".empty_gitconfig"))
        .status()
        .expect("Failed to execute git command");
    assert!(status.success(), "Git command failed: git {:?}", args);
}

fn assert_no_git_leaks(dir: &Path) {
    let mut to_visit = vec![dir.to_path_buf()];
    while let Some(current) = to_visit.pop() {
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                assert_ne!(
                    name, ".git",
                    "Found leaked .git in installed package: {}",
                    entry.path().display()
                );
                assert_ne!(
                    name, ".rnpm_checkout_done",
                    "Found leaked .rnpm_checkout_done in installed package: {}",
                    entry.path().display()
                );
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        to_visit.push(entry.path());
                    }
                }
            }
        }
    }
}

/// Test 1: Git dependency with a recursive git submodule:
/// Verify submodule files are present in installed node_modules/<pkg>/... and NO .git file/folder leaks.
#[tokio::test]
async fn test_git_recursive_submodules() {
    let root_temp = tempdir().unwrap();
    let sub2_dir = root_temp.path().join("sub2_repo");
    let sub1_dir = root_temp.path().join("sub1_repo");
    let main_dir = root_temp.path().join("main_repo");

    // 1. Initialize sub2 (innermost submodule)
    std::fs::create_dir_all(&sub2_dir).unwrap();
    run_git(&sub2_dir, &["init"]);
    run_git(&sub2_dir, &["config", "user.name", "Tester"]);
    run_git(&sub2_dir, &["config", "user.email", "test@example.com"]);
    std::fs::write(
        sub2_dir.join("nested.txt"),
        "content of nested submodule 2\n",
    )
    .unwrap();
    run_git(&sub2_dir, &["add", "."]);
    run_git(&sub2_dir, &["commit", "-m", "init sub2"]);

    // 2. Initialize sub1 (middle submodule containing sub2)
    std::fs::create_dir_all(&sub1_dir).unwrap();
    run_git(&sub1_dir, &["init"]);
    run_git(&sub1_dir, &["config", "user.name", "Tester"]);
    run_git(&sub1_dir, &["config", "user.email", "test@example.com"]);
    let sub2_url = sub2_dir.to_string_lossy().replace('\\', "/");
    run_git(
        &sub1_dir,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &sub2_url,
            "sub2",
        ],
    );
    std::fs::write(sub1_dir.join("sub1.txt"), "content of submodule 1\n").unwrap();
    run_git(&sub1_dir, &["add", "."]);
    run_git(&sub1_dir, &["commit", "-m", "init sub1 with sub2"]);

    // 3. Initialize main repo containing sub1
    std::fs::create_dir_all(&main_dir).unwrap();
    run_git(&main_dir, &["init"]);
    run_git(&main_dir, &["config", "user.name", "Tester"]);
    run_git(&main_dir, &["config", "user.email", "test@example.com"]);
    let sub1_url = sub1_dir.to_string_lossy().replace('\\', "/");
    run_git(
        &main_dir,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &sub1_url,
            "sub1",
        ],
    );
    let pkg_json = serde_json::json!({
        "name": "pkg-with-submodules",
        "version": "1.0.0",
        "description": "Git dependency with recursive submodules",
        "main": "index.js"
    });
    std::fs::write(main_dir.join("package.json"), pkg_json.to_string()).unwrap();
    std::fs::write(
        main_dir.join("index.js"),
        "module.exports = 'main with submodules';\n",
    )
    .unwrap();
    run_git(&main_dir, &["add", "."]);
    run_git(&main_dir, &["commit", "-m", "init main with sub1"]);

    let main_url = format!(
        "git+file://{}",
        main_dir.to_string_lossy().replace('\\', "/")
    );

    // 4. Consumer project installing the git dependency
    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-with-submodules": main_url
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir
        .path()
        .join("node_modules")
        .join("pkg-with-submodules");
    assert!(
        installed_pkg.join("package.json").exists(),
        "package.json missing in installed package"
    );
    assert!(
        installed_pkg.join("index.js").exists(),
        "index.js missing in installed package"
    );

    // Submodule 1 files must exist
    let sub1_file = installed_pkg.join("sub1").join("sub1.txt");
    assert!(
        sub1_file.exists(),
        "submodule 1 file 'sub1/sub1.txt' missing in installed package"
    );
    let sub1_content = std::fs::read_to_string(&sub1_file).unwrap();
    assert_eq!(sub1_content.trim(), "content of submodule 1");

    // Submodule 2 (recursive) files must exist
    let sub2_file = installed_pkg
        .join("sub1")
        .join("sub2")
        .join("nested.txt");
    assert!(
        sub2_file.exists(),
        "nested submodule 2 file 'sub1/sub2/nested.txt' missing in installed package"
    );
    let sub2_content = std::fs::read_to_string(&sub2_file).unwrap();
    assert_eq!(sub2_content.trim(), "content of nested submodule 2");

    // Verify NO .git file or directory or .rnpm_checkout_done leaks into installed package
    assert_no_git_leaks(&installed_pkg);
}

/// Test 2: Git dependency with a `prepare` script:
/// Verify dist/built.js IS built and installed in node_modules/<pkg>/dist/built.js,
/// while excluded source files (e.g. src/unpacked.ts) are NOT leaked into node_modules/<pkg>!
#[tokio::test]
async fn test_git_prepare_then_pack_build_flow() {
    let repo_dir = tempdir().unwrap();

    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(repo_dir.path(), &["config", "user.email", "test@example.com"]);

    let pkg_json = serde_json::json!({
        "name": "pkg-git-prepare",
        "version": "1.0.0",
        "description": "Git dependency with prepare script and files array",
        "main": "dist/built.js",
        "scripts": {
            "prepare": "node -e \"const fs = require('fs'); fs.mkdirSync('dist', {recursive: true}); fs.writeFileSync('dist/built.js', 'module.exports = 42;');\""
        },
        "files": [
            "dist"
        ]
    });
    std::fs::write(repo_dir.path().join("package.json"), pkg_json.to_string()).unwrap();

    // Create source files that should NOT be packed into node_modules
    let src_dir = repo_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("unpacked.ts"),
        "export const secretSource = 'this should never be in node_modules';\n",
    )
    .unwrap();

    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "init prepare repo"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.path().to_string_lossy().replace('\\', "/")
    );

    // Consumer project installing the git dependency
    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-prepare": git_url
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir.path().join("node_modules").join("pkg-git-prepare");

    // dist/built.js must exist and contain built output
    let built_file = installed_pkg.join("dist").join("built.js");
    assert!(
        built_file.exists(),
        "Expected dist/built.js to be built and installed via prepare script"
    );
    let built_content = std::fs::read_to_string(&built_file).unwrap();
    assert!(
        built_content.contains("module.exports = 42;"),
        "Built file content mismatch: {built_content}"
    );

    // package.json must exist
    assert!(installed_pkg.join("package.json").exists());

    // Excluded source file src/unpacked.ts must NOT exist in node_modules/<pkg>
    let unpacked_file = installed_pkg.join("src").join("unpacked.ts");
    assert!(
        !unpacked_file.exists(),
        "Source file 'src/unpacked.ts' leaked into installed node_modules despite files: ['dist'] filter"
    );
    assert!(
        !installed_pkg.join("src").exists(),
        "Directory 'src' leaked into installed node_modules despite files: ['dist'] filter"
    );

    // Verify NO .git file or directory or .rnpm_checkout_done leaks
    assert_no_git_leaks(&installed_pkg);
}
/// Test 3: Same git dependency with `--ignore-scripts`:
/// Verify `prepare` does NOT run.
#[tokio::test]
async fn test_git_prepare_ignored_with_ignore_scripts() {
    let repo_dir = tempdir().unwrap();

    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(repo_dir.path(), &["config", "user.email", "test@example.com"]);

    let pkg_json = serde_json::json!({
        "name": "pkg-git-prepare-ignore",
        "version": "1.0.0",
        "description": "Git dependency with prepare script tested under ignore-scripts",
        "main": "dist/built.js",
        "scripts": {
            "prepare": "node -e \"const fs = require('fs'); fs.mkdirSync('dist', {recursive: true}); fs.writeFileSync('dist/built.js', 'module.exports = 42;');\""
        },
        "files": [
            "dist"
        ]
    });
    std::fs::write(repo_dir.path().join("package.json"), pkg_json.to_string()).unwrap();

    let src_dir = repo_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("unpacked.ts"),
        "export const code = 'unpacked';\n",
    )
    .unwrap();

    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "init prepare repo"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.path().to_string_lossy().replace('\\', "/")
    );

    // Consumer project installing the git dependency with ignore_scripts: true
    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app-ignore",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-prepare-ignore": git_url
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_json.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ignore_scripts: true,
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir
        .path()
        .join("node_modules")
        .join("pkg-git-prepare-ignore");

    // package.json must exist
    assert!(installed_pkg.join("package.json").exists());

    // dist/built.js must NOT exist because prepare was skipped!
    let built_file = installed_pkg.join("dist").join("built.js");
    assert!(
        !built_file.exists(),
        "dist/built.js should NOT have been created when --ignore-scripts is true"
    );

    // src/unpacked.ts must NOT exist (filtered out by files: ['dist'])
    assert!(!installed_pkg.join("src").exists());

    // Verify NO .git file or directory or .rnpm_checkout_done leaks
    assert_no_git_leaks(&installed_pkg);
}

/// Test A: Git dep has a devDependency (served from local file: dep)
/// providing a .bin build tool (`my-builder`), and `"scripts": { "prepare": "my-builder" }`
/// generates `dist/out.js` + `"files": ["dist"]` -> verify `node_modules/<pkg>/dist/out.js` is built and installed!
#[tokio::test]
async fn test_git_prepare_with_dev_dependency_bin_tool() {
    let tmp = tempdir().unwrap();

    let builder_json = serde_json::json!({
        "name": "my-builder",
        "version": "1.0.0",
        "bin": {
            "my-builder": "bin.js"
        }
    });
    let builder_script = r#"#!/usr/bin/env node
const fs = require('fs');
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/out.js', 'module.exports = "built by my-builder";\n');
"#;

    let builder_tarball_bytes = build_mock_tarball(&[
        ("package.json", builder_json.to_string().as_bytes()),
        ("bin.js", builder_script.as_bytes()),
    ]);
    let builder_tarball_path = tmp.path().join("my-builder-1.0.0.tgz");
    std::fs::write(&builder_tarball_path, &builder_tarball_bytes).unwrap();

    let builder_file_url = format!(
        "file:{}",
        builder_tarball_path.to_string_lossy().replace('\\', "/")
    );

    // Create Git repository for the git dependency
    let repo_dir = tmp.path().join("git-pkg-repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(&repo_dir, &["init"]);
    run_git(&repo_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_dir, &["config", "user.email", "test@example.com"]);

    let git_pkg_json = serde_json::json!({
        "name": "pkg-git-builder",
        "version": "1.0.0",
        "main": "dist/out.js",
        "scripts": {
            "prepare": "my-builder"
        },
        "devDependencies": {
            "my-builder": builder_file_url
        },
        "files": [
            "dist"
        ]
    });
    std::fs::write(repo_dir.join("package.json"), git_pkg_json.to_string()).unwrap();

    let src_dir = repo_dir.join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("dev-source.ts"),
        "export const devOnly = true;\n",
    )
    .unwrap();

    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "init git repo with devDependency builder"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.to_string_lossy().replace('\\', "/")
    );

    // Consumer project installing the git dependency
    let proj_dir = tmp.path().join("consumer-proj");
    let cache_dir = tmp.path().join("cache");
    std::fs::create_dir_all(&proj_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app-a",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-builder": git_url
        }
    });
    std::fs::write(proj_dir.join("package.json"), consumer_json.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.clone(),
        cache_dir: Some(cache_dir),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir.join("node_modules").join("pkg-git-builder");
    let out_file = installed_pkg.join("dist").join("out.js");
    assert!(
        out_file.exists(),
        "Expected node_modules/pkg-git-builder/dist/out.js to be built and installed via my-builder"
    );
    let out_content = std::fs::read_to_string(&out_file).unwrap();
    assert!(
        out_content.contains("built by my-builder"),
        "Content mismatch in out.js: {out_content}"
    );

    // package.json must exist
    assert!(installed_pkg.join("package.json").exists());

    // Staging node_modules must NOT leak into installed package
    assert!(
        !installed_pkg.join("node_modules").exists(),
        "Staging node_modules leaked into installed node_modules/pkg-git-builder"
    );

    // Filtered src files must NOT exist
    assert!(!installed_pkg.join("src").exists());

    // Verify NO .git file or directory or .rnpm_checkout_done leaks
    assert_no_git_leaks(&installed_pkg);
}

/// Test B: Git dep has `"prepack"` + `"prepare"` creating `dist/out.js` AND `"postpack"` deleting `dist/`
/// -> verify `node_modules/<pkg>/dist/out.js` IS present in the installed package (proving packing happened BEFORE `postpack`!)!
#[tokio::test]
async fn test_git_prepare_pack_lifecycle_order_postpack_after_collection() {
    let tmp = tempdir().unwrap();
    let repo_dir = tmp.path().join("git-pkg-lifecycle-repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(&repo_dir, &["init"]);
    run_git(&repo_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_dir, &["config", "user.email", "test@example.com"]);

    let git_pkg_json = serde_json::json!({
        "name": "pkg-git-lifecycle-order",
        "version": "1.0.0",
        "main": "dist/out.js",
        "scripts": {
            "prepack": "node -e \"const fs = require('fs'); fs.mkdirSync('dist', {recursive: true}); fs.writeFileSync('dist/pre.txt', 'prepack ran');\"",
            "prepare": "node -e \"const fs = require('fs'); fs.mkdirSync('dist', {recursive: true}); fs.writeFileSync('dist/out.js', 'module.exports = 12345;');\"",
            "postpack": "node -e \"const fs = require('fs'); fs.rmSync('dist', {recursive: true, force: true});\""
        },
        "files": [
            "dist"
        ]
    });
    std::fs::write(repo_dir.join("package.json"), git_pkg_json.to_string()).unwrap();

    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "init git repo with prepack/prepare/postpack"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.to_string_lossy().replace('\\', "/")
    );

    // Consumer project installing the git dependency
    let proj_dir = tmp.path().join("consumer-proj-b");
    let cache_dir = tmp.path().join("cache-b");
    std::fs::create_dir_all(&proj_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app-b",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-lifecycle-order": git_url
        }
    });
    std::fs::write(proj_dir.join("package.json"), consumer_json.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.clone(),
        cache_dir: Some(cache_dir),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir.join("node_modules").join("pkg-git-lifecycle-order");
    let out_file = installed_pkg.join("dist").join("out.js");
    assert!(
        out_file.exists(),
        "Expected dist/out.js to be present in installed package! If postpack ran before packing, this file would have been deleted."
    );
    let out_content = std::fs::read_to_string(&out_file).unwrap();
    assert!(
        out_content.contains("module.exports = 12345;"),
        "Content mismatch in out.js: {out_content}"
    );

    // package.json must exist
    assert!(installed_pkg.join("package.json").exists());

    // Verify NO .git file or directory or .rnpm_checkout_done leaks
    assert_no_git_leaks(&installed_pkg);
}

/// Test C: Outer install with `allow-registry=root` and `allow-git=root`
/// installs a Git dependency whose package.json has a `prepare` script + a registry `devDependency`
/// -> Must be REJECTED with `EALLOWREGISTRY` and ZERO HTTP requests to loopback registry!
#[tokio::test]
async fn test_git_prepare_inherits_outer_source_policy_eallowregistry_zero_http() {
    let server = CountingServer::start(|_path, _base_url| None).await;

    let tmp = tempdir().unwrap();
    let repo_dir = tmp.path().join("git-repo-with-devdep");
    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(&repo_dir, &["init"]);
    run_git(&repo_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_dir, &["config", "user.email", "test@example.com"]);

    let git_pkg_json = serde_json::json!({
        "name": "pkg-git-with-registry-devdep",
        "version": "1.0.0",
        "scripts": {
            "prepare": "node -e \"console.log('prepare script')\""
        },
        "devDependencies": {
            "some-registry-tool": "^1.0.0"
        }
    });
    std::fs::write(repo_dir.join("package.json"), git_pkg_json.to_string()).unwrap();

    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "init git repo with devDependency"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.to_string_lossy().replace('\\', "/")
    );

    // Consumer project with allow-registry=root and allow-git=root
    let proj_dir = tmp.path().join("consumer-proj-c");
    let cache_dir = tmp.path().join("cache-c");
    std::fs::create_dir_all(&proj_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app-c",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-with-registry-devdep": git_url
        }
    });
    std::fs::write(proj_dir.join("package.json"), consumer_json.to_string()).unwrap();
    std::fs::write(
        proj_dir.join(".npmrc"),
        "allow-git=root\nallow-registry=root\n",
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.clone(),
        cache_dir: Some(cache_dir),
        registry_url: Some(server.url()),
        ..Default::default()
    })
    .unwrap();

    let result = installer.install().await;
    assert!(
        result.is_err(),
        "Expected install to fail on transitive registry devDependency of git dep"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("EALLOWREGISTRY"),
        "Expected error message to contain EALLOWREGISTRY, got: {err_msg}"
    );
    assert!(
        err_msg.contains("Fetching non-root packages of type \"registry\" have been disabled"),
        "Expected error message to contain non-root qualifier, got: {err_msg}"
    );

    // ZERO HTTP requests must have been made to the registry!
    assert_eq!(
        server.request_count().await,
        0,
        "ZERO HTTP requests should have been made to the registry server"
    );
}

/// Test D: Outer project .npmrc restriction (allow-remote=none or allow-registry=none)
/// is strictly enforced during Git staging install even though staging dir has no .npmrc!
#[tokio::test]
async fn test_git_prepare_outer_npmrc_restriction_enforced_in_staging_without_npmrc() {
    let tmp = tempdir().unwrap();

    // D1: Outer allow-remote=none, git dep has remote devDependency
    let repo_remote_dir = tmp.path().join("git-repo-remote-devdep");
    std::fs::create_dir_all(&repo_remote_dir).unwrap();
    run_git(&repo_remote_dir, &["init"]);
    run_git(&repo_remote_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_remote_dir, &["config", "user.email", "test@example.com"]);

    let git_remote_json = serde_json::json!({
        "name": "pkg-git-remote-devdep",
        "version": "1.0.0",
        "scripts": {
            "prepare": "node -e \"console.log('prepare')\""
        },
        "devDependencies": {
            "remote-tarball": "http://127.0.0.1:9999/remote-tarball-1.0.0.tgz"
        }
    });
    std::fs::write(
        repo_remote_dir.join("package.json"),
        git_remote_json.to_string(),
    )
    .unwrap();
    run_git(&repo_remote_dir, &["add", "."]);
    run_git(&repo_remote_dir, &["commit", "-m", "init remote devdep repo"]);

    let git_remote_url = format!(
        "git+file://{}",
        repo_remote_dir.to_string_lossy().replace('\\', "/")
    );

    let proj_remote_dir = tmp.path().join("consumer-proj-d1");
    let cache_remote_dir = tmp.path().join("cache-d1");
    std::fs::create_dir_all(&proj_remote_dir).unwrap();
    std::fs::create_dir_all(&cache_remote_dir).unwrap();

    let consumer_d1_json = serde_json::json!({
        "name": "consumer-app-d1",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-remote-devdep": git_remote_url
        }
    });
    std::fs::write(
        proj_remote_dir.join("package.json"),
        consumer_d1_json.to_string(),
    )
    .unwrap();
    std::fs::write(proj_remote_dir.join(".npmrc"), "allow-remote=none\n").unwrap();

    let mut installer_d1 = Installer::new(InstallOptions {
        project_dir: proj_remote_dir.clone(),
        cache_dir: Some(cache_remote_dir),
        ..Default::default()
    })
    .unwrap();

    let result_d1 = installer_d1.install().await;
    assert!(
        result_d1.is_err(),
        "Expected install to fail on allow-remote=none in staging"
    );
    let err_msg_d1 = result_d1.unwrap_err().to_string();
    assert!(
        err_msg_d1.contains("EALLOWREMOTE"),
        "Expected EALLOWREMOTE, got: {err_msg_d1}"
    );

    // D2: Outer allow-registry=none, git dep has registry devDependency
    let repo_reg_dir = tmp.path().join("git-repo-reg-devdep");
    std::fs::create_dir_all(&repo_reg_dir).unwrap();
    run_git(&repo_reg_dir, &["init"]);
    run_git(&repo_reg_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_reg_dir, &["config", "user.email", "test@example.com"]);

    let git_reg_json = serde_json::json!({
        "name": "pkg-git-reg-devdep",
        "version": "1.0.0",
        "scripts": {
            "prepare": "node -e \"console.log('prepare')\""
        },
        "devDependencies": {
            "registry-pkg": "^1.0.0"
        }
    });
    std::fs::write(repo_reg_dir.join("package.json"), git_reg_json.to_string()).unwrap();
    run_git(&repo_reg_dir, &["add", "."]);
    run_git(&repo_reg_dir, &["commit", "-m", "init reg devdep repo"]);

    let git_reg_url = format!(
        "git+file://{}",
        repo_reg_dir.to_string_lossy().replace('\\', "/")
    );

    let proj_reg_dir = tmp.path().join("consumer-proj-d2");
    let cache_reg_dir = tmp.path().join("cache-d2");
    std::fs::create_dir_all(&proj_reg_dir).unwrap();
    std::fs::create_dir_all(&cache_reg_dir).unwrap();

    let consumer_d2_json = serde_json::json!({
        "name": "consumer-app-d2",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-reg-devdep": git_reg_url
        }
    });
    std::fs::write(
        proj_reg_dir.join("package.json"),
        consumer_d2_json.to_string(),
    )
    .unwrap();
    std::fs::write(proj_reg_dir.join(".npmrc"), "allow-registry=none\n").unwrap();

    let mut installer_d2 = Installer::new(InstallOptions {
        project_dir: proj_reg_dir.clone(),
        cache_dir: Some(cache_reg_dir),
        ..Default::default()
    })
    .unwrap();

    let result_d2 = installer_d2.install().await;
    assert!(
        result_d2.is_err(),
        "Expected install to fail on allow-registry=none in staging"
    );
    let err_msg_d2 = result_d2.unwrap_err().to_string();
    assert!(
        err_msg_d2.contains("EALLOWREGISTRY"),
        "Expected EALLOWREGISTRY, got: {err_msg_d2}"
    );
}

/// Test E: Under default allow-registry=all, git dependency with prepare script + registry devDependency
/// successfully fetches from registry, builds via prepare script, and completes installation!
#[tokio::test]
async fn test_git_prepare_with_registry_devdep_default_allow_registry_all() {
    let builder_json = serde_json::json!({
        "name": "my-build-tool",
        "version": "1.0.0",
        "bin": {
            "my-build-tool": "bin.js"
        }
    });
    let builder_script = r#"#!/usr/bin/env node
const fs = require('fs');
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/built.js', 'module.exports = 999;\n');
"#;

    let builder_tarball_bytes = build_mock_tarball(&[
        ("package.json", builder_json.to_string().as_bytes()),
        ("bin.js", builder_script.as_bytes()),
    ]);
    let builder_integrity = compute_ssri(&builder_tarball_bytes);

    let tarball_bytes_clone = builder_tarball_bytes.clone();
    let server = CountingServer::start(move |path, base_url| {
        if path == "/my-build-tool" {
            let body = serde_json::json!({
                "name": "my-build-tool",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "my-build-tool",
                        "version": "1.0.0",
                        "bin": {
                            "my-build-tool": "bin.js"
                        },
                        "dist": {
                            "tarball": format!("{base_url}/tarballs/my-build-tool-1.0.0.tgz"),
                            "integrity": builder_integrity
                        }
                    }
                }
            })
            .to_string();
            Some((
                200,
                vec![("Content-Type", "application/json".to_string())],
                body.into_bytes(),
            ))
        } else if path == "/tarballs/my-build-tool-1.0.0.tgz" {
            Some((
                200,
                vec![("Content-Type", "application/octet-stream".to_string())],
                tarball_bytes_clone.clone(),
            ))
        } else {
            None
        }
    })
    .await;

    let tmp = tempdir().unwrap();
    let repo_dir = tmp.path().join("git-repo-with-reg-builder");
    std::fs::create_dir_all(&repo_dir).unwrap();
    run_git(&repo_dir, &["init"]);
    run_git(&repo_dir, &["config", "user.name", "Tester"]);
    run_git(&repo_dir, &["config", "user.email", "test@example.com"]);

    let git_pkg_json = serde_json::json!({
        "name": "pkg-git-prepare-reg",
        "version": "1.0.0",
        "main": "dist/built.js",
        "scripts": {
            "prepare": "my-build-tool"
        },
        "devDependencies": {
            "my-build-tool": "^1.0.0"
        },
        "files": [
            "dist"
        ]
    });
    std::fs::write(repo_dir.join("package.json"), git_pkg_json.to_string()).unwrap();

    run_git(&repo_dir, &["add", "."]);
    run_git(&repo_dir, &["commit", "-m", "init git repo with registry devDependency"]);

    let git_url = format!(
        "git+file://{}",
        repo_dir.to_string_lossy().replace('\\', "/")
    );

    let proj_dir = tmp.path().join("consumer-proj-e");
    let cache_dir = tmp.path().join("cache-e");
    std::fs::create_dir_all(&proj_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();

    let consumer_json = serde_json::json!({
        "name": "consumer-app-e",
        "version": "1.0.0",
        "dependencies": {
            "pkg-git-prepare-reg": git_url
        }
    });
    std::fs::write(proj_dir.join("package.json"), consumer_json.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.clone(),
        cache_dir: Some(cache_dir),
        registry_url: Some(server.url()),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install should succeed with default allow-registry=all");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg = proj_dir.join("node_modules").join("pkg-git-prepare-reg");
    let built_file = installed_pkg.join("dist").join("built.js");
    assert!(
        built_file.exists(),
        "Expected dist/built.js to be built by registry devDependency tool"
    );
    let built_content = std::fs::read_to_string(&built_file).unwrap();
    assert!(
        built_content.contains("module.exports = 999;"),
        "Content mismatch: {built_content}"
    );

    // Verify registry request occurred
    assert!(
        server.request_count().await > 0,
        "Expected registry requests under allow-registry=all"
    );

    assert_no_git_leaks(&installed_pkg);
}
