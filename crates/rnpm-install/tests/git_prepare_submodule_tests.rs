use std::path::Path;
use tempfile::tempdir;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Builder, Header};

use rnpm_install::{InstallOptions, Installer};

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
