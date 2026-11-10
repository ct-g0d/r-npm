use std::path::Path;
use tempfile::tempdir;

use rnpm_core::spec::PackageTarget;
use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::LockfileV3;

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

fn get_git_output(dir: &Path, args: &[&str]) -> String {
    let _ = std::fs::write(dir.join(".empty_gitconfig"), "");
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join(".empty_gitconfig"))
        .output()
        .expect("Failed to execute git command");
    assert!(
        output.status.success(),
        "Git command failed: git {:?}",
        args
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn init_test_git_repo(path: &Path, name: &str, version: &str) -> (String, String) {
    std::fs::create_dir_all(path).unwrap();
    run_git(path, &["init"]);
    run_git(path, &["config", "user.name", "Tester"]);
    run_git(path, &["config", "user.email", "test@example.com"]);

    let manifest = serde_json::json!({
        "name": name,
        "version": version,
        "description": "test git dependency",
        "main": "index.js"
    });
    std::fs::write(path.join("package.json"), manifest.to_string()).unwrap();
    std::fs::write(path.join("index.js"), "module.exports = 'git pkg v1';\n").unwrap();

    run_git(path, &["add", "."]);
    run_git(path, &["commit", "-m", "Initial commit"]);

    let sha = get_git_output(path, &["rev-parse", "HEAD"]);
    let path_str = path.to_str().unwrap().replace('\\', "/");
    let url = format!("git+file://{path_str}");
    (sha, url)
}

#[test]
fn test_git_spec_target_parsing() {
    // github:
    let t1 = PackageTarget::parse("github:facebook/react#v18.2.0").unwrap();
    assert!(t1.is_git());
    assert_eq!(
        t1.git_clone_url().unwrap(),
        "https://github.com/facebook/react.git"
    );
    assert_eq!(t1.git_committish(), Some("v18.2.0"));

    // git+https:
    let t2 = PackageTarget::parse("git+https://github.com/org/repo.git#commit123").unwrap();
    assert!(t2.is_git());
    assert_eq!(
        t2.git_clone_url().unwrap(),
        "https://github.com/org/repo.git"
    );
    assert_eq!(t2.git_committish(), Some("commit123"));

    // git+ssh:
    let t3 = PackageTarget::parse("git+ssh://git@github.com/org/repo.git#main").unwrap();
    assert!(t3.is_git());
    assert_eq!(
        t3.git_clone_url().unwrap(),
        "ssh://git@github.com/org/repo.git"
    );
    assert_eq!(t3.git_committish(), Some("main"));

    // git://:
    let t4 = PackageTarget::parse("git://github.com/org/repo.git").unwrap();
    assert!(t4.is_git());
    assert_eq!(t4.git_clone_url().unwrap(), "git://github.com/org/repo.git");
    assert_eq!(t4.git_committish(), None);

    // gitlab:
    let t5 = PackageTarget::parse("gitlab:gitlab-org/gitlab#v2.0").unwrap();
    assert!(t5.is_git());
    assert_eq!(
        t5.git_clone_url().unwrap(),
        "https://gitlab.com/gitlab-org/gitlab.git"
    );
    assert_eq!(t5.git_committish(), Some("v2.0"));

    // bitbucket:
    let t6 = PackageTarget::parse("bitbucket:atlassian/repo#feature-branch").unwrap();
    assert!(t6.is_git());
    assert_eq!(
        t6.git_clone_url().unwrap(),
        "https://bitbucket.org/atlassian/repo.git"
    );
    assert_eq!(t6.git_committish(), Some("feature-branch"));
}

#[tokio::test]
async fn test_git_install_commit_and_tag_ref() {
    let repo_dir = tempdir().unwrap();
    let (commit1, git_url) = init_test_git_repo(repo_dir.path(), "my-git-dep", "1.0.0");
    run_git(repo_dir.path(), &["tag", "v1.0.0"]);

    // Commit a second version
    let manifest2 = serde_json::json!({
        "name": "my-git-dep",
        "version": "2.0.0"
    });
    std::fs::write(repo_dir.path().join("package.json"), manifest2.to_string()).unwrap();
    run_git(repo_dir.path(), &["commit", "-am", "Version 2.0.0"]);
    run_git(repo_dir.path(), &["tag", "v2.0.0"]);

    // Consumer project requesting v1.0.0 tag
    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-app",
        "version": "1.0.0",
        "dependencies": {
            "my-git-dep": format!("{git_url}#v1.0.0")
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
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

    // Verify extracted package in node_modules
    let installed_pkg_json = proj_dir.path().join("node_modules/my-git-dep/package.json");
    assert!(installed_pkg_json.exists());
    let installed_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&installed_pkg_json).unwrap()).unwrap();
    assert_eq!(installed_json["version"], "1.0.0");

    // Verify package-lock.json contains resolved commit SHA
    let lockfile = LockfileV3::load_from_file(&proj_dir.path().join("package-lock.json")).unwrap();
    let lock_entry = lockfile
        .get_package("node_modules/my-git-dep")
        .expect("Missing lock entry");
    assert_eq!(lock_entry.version.as_deref(), Some("1.0.0"));
    let resolved = lock_entry.resolved.as_ref().expect("Missing resolved URL");
    assert!(
        resolved.contains(&commit1),
        "Resolved URL '{resolved}' should contain commit SHA '{commit1}'"
    );

    // Verify cache remote exists
    assert!(cache_dir.path().join("_git-remotes").exists());
}

#[tokio::test]
async fn test_git_install_branch_ref() {
    let repo_dir = tempdir().unwrap();
    let (_commit1, git_url) = init_test_git_repo(repo_dir.path(), "branch-dep", "1.0.0");

    // Create a new branch with different contents
    run_git(repo_dir.path(), &["checkout", "-b", "feature-x"]);
    let manifest_branch = serde_json::json!({
        "name": "branch-dep",
        "version": "1.5.0-feat",
        "main": "feature.js"
    });
    std::fs::write(
        repo_dir.path().join("package.json"),
        manifest_branch.to_string(),
    )
    .unwrap();
    std::fs::write(
        repo_dir.path().join("feature.js"),
        "module.exports = 'feature-x';\n",
    )
    .unwrap();
    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "Feature commit"]);

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-branch",
        "dependencies": {
            "branch-dep": format!("{git_url}#feature-x")
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install branch failed");
    assert_eq!(summary.packages_installed, 1);

    let installed_pkg_json = proj_dir.path().join("node_modules/branch-dep/package.json");
    let installed_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&installed_pkg_json).unwrap()).unwrap();
    assert_eq!(installed_json["version"], "1.5.0-feat");
    assert!(proj_dir
        .path()
        .join("node_modules/branch-dep/feature.js")
        .exists());
}

#[tokio::test]
async fn test_git_install_direct_commit_sha() {
    let repo_dir = tempdir().unwrap();
    let (commit_sha, git_url) = init_test_git_repo(repo_dir.path(), "sha-dep", "1.0.0");

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-sha",
        "dependencies": {
            "sha-dep": format!("{git_url}#{commit_sha}")
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let summary = installer.install().await.expect("Install SHA failed");
    assert_eq!(summary.packages_installed, 1);
    assert!(proj_dir
        .path()
        .join("node_modules/sha-dep/package.json")
        .exists());
}

#[tokio::test]
async fn test_git_install_semver_tag_resolution() {
    let repo_dir = tempdir().unwrap();
    let (_c1, git_url) = init_test_git_repo(repo_dir.path(), "semver-git-dep", "1.0.0");
    run_git(repo_dir.path(), &["tag", "v1.0.0"]);

    std::fs::write(
        repo_dir.path().join("package.json"),
        r#"{"name":"semver-git-dep","version":"1.2.0"}"#,
    )
    .unwrap();
    run_git(repo_dir.path(), &["commit", "-am", "v1.2.0"]);
    run_git(repo_dir.path(), &["tag", "v1.2.0"]);

    std::fs::write(
        repo_dir.path().join("package.json"),
        r#"{"name":"semver-git-dep","version":"2.0.0"}"#,
    )
    .unwrap();
    run_git(repo_dir.path(), &["commit", "-am", "v2.0.0"]);
    run_git(repo_dir.path(), &["tag", "v2.0.0"]);

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-semver",
        "dependencies": {
            "semver-git-dep": format!("{git_url}#semver:^1.0.0")
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    installer
        .install()
        .await
        .expect("Install semver git failed");

    let installed_pkg_json = proj_dir
        .path()
        .join("node_modules/semver-git-dep/package.json");
    let installed_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&installed_pkg_json).unwrap()).unwrap();
    // ^1.0.0 should select highest 1.x tag -> 1.2.0
    assert_eq!(installed_json["version"], "1.2.0");
}

#[tokio::test]
async fn test_git_caching_and_offline_mode() {
    let repo_dir = tempdir().unwrap();
    let (_commit1, git_url) = init_test_git_repo(repo_dir.path(), "cached-dep", "1.0.0");

    let cache_dir = tempdir().unwrap();

    // 1. Initial online install populates cache
    let proj1_dir = tempdir().unwrap();
    let manifest1 = serde_json::json!({
        "name": "proj1",
        "dependencies": {
            "cached-dep": git_url.clone()
        }
    });
    std::fs::write(proj1_dir.path().join("package.json"), manifest1.to_string()).unwrap();

    let mut installer1 = Installer::new(InstallOptions {
        project_dir: proj1_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        offline: false,
        ..Default::default()
    })
    .unwrap();
    installer1.install().await.expect("Online install failed");

    // 2. Offline install with cached repo succeeds
    let proj2_dir = tempdir().unwrap();
    let manifest2 = serde_json::json!({
        "name": "proj2",
        "dependencies": {
            "cached-dep": git_url.clone()
        }
    });
    std::fs::write(proj2_dir.path().join("package.json"), manifest2.to_string()).unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: proj2_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        offline: true,
        ..Default::default()
    })
    .unwrap();
    installer2
        .install()
        .await
        .expect("Offline install should succeed with cached repo");
    assert!(proj2_dir
        .path()
        .join("node_modules/cached-dep/package.json")
        .exists());

    // 3. Offline install with UNCACHED repo fails gracefully
    let proj3_dir = tempdir().unwrap();
    let manifest3 = serde_json::json!({
        "name": "proj3",
        "dependencies": {
            "uncached-dep": "git+https://github.com/definitely/not-cached-repo.git#main"
        }
    });
    std::fs::write(proj3_dir.path().join("package.json"), manifest3.to_string()).unwrap();

    let mut installer3 = Installer::new(InstallOptions {
        project_dir: proj3_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        offline: true,
        ..Default::default()
    })
    .unwrap();
    let err = installer3.install().await.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("offline mode"),
        "Error should indicate offline failure: {err}"
    );
}

#[tokio::test]
async fn test_git_invalid_ref_error_handling() {
    let repo_dir = tempdir().unwrap();
    let (_c, git_url) = init_test_git_repo(repo_dir.path(), "invalid-ref-dep", "1.0.0");

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let manifest = serde_json::json!({
        "name": "proj-invalid-ref",
        "dependencies": {
            "invalid-ref-dep": format!("{git_url}#non-existent-tag-or-branch-12345")
        }
    });
    std::fs::write(proj_dir.path().join("package.json"), manifest.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let err = installer.install().await.unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "Expected ref not found error: {err}"
    );
}

#[tokio::test]
async fn test_git_clone_failure_error_handling() {
    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let manifest = serde_json::json!({
        "name": "proj-clone-fail",
        "dependencies": {
            "bad-repo": "git+file:///definitely/nonexistent/repo/on/disk.git"
        }
    });
    std::fs::write(proj_dir.path().join("package.json"), manifest.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let err = installer.install().await.unwrap_err();
    assert!(
        err.to_string().contains("Failed to clone git repository"),
        "Expected clone failure error: {err}"
    );
}

#[tokio::test]
async fn test_git_missing_package_json_error_handling() {
    let repo_dir = tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path()).unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(
        repo_dir.path(),
        &["config", "user.email", "test@example.com"],
    );
    std::fs::write(repo_dir.path().join("README.md"), "No package.json here\n").unwrap();
    run_git(repo_dir.path(), &["add", "."]);
    run_git(
        repo_dir.path(),
        &["commit", "-m", "init without package.json"],
    );

    let path_str = repo_dir.path().to_str().unwrap().replace('\\', "/");
    let git_url = format!("git+file://{path_str}");

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let manifest = serde_json::json!({
        "name": "proj-missing-json",
        "dependencies": {
            "no-json": git_url
        }
    });
    std::fs::write(proj_dir.path().join("package.json"), manifest.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let err = installer.install().await.unwrap_err();
    assert!(
        err.to_string().contains("package.json not found"),
        "Expected missing package.json error: {err}"
    );
}

#[tokio::test]
async fn test_git_ci_workflow() {
    let repo_dir = tempdir().unwrap();
    let (commit_sha, git_url) = init_test_git_repo(repo_dir.path(), "ci-git-dep", "1.0.0");

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let manifest = serde_json::json!({
        "name": "ci-consumer",
        "dependencies": {
            "ci-git-dep": git_url
        }
    });
    std::fs::write(proj_dir.path().join("package.json"), manifest.to_string()).unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    // 1. Initial install generates lockfile
    installer.install().await.expect("Install failed");
    assert!(proj_dir.path().join("package-lock.json").exists());

    // 2. Remove node_modules
    let node_modules = proj_dir.path().join("node_modules");
    std::fs::remove_dir_all(&node_modules).unwrap();
    assert!(!node_modules.exists());

    // 3. Run CI
    let ci_summary = installer.ci().await.expect("CI run failed");
    assert_eq!(ci_summary.packages_installed, 1);

    // 4. Verify node_modules restored from git
    let restored_json = proj_dir.path().join("node_modules/ci-git-dep/package.json");
    assert!(restored_json.exists());
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&restored_json).unwrap()).unwrap();
    assert_eq!(parsed["name"], "ci-git-dep");
    assert_eq!(parsed["version"], "1.0.0");

    // Verify lockfile matches manifest
    let lockfile = LockfileV3::load_from_file(&proj_dir.path().join("package-lock.json")).unwrap();
    let lock_entry = lockfile.get_package("node_modules/ci-git-dep").unwrap();
    assert!(lock_entry.resolved.as_ref().unwrap().contains(&commit_sha));
}

#[tokio::test]
async fn test_git_bin_shims() {
    let repo_dir = tempdir().unwrap();
    std::fs::create_dir_all(repo_dir.path()).unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(
        repo_dir.path(),
        &["config", "user.email", "test@example.com"],
    );

    let manifest = serde_json::json!({
        "name": "bin-git-dep",
        "version": "1.0.0",
        "bin": {
            "git-tool": "./bin/cli.js"
        }
    });
    std::fs::write(repo_dir.path().join("package.json"), manifest.to_string()).unwrap();
    std::fs::create_dir_all(repo_dir.path().join("bin")).unwrap();
    std::fs::write(
        repo_dir.path().join("bin/cli.js"),
        "#!/usr/bin/env node\nconsole.log('hi');\n",
    )
    .unwrap();
    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "add bin"]);

    let path_str = repo_dir.path().to_str().unwrap().replace('\\', "/");
    let git_url = format!("git+file://{path_str}");

    let proj_dir = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-bin",
        "dependencies": {
            "bin-git-dep": git_url
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    installer.install().await.expect("Install with bin failed");

    let bin_dir = proj_dir.path().join("node_modules/.bin");
    #[cfg(windows)]
    {
        assert!(
            bin_dir.join("git-tool.cmd").exists()
                || bin_dir.join("git-tool.ps1").exists()
                || bin_dir.join("git-tool").exists()
        );
    }
    #[cfg(not(windows))]
    {
        assert!(bin_dir.join("git-tool").exists());
    }
}

#[tokio::test]
async fn test_git_dependency_runs_prepare_lifecycle() {
    let repo_dir = tempdir().unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(
        repo_dir.path(),
        &["config", "user.email", "test@example.com"],
    );

    let proj_dir = tempdir().unwrap();
    let marker_path = proj_dir.path().join("git_prepare_executed.txt");
    let escaped_marker = marker_path.to_string_lossy().replace('\\', "/");

    let manifest = serde_json::json!({
        "name": "lifecycle-git-dep",
        "version": "1.0.0",
        "scripts": {
            "prepare": format!("node -e \"require('fs').writeFileSync('{escaped_marker}', 'git prepare ran')\"")
        }
    });
    std::fs::write(repo_dir.path().join("package.json"), manifest.to_string()).unwrap();
    std::fs::write(repo_dir.path().join("index.js"), "module.exports = {};\n").unwrap();
    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "add prepare script"]);

    let path_str = repo_dir.path().to_str().unwrap().replace('\\', "/");
    let git_url = format!("git+file://{path_str}");

    let cache_dir = tempdir().unwrap();

    let consumer_manifest = serde_json::json!({
        "name": "consumer-git-prepare",
        "dependencies": {
            "lifecycle-git-dep": git_url
        }
    });
    std::fs::write(
        proj_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer = Installer::new(InstallOptions {
        project_dir: proj_dir.path().to_path_buf(),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    installer
        .install()
        .await
        .expect("Install git dep with prepare script failed");

    assert!(
        marker_path.exists(),
        "Git dependency prepare script MUST be executed during install"
    );
    let content = std::fs::read_to_string(&marker_path).unwrap();
    assert_eq!(content, "git prepare ran");
}
