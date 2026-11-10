use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn rnpm_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rnpm")
}

fn git_cmd(path: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(path);
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", path.join(".empty_gitconfig"));
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

fn init_git_repo(path: &Path) {
    let _ = fs::write(path.join(".empty_gitconfig"), "");
    let out = git_cmd(path)
        .args(["init"])
        .output()
        .expect("git init failed");
    assert!(out.status.success(), "git init failed: {:?}", out);

    git_cmd(path)
        .args(["config", "user.name", "Test User"])
        .output()
        .expect("git config user.name failed");

    git_cmd(path)
        .args(["config", "user.email", "test@example.com"])
        .output()
        .expect("git config user.email failed");

    git_cmd(path)
        .args(["config", "commit.gpgSign", "false"])
        .output()
        .expect("git config commit.gpgSign failed");

    git_cmd(path)
        .args(["config", "tag.gpgSign", "false"])
        .output()
        .expect("git config tag.gpgSign failed");
}

fn git_commit_all(path: &Path, msg: &str) {
    git_cmd(path)
        .args(["add", "."])
        .output()
        .expect("git add failed");

    let out = git_cmd(path)
        .args(["commit", "-m", msg])
        .output()
        .expect("git commit failed");
    assert!(out.status.success(), "git commit failed: {:?}", out);
}

#[test]
fn test_version_bump_types_and_preid() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let initial_pkg = r#"{
  "name": "bump-test",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), initial_pkg).unwrap();

    // 1. patch: 1.0.0 -> 1.0.1
    let out = Command::new(rnpm_bin())
        .args(["version", "patch", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "patch failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v1.0.1");

    // 2. minor: 1.0.1 -> 1.1.0
    let out = Command::new(rnpm_bin())
        .args(["version", "minor", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "minor failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v1.1.0");

    // 3. major: 1.1.0 -> 2.0.0
    let out = Command::new(rnpm_bin())
        .args(["version", "major", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "major failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v2.0.0");

    // 4. premajor with preid=alpha: 2.0.0 -> 3.0.0-alpha.0
    let out = Command::new(rnpm_bin())
        .args([
            "version",
            "premajor",
            "--preid=alpha",
            "--no-git-tag-version",
        ])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "premajor failed: {:?}", out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "v3.0.0-alpha.0"
    );

    // 5. prerelease with preid=alpha: 3.0.0-alpha.0 -> 3.0.0-alpha.1
    let out = Command::new(rnpm_bin())
        .args([
            "version",
            "prerelease",
            "--preid=alpha",
            "--no-git-tag-version",
        ])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "prerelease failed: {:?}", out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "v3.0.0-alpha.1"
    );

    // 6. preminor with preid=beta: 3.0.0-alpha.1 -> 3.1.0-beta.0
    let out = Command::new(rnpm_bin())
        .args([
            "version",
            "preminor",
            "--preid=beta",
            "--no-git-tag-version",
        ])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "preminor failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v3.1.0-beta.0");

    // 7. prepatch with preid=rc: 3.1.0-beta.0 -> 3.1.1-rc.0
    let out = Command::new(rnpm_bin())
        .args(["version", "prepatch", "--preid=rc", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "prepatch failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v3.1.1-rc.0");

    // 8. explicit semver: 4.5.6 -> 4.5.6
    let out = Command::new(rnpm_bin())
        .args(["version", "4.5.6", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "explicit version failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v4.5.6");

    // 9. explicit semver with leading v: v5.0.0 -> 5.0.0
    let out = Command::new(rnpm_bin())
        .args(["version", "v5.0.0", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "leading v version failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v5.0.0");
}

#[test]
fn test_version_updates_package_json_and_package_lock() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = r#"{
  "name": "my-library",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let lock_json = r#"{
  "name": "my-library",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "my-library",
      "version": "1.0.0"
    }
  }
}
"#;
    fs::write(project_dir.join("package-lock.json"), lock_json).unwrap();

    let out = Command::new(rnpm_bin())
        .args(["version", "minor", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "Failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v1.1.0");

    // Verify package.json
    let pkg_content = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(
        pkg_content.ends_with('\n'),
        "package.json must end with trailing newline"
    );
    let parsed_pkg: serde_json::Value = serde_json::from_str(&pkg_content).unwrap();
    assert_eq!(parsed_pkg["version"], "1.1.0");
    assert!(
        pkg_content.contains("  \"version\": \"1.1.0\""),
        "Must have 2-space indentation"
    );

    // Verify package-lock.json
    let lock_content = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(
        lock_content.ends_with('\n'),
        "package-lock.json must end with trailing newline"
    );
    let parsed_lock: serde_json::Value = serde_json::from_str(&lock_content).unwrap();
    assert_eq!(parsed_lock["version"], "1.1.0");
    assert_eq!(parsed_lock["packages"][""]["version"], "1.1.0");
    assert!(
        lock_content.contains("  \"version\": \"1.1.0\""),
        "Must have 2-space indentation"
    );
}

#[test]
fn test_version_lifecycle_scripts_order_and_ignore() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = r#"{
  "name": "lifecycle-pkg",
  "version": "1.0.0",
  "scripts": {
    "preversion": "node -e \"require('fs').appendFileSync('events.txt', 'preversion:' + process.env.npm_old_version + '->' + process.env.npm_new_version + '\\n')\"",
    "version": "node -e \"require('fs').appendFileSync('events.txt', 'version:' + process.env.npm_old_version + '->' + process.env.npm_new_version + '\\n')\"",
    "postversion": "node -e \"require('fs').appendFileSync('events.txt', 'postversion:' + process.env.npm_old_version + '->' + process.env.npm_new_version + '\\n')\""
  }
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    let out = Command::new(rnpm_bin())
        .args(["version", "patch", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "Execution failed: {:?}", out);

    let events_file = project_dir.join("events.txt");
    assert!(events_file.exists(), "events.txt should have been created");
    let events = fs::read_to_string(&events_file).unwrap();
    let lines: Vec<&str> = events.lines().collect();
    assert_eq!(
        lines,
        vec![
            "preversion:1.0.0->1.0.1",
            "version:1.0.0->1.0.1",
            "postversion:1.0.0->1.0.1"
        ],
        "Lifecycle scripts must execute in exact order"
    );

    // Test --ignore-scripts
    fs::remove_file(&events_file).unwrap();
    let out_ignore = Command::new(rnpm_bin())
        .args([
            "version",
            "minor",
            "--no-git-tag-version",
            "--ignore-scripts",
        ])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        out_ignore.status.success(),
        "Failed with --ignore-scripts: {:?}",
        out_ignore
    );
    assert!(
        !events_file.exists(),
        "Lifecycle scripts must not run when --ignore-scripts is set"
    );
}

#[test]
fn test_version_git_integration_commit_and_tag() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    init_git_repo(project_dir);

    let pkg_json = r#"{
  "name": "git-app",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();
    git_commit_all(project_dir, "initial commit");

    // Bump patch with custom message
    let out = Command::new(rnpm_bin())
        .args(["version", "patch", "-m", "Release %s"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "version patch failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v1.0.1");

    // Verify git commit message
    let log_out = Command::new("git")
        .args(["log", "-1", "--pretty=%B"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    let commit_msg = String::from_utf8_lossy(&log_out.stdout);
    assert!(
        commit_msg.contains("Release 1.0.1"),
        "Expected message 'Release 1.0.1', got: {}",
        commit_msg
    );

    // Verify annotated git tag
    let describe_out = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(describe_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&describe_out.stdout).trim(),
        "v1.0.1"
    );

    // Verify tag annotation message
    let tag_out = Command::new("git")
        .args(["tag", "-l", "-n1", "v1.0.1"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    let tag_annotation = String::from_utf8_lossy(&tag_out.stdout);
    assert!(
        tag_annotation.contains("Release 1.0.1"),
        "Expected tag annotation to contain message"
    );

    // Verify working copy is clean
    let status_out = Command::new("git")
        .args(["status", "--porcelain", "-uno"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&status_out.stdout)
            .trim()
            .is_empty(),
        "Working directory must be clean"
    );

    // Test dirty working copy check
    fs::write(project_dir.join("tracked.txt"), "hello").unwrap();
    Command::new("git")
        .args(["add", "tracked.txt"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "add tracked"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    fs::write(project_dir.join("tracked.txt"), "hello world modified").unwrap();

    let dirty_out = Command::new(rnpm_bin())
        .args(["version", "minor"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        !dirty_out.status.success(),
        "Must fail when working copy is dirty"
    );
    let stderr = String::from_utf8_lossy(&dirty_out.stderr);
    assert!(
        stderr.contains("Git working directory not clean"),
        "Expected clean working dir error, got: {}",
        stderr
    );

    // Test force overrides dirty working copy
    let force_out = Command::new(rnpm_bin())
        .args(["version", "minor", "--force"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        force_out.status.success(),
        "Must succeed with --force on dirty working copy: {:?}",
        force_out
    );
}

#[test]
fn test_version_no_git_tag_version_skips_git() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    init_git_repo(project_dir);

    let pkg_json = r#"{
  "name": "skip-git-app",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();
    git_commit_all(project_dir, "initial commit");

    // 1. Using --no-git-tag-version
    let out = Command::new(rnpm_bin())
        .args(["version", "minor", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "Failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v1.1.0");

    // Verify git tag was not created
    let describe_out = Command::new("git")
        .args(["describe", "--tags"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        !describe_out.status.success(),
        "No git tag should have been created"
    );

    // Verify working copy shows uncommitted change
    let status_out = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status_str.contains("package.json"),
        "package.json should be modified but uncommitted"
    );

    // 2. Using --git-tag-version=false
    git_commit_all(project_dir, "commit 1.1.0");
    let out2 = Command::new(rnpm_bin())
        .args(["version", "patch", "--git-tag-version=false"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "Failed with --git-tag-version=false: {:?}",
        out2
    );
    assert_eq!(String::from_utf8_lossy(&out2.stdout).trim(), "v1.1.1");

    let describe_out2 = Command::new("git")
        .args(["describe", "--tags"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        !describe_out2.status.success(),
        "No git tag should have been created with --git-tag-version=false"
    );
}

#[test]
fn test_bare_version_display_map_and_json() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = r#"{
  "name": "sample-bare-app",
  "version": "3.2.1"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    // 1. Bare rnpm version text mode
    let out = Command::new(rnpm_bin())
        .args(["version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "Bare version failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sample-bare-app': '3.2.1'"),
        "Output should contain package name and version: {}",
        stdout
    );
    assert!(
        stdout.contains("npm: '11.20.0'"),
        "Output should contain npm version: {}",
        stdout
    );
    assert!(
        stdout.contains("node: '"),
        "Output should contain node version: {}",
        stdout
    );

    // 2. Bare rnpm version --json
    let out_json = Command::new(rnpm_bin())
        .args(["version", "--json"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        out_json.status.success(),
        "Bare version --json failed: {:?}",
        out_json
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out_json.stdout).expect("Output must be valid JSON");
    assert_eq!(parsed["sample-bare-app"], "3.2.1");
    assert_eq!(parsed["npm"], "11.20.0");
    assert!(parsed.get("node").is_some());
}

#[test]
fn test_version_allow_same_version() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = r#"{
  "name": "same-version-app",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();

    // Without --allow-same-version, bumping to 1.0.0 should error
    let out = Command::new(rnpm_bin())
        .args(["version", "1.0.0", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "Should fail when version is not changed without flag"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Version not changed"),
        "Expected 'Version not changed', got: {}",
        stderr
    );

    // With --allow-same-version, it should succeed
    let out_allow = Command::new(rnpm_bin())
        .args([
            "version",
            "1.0.0",
            "--no-git-tag-version",
            "--allow-same-version",
        ])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(
        out_allow.status.success(),
        "Should succeed with --allow-same-version: {:?}",
        out_allow
    );
    assert_eq!(String::from_utf8_lossy(&out_allow.stdout).trim(), "v1.0.0");
}

#[test]
fn test_version_from_git() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    init_git_repo(project_dir);

    let pkg_json = r#"{
  "name": "from-git-app",
  "version": "1.0.0"
}
"#;
    fs::write(project_dir.join("package.json"), pkg_json).unwrap();
    git_commit_all(project_dir, "initial commit");

    // Create an annotated git tag v2.5.0
    Command::new("git")
        .args(["tag", "-a", "-m", "tag 2.5.0", "v2.5.0"])
        .current_dir(project_dir)
        .output()
        .unwrap();

    // Run rnpm version from-git
    let out = Command::new(rnpm_bin())
        .args(["version", "from-git", "--no-git-tag-version"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "from-git failed: {:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "v2.5.0");

    let content = fs::read_to_string(project_dir.join("package.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["version"], "2.5.0");
}
