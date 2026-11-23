use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_exec_no_yes_flag_cancels_with_exit_code_1_and_no_mutations() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--no-yes",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"nonexistent-missing-pkg-12345\"]"),
        "stderr was: {stderr}"
    );

    // Verify no _npx package directory was created in cache
    let npx_cache = cache_dir.join("_npx");
    assert!(
        !npx_cache.exists() || fs::read_dir(&npx_cache).unwrap().count() == 0,
        "No npx cache mutations should occur on cancel"
    );
}

#[test]
fn test_exec_yes_false_flag_cancels_with_exit_code_1() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--yes=false",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"nonexistent-missing-pkg-12345\"]"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_exec_npmrc_yes_false_cancels_with_exit_code_1() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    // Create .npmrc with yes=false
    fs::write(tmp.path().join(".npmrc"), "yes=false\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"nonexistent-missing-pkg-12345\"]"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_exec_cli_yes_overrides_npmrc_yes_false() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    // Create .npmrc with yes=false
    fs::write(tmp.path().join(".npmrc"), "yes=false\n").unwrap();

    // Running with --yes overrides .npmrc. With --offline, it proceeds past consent check
    // and fails with offline error, NOT the missing-packages-and-no-YES-option error.
    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--yes",
            "--offline",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("npx canceled due to missing packages and no YES option"),
        "--yes should have overridden .npmrc yes=false, but got: {stderr}"
    );
    assert!(
        stderr.contains("offline") || stderr.contains("ENOTCACHED"),
        "Should reach offline check: {stderr}"
    );
}

#[test]
fn test_exec_cli_no_yes_overrides_npmrc_yes_true() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    // Create .npmrc with yes=true
    fs::write(tmp.path().join(".npmrc"), "yes=true\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--no-yes",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"nonexistent-missing-pkg-12345\"]"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_exec_package_flag_no_yes_cancels_with_multiple_packages() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "-p",
            "pkg-foo@1.0.0",
            "-p",
            "pkg-bar@2.0.0",
            "--no-yes",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "custom-bin",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"pkg-foo@1.0.0\",\"pkg-bar@2.0.0\"]"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_exec_call_package_flag_no_yes_cancels() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--package=pkg-call-only@1.0.0",
            "--no-yes",
            "-c",
            "echo hello",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"pkg-call-only@1.0.0\"]"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_exec_non_tty_unset_emits_warning() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    // In non-TTY / CI (which subprocess execution is), an unset consent emits npm's warn message
    // before attempting to fetch/install. With --offline, it then fails with ENOTCACHED/offline.
    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "exec",
            "--offline",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "some-missing-tool@1.2.3",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm warn exec The following package was not found and will be installed: some-missing-tool@1.2.3"),
        "stderr was: {stderr}"
    );
}

#[test]
fn test_npx_alias_no_yes_cancels() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args([
            "npx",
            "--no-yes",
            "--cache",
            cache_dir.to_str().unwrap(),
            "--",
            "nonexistent-missing-pkg-12345",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error npx canceled due to missing packages and no YES option: [\"nonexistent-missing-pkg-12345\"]"),
        "stderr was: {stderr}"
    );
}
