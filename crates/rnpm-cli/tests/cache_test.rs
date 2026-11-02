use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_cache_clean_requires_force() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("cache")
        .arg("clean")
        .arg("--cache")
        .arg(&cache_dir)
        .output()
        .expect("Failed to execute rnpm cache clean");

    assert!(!output.status.success(), "Expected failure without --force");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("As of npm@5, the npm cache self-heals"));
    assert!(stderr.contains("rnpm cache clean --force"));
}

#[test]
fn test_cli_cache_clean_with_force() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let content_dir = cache_dir.join("_cacache").join("content-v2");
    fs::create_dir_all(&content_dir).unwrap();
    fs::write(content_dir.join("test-blob"), "dummy-blob-data").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("cache")
        .arg("clean")
        .arg("--force")
        .arg("--cache")
        .arg(&cache_dir)
        .output()
        .expect("Failed to execute rnpm cache clean --force");

    assert!(output.status.success(), "Command failed: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm: cache cleared successfully"));

    assert!(!content_dir.join("test-blob").exists());
}

#[test]
fn test_cli_cache_verify() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("cache")
        .arg("verify")
        .arg("--cache")
        .arg(&cache_dir)
        .output()
        .expect("Failed to execute rnpm cache verify");

    assert!(output.status.success(), "Command failed: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cache verified and compacted"));
    assert!(stdout.contains("Content verified:"));
    assert!(stdout.contains("Index entries:"));
}
