use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cache_npx_ls_nonexistent() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    // do not create cache_dir/_npx

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .args(["cache", "npx", "ls", "--cache", cache_dir.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnpm cache npx ls");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npx cache does not exist"));
}

#[test]
fn test_cache_npx_ls_populated() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    fs::create_dir_all(&npx_dir).unwrap();

    let entry1 = npx_dir.join("0123456789abcdef");
    fs::create_dir_all(&entry1).unwrap();
    fs::write(
        entry1.join("package.json"),
        r#"{"_npx":{"packages":["cowsay@^1.5.0","chalk@^4.0.0"]}}"#,
    )
    .unwrap();

    let entry2 = npx_dir.join("fedcba9876543210");
    fs::create_dir_all(&entry2).unwrap();
    // No package.json -> empty/invalid

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .args(["cache", "npx", "ls", "--cache", cache_dir.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnpm cache npx ls");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0123456789abcdef: cowsay@^1.5.0, chalk@^4.0.0"));
    assert!(stdout.contains("fedcba9876543210: (empty/invalid)"));
}

#[test]
fn test_cache_npx_info_requires_key() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .args(["cache", "npx", "info", "--cache", cache_dir.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnpm cache npx info");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("npx info requires at least one key"));
}

#[test]
fn test_cache_npx_info_valid_and_abbrev() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    let entry_dir = npx_dir.join("a1b2c3d4e5f67890");
    fs::create_dir_all(&entry_dir).unwrap();
    fs::write(
        entry_dir.join("package.json"),
        r#"{"_npx":{"packages":["cowsay@^1.5.0"]}}"#,
    )
    .unwrap();

    // Mock installed package version in node_modules
    let nm_cowsay = entry_dir.join("node_modules").join("cowsay");
    fs::create_dir_all(&nm_cowsay).unwrap();
    fs::write(
        nm_cowsay.join("package.json"),
        r#"{"name":"cowsay","version":"1.5.0"}"#,
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test with prefix abbreviation "a1b2"
    let output = Command::new(rnpm_bin)
        .args([
            "cache",
            "npx",
            "info",
            "a1b2",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute rnpm cache npx info");

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid npx cache entry with key a1b2c3d4e5f67890"));
    assert!(stdout.contains("location:"));
    assert!(stdout.contains("packages:"));
    assert!(stdout.contains("- cowsay@^1.5.0 (cowsay@1.5.0)"));
}

#[test]
fn test_cache_npx_info_invalid_key() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    fs::create_dir_all(&npx_dir).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .args([
            "cache",
            "npx",
            "info",
            "nonexistent",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute rnpm cache npx info");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid npx key nonexistent"));
}

#[test]
fn test_cache_npx_rm_requires_force_without_keys() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    fs::create_dir_all(&npx_dir).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .args(["cache", "npx", "rm", "--cache", cache_dir.to_str().unwrap()])
        .output()
        .expect("Failed to execute rnpm cache npx rm");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Please use --force to remove entire npx cache"));
}

#[test]
fn test_cache_npx_rm_force_and_dry_run() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    fs::create_dir_all(&npx_dir).unwrap();
    let entry = npx_dir.join("aabbccddeeff0011");
    fs::create_dir_all(&entry).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test with --force --dry-run
    let output = Command::new(rnpm_bin)
        .args([
            "cache",
            "npx",
            "rm",
            "--force",
            "--dry-run",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute rnpm cache npx rm --force --dry-run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().is_empty(), "npm cache npx rm without keys is silent");
    assert!(npx_dir.exists(), "Directory should still exist after dry-run");

    // Test with --force
    let output2 = Command::new(rnpm_bin)
        .args([
            "cache",
            "npx",
            "rm",
            "--force",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute rnpm cache npx rm --force");

    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout2.trim().is_empty(), "npm cache npx rm without keys is silent");
    assert!(!npx_dir.exists(), "Directory should be removed with --force");
}

#[test]
fn test_cache_npx_rm_keys_and_abbrev() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let npx_dir = cache_dir.join("_npx");
    let entry1 = npx_dir.join("1122334455667788");
    let entry2 = npx_dir.join("9988776655443322");
    fs::create_dir_all(&entry1).unwrap();
    fs::create_dir_all(&entry2).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Remove entry1 by prefix abbreviation "1122"
    let output = Command::new(rnpm_bin)
        .args([
            "cache",
            "npx",
            "rm",
            "1122",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute rnpm cache npx rm 1122");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Removing npx key at"));
    assert!(!entry1.exists(), "entry1 should have been removed");
    assert!(entry2.exists(), "entry2 should remain");
}
