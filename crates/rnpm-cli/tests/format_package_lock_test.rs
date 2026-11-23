use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn setup_fixture(dir: &std::path::Path) {
    let pkgs_dir = dir.join("packages").join("pkg-a");
    fs::create_dir_all(&pkgs_dir).unwrap();
    fs::write(
        pkgs_dir.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0", "main": "index.js"}"#,
    )
    .unwrap();
    fs::write(pkgs_dir.join("index.js"), "module.exports = 'pkg-a';").unwrap();

    fs::write(
        dir.join("package.json"),
        r#"{
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "pkg-a": "file:./packages/pkg-a"
            }
        }"#,
    )
    .unwrap();
}

#[test]
fn test_cli_install_no_format_package_lock_flag() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--no-format-package-lock"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        !lock_content.contains('\n') && !lock_content.contains('\r'),
        "Lockfile with --no-format-package-lock must be single-line compact JSON, got: {lock_content}"
    );

    // Verify it is valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&lock_content).unwrap();
    assert_eq!(parsed["name"], "test-app");
    assert_eq!(parsed["lockfileVersion"], 3);
}

#[test]
fn test_cli_install_format_package_lock_false_flag() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--format-package-lock=false"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        !lock_content.contains('\n') && !lock_content.contains('\r'),
        "Lockfile with --format-package-lock=false must be single-line compact JSON, got: {lock_content}"
    );
}

#[test]
fn test_cli_install_format_package_lock_default_is_formatted() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        lock_content.contains('\n'),
        "Default lockfile must be formatted multi-line JSON"
    );
}

#[test]
fn test_cli_install_format_package_lock_via_npmrc() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    // Write .npmrc with format-package-lock=false
    fs::write(temp.path().join(".npmrc"), "format-package-lock=false\n").unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        !lock_content.contains('\n') && !lock_content.contains('\r'),
        "Lockfile with npmrc format-package-lock=false must be compact single-line JSON, got: {lock_content}"
    );
}

#[test]
fn test_cli_install_format_package_lock_via_env() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .env("npm_config_format_package_lock", "false")
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        !lock_content.contains('\n') && !lock_content.contains('\r'),
        "Lockfile with env format-package-lock=false must be compact single-line JSON, got: {lock_content}"
    );
}

#[test]
fn test_cli_install_no_format_package_lock_overrides_npmrc_true() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_fixture(temp.path());

    // Write .npmrc with format-package-lock=true
    fs::write(temp.path().join(".npmrc"), "format-package-lock=true\n").unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--no-format-package-lock"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lock_path = temp.path().join("package-lock.json");
    assert!(lock_path.exists(), "package-lock.json must exist");
    let lock_content = fs::read_to_string(&lock_path).unwrap();

    assert!(
        !lock_content.contains('\n') && !lock_content.contains('\r'),
        "Lockfile with --no-format-package-lock must override npmrc format-package-lock=true, got: {lock_content}"
    );
}
