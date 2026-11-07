use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_help_install_strategy() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("help")
        .arg("install-strategy")
        .output()
        .expect("Failed to execute rnpm help install-strategy");

    assert!(
        output.status.success(),
        "rnpm help install-strategy should exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("install-strategy - Installation strategy for node_modules layout"));
    assert!(stdout.contains("hoisted (default)"));
    assert!(stdout.contains("linked"));
    assert!(stdout.contains("nested"));
    assert!(stdout.contains("NTFS junctions"));
    assert!(stdout.contains("TRADE-OFFS"));
    assert!(stdout.contains("Phantom dependencies"));
}

#[test]
fn test_cli_install_strategy_invalid_value() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("install")
        .arg("--install-strategy")
        .arg("unsupported-layout")
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        !output.status.success(),
        "Invalid install-strategy should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value 'unsupported-layout'")
            || stderr.contains("hoisted")
            || stderr.contains("linked"),
        "Expected invalid value error message, got: {stderr}"
    );
}

#[test]
fn test_cli_install_with_install_strategy_linked() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let manifest = serde_json::json!({
        "name": "cli-linked-test",
        "version": "1.0.0",
        "dependencies": {}
    });
    fs::write(project_dir.join("package.json"), manifest.to_string()).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("install")
        .arg("--install-strategy=linked")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm install --install-strategy=linked");

    assert!(
        output.status.success(),
        "install with linked strategy should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(project_dir.join("package-lock.json").exists());
}

#[test]
fn test_cli_ci_with_install_strategy_linked() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let manifest = serde_json::json!({
        "name": "cli-ci-linked-test",
        "version": "1.0.0",
        "dependencies": {}
    });
    fs::write(project_dir.join("package.json"), manifest.to_string()).unwrap();

    let lockfile = serde_json::json!({
        "name": "cli-ci-linked-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "cli-ci-linked-test",
                "version": "1.0.0",
                "dependencies": {}
            }
        }
    });
    fs::write(project_dir.join("package-lock.json"), lockfile.to_string()).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("ci")
        .arg("--install-strategy=linked")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ci --install-strategy=linked");

    assert!(
        output.status.success(),
        "ci with linked strategy should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(project_dir.join("node_modules").exists());
}

#[test]
fn test_cli_npmrc_config_install_strategy_linked() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let manifest = serde_json::json!({
        "name": "cli-npmrc-linked-test",
        "version": "1.0.0",
        "dependencies": {}
    });
    fs::write(project_dir.join("package.json"), manifest.to_string()).unwrap();

    // Configure in .npmrc
    fs::write(project_dir.join(".npmrc"), "install-strategy=linked\n").unwrap();

    let output = Command::new(rnpm_bin)
        .arg("install")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm install with .npmrc");

    assert!(
        output.status.success(),
        "install with .npmrc install-strategy=linked should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
