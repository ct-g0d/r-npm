use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_empty_install_writes_no_hidden_lockfile() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();

    // Empty package.json with no dependencies
    fs::write(
        temp.path().join("package.json"),
        r#"{
            "name": "empty-app",
            "version": "1.0.0"
        }"#,
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .arg("install")
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Root package-lock.json should exist
    assert!(
        temp.path().join("package-lock.json").exists(),
        "package-lock.json must be written"
    );

    // Hidden lockfile node_modules/.package-lock.json must NOT exist (matches npm)
    assert!(
        !temp.path().join("node_modules/.package-lock.json").exists(),
        "node_modules/.package-lock.json must not exist when there are no dependencies installed"
    );

    // node_modules should not exist or be empty
    assert!(
        !temp.path().join("node_modules").exists(),
        "node_modules directory must not be left on disk after empty install"
    );
}
