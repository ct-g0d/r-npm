use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_shrinkwrap_renames_lockfile() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{"name":"shrinkwrap-test","version":"1.0.0"}"#;
    let lock_json = r#"{"name":"shrinkwrap-test","version":"1.0.0","lockfileVersion":3}"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp.path().join("package-lock.json"), lock_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["shrinkwrap"])
        .output()
        .expect("shrinkwrap failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(tmp.path().join("npm-shrinkwrap.json").exists());
    assert!(!tmp.path().join("package-lock.json").exists());
    assert!(out.stdout.is_empty(), "stdout should be empty, got: {}", String::from_utf8_lossy(&out.stdout));
    let rnpm_stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        rnpm_stderr.contains("npm notice package-lock.json has been renamed to npm-shrinkwrap.json"),
        "stderr: {}",
        rnpm_stderr
    );

    // Live npm comparison
    let tmp_npm = tempdir().unwrap();
    fs::write(tmp_npm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_npm.path().join("package-lock.json"), lock_json).unwrap();
    let npm_res = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "shrinkwrap"])
        .current_dir(tmp_npm.path())
        .output();
    if let Ok(npm_out) = npm_res {
        if npm_out.status.success() {
            assert!(npm_out.stdout.is_empty(), "npm stdout should be empty");
            let npm_stderr = String::from_utf8_lossy(&npm_out.stderr);
            assert!(npm_stderr.contains("npm notice package-lock.json has been renamed to npm-shrinkwrap.json"));
            assert!(tmp_npm.path().join("npm-shrinkwrap.json").exists());
            assert!(!tmp_npm.path().join("package-lock.json").exists());
        }
    }
}
