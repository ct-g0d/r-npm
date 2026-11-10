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
}
