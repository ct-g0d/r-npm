use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_update_dry_run_and_execution() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "update-test",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "^7.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "--package-lock-only"])
        .output()
        .expect("update failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}
