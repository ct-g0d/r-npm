use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_install_test_execution() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "install-test-pkg",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('install-test-ran')\""
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["install-test", "--package-lock-only"])
        .output()
        .expect("install-test failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("install-test-ran"));
}
