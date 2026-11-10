use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_pkg_get_name_npm_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0"
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["pkg", "get", "name"])
        .output()
        .expect("rnpm pkg get failed");

    assert!(rnpm_out.status.success());
    let rnpm_stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    assert_eq!(rnpm_stdout.trim(), "\"test-pkg\"");

    let npm_out = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "pkg", "get", "name"])
        .current_dir(tmp.path())
        .output();

    if let Ok(npm_res) = npm_out {
        if npm_res.status.success() {
            let npm_stdout = String::from_utf8_lossy(&npm_res.stdout);
            assert_eq!(rnpm_stdout.trim(), npm_stdout.trim());
        }
    }
}
