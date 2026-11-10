use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_fund_header_npm_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "7.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("fund")
        .output()
        .expect("rnpm fund failed");

    assert!(rnpm_out.status.success());
    let rnpm_stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    assert_eq!(rnpm_stdout.trim(), "test-pkg@1.0.0");

    // Also test --json
    let rnpm_json_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["fund", "--json"])
        .output()
        .expect("rnpm fund --json failed");
    assert!(rnpm_json_out.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&rnpm_json_out.stdout).expect("valid json");
    assert_eq!(json_val["name"], "test-pkg");
    assert_eq!(json_val["version"], "1.0.0");

    let npm_out = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "fund"])
        .current_dir(tmp.path())
        .output();

    if let Ok(npm_res) = npm_out {
        if npm_res.status.success() {
            let npm_stdout = String::from_utf8_lossy(&npm_res.stdout);
            assert_eq!(rnpm_stdout.trim(), npm_stdout.trim());
        }
    }
}
