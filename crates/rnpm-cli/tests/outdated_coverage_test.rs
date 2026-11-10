use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_outdated_command() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "outdated-test",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "6.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // npm and rnpm exit with 1 when outdated dependencies exist
    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["outdated", "--json"])
        .output()
        .expect("outdated failed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("is-number"));
}
