use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_outdated_column_layout_and_json_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "6.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Tabular layout
    let rnpm_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("outdated")
        .output()
        .expect("rnpm outdated failed");
    assert_eq!(rnpm_out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2);
    assert_eq!(
        lines[0],
        "Package    Current  Wanted  Latest  Location  Depended by"
    );
    assert_eq!(
        lines[1],
        "is-number  MISSING   6.0.0   7.0.0  -         test-pkg"
    );

    // 2. JSON output: missing packages must omit 'current' and 'location'
    let rnpm_json_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["outdated", "--json"])
        .output()
        .expect("rnpm outdated --json failed");
    assert_eq!(rnpm_json_out.status.code(), Some(1));
    let json_val: serde_json::Value = serde_json::from_slice(&rnpm_json_out.stdout)
        .expect("rnpm outdated --json must output valid JSON");
    let is_number = json_val
        .get("is-number")
        .expect("must have is-number entry");
    assert_eq!(is_number.get("wanted").and_then(|v| v.as_str()), Some("6.0.0"));
    assert_eq!(is_number.get("latest").and_then(|v| v.as_str()), Some("7.0.0"));
    assert_eq!(is_number.get("dependent").and_then(|v| v.as_str()), Some("test-pkg"));
    assert!(is_number.get("current").is_none(), "current must be omitted when MISSING");
    assert!(is_number.get("location").is_none(), "location must be omitted when MISSING");
}
