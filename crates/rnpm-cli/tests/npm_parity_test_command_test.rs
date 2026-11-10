use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_test_command_execution_and_output_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('tested')\""
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("test")
        .output()
        .expect("rnpm test failed");

    assert_eq!(rnpm_out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    assert!(
        stdout.contains("> test-pkg@1.0.0 test"),
        "Expected script header '> test-pkg@1.0.0 test', got: {}",
        stdout
    );
    assert!(
        stdout.contains("tested"),
        "Expected script output 'tested', got: {}",
        stdout
    );
}
