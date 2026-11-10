use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_help_no_args_parity() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("help")
        .output()
        .expect("rnpm help failed");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("npm <command>"));
    assert!(stdout.contains("npm install        install all the dependencies in your project"));
    assert!(stdout.contains("All commands:"));
    assert!(stdout.contains("prune, publish"));
}
