use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_config_lifecycle() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Config set in project .npmrc
    let set_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "set", "coverage_test_key=coverage_val", "--location=project"])
        .output()
        .expect("config set failed");
    assert!(set_out.status.success(), "stderr: {}", String::from_utf8_lossy(&set_out.stderr));

    // 2. Config get
    let get_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "get", "coverage_test_key"])
        .output()
        .expect("config get failed");
    assert!(get_out.status.success(), "stderr: {}", String::from_utf8_lossy(&get_out.stderr));
    let get_val = String::from_utf8_lossy(&get_out.stdout);
    assert_eq!(get_val.trim(), "coverage_val");

    // 3. Config list --json
    let list_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "list", "--json"])
        .output()
        .expect("config list failed");
    assert!(list_out.status.success(), "stderr: {}", String::from_utf8_lossy(&list_out.stderr));
    let list_json = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_json.contains("coverage_test_key"));

    // 4. Config edit
    let edit_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "edit"])
        .output()
        .expect("config edit failed");
    assert!(edit_out.status.success(), "stderr: {}", String::from_utf8_lossy(&edit_out.stderr));

    // 5. Config delete
    let del_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "delete", "coverage_test_key", "--location=project"])
        .output()
        .expect("config delete failed");
    assert!(del_out.status.success(), "stderr: {}", String::from_utf8_lossy(&del_out.stderr));

    // Verify key deleted
    let verify_get = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "get", "coverage_test_key"])
        .output()
        .expect("verify get failed");
    assert_eq!(String::from_utf8_lossy(&verify_get.stdout).trim(), "undefined");
}
