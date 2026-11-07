use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_doctor_standard_text_output() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm doctor");

    assert!(output.status.success(), "rnpm doctor should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm doctor"));
    assert!(stdout.contains("Platform"));
    assert!(stdout.contains("Registry"));
    assert!(stdout.contains("Dev Drive"));
    assert!(stdout.contains("Seek Penalty"));
    assert!(stdout.contains("rnpm doctor perf"));
}

#[test]
fn test_cli_doctor_standard_json_output() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .arg("--json")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm doctor --json");

    assert!(output.status.success(), "rnpm doctor --json should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("rnpm doctor --json must output valid JSON");

    assert!(val.get("rnpm_version").is_some());
    assert!(val.get("platform").is_some() || val.get("os").is_some());
    assert!(val.get("registry").is_some());
    assert!(val.get("cache_dir").is_some());
    assert!(val.get("dev_drive").is_some());
}

#[test]
fn test_cli_doctor_perf_text_output() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .arg("perf")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm doctor perf");

    assert!(output.status.success(), "rnpm doctor perf should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rnpm doctor perf"));
    assert!(stdout.contains("Project Directory"));
    assert!(stdout.contains("Package Store"));
    assert!(stdout.contains("Dev Drive"));
    assert!(stdout.contains("Volume / Block Cloning"));
    assert!(stdout.contains("Disk Speed"));
    assert!(stdout.contains("Windows Defender"));
    assert!(stdout.contains("Actionable Recommendations"));
    assert!(stdout.contains("Summary Table"));
}

#[test]
fn test_cli_doctor_perf_json_output() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .arg("perf")
        .arg("--json")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm doctor perf --json");

    assert!(
        output.status.success(),
        "rnpm doctor perf --json should exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("rnpm doctor perf --json must output valid JSON");

    assert!(val.get("project_path").is_some());
    assert!(val.get("store_path").is_some());
    assert!(val.get("same_volume").is_some());
    assert!(val.get("block_cloning_supported").is_some());
    assert!(val.get("items").is_some());
    assert!(val.get("recommendations").is_some());

    let items = val.get("items").unwrap().as_array().unwrap();
    assert!(
        !items.is_empty(),
        "Items array must contain diagnostic checks"
    );
}

#[test]
fn test_cli_doctor_perf_with_custom_store_dir() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let custom_store = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .arg("perf")
        .arg("--json")
        .env("RNPM_STORE_DIR", custom_store.path().to_str().unwrap())
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm doctor perf with custom RNPM_STORE_DIR");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("Output must be valid JSON");

    let store_path_val = val.get("store_path").unwrap().as_str().unwrap();
    assert_eq!(
        std::path::Path::new(store_path_val),
        custom_store.path(),
        "Custom RNPM_STORE_DIR must be reflected in doctor perf report"
    );
}

#[test]
fn test_cli_doctor_help() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("doctor")
        .arg("--help")
        .output()
        .expect("Failed to execute rnpm doctor --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("performance diagnostics") || stdout.contains("perf"));
}
