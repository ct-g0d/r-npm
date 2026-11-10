use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_prune_production_and_dry_run() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "prune-coverage-pkg",
  "version": "1.0.0",
  "devDependencies": {
    "is-number": "7.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();
    let nm_dir = tmp.path().join("node_modules").join("is-number");
    fs::create_dir_all(&nm_dir).unwrap();
    fs::write(nm_dir.join("package.json"), r#"{"name":"is-number","version":"7.0.0"}"#).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Dry run
    let dry_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["prune", "--production", "--dry-run", "--json"])
        .output()
        .expect("prune dry-run failed");

    assert!(dry_out.status.success(), "stderr: {}", String::from_utf8_lossy(&dry_out.stderr));
    assert!(nm_dir.exists());

    // 2. Real prune
    let prune_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["prune", "--production"])
        .output()
        .expect("prune failed");

    assert!(prune_out.status.success(), "stderr: {}", String::from_utf8_lossy(&prune_out.stderr));
    assert!(!nm_dir.exists());
}
