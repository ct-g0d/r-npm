use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_pack_dry_run_and_tarball() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "pack-coverage-pkg",
  "version": "1.0.0",
  "description": "test pack coverage"
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Dry run
    let dry_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["pack", "--dry-run", "--json"])
        .output()
        .expect("pack dry-run failed");

    assert!(dry_out.status.success(), "stderr: {}", String::from_utf8_lossy(&dry_out.stderr));
    let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
    assert!(dry_stdout.contains("pack-coverage-pkg-1.0.0.tgz"));
    assert!(!tmp.path().join("pack-coverage-pkg-1.0.0.tgz").exists());

    // 2. Real pack
    let real_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["pack"])
        .output()
        .expect("pack failed");

    assert!(real_out.status.success(), "stderr: {}", String::from_utf8_lossy(&real_out.stderr));
    assert!(tmp.path().join("pack-coverage-pkg-1.0.0.tgz").exists());
}
