use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_prune_reification_and_lockfile_generation() {
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

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["prune", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm prune failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("added 1 package in "),
        "Expected prune to reify tree and report 'added 1 package in ...', got: {}",
        stdout
    );
    assert!(tmp.path().join("package-lock.json").exists(), "package-lock.json must be written");
    assert!(tmp.path().join("node_modules").join("is-number").exists(), "node_modules/is-number must exist");
    assert!(tmp.path().join("node_modules").join(".package-lock.json").exists(), "hidden lockfile must exist");
}

#[test]
fn test_dedupe_reification_and_find_dupes() {
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

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("dedupe")
        .output()
        .expect("rnpm dedupe failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("added 1 package in "),
        "Expected dedupe to reify tree and report 'added 1 package in ...', got: {}",
        stdout
    );
    assert!(tmp.path().join("node_modules").join("is-number").exists());
    assert!(tmp.path().join("node_modules").join(".package-lock.json").exists());

    // Once installed, find-dupes should report 'up to date in '
    let find_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("find-dupes")
        .output()
        .expect("rnpm find-dupes failed");

    assert!(find_out.status.success());
    let find_stdout = String::from_utf8_lossy(&find_out.stdout);
    assert!(
        find_stdout.contains("up to date in "),
        "Expected find-dupes on clean tree to report 'up to date in ...', got: {}",
        find_stdout
    );
}

#[test]
fn test_rebuild_output_parity() {
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

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("rebuild")
        .output()
        .expect("rnpm rebuild failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rebuilt dependencies successfully"),
        "Expected 'rebuilt dependencies successfully', got: {}",
        stdout
    );
}
