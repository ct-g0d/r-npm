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
    fs::write(
        nm_dir.join("package.json"),
        r#"{"name":"is-number","version":"7.0.0"}"#,
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Dry run
    let dry_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["prune", "--production", "--dry-run", "--json"])
        .output()
        .expect("prune dry-run failed");

    assert!(
        dry_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    assert!(nm_dir.exists());

    // 2. Real prune
    let prune_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["prune", "--production"])
        .output()
        .expect("prune failed");

    assert!(
        prune_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&prune_out.stderr)
    );
    assert!(!nm_dir.exists());
}

#[test]
fn test_prune_workspace_forwarding() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "ws-prune-root",
  "version": "1.0.0",
  "workspaces": ["packages/*"]
}
"#,
    )
    .unwrap();
    let pkg_a = root.join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a).unwrap();
    fs::write(
        pkg_a.join("package.json"),
        r#"{
  "name": "pkg-a",
  "version": "1.0.0"
}
"#,
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Forwarding --workspace=pkg-a
    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["prune", "--workspace=pkg-a", "--dry-run"])
        .output()
        .expect("prune --workspace failed");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // 2. Forwarding -w pkg-a
    let out_short = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["prune", "-w", "pkg-a", "--dry-run"])
        .output()
        .expect("prune -w failed");
    assert!(out_short.status.success(), "stderr: {}", String::from_utf8_lossy(&out_short.stderr));

    // 3. Forwarding --workspaces and --include-workspace-root
    let out_ws = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["prune", "--workspaces", "--include-workspace-root", "--dry-run"])
        .output()
        .expect("prune --workspaces failed");
    assert!(out_ws.status.success(), "stderr: {}", String::from_utf8_lossy(&out_ws.stderr));

    // 4. Invalid workspace fails with No workspaces found
    let out_err = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["prune", "--workspace=nonexistent", "--dry-run"])
        .output()
        .expect("prune command run");
    assert!(!out_err.status.success());
    let stderr = String::from_utf8_lossy(&out_err.stderr);
    assert!(stderr.contains("No workspaces found"));
}
