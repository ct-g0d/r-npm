use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_update_dry_run_and_execution() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "update-test",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "^7.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "--package-lock-only"])
        .output()
        .expect("update failed");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_update_workspace_forwarding() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "ws-update-root",
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
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "--workspace=pkg-a", "--dry-run"])
        .output()
        .expect("update --workspace failed");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // 2. Forwarding -w pkg-a
    let out_short = Command::new(rnpm_bin)
        .current_dir(root)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "-w", "pkg-a", "--dry-run"])
        .output()
        .expect("update -w failed");
    assert!(out_short.status.success(), "stderr: {}", String::from_utf8_lossy(&out_short.stderr));

    // 3. Forwarding --workspaces and --include-workspace-root
    let out_ws = Command::new(rnpm_bin)
        .current_dir(root)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "--workspaces", "--include-workspace-root", "--dry-run"])
        .output()
        .expect("update --workspaces failed");
    assert!(out_ws.status.success(), "stderr: {}", String::from_utf8_lossy(&out_ws.stderr));

    // 4. Invalid workspace fails with ENOWORKSPACES / No workspaces found
    let out_err = Command::new(rnpm_bin)
        .current_dir(root)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["update", "--workspace=nonexistent", "--dry-run"])
        .output()
        .expect("update command run");
    assert!(!out_err.status.success());
    let stderr = String::from_utf8_lossy(&out_err.stderr);
    assert!(stderr.contains("No workspaces found"));
}
