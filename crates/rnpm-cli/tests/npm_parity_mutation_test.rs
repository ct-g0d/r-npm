use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(dir)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn fixture(dir: &Path) {
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"parity-fixture\",\n  \"version\": \"1.0.0\",\n  \"private\": true\n}\n",
    )
    .unwrap();
}

#[test]
fn silent_mutating_commands_do_not_print_summaries() {
    let tmp = tempdir().unwrap();
    fixture(tmp.path());
    for args in [
        vec!["install", "--silent"],
        vec!["ci", "--loglevel=silent"],
        vec!["uninstall", "absent", "--silent"],
        vec!["update", "--silent"],
        vec!["prune", "--silent"],
    ] {
        let output = run(tmp.path(), &args);
        assert!(
            output.stdout.is_empty(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn update_dry_run_without_lock_does_not_write_project_files() {
    let tmp = tempdir().unwrap();
    fixture(tmp.path());
    let before = fs::read(tmp.path().join("package.json")).unwrap();
    let output = run(tmp.path(), &["update", "--dry-run", "--silent"]);
    assert_eq!(fs::read(tmp.path().join("package.json")).unwrap(), before);
    assert!(!tmp.path().join("package-lock.json").exists());
    assert!(!tmp.path().join("node_modules").exists());
    assert!(output.stdout.is_empty());
}

#[test]
fn prune_empty_project_creates_root_lockfile() {
    let tmp = tempdir().unwrap();
    fixture(tmp.path());
    run(tmp.path(), &["prune", "--silent"]);
    let lock: serde_json::Value =
        serde_json::from_slice(&fs::read(tmp.path().join("package-lock.json")).unwrap()).unwrap();
    assert_eq!(lock["packages"][""]["name"], "parity-fixture");
    assert_eq!(
        lock["packages"][""],
        serde_json::json!({"name":"parity-fixture", "version":"1.0.0"})
    );
    assert!(!tmp.path().join("node_modules").exists());
}
