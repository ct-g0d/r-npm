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
fn config_get_registry_includes_default_and_project_override() {
    let tmp = tempdir().unwrap();
    fixture(tmp.path());
    let empty = tmp.path().join("empty.npmrc");
    fs::write(&empty, "").unwrap();
    let args = [
        "--userconfig",
        empty.to_str().unwrap(),
        "--globalconfig",
        empty.to_str().unwrap(),
        "config",
        "get",
        "registry",
    ];
    assert_eq!(
        String::from_utf8(run(tmp.path(), &args).stdout).unwrap(),
        "https://registry.npmjs.org/\n"
    );
    fs::write(
        tmp.path().join(".npmrc"),
        "registry=https://example.test/\n",
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(run(tmp.path(), &args).stdout).unwrap(),
        "https://example.test/\n"
    );
}
