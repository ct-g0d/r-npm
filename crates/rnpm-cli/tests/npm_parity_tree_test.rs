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

#[test]
fn optional_missing_peer_has_empty_json_entry() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#,
    )
    .unwrap();
    let child = tmp.path().join("node_modules/child");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("package.json"), r#"{"name":"child","version":"1.0.0","peerDependencies":{"absent":"*"},"peerDependenciesMeta":{"absent":{"optional":true}}}"#).unwrap();
    let output = run(tmp.path(), &["ls", "--all", "--json"]);
    let tree: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        tree["dependencies"]["child"]["dependencies"]["absent"],
        serde_json::json!({})
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "{\n  \"version\": \"1.0.0\",\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"child\": {\n      \"version\": \"1.0.0\",\n      \"overridden\": false,\n      \"dependencies\": {\n        \"absent\": {}\n      }\n    }\n  }\n}\n");
}

#[test]
fn explain_json_reports_dependents_without_requiring_lockfile() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"child":"^1.0.0"}}"#,
    )
    .unwrap();
    let child = tmp.path().join("node_modules/child");
    fs::create_dir_all(&child).unwrap();
    fs::write(
        child.join("package.json"),
        r#"{"name":"child","version":"1.2.0"}"#,
    )
    .unwrap();
    let output = run(tmp.path(), &["explain", "child", "--json"]);
    let explanation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(explanation[0]["name"], "child");
    assert_eq!(explanation[0]["dependents"][0]["spec"], "^1.0.0");
    assert_eq!(explanation[0]["dependents"][0]["type"], "prod");
    assert_eq!(
        explanation[0]["dependents"][0]["from"]["location"],
        tmp.path().to_str().unwrap()
    );
    let missing = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(tmp.path())
        .args(["explain", "absent", "--json"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
}
