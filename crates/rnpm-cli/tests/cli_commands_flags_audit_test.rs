use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn rnpm(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(dir)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn test_config_set_multiple_key_value_pairs() {
    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    fs::write(&npmrc_path, "").unwrap();

    // 1. Test `rnpm set` with key=val
    let out = rnpm(
        tmp.path(),
        &["set", "fund=false", "audit=false", "--location=project"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("fund=false"), "Expected fund=false in {content}");
    assert!(content.contains("audit=false"), "Expected audit=false in {content}");

    // 2. Test `rnpm config set` with multi pairs key=val and key val
    let out = rnpm(
        tmp.path(),
        &["config", "set", "foo=bar", "baz=qux", "--location=project"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("foo=bar"), "Expected foo=bar in {content}");
    assert!(content.contains("baz=qux"), "Expected baz=qux in {content}");

    // 3. Test `rnpm config set` with space separation `hello world`
    let out = rnpm(
        tmp.path(),
        &["config", "set", "hello", "world", "--location=project"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("hello=world"), "Expected hello=world in {content}");

    // 4. Test space-separated where value contains '='
    let out = rnpm(
        tmp.path(),
        &["config", "set", "mykey", "val=123", "--location=project"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("mykey=val=123"), "Expected mykey=val=123 in {content}");
}

#[test]
fn test_config_delete_multiple_keys() {
    let tmp = tempdir().unwrap();
    let npmrc_path = tmp.path().join(".npmrc");
    fs::write(
        &npmrc_path,
        "k1=v1\nk2=v2\nk3=v3\n",
    )
    .unwrap();

    let out = rnpm(
        tmp.path(),
        &["config", "delete", "k1", "k2", "--location=project"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(!content.contains("k1=v1"), "k1 should be deleted");
    assert!(!content.contains("k2=v2"), "k2 should be deleted");
    assert!(content.contains("k3=v3"), "k3 should remain");
}

#[test]
fn test_lifecycle_default_env() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name": "test-env-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let out = rnpm(tmp.path(), &["run", "env"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("npm_package_name=test-env-pkg")
            || stdout.contains("PATH=")
            || stdout.contains("Path="),
        "Expected environment output, got: {stdout}"
    );
}

#[test]
fn test_lifecycle_default_restart() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{
  "name": "test-restart-pkg",
  "version": "1.0.0",
  "scripts": {
    "start": "node -e \"console.log('RESTART_DEFAULT_START_PASS')\""
  }
}"#,
    )
    .unwrap();

    let out = rnpm(tmp.path(), &["restart"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RESTART_DEFAULT_START_PASS"),
        "Expected RESTART_DEFAULT_START_PASS in stdout: {stdout}"
    );
}

#[test]
fn test_lifecycle_commands_workspace_support() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{
  "name": "root-ws",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    )
    .unwrap();

    let pkg_a_dir = tmp.path().join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
  "name": "pkg-a",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('PKG_A_TEST_PASS')\""
  }
}"#,
    )
    .unwrap();

    let out = rnpm(tmp.path(), &["test", "-w", "pkg-a"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PKG_A_TEST_PASS"),
        "Expected PKG_A_TEST_PASS in output: {stdout}"
    );
}

#[test]
fn test_pkg_include_workspace_root() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{
  "name": "root-pkg",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    )
    .unwrap();

    let pkg_a_dir = tmp.path().join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
  "name": "pkg-a",
  "version": "1.0.0"
}"#,
    )
    .unwrap();

    let out = rnpm(
        tmp.path(),
        &["pkg", "get", "name", "--workspaces", "--include-workspace-root"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["root-pkg"], "root-pkg");
    assert_eq!(json["pkg-a"], "pkg-a");
}

#[test]
fn test_query_expect_result_count_and_expect_results() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{
  "name": "test-query-pkg",
  "version": "1.0.0"
}"#,
    )
    .unwrap();

    // 1. Count expectation matches (1 node :root) -> success exit 0
    let out = rnpm(tmp.path(), &["query", ":root", "--expect-result-count=1"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. Count expectation mismatch -> exit 1 with warning on stderr
    let out = rnpm(tmp.path(), &["query", ":root", "--expect-result-count=5"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm warn query Expected 5 results, got 1"),
        "stderr: {stderr}"
    );

    // 3. Expect no results but got 1 -> exit 1 with warning on stderr
    let out = rnpm(tmp.path(), &["query", ":root", "--expect-results=false"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm warn query Expected no results, got 1"),
        "stderr: {stderr}"
    );

    // 4. Mutual exclusion between --expect-results and --expect-result-count -> exit non-zero
    let out = rnpm(
        tmp.path(),
        &[
            "query",
            ":root",
            "--expect-results",
            "--expect-result-count=1",
        ],
    );
    assert!(
        !out.status.success(),
        "Expected failure when both flags provided"
    );
}

#[test]
fn test_test_command_filter_forwarding() {
    let tmp = tempdir().unwrap();
    let echo_script = tmp.path().join("echo_args.js");
    fs::write(
        &echo_script,
        r#"
const fs = require('fs');
fs.writeFileSync('args_out.json', JSON.stringify(process.argv.slice(2)));
console.log("ARGS_RECEIVED:" + JSON.stringify(process.argv.slice(2)));
"#,
    )
    .unwrap();

    fs::write(
        tmp.path().join("package.json"),
        r#"{
  "name": "test-filter-forwarding",
  "version": "1.0.0",
  "scripts": {
    "test": "node echo_args.js"
  }
}"#,
    )
    .unwrap();

    let out = rnpm(
        tmp.path(),
        &["test", "--filter", "my-spec", "--scope", "my-scope"],
    );
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(r#"ARGS_RECEIVED:["--filter","my-spec","--scope","my-scope"]"#),
        "Expected forwarded filter and scope in stdout: {stdout}"
    );

    let recorded = fs::read_to_string(tmp.path().join("args_out.json")).unwrap();
    let args: Vec<String> = serde_json::from_str(&recorded).unwrap();
    assert_eq!(
        args,
        vec!["--filter", "my-spec", "--scope", "my-scope"]
    );
}
