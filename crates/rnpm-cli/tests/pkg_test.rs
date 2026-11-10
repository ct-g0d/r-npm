use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

fn setup_simple_package(dir: &std::path::Path) {
    let manifest = serde_json::json!({
        "name": "sample-pkg",
        "version": "1.2.3",
        "description": "A sample package for pkg testing",
        "main": "index.js",
        "scripts": {
            "test": "echo test",
            "build": "echo build"
        },
        "keywords": ["test", "sample"],
        "author": "Alice",
        "license": "ISC"
    });
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn setup_workspace_monorepo(dir: &std::path::Path) {
    let root_manifest = serde_json::json!({
        "name": "workspace-root",
        "version": "1.0.0",
        "workspaces": ["packages/*"]
    });
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&root_manifest).unwrap(),
    )
    .unwrap();

    let pkg_a_dir = dir.join("packages").join("pkg-a");
    std::fs::create_dir_all(&pkg_a_dir).unwrap();
    let pkg_a = serde_json::json!({
        "name": "pkg-a",
        "version": "1.0.0",
        "scripts": {
            "test": "echo test-a"
        }
    });
    std::fs::write(
        pkg_a_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_a).unwrap(),
    )
    .unwrap();

    let pkg_b_dir = dir.join("packages").join("pkg-b");
    std::fs::create_dir_all(&pkg_b_dir).unwrap();
    let pkg_b = serde_json::json!({
        "name": "pkg-b",
        "version": "2.0.0",
        "scripts": {
            "test": "echo test-b"
        }
    });
    std::fs::write(
        pkg_b_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_b).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_pkg_get_single_key_raw_and_json() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Single key raw (without --json)
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "\"sample-pkg\"");

    // Single key with --json (returns JSON string with quotes)
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("--json")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "\"sample-pkg\"");

    // Non-string property (scripts object)
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("scripts")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get scripts");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["test"], "echo test");
    assert_eq!(json["build"], "echo build");
}

#[test]
fn test_pkg_get_multiple_keys() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("version")
        .arg("author")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get multiple");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(json["name"], "sample-pkg");
    assert_eq!(json["version"], "1.2.3");
    assert_eq!(json["author"], "Alice");
}

#[test]
fn test_pkg_get_entire_package() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(json["name"], "sample-pkg");
    assert_eq!(json["version"], "1.2.3");
    assert_eq!(json["main"], "index.js");
}

#[test]
fn test_pkg_get_nonexistent_field() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Single nonexistent field returns {}
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("nonexistent")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get nonexistent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json, serde_json::json!({}));

    // Multiple fields where one exists and one is nonexistent
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("nonexistent")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name nonexistent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["name"], "sample-pkg");
    assert!(json.get("nonexistent").is_none());
}

#[test]
fn test_pkg_set_multiple_assignments_and_coercion() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("set")
        .arg("author=Bob")
        .arg("version=2.0.0")
        .arg("private=true")
        .arg("num=42")
        .arg("empty=null")
        .arg("scripts.build=tsc -b")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg set");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["author"], "Bob");
    assert_eq!(json["version"], "2.0.0");
    assert_eq!(json["private"], true);
    assert_eq!(json["num"], 42);
    assert_eq!(json["empty"], Value::Null);
    assert_eq!(json["scripts"]["build"], "tsc -b");
}

#[test]
fn test_pkg_set_bracket_keys_and_arrays() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("set")
        .arg("dependencies[\"@scope/pkg\"]=^1.0.0")
        .arg("keywords[0]=first")
        .arg("keywords[1]=second")
        .arg("keywords[]=third")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg set with brackets");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["dependencies"]["@scope/pkg"], "^1.0.0");
    assert_eq!(
        json["keywords"],
        serde_json::json!(["first", "second", "third"])
    );
}

#[test]
fn test_pkg_delete_single_and_multiple() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("delete")
        .arg("author")
        .arg("description")
        .arg("scripts.build")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg delete");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert!(json.get("author").is_none());
    assert!(json.get("description").is_none());
    assert!(json["scripts"].get("build").is_none());
    assert_eq!(json["scripts"]["test"], "echo test");
}

#[test]
fn test_pkg_delete_array_indices() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_simple_package(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Pre-populate 3 items
    Command::new(rnpm_bin)
        .arg("pkg")
        .arg("set")
        .arg("keywords=[\"a\",\"b\",\"c\"]")
        .current_dir(project_dir)
        .output()
        .unwrap();

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("delete")
        .arg("keywords[1]")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg delete array element");

    assert!(output.status.success());
    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["keywords"], serde_json::json!(["a", "c"]));
}

#[test]
fn test_pkg_workspaces_get() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_workspace_monorepo(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Single key across all workspaces using --workspaces
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("--workspaces")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name --workspaces");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"], "pkg-a");
    assert_eq!(json["pkg-b"], "pkg-b");

    // Single key across all workspaces using -ws alias
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("-ws")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name -ws");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"], "pkg-a");
    assert_eq!(json["pkg-b"], "pkg-b");

    // Multiple keys across all workspaces
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("version")
        .arg("--workspaces")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get multiple --workspaces");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"]["name"], "pkg-a");
    assert_eq!(json["pkg-a"]["version"], "1.0.0");
    assert_eq!(json["pkg-b"]["name"], "pkg-b");
    assert_eq!(json["pkg-b"]["version"], "2.0.0");

    // Entire manifests across all workspaces
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("--workspaces")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get --workspaces");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"]["scripts"]["test"], "echo test-a");
    assert_eq!(json["pkg-b"]["scripts"]["test"], "echo test-b");
}

#[test]
fn test_pkg_workspace_filter_flags() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_workspace_monorepo(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Filter by package name with --workspace=pkg-a
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("--workspace=pkg-a")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get name --workspace=pkg-a");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"], "pkg-a");
    assert!(json.get("pkg-b").is_none());

    // Filter by -w short flag with relative path
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("version")
        .arg("-w")
        .arg("packages/pkg-b")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get version -w packages/pkg-b");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-b"], "2.0.0");
    assert!(json.get("pkg-a").is_none());

    // Filter multiple workspaces via multiple -w flags
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("version")
        .arg("-w")
        .arg("pkg-a")
        .arg("-w")
        .arg("pkg-b")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get version -w pkg-a -w pkg-b");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(json["pkg-a"], "1.0.0");
    assert_eq!(json["pkg-b"], "2.0.0");
}

#[test]
fn test_pkg_workspaces_set_and_delete() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_workspace_monorepo(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Set field in single workspace
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("set")
        .arg("customProp=hello")
        .arg("-w")
        .arg("pkg-a")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg set -w pkg-a");

    assert!(
        output.status.success(),
        "Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pkg_a_content =
        std::fs::read_to_string(project_dir.join("packages/pkg-a/package.json")).unwrap();
    let pkg_a_json: Value = serde_json::from_str(&pkg_a_content).unwrap();
    assert_eq!(pkg_a_json["customProp"], "hello");

    let pkg_b_content =
        std::fs::read_to_string(project_dir.join("packages/pkg-b/package.json")).unwrap();
    let pkg_b_json: Value = serde_json::from_str(&pkg_b_content).unwrap();
    assert!(pkg_b_json.get("customProp").is_none());

    // Set field across all workspaces
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("set")
        .arg("sharedFlag=true")
        .arg("--workspaces")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg set --workspaces");

    assert!(output.status.success());

    let pkg_a_json: Value = serde_json::from_str(
        &std::fs::read_to_string(project_dir.join("packages/pkg-a/package.json")).unwrap(),
    )
    .unwrap();
    let pkg_b_json: Value = serde_json::from_str(
        &std::fs::read_to_string(project_dir.join("packages/pkg-b/package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(pkg_a_json["sharedFlag"], true);
    assert_eq!(pkg_b_json["sharedFlag"], true);

    // Delete field across all workspaces
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("delete")
        .arg("sharedFlag")
        .arg("-ws")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg delete -ws");

    assert!(output.status.success());

    let pkg_a_json: Value = serde_json::from_str(
        &std::fs::read_to_string(project_dir.join("packages/pkg-a/package.json")).unwrap(),
    )
    .unwrap();
    let pkg_b_json: Value = serde_json::from_str(
        &std::fs::read_to_string(project_dir.join("packages/pkg-b/package.json")).unwrap(),
    )
    .unwrap();
    assert!(pkg_a_json.get("sharedFlag").is_none());
    assert!(pkg_b_json.get("sharedFlag").is_none());
}

#[test]
fn test_pkg_workspace_error_handling() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_workspace_monorepo(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Nonexistent workspace package
    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("-w")
        .arg("nonexistent-pkg")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ENOWORKSPACE"),
        "Expected ENOWORKSPACE in stderr: {stderr}"
    );

    // Project without workspaces passing --workspaces
    let tmp2 = tempdir().unwrap();
    setup_simple_package(tmp2.path());
    let output2 = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("--workspaces")
        .current_dir(tmp2.path())
        .output()
        .expect("Failed to execute rnpm pkg get --workspaces");

    assert!(!output2.status.success());
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("ENOWORKSPACES"),
        "Expected ENOWORKSPACES in stderr: {stderr2}"
    );
}

#[test]
fn test_pkg_prefix_flag() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    setup_workspace_monorepo(project_dir);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("pkg")
        .arg("get")
        .arg("name")
        .arg("--prefix")
        .arg("packages/pkg-a")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm pkg get with --prefix");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "\"pkg-a\"");
}
