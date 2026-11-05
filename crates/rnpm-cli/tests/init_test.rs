use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;
use serde_json::Value;

#[test]
fn test_init_non_interactive_yes() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("-y")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init -y");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));

    let manifest_path = project_dir.join("package.json");
    assert!(manifest_path.is_file(), "package.json should have been created");

    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    let dir_name = project_dir.file_name().unwrap().to_string_lossy().to_ascii_lowercase();
    let expected_name = dir_name.trim_start_matches('.');
    assert_eq!(json["name"], expected_name);
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["description"], "");
    assert_eq!(json["main"], "index.js");
    assert_eq!(json["scripts"]["test"], "echo \"Error: no test specified\" && exit 1");
    assert_eq!(json["keywords"], serde_json::json!([]));
    assert_eq!(json["author"], "");
    assert_eq!(json["license"], "ISC");
}

#[test]
fn test_init_non_interactive_force_and_aliases() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("--force")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init --force");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(project_dir.join("package.json").is_file());

    // Clean up and test -f
    std::fs::remove_file(project_dir.join("package.json")).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("-f")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init -f");

    assert!(output.status.success());
    assert!(project_dir.join("package.json").is_file());

    // Clean up and test --yes
    std::fs::remove_file(project_dir.join("package.json")).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("--yes")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init --yes");

    assert!(output.status.success());
    assert!(project_dir.join("package.json").is_file());
}

#[test]
fn test_create_subcommand_alias() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let output = Command::new(rnpm_bin)
        .arg("create")
        .arg("-y")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm create -y");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(project_dir.join("package.json").is_file());
}

#[test]
fn test_init_with_scope_flags() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // With --scope=@myorg
    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("-y")
        .arg("--scope=@myorg")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init -y --scope=@myorg");

    assert!(output.status.success());
    let json: Value = serde_json::from_str(&std::fs::read_to_string(project_dir.join("package.json")).unwrap()).unwrap();
    let name = json["name"].as_str().unwrap();
    assert!(name.starts_with("@myorg/"), "Expected name to start with @myorg/, got: {name}");

    // Test with --scope=anotherorg (without leading @)
    std::fs::remove_file(project_dir.join("package.json")).unwrap();
    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("-y")
        .arg("--scope=anotherorg")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init -y --scope=anotherorg");

    assert!(output.status.success());
    let json: Value = serde_json::from_str(&std::fs::read_to_string(project_dir.join("package.json")).unwrap()).unwrap();
    let name = json["name"].as_str().unwrap();
    assert!(name.starts_with("@anotherorg/"), "Expected name to start with @anotherorg/, got: {name}");
}

#[test]
fn test_init_preserves_existing_package_json() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let initial_manifest = serde_json::json!({
        "name": "my-preexisting-app",
        "version": "5.4.3",
        "description": "Preexisting description",
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "customSetting": true
    });

    std::fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&initial_manifest).unwrap(),
    ).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("-y")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init -y");

    assert!(output.status.success());

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["name"], "my-preexisting-app");
    assert_eq!(json["version"], "5.4.3");
    assert_eq!(json["description"], "Preexisting description");
    assert_eq!(json["dependencies"]["lodash"], "^4.17.21");
    assert_eq!(json["customSetting"], true);
    // Missing default fields should be populated
    assert_eq!(json["main"], "index.js");
    assert_eq!(json["scripts"]["test"], "echo \"Error: no test specified\" && exit 1");
    assert_eq!(json["keywords"], serde_json::json!([]));
    assert_eq!(json["author"], "");
    assert_eq!(json["license"], "ISC");
}

#[test]
fn test_init_interactive_piped_custom_values() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let inputs = [
        "custom-interactive-pkg",
        "2.1.0",
        "Interactive description",
        "app.js",
        "jest --runInBand",
        "https://github.com/myorg/custom-interactive-pkg.git",
        "cli, rust, package",
        "Alice <alice@example.com>",
        "MIT",
        "yes",
    ].join("\n") + "\n";

    let mut child = Command::new(rnpm_bin)
        .arg("init")
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn rnpm init");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(inputs.as_bytes()).expect("Failed to write stdin");
    }

    let output = child.wait_with_output().expect("Failed to wait on child");
    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["name"], "custom-interactive-pkg");
    assert_eq!(json["version"], "2.1.0");
    assert_eq!(json["description"], "Interactive description");
    assert_eq!(json["main"], "app.js");
    assert_eq!(json["scripts"]["test"], "jest --runInBand");
    assert_eq!(json["repository"]["url"], "https://github.com/myorg/custom-interactive-pkg.git");
    assert_eq!(json["keywords"], serde_json::json!(["cli", "rust", "package"]));
    assert_eq!(json["author"], "Alice <alice@example.com>");
    assert_eq!(json["license"], "MIT");
}

#[test]
fn test_init_interactive_abort_on_no() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let inputs = [
        "aborted-pkg",
        "1.0.0",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "no",
    ].join("\n") + "\n";

    let mut child = Command::new(rnpm_bin)
        .arg("init")
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn rnpm init");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(inputs.as_bytes()).expect("Failed to write stdin");
    }

    let output = child.wait_with_output().expect("Failed to wait on child");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm notice canceled"));
    assert!(!project_dir.join("package.json").exists(), "package.json should not exist after cancel");
}

#[test]
fn test_init_interactive_defaults_on_empty_enters() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let inputs = "\n\n\n\n\n\n\n\n\nyes\n";

    let mut child = Command::new(rnpm_bin)
        .arg("init")
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn rnpm init");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(inputs.as_bytes()).expect("Failed to write stdin");
    }

    let output = child.wait_with_output().expect("Failed to wait on child");
    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));

    let content = std::fs::read_to_string(project_dir.join("package.json")).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["description"], "");
    assert_eq!(json["main"], "index.js");
    assert_eq!(json["license"], "ISC");
}

#[test]
fn test_init_initializer_delegation_to_create_pkg() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let marker_file = project_dir.join("initializer_out.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    // Set up mock package in node_modules/create-vite
    let tool_dir = project_dir.join("node_modules").join("create-vite");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(
        tool_dir.join("index.js"),
        format!(
            "const fs = require('fs'); fs.writeFileSync('{escaped_marker}', process.argv.slice(2).join(' '));\n"
        ),
    ).unwrap();

    let bin_dir = project_dir.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    rnpm_shim::create_shims(&bin_dir, "create-vite", "create-vite/index.js").unwrap();

    // Call rnpm init vite my-app --template react
    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("vite")
        .arg("my-app")
        .arg("--template")
        .arg("react")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init vite");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(marker_file.is_file(), "Marker file should have been written by create-vite");

    let marker_content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(marker_content.trim(), "my-app --template react");
}

#[test]
fn test_create_initializer_delegation() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let marker_file = project_dir.join("create_out.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    // Set up mock package in node_modules/create-react-app
    let tool_dir = project_dir.join("node_modules").join("create-react-app");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(
        tool_dir.join("index.js"),
        format!(
            "const fs = require('fs'); fs.writeFileSync('{escaped_marker}', process.argv.slice(2).join(' '));\n"
        ),
    ).unwrap();

    let bin_dir = project_dir.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    rnpm_shim::create_shims(&bin_dir, "create-react-app", "create-react-app/index.js").unwrap();

    // Call rnpm create react-app my-react-app
    let output = Command::new(rnpm_bin)
        .arg("create")
        .arg("react-app")
        .arg("my-react-app")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm create react-app");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(marker_file.is_file(), "Marker file should have been written by create-react-app");

    let marker_content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(marker_content.trim(), "my-react-app");
}

#[test]
fn test_init_scoped_initializer_delegation() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let marker_file = project_dir.join("scoped_create_out.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    // Set up mock package in node_modules/@foo/create-bar
    let tool_dir = project_dir.join("node_modules").join("@foo").join("create-bar");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(
        tool_dir.join("index.js"),
        format!(
            "const fs = require('fs'); fs.writeFileSync('{escaped_marker}', process.argv.slice(2).join(' '));\n"
        ),
    ).unwrap();

    let bin_dir = project_dir.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    rnpm_shim::create_shims(&bin_dir, "create-bar", "@foo/create-bar/index.js").unwrap();

    // Call rnpm init @foo/bar app-target
    let output = Command::new(rnpm_bin)
        .arg("init")
        .arg("@foo/bar")
        .arg("app-target")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm init @foo/bar");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(marker_file.is_file());

    let marker_content = std::fs::read_to_string(&marker_file).unwrap();
    assert_eq!(marker_content.trim(), "app-target");
}
