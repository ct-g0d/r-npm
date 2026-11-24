use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_shrinkwrap_without_package_lock_preserves_metadata_and_node_modules() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "my-shrinkwrap-app",
        "version": "3.2.1",
        "dependencies": {
            "my-dep": "^1.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let dep_dir = tmp.path().join("node_modules").join("my-dep");
    fs::create_dir_all(&dep_dir).unwrap();
    let dep_pkg = serde_json::json!({
        "name": "my-dep",
        "version": "1.2.3",
        "dependencies": {
            "sub-dep": "^0.1.0"
        }
    });
    fs::write(dep_dir.join("package.json"), dep_pkg.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .arg("shrinkwrap")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm shrinkwrap");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let shrinkwrap_path = tmp.path().join("npm-shrinkwrap.json");
    assert!(shrinkwrap_path.exists());

    let content = fs::read_to_string(&shrinkwrap_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["name"], "my-shrinkwrap-app");
    assert_eq!(parsed["version"], "3.2.1");
    assert_eq!(parsed["lockfileVersion"], 3);

    let packages = parsed["packages"].as_object().unwrap();
    let root = &packages[""];
    assert_eq!(root["name"], "my-shrinkwrap-app");
    assert_eq!(root["version"], "3.2.1");
    assert_eq!(root["dependencies"]["my-dep"], "^1.0.0");

    let dep_node = &packages["node_modules/my-dep"];
    assert_eq!(dep_node["version"], "1.2.3");
    assert_eq!(dep_node["dependencies"]["sub-dep"], "^0.1.0");
}

#[test]
fn test_config_list_custom_userconfig_display() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let custom_npmrc = tmp.path().join("custom.npmrc");
    fs::write(&custom_npmrc, "registry=https://custom-registry.org/\n").unwrap();

    let out = Command::new(rnpm_bin)
        .args(["config", "list"])
        .env("NPM_CONFIG_USERCONFIG", &custom_npmrc)
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run config list");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let custom_path_str = custom_npmrc.to_string_lossy();
    assert!(
        stdout.contains(&*custom_path_str),
        "stdout should contain custom userconfig path '{custom_path_str}', got:\n{stdout}"
    );

    let out_json = Command::new(rnpm_bin)
        .args(["config", "list", "--json"])
        .env("NPM_CONFIG_USERCONFIG", &custom_npmrc)
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run config list --json");

    assert!(out_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&out_json.stdout).unwrap();
    assert_eq!(
        json_val["userconfig"].as_str().unwrap(),
        custom_path_str.as_ref()
    );
}

#[test]
fn test_pkg_set_scripts_invalid_validation() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "scripts-validation-app",
        "version": "1.0.0",
        "scripts": {
            "start": "node index.js"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    // 1. Setting non-string script should fail with ESCRIPTSINVALID
    let out_bool = Command::new(rnpm_bin)
        .args(["pkg", "set", "scripts.test=true", "--json"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm pkg set");

    assert!(!out_bool.status.success());
    let stderr_bool = String::from_utf8_lossy(&out_bool.stderr);
    let stdout_bool = String::from_utf8_lossy(&out_bool.stdout);
    assert!(
        stderr_bool.contains("ESCRIPTSINVALID") || stdout_bool.contains("ESCRIPTSINVALID"),
        "stderr: {stderr_bool}, stdout: {stdout_bool}"
    );

    // 2. Setting nested object under scripts should fail with ESCRIPTSINVALID
    let out_nested = Command::new(rnpm_bin)
        .args(["pkg", "set", "scripts.foo.bar=echo 1"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm pkg set");

    assert!(!out_nested.status.success());
    let stderr_nested = String::from_utf8_lossy(&out_nested.stderr);
    let stdout_nested = String::from_utf8_lossy(&out_nested.stdout);
    assert!(
        stderr_nested.contains("ESCRIPTSINVALID") || stdout_nested.contains("ESCRIPTSINVALID"),
        "stderr: {stderr_nested}, stdout: {stdout_nested}"
    );

    // 3. Setting valid string script should succeed
    let out_valid = Command::new(rnpm_bin)
        .args(["pkg", "set", "scripts.test=echo 42"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm pkg set");

    assert!(
        out_valid.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_valid.stderr)
    );

    let content = fs::read_to_string(tmp.path().join("package.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["scripts"]["test"], "echo 42");
}

#[test]
fn test_explain_missing_error_formatting() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "explain-formatting-app",
        "version": "1.0.0"
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    // 1. Text mode
    let out_text = Command::new(rnpm_bin)
        .args(["explain", "non-existent-dep"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run explain");

    assert!(!out_text.status.success());
    let stderr_text = String::from_utf8_lossy(&out_text.stderr);
    assert!(
        stderr_text.contains("No dependencies found matching non-existent-dep"),
        "stderr: {stderr_text}"
    );
    assert!(
        !stderr_text.contains("EUSAGE"),
        "stderr should not contain EUSAGE: {stderr_text}"
    );

    // 2. JSON mode
    let out_json = Command::new(rnpm_bin)
        .args(["explain", "non-existent-dep", "--json"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run explain --json");

    assert!(!out_json.status.success());
    let stdout_json = String::from_utf8_lossy(&out_json.stdout);
    let parsed_err: serde_json::Value = serde_json::from_str(&stdout_json).unwrap();
    assert_eq!(
        parsed_err["error"]["summary"],
        "No dependencies found matching non-existent-dep"
    );
    assert!(
        parsed_err["error"].get("code").is_none(),
        "JSON error should not contain code EUSAGE: {stdout_json}"
    );
}

#[test]
fn test_query_sibling_combinators_and_classes() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "query-sibling-app",
        "version": "1.0.0",
        "dependencies": {
            "pkg-a": "^1.0.0",
            "pkg-b": "^1.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let a_dir = tmp.path().join("node_modules").join("pkg-a");
    let b_dir = tmp.path().join("node_modules").join("pkg-b");
    fs::create_dir_all(&a_dir).unwrap();
    fs::create_dir_all(&b_dir).unwrap();

    fs::write(
        a_dir.join("package.json"),
        serde_json::json!({ "name": "pkg-a", "version": "1.0.0" }).to_string(),
    )
    .unwrap();
    fs::write(
        b_dir.join("package.json"),
        serde_json::json!({ "name": "pkg-b", "version": "1.0.0" }).to_string(),
    )
    .unwrap();

    // Subsequent sibling: [name=pkg-a] ~ [name=pkg-b]
    let out_tilde = Command::new(rnpm_bin)
        .args(["query", "[name=pkg-a] ~ [name=pkg-b]"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run query");

    assert!(out_tilde.status.success());
    let json_tilde: serde_json::Value = serde_json::from_slice(&out_tilde.stdout).unwrap();
    let arr_tilde = json_tilde.as_array().unwrap();
    assert_eq!(arr_tilde.len(), 1);
    assert_eq!(arr_tilde[0]["name"], "pkg-b");

    // Adjacent sibling: [name=pkg-a] + [name=pkg-b]
    let out_plus = Command::new(rnpm_bin)
        .args(["query", "[name=pkg-a] + [name=pkg-b]"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run query");

    assert!(out_plus.status.success());
    let json_plus: serde_json::Value = serde_json::from_slice(&out_plus.stdout).unwrap();
    let arr_plus = json_plus.as_array().unwrap();
    assert_eq!(arr_plus.len(), 1);
    assert_eq!(arr_plus[0]["name"], "pkg-b");

    // Class selector: .prod
    let out_class = Command::new(rnpm_bin)
        .args(["query", ".prod"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run query");

    assert!(out_class.status.success());
    let json_class: serde_json::Value = serde_json::from_slice(&out_class.stdout).unwrap();
    let arr_class = json_class.as_array().unwrap();
    assert!(arr_class.iter().any(|p| p["name"] == "pkg-a"));
    assert!(arr_class.iter().any(|p| p["name"] == "pkg-b"));
}

#[test]
fn test_outdated_404_package_skips_cleanly() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Installed package that does not exist in registry
    let unreg_dir = tmp.path().join("node_modules").join("unregistered-private-dummy-999");
    fs::create_dir_all(&unreg_dir).unwrap();
    fs::write(
        unreg_dir.join("package.json"),
        serde_json::json!({
            "name": "unregistered-private-dummy-999",
            "version": "1.0.0"
        })
        .to_string(),
    )
    .unwrap();

    let pkg_json = serde_json::json!({
        "name": "outdated-404-app",
        "version": "1.0.0",
        "dependencies": {
            "unregistered-private-dummy-999": "^1.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .args(["outdated"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run outdated");

    // Real npm 11.20.0 exits 0 when all installed packages are up to date or skipped due to 404
    assert!(
        out.status.success(),
        "outdated must not fail on 404 package. status: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_run_with_prefix_executes_in_prefix_and_preserves_init_cwd() {
    let tmp = tempdir().unwrap();
    let sub = tmp.path().join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(
        sub.join("package.json"),
        serde_json::json!({
            "name": "sub-pkg",
            "version": "1.0.0",
            "scripts": {
                "hello": "node -e \"console.log('INIT=' + process.env.INIT_CWD); console.log('CWD=' + process.cwd())\""
            }
        })
        .to_string(),
    )
    .unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let out = Command::new(rnpm_bin)
        .args(["--prefix", "./sub", "run", "hello"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to run rnpm --prefix ./sub run hello");

    assert!(
        out.status.success(),
        "rnpm --prefix ./sub run hello must succeed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected_init = fs::canonicalize(tmp.path()).unwrap_or_else(|_| tmp.path().to_path_buf());
    let expected_sub = fs::canonicalize(&sub).unwrap_or_else(|_| sub.clone());
    let norm = |p: &std::path::Path| {
        let canon = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let s = canon.to_string_lossy().to_string();
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_ascii_lowercase()
    };
    let actual_init = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("INIT="))
        .unwrap_or_else(|| panic!("Missing INIT= line in stdout:\n{stdout}"));
    let actual_cwd = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("CWD="))
        .unwrap_or_else(|| panic!("Missing CWD= line in stdout:\n{stdout}"));
    assert_eq!(
        norm(std::path::Path::new(actual_init)),
        norm(&expected_init),
        "INIT_CWD should be outer invocation dir '{}', got:\n{stdout}",
        norm(&expected_init)
    );
    assert_eq!(
        norm(std::path::Path::new(actual_cwd)),
        norm(&expected_sub),
        "process.cwd() should be prefix dir '{}', got:\n{stdout}",
        norm(&expected_sub)
    );
}
