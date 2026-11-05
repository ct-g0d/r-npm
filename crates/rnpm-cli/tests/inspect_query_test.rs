use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_list_clean_tree_and_depth() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let package_json = serde_json::json!({
        "name": "list-clean-app",
        "version": "1.0.0",
        "dependencies": {
            "dep-a": "^1.0.0"
        }
    });
    std::fs::write(project_dir.join("package.json"), package_json.to_string()).unwrap();

    let dep_a_dir = project_dir.join("node_modules").join("dep-a");
    std::fs::create_dir_all(&dep_a_dir).unwrap();
    let dep_a_pkg = serde_json::json!({
        "name": "dep-a",
        "version": "1.2.0",
        "dependencies": {
            "sub-b": "^2.0.0"
        }
    });
    std::fs::write(dep_a_dir.join("package.json"), dep_a_pkg.to_string()).unwrap();

    let sub_b_dir = dep_a_dir.join("node_modules").join("sub-b");
    std::fs::create_dir_all(&sub_b_dir).unwrap();
    let sub_b_pkg = serde_json::json!({
        "name": "sub-b",
        "version": "2.1.0"
    });
    std::fs::write(sub_b_dir.join("package.json"), sub_b_pkg.to_string()).unwrap();

    // 1. Standard rnpm ls (depth 0 by default)
    let output = Command::new(rnpm_bin)
        .arg("ls")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ls");

    assert!(output.status.success(), "Exit code must be 0 for clean tree");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("list-clean-app@1.0.0"));
    assert!(stdout.contains("+-- dep-a@1.2.0") || stdout.contains("`-- dep-a@1.2.0"));
    assert!(!stdout.contains("sub-b@2.1.0"), "Depth 0 must not show sub-b");

    // 2. rnpm ls --all (shows sub-b)
    let output_all = Command::new(rnpm_bin)
        .args(["ls", "--all"])
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ls --all");

    assert!(output_all.status.success());
    let stdout_all = String::from_utf8_lossy(&output_all.stdout);
    assert!(stdout_all.contains("dep-a@1.2.0"));
    assert!(stdout_all.contains("sub-b@2.1.0"));

    // 3. rnpm ls --json
    let output_json = Command::new(rnpm_bin)
        .args(["ls", "--json", "--all"])
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ls --json");

    assert!(output_json.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&output_json.stdout).unwrap();
    assert_eq!(json_val["name"], "list-clean-app");
    assert_eq!(json_val["version"], "1.0.0");
    assert_eq!(json_val["dependencies"]["dep-a"]["version"], "1.2.0");
    assert_eq!(json_val["dependencies"]["dep-a"]["dependencies"]["sub-b"]["version"], "2.1.0");

    // 4. rnpm ls --parseable
    let output_p = Command::new(rnpm_bin)
        .args(["ls", "-p", "--all"])
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ls -p");

    assert!(output_p.status.success());
    let stdout_p = String::from_utf8_lossy(&output_p.stdout);
    assert!(stdout_p.contains("list-clean-app") || stdout_p.contains(project_dir.to_str().unwrap()));
    assert!(stdout_p.contains("dep-a"));
    assert!(stdout_p.contains("sub-b"));

    // 5. rnpm la and rnpm ll aliases (imply --long)
    let output_la = Command::new(rnpm_bin)
        .arg("la")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm la");
    assert!(output_la.status.success());
    let stdout_la = String::from_utf8_lossy(&output_la.stdout);
    assert!(stdout_la.contains("| "));
}

#[test]
fn test_cli_list_problems_exit_code_1_and_elsproblems() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let package_json = serde_json::json!({
        "name": "list-problems-app",
        "version": "1.0.0",
        "dependencies": {
            "missing-dep": "^1.0.0",
            "invalid-dep": "^2.0.0"
        }
    });
    std::fs::write(project_dir.join("package.json"), package_json.to_string()).unwrap();

    let invalid_dir = project_dir.join("node_modules").join("invalid-dep");
    std::fs::create_dir_all(&invalid_dir).unwrap();
    let invalid_pkg = serde_json::json!({
        "name": "invalid-dep",
        "version": "1.0.0"
    });
    std::fs::write(invalid_dir.join("package.json"), invalid_pkg.to_string()).unwrap();

    let extraneous_dir = project_dir.join("node_modules").join("extra-dep");
    std::fs::create_dir_all(&extraneous_dir).unwrap();
    let extraneous_pkg = serde_json::json!({
        "name": "extra-dep",
        "version": "3.0.0"
    });
    std::fs::write(extraneous_dir.join("package.json"), extraneous_pkg.to_string()).unwrap();

    let output = Command::new(rnpm_bin)
        .arg("ls")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ls");

    assert!(!output.status.success(), "Exit code must be 1 when problems exist");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stdout.contains("UNMET DEPENDENCY missing-dep@^1.0.0"));
    assert!(stdout.contains("invalid-dep@1.0.0 invalid:"));
    assert!(stdout.contains("extra-dep@3.0.0 extraneous"));

    assert!(stderr.contains("npm error code ELSPROBLEMS"));
    assert!(stderr.contains("extraneous: extra-dep@3.0.0"));
    assert!(stderr.contains("invalid: invalid-dep@1.0.0"));
    assert!(stderr.contains("missing: missing-dep@^1.0.0"));
}

#[test]
fn test_cli_query_selectors() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let package_json = serde_json::json!({
        "name": "query-test-app",
        "version": "2.0.0",
        "dependencies": {
            "react": "^18.2.0",
            "missing-lib": "^1.0.0"
        }
    });
    std::fs::write(project_dir.join("package.json"), package_json.to_string()).unwrap();

    let react_dir = project_dir.join("node_modules").join("react");
    std::fs::create_dir_all(&react_dir).unwrap();
    let react_pkg = serde_json::json!({
        "name": "react",
        "version": "18.2.0",
        "description": "React library"
    });
    std::fs::write(react_dir.join("package.json"), react_pkg.to_string()).unwrap();

    let extra_dir = project_dir.join("node_modules").join("extra-tool");
    std::fs::create_dir_all(&extra_dir).unwrap();
    let extra_pkg = serde_json::json!({
        "name": "extra-tool",
        "version": "0.5.0"
    });
    std::fs::write(extra_dir.join("package.json"), extra_pkg.to_string()).unwrap();

    // 1. Query :root
    let out_root = Command::new(rnpm_bin)
        .args(["query", ":root"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_root.status.success());
    let res_root: serde_json::Value = serde_json::from_slice(&out_root.stdout).unwrap();
    let arr_root = res_root.as_array().unwrap();
    assert_eq!(arr_root.len(), 1);
    assert_eq!(arr_root[0]["name"], "query-test-app");

    // 2. Query [name=react]
    let out_react = Command::new(rnpm_bin)
        .args(["query", "[name=react]"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_react.status.success());
    let res_react: serde_json::Value = serde_json::from_slice(&out_react.stdout).unwrap();
    let arr_react = res_react.as_array().unwrap();
    assert_eq!(arr_react.len(), 1);
    assert_eq!(arr_react[0]["name"], "react");
    assert_eq!(arr_react[0]["version"], "18.2.0");

    // 3. Query [version^=18]
    let out_ver = Command::new(rnpm_bin)
        .args(["query", "[version^=18]"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_ver.status.success());
    let res_ver: serde_json::Value = serde_json::from_slice(&out_ver.stdout).unwrap();
    let arr_ver = res_ver.as_array().unwrap();
    assert_eq!(arr_ver.len(), 1);
    assert_eq!(arr_ver[0]["name"], "react");

    // 4. Query :extraneous
    let out_extra = Command::new(rnpm_bin)
        .args(["query", ":extraneous"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_extra.status.success());
    let res_extra: serde_json::Value = serde_json::from_slice(&out_extra.stdout).unwrap();
    let arr_extra = res_extra.as_array().unwrap();
    assert_eq!(arr_extra.len(), 1);
    assert_eq!(arr_extra[0]["name"], "extra-tool");

    // 5. Query :missing
    let out_miss = Command::new(rnpm_bin)
        .args(["query", ":missing"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_miss.status.success());
    let res_miss: serde_json::Value = serde_json::from_slice(&out_miss.stdout).unwrap();
    let arr_miss = res_miss.as_array().unwrap();
    assert_eq!(arr_miss.len(), 1);
    assert_eq!(arr_miss[0]["name"], "missing-lib");

    // 6. Query :root > [name=react]
    let out_child = Command::new(rnpm_bin)
        .args(["query", ":root > [name=react]"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(out_child.status.success());
    let res_child: serde_json::Value = serde_json::from_slice(&out_child.stdout).unwrap();
    assert_eq!(res_child.as_array().unwrap().len(), 1);
}

#[test]
fn test_cli_view_and_outdated_dispatch() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    // 1. rnpm view with missing argument emits EUSAGE
    let out_view = Command::new(rnpm_bin)
        .arg("view")
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert!(!out_view.status.success());
    let stderr_view = String::from_utf8_lossy(&out_view.stderr);
    assert!(stderr_view.contains("EUSAGE") || stderr_view.contains("Must provide a package name"));

    // 2. rnpm outdated on clean package with no dependencies exits 0 and prints nothing
    let pkg_json = serde_json::json!({
        "name": "empty-app",
        "version": "1.0.0"
    });
    std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

    let out_outdated = Command::new(rnpm_bin)
        .arg("outdated")
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert_eq!(out_outdated.status.code(), Some(0));

    let out_outdated_json = Command::new(rnpm_bin)
        .args(["outdated", "--json"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    assert_eq!(out_outdated_json.status.code(), Some(0));
    let stdout_json = String::from_utf8_lossy(&out_outdated_json.stdout);
    assert_eq!(stdout_json.trim(), "{}");
}
