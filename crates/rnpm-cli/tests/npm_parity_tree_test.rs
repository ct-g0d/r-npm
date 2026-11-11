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

#[test]
fn explain_shared_dependency_keeps_each_requesting_spec() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"a":"1.0.0","b":"1.0.0"}}"#,
    )
    .unwrap();
    for (name, manifest) in [
        (
            "a",
            r#"{"name":"a","version":"1.0.0","dependencies":{"shared":"^1.0.0"}}"#,
        ),
        (
            "b",
            r#"{"name":"b","version":"1.0.0","dependencies":{"shared":"~1.2.0"}}"#,
        ),
        ("shared", r#"{"name":"shared","version":"1.2.3"}"#),
    ] {
        let dir = tmp.path().join("node_modules").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), manifest).unwrap();
    }
    let output = run(tmp.path(), &["explain", "shared", "--json"]);
    let explanation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let edges = explanation[0]["dependents"].as_array().unwrap();
    assert_eq!(edges.len(), 2);
    assert_eq!(edges[0]["spec"], "^1.0.0");
    assert_eq!(edges[1]["spec"], "~1.2.0");
    assert_eq!(edges[1]["from"]["dependents"][0]["spec"], "1.0.0");
}

#[test]
fn test_ls_and_ll_live_npm_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "dependencies": {
    "is-number": "7.0.0"
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Text ls with unmet dependency: exits code 1, ELSPROBLEMS on stderr
    let rnpm_ls = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("ls")
        .output()
        .expect("rnpm ls failed");
    assert_eq!(rnpm_ls.status.code(), Some(1));
    let rnpm_stderr = String::from_utf8_lossy(&rnpm_ls.stderr);
    let rnpm_stdout = String::from_utf8_lossy(&rnpm_ls.stdout);
    assert!(rnpm_stderr.contains("ELSPROBLEMS"));
    assert!(rnpm_stdout.contains("UNMET DEPENDENCY is-number@7.0.0"));

    // 2. JSON ls
    let rnpm_json = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["ls", "--json"])
        .output()
        .expect("rnpm ls --json failed");
    assert_eq!(rnpm_json.status.code(), Some(1));
    let rnpm_val: serde_json::Value = serde_json::from_slice(&rnpm_json.stdout)
        .expect("rnpm ls --json must be valid JSON");
    assert_eq!(rnpm_val["name"], "test-pkg");
    assert_eq!(rnpm_val["dependencies"]["is-number"]["required"], "7.0.0");
    assert_eq!(rnpm_val["dependencies"]["is-number"]["missing"], true);

    // 3. Compare with live npm.cmd
    let iso = tempdir().unwrap();
    let cache_dir = iso.path().join("cache");
    let prefix_dir = iso.path().join("prefix");
    let appdata = iso.path().join("appdata");
    let localappdata = iso.path().join("localappdata");
    let userconfig = iso.path().join(".npmrc");
    let globalconfig = iso.path().join("global.npmrc");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::create_dir_all(&prefix_dir).unwrap();
    fs::create_dir_all(&appdata).unwrap();
    fs::create_dir_all(&localappdata).unwrap();
    fs::write(&userconfig, "registry=http://127.0.0.1:9/\n").unwrap();
    fs::write(&globalconfig, "").unwrap();

    let npm_res = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "ls", "--json"])
        .current_dir(tmp.path())
        .env("HOME", iso.path())
        .env("USERPROFILE", iso.path())
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("PREFIX", &prefix_dir)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();
    if let Ok(npm_out) = npm_res {
        assert_eq!(npm_out.status.code(), Some(1));
        let npm_val: serde_json::Value = serde_json::from_slice(&npm_out.stdout)
            .expect("npm ls --json must be valid JSON");
        assert_eq!(rnpm_val["name"], npm_val["name"]);
        assert_eq!(rnpm_val["version"], npm_val["version"]);
        assert_eq!(
            rnpm_val["dependencies"]["is-number"]["required"],
            npm_val["dependencies"]["is-number"]["required"]
        );
        assert_eq!(
            rnpm_val["dependencies"]["is-number"]["missing"],
            npm_val["dependencies"]["is-number"]["missing"]
        );
    }

    // 4. Test ll (long list)
    let rnpm_ll = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .arg("ll")
        .output()
        .expect("rnpm ll failed");
    assert_eq!(rnpm_ll.status.code(), Some(1));
    let rnpm_ll_stdout = String::from_utf8_lossy(&rnpm_ll.stdout);
    assert!(rnpm_ll_stdout.contains("test-pkg@1.0.0"));
    assert!(rnpm_ll_stdout.contains("UNMET DEPENDENCY is-number@7.0.0"));
}


#[test]
fn test_tree_bom_package_json() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        "\u{feff}{\"name\":\"bom-test\",\"version\":\"1.2.3\",\"dependencies\":{}}",
    )
    .unwrap();

    let output = run(tmp.path(), &["ls", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["name"], "bom-test");
    assert_eq!(json["version"], "1.2.3");
}
