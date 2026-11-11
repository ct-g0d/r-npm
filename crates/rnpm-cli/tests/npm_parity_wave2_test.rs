use std::{fs, path::Path, process::{Command, Output}};
use serde_json::{json, Value};
use tempfile::tempdir;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(dir)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(args).output().unwrap()
}

fn fixture(dir: &Path, name: &str, hooks: &[&str]) {
    fs::create_dir_all(dir).unwrap();
    let scripts: serde_json::Map<String, Value> = hooks.iter()
        .map(|hook| (hook.to_string(), json!("node probe.cjs"))).collect();
    fs::write(dir.join("package.json"), serde_json::to_string_pretty(&json!({
        "name": name, "version": "1.0.0", "scripts": scripts
    })).unwrap() + "\n").unwrap();
    fs::write(dir.join("probe.cjs"), "require('fs').appendFileSync('events.txt', process.env.npm_lifecycle_event + '\\n'); console.log(process.env.npm_lifecycle_event);").unwrap();
}

fn success(out: &Output) {
    assert!(out.status.success(), "stdout={} stderr={}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

fn events(dir: &Path) -> String {
    fs::read_to_string(dir.join("events.txt")).unwrap_or_default()
}

fn workspace(dir: &Path) {
    fixture(dir, "root", &["prex", "x", "postx"]);
    let path = dir.join("package.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["workspaces"] = json!(["packages/*"]);
    fs::write(path, serde_json::to_string_pretty(&manifest).unwrap() + "\n").unwrap();
    fixture(&dir.join("packages/a"), "a", &["prex", "x", "postx"]);
    fixture(&dir.join("packages/b"), "b", &["prex", "x", "postx"]);
}

#[test]
fn run_pre_and_post_hooks_and_ignore_scripts_contract() {
    for (flags, expected) in [
        (vec![], "prex\nx\npostx\n"),
        (vec!["--foreground-scripts"], "prex\nx\npostx\n"),
        (vec!["--ignore-scripts"], "x\n"),
    ] {
        let temp = tempdir().unwrap();
        fixture(temp.path(), "fixture", &["prex", "x", "postx"]);
        let mut args = vec!["run", "x"];
        args.extend(flags);
        success(&run(temp.path(), &args));
        assert_eq!(events(temp.path()), expected);
    }
}

#[test]
fn run_hook_failure_preserves_exit_code_and_stops_later_hooks() {
    let temp = tempdir().unwrap();
    fixture(temp.path(), "fixture", &["prex", "x", "postx"]);
    fs::write(temp.path().join("probe.cjs"), "require('fs').appendFileSync('events.txt', process.env.npm_lifecycle_event + '\\n'); if (process.env.npm_lifecycle_event === 'prex') process.exit(7);").unwrap();
    let out = run(temp.path(), &["run", "x"]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(events(temp.path()), "prex\n");
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn install_and_ci_run_all_root_hooks_in_npm_order() {
    for command in ["install", "ci"] {
        let temp = tempdir().unwrap();
        fixture(temp.path(), "fixture", &["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"]);
        fs::write(temp.path().join("package-lock.json"), serde_json::to_string_pretty(&json!({
            "name":"fixture", "version":"1.0.0", "lockfileVersion":3, "requires":true,
            "packages":{"":{"name":"fixture","version":"1.0.0","hasInstallScript":true}}
        })).unwrap() + "\n").unwrap();
        success(&run(temp.path(), &[command, "--silent"]));
        assert_eq!(events(temp.path()), "preinstall\ninstall\npostinstall\nprepublish\npreprepare\nprepare\npostprepare\n");
    }
}

#[test]
fn pack_runs_hooks_even_in_dry_run_and_honors_ignore_scripts() {
    for ignore in [false, true] {
        let temp = tempdir().unwrap();
        fixture(temp.path(), "fixture", &["prepack", "prepare", "postpack"]);
        let mut args = vec!["pack", "--dry-run", "--silent"];
        if ignore { args.push("--ignore-scripts"); }
        let out = run(temp.path(), &args);
        success(&out);
        assert_eq!(events(temp.path()), if ignore { "" } else { "prepack\nprepare\npostpack\n" });
        assert_eq!(String::from_utf8(out.stdout).unwrap(), if ignore {
            "fixture-1.0.0.tgz\n"
        } else {
            "prepack\nprepare\npostpack\nfixture-1.0.0.tgz\n"
        });
        assert!(!temp.path().join("fixture-1.0.0.tgz").exists());
    }
}

#[test]
fn workspace_run_selection_and_root_hook_order() {
    let temp = tempdir().unwrap();
    workspace(temp.path());
    let out = run(temp.path(), &["run", "x", "--workspaces", "--include-workspace-root", "--silent"]);
    success(&out);
    for dir in [temp.path().to_path_buf(), temp.path().join("packages/a"), temp.path().join("packages/b")] {
        assert_eq!(events(&dir), "prex\nx\npostx\n");
    }
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "prex\nx\npostx\nprex\nx\npostx\nprex\nx\npostx\n");
}

#[test]
fn workspace_missing_script_requires_if_present_and_never_runs_orphan_hooks() {
    let temp = tempdir().unwrap();
    workspace(temp.path());
    let out = run(temp.path(), &["run", "absent", "--workspaces"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("npm error Lifecycle script `absent` failed with error:"));
    let out = run(temp.path(), &["run", "absent", "--workspaces", "--if-present"]);
    success(&out);
    assert!(out.stdout.is_empty());
    let manifest_path = temp.path().join("packages/a/package.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["scripts"].as_object_mut().unwrap().remove("x");
    fs::write(manifest_path, manifest.to_string()).unwrap();
    success(&run(temp.path(), &["run", "x", "--workspaces", "--if-present", "--silent"]));
    assert_eq!(events(&temp.path().join("packages/a")), "");
    assert_eq!(events(&temp.path().join("packages/b")), "prex\nx\npostx\n");
}

#[test]
fn workspace_version_bumps_only_members() {
    let temp = tempdir().unwrap();
    workspace(temp.path());
    let out = run(temp.path(), &["version", "patch", "--workspaces", "--no-git-tag-version", "--silent"]);
    success(&out);
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "a\nv1.0.1\nb\nv1.0.1\n");
    for (relative, version) in [("package.json", "1.0.0"), ("packages/a/package.json", "1.0.1"), ("packages/b/package.json", "1.0.1")] {
        let manifest: Value = serde_json::from_slice(&fs::read(temp.path().join(relative)).unwrap()).unwrap();
        assert_eq!(manifest["version"], version);
    }
}

#[test]
fn workspace_exec_runs_in_each_member() {
    let temp = tempdir().unwrap();
    workspace(temp.path());
    for name in ["a", "b"] {
        fs::write(temp.path().join(format!("packages/{name}/exec.cjs")), "console.log(require('./package.json').name)").unwrap();
    }
    let out = run(temp.path(), &["exec", "--workspaces", "--", "node", "exec.cjs"]);
    success(&out);
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "a\nb\n");
}

#[test]
fn run_manifest_errors_have_npm_first_line() {
    let temp = tempdir().unwrap();
    let out = run(temp.path(), &["run", "x"]);
    let expected_code = if cfg!(windows) { -4058 } else { 0xfffffffe_u32 as i32 };
    assert_eq!(out.status.code(), Some(expected_code));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("npm error code ENOENT\n"));
    fs::write(temp.path().join("package.json"), "{invalid").unwrap();
    let out = run(temp.path(), &["run", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("npm error code EJSONPARSE\n"));
}

#[test]
fn unknown_command_uses_npm_stdout_and_exit_code() {
    let temp = tempdir().unwrap();
    let out = run(temp.path(), &["nonesuch"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("Unknown command: \"nonesuch\"\n"));
    assert!(out.stderr.is_empty());
}

#[test]
fn start_falls_back_to_server_js() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "start-fixture", "version": "1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("server.js"),
        r#"console.log("running-server-js");"#,
    )
    .unwrap();
    let out = run(temp.path(), &["start"]);
    success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("running-server-js"));
    assert!(stdout.contains("> start-fixture@1.0.0 start"));
    assert!(stdout.contains("> node server.js"));
}

#[test]
fn publish_dry_run_json_shape() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "test-publish-pkg", "version": "1.2.3"}"#,
    )
    .unwrap();
    let out = run(temp.path(), &["publish", "--dry-run", "--json"]);
    success(&out);
    let val: Value = serde_json::from_slice(&out.stdout).expect("valid json output");
    assert!(val.get("test-publish-pkg").is_some());
    let pkg = &val["test-publish-pkg"];
    assert_eq!(pkg["id"], "test-publish-pkg@1.2.3");
    assert_eq!(pkg["name"], "test-publish-pkg");
    assert_eq!(pkg["version"], "1.2.3");
    assert!(pkg["files"].is_array());
}

#[test]
fn list_workspace_filter_and_validation() {
    let temp = tempdir().unwrap();
    workspace(temp.path());
    let out = run(temp.path(), &["ls", "-w", "a"]);
    success(&out);

    let err_out = run(temp.path(), &["ls", "-w", "nonexistent"]);
    assert_eq!(err_out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&err_out.stderr);
    assert!(stderr.contains("ENOWORKSPACES") || stderr.contains("No workspaces found"));
}

#[test]
fn npm_command_environment_variable() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "cmd-test", "version": "1.0.0", "scripts": {"test": "node print-cmd.cjs"}}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("print-cmd.cjs"),
        r#"console.log("COMMAND=" + process.env.npm_command);"#,
    )
    .unwrap();
    let out = run(temp.path(), &["test"]);
    success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("COMMAND=test"));
}
