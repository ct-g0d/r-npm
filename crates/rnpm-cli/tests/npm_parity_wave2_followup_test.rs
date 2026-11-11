use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(dir)
        .env("NPM_CONFIG_CACHE", dir.join(".test-cache"))
        .env("NPM_CONFIG_USERCONFIG", dir.join("missing-user.npmrc"))
        .env("NPM_CONFIG_GLOBALCONFIG", dir.join("missing-global.npmrc"))
        .env("NPM_CONFIG_AUDIT", "false")
        .env("NPM_CONFIG_FUND", "false")
        .env("LC_ALL", "C.UTF-8")
        .args(args)
        .output()
        .unwrap()
}

fn manifest(dir: &Path, value: Value) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("package.json"),
        serde_json::to_string_pretty(&value).unwrap() + "\n",
    )
    .unwrap();
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn workspaces(dir: &Path) {
    manifest(
        dir,
        json!({"name":"root","version":"1.0.0","workspaces":["packages/*"]}),
    );
    for name in ["a", "b"] {
        let mut package = json!({"name":name,"version":"1.0.0","scripts":{"x":"node probe.cjs"}});
        if name == "a" {
            package["dependencies"] = json!({"b":"1.0.0"});
        }
        let member = dir.join("packages").join(name);
        manifest(&member, package);
        fs::write(
            member.join("probe.cjs"),
            "console.log(require('./package.json').name);console.log(process.env.INIT_CWD);",
        )
        .unwrap();
    }
}

#[test]
fn workspace_run_uses_manifest_order_and_original_init_cwd() {
    let temp = tempdir().unwrap();
    workspaces(temp.path());
    let out = run(temp.path(), &["run", "x", "--workspaces", "--silent"]);
    success(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "a\n{}\nb\n{}\n",
            temp.path().display(),
            temp.path().display()
        )
    );
    let mut root: Value =
        serde_json::from_slice(&fs::read(temp.path().join("package.json")).unwrap()).unwrap();
    root["workspaces"] = json!(["packages/b", "packages/a"]);
    manifest(temp.path(), root);
    let out = run(
        temp.path(),
        &["exec", "--workspaces", "--", "node", "probe.cjs"],
    );
    success(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "b\n{}\na\n{}\n",
            temp.path().display(),
            temp.path().display()
        )
    );
}

#[test]
fn run_environment_uses_npm_package_fields_and_all_ancestor_bins() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"env-fixture","version":"1.0.0","description":"not exported",
        "config":{"enabled":false,"count":3},"engines":{"node":">=20"},"bin":{"tool":"tool.js"},
        "scripts":{"x":"node probe.cjs"}}),
    );
    fs::write(temp.path().join("probe.cjs"), r#"
const p=require('path');
const keys=['npm_package_name','npm_package_version','npm_package_description','npm_package_scripts_x','npm_package_config_enabled','npm_package_config_count','npm_package_engines_node','npm_package_bin_tool','npm_config_ignore_scripts'];
console.log(JSON.stringify(Object.fromEntries(keys.map(k=>[k,process.env[k]??null]))));
console.log(JSON.stringify(process.env.PATH.split(p.delimiter).slice(0,2)));
"#).unwrap();
    let out = run(temp.path(), &["run", "x", "--ignore-scripts", "--silent"]);
    success(&out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = stdout.lines();
    let env: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(
        env,
        json!({"npm_package_name":"env-fixture","npm_package_version":"1.0.0",
        "npm_package_description":null,"npm_package_scripts_x":null,"npm_package_config_enabled":"",
        "npm_package_config_count":"3","npm_package_engines_node":">=20","npm_package_bin_tool":"tool.js",
        "npm_config_ignore_scripts":"true"})
    );
    let bins: Vec<String> = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(
        bins,
        vec![
            temp.path()
                .join("node_modules")
                .join(".bin")
                .display()
                .to_string(),
            temp.path()
                .parent()
                .unwrap()
                .join("node_modules")
                .join(".bin")
                .display()
                .to_string()
        ]
    );
}

#[test]
fn version_hook_headers_match_npm_and_respect_silent() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"fixture","version":"1.0.0","scripts":{
        "preversion":"node probe.cjs","version":"node probe.cjs","postversion":"node probe.cjs"}}),
    );
    fs::write(
        temp.path().join("probe.cjs"),
        "console.log(process.env.npm_lifecycle_event)",
    )
    .unwrap();
    let out = run(temp.path(), &["version", "patch", "--no-git-tag-version"]);
    success(&out);
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "\n> preversion\n> node probe.cjs\n\npreversion\n\n> version\n> node probe.cjs\n\nversion\n\n> postversion\n> node probe.cjs\n\npostversion\nv1.0.1\n");
    let out = run(
        temp.path(),
        &["version", "patch", "--no-git-tag-version", "--silent"],
    );
    success(&out);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "preversion\nversion\npostversion\nv1.0.2\n"
    );
}

#[test]
fn pack_json_preserves_npm_key_order_and_gitignore_warning() {
    let temp = tempdir().unwrap();
    manifest(temp.path(), json!({"name":"fixture","version":"1.0.0"}));
    fs::write(temp.path().join(".gitignore"), "omit.js\n").unwrap();
    fs::write(temp.path().join("omit.js"), "omit").unwrap();
    let out = run(temp.path(), &["pack", "--dry-run", "--json"]);
    success(&out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("[\n  {\n    \"id\": \"fixture@1.0.0\",\n    \"name\": \"fixture\","),
        "{stdout}"
    );
    assert!(stdout.contains("\"path\": \"package.json\",\n        \"size\":"));
    assert!(!stdout.contains("omit.js"));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "npm warn gitignore-fallback No .npmignore file found, using .gitignore for file exclusion. Consider creating a .npmignore file to explicitly control published files.\n");
}

#[test]
fn install_from_workspace_subdirectory_writes_root_lock_only() {
    let temp = tempdir().unwrap();
    workspaces(temp.path());
    let out = run(
        &temp.path().join("packages/a"),
        &["install", "--ignore-scripts", "--silent"],
    );
    success(&out);
    assert!(temp.path().join("package-lock.json").exists());
    assert!(!temp.path().join("packages/a/package-lock.json").exists());
    assert!(temp.path().join("node_modules/a/package.json").exists());
    assert!(temp.path().join("node_modules/b/package.json").exists());
}

#[test]
fn single_hyphen_workspaces_warning_matches_npm() {
    let temp = tempdir().unwrap();
    workspaces(temp.path());
    let out = run(temp.path(), &["run", "absent", "-ws", "--if-present"]);
    success(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "npm warn -ws is not a valid single-hyphen cli flag and will be removed in the future\n"
    );
}

#[test]
fn root_install_hook_headers_and_failures_match_npm() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"fixture","version":"1.0.0","scripts":{"install":"node probe.cjs"}}),
    );
    fs::write(temp.path().join("probe.cjs"), "console.log('installed')").unwrap();
    let out = run(temp.path(), &["install"]);
    success(&out);
    assert!(String::from_utf8_lossy(&out.stdout)
        .starts_with("\n> fixture@1.0.0 install\n> node probe.cjs\n\ninstalled\n"));
    fs::write(temp.path().join("probe.cjs"), "process.exit(7)").unwrap();
    let out = run(temp.path(), &["install"]);
    assert_eq!(out.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("npm error code 7\n"));
}

#[test]
fn publish_dry_run_runs_prepare_and_keeps_script_output_in_silent_mode() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"fixture","version":"1.0.0","scripts":{
        "prepack":"node probe.cjs","prepare":"node probe.cjs","postpack":"node probe.cjs"}}),
    );
    fs::write(
        temp.path().join("probe.cjs"),
        "console.log(process.env.npm_lifecycle_event)",
    )
    .unwrap();
    let out = run(temp.path(), &["publish", "--dry-run", "--silent"]);
    success(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "prepack\nprepare\npostpack\n"
    );
    let out = run(
        temp.path(),
        &["publish", "--dry-run", "--json", "--ignore-scripts"],
    );
    success(&out);
    let output: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(output.as_object().unwrap().len(), 1);
    assert_eq!(output["fixture"]["id"], "fixture@1.0.0");
    assert!(output["fixture"]["shasum"].is_string());
}

#[test]
fn workspace_version_refreshes_root_lockfile_and_links() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"root","version":"1.0.0","workspaces":["packages/*"]}),
    );
    manifest(
        &temp.path().join("packages/a"),
        json!({"name":"a","version":"1.0.0"}),
    );
    let out = run(
        temp.path(),
        &[
            "version",
            "patch",
            "--workspaces",
            "--no-git-tag-version",
            "--silent",
        ],
    );
    success(&out);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "a\nv1.0.1\n");
    let lock: Value =
        serde_json::from_slice(&fs::read(temp.path().join("package-lock.json")).unwrap()).unwrap();
    assert_eq!(lock["packages"]["packages/a"]["version"], "1.0.1");
    assert_eq!(lock["packages"]["node_modules/a"]["link"], true);
    assert!(temp.path().join("node_modules/a/package.json").exists());
}

#[test]
fn empty_workspace_list_and_pack_notices_match_npm() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"root","version":"1.0.0","workspaces":["packages/*"]}),
    );
    manifest(
        &temp.path().join("packages/a"),
        json!({"name":"a","version":"1.0.0"}),
    );
    let out = run(temp.path(), &["ls", "--workspaces"]);
    success(&out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "root@1.0.0 {}\n\u{2514}\u{2500}\u{2500} (empty)\n\n",
            temp.path().display()
        )
    );
    let out = run(&temp.path().join("packages/a"), &["pack", "--dry-run"]);
    success(&out);
    let notices = String::from_utf8_lossy(&out.stderr);
    assert!(
        notices.starts_with("npm notice\nnpm notice \u{1f4e6}  a@1.0.0\n"),
        "{notices}"
    );
    assert!(notices.contains("[...]"), "{notices}");
}

#[test]
fn pack_json_hook_banners_go_to_stderr_and_script_output_is_preserved() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"fixture","version":"1.0.0","scripts":{"prepack":"node probe.cjs"}}),
    );
    fs::write(temp.path().join("probe.cjs"), "console.log('prepacked')").unwrap();
    let out = run(temp.path(), &["pack", "--dry-run", "--json"]);
    success(&out);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("prepacked\n[\n"));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "\n> fixture@1.0.0 prepack\n> node probe.cjs\n\n"
    );
}

#[test]
fn install_json_routes_root_lifecycle_banner_to_stderr() {
    let temp = tempdir().unwrap();
    manifest(
        temp.path(),
        json!({"name":"root","version":"1.0.0","scripts":{"postinstall":"node -e \"\""}}),
    );
    let out = run(temp.path(), &["install", "--json"]);
    success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("> root@1.0.0 postinstall"),
        "banner leaked into JSON stdout: {stdout}"
    );
    if !stdout.trim().is_empty() {
        serde_json::from_str::<Value>(stdout.trim()).expect("stdout must be valid JSON");
    }
    assert!(
        stderr.contains("> root@1.0.0 postinstall"),
        "banner missing from stderr: {stderr}"
    );
}

#[test]
fn install_from_workspace_member_resolves_relative_spec_against_member_dir() {
    // npm 11.20 saves member-relative specs and root-relative resolutions.
    for (input, saved_spec, resolved, archive) in [
        (
            "./vendor/dep.tgz",
            "file:vendor/dep.tgz",
            "file:packages/a/vendor/dep.tgz",
            true,
        ),
        (
            "file:./vendor/dep.tgz",
            "file:vendor/dep.tgz",
            "file:packages/a/vendor/dep.tgz",
            true,
        ),
        ("../x", "file:../x", "packages/x", false),
        ("file:../x", "file:../x", "packages/x", false),
        ("file:./x", "file:x", "packages/a/x", false),
        ("./x", "file:x", "packages/a/x", false),
        (
            "vendor/dep",
            "file:vendor/dep",
            "packages/a/vendor/dep",
            false,
        ),
        // Preserve rnpm's existing support for bare local directory names.
        ("x", "file:x", "packages/a/x", false),
    ] {
        let temp = tempdir().unwrap();
        manifest(
            temp.path(),
            json!({"name":"root","version":"1.0.0","workspaces":["packages/a"]}),
        );
        let member = temp.path().join("packages/a");
        manifest(&member, json!({"name":"a","version":"1.0.0"}));
        for dir in [
            member.join("x"),
            member.join("vendor/dep"),
            temp.path().join("packages/x"),
        ] {
            manifest(&dir, json!({"name":"dep","version":"1.0.0"}));
        }
        let package = br#"{"name":"dep","version":"1.0.0"}"#;
        let file = fs::File::create(member.join("vendor/dep.tgz")).unwrap();
        let gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(package.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", &package[..])
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();

        let out = run(
            &member,
            &["install", input, "--offline", "--ignore-scripts"],
        );
        success(&out);
        let saved: Value =
            serde_json::from_slice(&fs::read(member.join("package.json")).unwrap()).unwrap();
        assert_eq!(saved["dependencies"]["dep"], saved_spec, "{input}");
        let root: Value =
            serde_json::from_slice(&fs::read(temp.path().join("package.json")).unwrap()).unwrap();
        assert!(root.get("dependencies").is_none(), "{input}: {root}");
        let lock: Value =
            serde_json::from_slice(&fs::read(temp.path().join("package-lock.json")).unwrap())
                .unwrap();
        assert_eq!(
            lock["packages"]["packages/a"]["dependencies"]["dep"], saved_spec,
            "{input}"
        );
        let entry = &lock["packages"]["node_modules/dep"];
        assert_eq!(entry["resolved"], resolved, "{input}");
        if archive {
            assert!(entry["integrity"].as_str().unwrap().starts_with("sha512-"));
            assert_eq!(entry["version"], "1.0.0");
        } else {
            assert_eq!(entry["link"], true, "{input}");
            assert_eq!(lock["packages"][resolved]["version"], "1.0.0");
        }
        let installed: Value = serde_json::from_slice(
            &fs::read(temp.path().join("node_modules/dep/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(installed["name"], "dep", "{input}");
        assert!(!member.join("package-lock.json").exists());
    }
}
