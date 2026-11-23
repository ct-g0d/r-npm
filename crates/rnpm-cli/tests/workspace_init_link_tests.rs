use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn isolated_cmd(
    bin: &str,
    dir: &Path,
    user_home: &Path,
    global_prefix: &Path,
) -> Command {
    let appdata = user_home.join("AppData").join("Roaming");
    let localappdata = user_home.join("AppData").join("Local");
    let cache_dir = user_home.join(".npm-cache");
    let user_npmrc = user_home.join(".npmrc");
    let global_npmrc = global_prefix.join("etc").join("npmrc");
    let _ = fs::create_dir_all(&appdata);
    let _ = fs::create_dir_all(&localappdata);
    let _ = fs::create_dir_all(global_prefix.join("etc"));

    let mut cmd = Command::new(bin);
    cmd.current_dir(dir);
    cmd.env("USERPROFILE", user_home);
    cmd.env("HOME", user_home);
    cmd.env("APPDATA", &appdata);
    cmd.env("LOCALAPPDATA", &localappdata);
    cmd.env("PREFIX", global_prefix);
    cmd.env("NPM_CONFIG_PREFIX", global_prefix);
    cmd.env("NPM_CONFIG_USERCONFIG", &user_npmrc);
    cmd.env("NPM_CONFIG_GLOBALCONFIG", &global_npmrc);
    cmd.env("NPM_CONFIG_CACHE", &cache_dir);
    cmd
}

#[test]
fn test_init_workspace_creates_manifest_and_registers_in_root() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Create root package.json without workspaces
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "my-monorepo",
  "version": "1.0.0"
}
"#,
    )
    .unwrap();

    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["init", "-y", "-w", "packages/alpha"])
        .output()
        .expect("failed to execute rnpm init");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 1. Verify packages/alpha/package.json exists
    let alpha_manifest_path = root.join("packages").join("alpha").join("package.json");
    assert!(alpha_manifest_path.exists(), "packages/alpha/package.json must exist");

    let alpha_json: Value =
        serde_json::from_str(&fs::read_to_string(&alpha_manifest_path).unwrap()).unwrap();
    assert_eq!(alpha_json["name"], "alpha");
    assert_eq!(alpha_json["version"], "1.0.0");

    // 2. Verify root package.json has "workspaces": ["packages/alpha"]
    let root_json: Value =
        serde_json::from_str(&fs::read_to_string(root.join("package.json")).unwrap()).unwrap();
    let ws = root_json["workspaces"]
        .as_array()
        .expect("workspaces must be an array");
    assert_eq!(ws, &vec![Value::String("packages/alpha".to_string())]);
}

#[test]
fn test_init_workspace_does_not_duplicate_when_glob_already_satisfies() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    // Create root package.json with glob "packages/*"
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "my-monorepo",
  "version": "1.0.0",
  "workspaces": [
    "packages/*"
  ]
}
"#,
    )
    .unwrap();

    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["init", "-y", "-w", "packages/beta"])
        .output()
        .expect("failed to execute rnpm init");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify packages/beta/package.json exists
    let beta_manifest_path = root.join("packages").join("beta").join("package.json");
    assert!(beta_manifest_path.exists(), "packages/beta/package.json must exist");
    let beta_json: Value =
        serde_json::from_str(&fs::read_to_string(&beta_manifest_path).unwrap()).unwrap();
    assert_eq!(beta_json["name"], "beta");

    // Verify root package.json still only has ["packages/*"]
    let root_json: Value =
        serde_json::from_str(&fs::read_to_string(root.join("package.json")).unwrap()).unwrap();
    let ws = root_json["workspaces"]
        .as_array()
        .expect("workspaces must be an array");
    assert_eq!(ws, &vec![Value::String("packages/*".to_string())]);
}

#[test]
fn test_init_workspace_with_scope() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "my-monorepo",
  "version": "1.0.0"
}
"#,
    )
    .unwrap();

    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["init", "-y", "--scope=@acme", "-w", "packages/gamma"])
        .output()
        .expect("failed to execute rnpm init");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let gamma_manifest_path = root.join("packages").join("gamma").join("package.json");
    assert!(gamma_manifest_path.exists());
    let gamma_json: Value =
        serde_json::from_str(&fs::read_to_string(&gamma_manifest_path).unwrap()).unwrap();
    assert_eq!(gamma_json["name"], "@acme/gamma");
}

#[test]
fn test_init_multiple_workspaces_in_one_invocation() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "multi-ws-repo",
  "version": "1.0.0"
}
"#,
    )
    .unwrap();

    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["init", "-w", "packages/a", "-w", "packages/b", "-y"])
        .output()
        .expect("failed to execute rnpm init");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(root.join("packages").join("a").join("package.json").exists());
    assert!(root.join("packages").join("b").join("package.json").exists());

    let root_json: Value =
        serde_json::from_str(&fs::read_to_string(root.join("package.json")).unwrap()).unwrap();
    let ws = root_json["workspaces"]
        .as_array()
        .expect("workspaces must be array");
    assert!(ws.contains(&Value::String("packages/a".to_string())));
    assert!(ws.contains(&Value::String("packages/b".to_string())));
}

#[test]
fn test_init_workspace_missing_root_package_json_fails() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["init", "-y", "-w", "packages/foo"])
        .output()
        .expect("failed to execute rnpm init");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ENOENT") || stderr.contains("Missing package.json"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_link_workspace_globally_and_into_another_workspace() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("repo");
    let user_home = tmp.path().join("userhome");
    let global_prefix = tmp.path().join("global");

    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&user_home).unwrap();
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Set up monorepo with packages/alpha and packages/beta
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "my-monorepo",
  "version": "1.0.0",
  "workspaces": [
    "packages/*"
  ]
}
"#,
    )
    .unwrap();

    let alpha_dir = root.join("packages").join("alpha");
    fs::create_dir_all(&alpha_dir).unwrap();
    fs::write(
        alpha_dir.join("package.json"),
        r#"{
  "name": "alpha",
  "version": "1.0.0",
  "bin": {
    "alpha-bin": "cli.js"
  }
}
"#,
    )
    .unwrap();
    fs::write(
        alpha_dir.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('alpha');\n",
    )
    .unwrap();

    let beta_dir = root.join("packages").join("beta");
    fs::create_dir_all(&beta_dir).unwrap();
    fs::write(
        beta_dir.join("package.json"),
        r#"{
  "name": "beta",
  "version": "1.0.0"
}
"#,
    )
    .unwrap();

    // 2. Run `rnpm link -w packages/alpha` from monorepo root
    let out = isolated_cmd(rnpm_bin, &root, &user_home, &global_prefix)
        .args(["link", "-w", "packages/alpha"])
        .output()
        .expect("failed to execute rnpm link -w packages/alpha");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify alpha is linked in global prefix
    let global_nm = if cfg!(windows) {
        global_prefix.join("node_modules")
    } else {
        global_prefix.join("lib").join("node_modules")
    };
    let global_target = global_nm.join("alpha");
    assert!(global_target.exists(), "global target should exist at {}", global_target.display());
    assert!(
        rnpm_fs::is_junction(&global_target).unwrap_or(false)
            || global_target.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false),
        "global target should be junction or symlink"
    );

    // Verify global bin shim
    let global_bin = if cfg!(windows) {
        global_prefix.clone()
    } else {
        global_prefix.join("bin")
    };
    #[cfg(windows)]
    assert!(global_bin.join("alpha-bin.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("alpha-bin").exists());

    // 3. Run `rnpm link alpha -w packages/beta`
    let out = isolated_cmd(rnpm_bin, &root, &user_home, &global_prefix)
        .args(["link", "alpha", "-w", "packages/beta"])
        .output()
        .expect("failed to execute rnpm link alpha -w packages/beta");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify alpha is linked into packages/beta/node_modules/alpha
    let beta_alpha_nm = beta_dir.join("node_modules").join("alpha");
    assert!(
        beta_alpha_nm.exists(),
        "packages/beta/node_modules/alpha should exist at {}",
        beta_alpha_nm.display()
    );
    assert!(
        rnpm_fs::is_junction(&beta_alpha_nm).unwrap_or(false)
            || beta_alpha_nm.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false),
        "beta node_modules alpha should be junction or symlink"
    );

    // 4. Also test with --save to verify manifest mutation
    let out_save = isolated_cmd(rnpm_bin, &root, &user_home, &global_prefix)
        .args(["link", "alpha", "-w", "packages/beta", "--save"])
        .output()
        .expect("failed to execute rnpm link alpha -w packages/beta --save");

    assert!(out_save.status.success());
    let beta_json: Value =
        serde_json::from_str(&fs::read_to_string(beta_dir.join("package.json")).unwrap()).unwrap();
    assert!(
        beta_json["dependencies"]["alpha"].is_string(),
        "beta dependencies should include alpha: {:?}",
        beta_json
    );
}

#[test]
fn test_link_nonexistent_workspace_fails_cleanly() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("repo");
    let user_home = tmp.path().join("userhome");
    let global_prefix = tmp.path().join("global");

    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&user_home).unwrap();
    fs::create_dir_all(&global_prefix).unwrap();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "my-monorepo",
  "version": "1.0.0",
  "workspaces": [
    "packages/*"
  ]
}
"#,
    )
    .unwrap();

    let out = isolated_cmd(rnpm_bin, &root, &user_home, &global_prefix)
        .args(["link", "-w", "packages/nonexistent"])
        .output()
        .expect("failed to execute rnpm link");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("No workspaces found") || stderr.contains("ENOWORKSPACES"),
        "stderr should mention No workspaces found: {stderr}"
    );
}
