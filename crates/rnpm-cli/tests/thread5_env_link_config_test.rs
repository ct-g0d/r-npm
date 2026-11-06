use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_config_cli_set_get_delete_list() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let proj_dir = tmp.path().join("proj");
    fs::create_dir_all(&proj_dir).unwrap();

    let user_home = tmp.path().join("userhome");
    fs::create_dir_all(&user_home).unwrap();

    let global_prefix = tmp.path().join("global");
    fs::create_dir_all(&global_prefix).unwrap();

    let pkg_json = r#"{"name": "config-test", "version": "1.0.0"}"#;
    fs::write(proj_dir.join("package.json"), pkg_json).unwrap();

    // 1. Config set in local/project .npmrc
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "set", "test-key", "test-value-123"])
        .output()
        .expect("config set failed");
    assert!(out.status.success());

    // 2. Config get
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "get", "test-key"])
        .output()
        .expect("config get failed");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "test-value-123");

    // 3. Config set --global
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "set", "global-key", "global-val-456", "--global"])
        .output()
        .expect("config set global failed");
    assert!(out.status.success());

    // Config get global
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "get", "global-key"])
        .output()
        .expect("config get global failed");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "global-val-456");

    // 4. Config list --json
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "list", "--json"])
        .output()
        .expect("config list --json failed");
    assert!(out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(json_val["test-key"], "test-value-123");
    assert_eq!(json_val["global-key"], "global-val-456");

    // 5. Config list text format
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "list"])
        .output()
        .expect("config list failed");
    assert!(out.status.success());
    let list_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(list_stdout.contains("test-key = \"test-value-123\""));
    assert!(list_stdout.contains("npm local prefix ="));
    assert!(list_stdout.contains("npm global prefix ="));

    // 6. Config delete
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "delete", "test-key"])
        .output()
        .expect("config delete failed");
    assert!(out.status.success());

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "get", "test-key"])
        .output()
        .expect("config get deleted key failed");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "undefined");

    // 7. Config delete --global
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "delete", "global-key", "--global"])
        .output()
        .expect("config delete global failed");
    assert!(out.status.success());

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .env("PREFIX", &global_prefix)
        .args(["config", "get", "global-key"])
        .output()
        .expect("config get deleted global key failed");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "undefined");
}

#[test]
fn test_top_level_get_set_aliases() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let proj_dir = tmp.path().join("proj");
    fs::create_dir_all(&proj_dir).unwrap();
    let user_home = tmp.path().join("userhome");
    fs::create_dir_all(&user_home).unwrap();

    let set = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .args(["set", "alias-key", "alias-value", "--location", "project"])
        .output()
        .unwrap();
    assert!(set.status.success(), "set failed: {}", String::from_utf8_lossy(&set.stderr));

    let get = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("USERPROFILE", &user_home)
        .env("HOME", &user_home)
        .args(["get", "alias-key"])
        .output()
        .unwrap();
    assert!(get.status.success(), "get failed: {}", String::from_utf8_lossy(&get.stderr));
    assert_eq!(String::from_utf8_lossy(&get.stdout).trim(), "alias-value");
}

#[test]
fn test_prefix_root_bin_cli() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let proj_dir = tmp.path().join("my-app");
    fs::create_dir_all(&proj_dir).unwrap();
    fs::write(proj_dir.join("package.json"), r#"{"name": "my-app"}"#).unwrap();

    let global_prefix = tmp.path().join("global-pref");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Local prefix, root, bin
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .arg("prefix")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), proj_dir.to_string_lossy());

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .arg("root")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        proj_dir.join("node_modules").to_string_lossy()
    );

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .arg("bin")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        proj_dir.join("node_modules").join(".bin").to_string_lossy()
    );

    // 2. Global prefix, root, bin
    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .args(["prefix", "-g"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), global_prefix.to_string_lossy());

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .args(["root", "--global"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let expected_root = if cfg!(windows) {
        global_prefix.join("node_modules")
    } else {
        global_prefix.join("lib").join("node_modules")
    };
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_root.to_string_lossy());

    let out = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("PREFIX", &global_prefix)
        .args(["bin", "-g"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let expected_bin = if cfg!(windows) {
        global_prefix.clone()
    } else {
        global_prefix.join("bin")
    };
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_bin.to_string_lossy());
}

#[test]
fn test_link_and_unlink_cli() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let global_prefix = root.join("global-link-root");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Create a package to link
    let pkg_dir = root.join("pkg-source");
    fs::create_dir_all(pkg_dir.join("bin")).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{
            "name": "my-cli-linked",
            "version": "1.0.0",
            "bin": {
                "my-cli-cmd": "./bin/run.js"
            }
        }"#,
    ).unwrap();
    fs::write(pkg_dir.join("bin").join("run.js"), "#!/usr/bin/env node\nconsole.log(123);\n").unwrap();

    // 2. npm link in pkg-source
    let out = Command::new(rnpm_bin)
        .current_dir(&pkg_dir)
        .env("PREFIX", &global_prefix)
        .arg("link")
        .output()
        .expect("npm link in source failed");
    assert!(out.status.success());

    let global_nm = if cfg!(windows) {
        global_prefix.join("node_modules")
    } else {
        global_prefix.join("lib").join("node_modules")
    };
    let global_target = global_nm.join("my-cli-linked");
    assert!(global_target.exists());
    assert!(rnpm_fs::is_junction(&global_target).unwrap());

    let global_bin = if cfg!(windows) {
        global_prefix.clone()
    } else {
        global_prefix.join("bin")
    };
    #[cfg(windows)]
    assert!(global_bin.join("my-cli-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("my-cli-cmd").exists());

    // 3. Create consumer app
    let consumer_dir = root.join("consumer-app");
    fs::create_dir_all(&consumer_dir).unwrap();
    fs::write(
        consumer_dir.join("package.json"),
        r#"{"name": "consumer-app", "version": "1.0.0"}"#,
    ).unwrap();

    // 4. npm link my-cli-linked in consumer-app
    let out = Command::new(rnpm_bin)
        .current_dir(&consumer_dir)
        .env("PREFIX", &global_prefix)
        .args(["link", "my-cli-linked"])
        .output()
        .expect("npm link in consumer failed");
    assert!(out.status.success());

    let local_target = consumer_dir.join("node_modules").join("my-cli-linked");
    assert!(local_target.exists());
    assert!(rnpm_fs::is_junction(&local_target).unwrap());

    let local_bin = consumer_dir.join("node_modules").join(".bin");
    #[cfg(windows)]
    assert!(local_bin.join("my-cli-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(local_bin.join("my-cli-cmd").exists());

    // 5. npm unlink my-cli-linked in consumer-app
    let out = Command::new(rnpm_bin)
        .current_dir(&consumer_dir)
        .env("PREFIX", &global_prefix)
        .args(["unlink", "my-cli-linked"])
        .output()
        .expect("npm unlink in consumer failed");
    assert!(out.status.success());
    assert!(!local_target.exists());
    #[cfg(windows)]
    assert!(!local_bin.join("my-cli-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(!local_bin.join("my-cli-cmd").exists());

    // 6. npm unlink in pkg-source
    let out = Command::new(rnpm_bin)
        .current_dir(&pkg_dir)
        .env("PREFIX", &global_prefix)
        .arg("unlink")
        .output()
        .expect("npm unlink in source failed");
    assert!(out.status.success());
    assert!(!global_target.exists());
    #[cfg(windows)]
    assert!(!global_bin.join("my-cli-cmd.cmd").exists());
    #[cfg(not(windows))]
    assert!(!global_bin.join("my-cli-cmd").exists());
}

#[test]
fn test_global_install_and_uninstall_cli() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let global_prefix = root.join("global-cli-env");
    fs::create_dir_all(&global_prefix).unwrap();

    // 1. Create a tool package
    let tool_dir = root.join("glob-cli-pkg");
    fs::create_dir_all(tool_dir.join("bin")).unwrap();
    fs::write(
        tool_dir.join("package.json"),
        r#"{
            "name": "glob-cli-pkg",
            "version": "1.0.0",
            "bin": {
                "glob-runner": "./bin/run.js"
            }
        }"#,
    ).unwrap();
    fs::write(tool_dir.join("bin").join("run.js"), "#!/usr/bin/env node\nconsole.log(999);\n").unwrap();

    let spec = format!("glob-cli-pkg@file:{}", tool_dir.display());

    // 2. rnpm install -g <pkg>
    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .env("PREFIX", &global_prefix)
        .args(["install", "-g", &spec])
        .output()
        .expect("rnpm install -g failed");
    assert!(out.status.success(), "install -g failed: {}", String::from_utf8_lossy(&out.stderr));

    let global_nm = if cfg!(windows) {
        global_prefix.join("node_modules")
    } else {
        global_prefix.join("lib").join("node_modules")
    };
    let installed_pkg = global_nm.join("glob-cli-pkg");
    assert!(installed_pkg.exists());

    let global_bin = if cfg!(windows) {
        global_prefix.clone()
    } else {
        global_prefix.join("bin")
    };
    #[cfg(windows)]
    assert!(global_bin.join("glob-runner.cmd").exists());
    #[cfg(not(windows))]
    assert!(global_bin.join("glob-runner").exists());

    // 3. rnpm uninstall --global glob-cli-pkg
    let out = Command::new(rnpm_bin)
        .current_dir(root)
        .env("PREFIX", &global_prefix)
        .args(["uninstall", "--global", "glob-cli-pkg"])
        .output()
        .expect("rnpm uninstall --global failed");
    assert!(out.status.success(), "uninstall --global failed: {}", String::from_utf8_lossy(&out.stderr));

    assert!(!installed_pkg.exists());
    #[cfg(windows)]
    assert!(!global_bin.join("glob-runner.cmd").exists());
    #[cfg(not(windows))]
    assert!(!global_bin.join("glob-runner").exists());
}
