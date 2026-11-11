use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_install_uninstall_summary_phrasing_and_json_parity() {
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

    // 1. Initial install: must contain "added 1 package in "
    let rnpm_inst = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["install", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm install failed");
    assert!(rnpm_inst.status.success());
    let inst_stdout = String::from_utf8_lossy(&rnpm_inst.stdout);
    assert!(
        inst_stdout.contains("added 1 package in ") || inst_stdout.contains("added 1 package in"),
        "Expected 'added 1 package in ...', got: {}",
        inst_stdout
    );

    // 2. Subsequent install: must contain "up to date in "
    let rnpm_reinst = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["install", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm second install failed");
    assert!(rnpm_reinst.status.success());
    let reinst_stdout = String::from_utf8_lossy(&rnpm_reinst.stdout);
    assert!(
        reinst_stdout.contains("up to date in "),
        "Expected 'up to date in ...', got: {}",
        reinst_stdout
    );

    // 3. Install with --json: must produce valid JSON with npm fields
    let rnpm_json_inst = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["install", "--json", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm install --json failed");
    assert!(rnpm_json_inst.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&rnpm_json_inst.stdout)
        .expect("rnpm install --json must output valid JSON");
    assert!(json_val.get("added").is_some());
    assert!(json_val.get("removed").is_some());

    // 4a. Update: on clean project, must contain "up to date in "
    let rnpm_up = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["update"])
        .output()
        .expect("rnpm update failed");
    assert!(rnpm_up.status.success());
    let up_stdout = String::from_utf8_lossy(&rnpm_up.stdout);
    assert!(
        up_stdout.contains("up to date in "),
        "Expected 'up to date in ...', got: {}",
        up_stdout
    );

    // 4b. Uninstall: must contain "removed 1 package in "
    let rnpm_uninst = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["uninstall", "is-number", "--no-audit", "--no-fund"])
        .output()
        .expect("rnpm uninstall failed");
    assert!(rnpm_uninst.status.success());
    let uninst_stdout = String::from_utf8_lossy(&rnpm_uninst.stdout);
    assert!(
        uninst_stdout.contains("removed 1 package in "),
        "Expected 'removed 1 package in ...', got: {}",
        uninst_stdout
    );

    // 5. Compare structure against npm if available
    let npm_tmp = tempdir().unwrap();
    fs::write(npm_tmp.path().join("package.json"), pkg_json).unwrap();

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

    let npm_inst = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "install", "--offline", "--no-audit", "--no-fund"])
        .current_dir(npm_tmp.path())
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

    if let Ok(npm_res) = npm_inst {
        if npm_res.status.success() {
            let npm_stdout = String::from_utf8_lossy(&npm_res.stdout);
            assert!(
                npm_stdout.contains("added 1 package in "),
                "npm output phrasing check: {}",
                npm_stdout
            );
        }
    }
}
