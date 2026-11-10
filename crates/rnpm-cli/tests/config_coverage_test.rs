use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_config_lifecycle() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Config set in project .npmrc
    let set_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "set", "coverage_test_key=coverage_val", "--location=project"])
        .output()
        .expect("config set failed");
    assert!(set_out.status.success(), "stderr: {}", String::from_utf8_lossy(&set_out.stderr));

    // 2. Config get
    let get_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "get", "coverage_test_key"])
        .output()
        .expect("config get failed");
    assert!(get_out.status.success(), "stderr: {}", String::from_utf8_lossy(&get_out.stderr));
    let get_val = String::from_utf8_lossy(&get_out.stdout);
    assert_eq!(get_val.trim(), "coverage_val");

    // 3. Config list --json
    let list_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "list", "--json"])
        .output()
        .expect("config list failed");
    assert!(list_out.status.success(), "stderr: {}", String::from_utf8_lossy(&list_out.stderr));
    let list_json = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_json.contains("coverage_test_key"));

    // 4. Config edit
    let edit_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "edit"])
        .output()
        .expect("config edit failed");
    assert!(edit_out.status.success(), "stderr: {}", String::from_utf8_lossy(&edit_out.stderr));

    // 5. Config delete
    let del_out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "delete", "coverage_test_key", "--location=project"])
        .output()
        .expect("config delete failed");
    assert!(del_out.status.success(), "stderr: {}", String::from_utf8_lossy(&del_out.stderr));

    // Verify key deleted
    let verify_get = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["config", "get", "coverage_test_key"])
        .output()
        .expect("verify get failed");
    assert_eq!(String::from_utf8_lossy(&verify_get.stdout).trim(), "undefined");
}

fn normalize_output(text: &str) -> String {
    text.replace("\r\n", "\n")
        .lines()
        .filter(|line| !line.contains("A complete log of this run can be found in:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[test]
fn test_config_get_set_delete_live_npm_parity() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();

    let iso_rnpm = tmp_rnpm.path().join("iso");
    let iso_npm = tmp_npm.path().join("iso");
    fs::create_dir_all(&iso_rnpm).unwrap();
    fs::create_dir_all(&iso_npm).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test 1: config get registry (default)
    let rnpm_get_reg = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .env("HOME", &iso_rnpm)
        .env("USERPROFILE", &iso_rnpm)
        .env("npm_config_userconfig", iso_rnpm.join(".npmrc"))
        .env("npm_config_globalconfig", iso_rnpm.join("global.npmrc"))
        .env("USERCONFIG", iso_rnpm.join(".npmrc"))
        .env("GLOBALCONFIG", iso_rnpm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_rnpm.join("prefix"))
        .env("CACHE", iso_rnpm.join("cache"))
        .env("APPDATA", iso_rnpm.join("appdata"))
        .env("LOCALAPPDATA", iso_rnpm.join("localappdata"))
        .args(["config", "get", "registry"])
        .output()
        .expect("rnpm config get registry failed");

    let npm_get_reg = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "config", "get", "registry"])
        .current_dir(tmp_npm.path())
        .env("HOME", &iso_npm)
        .env("USERPROFILE", &iso_npm)
        .env("npm_config_userconfig", iso_npm.join(".npmrc"))
        .env("npm_config_globalconfig", iso_npm.join("global.npmrc"))
        .env("USERCONFIG", iso_npm.join(".npmrc"))
        .env("GLOBALCONFIG", iso_npm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_npm.join("prefix"))
        .env("CACHE", iso_npm.join("cache"))
        .env("NPM_CONFIG_CACHE", iso_npm.join("cache"))
        .env("npm_config_cache", iso_npm.join("cache"))
        .env("APPDATA", iso_npm.join("appdata"))
        .env("LOCALAPPDATA", iso_npm.join("localappdata"))
        .output();

    if let Ok(npm_res) = npm_get_reg {
        if npm_res.status.success() {
            assert_eq!(rnpm_get_reg.status.code(), npm_res.status.code());
            assert_eq!(
                normalize_output(&String::from_utf8_lossy(&rnpm_get_reg.stdout)),
                normalize_output(&String::from_utf8_lossy(&npm_res.stdout))
            );
            assert_eq!(
                normalize_output(&String::from_utf8_lossy(&rnpm_get_reg.stderr)),
                normalize_output(&String::from_utf8_lossy(&npm_res.stderr))
            );
        }
    }

    // Test 2: config set init-author-name=TestAuthor
    let userconfig_rnpm = iso_rnpm.join(".npmrc");
    let userconfig_npm = iso_npm.join(".npmrc");

    let rnpm_set = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .env("HOME", &iso_rnpm)
        .env("USERPROFILE", &iso_rnpm)
        .env("npm_config_userconfig", &userconfig_rnpm)
        .env("npm_config_globalconfig", iso_rnpm.join("global.npmrc"))
        .env("USERCONFIG", &userconfig_rnpm)
        .env("GLOBALCONFIG", iso_rnpm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_rnpm.join("prefix"))
        .env("CACHE", iso_rnpm.join("cache"))
        .env("APPDATA", iso_rnpm.join("appdata"))
        .env("LOCALAPPDATA", iso_rnpm.join("localappdata"))
        .args(["config", "set", "init-author-name=TestAuthor", "--userconfig", userconfig_rnpm.to_str().unwrap()])
        .output()
        .expect("rnpm config set failed");

    let npm_set = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "config",
            "set",
            "init-author-name=TestAuthor",
            "--userconfig",
            userconfig_npm.to_str().unwrap(),
        ])
        .current_dir(tmp_npm.path())
        .env("HOME", &iso_npm)
        .env("USERPROFILE", &iso_npm)
        .env("npm_config_userconfig", &userconfig_npm)
        .env("npm_config_globalconfig", iso_npm.join("global.npmrc"))
        .env("USERCONFIG", &userconfig_npm)
        .env("GLOBALCONFIG", iso_npm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_npm.join("prefix"))
        .env("CACHE", iso_npm.join("cache"))
        .env("NPM_CONFIG_CACHE", iso_npm.join("cache"))
        .env("npm_config_cache", iso_npm.join("cache"))
        .env("APPDATA", iso_npm.join("appdata"))
        .env("LOCALAPPDATA", iso_npm.join("localappdata"))
        .output();

    if let Ok(npm_res) = npm_set {
        if npm_res.status.success() {
            assert_eq!(rnpm_set.status.code(), npm_res.status.code());
            assert_eq!(
                normalize_output(&String::from_utf8_lossy(&rnpm_set.stdout)),
                normalize_output(&String::from_utf8_lossy(&npm_res.stdout))
            );
        }
    }

    // Test 3: config get init-author-name
    let rnpm_get_custom = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .env("HOME", &iso_rnpm)
        .env("USERPROFILE", &iso_rnpm)
        .env("npm_config_userconfig", &userconfig_rnpm)
        .env("npm_config_globalconfig", iso_rnpm.join("global.npmrc"))
        .env("USERCONFIG", &userconfig_rnpm)
        .env("GLOBALCONFIG", iso_rnpm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_rnpm.join("prefix"))
        .env("CACHE", iso_rnpm.join("cache"))
        .env("APPDATA", iso_rnpm.join("appdata"))
        .env("LOCALAPPDATA", iso_rnpm.join("localappdata"))
        .args(["config", "get", "init-author-name", "--userconfig", userconfig_rnpm.to_str().unwrap()])
        .output()
        .expect("rnpm config get init-author-name failed");

    let npm_get_custom = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "config",
            "get",
            "init-author-name",
            "--userconfig",
            userconfig_npm.to_str().unwrap(),
        ])
        .current_dir(tmp_npm.path())
        .env("HOME", &iso_npm)
        .env("USERPROFILE", &iso_npm)
        .env("npm_config_userconfig", &userconfig_npm)
        .env("npm_config_globalconfig", iso_npm.join("global.npmrc"))
        .env("USERCONFIG", &userconfig_npm)
        .env("GLOBALCONFIG", iso_npm.join("global.npmrc"))
        .env("NPM_CONFIG_PREFIX", iso_npm.join("prefix"))
        .env("CACHE", iso_npm.join("cache"))
        .env("NPM_CONFIG_CACHE", iso_npm.join("cache"))
        .env("npm_config_cache", iso_npm.join("cache"))
        .env("APPDATA", iso_npm.join("appdata"))
        .env("LOCALAPPDATA", iso_npm.join("localappdata"))
        .output();

    if let Ok(npm_res) = npm_get_custom {
        if npm_res.status.success() {
            assert_eq!(rnpm_get_custom.status.code(), npm_res.status.code());
            assert_eq!(
                normalize_output(&String::from_utf8_lossy(&rnpm_get_custom.stdout)),
                normalize_output(&String::from_utf8_lossy(&npm_res.stdout))
            );
        }
    }
}

