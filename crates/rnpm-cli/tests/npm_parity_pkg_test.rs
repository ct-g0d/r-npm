use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_pkg_get_name_npm_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0"
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

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

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_out = Command::new(rnpm_bin)
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
        .args(["pkg", "get", "name"])
        .output()
        .expect("rnpm pkg get failed");

    assert!(rnpm_out.status.success());
    let rnpm_stdout = String::from_utf8_lossy(&rnpm_out.stdout);
    assert_eq!(rnpm_stdout.trim(), "\"test-pkg\"");

    let npm_out = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "pkg", "get", "name"])
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

    if let Ok(npm_res) = npm_out {
        if npm_res.status.success() {
            let npm_stdout = String::from_utf8_lossy(&npm_res.stdout);
            assert_eq!(rnpm_stdout.trim(), npm_stdout.trim());
        }
    }
}
