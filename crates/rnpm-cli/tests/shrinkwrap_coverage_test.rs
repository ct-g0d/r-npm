use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;
use common::isolated_npm;

#[test]
fn test_shrinkwrap_renames_lockfile() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{"name":"shrinkwrap-test","version":"1.0.0"}"#;
    let lock_json = r#"{"name":"shrinkwrap-test","version":"1.0.0","lockfileVersion":3}"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp.path().join("package-lock.json"), lock_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args(["shrinkwrap"])
        .output()
        .expect("shrinkwrap failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(tmp.path().join("npm-shrinkwrap.json").exists());
    assert!(!tmp.path().join("package-lock.json").exists());
    assert!(out.stdout.is_empty(), "stdout should be empty, got: {}", String::from_utf8_lossy(&out.stdout));
    let rnpm_stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        rnpm_stderr.contains("npm notice package-lock.json has been renamed to npm-shrinkwrap.json"),
        "stderr: {}",
        rnpm_stderr
    );

    let iso = tempdir().unwrap();
    let cache_dir = iso.path().join("cache");
    let prefix_dir = iso.path().join("prefix");
    let appdata = iso.path().join("appdata");
    let localappdata = iso.path().join("localappdata");
    let userconfig = iso.path().join(".npmrc");
    let globalconfig = iso.path().join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(&userconfig, "registry=http://127.0.0.1:9/\n").unwrap();
    std::fs::write(&globalconfig, "").unwrap();

    let tmp_npm = tempdir().unwrap();
    fs::write(tmp_npm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_npm.path().join("package-lock.json"), lock_json).unwrap();
    let npm_res = isolated_npm(iso.path())
        .arg("shrinkwrap")
        .current_dir(tmp_npm.path())
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
        if npm_out.status.success() {
            assert!(npm_out.stdout.is_empty(), "npm stdout should be empty");
            let npm_stderr = String::from_utf8_lossy(&npm_out.stderr);
            assert!(npm_stderr.contains("npm notice package-lock.json has been renamed to npm-shrinkwrap.json"));
            assert!(tmp_npm.path().join("npm-shrinkwrap.json").exists());
            assert!(!tmp_npm.path().join("package-lock.json").exists());
        }
    }
}
