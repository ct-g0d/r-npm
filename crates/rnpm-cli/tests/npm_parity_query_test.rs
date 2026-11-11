use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;
use common::isolated_npm;

#[test]
fn test_query_root_npm_parity() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
  "name": "test-pkg",
  "version": "1.0.0",
  "description": "test fixture",
  "scripts": {
    "test": "node -e \"console.log('tested')\""
  },
  "dependencies": {
    "is-number": "7.0.0"
  }
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
        .args(["query", ":root"])
        .output()
        .expect("rnpm query :root failed");

    assert!(rnpm_out.status.success());
    let rnpm_val: serde_json::Value =
        serde_json::from_slice(&rnpm_out.stdout).expect("rnpm output should be valid JSON array");
    let rnpm_arr = rnpm_val.as_array().expect("rnpm query should be array");
    assert_eq!(rnpm_arr.len(), 1);
    let rnpm_obj = rnpm_arr[0].as_object().expect("root node should be object");

    // Check that manifest fields appear first and in order
    let keys: Vec<&str> = rnpm_obj.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        &keys[..5],
        &["name", "version", "description", "scripts", "dependencies"]
    );

    // Check Arborist metadata fields follow
    assert_eq!(
        &keys[5..],
        &[
            "_id",
            "pkgid",
            "location",
            "path",
            "realpath",
            "resolved",
            "from",
            "to",
            "dev",
            "inBundle",
            "deduped",
            "overridden",
            "queryContext"
        ]
    );

    // If npm is available, compare directly against npm query :root
    let npm_out = isolated_npm()
        .args(["query", ":root"])
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
            let npm_val: serde_json::Value = serde_json::from_slice(&npm_res.stdout)
                .expect("npm output should be valid JSON array");
            let npm_arr = npm_val.as_array().expect("npm query should be array");
            assert_eq!(npm_arr.len(), 1);
            let npm_obj = npm_arr[0].as_object().expect("npm root node should be object");

            let npm_keys: Vec<&str> = npm_obj.keys().map(|k| k.as_str()).collect();
            assert_eq!(keys, npm_keys, "Field set and order must match npm exactly");
        }
    }
}
