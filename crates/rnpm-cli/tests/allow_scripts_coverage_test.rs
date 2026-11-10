use std::process::Command;
use tempfile::tempdir;

fn normalize_output(text: &str) -> String {
    let mut in_notice = false;
    text.replace("\r\n", "\n")
        .lines()
        .filter(|line| {
            if line.contains("A complete log of this run can be found in:") {
                return false;
            }
            if line.contains("New major version of npm available!") {
                in_notice = true;
                return false;
            }
            if in_notice {
                if line.starts_with("npm notice") {
                    return false;
                } else {
                    in_notice = false;
                }
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn setup_fixture(dir: &std::path::Path) {
    let pkg_dir = dir.join("node_modules").join("my-pkg");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let pkg_json = serde_json::json!({
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "my-pkg": "1.0.0"
        }
    });
    std::fs::write(dir.join("package.json"), serde_json::to_string_pretty(&pkg_json).unwrap()).unwrap();

    let lock_json = serde_json::json!({
        "name": "test-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-app",
                "version": "1.0.0",
                "dependencies": {
                    "my-pkg": "1.0.0"
                }
            },
            "node_modules/my-pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz"
            }
        }
    });
    std::fs::write(dir.join("package-lock.json"), serde_json::to_string_pretty(&lock_json).unwrap()).unwrap();

    let my_pkg_json = serde_json::json!({
        "name": "my-pkg",
        "version": "1.0.0",
        "scripts": {
            "install": "echo 1"
        }
    });
    std::fs::write(pkg_dir.join("package.json"), serde_json::to_string_pretty(&my_pkg_json).unwrap()).unwrap();
}

#[test]
fn test_cli_approve_scripts_parity() {
    let tmp = tempdir().unwrap();
    let iso = tmp.path().join("iso");
    let cache_dir = iso.join("cache");
    let prefix_dir = iso.join("prefix");
    let appdata = iso.join("appdata");
    let localappdata = iso.join("localappdata");
    let userconfig = iso.join(".npmrc");
    let globalconfig = iso.join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(&userconfig, "").unwrap();

    let dir_rnpm = tmp.path().join("rnpm_app");
    let dir_npm = tmp.path().join("npm_app");
    std::fs::create_dir_all(&dir_rnpm).unwrap();
    std::fs::create_dir_all(&dir_npm).unwrap();
    setup_fixture(&dir_rnpm);
    setup_fixture(&dir_npm);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(&dir_rnpm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["approve-scripts", "my-pkg"])
        .output()
        .expect("rnpm approve-scripts failed");

    let npm_res = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "approve-scripts",
            "my-pkg",
            "--no-update-notifier",
        ])
        .current_dir(&dir_npm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res {
        assert_eq!(rnpm_res.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_res.status.success());
    }

    // Verify package.json updated with allowScripts
    let pkg_rnpm: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir_rnpm.join("package.json")).unwrap()).unwrap();
    assert_eq!(pkg_rnpm["allowScripts"]["my-pkg@1.0.0"], true);
}

#[test]
fn test_cli_deny_scripts_parity() {
    let tmp = tempdir().unwrap();
    let iso = tmp.path().join("iso");
    let cache_dir = iso.join("cache");
    let prefix_dir = iso.join("prefix");
    let appdata = iso.join("appdata");
    let localappdata = iso.join("localappdata");
    let userconfig = iso.join(".npmrc");
    let globalconfig = iso.join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(&userconfig, "").unwrap();

    let dir_rnpm = tmp.path().join("rnpm_app");
    let dir_npm = tmp.path().join("npm_app");
    std::fs::create_dir_all(&dir_rnpm).unwrap();
    std::fs::create_dir_all(&dir_npm).unwrap();
    setup_fixture(&dir_rnpm);
    setup_fixture(&dir_npm);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(&dir_rnpm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["deny-scripts", "my-pkg"])
        .output()
        .expect("rnpm deny-scripts failed");

    let npm_res = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "deny-scripts",
            "my-pkg",
            "--no-update-notifier",
        ])
        .current_dir(&dir_npm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res {
        assert_eq!(rnpm_res.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_res.status.success());
    }

    let pkg_rnpm: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir_rnpm.join("package.json")).unwrap()).unwrap();
    assert_eq!(pkg_rnpm["allowScripts"]["my-pkg"], false);
}

#[test]
fn test_cli_install_scripts_parity() {
    let tmp = tempdir().unwrap();
    let iso = tmp.path().join("iso");
    let cache_dir = iso.join("cache");
    let prefix_dir = iso.join("prefix");
    let appdata = iso.join("appdata");
    let localappdata = iso.join("localappdata");
    let userconfig = iso.join(".npmrc");
    let globalconfig = iso.join("global.npmrc");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&prefix_dir).unwrap();
    std::fs::create_dir_all(&appdata).unwrap();
    std::fs::create_dir_all(&localappdata).unwrap();
    std::fs::write(&userconfig, "").unwrap();

    let dir_rnpm = tmp.path().join("rnpm_app");
    let dir_npm = tmp.path().join("npm_app");
    std::fs::create_dir_all(&dir_rnpm).unwrap();
    std::fs::create_dir_all(&dir_npm).unwrap();
    setup_fixture(&dir_rnpm);
    setup_fixture(&dir_npm);

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(&dir_rnpm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .args(["install-scripts", "approve", "my-pkg"])
        .output()
        .expect("rnpm install-scripts failed");

    let npm_res = Command::new("cmd.exe")
        .args([
            "/d",
            "/s",
            "/c",
            "npm.cmd",
            "install-scripts",
            "approve",
            "my-pkg",
            "--no-update-notifier",
        ])
        .current_dir(&dir_npm)
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
        .env("npm_config_userconfig", &userconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("USERCONFIG", &userconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .output();

    if let Ok(npm_out) = npm_res {
        assert_eq!(rnpm_res.status.code(), npm_out.status.code());
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stdout))
        );
        assert_eq!(
            normalize_output(&String::from_utf8_lossy(&rnpm_res.stderr)),
            normalize_output(&String::from_utf8_lossy(&npm_out.stderr))
        );
    } else {
        assert!(rnpm_res.status.success());
    }
}
