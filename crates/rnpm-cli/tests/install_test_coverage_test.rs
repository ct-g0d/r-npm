use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;
use common::isolated_npm;

#[test]
fn test_install_test_execution() {
    let tmp = tempdir().unwrap();
    let iso = tmp.path().join("iso");
    let cache_dir = iso.join("cache");
    let prefix_dir = iso.join("prefix");
    let appdata = iso.join("appdata");
    let localappdata = iso.join("localappdata");
    let userconfig = iso.join(".npmrc");
    let globalconfig = iso.join("global.npmrc");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::create_dir_all(&prefix_dir).unwrap();
    fs::create_dir_all(&appdata).unwrap();
    fs::create_dir_all(&localappdata).unwrap();
    fs::write(&userconfig, "registry=http://127.0.0.1:9/\n").unwrap();
    fs::write(&globalconfig, "").unwrap();

    let pkg_json = r#"{
  "name": "install-test-pkg",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('install-test-ran')\""
  }
}
"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .env("HOME", &iso)
        .env("USERPROFILE", &iso)
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
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["install-test", "--package-lock-only"])
        .output()
        .expect("install-test failed");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("install-test-ran"));
}

fn normalize_output(text: &str) -> String {
    let s = text.replace("\r\n", "\n");
    // Normalize timings
    let mut normalized = String::new();
    let mut rest = s.as_str();
    while let Some(idx) = rest.find(" in ") {
        normalized.push_str(&rest[..idx + 4]);
        let after = &rest[idx + 4..];
        let end_num = after.find(|c: char| !c.is_numeric() && c != '.');
        if let Some(num_len) = end_num {
            let suffix = &after[num_len..];
            if let Some(stripped) = suffix.strip_prefix("ms") {
                normalized.push_str("<TIME>");
                rest = stripped;
                continue;
            } else if let Some(stripped) = suffix.strip_prefix('s') {
                normalized.push_str("<TIME>");
                rest = stripped;
                continue;
            }
        }
        normalized.push_str(&rest[idx + 4..idx + 5]);
        rest = &rest[idx + 5..];
    }
    normalized.push_str(rest);

    normalized
        .lines()
        .filter(|line| !line.contains("A complete log of this run can be found in:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[test]
fn test_install_test_live_npm_parity() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();

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

    let pkg_json = r#"{
  "name": "install-test-parity",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('it-ok')\""
  }
}
"#;
    let lock_json = r#"{
  "name": "install-test-parity",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "install-test-parity",
      "version": "1.0.0",
      "scripts": {
        "test": "node -e \"console.log('it-ok')\""
      }
    }
  }
}
"#;
    fs::write(tmp_rnpm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_rnpm.path().join("package-lock.json"), lock_json).unwrap();

    fs::write(tmp_npm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_npm.path().join("package-lock.json"), lock_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
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
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["install-test"])
        .output()
        .expect("rnpm install-test failed");

    let npm_res = isolated_npm()
        .args(["install-test", "--no-audit", "--no-fund"])
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
            assert_eq!(rnpm_res.status.code(), npm_out.status.code());
            let rnpm_stdout = normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout));
            let npm_stdout = normalize_output(&String::from_utf8_lossy(&npm_out.stdout));
            assert_eq!(rnpm_stdout, npm_stdout, "stdout mismatch: rnpm={:?} vs npm={:?}", rnpm_stdout, npm_stdout);
        }
    }
}

#[test]
fn test_install_ci_test_live_npm_parity() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();

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

    let pkg_json = r#"{
  "name": "install-ci-test-parity",
  "version": "1.0.0",
  "scripts": {
    "test": "node -e \"console.log('cit-ok')\""
  }
}
"#;
    let lock_json = r#"{
  "name": "install-ci-test-parity",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "install-ci-test-parity",
      "version": "1.0.0",
      "scripts": {
        "test": "node -e \"console.log('cit-ok')\""
      }
    }
  }
}
"#;
    fs::write(tmp_rnpm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_rnpm.path().join("package-lock.json"), lock_json).unwrap();

    fs::write(tmp_npm.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp_npm.path().join("package-lock.json"), lock_json).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
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
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(["install-ci-test"])
        .output()
        .expect("rnpm install-ci-test failed");

    let npm_res = isolated_npm()
        .args(["install-ci-test", "--no-audit", "--no-fund"])
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
            assert_eq!(rnpm_res.status.code(), npm_out.status.code());
            let rnpm_stdout = normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout));
            let npm_stdout = normalize_output(&String::from_utf8_lossy(&npm_out.stdout));
            assert_eq!(rnpm_stdout, npm_stdout, "stdout mismatch: rnpm={:?} vs npm={:?}", rnpm_stdout, npm_stdout);
        }
    }
}

