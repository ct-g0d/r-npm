use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_prefix_root_live_npm_parity() {
    let tmp = tempdir().unwrap();
    let proj_dir = tmp.path().join("my-project");
    fs::create_dir_all(&proj_dir).unwrap();
    fs::write(proj_dir.join("package.json"), r#"{"name":"my-project","version":"1.0.0"}"#).unwrap();

    let isolated_env = tmp.path().join("isolated");
    let isolated_cache = isolated_env.join("cache");
    let isolated_prefix = isolated_env.join("prefix");
    let isolated_userconfig = isolated_env.join(".npmrc");
    let isolated_globalconfig = isolated_env.join("global.npmrc");
    let isolated_appdata = isolated_env.join("appdata");
    let isolated_localappdata = isolated_env.join("localappdata");
    fs::create_dir_all(&isolated_cache).unwrap();
    fs::create_dir_all(&isolated_prefix).unwrap();
    fs::create_dir_all(&isolated_appdata).unwrap();
    fs::create_dir_all(&isolated_localappdata).unwrap();
    fs::write(&isolated_userconfig, "registry=http://127.0.0.1:9/\n").unwrap();
    fs::write(&isolated_globalconfig, "").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Local prefix
    let rnpm_prefix = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .arg("prefix")
        .output()
        .expect("rnpm prefix failed");
    assert!(rnpm_prefix.status.success());
    let rnpm_prefix_out = String::from_utf8_lossy(&rnpm_prefix.stdout).trim().to_string();

    // 2. Local root
    let rnpm_root = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .arg("root")
        .output()
        .expect("rnpm root failed");
    assert!(rnpm_root.status.success());
    let rnpm_root_out = String::from_utf8_lossy(&rnpm_root.stdout).trim().to_string();

    // 3. Global prefix
    let rnpm_gprefix = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .args(["prefix", "-g"])
        .output()
        .expect("rnpm prefix -g failed");
    assert!(rnpm_gprefix.status.success());
    let rnpm_gprefix_out = String::from_utf8_lossy(&rnpm_gprefix.stdout).trim().to_string();

    // 4. Global root
    let rnpm_groot = Command::new(rnpm_bin)
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .args(["root", "-g"])
        .output()
        .expect("rnpm root -g failed");
    assert!(rnpm_groot.status.success());
    let rnpm_groot_out = String::from_utf8_lossy(&rnpm_groot.stdout).trim().to_string();

    // Now compare with live npm.cmd
    let npm_prefix = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "prefix"])
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .output();

    if let Ok(npm_p) = npm_prefix {
        if npm_p.status.success() {
            let npm_p_out = String::from_utf8_lossy(&npm_p.stdout).trim().to_string();
            // Paths should represent the same path
            assert_eq!(
                PathBuf::from(&rnpm_prefix_out).canonicalize().unwrap_or(PathBuf::from(&rnpm_prefix_out)),
                PathBuf::from(&npm_p_out).canonicalize().unwrap_or(PathBuf::from(&npm_p_out)),
                "Prefix output mismatch: rnpm={} vs npm={}",
                rnpm_prefix_out,
                npm_p_out
            );
        }
    }

    let npm_root = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "root"])
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .output();

    if let Ok(npm_r) = npm_root {
        if npm_r.status.success() {
            let npm_r_out = String::from_utf8_lossy(&npm_r.stdout).trim().to_string();
            assert_eq!(
                PathBuf::from(&rnpm_root_out).canonicalize().unwrap_or(PathBuf::from(&rnpm_root_out)),
                PathBuf::from(&npm_r_out).canonicalize().unwrap_or(PathBuf::from(&npm_r_out)),
                "Root output mismatch: rnpm={} vs npm={}",
                rnpm_root_out,
                npm_r_out
            );
        }
    }

    let npm_gprefix = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "prefix", "-g"])
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .output();

    if let Ok(npm_gp) = npm_gprefix {
        if npm_gp.status.success() {
            let npm_gp_out = String::from_utf8_lossy(&npm_gp.stdout).trim().to_string();
            assert_eq!(
                PathBuf::from(&rnpm_gprefix_out).canonicalize().unwrap_or(PathBuf::from(&rnpm_gprefix_out)),
                PathBuf::from(&npm_gp_out).canonicalize().unwrap_or(PathBuf::from(&npm_gp_out)),
                "Global prefix output mismatch: rnpm={} vs npm={}",
                rnpm_gprefix_out,
                npm_gp_out
            );
        }
    }

    let npm_groot = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "root", "-g"])
        .current_dir(&proj_dir)
        .env("HOME", &isolated_env)
        .env("USERPROFILE", &isolated_env)
        .env("npm_config_userconfig", &isolated_userconfig)
        .env("npm_config_globalconfig", &isolated_globalconfig)
        .env("NPM_CONFIG_PREFIX", &isolated_prefix)
        .env("PREFIX", &isolated_prefix)
        .env("USERCONFIG", &isolated_userconfig)
        .env("GLOBALCONFIG", &isolated_globalconfig)
        .env("CACHE", &isolated_cache)
        .env("NPM_CONFIG_CACHE", &isolated_cache)
        .env("npm_config_cache", &isolated_cache)
        .env("APPDATA", &isolated_appdata)
        .env("LOCALAPPDATA", &isolated_localappdata)
        .output();

    if let Ok(npm_gr) = npm_groot {
        if npm_gr.status.success() {
            let npm_gr_out = String::from_utf8_lossy(&npm_gr.stdout).trim().to_string();
            assert_eq!(
                PathBuf::from(&rnpm_groot_out).canonicalize().unwrap_or(PathBuf::from(&rnpm_groot_out)),
                PathBuf::from(&npm_gr_out).canonicalize().unwrap_or(PathBuf::from(&npm_gr_out)),
                "Global root output mismatch: rnpm={} vs npm={}",
                rnpm_groot_out,
                npm_gr_out
            );
        }
    }
}
