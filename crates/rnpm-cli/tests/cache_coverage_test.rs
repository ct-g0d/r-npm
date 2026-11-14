use std::fs;
use std::process::Command;
use tempfile::tempdir;

mod common;
use common::isolated_npm;

#[test]
fn test_cache_add_and_ls_and_verify() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let sample_file = tmp.path().join("sample.tgz");
    fs::write(&sample_file, b"sample package archive content").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test cache add
    let add_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "add",
            sample_file.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache add");

    assert!(add_output.status.success(), "cache add failed: {}", String::from_utf8_lossy(&add_output.stderr));
    let stdout = String::from_utf8_lossy(&add_output.stdout);
    assert!(stdout.is_empty(), "npm cache add is silent");
    let key = format!(
        "pacote:tarball:file:{}",
        sample_file.to_string_lossy().replace('\\', "/")
    );
    let cache = rnpm_cache::Cache::new(&cache_dir).unwrap();
    let (_, cached) = cache
        .get(&key)
        .unwrap()
        .expect("archive bytes must be cached");
    assert_eq!(cached, b"sample package archive content");

    // Test cache ls
    let ls_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "ls",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache ls");

    assert!(ls_output.status.success(), "cache ls failed: {}", String::from_utf8_lossy(&ls_output.stderr));
    let ls_stdout = String::from_utf8_lossy(&ls_output.stdout);
    assert_eq!(ls_stdout.trim(), key);

    // Test cache verify
    let verify_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "verify",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache verify");

    assert!(verify_output.status.success(), "cache verify failed: {}", String::from_utf8_lossy(&verify_output.stderr));
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("Cache verified"));
}

fn normalize_output(text: &str, dir: &std::path::Path) -> String {
    let mut s = text.replace("\r\n", "\n");
    let dir_str = dir.to_string_lossy();
    s = s.replace(&dir_str.to_string(), "<DIR>");
    s = s.replace(&dir_str.replace('\\', "/"), "<DIR>");
    if let Ok(canon) = dir.canonicalize() {
        let canon_str = canon.to_string_lossy();
        s = s.replace(&canon_str.to_string(), "<DIR>");
        s = s.replace(&canon_str.replace('\\', "/"), "<DIR>");
        let unc = canon_str.trim_start_matches(r"\\?\");
        s = s.replace(unc, "<DIR>");
        s = s.replace(&unc.replace('\\', "/"), "<DIR>");
    }

    normalized_lines(&s)
}

fn normalized_lines(s: &str) -> String {
    s.lines()
        .filter(|line| !line.contains("A complete log of this run can be found in:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[test]
fn test_cache_clean_eusage_live_npm_parity() {
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

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp.path())
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
        .args(["cache", "clean"])
        .output()
        .expect("rnpm cache clean failed");

    assert_eq!(rnpm_res.status.code(), Some(1));

    let npm_res = isolated_npm(&iso)
        .args(["cache", "clean"])
        .current_dir(tmp.path())
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
        let rnpm_stdout = normalize_output(&String::from_utf8_lossy(&rnpm_res.stdout), tmp.path());
        let npm_stdout = normalize_output(&String::from_utf8_lossy(&npm_out.stdout), tmp.path());
        assert_eq!(rnpm_stdout, npm_stdout);

        let rnpm_stderr = normalize_output(&String::from_utf8_lossy(&rnpm_res.stderr), tmp.path());
        let npm_stderr = normalize_output(&String::from_utf8_lossy(&npm_out.stderr), tmp.path());
        assert_eq!(rnpm_stderr, npm_stderr, "stderr mismatch: rnpm={:?} vs npm={:?}", rnpm_stderr, npm_stderr);
    }
}

