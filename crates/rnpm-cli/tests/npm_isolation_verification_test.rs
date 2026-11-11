use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

mod common;
use common::{isolated_npm, IsolatedNpmEnv};

fn normalize_path(path: &Path) -> PathBuf {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    #[cfg(windows)]
    {
        let s = canonical.to_string_lossy().replace('\\', "/").to_lowercase();
        let s = s.strip_prefix("//?/").unwrap_or(&s);
        let s = s.strip_prefix(r"\\?\").unwrap_or(s);
        PathBuf::from(s.trim_end_matches('/'))
    }
    #[cfg(not(windows))]
    {
        let s = canonical.to_string_lossy().to_string();
        PathBuf::from(s.trim_end_matches('/'))
    }
}

#[test]
fn test_isolated_npm_child_sees_temporary_paths() {
    let tmp = tempdir().unwrap();
    let iso_root = tmp.path().join("iso_root");
    fs::create_dir_all(&iso_root).unwrap();

    let env = IsolatedNpmEnv::new(&iso_root);

    // Verify directories and default config files were created by the factory
    assert!(env.cache_dir.exists(), "cache_dir must be created");
    assert!(env.prefix_dir.exists(), "prefix_dir must be created");
    assert!(env.appdata.exists(), "appdata must be created");
    assert!(env.localappdata.exists(), "localappdata must be created");
    assert!(env.logs_dir.exists(), "logs_dir must be created");
    assert!(env.userconfig.exists(), ".npmrc must exist");
    assert!(env.globalconfig.exists(), "global.npmrc must exist");

    // Verify paths are strictly scoped inside the temporary root
    assert!(env.cache_dir.starts_with(&iso_root));
    assert!(env.prefix_dir.starts_with(&iso_root));
    assert!(env.appdata.starts_with(&iso_root));
    assert!(env.localappdata.starts_with(&iso_root));
    assert!(env.logs_dir.starts_with(&iso_root));
    assert!(env.userconfig.starts_with(&iso_root));
    assert!(env.globalconfig.starts_with(&iso_root));

    // Verify they never match host environment variables
    if let Ok(host_home) = std::env::var("HOME") {
        assert_ne!(env.root.to_string_lossy(), host_home);
    }
    if let Ok(host_profile) = std::env::var("USERPROFILE") {
        assert_ne!(env.root.to_string_lossy(), host_profile);
    }
    if let Ok(host_appdata) = std::env::var("APPDATA") {
        assert_ne!(env.appdata.to_string_lossy(), host_appdata);
    }

    // 1. Verify child npm cache: must spawn successfully and exit 0
    let mut cache_cmd = isolated_npm(&iso_root);
    cache_cmd.args(["config", "get", "cache"]).current_dir(tmp.path());
    let cache_output = cache_cmd
        .output()
        .expect("Failed to spawn isolated npm for cache query");

    assert!(
        cache_output.status.success(),
        "npm config get cache failed with code {:?}\nstdout: {}\nstderr: {}",
        cache_output.status.code(),
        String::from_utf8_lossy(&cache_output.stdout),
        String::from_utf8_lossy(&cache_output.stderr)
    );

    let cache_out_str = String::from_utf8_lossy(&cache_output.stdout).trim().to_string();
    assert!(!cache_out_str.is_empty(), "npm cache query returned empty output");

    let child_cache = normalize_path(Path::new(&cache_out_str));
    let expected_cache = normalize_path(&env.cache_dir);
    assert_eq!(
        child_cache, expected_cache,
        "Child npm cache ({:?}) must exactly equal isolated cache dir ({:?})",
        child_cache, expected_cache
    );

    // 2. Verify child npm prefix: must spawn successfully and exit 0
    let mut prefix_cmd = isolated_npm(&iso_root);
    prefix_cmd.args(["config", "get", "prefix"]).current_dir(tmp.path());
    let prefix_output = prefix_cmd
        .output()
        .expect("Failed to spawn isolated npm for prefix query");

    assert!(
        prefix_output.status.success(),
        "npm config get prefix failed with code {:?}\nstdout: {}\nstderr: {}",
        prefix_output.status.code(),
        String::from_utf8_lossy(&prefix_output.stdout),
        String::from_utf8_lossy(&prefix_output.stderr)
    );

    let prefix_out_str = String::from_utf8_lossy(&prefix_output.stdout).trim().to_string();
    assert!(!prefix_out_str.is_empty(), "npm prefix query returned empty output");

    let child_prefix = normalize_path(Path::new(&prefix_out_str));
    let expected_prefix = normalize_path(&env.prefix_dir);
    assert_eq!(
        child_prefix, expected_prefix,
        "Child npm prefix ({:?}) must exactly equal isolated prefix dir ({:?})",
        child_prefix, expected_prefix
    );

    // 3. Verify child npm userconfig: must spawn successfully and exit 0
    let mut userconfig_cmd = isolated_npm(&iso_root);
    userconfig_cmd.args(["config", "get", "userconfig"]).current_dir(tmp.path());
    let userconfig_output = userconfig_cmd
        .output()
        .expect("Failed to spawn isolated npm for userconfig query");

    assert!(
        userconfig_output.status.success(),
        "npm config get userconfig failed with code {:?}\nstdout: {}\nstderr: {}",
        userconfig_output.status.code(),
        String::from_utf8_lossy(&userconfig_output.stdout),
        String::from_utf8_lossy(&userconfig_output.stderr)
    );

    let userconfig_out_str = String::from_utf8_lossy(&userconfig_output.stdout).trim().to_string();
    assert!(!userconfig_out_str.is_empty(), "npm userconfig query returned empty output");

    let child_userconfig = normalize_path(Path::new(&userconfig_out_str));
    let expected_userconfig = normalize_path(&env.userconfig);
    assert_eq!(
        child_userconfig, expected_userconfig,
        "Child npm userconfig ({:?}) must exactly equal isolated userconfig ({:?})",
        child_userconfig, expected_userconfig
    );
}

#[test]
fn test_scrub_inherited_npm_config_env_regression() {
    let tmp = tempfile::tempdir().expect("Failed to create tempdir");
    let mut cmd = isolated_npm(tmp.path());

    let dummy_keys = [
        "npm_config_dummy_leak",
        "NPM_CONFIG_UPPER_LEAK",
        "Npm_Config_Mixed_Leak",
        "npm_config_prefix",
        "npm_config_registry",
    ];

    IsolatedNpmEnv::scrub_env_keys(&mut cmd, dummy_keys);

    let envs: Vec<_> = cmd.get_envs().collect();
    for dummy in &dummy_keys {
        let removed = envs
            .iter()
            .any(|(k, v)| k.to_string_lossy().eq_ignore_ascii_case(dummy) && v.is_none());
        assert!(
            removed,
            "Inherited dummy key {:?} must be scrubbed with env_remove",
            dummy
        );
    }
}
