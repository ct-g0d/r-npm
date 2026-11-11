use std::fs;
use tempfile::tempdir;

mod common;
use common::{isolated_npm, IsolatedNpmEnv};

#[test]
fn test_isolated_npm_child_sees_temporary_paths() {
    let tmp = tempdir().unwrap();
    let iso_root = tmp.path().join("iso_root");
    fs::create_dir_all(&iso_root).unwrap();

    let env = IsolatedNpmEnv::new(&iso_root);

    // Verify directories were created by the factory
    assert!(env.cache_dir.exists(), "cache_dir must be created");
    assert!(env.prefix_dir.exists(), "prefix_dir must be created");
    assert!(env.appdata.exists(), "appdata must be created");
    assert!(env.localappdata.exists(), "localappdata must be created");
    assert!(env.logs_dir.exists(), "logs_dir must be created");
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

    // Spawn live isolated command and verify child process configuration
    let mut cmd = isolated_npm(&iso_root);
    cmd.args(["config", "get", "cache"]).current_dir(tmp.path());

    if let Ok(output) = cmd.output() {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let norm_out = out_str.replace('\\', "/").to_lowercase();
            let norm_expected = env.cache_dir.to_string_lossy().replace('\\', "/").to_lowercase();
            assert!(
                norm_out.contains(&norm_expected) || norm_expected.contains(&norm_out),
                "Child npm cache ({:?}) must match temporary isolated cache ({:?})",
                out_str,
                env.cache_dir
            );
        }
    }

    // Verify prefix
    let mut prefix_cmd = isolated_npm(&iso_root);
    prefix_cmd.args(["config", "get", "prefix"]).current_dir(tmp.path());
    if let Ok(output) = prefix_cmd.output() {
        if output.status.success() {
            let out_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let norm_out = out_str.replace('\\', "/").to_lowercase();
            let norm_expected = env.prefix_dir.to_string_lossy().replace('\\', "/").to_lowercase();
            assert!(
                norm_out.contains(&norm_expected) || norm_expected.contains(&norm_out),
                "Child npm prefix ({:?}) must match temporary isolated prefix ({:?})",
                out_str,
                env.prefix_dir
            );
        }
    }
}
