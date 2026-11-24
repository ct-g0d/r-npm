use rnpm_install::fast_path::compute_project_fingerprint;
use rnpm_install::InstallOptions;
use tempfile::tempdir;

/// Isolated in its own integration test binary because it mutates process-wide
/// `rnpm_config` static overrides (`set_process_userconfig`, `set_process_globalconfig`,
/// `set_process_cli_overrides`), which would otherwise race with parallel unit tests.
#[test]
fn test_compute_project_fingerprint_respects_userconfig_and_globalconfig_overrides() {
    let tmp = tempdir().unwrap();
    let pkg_json = tmp.path().join("package.json");
    std::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#).unwrap();

    let opts = InstallOptions {
        project_dir: tmp.path().to_path_buf(),
        config_override: None,
        ..Default::default()
    };

    let base_fp = compute_project_fingerprint(tmp.path(), &opts).unwrap();

    // 1. Setting userconfig override
    let user_npmrc = tmp.path().join(".user-npmrc");
    std::fs::write(&user_npmrc, "registry=https://custom-user-registry.org/\n").unwrap();
    rnpm_config::set_process_userconfig(user_npmrc.clone());

    let userconfig_fp = compute_project_fingerprint(tmp.path(), &opts).unwrap();
    assert_ne!(
        base_fp, userconfig_fp,
        "fingerprint must change when process userconfig override is set"
    );

    // Modifying userconfig file content must also change fingerprint
    std::fs::write(&user_npmrc, "registry=https://updated-user-registry.org/\n").unwrap();
    let userconfig_updated_fp = compute_project_fingerprint(tmp.path(), &opts).unwrap();
    assert_ne!(
        userconfig_fp, userconfig_updated_fp,
        "fingerprint must change when userconfig file content is modified"
    );

    // 2. Setting globalconfig override
    let global_npmrc = tmp.path().join(".global-npmrc");
    std::fs::write(&global_npmrc, "logs-max=100\n").unwrap();
    rnpm_config::set_process_globalconfig(global_npmrc);

    let globalconfig_fp = compute_project_fingerprint(tmp.path(), &opts).unwrap();
    assert_ne!(
        userconfig_updated_fp, globalconfig_fp,
        "fingerprint must change when process globalconfig override is set"
    );

    // 3. Setting CLI overrides
    let mut cli_map = std::collections::BTreeMap::new();
    cli_map.insert("fetch-retries".to_string(), "5".to_string());
    rnpm_config::set_process_cli_overrides(cli_map);

    let cli_fp = compute_project_fingerprint(tmp.path(), &opts).unwrap();
    assert_ne!(
        globalconfig_fp, cli_fp,
        "fingerprint must change when process CLI overrides are set"
    );
    rnpm_config::set_process_cli_overrides(std::collections::BTreeMap::new());
}
