use crate::*;
use std::path::PathBuf;

#[test]
fn test_is_sensitive_credential_key() {
    assert!(is_sensitive_credential_key("NPM_TOKEN"));
    assert!(is_sensitive_credential_key("_authToken"));
    assert!(is_sensitive_credential_key("//registry.npmjs.org/:_authToken"));
    assert!(is_sensitive_credential_key("npm_config_password"));
    assert!(is_sensitive_credential_key("secret_key"));
    assert!(is_sensitive_credential_key("AUTH_TOKEN"));
    assert!(is_sensitive_credential_key("_auth"));

    // Non-sensitive keys
    assert!(!is_sensitive_credential_key("PATH"));
    assert!(!is_sensitive_credential_key("AUTHOR"));
    assert!(!is_sensitive_credential_key("npm_package_author"));
    assert!(!is_sensitive_credential_key("INIT_CWD"));
    assert!(!is_sensitive_credential_key("NODE_ENV"));
}

#[test]
fn test_build_lifecycle_env_scrubbing() {
    let mut ctx = LifecycleContext::new(
        PathBuf::from("/project"),
        PathBuf::from("/project/node_modules/my-pkg"),
        "my-pkg",
        "postinstall",
        "echo 1",
    );
    ctx.extra_env.insert("npm_config__authToken".to_string(), "leak_token_123".to_string());
    ctx.extra_env.insert("//127.0.0.1:4873/:_authToken".to_string(), "leak_token_456".to_string());
    ctx.extra_env.insert("SAFE_VAR".to_string(), "safe_value".to_string());

    let env = build_lifecycle_env(&ctx);

    assert_eq!(env.get("SAFE_VAR").unwrap(), "safe_value");
    assert_eq!(env.get("npm_lifecycle_event").unwrap(), "postinstall");
    assert_eq!(env.get("npm_package_name").unwrap(), "my-pkg");
    assert_eq!(env.get("INIT_CWD").unwrap(), "/project");

    // Verify sensitive keys are scrubbed
    assert!(!env.contains_key("npm_config__authToken"));
    assert!(!env.contains_key("//127.0.0.1:4873/:_authToken"));
}

#[test]
fn test_execute_lifecycle_script_runs() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = LifecycleContext::new(
        temp.path(),
        temp.path(),
        "test-pkg",
        "test-event",
        "node -e \"process.exit(0)\"",
    );
    let status = execute_lifecycle_script(&ctx).unwrap();
    assert!(status.success());
}
