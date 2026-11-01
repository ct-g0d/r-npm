use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;
use url::Url;
use crate::npmrc::{interpolate_env, Npmrc};
use crate::Config;

#[test]
fn test_env_interpolation() {
    let mut env_map = HashMap::new();
    env_map.insert("AUTH_TOKEN".to_string(), "secret_token_123".to_string());
    env_map.insert("MY_HOST".to_string(), "myregistry.internal".to_string());

    let lookup = |var: &str| env_map.get(var).cloned();

    assert_eq!(
        interpolate_env("//${MY_HOST}/:_authToken=${AUTH_TOKEN}", &lookup),
        "//myregistry.internal/:_authToken=secret_token_123"
    );

    // Fallback default value
    assert_eq!(
        interpolate_env("val=${UNSET_VAR:-default_val}", &lookup),
        "val=default_val"
    );

    // Unset without fallback produces empty
    assert_eq!(
        interpolate_env("val=${UNSET_VAR}", &lookup),
        "val="
    );

    // $VAR shorthand
    assert_eq!(
        interpolate_env("token=$AUTH_TOKEN", &lookup),
        "token=secret_token_123"
    );
}

#[test]
fn test_npmrc_parsing_comments_and_settings() {
    let content = r#"
    # This is a comment
    ; This is also a comment
    registry = https://registry.npmjs.org/
    strict-ssl = true
    save-exact
    "#;

    let npmrc = Npmrc::parse(content).unwrap();
    assert_eq!(npmrc.registry.as_str(), "https://registry.npmjs.org/");
    assert_eq!(npmrc.settings.get("strict-ssl").unwrap(), "true");
    assert_eq!(npmrc.settings.get("save-exact").unwrap(), "true");
}

#[test]
fn test_scoped_registries() {
    let content = r#"
    registry = https://registry.npmjs.org/
    @myorg:registry = https://npm.pkg.github.com/
    @company:registry = https://custom.internal.net/npm/
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    // Scoped package resolves to custom registry
    let reg1 = npmrc.registry_for_package("@myorg/widget");
    assert_eq!(reg1.as_str(), "https://npm.pkg.github.com/");

    let reg2 = npmrc.registry_for_package("@company/core");
    assert_eq!(reg2.as_str(), "https://custom.internal.net/npm/");

    // Unscoped package resolves to default registry
    let reg_default = npmrc.registry_for_package("express");
    assert_eq!(reg_default.as_str(), "https://registry.npmjs.org/");

    // Different scope falls back to default registry
    let reg_other = npmrc.registry_for_package("@other/lib");
    assert_eq!(reg_other.as_str(), "https://registry.npmjs.org/");
}

#[test]
fn test_auth_token_resolution() {
    let content = r#"
    //registry.npmjs.org/:_authToken=npm_test_token_global
    //npm.pkg.github.com/:_authToken=ghp_secret_token
    //localhost:4873/:_authToken=local_test_token
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    let npmjs_url = Url::parse("https://registry.npmjs.org/@scope/pkg").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&npmjs_url),
        Some("npm_test_token_global")
    );

    let github_url = Url::parse("https://npm.pkg.github.com/@myorg/foo").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&github_url),
        Some("ghp_secret_token")
    );

    let local_url = Url::parse("http://localhost:4873/tarballs/foo.tgz").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&local_url),
        Some("local_test_token")
    );

    let unknown_url = Url::parse("https://unknown.registry.com/").unwrap();
    assert_eq!(npmrc.get_auth_token(&unknown_url), None);
}

#[test]
fn test_config_merging_precedence() {
    let dir = tempdir().unwrap();
    let project_dir = dir.path().to_path_buf();

    // User settings
    let mut user_npmrc = Npmrc::new();
    user_npmrc.set("registry", "https://user.registry.com/").unwrap();
    user_npmrc.set("package-lock", "true").unwrap();
    user_npmrc.set("@myorg:registry", "https://user.myorg.com/").unwrap();

    // Project settings
    let project_npmrc_content = r#"
    registry = https://project.registry.com/
    save-exact = true
    "#;
    let project_npmrc_path = project_dir.join(".npmrc");
    fs::write(&project_npmrc_path, project_npmrc_content).unwrap();

    let project_npmrc = Npmrc::from_file(&project_npmrc_path).unwrap();

    // Merge: project into user
    user_npmrc.merge(project_npmrc);

    // Project overrides user registry
    assert_eq!(user_npmrc.registry.as_str(), "https://project.registry.com/");
    // User scoped registry preserved
    assert_eq!(
        user_npmrc.scoped_registries.get("@myorg").unwrap().as_str(),
        "https://user.myorg.com/"
    );
    // User setting preserved
    assert_eq!(user_npmrc.settings.get("package-lock").unwrap(), "true");
    // Project setting added
    assert_eq!(user_npmrc.settings.get("save-exact").unwrap(), "true");

    // Test Config::load with project directory
    let loaded = Config::load(Some(&project_dir)).unwrap();
    assert_eq!(loaded.npmrc.registry.as_str(), "https://project.registry.com/");
    assert_eq!(loaded.npmrc.settings.get("save-exact").unwrap(), "true");
}
