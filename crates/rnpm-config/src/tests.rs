use crate::npmrc::{interpolate_env, Npmrc};
use crate::{Config, ConfigOptions};
use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;
use url::Url;

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
    assert_eq!(interpolate_env("val=${UNSET_VAR}", &lookup), "val=");

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
    assert_eq!(npmrc.get_auth_token(&github_url), Some("ghp_secret_token"));

    let local_url = Url::parse("http://localhost:4873/tarballs/foo.tgz").unwrap();
    assert_eq!(npmrc.get_auth_token(&local_url), Some("local_test_token"));

    let unknown_url = Url::parse("https://unknown.registry.com/").unwrap();
    assert_eq!(npmrc.get_auth_token(&unknown_url), None);
}

#[test]
fn test_config_merging_precedence() {
    let dir = tempdir().unwrap();
    let project_dir = dir.path().to_path_buf();

    // User settings
    let mut user_npmrc = Npmrc::new();
    user_npmrc
        .set("registry", "https://user.registry.com/")
        .unwrap();
    user_npmrc.set("package-lock", "true").unwrap();
    user_npmrc
        .set("@myorg:registry", "https://user.myorg.com/")
        .unwrap();

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
    assert_eq!(
        user_npmrc.registry.as_str(),
        "https://project.registry.com/"
    );
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
    assert_eq!(
        loaded.npmrc.registry.as_str(),
        "https://project.registry.com/"
    );
    assert_eq!(loaded.npmrc.settings.get("save-exact").unwrap(), "true");
}

#[test]
fn test_env_interpolation_escaping_and_defaults() {
    let mut env_map = HashMap::new();
    env_map.insert("EMPTY_VAR".to_string(), "".to_string());
    env_map.insert("SET_VAR".to_string(), "val".to_string());
    let lookup = |var: &str| env_map.get(var).cloned();

    // 1. Escaping ${VAR} and $VAR
    assert_eq!(interpolate_env(r"\${SET_VAR}", &lookup), "${SET_VAR}");
    assert_eq!(interpolate_env(r"\$SET_VAR", &lookup), "$SET_VAR");
    assert_eq!(interpolate_env("Cost is $$100", &lookup), "Cost is $100");

    // 2. ${VAR:-default} uses default when unset OR empty
    assert_eq!(
        interpolate_env("${UNSET_VAR:-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(
        interpolate_env("${EMPTY_VAR:-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(interpolate_env("${SET_VAR:-fallback}", &lookup), "val");

    // 3. ${VAR-default} uses default ONLY when unset (keeps empty if set to empty)
    assert_eq!(
        interpolate_env("${UNSET_VAR-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(interpolate_env("${EMPTY_VAR-fallback}", &lookup), "");
    assert_eq!(interpolate_env("${SET_VAR-fallback}", &lookup), "val");

    // 4. Multi-byte Unicode in input works safely without slice boundary issues
    let unicode_input = "prefix 🦀 ${SET_VAR} 🚀 suffix";
    assert_eq!(
        interpolate_env(unicode_input, &lookup),
        "prefix 🦀 val 🚀 suffix"
    );

    // 5. Invalid identifiers preserved as literal
    assert_eq!(
        interpolate_env("${VAR; injection}", &lookup),
        "${VAR; injection}"
    );
}

#[test]
fn test_scoped_precedence_and_alternate_syntaxes() {
    let content = r#"
    registry = https://registry.npmjs.org/
    @myorg:registry = https://custom1.org/
    @altorg/registry = https://custom2.org/
    thirdorg:registry = https://custom3.org/
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    // Standard @myorg:registry
    assert_eq!(
        npmrc.registry_for_package("@myorg/widget").as_str(),
        "https://custom1.org/"
    );

    // Alternate @altorg/registry syntax
    assert_eq!(
        npmrc.registry_for_package("@altorg/pkg").as_str(),
        "https://custom2.org/"
    );

    // Bare thirdorg:registry syntax
    assert_eq!(
        npmrc.registry_for_package("@thirdorg/lib").as_str(),
        "https://custom3.org/"
    );

    // Case insensitivity
    assert_eq!(
        npmrc.registry_for_package("@MYORG/WIDGET").as_str(),
        "https://custom1.org/"
    );

    // Encoded scoped package name
    assert_eq!(
        npmrc.registry_for_package("@myorg%2fwidget").as_str(),
        "https://custom1.org/"
    );

    // Unscoped package falls back to default registry
    assert_eq!(
        npmrc.registry_for_package("react").as_str(),
        "https://registry.npmjs.org/"
    );

    // Unmatched scope falls back to default registry
    assert_eq!(
        npmrc.registry_for_package("@unknown/pkg").as_str(),
        "https://registry.npmjs.org/"
    );
}

#[test]
fn test_auth_token_for_package_and_crlf_rejection() {
    let content = r#"
    registry = https://registry.npmjs.org/
    @corp:registry = https://npm.corp.internal/
    //registry.npmjs.org/:_authToken = public_token
    //npm.corp.internal/:_authToken = internal_token
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    // Auth token for scoped package
    assert_eq!(
        npmrc.get_auth_token_for_package("@corp/secret-lib"),
        Some("internal_token")
    );

    // Auth token for unscoped package
    assert_eq!(
        npmrc.get_auth_token_for_package("lodash"),
        Some("public_token")
    );

    // Rejection of CRLF / newline injection in auth token
    let mut bad_npmrc = Npmrc::new();
    assert!(bad_npmrc
        .set("//registry.org/:_authToken", "token\r\nevil=1")
        .is_err());
    assert!(bad_npmrc.set("key\ninvalid", "val").is_err());
}

#[test]
fn test_package_metadata_url_and_validation() {
    let mut npmrc = Npmrc::new();
    npmrc
        .set("@myorg:registry", "https://custom.registry.com/")
        .unwrap();

    // Scoped package URL formatting
    let url = npmrc.package_metadata_url("@myorg/pkg").unwrap();
    assert_eq!(url.as_str(), "https://custom.registry.com/@myorg%2fpkg");

    // Unscoped package URL formatting
    let unscoped_url = npmrc.package_metadata_url("lodash").unwrap();
    assert_eq!(unscoped_url.as_str(), "https://registry.npmjs.org/lodash");

    // Path traversal in package name is rejected
    assert!(npmrc.package_metadata_url("../foo").is_err());
    assert!(npmrc
        .package_metadata_url("@myorg/../../etc/passwd")
        .is_err());
    assert!(npmrc.package_metadata_url("").is_err());
}

#[test]
fn test_malicious_scopes_unicode_spoofing_and_rejection() {
    use crate::npmrc::validate_package_name;

    let content = r#"
    registry = https://registry.npmjs.org/
    @company:registry = https://npm.company.internal/
    "#;
    let npmrc = Npmrc::parse(content).unwrap();

    // 1. Cyrillic homoglyph spoofing: '@соmраny/secret' where 'о', 'а' are Cyrillic U+043E, U+0430
    let cyrillic_spoofed = "@\u{0441}\u{043E}m\u{0440}\u{0430}ny/secret";
    // Must fail package validation
    assert!(validate_package_name(cyrillic_spoofed).is_err());
    // In registry_for_package fallback: must NEVER match the private @company registry
    let routed = npmrc.registry_for_package(cyrillic_spoofed);
    assert_eq!(
        routed.as_str(),
        "https://registry.npmjs.org/",
        "Unicode spoofed package must never route to private company registry"
    );

    // 2. Zero-width space spoofing: '@company\u{200B}/secret'
    let zwsp_spoofed = "@company\u{200B}/secret";
    assert!(validate_package_name(zwsp_spoofed).is_err());
    assert_eq!(
        npmrc.registry_for_package(zwsp_spoofed).as_str(),
        "https://registry.npmjs.org/"
    );

    // 3. Fullwidth @ spoofing: '＠company/secret' (U+FF20)
    let fullwidth_at = "\u{FF20}company/secret";
    assert!(validate_package_name(fullwidth_at).is_err());
    assert_eq!(
        npmrc.registry_for_package(fullwidth_at).as_str(),
        "https://registry.npmjs.org/"
    );

    // 4. Right-to-Left (RTL) override spoofing: '@company\u{202E}evil/secret'
    let rtl_spoofed = "@company\u{202E}evil/secret";
    assert!(validate_package_name(rtl_spoofed).is_err());
    assert_eq!(
        npmrc.registry_for_package(rtl_spoofed).as_str(),
        "https://registry.npmjs.org/"
    );
}

#[test]
fn test_malicious_scopes_directory_traversal_attempts() {
    use crate::npmrc::validate_package_name;

    let malicious_names = [
        "@../pkg",
        "@../../etc/passwd",
        "@%2e%2e/pkg",
        "@scope/../../escaped",
        "@scope%2f..%2f..%2fescaped",
        "@..%2f..%2f/pkg",
        "../foo",
        "../../foo",
        "..%2f..",
        "foo/",
        "/foo",
        "@/foo",
        "@scope//pkg",
        "@scope",
        "@scope/",
        "foo/bar/baz",
        "%2e%2e",
        "foo\\bar",
        "foo\0bar",
    ];

    for name in malicious_names {
        assert!(
            validate_package_name(name).is_err(),
            "Expected '{name}' to fail validation as malicious / directory traversal"
        );
    }
}

#[test]
fn test_mixed_case_scopes_and_alternate_syntaxes() {
    let content = r#"
    registry = https://registry.npmjs.org/
    @MyOrg:registry = https://npm.myorg.internal/
    @MixedCase/registry = https://npm.mixed.internal/
    UpperOrg:registry = https://npm.upper.internal/
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    // Verify all casing variations route to the expected registry
    let variants_myorg = [
        "@myorg/pkg",
        "@MYORG/pkg",
        "@MyOrg/Pkg",
        "@mYoRg/pkg",
        "@MyOrg%2fpkg",
    ];
    for var in variants_myorg {
        assert_eq!(
            npmrc.registry_for_package(var).as_str(),
            "https://npm.myorg.internal/",
            "Variant '{var}' must route to @myorg registry"
        );
    }

    // Verify @MixedCase/registry
    assert_eq!(
        npmrc.registry_for_package("@mixedcase/lib").as_str(),
        "https://npm.mixed.internal/"
    );
    assert_eq!(
        npmrc.registry_for_package("@MIXEDCASE/lib").as_str(),
        "https://npm.mixed.internal/"
    );

    // Verify UpperOrg:registry
    assert_eq!(
        npmrc.registry_for_package("@upperorg/core").as_str(),
        "https://npm.upper.internal/"
    );
    assert_eq!(
        npmrc.registry_for_package("@UPPERORG/core").as_str(),
        "https://npm.upper.internal/"
    );

    // Metadata URL generation handles mixed-case correctly
    let meta_url = npmrc.package_metadata_url("@MyOrg/Package-A").unwrap();
    assert_eq!(
        meta_url.as_str(),
        "https://npm.myorg.internal/@MyOrg%2fPackage-A"
    );
}

#[test]
fn test_npmrc_token_expansion_npm_token_and_ci_auth_key() {
    use crate::npmrc::{is_sensitive_credential_key, mask_credential, scrub_credentials};

    let mut env_map = HashMap::new();
    env_map.insert(
        "NPM_TOKEN".to_string(),
        "npm_live_prod_secret_token_1234567890".to_string(),
    );
    env_map.insert(
        "CI_AUTH_KEY".to_string(),
        "ghp_ci_runner_key_9876543210abcdef".to_string(),
    );
    env_map.insert(
        "CUSTOM_REGISTRY_HOST".to_string(),
        "npm.internal.corp".to_string(),
    );

    let lookup = |var: &str| env_map.get(var).cloned();

    let content = r#"
    registry = https://registry.npmjs.org/
    //registry.npmjs.org/:_authToken = ${NPM_TOKEN}
    @corp:registry = https://${CUSTOM_REGISTRY_HOST}/
    //${CUSTOM_REGISTRY_HOST}/:_authToken = ${CI_AUTH_KEY}
    //fallback.internal/:_authToken = ${UNSET_SECRET:-fallback_secret_token}
    escaped_val = \${NPM_TOKEN}
    save-exact = true
    "#;

    let npmrc = Npmrc::parse_with_env(content, lookup).unwrap();

    // 1. Verify NPM_TOKEN was expanded correctly
    let npmjs_url = Url::parse("https://registry.npmjs.org/@scope/pkg").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&npmjs_url),
        Some("npm_live_prod_secret_token_1234567890")
    );

    // 2. Verify CI_AUTH_KEY and CUSTOM_REGISTRY_HOST expansion
    let corp_url = Url::parse("https://npm.internal.corp/@corp/tools").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&corp_url),
        Some("ghp_ci_runner_key_9876543210abcdef")
    );

    // 3. Verify fallback default expansion
    let fallback_url = Url::parse("https://fallback.internal/tarball.tgz").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&fallback_url),
        Some("fallback_secret_token")
    );

    // 4. Verify escaped syntax remains literal
    assert_eq!(npmrc.settings.get("escaped_val").unwrap(), "${NPM_TOKEN}");

    // 5. Verify Debug formatting DOES NOT leak credentials
    let debug_repr = format!("{:?}", npmrc);
    assert!(
        !debug_repr.contains("npm_live_prod_secret_token_1234567890"),
        "Debug formatting must NOT leak raw NPM_TOKEN: {debug_repr}"
    );
    assert!(
        !debug_repr.contains("ghp_ci_runner_key_9876543210abcdef"),
        "Debug formatting must NOT leak raw CI_AUTH_KEY: {debug_repr}"
    );
    assert!(
        debug_repr.contains("npm_***7890"),
        "Debug formatting should display masked token: {debug_repr}"
    );

    // 6. Verify scrubbed_settings and format_scrubbed
    let scrubbed_settings = npmrc.scrubbed_settings();
    assert_eq!(scrubbed_settings.get("save-exact").unwrap(), "true");

    let scrubbed_export = npmrc.format_scrubbed();
    assert!(!scrubbed_export.contains("npm_live_prod_secret_token_1234567890"));
    assert!(!scrubbed_export.contains("ghp_ci_runner_key_9876543210abcdef"));
    assert!(scrubbed_export.contains("[REDACTED]"));

    // 7. Test standalone credential scrubbing
    let raw_log = "Error 401 connecting with Bearer npm_live_prod_secret_token_1234567890 to //registry.npmjs.org/:_authToken=npm_live_prod_secret_token_1234567890";
    let cleaned = scrub_credentials(raw_log);
    assert!(!cleaned.contains("npm_live_prod_secret_token_1234567890"));
    assert!(cleaned.contains("[REDACTED]"));

    // 8. Test key sensitivity detection
    assert!(is_sensitive_credential_key(
        "//registry.npmjs.org/:_authToken"
    ));
    assert!(is_sensitive_credential_key("NPM_TOKEN"));
    assert!(is_sensitive_credential_key("CI_AUTH_KEY"));
    assert!(is_sensitive_credential_key("_authToken"));
    assert!(!is_sensitive_credential_key("registry"));
    assert!(!is_sensitive_credential_key("save-exact"));
    assert!(!is_sensitive_credential_key("author"));

    // 9. Test mask_credential
    assert_eq!(mask_credential("npm_1234567890abcdef"), "npm_***cdef");
    assert_eq!(mask_credential("ghp_1234567890abcdef"), "ghp_***cdef");
    assert_eq!(mask_credential("short"), "[REDACTED]");
    assert_eq!(mask_credential(""), "");
}

#[test]
fn test_full_npmrc_precedence_chain() {
    use crate::ConfigOptions;
    use std::collections::BTreeMap;

    let temp_root = tempdir().unwrap();
    let root_path = temp_root.path();

    let global_file = root_path.join("global.npmrc");
    fs::write(
        &global_file,
        "registry=https://global.registry.org/\nglobal_only=1\ncommon=from_global\n",
    )
    .unwrap();

    let user_file = root_path.join("user.npmrc");
    fs::write(
        &user_file,
        "registry=https://user.registry.org/\nuser_only=2\ncommon=from_user\n",
    )
    .unwrap();

    let ws_dir = root_path.join("workspace");
    let packages_dir = ws_dir.join("packages");
    let project_dir = packages_dir.join("pkg-member");
    fs::create_dir_all(&project_dir).unwrap();

    let ws_pkg_json = r#"{"name": "root-ws", "workspaces": ["packages/*"]}"#;
    fs::write(ws_dir.join("package.json"), ws_pkg_json).unwrap();
    fs::write(
        ws_dir.join(".npmrc"),
        "registry=https://ws.registry.org/\nws_only=3\ncommon=from_ws\n",
    )
    .unwrap();

    let member_pkg_json = r#"{"name": "pkg-member", "version": "1.0.0"}"#;
    fs::write(project_dir.join("package.json"), member_pkg_json).unwrap();
    fs::write(
        project_dir.join(".npmrc"),
        "registry=https://proj.registry.org/\nproj_only=4\ncommon=from_proj\n",
    )
    .unwrap();

    let mut env_map = BTreeMap::new();
    env_map.insert(
        "npm_config_registry".to_string(),
        "https://env.registry.org/".to_string(),
    );
    env_map.insert("npm_config_env_only".to_string(), "5".to_string());
    env_map.insert("npm_config_common".to_string(), "from_env".to_string());

    let mut cli_map = BTreeMap::new();
    cli_map.insert(
        "registry".to_string(),
        "https://cli.registry.org/".to_string(),
    );
    cli_map.insert("cli_only".to_string(), "6".to_string());
    cli_map.insert("common".to_string(), "from_cli".to_string());

    let opts = ConfigOptions::new()
        .globalconfig(global_file)
        .userconfig(user_file)
        .project_dir(&project_dir)
        .env_vars(env_map)
        .cli_overrides(cli_map);

    let loaded = Config::load_with_options(opts).unwrap();

    assert_eq!(loaded.npmrc.registry.as_str(), "https://cli.registry.org/");
    assert_eq!(loaded.get("common"), Some("from_cli"));
    assert_eq!(loaded.get("cli_only"), Some("6"));
    assert_eq!(loaded.get("env_only"), Some("5"));
    assert_eq!(loaded.get("proj_only"), Some("4"));
    assert_eq!(loaded.get("ws_only"), Some("3"));
    assert_eq!(loaded.get("user_only"), Some("2"));
    assert_eq!(loaded.get("global_only"), Some("1"));
}

#[test]
fn test_workspace_and_project_npmrc_precedence() {
    use crate::ConfigOptions;

    let temp_root = tempdir().unwrap();
    let root_path = temp_root.path();

    let ws_dir = root_path.join("monorepo");
    let packages_dir = ws_dir.join("packages");
    let pkg_a_dir = packages_dir.join("pkg-a");
    let pkg_b_dir = packages_dir.join("pkg-b");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::create_dir_all(&pkg_b_dir).unwrap();

    let ws_pkg_json = r#"{"name": "root-ws", "workspaces": ["packages/*"]}"#;
    fs::write(ws_dir.join("package.json"), ws_pkg_json).unwrap();
    fs::write(
        ws_dir.join(".npmrc"),
        "registry=https://ws.registry.org/\nstrict-ssl=true\nshared_flag=from_ws\n",
    )
    .unwrap();

    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0"}"#,
    )
    .unwrap();

    fs::write(
        pkg_b_dir.join("package.json"),
        r#"{"name": "pkg-b", "version": "1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        pkg_b_dir.join(".npmrc"),
        "registry=https://pkg-b.registry.org/\nshared_flag=from_pkg_b\n",
    )
    .unwrap();

    let loaded_a = Config::load_with_options(
        ConfigOptions::new()
            .project_dir(&pkg_a_dir)
            .env_vars(std::collections::BTreeMap::new()),
    )
    .unwrap();
    assert_eq!(loaded_a.npmrc.registry.as_str(), "https://ws.registry.org/");
    assert_eq!(loaded_a.get("strict-ssl"), Some("true"));
    assert_eq!(loaded_a.get("shared_flag"), Some("from_ws"));

    let loaded_b = Config::load_with_options(
        ConfigOptions::new()
            .project_dir(&pkg_b_dir)
            .env_vars(std::collections::BTreeMap::new()),
    )
    .unwrap();
    assert_eq!(
        loaded_b.npmrc.registry.as_str(),
        "https://pkg-b.registry.org/"
    );
    assert_eq!(loaded_b.get("strict-ssl"), Some("true"));
    assert_eq!(loaded_b.get("shared_flag"), Some("from_pkg_b"));
}

#[test]
fn test_env_vars_and_cli_overrides() {
    use crate::ConfigOptions;
    use std::collections::BTreeMap;

    let mut env_map = BTreeMap::new();
    env_map.insert("NPM_CONFIG_STRICT_SSL".to_string(), "false".to_string());
    env_map.insert(
        "npm_config_proxy".to_string(),
        "http://proxy.corp:8080".to_string(),
    );
    env_map.insert(
        "NPM_CONFIG_HTTPS_PROXY".to_string(),
        "https://proxy.corp:8443".to_string(),
    );
    env_map.insert("npm_config_fetch_timeout".to_string(), "45000".to_string());
    env_map.insert(
        "npm_config_cafile".to_string(),
        "/path/to/cert.pem".to_string(),
    );
    env_map.insert("npm_config__auth".to_string(), "token_123".to_string());

    let loaded_env =
        Config::load_with_options(ConfigOptions::new().env_vars(env_map.clone())).unwrap();
    assert_eq!(loaded_env.get("strict-ssl"), Some("false"));
    assert_eq!(loaded_env.get("strict_ssl"), Some("false"));
    assert_eq!(loaded_env.get_bool("strict_ssl"), Some(false));
    assert_eq!(loaded_env.get("proxy"), Some("http://proxy.corp:8080"));
    assert_eq!(
        loaded_env.get("https-proxy"),
        Some("https://proxy.corp:8443")
    );
    assert_eq!(
        loaded_env.get("https_proxy"),
        Some("https://proxy.corp:8443")
    );
    assert_eq!(loaded_env.get("fetch-timeout"), Some("45000"));
    assert_eq!(loaded_env.get("fetch_timeout"), Some("45000"));
    assert_eq!(loaded_env.get("cafile"), Some("/path/to/cert.pem"));
    assert_eq!(loaded_env.get("_auth"), Some("token_123"));

    let mut cli_map = BTreeMap::new();
    cli_map.insert("--strict-ssl".to_string(), "true".to_string());
    cli_map.insert("proxy".to_string(), "http://cli.proxy:9000".to_string());

    let loaded_cli = Config::load_with_options(
        ConfigOptions::new()
            .env_vars(env_map)
            .cli_overrides(cli_map),
    )
    .unwrap();
    assert_eq!(loaded_cli.get("strict-ssl"), Some("true"));
    assert_eq!(loaded_cli.get_bool("strict-ssl"), Some(true));
    assert_eq!(loaded_cli.get("proxy"), Some("http://cli.proxy:9000"));
    assert_eq!(
        loaded_cli.get("https-proxy"),
        Some("https://proxy.corp:8443")
    );
}

#[test]
fn test_config_file_set_and_delete() {
    use crate::{delete_config_value_from_file, set_config_value_in_file};

    let dir = tempdir().unwrap();
    let npmrc_path = dir.path().join(".npmrc");

    // Setting a new key creates file
    set_config_value_in_file(&npmrc_path, "registry", "https://custom.registry.com/").unwrap();
    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("registry=https://custom.registry.com/"));

    // Setting another key appends
    set_config_value_in_file(&npmrc_path, "save-exact", "true").unwrap();
    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("save-exact=true"));

    // Updating existing key replaces in place
    set_config_value_in_file(&npmrc_path, "registry", "https://updated.registry.com/").unwrap();
    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(content.contains("registry=https://updated.registry.com/"));
    assert!(!content.contains("https://custom.registry.com/"));

    // Deleting a key removes it
    let deleted = delete_config_value_from_file(&npmrc_path, "save-exact").unwrap();
    assert!(deleted);
    let content = fs::read_to_string(&npmrc_path).unwrap();
    assert!(!content.contains("save-exact"));
    assert!(content.contains("registry=https://updated.registry.com/"));

    // Deleting nonexistent key returns false
    let not_deleted = delete_config_value_from_file(&npmrc_path, "nonexistent").unwrap();
    assert!(!not_deleted);
}

#[test]
fn test_config_detailed_and_paths() {
    use crate::{
        find_global_bin_dir, find_global_node_modules, find_global_prefix_with_env,
        find_local_bin_dir, find_local_node_modules, find_local_prefix, Config, ConfigOptions,
    };
    use std::path::PathBuf;

    let dir = tempdir().unwrap();
    let proj_dir = dir.path().join("my-app");
    fs::create_dir_all(&proj_dir).unwrap();
    fs::write(proj_dir.join("package.json"), r#"{"name": "my-app"}"#).unwrap();

    // Local path resolution
    let local_pref = find_local_prefix(&proj_dir);
    assert_eq!(local_pref, proj_dir);
    let local_nm = find_local_node_modules(&proj_dir);
    assert_eq!(local_nm, proj_dir.join("node_modules"));
    let local_bin = find_local_bin_dir(&proj_dir);
    assert_eq!(local_bin, proj_dir.join("node_modules").join(".bin"));

    // Global path resolution with env mock
    let mock_prefix = PathBuf::from(r"D:\custom-npm-prefix");
    let global_pref = find_global_prefix_with_env(|var| {
        if var == "PREFIX" {
            Some(mock_prefix.to_string_lossy().to_string())
        } else {
            None
        }
    });
    assert_eq!(global_pref, mock_prefix);

    let global_bin = find_global_bin_dir(&mock_prefix);
    #[cfg(windows)]
    assert_eq!(global_bin, mock_prefix);
    #[cfg(not(windows))]
    assert_eq!(global_bin, mock_prefix.join("bin"));

    let global_nm = find_global_node_modules(&mock_prefix);
    #[cfg(windows)]
    assert_eq!(global_nm, mock_prefix.join("node_modules"));
    #[cfg(not(windows))]
    assert_eq!(global_nm, mock_prefix.join("lib").join("node_modules"));

    // Detailed config report
    fs::write(proj_dir.join(".npmrc"), "my-key = my-val\n").unwrap();
    let opts = ConfigOptions::new().project_dir(&proj_dir);
    let detailed = Config::load_detailed(opts).unwrap();
    assert_eq!(detailed.effective.get("my-key").unwrap(), "my-val");
    let formatted = detailed.format_text();
    assert!(formatted.contains("my-key = \"my-val\""));
    assert!(formatted.contains("npm local prefix ="));
}

#[test]
fn test_fix_npmrc_content_repairs_keys() {
    use crate::fix_npmrc_content;

    let input = r#"
# Comments should be preserved
; Semicolon comments too
_authtoken = should-be-deleted
-authtoken = also-deleted
_authToken = my-secret-token
_auth = basic-auth-string
email = user@example.com
username = user1
_password = pass1
global-style = true
legacy-bundling = true
only = prod
production = true
shrinkwrap = false
also = dev
dev = true
optional = false
init.author.name = Author Name
init.author.email = author@example.com
init.license = MIT
//registry.npmjs.org/:_authToken = already-scoped
valid-custom-key = preserved
"#;

    let (fixed, summaries) = fix_npmrc_content(input, "project", "//registry.npmjs.org/");

    assert!(fixed.contains("# Comments should be preserved"));
    assert!(fixed.contains("; Semicolon comments too"));
    assert!(!fixed.contains("_authtoken ="));
    assert!(!fixed.contains("-authtoken ="));
    assert!(fixed.contains("//registry.npmjs.org/:_authToken=my-secret-token"));
    assert!(fixed.contains("//registry.npmjs.org/:_auth=basic-auth-string"));
    assert!(fixed.contains("//registry.npmjs.org/:email=user@example.com"));
    assert!(fixed.contains("//registry.npmjs.org/:username=user1"));
    assert!(fixed.contains("//registry.npmjs.org/:_password=pass1"));
    assert!(fixed.contains("install-strategy=shallow"));
    assert!(fixed.contains("install-strategy=nested"));
    assert!(fixed.contains("omit=dev"));
    assert!(fixed.contains("package-lock=false"));
    assert!(fixed.contains("include=dev"));
    assert!(fixed.contains("omit=optional"));
    assert!(fixed.contains("init-author-name=Author Name"));
    assert!(fixed.contains("init-author-email=author@example.com"));
    assert!(fixed.contains("init-license=MIT"));
    assert!(fixed.contains("//registry.npmjs.org/:_authToken = already-scoped"));
    assert!(fixed.contains("valid-custom-key = preserved"));

    assert!(!summaries.is_empty());
}

#[test]
fn test_fix_npmrc_content_deletes_lonely_username_or_password() {
    use crate::fix_npmrc_content;

    let input = "username = lonely_user\n";
    let (fixed, summaries) = fix_npmrc_content(input, "project", "//registry.npmjs.org/");
    assert!(!fixed.contains("username"));
    assert!(summaries.iter().any(|s| s.contains("deleted")));

    let input_pw = "_password = lonely_pw\n";
    let (fixed_pw, summaries_pw) = fix_npmrc_content(input_pw, "project", "//registry.npmjs.org/");
    assert!(!fixed_pw.contains("_password"));
    assert!(summaries_pw.iter().any(|s| s.contains("deleted")));
}

#[test]
fn test_min_release_age_parsing() {
    let now_ms = 1_700_000_000_000_i64;

    // 7 days = 7 * 86,400,000 = 604,800,000 ms
    let mut config = Config::new();
    config.npmrc.set("min-release-age", "7").unwrap();
    assert_eq!(
        config.min_release_age_cutoff_at(now_ms),
        Some(now_ms - 604_800_000)
    );
    assert_eq!(
        config.before_cutoff_at(now_ms),
        Some(now_ms - 604_800_000)
    );

    // Float days: 0.5 days = 43,200,000 ms
    let mut config_float = Config::new();
    config_float.npmrc.set("min-release-age", "0.5").unwrap();
    assert_eq!(
        config_float.min_release_age_cutoff_at(now_ms),
        Some(now_ms - 43_200_000)
    );

    // 0 days disables cutoff (matching npm 11.20.0 `age ? new Date(...) : null`)
    let mut config_zero = Config::new();
    config_zero.npmrc.set("min-release-age", "0").unwrap();
    assert_eq!(config_zero.min_release_age_cutoff_at(now_ms), None);
    assert_eq!(config_zero.before_cutoff_at(now_ms), None);

    // Negative days disables cutoff
    let mut config_neg = Config::new();
    config_neg.npmrc.set("min-release-age", "-5").unwrap();
    assert_eq!(config_neg.min_release_age_cutoff_at(now_ms), None);

    // "null" string disables cutoff
    let mut config_null = Config::new();
    config_null.npmrc.set("min-release-age", "null").unwrap();
    assert_eq!(config_null.min_release_age_cutoff_at(now_ms), None);

    // Underscore alias min_release_age
    let mut config_under = Config::new();
    config_under.npmrc.set("min_release_age", "14").unwrap();
    assert_eq!(
        config_under.min_release_age_cutoff_at(now_ms),
        Some(now_ms - 14 * 86_400_000)
    );
}

#[test]
fn test_before_vs_min_release_age_precedence() {
    let now_ms = 1_700_000_000_000_i64;

    // When both before and min-release-age are present, before wins
    let mut config = Config::new();
    config.npmrc.set("min-release-age", "7").unwrap();
    config.npmrc.set("before", "2023-01-01T00:00:00.000Z").unwrap();
    let expected_before = crate::date::parse_js_date("2023-01-01T00:00:00.000Z").unwrap();
    assert_eq!(config.before_cutoff_at(now_ms), Some(expected_before));

    // When before is explicitly "null", it wins over min-release-age and disables cutoff
    let mut config_null_before = Config::new();
    config_null_before.npmrc.set("min-release-age", "7").unwrap();
    config_null_before.npmrc.set("before", "null").unwrap();
    assert_eq!(config_null_before.before_cutoff_at(now_ms), None);
}

#[test]
fn test_min_release_age_exclude_parsing() {
    // Array syntax in .npmrc: min-release-age-exclude[]
    let npmrc_content = r#"
min-release-age-exclude[] = @myorg/*
min-release-age-exclude[] = my-internal-pkg
min-release-age-exclude[] = @myorg/*
"#;
    let npmrc = Npmrc::parse(npmrc_content).unwrap();
    let config = Config {
        npmrc,
        ..Default::default()
    };
    let excludes = config.min_release_age_exclude();
    assert_eq!(excludes, vec!["@myorg/*", "my-internal-pkg"]);

    // Comma-separated list syntax
    let npmrc_comma = r#"
min-release-age-exclude = @myorg/*, my-internal-pkg,  foo-lib , , @myorg/*
"#;
    let npmrc2 = Npmrc::parse(npmrc_comma).unwrap();
    let config2 = Config {
        npmrc: npmrc2,
        ..Default::default()
    };
    let excludes2 = config2.min_release_age_exclude();
    assert_eq!(excludes2, vec!["@myorg/*", "my-internal-pkg", "foo-lib"]);
}

#[test]
fn test_min_release_age_exclude_matching_with_config() {
    let npmrc_content = r#"
min-release-age = 7
min-release-age-exclude[] = @myorg/*
min-release-age-exclude[] = trusted-internal
"#;
    let config = Config {
        npmrc: Npmrc::parse(npmrc_content).unwrap(),
        ..Default::default()
    };
    let excludes = config.min_release_age_exclude();

    assert!(crate::is_release_age_excluded("@myorg/utils", &excludes));
    assert!(crate::is_release_age_excluded("@myorg/core", &excludes));
    assert!(crate::is_release_age_excluded("trusted-internal", &excludes));
    assert!(!crate::is_release_age_excluded("lodash", &excludes));
    assert!(!crate::is_release_age_excluded("@other/utils", &excludes));
}

#[test]
fn test_layer_aware_before_vs_min_release_age_precedence() {
    let now_ms = 1_700_000_000_000_i64;
    let expected_date_ms = crate::date::parse_js_date("2023-01-01T00:00:00.000Z").unwrap();
    let expected_age_ms = now_ms - (7 * 86_400_000);

    let temp = tempfile::tempdir().unwrap();
    let user_npmrc = temp.path().join("user.npmrc");
    let proj_dir = temp.path().join("project");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let proj_npmrc = proj_dir.join(".npmrc");

    // (a) CLI `--min-release-age` beats user `.npmrc` `before`
    std::fs::write(&user_npmrc, "before = 2023-01-01T00:00:00.000Z\n").unwrap();
    let config_a = Config::load_with_options(
        ConfigOptions::new()
            .userconfig(user_npmrc.clone())
            .with_cli("min-release-age", "7"),
    )
    .unwrap();
    assert_eq!(
        config_a.before_cutoff_at(now_ms),
        Some(expected_age_ms),
        "CLI min-release-age must beat user .npmrc before"
    );

    // (b) project `.npmrc` `min-release-age` beats user `.npmrc` `before`
    std::fs::write(&user_npmrc, "before = 2023-01-01T00:00:00.000Z\n").unwrap();
    std::fs::write(&proj_npmrc, "min-release-age = 7\n").unwrap();
    let config_b = Config::load_with_options(
        ConfigOptions::new()
            .userconfig(user_npmrc.clone())
            .project_dir(&proj_dir),
    )
    .unwrap();
    assert_eq!(
        config_b.before_cutoff_at(now_ms),
        Some(expected_age_ms),
        "Project .npmrc min-release-age must beat user .npmrc before"
    );

    // (c) CLI `--before` beats CLI `--min-release-age`
    let config_c = Config::load_with_options(
        ConfigOptions::new()
            .with_cli("before", "2023-01-01T00:00:00.000Z")
            .with_cli("min-release-age", "7"),
    )
    .unwrap();
    assert_eq!(
        config_c.before_cutoff_at(now_ms),
        Some(expected_date_ms),
        "CLI --before must beat CLI --min-release-age (tie-breaker in same layer)"
    );

    // (d) user `.npmrc` `before` beats user `.npmrc` `min-release-age`
    std::fs::write(
        &user_npmrc,
        "before = 2023-01-01T00:00:00.000Z\nmin-release-age = 7\n",
    )
    .unwrap();
    let config_d =
        Config::load_with_options(ConfigOptions::new().userconfig(user_npmrc.clone())).unwrap();
    assert_eq!(
        config_d.before_cutoff_at(now_ms),
        Some(expected_date_ms),
        "User .npmrc before must beat user .npmrc min-release-age (tie-breaker in same layer)"
    );
}

#[test]
fn test_nested_env_interpolation_edge_cases() {
    let mut env_map = HashMap::new();
    env_map.insert("BAR".to_string(), "bar_val".to_string());
    env_map.insert("INNER".to_string(), "inner_val".to_string());
    env_map.insert("PRIMARY".to_string(), "primary_val".to_string());
    let lookup = |var: &str| env_map.get(var).cloned();

    // Nested braces fallback: FOO is unset, BAR is set
    assert_eq!(
        interpolate_env("val=${FOO:-${BAR}}", &lookup),
        "val=bar_val"
    );

    // Deeply nested fallback: A and B are unset, fallback is literal
    assert_eq!(
        interpolate_env("val=${A:-${B:-fallback_val}}", &lookup),
        "val=fallback_val"
    );

    // Nested variable inside default prefix/suffix
    assert_eq!(
        interpolate_env("val=${UNSET:-prefix_${INNER}_suffix}", &lookup),
        "val=prefix_inner_val_suffix"
    );

    // Unclosed brace should be left untouched
    assert_eq!(
        interpolate_env("val=${UNCLOSED", &lookup),
        "val=${UNCLOSED"
    );

    // Primary variable is set: default is ignored
    assert_eq!(
        interpolate_env("val=${PRIMARY:-${IGNORED:-fallback}}", &lookup),
        "val=primary_val"
    );
}

#[test]
fn test_scoped_registry_auth_token_subpath_matching() {
    let content = r#"
    //registry.corp.com/api/npm/:_authToken = token_subpath
    //registry.corp.com/:_authToken = token_root
    _authToken = token_global
    "#;
    let npmrc = Npmrc::parse(content).unwrap();

    // 1. Matches subpath token because URL has /api/npm/virtual/
    let subpath_url = Url::parse("https://registry.corp.com/api/npm/virtual/@scope/pkg").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&subpath_url),
        Some("token_subpath")
    );

    // 2. Matches root token because URL path is /other/path
    let root_url = Url::parse("https://registry.corp.com/other/path/@scope/pkg").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&root_url),
        Some("token_root")
    );

    // 3. Different host falls back to global token
    let other_host_url = Url::parse("https://other.domain.com/pkg").unwrap();
    assert_eq!(
        npmrc.get_auth_token(&other_host_url),
        Some("token_global")
    );
}

#[test]
fn test_scoped_registry_basic_auth_resolution() {
    let content = r#"
    //registry.corp.com/private/:_auth = cHJpdmF0ZV91c2VyOnBhc3M=
    //other.org/:username = myuser
    //other.org/:_password = mypass
    _auth = Z2xvYmFsOnBhc3M=
    "#;
    let npmrc = Npmrc::parse(content).unwrap();

    // 1. Scoped _auth on subpath
    let priv_url = Url::parse("https://registry.corp.com/private/sub/pkg").unwrap();
    assert_eq!(
        npmrc.get_basic_auth(&priv_url),
        Some("cHJpdmF0ZV91c2VyOnBhc3M=".to_string())
    );

    // 2. Scoped username + password
    let other_url = Url::parse("https://other.org/pkg").unwrap();
    let expected_b64 = data_encoding::BASE64.encode(b"myuser:mypass");
    assert_eq!(
        npmrc.get_basic_auth(&other_url),
        Some(expected_b64)
    );

    // 3. Fallback to global _auth
    let unauth_url = Url::parse("https://unknown.net/pkg").unwrap();
    assert_eq!(
        npmrc.get_basic_auth(&unauth_url),
        Some("Z2xvYmFsOnBhc3M=".to_string())
    );
}

#[test]
fn test_no_proxy_matcher_extreme_cases() {
    use crate::npmrc::NoProxyMatcher;

    // Wildcard matches everything
    let star_matcher = NoProxyMatcher::parse("*");
    assert!(star_matcher.matches("example.com", Some(80)));
    assert!(star_matcher.matches("192.168.1.1", Some(443)));
    assert!(star_matcher.matches("fe80::1", Some(8080)));
    assert!(star_matcher.matches("anything", None));

    // IPv4 CIDR, IPv6 CIDR, domains, port-specific
    let rules = "10.0.0.0/8, 192.168.1.0/24, fd00::/8, 127.0.0.1, .internal.net, corp.com:8443";
    let matcher = NoProxyMatcher::parse(rules);

    // IPv4 CIDR matching
    assert!(matcher.matches("10.254.1.2", Some(80)));
    assert!(matcher.matches("192.168.1.55", Some(443)));
    assert!(!matcher.matches("192.168.2.1", Some(80)));
    assert!(!matcher.matches("172.16.0.1", Some(80)));

    // IPv6 CIDR matching
    assert!(matcher.matches("fd00::1", Some(80)));
    assert!(matcher.matches("fd12:3456:789a::1", Some(443)));
    assert!(!matcher.matches("fe80::1", Some(80)));

    // Exact IP matching
    assert!(matcher.matches("127.0.0.1", Some(80)));
    assert!(matcher.matches("127.0.0.1", Some(9999)));
    assert!(!matcher.matches("127.0.0.2", Some(80)));

    // Domain matching (.internal.net matches any subdomain or exact)
    assert!(matcher.matches("api.internal.net", Some(443)));
    assert!(matcher.matches("sub.dev.internal.net", Some(80)));
    assert!(matcher.matches("internal.net", Some(80)));
    assert!(!matcher.matches("external.net", Some(80)));

    // Port-specific host matching
    assert!(matcher.matches("corp.com", Some(8443)));
    assert!(!matcher.matches("corp.com", Some(80)));
    assert!(!matcher.matches("corp.com", Some(443)));
    assert!(!matcher.matches("corp.com", None));
}

#[test]
fn test_config_proxy_and_no_proxy_helpers() {
    let mut opts = ConfigOptions::new();
    opts = opts.with_cli("https-proxy", "http://corporate-proxy:8080");
    opts = opts.with_cli("no-proxy", "localhost,127.0.0.1,10.0.0.0/8,*.corp.internal");
    let cfg = Config::load_with_options(opts).unwrap();

    assert_eq!(cfg.https_proxy(), Some("http://corporate-proxy:8080"));

    let local_url = Url::parse("https://localhost:3000/pkg").unwrap();
    assert!(cfg.should_bypass_proxy(&local_url));

    let corp_url = Url::parse("https://registry.corp.internal/pkg").unwrap();
    assert!(cfg.should_bypass_proxy(&corp_url));

    let private_ip_url = Url::parse("https://10.5.20.1/pkg").unwrap();
    assert!(cfg.should_bypass_proxy(&private_ip_url));

    let external_url = Url::parse("https://registry.npmjs.org/pkg").unwrap();
    assert!(!cfg.should_bypass_proxy(&external_url));
}

#[test]
fn test_credential_scrubbing_edge_cases() {
    use crate::npmrc::scrub_credentials;

    let raw = r#"
    //registry.npmjs.org/:_authToken=npm_secret_12345
    _auth = dXNlcjpwYXNzd29yZA==
    password: my_super_secret_password
    proxy = http://proxyuser:proxypass@proxy.corp.com:8080
    normal_key = normal_value
    "#;

    let scrubbed = scrub_credentials(raw);
    assert!(!scrubbed.contains("npm_secret_12345"));
    assert!(!scrubbed.contains("dXNlcjpwYXNzd29yZA=="));
    assert!(!scrubbed.contains("my_super_secret_password"));
    assert!(!scrubbed.contains("proxyuser:proxypass"));
    assert!(scrubbed.contains("normal_key = normal_value"));
}

#[test]
fn test_malformed_npmrc_lines_and_null_bytes() {
    // Missing key
    assert!(Npmrc::parse("=some_value").is_err());

    // Null byte in content
    assert!(Npmrc::parse("key=val\0ue").is_err());
}

#[test]
fn test_url_credentials_linear_order_scrubbing() {
    use crate::npmrc::scrub_credentials;

    // Both orders: https followed by http, and http followed by https
    let text1 = "https://user1:pass1@secure.example.com/api and http://user2:pass2@plain.example.com/api";
    let scrubbed1 = scrub_credentials(text1);
    assert!(!scrubbed1.contains("pass1"), "pass1 must be scrubbed");
    assert!(!scrubbed1.contains("pass2"), "pass2 must be scrubbed");
    assert!(scrubbed1.contains("https://user1:[REDACTED]@secure.example.com/api"));
    assert!(scrubbed1.contains("http://user2:[REDACTED]@plain.example.com/api"));

    let text2 = "http://userA:passA@plain.example.com/api and https://userB:passB@secure.example.com/api";
    let scrubbed2 = scrub_credentials(text2);
    assert!(!scrubbed2.contains("passA"), "passA must be scrubbed");
    assert!(!scrubbed2.contains("passB"), "passB must be scrubbed");
    assert!(scrubbed2.contains("http://userA:[REDACTED]@plain.example.com/api"));
    assert!(scrubbed2.contains("https://userB:[REDACTED]@secure.example.com/api"));
}

#[test]
fn test_quoted_kv_scrubbing() {
    use crate::npmrc::scrub_credentials;

    // Double quoted value
    let raw_double = "password=\"secret_pass_123\" and foo=\"bar\"";
    let scrubbed_double = scrub_credentials(raw_double);
    assert!(!scrubbed_double.contains("secret_pass_123"), "Secret password inside double quotes must not leak: {scrubbed_double}");
    assert!(scrubbed_double.contains("password=\"[REDACTED]\""));
    assert!(scrubbed_double.contains("foo=\"bar\""));

    // Single quoted value
    let raw_single = "password='secret_pass_456' and key=value";
    let scrubbed_single = scrub_credentials(raw_single);
    assert!(!scrubbed_single.contains("secret_pass_456"), "Secret password inside single quotes must not leak: {scrubbed_single}");
    assert!(scrubbed_single.contains("password='[REDACTED]'"));
    assert!(scrubbed_single.contains("key=value"));

    // Colon separator with quotes
    let raw_colon = "_auth: \"secret_token_abc\"";
    let scrubbed_colon = scrub_credentials(raw_colon);
    assert!(!scrubbed_colon.contains("secret_token_abc"));
    assert!(scrubbed_colon.contains("_auth: \"[REDACTED]\""));
}

#[test]
fn test_mask_credential_utf8_multibyte() {
    use crate::npmrc::mask_credential;

    // Standard ASCII
    assert_eq!(mask_credential("npm_1234567890abcdef"), "npm_***cdef");
    assert_eq!(mask_credential("ghp_1234567890"), "ghp_***7890");
    assert_eq!(mask_credential("short"), "[REDACTED]");
    assert_eq!(mask_credential(""), "");

    // Multi-byte UTF-8 characters: must not panic on char boundary slicing
    let multi_byte1 = "secret_🔑";
    let masked1 = mask_credential(multi_byte1);
    assert!(masked1.contains("🔑"), "Masked multi-byte string must preserve trailing char: {masked1}");

    let multi_byte2 = "ghp_1234你好";
    let masked2 = mask_credential(multi_byte2);
    assert!(masked2.starts_with("ghp_***"));
    assert!(masked2.ends_with("34你好"));
}

#[test]
fn test_bracketed_ipv6_no_proxy() {
    use crate::npmrc::NoProxyMatcher;

    // Matcher with bracketed and CIDR IPv6 rules
    let matcher = NoProxyMatcher::parse("[::1], [::1]:8080, ::1/128, fd00::/8");

    // Match against bracketed URL host
    let url_bracketed = Url::parse("http://[::1]:8080/path").unwrap();
    assert!(matcher.matches_url(&url_bracketed));

    // Match against bracketed host string directly
    assert!(matcher.matches("[::1]", Some(8080)));
    assert!(matcher.matches("::1", Some(8080)));
    assert!(matcher.matches("[::1]", Some(9000))); // matched by ::1/128 or [::1]

    // Config helper should_bypass_proxy with bracketed IPv6
    let cfg = Config::default();
    let local_v6 = Url::parse("http://[::1]:3000/").unwrap();
    assert!(cfg.should_bypass_proxy(&local_v6), "http://[::1]:3000/ must bypass proxy");
}

#[test]
fn test_npmrc_quoting_comments_escaping_bare_keys() {
    let content = r#"
        # Global settings
        registry = "https://registry.npmjs.org/" ; inline comment
        save-exact = true # another comment
        bare-flag
        empty-val =
        escaped-semicolon = foo\;bar\#baz
        single-quoted = 'single value'
        [dummy-section]
        inside-section = "section_val"
    "#;

    let parsed = Npmrc::parse(content).unwrap();
    assert_eq!(parsed.registry.as_str(), "https://registry.npmjs.org/");
    assert_eq!(parsed.settings.get("save-exact").map(|s| s.as_str()), Some("true"));
    assert_eq!(parsed.settings.get("bare-flag").map(|s| s.as_str()), Some("true"));
    assert_eq!(parsed.settings.get("empty-val").map(|s| s.as_str()), Some(""));
    assert_eq!(parsed.settings.get("escaped-semicolon").map(|s| s.as_str()), Some("foo;bar#baz"));
    assert_eq!(parsed.settings.get("single-quoted").map(|s| s.as_str()), Some("single value"));
    assert_eq!(parsed.settings.get("inside-section").map(|s| s.as_str()), Some("section_val"));
}

#[test]
fn test_npmrc_uri_scoped_longest_prefix_and_auth_tokens() {
    let content = r#"
        //registry.npmjs.org/:_authToken=secret_npm_token
        //custom.registry.com/path:_authToken=secret_custom_token
        //custom.registry.com/path:certfile=/certs/client.crt
        //custom.registry.com/path:keyfile=/certs/client.key
        //custom.registry.com/:cafile=/certs/ca.pem
        //custom.registry.com/:proxy=http://proxy.corp:8080
    "#;

    let parsed = Npmrc::parse(content).unwrap();
    let npmjs_url = Url::parse("https://registry.npmjs.org/package").unwrap();
    assert_eq!(parsed.get_auth_token(&npmjs_url), Some("secret_npm_token"));

    let custom_url = Url::parse("https://custom.registry.com/path/deep/package").unwrap();
    assert_eq!(parsed.get_auth_token(&custom_url), Some("secret_custom_token"));
    assert_eq!(parsed.get_cert(&custom_url), Some("/certs/client.crt"));
    assert_eq!(parsed.get_key(&custom_url), Some("/certs/client.key"));
    assert_eq!(parsed.get_ca(&custom_url), Some("/certs/ca.pem"));
    assert_eq!(parsed.get_proxy_for_registry(&custom_url), Some("http://proxy.corp:8080"));
}

#[test]
fn test_auth_type_not_redacted() {
    use crate::npmrc::is_sensitive_credential_key;

    assert!(!is_sensitive_credential_key("auth-type"));
    assert!(!is_sensitive_credential_key("auth_type"));
    assert!(!is_sensitive_credential_key("author"));
    assert!(is_sensitive_credential_key("_authToken"));
    assert!(is_sensitive_credential_key("_auth"));
    assert!(is_sensitive_credential_key("//registry.npmjs.org/:_authToken"));

    let mut npmrc = Npmrc::default();
    npmrc.set("auth-type", "web").unwrap();
    let scrubbed = npmrc.format_scrubbed();
    assert!(scrubbed.contains("auth-type=web"), "auth-type must not be redacted");
}

#[test]
fn test_interpolate_env_optional_and_fallbacks() {
    let lookup = |name: &str| match name {
        "DEFINED" => Some("foo".to_string()),
        "EMPTY" => Some("".to_string()),
        _ => None,
    };

    assert_eq!(interpolate_env("val=${DEFINED}", &lookup), "val=foo");
    assert_eq!(interpolate_env("val=${UNDEFINED}", &lookup), "val=");
    assert_eq!(interpolate_env("val=${UNDEFINED?}", &lookup), "val=");
    assert_eq!(interpolate_env("val=${DEFINED?}", &lookup), "val=foo");
    assert_eq!(interpolate_env("val=${UNDEFINED:-fallback}", &lookup), "val=fallback");
    assert_eq!(interpolate_env("val=${EMPTY:-fallback}", &lookup), "val=fallback");
    assert_eq!(interpolate_env("val=${EMPTY-fallback}", &lookup), "val=");
}

#[test]
fn test_config_builtin_layer_and_precedence() {
    let temp_dir = tempfile::tempdir().unwrap();
    let builtin_rc = temp_dir.path().join("builtin.npmrc");
    let global_rc = temp_dir.path().join("global.npmrc");

    std::fs::write(&builtin_rc, "registry=https://builtin.registry.org/\nsave-exact=false\n").unwrap();
    std::fs::write(&global_rc, "save-exact=true\n").unwrap();

    let opts = ConfigOptions::new()
        .builtin_config(builtin_rc)
        .globalconfig(global_rc)
        .userconfig(std::path::PathBuf::from("false"))
        .env_vars(std::collections::BTreeMap::new());

    let cfg = Config::load_with_options(opts).unwrap();
    assert_eq!(cfg.get("registry"), Some("https://builtin.registry.org/"));
    assert_eq!(cfg.get("save-exact"), Some("true"));
    assert_eq!(cfg.layers.len(), 2);
    assert_eq!(cfg.layers[0].name, "builtin");
    assert_eq!(cfg.layers[1].name, "global");
}

#[test]
fn test_config_nerf_darted_env_vars() {
    let mut env_map = std::collections::BTreeMap::new();
    env_map.insert(
        "npm_config_//registry.npmjs.org/:_authToken".to_string(),
        "env_token_secret".to_string(),
    );
    env_map.insert("npm_config_save_exact".to_string(), "true".to_string());

    let opts = ConfigOptions::new().env_vars(env_map);
    let cfg = Config::load_with_options(opts).unwrap();

    let url = Url::parse("https://registry.npmjs.org/").unwrap();
    assert_eq!(cfg.npmrc.get_auth_token(&url), Some("env_token_secret"));
    assert_eq!(cfg.get("save-exact"), Some("true"));
}

#[test]
fn test_config_standard_proxy_env_fallbacks() {
    let mut env_map = std::collections::BTreeMap::new();
    env_map.insert("HTTPS_PROXY".to_string(), "http://env-proxy:8080".to_string());
    env_map.insert("NO_PROXY".to_string(), "localhost,127.0.0.1".to_string());

    let opts = ConfigOptions::new().env_vars(env_map);
    let cfg = Config::load_with_options(opts).unwrap();

    assert_eq!(cfg.https_proxy(), Some("http://env-proxy:8080"));
    assert_eq!(cfg.no_proxy(), Some("localhost,127.0.0.1"));
}

#[test]
fn test_config_unicode_env_vars_crossing_byte_boundary() {
    let mut env_map = std::collections::BTreeMap::new();
    // Character crossing byte 11:
    // "npm_con" (7 bytes) + 🦀 (4 bytes: 7..11) -> boundary falls inside 🦀
    env_map.insert("npm_con\u{1f980}".to_string(), "crab_val".to_string());
    // "npm_conf" (8 bytes) + é (2 bytes: 8..10) + "_abc" -> boundary at 11 is valid
    env_map.insert("npm_conf\u{00e9}_abc".to_string(), "accent_val".to_string());
    // Valid npm_config_ prefix with unicode key afterwards
    env_map.insert("npm_config_\u{1f980}".to_string(), "unicode_setting".to_string());
    env_map.insert("npm_config_test_\u{1f980}_end".to_string(), "unicode_mid".to_string());

    let opts = ConfigOptions::new().env_vars(env_map);
    let cfg = Config::load_with_options(opts).expect("Unicode env vars must not panic during config loading");

    assert_eq!(cfg.get("\u{1f980}"), Some("unicode_setting"));
    assert_eq!(cfg.get("test-\u{1f980}-end"), Some("unicode_mid"));
}

#[test]
fn test_config_proxy_precedence_and_http_proxy_isolation() {
    // 1. .npmrc `proxy` takes precedence over ambient HTTPS_PROXY
    let temp = tempfile::tempdir().unwrap();
    let npmrc_path = temp.path().join(".npmrc");
    std::fs::write(&npmrc_path, "proxy = http://npmrc-proxy:8080\n").unwrap();

    let mut env_map = std::collections::BTreeMap::new();
    env_map.insert("HTTPS_PROXY".to_string(), "http://ambient-https:8443".to_string());
    env_map.insert("HTTP_PROXY".to_string(), "http://ambient-http:8080".to_string());

    let opts = ConfigOptions::new()
        .userconfig(npmrc_path)
        .env_vars(env_map);
    let cfg = Config::load_with_options(opts).unwrap();

    assert_eq!(cfg.proxy(), Some("http://npmrc-proxy:8080"));
    // Explicit .npmrc proxy prevents ambient HTTPS_PROXY from setting https-proxy
    assert_eq!(cfg.https_proxy(), None);

    let https_registry = Url::parse("https://registry.npmjs.org/").unwrap();
    assert_eq!(
        cfg.npmrc.get_proxy_for_registry(&https_registry),
        Some("http://npmrc-proxy:8080")
    );

    // 2. HTTP_PROXY sets `http-proxy` only and does NOT populate HTTPS proxy
    let mut env_map_http = std::collections::BTreeMap::new();
    env_map_http.insert("HTTP_PROXY".to_string(), "http://ambient-http-only:8080".to_string());

    let opts_http = ConfigOptions::new()
        .userconfig(std::path::PathBuf::from("false"))
        .env_vars(env_map_http);
    let cfg_http = Config::load_with_options(opts_http).unwrap();

    assert_eq!(cfg_http.http_proxy(), Some("http://ambient-http-only:8080"));
    assert_eq!(cfg_http.proxy(), None);
    assert_eq!(cfg_http.https_proxy(), None);

    // HTTPS requests must NOT be proxied by HTTP_PROXY
    assert_eq!(cfg_http.npmrc.get_proxy_for_registry(&https_registry), None);

    // HTTP requests DO use http-proxy
    let http_registry = Url::parse("http://registry.internal.org/").unwrap();
    assert_eq!(
        cfg_http.npmrc.get_proxy_for_registry(&http_registry),
        Some("http://ambient-http-only:8080")
    );
}

#[test]
fn test_config_set_roundtrip_special_characters_and_deletion() {
    use crate::set_config_value_in_file;

    let temp = tempfile::tempdir().unwrap();
    let npmrc_path = temp.path().join(".npmrc");

    let test_cases = [
        ("key_hash", "foo#bar"),
        ("key_semi", "foo;bar"),
        ("key_backslash", "foo\\bar\\baz"),
        ("key_quote", "foo\"bar\"baz"),
        ("key_single", "it's a 'quoted' value"),
        ("key_equals", "foo=bar=baz"),
        ("key_url", "https://github.com/org/repo#v1.2.3"),
        ("key_spaces", "   leading and trailing spaces   "),
    ];

    for (k, v) in &test_cases {
        set_config_value_in_file(&npmrc_path, k, v).unwrap();
    }

    // Reload with Npmrc::from_file
    let loaded_npmrc = Npmrc::from_file(&npmrc_path).unwrap();
    for (k, v) in &test_cases {
        assert_eq!(
            loaded_npmrc.settings.get(*k).map(|s| s.as_str()),
            Some(*v),
            "Failed round-trip for key: {k}"
        );
    }

    // Reload through Config::load_with_options
    let opts = ConfigOptions::new()
        .userconfig(npmrc_path.clone())
        .env_vars(std::collections::BTreeMap::new());
    let cfg = Config::load_with_options(opts).unwrap();
    for (k, v) in &test_cases {
        assert_eq!(cfg.get(k), Some(*v), "Failed Config::get for key: {k}");
    }

    // Empty value deletes key matching npm 11.20.0 behavior
    set_config_value_in_file(&npmrc_path, "key_spaces", "").unwrap();
    let reloaded = Npmrc::from_file(&npmrc_path).unwrap();
    assert_eq!(reloaded.settings.get("key_spaces"), None);
    // Other keys remain intact
    assert_eq!(
        reloaded.settings.get("key_url").map(|s| s.as_str()),
        Some("https://github.com/org/repo#v1.2.3")
    );
}

#[test]
fn test_npmrc_scoped_tls_entries_and_longest_prefix_precedence() {
    let content = r#"
    //registry.example.com/:certfile = /path/to/root.crt
    //registry.example.com/:keyfile = /path/to/root.key
    //registry.example.com/scoped/:cert = scoped_inline_cert
    //registry.example.com/scoped/:key = scoped_inline_key
    "#;

    let npmrc = Npmrc::parse(content).unwrap();

    // 1. scoped_tls_entries extraction
    let entries = npmrc.scoped_tls_entries();
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].prefix, "//registry.example.com/");
    assert_eq!(entries[0].certfile.as_deref(), Some("/path/to/root.crt"));
    assert_eq!(entries[0].keyfile.as_deref(), Some("/path/to/root.key"));
    assert_eq!(entries[0].cert, None);
    assert_eq!(entries[0].key, None);

    assert_eq!(entries[1].prefix, "//registry.example.com/scoped/");
    assert_eq!(entries[1].cert.as_deref(), Some("scoped_inline_cert"));
    assert_eq!(entries[1].key.as_deref(), Some("scoped_inline_key"));
    assert_eq!(entries[1].certfile, None);
    assert_eq!(entries[1].keyfile, None);

    // 2. scoped_tls_configs tuples
    let tuples = npmrc.scoped_tls_configs();
    assert_eq!(tuples.len(), 2);
    assert_eq!(tuples[0].0, "//registry.example.com/");
    assert_eq!(tuples[0].2.as_deref(), Some("/path/to/root.crt"));
    assert_eq!(tuples[1].0, "//registry.example.com/scoped/");
    assert_eq!(tuples[1].1.as_deref(), Some("scoped_inline_cert"));

    // 3. Longest-prefix precedence: scoped prefix /scoped/ wins over root /
    let scoped_pkg_url = Url::parse("https://registry.example.com/scoped/sub/package").unwrap();
    assert_eq!(npmrc.get_cert(&scoped_pkg_url), Some("scoped_inline_cert"));
    assert_eq!(npmrc.get_key(&scoped_pkg_url), Some("scoped_inline_key"));

    // Root prefix fallback for non-scoped path
    let other_pkg_url = Url::parse("https://registry.example.com/other/package").unwrap();
    assert_eq!(npmrc.get_cert(&other_pkg_url), Some("/path/to/root.crt"));
    assert_eq!(npmrc.get_key(&other_pkg_url), Some("/path/to/root.key"));
}

#[test]
fn test_find_workspace_root_dynamic_stateless() {
    let tmp = tempdir().unwrap();

    // Setup Tree A
    let root_a = tmp.path().join("root_a");
    let pkg_a = root_a.join("packages").join("pkg_a");
    fs::create_dir_all(&pkg_a).unwrap();
    fs::write(
        root_a.join("package.json"),
        r#"{"name":"root-a","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(pkg_a.join("package.json"), r#"{"name":"pkg-a"}"#).unwrap();

    // Setup Tree B
    let root_b = tmp.path().join("root_b");
    let pkg_b = root_b.join("modules").join("pkg_b");
    fs::create_dir_all(&pkg_b).unwrap();
    fs::write(
        root_b.join("package.json"),
        r#"{"name":"root-b","workspaces":["modules/*"]}"#,
    )
    .unwrap();
    fs::write(pkg_b.join("package.json"), r#"{"name":"pkg-b"}"#).unwrap();

    // Setup standalone
    let standalone = tmp.path().join("standalone").join("child");
    fs::create_dir_all(&standalone).unwrap();
    fs::write(standalone.join("package.json"), r#"{"name":"alone"}"#).unwrap();

    // Interleaved lookups must correctly find their respective roots without cross-talk
    let found_a = crate::find_workspace_root(&pkg_a);
    let found_b = crate::find_workspace_root(&pkg_b);
    let found_alone = crate::find_workspace_root(&standalone);

    assert_eq!(
        found_a.as_deref().and_then(|p| p.canonicalize().ok()),
        root_a.canonicalize().ok()
    );
    assert_eq!(
        found_b.as_deref().and_then(|p| p.canonicalize().ok()),
        root_b.canonicalize().ok()
    );
    assert_eq!(found_alone, None);

    // Verify dynamic mutation: adding a workspace package.json above standalone is immediately detected
    let standalone_parent = standalone.parent().unwrap();
    fs::write(
        standalone_parent.join("package.json"),
        r#"{"name":"parent","workspaces":["child"]}"#,
    )
    .unwrap();

    let found_new = crate::find_workspace_root(&standalone);
    assert_eq!(
        found_new.as_deref().and_then(|p| p.canonicalize().ok()),
        standalone_parent.canonicalize().ok()
    );
}

