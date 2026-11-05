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

#[test]
fn test_env_interpolation_escaping_and_defaults() {
    let mut env_map = HashMap::new();
    env_map.insert("EMPTY_VAR".to_string(), "".to_string());
    env_map.insert("SET_VAR".to_string(), "val".to_string());
    let lookup = |var: &str| env_map.get(var).cloned();

    // 1. Escaping ${VAR} and $VAR
    assert_eq!(
        interpolate_env(r"\${SET_VAR}", &lookup),
        "${SET_VAR}"
    );
    assert_eq!(
        interpolate_env(r"\$SET_VAR", &lookup),
        "$SET_VAR"
    );
    assert_eq!(
        interpolate_env("Cost is $$100", &lookup),
        "Cost is $100"
    );

    // 2. ${VAR:-default} uses default when unset OR empty
    assert_eq!(
        interpolate_env("${UNSET_VAR:-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(
        interpolate_env("${EMPTY_VAR:-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(
        interpolate_env("${SET_VAR:-fallback}", &lookup),
        "val"
    );

    // 3. ${VAR-default} uses default ONLY when unset (keeps empty if set to empty)
    assert_eq!(
        interpolate_env("${UNSET_VAR-fallback}", &lookup),
        "fallback"
    );
    assert_eq!(
        interpolate_env("${EMPTY_VAR-fallback}", &lookup),
        ""
    );
    assert_eq!(
        interpolate_env("${SET_VAR-fallback}", &lookup),
        "val"
    );

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
    assert!(bad_npmrc.set("//registry.org/:_authToken", "token\r\nevil=1").is_err());
    assert!(bad_npmrc.set("key\ninvalid", "val").is_err());
}

#[test]
fn test_package_metadata_url_and_validation() {
    let mut npmrc = Npmrc::new();
    npmrc.set("@myorg:registry", "https://custom.registry.com/").unwrap();

    // Scoped package URL formatting
    let url = npmrc.package_metadata_url("@myorg/pkg").unwrap();
    assert_eq!(url.as_str(), "https://custom.registry.com/@myorg%2fpkg");

    // Unscoped package URL formatting
    let unscoped_url = npmrc.package_metadata_url("lodash").unwrap();
    assert_eq!(unscoped_url.as_str(), "https://registry.npmjs.org/lodash");

    // Path traversal in package name is rejected
    assert!(npmrc.package_metadata_url("../foo").is_err());
    assert!(npmrc.package_metadata_url("@myorg/../../etc/passwd").is_err());
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
    env_map.insert("NPM_TOKEN".to_string(), "npm_live_prod_secret_token_1234567890".to_string());
    env_map.insert("CI_AUTH_KEY".to_string(), "ghp_ci_runner_key_9876543210abcdef".to_string());
    env_map.insert("CUSTOM_REGISTRY_HOST".to_string(), "npm.internal.corp".to_string());

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

    let npmrc = Npmrc::parse_with_env(content, &lookup).unwrap();

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
    assert_eq!(
        npmrc.settings.get("escaped_val").unwrap(),
        "${NPM_TOKEN}"
    );

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
    assert!(is_sensitive_credential_key("//registry.npmjs.org/:_authToken"));
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
    use std::collections::BTreeMap;
    use crate::ConfigOptions;

    let temp_root = tempdir().unwrap();
    let root_path = temp_root.path();

    let global_file = root_path.join("global.npmrc");
    fs::write(&global_file, "registry=https://global.registry.org/\nglobal_only=1\ncommon=from_global\n").unwrap();

    let user_file = root_path.join("user.npmrc");
    fs::write(&user_file, "registry=https://user.registry.org/\nuser_only=2\ncommon=from_user\n").unwrap();

    let ws_dir = root_path.join("workspace");
    let packages_dir = ws_dir.join("packages");
    let project_dir = packages_dir.join("pkg-member");
    fs::create_dir_all(&project_dir).unwrap();

    let ws_pkg_json = r#"{"name": "root-ws", "workspaces": ["packages/*"]}"#;
    fs::write(ws_dir.join("package.json"), ws_pkg_json).unwrap();
    fs::write(ws_dir.join(".npmrc"), "registry=https://ws.registry.org/\nws_only=3\ncommon=from_ws\n").unwrap();

    let member_pkg_json = r#"{"name": "pkg-member", "version": "1.0.0"}"#;
    fs::write(project_dir.join("package.json"), member_pkg_json).unwrap();
    fs::write(project_dir.join(".npmrc"), "registry=https://proj.registry.org/\nproj_only=4\ncommon=from_proj\n").unwrap();

    let mut env_map = BTreeMap::new();
    env_map.insert("npm_config_registry".to_string(), "https://env.registry.org/".to_string());
    env_map.insert("npm_config_env_only".to_string(), "5".to_string());
    env_map.insert("npm_config_common".to_string(), "from_env".to_string());

    let mut cli_map = BTreeMap::new();
    cli_map.insert("registry".to_string(), "https://cli.registry.org/".to_string());
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
    assert_eq!(loaded_b.npmrc.registry.as_str(), "https://pkg-b.registry.org/");
    assert_eq!(loaded_b.get("strict-ssl"), Some("true"));
    assert_eq!(loaded_b.get("shared_flag"), Some("from_pkg_b"));
}

#[test]
fn test_env_vars_and_cli_overrides() {
    use std::collections::BTreeMap;
    use crate::ConfigOptions;

    let mut env_map = BTreeMap::new();
    env_map.insert("NPM_CONFIG_STRICT_SSL".to_string(), "false".to_string());
    env_map.insert("npm_config_proxy".to_string(), "http://proxy.corp:8080".to_string());
    env_map.insert("NPM_CONFIG_HTTPS_PROXY".to_string(), "https://proxy.corp:8443".to_string());
    env_map.insert("npm_config_fetch_timeout".to_string(), "45000".to_string());
    env_map.insert("npm_config_cafile".to_string(), "/path/to/cert.pem".to_string());
    env_map.insert("npm_config__auth".to_string(), "token_123".to_string());

    let loaded_env = Config::load_with_options(ConfigOptions::new().env_vars(env_map.clone())).unwrap();
    assert_eq!(loaded_env.get("strict-ssl"), Some("false"));
    assert_eq!(loaded_env.get("strict_ssl"), Some("false"));
    assert_eq!(loaded_env.get_bool("strict_ssl"), Some(false));
    assert_eq!(loaded_env.get("proxy"), Some("http://proxy.corp:8080"));
    assert_eq!(loaded_env.get("https-proxy"), Some("https://proxy.corp:8443"));
    assert_eq!(loaded_env.get("https_proxy"), Some("https://proxy.corp:8443"));
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
    assert_eq!(loaded_cli.get("https-proxy"), Some("https://proxy.corp:8443"));
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
    use std::path::PathBuf;
    use crate::{
        find_global_bin_dir, find_global_node_modules, find_global_prefix_with_env,
        find_local_bin_dir, find_local_node_modules, find_local_prefix, Config, ConfigOptions,
    };

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
