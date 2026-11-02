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
