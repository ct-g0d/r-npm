use std::path::PathBuf;
use crate::error::IntegrityError;
use crate::integrity::{Algorithm, Integrity};
use crate::manifest::Manifest;
use crate::semver::{Range, Version};
use crate::spec::{PackageSpec, PackageTarget};

#[test]
fn test_semver_version_parsing_and_order() {
    let v1 = Version::parse("1.2.3").unwrap();
    assert_eq!(v1.major, 1);
    assert_eq!(v1.minor, 2);
    assert_eq!(v1.patch, 3);
    assert!(v1.prerelease.is_empty());
    assert!(v1.build.is_empty());

    // Loose parsing with v and =
    let v2 = Version::parse("  v1.2.3  ").unwrap();
    assert_eq!(v1, v2);

    let v3 = Version::parse("=1.2.3").unwrap();
    assert_eq!(v1, v3);

    // Prerelease and build
    let vp1 = Version::parse("1.0.0-alpha.1+build.123").unwrap();
    assert_eq!(vp1.to_string(), "1.0.0-alpha.1+build.123");
    assert!(vp1.is_prerelease());

    // Semver precedence rules
    let va = Version::parse("1.0.0-alpha").unwrap();
    let va1 = Version::parse("1.0.0-alpha.1").unwrap();
    let va_beta = Version::parse("1.0.0-alpha.beta").unwrap();
    let vb = Version::parse("1.0.0-beta").unwrap();
    let vb2 = Version::parse("1.0.0-beta.2").unwrap();
    let vb11 = Version::parse("1.0.0-beta.11").unwrap();
    let vrc1 = Version::parse("1.0.0-rc.1").unwrap();
    let v_final = Version::parse("1.0.0").unwrap();

    assert!(va < va1);
    assert!(va1 < va_beta);
    assert!(va_beta < vb);
    assert!(vb < vb2);
    assert!(vb2 < vb11);
    assert!(vb11 < vrc1);
    assert!(vrc1 < v_final);

    // Numeric prerelease lower than alphanumeric
    let v_num = Version::parse("1.0.0-1").unwrap();
    let v_str = Version::parse("1.0.0-alpha").unwrap();
    assert!(v_num < v_str);

    // Build metadata is ignored in precedence
    let vb1 = Version::parse("1.0.0+20130313144700").unwrap();
    let vb2 = Version::parse("1.0.0+exp.sha.5114f85").unwrap();
    assert_eq!(vb1.cmp(&vb2), std::cmp::Ordering::Equal);
}

#[test]
fn test_semver_range_caret() {
    let r1 = Range::parse("^1.2.3").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r1.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.2.2").unwrap()));

    // Caret 0.x
    let r2 = Range::parse("^0.2.3").unwrap();
    assert!(r2.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r2.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r2.satisfies(&Version::parse("0.3.0").unwrap()));

    // Caret 0.0.x
    let r3 = Range::parse("^0.0.3").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(!r3.satisfies(&Version::parse("0.0.4").unwrap()));
}

#[test]
fn test_semver_range_tilde_and_x() {
    let r1 = Range::parse("~1.2.3").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.2.8").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.3.0").unwrap()));

    let r2 = Range::parse("1.x").unwrap();
    assert!(r2.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("1.99.0").unwrap()));
    assert!(!r2.satisfies(&Version::parse("2.0.0").unwrap()));

    let r3 = Range::parse("*").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(r3.satisfies(&Version::parse("99.9.9").unwrap()));
}

#[test]
fn test_semver_range_hyphen_and_or() {
    let r = Range::parse("1.2.3 - 2.3.4").unwrap();
    assert!(r.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r.satisfies(&Version::parse("2.3.5").unwrap()));

    let r_or = Range::parse("^1.0.0 || >=2.5.0 <3.0.0").unwrap();
    assert!(r_or.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_or.satisfies(&Version::parse("2.6.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("3.0.0").unwrap()));
}

#[test]
fn test_semver_prerelease_matching_rule() {
    let r = Range::parse("^1.2.3").unwrap();
    // Prerelease not allowed when range has no prerelease on tuple
    assert!(!r.satisfies(&Version::parse("1.2.4-alpha").unwrap()));

    // But if range explicitly targets prerelease on tuple
    let r_pre = Range::parse("^1.2.3-alpha.1").unwrap();
    assert!(r_pre.satisfies(&Version::parse("1.2.3-alpha.2").unwrap()));
    assert!(r_pre.satisfies(&Version::parse("1.2.4").unwrap()));
    // Tuple mismatch with prerelease should not match
    assert!(!r_pre.satisfies(&Version::parse("1.2.4-beta").unwrap()));
}

#[test]
fn test_package_spec_parsing() {
    // Ordinary package
    let s1 = PackageSpec::parse("express").unwrap();
    assert_eq!(s1.name, "express");
    assert_eq!(s1.target, PackageTarget::Tag("latest".to_string()));

    // Exact version
    let s2 = PackageSpec::parse("express@4.18.2").unwrap();
    assert_eq!(s2.name, "express");
    assert_eq!(
        s2.target,
        PackageTarget::Version(Version::parse("4.18.2").unwrap())
    );

    // Semver range
    let s3 = PackageSpec::parse("express@^4.18.0").unwrap();
    assert_eq!(s3.name, "express");
    assert_eq!(
        s3.target,
        PackageTarget::Range(Range::parse("^4.18.0").unwrap())
    );

    // Scoped package
    let s4 = PackageSpec::parse("@types/node@^18.0.0").unwrap();
    assert_eq!(s4.name, "@types/node");
    assert_eq!(
        s4.target,
        PackageTarget::Range(Range::parse("^18.0.0").unwrap())
    );

    // npm: alias
    let s5 = PackageSpec::parse("my-react@npm:react@^18.2.0").unwrap();
    assert_eq!(s5.name, "my-react");
    assert_eq!(
        s5.target,
        PackageTarget::Alias {
            name: "react".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("^18.2.0").unwrap())),
        }
    );

    // direct npm: alias
    let s5_direct = PackageSpec::parse("npm:react@^18.2.0").unwrap();
    assert_eq!(s5_direct.name, "react");

    // file: specifier
    let s6 = PackageSpec::parse("foo@file:../local-pkg").unwrap();
    assert_eq!(s6.name, "foo");
    assert_eq!(s6.target, PackageTarget::File(PathBuf::from("../local-pkg")));

    // parse_dependency helper
    let s7 = PackageSpec::parse_dependency("aliased", "npm:@scope/lib@~1.0.0").unwrap();
    assert_eq!(s7.name, "aliased");
    assert_eq!(
        s7.target,
        PackageTarget::Alias {
            name: "@scope/lib".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("~1.0.0").unwrap())),
        }
    );
}

#[test]
fn test_ssri_integrity_verification_and_precedence() {
    let data = b"hello world integrity test payload";

    let integrity_sha1 = Integrity::from_bytes(data, Algorithm::Sha1);
    let integrity_sha512 = Integrity::from_bytes(data, Algorithm::Sha512);

    // Valid single hash verification
    assert!(integrity_sha512.verify(data).is_ok());

    // Corrupted data detection
    let corrupted = b"corrupted payload";
    assert!(matches!(
        integrity_sha512.verify(corrupted),
        Err(IntegrityError::Mismatch { .. })
    ));

    // Multi-hash parsing and strongest algorithm precedence:
    // Format: "sha512-... sha1-..."
    let combined_str = format!("{} {}", integrity_sha512, integrity_sha1);
    let combined = Integrity::parse(&combined_str).unwrap();
    assert_eq!(combined.strongest_algorithm(), Some(Algorithm::Sha512));
    assert!(combined.verify(data).is_ok());

    // CRUCIAL: Weak hash matches, but strongest hash fails!
    // A corrupted sha512 with a valid sha1: MUST FAIL!
    let fake_sha512 = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let attack_str = format!("{} {}", fake_sha512, integrity_sha1);
    let attack_integrity = Integrity::parse(&attack_str).unwrap();
    let result = attack_integrity.verify(data);
    assert!(result.is_err(), "Strongest hash failure must reject even if weaker hash matches");
    if let Err(IntegrityError::Mismatch { algorithm, .. }) = result {
        assert_eq!(algorithm, "sha512");
    } else {
        panic!("Expected Mismatch error");
    }
}

#[test]
fn test_manifest_parsing_and_bom_tolerance() {
    let json_text = r#"{
        "name": "@myorg/my-pkg",
        "version": "1.2.3",
        "description": "A test package",
        "bin": {
            "cli": "./bin/cli.js"
        },
        "scripts": {
            "test": "echo test"
        },
        "dependencies": {
            "react": "^18.2.0"
        },
        "devDependencies": {
            "typescript": "^5.0.0"
        },
        "peerDependencies": {
            "react-dom": "^18.2.0"
        },
        "optionalDependencies": {
            "fsevents": "^2.3.2"
        },
        "bundleDependencies": ["react"]
    }"#;

    // Normal parse
    let manifest = Manifest::from_str(json_text).unwrap();
    assert_eq!(manifest.name.as_deref(), Some("@myorg/my-pkg"));
    assert_eq!(manifest.version.as_deref(), Some("1.2.3"));
    assert_eq!(manifest.dependencies.get("react").unwrap(), "^18.2.0");
    assert_eq!(manifest.bin_entries(), vec![("cli".to_string(), "./bin/cli.js".to_string())]);
    assert_eq!(manifest.bundled_package_names(), vec!["react".to_string()]);

    // UTF-8 BOM tolerance on bytes
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(json_text.as_bytes());
    let manifest_bom = Manifest::from_slice(&bom_bytes).unwrap();
    assert_eq!(manifest_bom.name.as_deref(), Some("@myorg/my-pkg"));

    // UTF-8 BOM tolerance on string
    let bom_str = format!("\u{feff}{json_text}");
    let manifest_str_bom = Manifest::from_str(&bom_str).unwrap();
    assert_eq!(manifest_str_bom.name.as_deref(), Some("@myorg/my-pkg"));

    // Single bin string normalization
    let single_bin_json = r#"{
        "name": "@myorg/my-tool",
        "version": "1.0.0",
        "bin": "./dist/cli.js"
    }"#;
    let single_bin_manifest = Manifest::from_str(single_bin_json).unwrap();
    assert_eq!(
        single_bin_manifest.bin_entries(),
        vec![("my-tool".to_string(), "./dist/cli.js".to_string())]
    );

    // Malformed JSON diagnostic
    let malformed = r#"{ "name": "bad", "version": 1.2.3 }"#;
    let err = Manifest::from_str(malformed).unwrap_err();
    assert!(matches!(err, crate::error::ManifestError::MalformedJson { .. }));
}
