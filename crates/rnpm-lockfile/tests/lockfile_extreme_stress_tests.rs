//! Extreme Borderline Stress & Real-World Corpus Swarm Tests for `rnpm-lockfile` (CP2-4).
//!
//! Tests:
//! 1. Lockfile v1 -> v3 inflation:
//!    - Nested `dependencies` flattening into v3 `packages` map
//!    - `bundled: true` vs `inBundle: true` normalization
//!    - `dev: true` + `optional: true` -> `devOptional: true`
//!    - `npm:` aliases (unscoped and scoped) inflating `pkg.name` and clean `pkg.version`
//!    - Missing `packages` in v2/v3 fallback to `dependencies`
//! 2. Lockfile v2 retention:
//!    - Preserving BOTH `dependencies` and `packages` sections cleanly (`lockfileVersion: 2`)
//!    - Formatting links as `file:<path>` in legacy dependencies
//!    - Preserving aliases as `npm:real_name@ver` in legacy dependencies
//!    - Filtering out workspace directories outside `node_modules/` from legacy `dependencies`
//! 3. Hidden lockfile `node_modules/.package-lock.json`:
//!    - Forced to v3, omitting root `""`
//!    - Omits platform-incompatible optional packages (e.g. `fsevents` on non-darwin)
//!    - Prioritizes `npm-shrinkwrap.json` over `package-lock.json` when detecting project format
//! 4. Formatting edge cases:
//!    - `format-package-lock=false` (compact single-line JSON)
//!    - Tabs indentation (`\t`) preservation
//!    - 4-space indentation preservation
//!    - CRLF (`\r\n`) vs LF (`\n`) preservation without `\r\r\n`
//!    - One-line `package.json` format fallback to lockfile or 2-spaces
//! 5. Corrupted, truncated, and malformed lockfiles:
//!    - Truncated JSON returns clean `LockfileError::Json` (no panic)
//!    - Empty string and primitive JSON values return clean error (no panic)
//!    - String lockfileVersion (`"1"`, `"2"`, `"3"`) parsed correctly
//!    - Missing lockfileVersion defaults to 1
//!    - Tampered or weak integrity hashes flagged cleanly

use rnpm_core::manifest::{Manifest, ManifestFormat};
use rnpm_core::PlatformList;
use rnpm_lockfile::{
    parse_and_migrate, verify_lockfile_integrity, IntegrityPolicy, LockfileError, LockfilePackage,
    LockfileV3,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

const VALID_SHA1: &str = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// =========================================================================
// 1. Lockfile v1 -> v3 Inflation
// =========================================================================

#[test]
fn test_v1_to_v3_inflation_nested_and_flags() {
    let v1_json = r#"{
        "name": "my-v1-app",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "requires": true,
        "dependencies": {
            "top-dep": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/top-dep/-/top-dep-1.0.0.tgz",
                "integrity": "sha512-AAA==",
                "dev": true,
                "optional": true,
                "dependencies": {
                    "nested-dep": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/nested-dep/-/nested-dep-2.0.0.tgz",
                        "integrity": "sha512-BBB==",
                        "bundled": true,
                        "requires": {
                            "sub-req": "^1.0.0"
                        }
                    }
                }
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("v1 lockfile must migrate to v3 cleanly");
    assert_eq!(v3.lockfile_version, 3);
    assert_eq!(v3.name, "my-v1-app");
    assert_eq!(v3.version.as_deref(), Some("1.0.0"));

    // Check top-level dependency
    let top = v3
        .packages
        .get("node_modules/top-dep")
        .expect("top-dep must be flattened to node_modules/top-dep");
    assert_eq!(top.version.as_deref(), Some("1.0.0"));
    assert_eq!(top.dev, Some(true));
    assert_eq!(top.optional, Some(true));
    assert!(top.is_effective_dev());
    assert!(top.is_effective_optional());

    // Check nested dependency
    let nested = v3
        .packages
        .get("node_modules/top-dep/node_modules/nested-dep")
        .expect("nested-dep must be flattened with recursive path");
    assert_eq!(nested.version.as_deref(), Some("2.0.0"));
    assert_eq!(nested.in_bundle, Some(true));
    assert_eq!(
        nested
            .dependencies
            .as_ref()
            .and_then(|d| d.get("sub-req"))
            .map(|s| s.as_str()),
        Some("^1.0.0")
    );
}

#[test]
fn test_v1_to_v3_inflation_aliases_unscoped_and_scoped() {
    let v1_json = r#"{
        "name": "alias-app",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "my-chalk": {
                "version": "npm:chalk@5.0.0",
                "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz",
                "integrity": "sha512-CHALK=="
            },
            "@my-scope/core": {
                "version": "npm:@babel/core@7.24.0",
                "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
                "integrity": "sha512-BABEL=="
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("v1 with aliases must migrate cleanly");

    let chalk_pkg = v3
        .packages
        .get("node_modules/my-chalk")
        .expect("my-chalk must exist in packages");
    assert_eq!(
        chalk_pkg.name.as_deref(),
        Some("chalk"),
        "inflated package name must be the real aliased package name"
    );
    assert_eq!(
        chalk_pkg.version.as_deref(),
        Some("5.0.0"),
        "version must be cleanly extracted without npm: prefix"
    );

    let babel_pkg = v3
        .packages
        .get("node_modules/@my-scope/core")
        .expect("@my-scope/core must exist in packages");
    assert_eq!(
        babel_pkg.name.as_deref(),
        Some("@babel/core"),
        "scoped alias target name must be correctly extracted"
    );
    assert_eq!(
        babel_pkg.version.as_deref(),
        Some("7.24.0"),
        "scoped alias target version must be cleanly extracted"
    );
}

#[test]
fn test_v1_to_v3_inflation_bundled_variants() {
    let v1_json = r#"{
        "name": "bundled-app",
        "lockfileVersion": 1,
        "dependencies": {
            "pkg-a": {
                "version": "1.0.0",
                "bundled": true
            },
            "pkg-b": {
                "version": "2.0.0",
                "inBundle": true
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("bundled variants must migrate cleanly");
    let pkg_a = v3.packages.get("node_modules/pkg-a").unwrap();
    let pkg_b = v3.packages.get("node_modules/pkg-b").unwrap();
    assert_eq!(pkg_a.in_bundle, Some(true));
    assert_eq!(pkg_b.in_bundle, Some(true));
}

#[test]
fn test_v2_to_v3_inflation_missing_packages_fallback() {
    // Some v2 lockfiles encountered in the wild have `dependencies` populated
    // but have an empty or partial `packages` map.
    let v2_json = r#"{
        "name": "v2-empty-packages",
        "version": "1.2.3",
        "lockfileVersion": 2,
        "packages": {},
        "dependencies": {
            "foo": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                "integrity": "sha512-FOO=="
            }
        }
    }"#;

    let v3 = parse_and_migrate(v2_json).expect("v2 with empty packages must migrate cleanly");
    assert_eq!(v3.lockfile_version, 3);
    let foo = v3
        .packages
        .get("node_modules/foo")
        .expect("foo must be inflated from dependencies");
    assert_eq!(foo.version.as_deref(), Some("1.0.0"));

    // Root package should have been reconstructed
    let root = v3.packages.get("").expect("root package must be present");
    assert_eq!(root.name.as_deref(), Some("v2-empty-packages"));
    assert_eq!(root.version.as_deref(), Some("1.2.3"));
    assert_eq!(
        root.dependencies
            .as_ref()
            .and_then(|d| d.get("foo"))
            .map(|s| s.as_str()),
        Some("1.0.0")
    );
}

#[test]
fn test_v3_inflation_missing_packages_with_dependencies_fallback() {
    // Malformed v3 lockfile with lockfileVersion: 3 but empty packages and legacy dependencies present
    let malformed_v3 = r#"{
        "name": "malformed-v3",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {},
        "dependencies": {
            "bar": {
                "version": "2.1.0",
                "resolved": "https://registry.npmjs.org/bar/-/bar-2.1.0.tgz",
                "integrity": "sha512-BAR=="
            }
        }
    }"#;

    let v3 = parse_and_migrate(malformed_v3).expect("v3 with legacy dependencies must recover");
    assert_eq!(v3.lockfile_version, 3);
    assert!(v3.packages.contains_key("node_modules/bar"));
}

// =========================================================================
// 2. Lockfile v2 Retention
// =========================================================================

#[test]
fn test_v2_retention_packages_and_dependencies() {
    let mut lock = LockfileV3::new("v2-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/dep-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/dep-a/-/dep-a-1.0.0.tgz".to_string()),
            integrity: Some("sha512-AAA==".to_string()),
            ..Default::default()
        },
    );

    let json_v2 = lock
        .to_json_string_version(2)
        .expect("must serialize to v2 cleanly");
    let val: serde_json::Value =
        serde_json::from_str(&json_v2).expect("serialized v2 must be valid json");

    assert_eq!(val["lockfileVersion"], 2);
    assert!(
        val["packages"].is_object(),
        "v2 must retain 'packages' section"
    );
    assert!(
        val["dependencies"].is_object(),
        "v2 must retain 'dependencies' section"
    );
    assert_eq!(val["packages"]["node_modules/dep-a"]["version"], "1.0.0");
    assert_eq!(val["dependencies"]["dep-a"]["version"], "1.0.0");
}

#[test]
fn test_v2_retention_link_packages_as_file_spec() {
    let mut lock = LockfileV3::new("v2-links", Some("1.0.0".to_string()));
    lock.insert_package(
        "packages/my-lib",
        LockfilePackage {
            version: Some("0.1.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/my-lib",
        LockfilePackage {
            resolved: Some("packages/my-lib".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );

    let json_v2 = lock
        .to_json_string_version(2)
        .expect("must serialize to v2");
    let val: serde_json::Value = serde_json::from_str(&json_v2).unwrap();

    // In legacy dependencies, symlinks/links must be represented with "version": "file:..."
    let legacy_dep = &val["dependencies"]["my-lib"];
    assert!(
        legacy_dep.is_object(),
        "my-lib must be in legacy dependencies"
    );
    assert_eq!(
        legacy_dep["version"], "file:packages/my-lib",
        "symlink version must be file:<target>"
    );
}

#[test]
fn test_v2_retention_alias_formatting() {
    let mut lock = LockfileV3::new("v2-aliases", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/my-chalk",
        LockfilePackage {
            name: Some("chalk".to_string()),
            version: Some("5.0.0".to_string()),
            ..Default::default()
        },
    );

    let json_v2 = lock
        .to_json_string_version(2)
        .expect("must serialize to v2");
    let val: serde_json::Value = serde_json::from_str(&json_v2).unwrap();

    let legacy_chalk = &val["dependencies"]["my-chalk"];
    assert_eq!(
        legacy_chalk["version"], "npm:chalk@5.0.0",
        "legacy dependency for alias must be formatted as npm:real_name@version"
    );
}

#[test]
fn test_v2_retention_workspace_directories_filtered_out() {
    let mut lock = LockfileV3::new("v2-workspaces", Some("1.0.0".to_string()));
    lock.insert_package(
        "packages/member-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lock.insert_package(
        "node_modules/member-a",
        LockfilePackage {
            resolved: Some("packages/member-a".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );

    let json_v2 = lock
        .to_json_string_version(2)
        .expect("must serialize to v2");
    let val: serde_json::Value = serde_json::from_str(&json_v2).unwrap();

    // Legacy dependencies should NOT contain "packages"
    assert!(
        val["dependencies"].get("packages").is_none(),
        "workspace directories outside node_modules must not be added to legacy dependencies"
    );
    assert!(
        val["dependencies"].get("member-a").is_some(),
        "the link in node_modules/member-a should be added"
    );
}

// =========================================================================
// 3. Hidden Lockfile & Platform Skipping
// =========================================================================

#[test]
fn test_save_hidden_platform_skipping() {
    let dir = tempdir().unwrap();
    let project_dir = dir.path();
    fs::create_dir_all(project_dir.join("node_modules")).unwrap();

    let mut lock = LockfileV3::new("hidden-test", Some("1.0.0".to_string()));

    // Package for darwin only (e.g. fsevents)
    let mut fsevents = LockfilePackage {
        version: Some("2.3.3".to_string()),
        optional: Some(true),
        os: Some(PlatformList::from(vec!["darwin".to_string()])),
        ..Default::default()
    };
    fsevents.normalize_flags();
    lock.insert_package("node_modules/fsevents", fsevents);

    // Package for all platforms
    let mut lodash = LockfilePackage {
        version: Some("4.17.21".to_string()),
        ..Default::default()
    };
    lodash.normalize_flags();
    lock.insert_package("node_modules/lodash", lodash);

    // Save hidden lockfile
    lock.save_hidden(project_dir)
        .expect("save_hidden must succeed");

    let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
    assert!(
        hidden_path.exists(),
        "node_modules/.package-lock.json must be written"
    );

    let loaded =
        LockfileV3::load_from_file(&hidden_path).expect("hidden lockfile must be loadable");
    assert_eq!(loaded.lockfile_version, 3);
    assert!(
        !loaded.packages.contains_key(""),
        "root package must be omitted from hidden lockfile"
    );

    #[cfg(target_os = "windows")]
    {
        assert!(
            !loaded.packages.contains_key("node_modules/fsevents"),
            "darwin-only fsevents must be omitted on Windows"
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert!(
            !loaded.packages.contains_key("node_modules/fsevents"),
            "darwin-only fsevents must be omitted on Linux"
        );
    }
}

#[test]
fn test_save_hidden_shrinkwrap_precedence_in_format() {
    let dir = tempdir().unwrap();
    let project_dir = dir.path();
    fs::create_dir_all(project_dir.join("node_modules")).unwrap();

    // Write package.json with 2 spaces
    fs::write(
        project_dir.join("package.json"),
        "{\n  \"name\": \"app\"\n}\n",
    )
    .unwrap();

    // Write npm-shrinkwrap.json with 4 spaces indent
    fs::write(
        project_dir.join("npm-shrinkwrap.json"),
        "{\n    \"name\": \"app\",\n    \"lockfileVersion\": 3,\n    \"packages\": {}\n}\n",
    )
    .unwrap();

    // Write package-lock.json with tabs
    fs::write(
        project_dir.join("package-lock.json"),
        "{\n\t\"name\": \"app\",\n\t\"lockfileVersion\": 3,\n\t\"packages\": {}\n}\n",
    )
    .unwrap();

    let lock = LockfileV3::new("app", Some("1.0.0".to_string()));
    lock.save_hidden(project_dir).unwrap();

    let hidden_content =
        fs::read_to_string(project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH)).unwrap();
    assert!(
        hidden_content.contains("{\n  \"name\": \"app\""),
        "format from package.json takes precedence when package.json has indentation"
    );
}

// =========================================================================
// 4. Formatting Edge Cases
// =========================================================================

#[test]
fn test_formatting_compact_single_line_json() {
    let mut lock = LockfileV3::new("compact-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let compact_v3 = lock
        .to_json_string_compact()
        .expect("compact v3 must succeed");
    assert!(
        !compact_v3.contains('\n'),
        "compact v3 must not contain newlines"
    );
    assert!(
        compact_v3.starts_with("{\"name\":\"compact-test\""),
        "must be compact JSON"
    );

    let compact_v2 = lock
        .to_json_string_version_compact(2)
        .expect("compact v2 must succeed");
    assert!(
        !compact_v2.contains('\n'),
        "compact v2 must not contain newlines"
    );
    assert!(
        compact_v2.contains("\"dependencies\":{"),
        "compact v2 must have dependencies"
    );
}

#[test]
fn test_formatting_tabs_indentation_preservation() {
    let mut lock = LockfileV3::new("tabs-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let format = ManifestFormat {
        indent: "\t".to_string(),
        newline: "\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let formatted = lock.to_json_string_formatted(&format).unwrap();
    assert!(
        formatted.contains("{\n\t\"name\": \"tabs-test\""),
        "must be indented with tabs"
    );
}

#[test]
fn test_formatting_4_spaces_indentation_preservation() {
    let mut lock = LockfileV3::new("four-spaces", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let format = ManifestFormat {
        indent: "    ".to_string(),
        newline: "\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let formatted = lock.to_json_string_formatted(&format).unwrap();
    assert!(
        formatted.contains("{\n    \"name\": \"four-spaces\""),
        "must be indented with 4 spaces"
    );
}

#[test]
fn test_formatting_crlf_preservation_no_duplicate_carriage_return() {
    let mut lock = LockfileV3::new("crlf-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let format = ManifestFormat {
        indent: "  ".to_string(),
        newline: "\r\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let formatted = lock.to_json_string_formatted(&format).unwrap();
    assert!(formatted.contains("\r\n"), "must contain CRLF");
    assert!(
        !formatted.contains("\r\r\n"),
        "must NEVER contain duplicated carriage returns (\\r\\r\\n)"
    );
}

#[test]
fn test_formatting_one_line_package_json_fallback() {
    let dir = tempdir().unwrap();
    let project_dir = dir.path();

    // One-line package.json without indentation or newlines
    fs::write(
        project_dir.join("package.json"),
        r#"{"name":"one-liner","version":"1.0.0"}"#,
    )
    .unwrap();

    // An existing package-lock.json with 4 spaces indentation
    fs::write(
        project_dir.join("package-lock.json"),
        "{\n    \"name\": \"one-liner\",\n    \"lockfileVersion\": 3,\n    \"packages\": {}\n}\n",
    )
    .unwrap();

    let lock = LockfileV3::new("one-liner", Some("1.0.0".to_string()));
    let save_path = project_dir.join("package-lock.json");
    lock.save_to_file(&save_path).unwrap();

    let saved = fs::read_to_string(&save_path).unwrap();
    assert!(
        saved.contains("{\n    \"name\": \"one-liner\""),
        "when package.json is one-line, formatting must fall back to the existing lockfile's 4 spaces"
    );
}

// =========================================================================
// 5. Corrupted, Truncated, and Malformed Lockfiles
// =========================================================================

#[test]
fn test_corrupted_truncated_json_clean_error() {
    let truncated_cases = [
        "",
        "   ",
        "{",
        "{\"name\": \"app\", \"lockfileVersion\":",
        "{\"packages\": { \"node_modules/a\": ",
        "{\"name\": \"app\", \"lockfileVersion\": 3, \"packages\":",
    ];

    for case in truncated_cases {
        let res = parse_and_migrate(case);
        assert!(
            res.is_err(),
            "truncated JSON '{case}' must return Err, never panic"
        );
        match res.unwrap_err() {
            LockfileError::Json(_) => {}
            other => panic!("expected Json error for truncated input, got: {other:?}"),
        }
    }
}

#[test]
fn test_malformed_primitive_json_clean_error() {
    let primitive_cases = ["42", "true", "false", "\"just a string\"", "null", "[1, 2]"];

    for case in primitive_cases {
        let res = parse_and_migrate(case);
        assert!(
            res.is_err(),
            "primitive JSON '{case}' must return Err, never panic"
        );
    }
}

#[test]
fn test_string_and_missing_lockfile_version() {
    // Missing lockfileVersion defaults to 1
    let missing_ver = r#"{
        "name": "no-version",
        "dependencies": {
            "dep": { "version": "1.0.0" }
        }
    }"#;
    let v3_missing =
        parse_and_migrate(missing_ver).expect("missing lockfileVersion should default to 1");
    assert_eq!(v3_missing.lockfile_version, 3);
    assert!(v3_missing.packages.contains_key("node_modules/dep"));

    // String lockfileVersion "2"
    let str_v2 = r#"{
        "name": "str-v2",
        "lockfileVersion": "2",
        "packages": {
            "": { "name": "str-v2" },
            "node_modules/dep": { "version": "2.0.0" }
        }
    }"#;
    let v3_v2 = parse_and_migrate(str_v2).expect("string lockfileVersion '2' must parse");
    assert_eq!(v3_v2.lockfile_version, 3);
    assert_eq!(
        v3_v2.packages["node_modules/dep"].version.as_deref(),
        Some("2.0.0")
    );

    // String lockfileVersion "3"
    let str_v3 = r#"{
        "name": "str-v3",
        "lockfileVersion": "3",
        "packages": {
            "": { "name": "str-v3" }
        }
    }"#;
    let v3_v3 = parse_and_migrate(str_v3).expect("string lockfileVersion '3' must parse");
    assert_eq!(v3_v3.lockfile_version, 3);
}

#[test]
fn test_integrity_tampered_weak_clean_error() {
    let mut lock = LockfileV3::new("integrity-test", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/weak-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/weak-pkg/-/weak-pkg-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA1.to_string()), // Weak sha1
            ..Default::default()
        },
    );

    let policy = IntegrityPolicy::default(); // Requires sha512
    let res = verify_lockfile_integrity(&lock, &policy);
    assert!(res.is_err(), "weak sha1 integrity must be rejected");
    match res.unwrap_err() {
        LockfileError::WeakIntegrity { algorithm, .. } => {
            assert_eq!(algorithm, "sha1");
        }
        other => panic!("expected WeakIntegrity error, got: {other:?}"),
    }

    // Invalid base64
    let mut lock_bad = LockfileV3::new("bad-integrity", Some("1.0.0".to_string()));
    lock_bad.insert_package(
        "node_modules/bad-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            integrity: Some("sha512-NOT-VALID-BASE64!@#$%^&*()".to_string()),
            ..Default::default()
        },
    );
    let res_bad = verify_lockfile_integrity(&lock_bad, &policy);
    assert!(res_bad.is_err(), "invalid integrity string must fail");
}

// =========================================================================
// 6. Drift Detection in matches_manifest_ext
// =========================================================================

#[test]
fn test_matches_manifest_ext_workspaces_drift() {
    let mut manifest = Manifest {
        name: Some("ws-app".to_string()),
        version: Some("1.0.0".to_string()),
        workspaces: Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
            "packages/*".to_string(),
        ])),
        ..Default::default()
    };

    let lockfile = LockfileV3::from_manifest(&manifest);
    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "lockfile created from manifest must match"
    );

    // Drift 1: Workspaces changed in manifest
    manifest.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "packages/a".to_string(),
        "packages/b".to_string(),
    ]));
    assert!(
        !lockfile.matches_manifest_ext(&manifest, true, false),
        "workspaces drift must be detected"
    );

    // Drift 2: Workspaces removed in manifest
    manifest.workspaces = None;
    assert!(
        !lockfile.matches_manifest_ext(&manifest, true, false),
        "workspaces removal must be detected"
    );
}

#[test]
fn test_matches_manifest_ext_overrides_drift() {
    let mut manifest = Manifest {
        name: Some("overrides-app".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: {
            let mut m = BTreeMap::new();
            m.insert("foo".to_string(), "^1.0.0".to_string());
            m
        },
        ..Default::default()
    };

    let mut lockfile = LockfileV3::from_manifest(&manifest);
    lockfile.insert_package(
        "node_modules/foo",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            ..Default::default()
        },
    );

    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "should match before overrides"
    );

    // Add override requiring foo@2.0.0, but lockfile is resolved to 1.2.0
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "foo": "2.0.0" }),
    );
    assert!(
        !lockfile.matches_manifest_ext(&manifest, true, false),
        "unmatched override must trigger drift detection"
    );

    // Update lockfile to 2.0.0 satisfying the override
    lockfile.insert_package(
        "node_modules/foo",
        LockfilePackage {
            version: Some("2.0.0".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "matching override must satisfy matches_manifest_ext"
    );
}

#[test]
fn test_matches_manifest_ext_non_registry_and_alias_spec_drift() {
    let manifest = Manifest {
        name: Some("spec-app".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: {
            let mut m = BTreeMap::new();
            m.insert(
                "tarball-pkg".to_string(),
                "https://example.com/tarball-1.0.0.tgz".to_string(),
            );
            m.insert(
                "git-pkg".to_string(),
                "git+https://github.com/foo/bar.git#v1.0.0".to_string(),
            );
            m.insert("alias-pkg".to_string(), "npm:real-pkg@^1.0.0".to_string());
            m
        },
        ..Default::default()
    };

    let mut lockfile = LockfileV3::from_manifest(&manifest);
    lockfile.insert_package(
        "node_modules/tarball-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://example.com/tarball-1.0.0.tgz".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/git-pkg",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+https://github.com/foo/bar.git#v1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/alias-pkg",
        LockfilePackage {
            name: Some("real-pkg".to_string()),
            version: Some("1.5.0".to_string()),
            ..Default::default()
        },
    );

    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "in-sync non-registry and alias specs must match"
    );

    // Drift 1: Tarball URL changed in manifest
    let mut drifted_manifest = manifest.clone();
    drifted_manifest.dependencies.insert(
        "tarball-pkg".to_string(),
        "https://example.com/tarball-2.0.0.tgz".to_string(),
    );
    assert!(
        !lockfile.matches_manifest_ext(&drifted_manifest, true, false),
        "tarball URL drift must be detected"
    );

    // Drift 2: Git URL changed in manifest
    let mut drifted_git = manifest.clone();
    drifted_git.dependencies.insert(
        "git-pkg".to_string(),
        "git+https://github.com/foo/bar.git#v2.0.0".to_string(),
    );
    assert!(
        !lockfile.matches_manifest_ext(&drifted_git, true, false),
        "git spec drift must be detected"
    );

    // Drift 3: Alias target changed in manifest (real-pkg -> other-pkg)
    let mut drifted_alias = manifest.clone();
    drifted_alias.dependencies.insert(
        "alias-pkg".to_string(),
        "npm:other-pkg@^1.0.0".to_string(),
    );
    assert!(
        !lockfile.matches_manifest_ext(&drifted_alias, true, false),
        "alias package name drift must be detected"
    );
}
