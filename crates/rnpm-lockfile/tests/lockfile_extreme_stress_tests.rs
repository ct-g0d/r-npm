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
fn test_matches_manifest_ext_referential_override_demo() {
    let mut manifest = Manifest {
        name: Some("referential-override-demo-app".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: {
            let mut m = BTreeMap::new();
            m.insert("demo".to_string(), "^1.0.0".to_string());
            m
        },
        ..Default::default()
    };

    // npm-style referential override: {"demo": "$demo"}
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "demo": "$demo" }),
    );

    let mut lockfile = LockfileV3::from_manifest(&manifest);
    lockfile.insert_package(
        "node_modules/demo",
        LockfilePackage {
            version: Some("1.2.0".to_string()),
            ..Default::default()
        },
    );

    // 1. Direct referential override: $demo resolves to root's ^1.0.0 and must match lockfile 1.2.0
    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "referential override $demo should resolve to root's ^1.0.0 and match lockfile 1.2.0"
    );
    assert!(
        lockfile.matches_manifest_for_ci(&manifest, true),
        "matches_manifest_for_ci must accept referential override $demo matching lockfile"
    );

    // 2. If lockfile package does not satisfy ^1.0.0, drift should be detected
    lockfile.insert_package(
        "node_modules/demo",
        LockfilePackage {
            version: Some("2.0.0".to_string()),
            ..Default::default()
        },
    );
    assert!(
        !lockfile.matches_manifest_ext(&manifest, true, false),
        "referential override $demo must reject lockfile version 2.0.0 not satisfying ^1.0.0"
    );
    assert!(
        !lockfile.matches_manifest_for_ci(&manifest, true),
        "matches_manifest_for_ci must reject lockfile version 2.0.0 not satisfying ^1.0.0"
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

// =========================================================================
// 7. Round 2 Regression Tests
// =========================================================================

#[test]
fn test_non_aliased_legacy_package_not_turned_into_alias_on_export() {
    // Legacy dependency has explicit name equal to its map key ("foo": { "name": "foo", "version": "1.0.0" })
    let v1_json = r#"{
        "name": "non-alias-test",
        "lockfileVersion": 1,
        "dependencies": {
            "foo": {
                "name": "foo",
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
            },
            "my-chalk": {
                "name": "chalk",
                "version": "5.0.0",
                "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz"
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("migration must succeed");
    // foo should not have name: Some("foo") because it is not an alias
    let foo_pkg = v3.packages.get("node_modules/foo").unwrap();
    assert_eq!(
        foo_pkg.name, None,
        "non-aliased package must have name: None"
    );

    // my-chalk MUST have name: Some("chalk") because it is an alias
    let chalk_pkg = v3.packages.get("node_modules/my-chalk").unwrap();
    assert_eq!(
        chalk_pkg.name.as_deref(),
        Some("chalk"),
        "aliased package must have name: Some(\"chalk\")"
    );

    // Now test export back to v2 legacy dependencies:
    let v2_json = v3.to_json_string_version(2).unwrap();
    let val: serde_json::Value = serde_json::from_str(&v2_json).unwrap();

    assert_eq!(
        val["dependencies"]["foo"]["version"], "1.0.0",
        "non-aliased package must export version: 1.0.0, NOT npm:foo@1.0.0"
    );
    assert_eq!(
        val["dependencies"]["my-chalk"]["version"], "npm:chalk@5.0.0",
        "aliased package must export version: npm:chalk@5.0.0"
    );

    // Also verify if a v3 package explicitly has name: Some("bar") where key is node_modules/bar
    let mut lock = LockfileV3::new("roundtrip-check", Some("1.0.0".to_string()));
    lock.insert_package(
        "node_modules/bar",
        LockfilePackage {
            name: Some("bar".to_string()),
            version: Some("2.0.0".to_string()),
            ..Default::default()
        },
    );
    let v2_roundtrip = lock.to_json_string_version(2).unwrap();
    let val_rt: serde_json::Value = serde_json::from_str(&v2_roundtrip).unwrap();
    assert_eq!(
        val_rt["dependencies"]["bar"]["version"], "2.0.0",
        "to_legacy_dependencies must not emit npm: prefix when name == dep_name"
    );
}

#[test]
fn test_version_matches_target_non_semver_for_file_git_url() {
    // 1. Git dependency with a commit hash as version
    let git_pkg = LockfilePackage {
        version: Some("abcd1234ef567890abcd1234ef567890abcd1234".to_string()),
        resolved: Some("git+https://github.com/foo/bar.git#abcd1234".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec(
            "git-dep",
            &git_pkg,
            "git+https://github.com/foo/bar.git#main"
        ),
        "package_satisfies_spec must accept non-semver git versions"
    );

    // 2. File dependency with a local path as version
    let file_pkg = LockfilePackage {
        version: Some("file:../my-local-dep".to_string()),
        resolved: Some("file:../my-local-dep".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec(
            "file-dep",
            &file_pkg,
            "file:../my-local-dep"
        ),
        "package_satisfies_spec must accept non-semver file versions"
    );

    // 3. URL dependency with a tarball URL as version
    let url_pkg = LockfilePackage {
        version: Some("https://example.com/archive.tgz".to_string()),
        resolved: Some("https://example.com/archive.tgz".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec(
            "url-dep",
            &url_pkg,
            "https://example.com/archive.tgz"
        ),
        "package_satisfies_spec must accept non-semver URL versions"
    );

    // 4. Tag target with non-semver version
    assert!(
        LockfileV3::package_satisfies_spec("tag-dep", &url_pkg, "latest"),
        "package_satisfies_spec must accept non-semver versions for Tag targets"
    );

    // 5. Version/Range target with non-semver version MUST still fail cleanly
    assert!(
        !LockfileV3::package_satisfies_spec("semver-dep", &url_pkg, "^1.0.0"),
        "package_satisfies_spec must reject non-semver version for Range targets"
    );
}

#[test]
fn test_deserialize_lockfile_version_integral_floats_and_rejections() {
    // Float 2.0
    let json_f2 = r#"{"name": "f2", "lockfileVersion": 2.0, "packages": { "": {} }}"#;
    let lf_f2 = LockfileV3::from_json_str(json_f2).expect("lockfileVersion 2.0 must parse");
    assert_eq!(lf_f2.lockfile_version, 2);

    // Float 3.0
    let json_f3 = r#"{"name": "f3", "lockfileVersion": 3.0, "packages": { "": {} }}"#;
    let lf_f3 = LockfileV3::from_json_str(json_f3).expect("lockfileVersion 3.0 must parse");
    assert_eq!(lf_f3.lockfile_version, 3);

    // String float "2.0" and "3.0"
    let json_s2 = r#"{"name": "s2", "lockfileVersion": "2.0", "packages": { "": {} }}"#;
    let lf_s2 = LockfileV3::from_json_str(json_s2).expect("lockfileVersion '2.0' must parse");
    assert_eq!(lf_s2.lockfile_version, 2);

    let json_s3 = r#"{"name": "s3", "lockfileVersion": "3.0", "packages": { "": {} }}"#;
    let lf_s3 = LockfileV3::from_json_str(json_s3).expect("lockfileVersion '3.0' must parse");
    assert_eq!(lf_s3.lockfile_version, 3);

    // Rejection 1: Fractional float 2.5
    let json_fract = r#"{"name": "fract", "lockfileVersion": 2.5, "packages": { "": {} }}"#;
    assert!(
        LockfileV3::from_json_str(json_fract).is_err(),
        "fractional lockfileVersion 2.5 must be rejected"
    );

    // Rejection 2: Negative number -1
    let json_neg = r#"{"name": "neg", "lockfileVersion": -1, "packages": { "": {} }}"#;
    assert!(
        LockfileV3::from_json_str(json_neg).is_err(),
        "negative lockfileVersion -1 must be rejected"
    );

    // Rejection 3: Negative float -2.0
    let json_neg_f = r#"{"name": "neg-f", "lockfileVersion": -2.0, "packages": { "": {} }}"#;
    assert!(
        LockfileV3::from_json_str(json_neg_f).is_err(),
        "negative lockfileVersion -2.0 must be rejected"
    );
}

// =========================================================================
// 10. Workspace Metadata Drift Differential Regressions (CP2 Swarm Lane C)
// =========================================================================

#[test]
fn test_matches_manifest_ext_absent_root_workspace_metadata_v3_omission() {
    let manifest = Manifest {
        name: Some("ws-monorepo".to_string()),
        version: Some("1.0.0".to_string()),
        workspaces: Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
            "packages/*".to_string(),
        ])),
        ..Default::default()
    };

    // npm v3 lockfile where root package "" omitted `workspaces` metadata
    let mut lockfile = LockfileV3::new("ws-monorepo", Some("1.0.0".to_string()));
    assert!(
        lockfile.root_package().unwrap().workspaces.is_none(),
        "root_pkg.workspaces must be None (omitted root metadata)"
    );

    // Lockfile contains discovered workspace members and available links
    lockfile.insert_package(
        "packages/member-a",
        LockfilePackage {
            name: Some("member-a".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "packages/member-b",
        LockfilePackage {
            name: Some("member-b".to_string()),
            version: Some("2.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/member-a",
        LockfilePackage {
            resolved: Some("packages/member-a".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/member-b",
        LockfilePackage {
            resolved: Some("packages/member-b".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );

    // 1. Must match successfully despite absent root workspace metadata (P1 bug fix)
    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "v3 lockfile with omitted root workspaces metadata must validate via discovered members and available links"
    );

    // 2. Genuine drift: workspace patterns changed to an unrelated pattern
    let mut drifted_patterns = manifest.clone();
    drifted_patterns.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "apps/*".to_string(),
    ]));
    assert!(
        !lockfile.matches_manifest_ext(&drifted_patterns, true, false),
        "must detect genuine drift when workspace patterns change"
    );

    // 3. Genuine drift: member-b removed from manifest workspace patterns
    let mut drifted_subset = manifest.clone();
    drifted_subset.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "packages/member-a".to_string(),
    ]));
    assert!(
        !lockfile.matches_manifest_ext(&drifted_subset, true, false),
        "must detect genuine drift when a member package in lockfile no longer matches workspace patterns"
    );

    // 4. Genuine drift: workspaces removed from manifest
    let mut drifted_no_ws = manifest.clone();
    drifted_no_ws.workspaces = None;
    assert!(
        !lockfile.matches_manifest_ext(&drifted_no_ws, true, false),
        "must detect genuine drift when workspaces field is deleted from package.json"
    );
}

#[test]
fn test_matches_manifest_ext_absent_root_workspace_metadata_legacy_v1_lock() {
    let mut manifest = Manifest {
        name: Some("v1-ws-root".to_string()),
        version: Some("1.0.0".to_string()),
        workspaces: Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
            "packages/*".to_string(),
        ])),
        ..Default::default()
    };
    manifest
        .dependencies
        .insert("pkg-x".to_string(), "file:packages/pkg-x".to_string());
    manifest
        .dependencies
        .insert("pkg-y".to_string(), "file:packages/pkg-y".to_string());

    // Migrated npm v1 lockfile: root package "" has no workspaces metadata
    let mut lockfile = LockfileV3::new("v1-ws-root", Some("1.0.0".to_string()));
    assert!(lockfile.root_package().unwrap().workspaces.is_none());
    let mut root_deps = BTreeMap::new();
    root_deps.insert("pkg-x".to_string(), "file:packages/pkg-x".to_string());
    root_deps.insert("pkg-y".to_string(), "file:packages/pkg-y".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(root_deps);

    // Legacy v1 dependency entries migrated to node_modules/ with file: targets
    lockfile.insert_package(
        "node_modules/pkg-x",
        LockfilePackage {
            version: Some("file:packages/pkg-x".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/pkg-y",
        LockfilePackage {
            version: Some("file:packages/pkg-y".to_string()),
            ..Default::default()
        },
    );

    // 1. Must validate legacy lock via available links matching workspace patterns
    assert!(
        lockfile.matches_manifest_ext(&manifest, true, false),
        "legacy v1 lockfile must match via available file: links"
    );

    // 2. Genuine drift: patterns changed in manifest
    let mut drifted = manifest.clone();
    drifted.workspaces = Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
        "components/*".to_string(),
    ]));
    assert!(
        !lockfile.matches_manifest_ext(&drifted, true, false),
        "must detect genuine drift when workspace pattern does not match legacy links"
    );

    // 3. Genuine drift: workspaces removed
    let mut no_ws = manifest.clone();
    no_ws.workspaces = None;
    no_ws.dependencies.clear();
    assert!(
        !lockfile.matches_manifest_ext(&no_ws, true, false),
        "must detect genuine drift when workspaces removed from manifest"
    );
}

#[test]
fn test_matches_manifest_ext_workspace_drift_empty_lockfile_with_absent_metadata_fails() {
    let manifest = Manifest {
        name: Some("empty-ws-root".to_string()),
        version: Some("1.0.0".to_string()),
        workspaces: Some(rnpm_core::manifest::PackageWorkspaces::List(vec![
            "packages/*".to_string(),
        ])),
        ..Default::default()
    };

    // Lockfile with absent root workspaces and no workspace members or links
    let mut lockfile = LockfileV3::new("empty-ws-root", Some("1.0.0".to_string()));
    lockfile.insert_package(
        "node_modules/lodash",
        LockfilePackage {
            version: Some("4.17.21".to_string()),
            resolved: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
            ..Default::default()
        },
    );

    assert!(
        !lockfile.matches_manifest_ext(&manifest, true, false),
        "lockfile lacking both root workspaces and any workspace members/links must trigger drift detection"
    );
}

#[test]
fn test_matches_manifest_ext_workspace_drift_discovered_disk_members_differential() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root_path = temp_dir.path();

    // Setup root package.json
    let root_pkg_json = r#"{
        "name": "disk-ws-test",
        "version": "1.0.0",
        "workspaces": ["packages/*"]
    }"#;
    std::fs::write(root_path.join("package.json"), root_pkg_json).unwrap();

    // Setup member packages on disk
    std::fs::create_dir_all(root_path.join("packages/pkg-a")).unwrap();
    std::fs::write(
        root_path.join("packages/pkg-a/package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0"}"#,
    )
    .unwrap();

    std::fs::create_dir_all(root_path.join("packages/pkg-b")).unwrap();
    std::fs::write(
        root_path.join("packages/pkg-b/package.json"),
        r#"{"name": "pkg-b", "version": "1.0.0"}"#,
    )
    .unwrap();

    let manifest = Manifest::from_file(root_path.join("package.json")).unwrap();

    // Lockfile with absent root workspaces metadata but matching members
    let mut lockfile = LockfileV3::new("disk-ws-test", Some("1.0.0".to_string()));
    lockfile.insert_package(
        "packages/pkg-a",
        LockfilePackage {
            name: Some("pkg-a".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "packages/pkg-b",
        LockfilePackage {
            name: Some("pkg-b".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/pkg-a",
        LockfilePackage {
            resolved: Some("packages/pkg-a".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/pkg-b",
        LockfilePackage {
            resolved: Some("packages/pkg-b".to_string()),
            link: Some(true),
            ..Default::default()
        },
    );

    // 1. Initial matching members pass when supplied explicitly (no ambient CWD lookup)
    let initial_members =
        rnpm_core::workspace::discover_workspaces_from_manifest(root_path, &manifest).unwrap();
    assert_eq!(initial_members.len(), 2);
    assert!(
        lockfile.matches_manifest_ext_with_workspaces(&manifest, true, false, Some(&initial_members)),
        "must match when discovered disk members match lockfile members"
    );

    // 2. Unhoisted workspace dependency must NOT trigger false drift (Round 1 Finding 1 regression)
    let mut lockfile_with_unhoisted = lockfile.clone();
    lockfile_with_unhoisted.insert_package(
        "packages/pkg-a/node_modules/nested-dep",
        LockfilePackage {
            version: Some("1.2.3".to_string()),
            resolved: Some("https://registry.npmjs.org/nested-dep/-/nested-dep-1.2.3.tgz".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile_with_unhoisted.matches_manifest_ext_with_workspaces(
            &manifest,
            true,
            false,
            Some(&initial_members),
        ),
        "unhoisted package inside workspace member node_modules must not cause false ELOCKFILE_DRIFT"
    );

    // 3. Add a new workspace member pkg-c on disk (not in lockfile) -> must trigger drift!
    std::fs::create_dir_all(root_path.join("packages/pkg-c")).unwrap();
    std::fs::write(
        root_path.join("packages/pkg-c/package.json"),
        r#"{"name": "pkg-c", "version": "1.0.0"}"#,
    )
    .unwrap();

    let members_with_c =
        rnpm_core::workspace::discover_workspaces_from_manifest(root_path, &manifest).unwrap();
    assert_eq!(members_with_c.len(), 3);
    assert!(
        !lockfile.matches_manifest_ext_with_workspaces(&manifest, true, false, Some(&members_with_c)),
        "must detect genuine drift when a new member is added to disk but missing from lockfile"
    );

    // 4. Remove pkg-c, and remove pkg-b from disk (still in lockfile) -> must trigger drift!
    std::fs::remove_dir_all(root_path.join("packages/pkg-c")).unwrap();
    std::fs::remove_dir_all(root_path.join("packages/pkg-b")).unwrap();

    let members_without_b =
        rnpm_core::workspace::discover_workspaces_from_manifest(root_path, &manifest).unwrap();
    assert_eq!(members_without_b.len(), 1);
    assert!(
        !lockfile.matches_manifest_ext_with_workspaces(
            &manifest,
            true,
            false,
            Some(&members_without_b),
        ),
        "must detect genuine drift when a member in lockfile is deleted from disk"
    );

    // 5. Remove pkg-a as well: all workspace members deleted from disk (Round 1 Finding 2 regression)
    std::fs::remove_dir_all(root_path.join("packages/pkg-a")).unwrap();
    let empty_members =
        rnpm_core::workspace::discover_workspaces_from_manifest(root_path, &manifest).unwrap();
    assert!(empty_members.is_empty(), "all workspace members on disk deleted");
    assert!(
        !lockfile.matches_manifest_ext_with_workspaces(&manifest, true, false, Some(&empty_members)),
        "must detect drift for stale lockfile members when all workspace packages are deleted from disk"
    );

    // 6. Explicitly empty discovered members with an empty lockfile matches
    let empty_lockfile = LockfileV3::new("disk-ws-test", Some("1.0.0".to_string()));
    assert!(
        empty_lockfile.matches_manifest_ext_with_workspaces(
            &manifest,
            true,
            false,
            Some(&empty_members),
        ),
        "clean empty lockfile matches explicitly empty discovered workspace members"
    );

    // 7. Discovery unavailable (None) uses in-memory patterns
    assert!(
        lockfile.matches_manifest_ext_with_workspaces(&manifest, true, false, None),
        "lockfile with matching members validates against patterns when discovery is unavailable"
    );
    assert!(
        !empty_lockfile.matches_manifest_ext_with_workspaces(&manifest, true, false, None),
        "empty lockfile with omitted root metadata fails when discovery is unavailable"
    );
}

#[test]
fn test_path_matches_workspace_patterns_comprehensive() {
    let patterns = vec![
        "packages/*".to_string(),
        "apps/**".to_string(),
        "modules/**/pkg".to_string(),
        "tools/cli".to_string(),
        "!packages/ignored".to_string(),
    ];

    // Single wildcard match
    assert!(LockfileV3::path_matches_workspace_patterns("packages/pkg-a", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("packages/pkg-b", &patterns));
    assert!(!LockfileV3::path_matches_workspace_patterns("packages/nested/pkg", &patterns));
    assert!(!LockfileV3::path_matches_workspace_patterns("packages", &patterns));

    // Recursive wildcard match
    assert!(LockfileV3::path_matches_workspace_patterns("apps/web", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("apps/mobile/ios", &patterns));

    // Non-trailing ** (Round 1 Finding 4 parity)
    assert!(LockfileV3::path_matches_workspace_patterns("modules/pkg", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("modules/a/pkg", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("modules/a/b/pkg", &patterns));

    // Exact path match
    assert!(LockfileV3::path_matches_workspace_patterns("tools/cli", &patterns));
    assert!(!LockfileV3::path_matches_workspace_patterns("tools/other", &patterns));

    // Negative pattern exclusion
    assert!(!LockfileV3::path_matches_workspace_patterns("packages/ignored", &patterns));

    // Excluded directory segments (node_modules)
    assert!(!LockfileV3::path_matches_workspace_patterns(
        "packages/pkg-a/node_modules/dep",
        &patterns
    ));

    // Normalization (leading ./, backslashes, trailing /)
    assert!(LockfileV3::path_matches_workspace_patterns("./packages/pkg-a", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("packages\\pkg-a", &patterns));
    assert!(LockfileV3::path_matches_workspace_patterns("packages/pkg-a/", &patterns));
}

#[test]
fn test_engine_non_ascii_whitespace_boundary_no_panic() {
    // Non-ASCII whitespace characters like U+00A0 (NBSP, 2 bytes) and U+3000 (ideographic space, 3 bytes)
    // should not cause byte-indexing panics on character boundaries.
    let json = r#"{
        "name": "engine-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "engine-test",
                "version": "1.0.0",
                "engines": [
                    "node\u00A0>=18.0.0",
                    "npm\u3000>=9.0.0"
                ]
            }
        }
    }"#;

    let lock: LockfileV3 = serde_json::from_str(json).expect("Must parse engines with non-ASCII whitespace without panic");
    let root = lock.packages.get("").expect("Root package must exist");
    let map = root.engines_map().expect("Engines map must parse");
    assert_eq!(map.get("node").map(|s| s.as_str()), Some(">=18.0.0"));
    assert_eq!(map.get("npm").map(|s| s.as_str()), Some(">=9.0.0"));
}

#[test]
fn test_license_deserialization_shapes() {
    let json = r#"{
        "name": "license-shapes",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/obj-lic": {
                "version": "1.0.0",
                "license": { "type": "MIT", "url": "https://example.com" }
            },
            "node_modules/name-lic": {
                "version": "1.0.0",
                "license": { "name": "Apache-2.0" }
            },
            "node_modules/arr-lic": {
                "version": "1.0.0",
                "license": ["MIT", "Apache-2.0"]
            },
            "node_modules/str-lic": {
                "version": "1.0.0",
                "license": "BSD-3-Clause"
            }
        }
    }"#;

    let lock: LockfileV3 = serde_json::from_str(json).expect("Must parse object and array license shapes");
    assert_eq!(lock.packages.get("node_modules/obj-lic").unwrap().license.as_deref(), Some("MIT"));
    assert_eq!(lock.packages.get("node_modules/name-lic").unwrap().license.as_deref(), Some("Apache-2.0"));
    assert_eq!(lock.packages.get("node_modules/arr-lic").unwrap().license.as_deref(), Some("MIT OR Apache-2.0"));
    assert_eq!(lock.packages.get("node_modules/str-lic").unwrap().license.as_deref(), Some("BSD-3-Clause"));
}

#[test]
fn test_integrity_and_shrinkwrap_aliases() {
    let json = r#"{
        "name": "alias-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/aliased-pkg": {
                "version": "1.0.0",
                "_integrity": "sha512-test==",
                "_hasShrinkwrap": true
            }
        }
    }"#;

    let lock: LockfileV3 = serde_json::from_str(json).expect("Must parse _integrity and _hasShrinkwrap aliases");
    let pkg = lock.packages.get("node_modules/aliased-pkg").unwrap();
    assert_eq!(pkg.integrity.as_deref(), Some("sha512-test=="));
    assert_eq!(pkg.has_shrinkwrap, Some(true));
}

#[test]
fn test_flag_mutations_clear_raw_value() {
    let json = r#"{
        "name": "raw-val-test",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/foo": {
                "version": "1.0.0",
                "dev": true
            }
        }
    }"#;

    let mut lock = LockfileV3::from_json_str(json).unwrap();
    let pkg = lock.packages.get_mut("node_modules/foo").unwrap();
    assert!(pkg.raw_value.is_some(), "from_json_str must cache raw_value");

    // Mutation via set_dev must clear raw_value
    pkg.set_dev(false);
    assert!(pkg.raw_value.is_none(), "set_dev must invalidate raw_value");

    let out_json = lock.to_json_string().unwrap();
    assert!(!out_json.contains("\"dev\": true"), "Output JSON must reflect mutated dev: false");
}

#[test]
fn test_to_legacy_dependencies_link_parity() {
    let mut lock = LockfileV3::new("link-test", Some("1.0.0".to_string()));
    lock.lockfile_version = 2;

    // Target workspace package
    let mut target = LockfilePackage {
        version: Some("1.2.3".to_string()),
        ..Default::default()
    };
    let mut target_deps = BTreeMap::new();
    target_deps.insert("chalk".to_string(), "^5.0.0".to_string());
    target.dependencies = Some(target_deps);
    lock.packages.insert("packages/my-ws".to_string(), target);

    // Symlink node
    let link_pkg = LockfilePackage {
        resolved: Some("packages/my-ws".to_string()),
        link: Some(true),
        dev: Some(true),
        ..Default::default()
    };
    lock.packages.insert("node_modules/my-ws".to_string(), link_pkg);

    let json = lock.to_json_string_version(2).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    let link_dep = &val["dependencies"]["my-ws"];
    assert_eq!(link_dep["version"], "file:packages/my-ws");
    assert!(link_dep.get("resolved").is_none(), "Link must NOT have resolved in legacy dependencies");
    assert!(link_dep.get("integrity").is_none(), "Link must NOT have integrity in legacy dependencies");
    assert!(link_dep.get("dev").is_none(), "Link must NOT have dev flag in legacy dependencies");
    assert_eq!(link_dep["requires"]["chalk"], "^5.0.0", "Link requires must be populated from target package");
}

#[test]
fn test_to_legacy_dependencies_requires_includes_optional_and_omits_dev_optional_when_dev() {
    let mut lock = LockfileV3::new("requires-test", Some("1.0.0".to_string()));
    lock.lockfile_version = 2;

    let mut pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        dev: Some(true),
        dev_optional: Some(true), // redundant flag with dev
        ..Default::default()
    };
    let mut deps = BTreeMap::new();
    deps.insert("dep-prod".to_string(), "1.0.0".to_string());
    pkg.dependencies = Some(deps);
    let mut opt_deps = BTreeMap::new();
    opt_deps.insert("dep-opt".to_string(), "2.0.0".to_string());
    pkg.optional_dependencies = Some(opt_deps);

    lock.packages.insert("node_modules/foo".to_string(), pkg);

    let json = lock.to_json_string_version(2).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    let foo = &val["dependencies"]["foo"];
    assert_eq!(foo["dev"], true);
    assert!(foo.get("devOptional").is_none(), "devOptional must be omitted when dev: true");
    assert_eq!(foo["requires"]["dep-prod"], "1.0.0");
    assert_eq!(foo["requires"]["dep-opt"], "2.0.0");
}

#[test]
fn test_v1_to_v3_directory_link_migration() {
    let v1_json = r#"{
        "name": "v1-link-test",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "local-ws": {
                "version": "file:packages/local-ws",
                "requires": {
                    "bar": "1.0.0"
                }
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("Must migrate v1 file: links to v3");
    let link = v3.packages.get("node_modules/local-ws").expect("Must create node_modules link entry");
    assert_eq!(link.link, Some(true));
    assert_eq!(link.resolved.as_deref(), Some("packages/local-ws"));
    assert!(link.version.is_none());

    let target = v3.packages.get("packages/local-ws").expect("Must create target entry for workspace link");
    assert_eq!(target.dependencies.as_ref().unwrap().get("bar").map(|s| s.as_str()), Some("1.0.0"));
}

#[test]
fn test_integrity_audit_aliased_direct_dependency() {
    let mut lock = LockfileV3::new("audit-alias-test", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    root_deps.insert("my-alias".to_string(), "npm:chalk@5.0.0".to_string());
    lock.root_package_mut().unwrap().dependencies = Some(root_deps);

    let mut pkg = LockfilePackage {
        name: Some("chalk".to_string()),
        version: Some("5.0.0".to_string()),
        resolved: Some("file:./local-chalk.tgz".to_string()),
        integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
        ..Default::default()
    };
    pkg.normalize_flags();
    lock.packages.insert("node_modules/my-alias".to_string(), pkg);

    let policy = IntegrityPolicy {
        allow_transitive_file: false, // Disallow transitive files, but direct files are allowed
        require_integrity: false,
        ..Default::default()
    };

    let res = verify_lockfile_integrity(&lock, &policy);
    assert!(res.is_ok(), "Aliased direct dependency must be recognized as direct");
}

#[test]
fn test_target_matches_resolved_path_boundary_no_false_positive() {
    let pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:packages/client-app".to_string()),
        ..Default::default()
    };
    // Spec asks for file:packages/app - should NOT match packages/client-app despite sharing suffix
    assert!(
        !LockfileV3::package_satisfies_spec("app", &pkg, "file:packages/app"),
        "client-app should not match app via bare substring suffix"
    );
    // Spec asks for file:packages/client-app - SHOULD match
    assert!(
        LockfileV3::package_satisfies_spec("client-app", &pkg, "file:packages/client-app"),
        "exact path match must succeed"
    );
}

#[test]
fn test_target_matches_resolved_relative_vs_relative_drift() {
    let pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:other/pkg".to_string()),
        ..Default::default()
    };
    // Drifted relative path file:./pkg vs file:other/pkg must NOT match
    assert!(
        !LockfileV3::package_satisfies_spec("pkg", &pkg, "file:./pkg"),
        "file:./pkg must not match drifted relative file:other/pkg"
    );
    // Relative paths with ./ or trailing slash matching normalized path
    let pkg_valid = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:pkg".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec("pkg", &pkg_valid, "file:./pkg/"),
        "file:./pkg/ must match file:pkg"
    );
    assert!(
        LockfileV3::package_satisfies_spec("pkg", &pkg_valid, "file:pkg"),
        "file:pkg must match file:pkg"
    );

    // Absolute path matches valid relative suffix
    let abs_pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("file:/workspace/project/packages/my-dep".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec("my-dep", &abs_pkg, "file:packages/my-dep"),
        "Absolute resolved path must match relative spec suffix"
    );
}

#[test]
fn test_git_shorthand_matches_full_resolved_urls() {
    let pkg_ssh = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+ssh://git@github.com/user/repo.git#1111111111111111111111111111111111111111".to_string()),
        ..Default::default()
    };
    let pkg_https = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+https://github.com/user/repo.git#1111111111111111111111111111111111111111".to_string()),
        ..Default::default()
    };

    // github: shorthand matches git+ssh and git+https
    assert!(
        LockfileV3::package_satisfies_spec("repo", &pkg_ssh, "github:user/repo"),
        "github:user/repo must match git+ssh"
    );
    assert!(
        LockfileV3::package_satisfies_spec("repo", &pkg_https, "github:user/repo"),
        "github:user/repo must match git+https"
    );

    // gitlab: shorthand matches git+https
    let gitlab_pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+https://gitlab.com/group/project.git#1111111111111111111111111111111111111111".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec("project", &gitlab_pkg, "gitlab:group/project"),
        "gitlab:group/project must match git+https"
    );

    // bitbucket: shorthand matches git+https
    let bb_pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+https://bitbucket.org/team/repo.git#1111111111111111111111111111111111111111".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec("repo", &bb_pkg, "bitbucket:team/repo"),
        "bitbucket:team/repo must match git+https"
    );

    // Rejects different repo
    assert!(
        !LockfileV3::package_satisfies_spec("repo", &pkg_ssh, "github:user/other"),
        "github:user/other must not match user/repo"
    );
}

#[test]
fn test_git_committish_drift_detected() {
    let pkg = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+https://github.com/org/repo.git#1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b".to_string()),
        ..Default::default()
    };
    // Spec with different committish
    assert!(
        !LockfileV3::package_satisfies_spec("repo", &pkg, "git+https://github.com/org/repo.git#2a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b"),
        "Mismatched committish must be detected as drift"
    );
    // Spec with matching committish (case-insensitive)
    assert!(
        LockfileV3::package_satisfies_spec("repo", &pkg, "git+https://github.com/org/repo.git#1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b"),
        "Matching committish must satisfy spec"
    );
    assert!(
        LockfileV3::package_satisfies_spec("repo", &pkg, "git+https://github.com/org/repo.git#1A2B3C4D5E6F1A2B3C4D5E6F1A2B3C4D5E6F1A2B"),
        "Case-insensitive committish must satisfy spec"
    );

    // 64-character SHA-256 committish
    let pkg_sha256 = LockfilePackage {
        version: Some("1.0.0".to_string()),
        resolved: Some("git+https://github.com/org/repo.git#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        ..Default::default()
    };
    assert!(
        LockfileV3::package_satisfies_spec("repo", &pkg_sha256, "git+https://github.com/org/repo.git#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "64-character SHA-256 case-insensitive committish must satisfy spec"
    );
    assert!(
        !LockfileV3::package_satisfies_spec("repo", &pkg_sha256, "git+https://github.com/org/repo.git#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        "Mismatched 64-char SHA-256 committish must be detected as drift"
    );
}

#[test]
fn test_symlink_drift_detection_with_link_flag() {
    let pkg = LockfilePackage {
        link: Some(true),
        resolved: Some("packages/local-a".to_string()),
        ..Default::default()
    };
    // Matching path
    assert!(
        LockfileV3::package_satisfies_spec("local-pkg", &pkg, "file:./packages/local-a"),
        "Matching symlink target must satisfy spec"
    );
    // Drifted path
    assert!(
        !LockfileV3::package_satisfies_spec("local-pkg", &pkg, "file:./packages/local-b"),
        "Drifted symlink target must be detected as drift even when link: true"
    );
}

#[test]
fn test_migration_symlink_omits_duplicated_dependencies() {
    let v1_json = r#"{
        "name": "v1-symlink-clean",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "my-link": {
                "version": "file:packages/my-link",
                "requires": {
                    "nested": "1.0.0"
                }
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("Must migrate v1 file: links");
    let link = v3.packages.get("node_modules/my-link").expect("Link node must exist");
    assert_eq!(link.link, Some(true));
    assert_eq!(link.resolved.as_deref(), Some("packages/my-link"));
    // Arborist parity: symlink node does not duplicate dependencies
    assert!(link.dependencies.is_none(), "Symlink node must not duplicate dependencies");

    let target = v3.packages.get("packages/my-link").expect("Target node must exist");
    assert_eq!(target.dependencies.as_ref().unwrap().get("nested").map(|s| s.as_str()), Some("1.0.0"));
}

#[test]
fn test_migration_file_dot_maps_to_root() {
    let v1_json = r#"{
        "name": "v1-self-link",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "self": {
                "version": "file:."
            }
        }
    }"#;

    let v3 = parse_and_migrate(v1_json).expect("Must migrate v1 file:. link");
    let link = v3.packages.get("node_modules/self").expect("Link node must exist");
    assert_eq!(link.link, Some(true));
    assert_eq!(link.resolved.as_deref(), Some(""));
}

#[test]
fn test_legacy_dependencies_windows_backslashes_in_link() {
    let mut lock = LockfileV3::new("win-link-test", Some("1.0.0".to_string()));
    lock.lockfile_version = 2;

    let mut target = LockfilePackage {
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    let mut deps = BTreeMap::new();
    deps.insert("chalk".to_string(), "5.0.0".to_string());
    target.dependencies = Some(deps);
    lock.packages.insert("packages/my-ws".to_string(), target);

    let link_pkg = LockfilePackage {
        resolved: Some("packages\\my-ws".to_string()),
        link: Some(true),
        ..Default::default()
    };
    lock.packages.insert("node_modules/my-ws".to_string(), link_pkg);

    let json = lock.to_json_string_version(2).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["dependencies"]["my-ws"]["requires"]["chalk"], "5.0.0");
}

#[test]
fn test_enrich_packages_from_legacy_clears_link_flags() {
    let v2_json = r#"{
        "name": "v2-link-flags",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "v2-link-flags",
                "version": "1.0.0"
            },
            "node_modules/my-link": {
                "resolved": "packages/my-link",
                "link": true
            }
        },
        "dependencies": {
            "my-link": {
                "version": "file:packages/my-link",
                "dev": true
            }
        }
    }"#;

    let v3 = parse_and_migrate(v2_json).expect("Must migrate v2 file: links");
    let link = v3.packages.get("node_modules/my-link").expect("Link node must exist");
    assert_eq!(link.link, Some(true));
    assert!(link.dev.is_none(), "Link node must not have dev flag");
}

// =========================================================================
// 12. Opus 5.5 Findings Regression Tests (Swarm Worker 17)
// =========================================================================

#[test]
fn test_opus_finding_1_non_registry_git_and_path_ref_flipping_drift() {
    // 1. user/repo#v1 -> user/repo#v2 drift
    let mut manifest_v1 = Manifest {
        name: Some("test-app".to_string()),
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    manifest_v1.dependencies.insert("shorthand-dep".to_string(), "foo/bar#v1".to_string());
    let mut lockfile = LockfileV3::from_manifest(&manifest_v1);
    lockfile.insert_package(
        "node_modules/shorthand-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile.matches_manifest_for_ci(&manifest_v1, true),
        "in-sync shorthand git dependency must pass CI"
    );
    let mut manifest_v2 = manifest_v1.clone();
    manifest_v2.dependencies.insert("shorthand-dep".to_string(), "foo/bar#v2".to_string());
    assert!(
        !lockfile.matches_manifest_for_ci(&manifest_v2, true),
        "user/repo#v1 -> #v2 must be detected as drift"
    );

    // 2. github:user/repo#v1 -> github:user/repo#v2 drift
    let mut manifest_gh1 = Manifest {
        name: Some("test-app".to_string()),
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    manifest_gh1.dependencies.insert("gh-dep".to_string(), "github:foo/bar#v1".to_string());
    let mut lockfile_gh = LockfileV3::from_manifest(&manifest_gh1);
    lockfile_gh.insert_package(
        "node_modules/gh-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile_gh.matches_manifest_for_ci(&manifest_gh1, true),
        "in-sync github: spec must pass CI"
    );
    let mut manifest_gh2 = manifest_gh1.clone();
    manifest_gh2.dependencies.insert("gh-dep".to_string(), "github:foo/bar#v2".to_string());
    assert!(
        !lockfile_gh.matches_manifest_for_ci(&manifest_gh2, true),
        "github:user/repo#v1 -> #v2 must be detected as drift"
    );

    // 3. gitlab:user/repo#v1 -> gitlab:user/repo#v2 drift
    let mut manifest_gl1 = Manifest {
        name: Some("test-app".to_string()),
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    manifest_gl1.dependencies.insert("gl-dep".to_string(), "gitlab:foo/bar#v1".to_string());
    let mut lockfile_gl = LockfileV3::from_manifest(&manifest_gl1);
    lockfile_gl.insert_package(
        "node_modules/gl-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+https://gitlab.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile_gl.matches_manifest_for_ci(&manifest_gl1, true),
        "in-sync gitlab: spec must pass CI"
    );
    let mut manifest_gl2 = manifest_gl1.clone();
    manifest_gl2.dependencies.insert("gl-dep".to_string(), "gitlab:foo/bar#v2".to_string());
    assert!(
        !lockfile_gl.matches_manifest_for_ci(&manifest_gl2, true),
        "gitlab:user/repo#v1 -> #v2 must be detected as drift"
    );

    // 4. git@github.com:user/repo#v1 -> git@github.com:user/repo#v2 drift
    let mut manifest_ssh1 = Manifest {
        name: Some("test-app".to_string()),
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    manifest_ssh1.dependencies.insert("ssh-dep".to_string(), "git@github.com:foo/bar.git#v1".to_string());
    let mut lockfile_ssh = LockfileV3::from_manifest(&manifest_ssh1);
    lockfile_ssh.insert_package(
        "node_modules/ssh-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile_ssh.matches_manifest_for_ci(&manifest_ssh1, true),
        "in-sync git@host spec must pass CI"
    );
    let mut manifest_ssh2 = manifest_ssh1.clone();
    manifest_ssh2.dependencies.insert("ssh-dep".to_string(), "git@github.com:foo/bar.git#v2".to_string());
    assert!(
        !lockfile_ssh.matches_manifest_for_ci(&manifest_ssh2, true),
        "git@host#v1 -> #v2 must be detected as drift"
    );

    // 5. Local path ./a -> ./b drift
    let mut manifest_path_a = Manifest {
        name: Some("test-app".to_string()),
        version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    manifest_path_a.dependencies.insert("local-dep".to_string(), "./a".to_string());
    let mut lockfile_path = LockfileV3::from_manifest(&manifest_path_a);
    lockfile_path.insert_package(
        "node_modules/local-dep",
        LockfilePackage {
            version: Some("file:./a".to_string()),
            resolved: Some("file:./a".to_string()),
            ..Default::default()
        },
    );
    assert!(
        lockfile_path.matches_manifest_for_ci(&manifest_path_a, true),
        "in-sync ./a spec must pass CI"
    );
    let mut manifest_path_b = manifest_path_a.clone();
    manifest_path_b.dependencies.insert("local-dep".to_string(), "./b".to_string());
    assert!(
        !lockfile_path.matches_manifest_for_ci(&manifest_path_b, true),
        "./a -> ./b path change must be detected as drift"
    );
}

#[test]
fn test_opus_finding_1_canonical_matching_non_registry_specs_pass_ci() {
    let manifest = Manifest {
        name: Some("canon-app".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: {
            let mut m = BTreeMap::new();
            // Manifest uses shorthand foo/bar#v1
            m.insert("git-dep".to_string(), "foo/bar#v1".to_string());
            // Manifest uses bare relative path ./local-pkg
            m.insert("file-dep".to_string(), "./local-pkg".to_string());
            // Manifest uses npm alias with git target
            m.insert("alias-dep".to_string(), "npm:real-dep@foo/bar#v1".to_string());
            m
        },
        ..Default::default()
    };

    let mut lockfile = LockfileV3::new("canon-app", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    // Lockfile root has github: expansion
    root_deps.insert("git-dep".to_string(), "github:foo/bar#v1".to_string());
    // Lockfile root has file: prefix
    root_deps.insert("file-dep".to_string(), "file:./local-pkg".to_string());
    // Lockfile root has npm alias with github: expansion
    root_deps.insert("alias-dep".to_string(), "npm:real-dep@github:foo/bar#v1".to_string());
    lockfile.root_package_mut().unwrap().dependencies = Some(root_deps);

    lockfile.insert_package(
        "node_modules/git-dep",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/file-dep",
        LockfilePackage {
            version: Some("file:./local-pkg".to_string()),
            resolved: Some("file:./local-pkg".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/alias-dep",
        LockfilePackage {
            name: Some("real-dep".to_string()),
            version: Some("1.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/foo/bar.git#7971714392a83cfd5d0eb871638ecf15b8822557".to_string()),
            ..Default::default()
        },
    );

    assert!(
        lockfile.matches_manifest_for_ci(&manifest, true),
        "canonically identical non-registry specs (shorthand vs expanded, ./ vs file:./) must pass CI"
    );
}

#[test]
fn test_opus_bonus_finding_is_direct_dependency_aliased_and_hoisted() {
    let mut lock = LockfileV3::new("bonus-test", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    root_deps.insert("real-pkg".to_string(), "^1.0.0".to_string());
    root_deps.insert("my-alias".to_string(), "npm:real-pkg@^2.0.0".to_string());
    lock.root_package_mut().unwrap().dependencies = Some(root_deps);

    // Direct dependency 1: node_modules/real-pkg
    lock.insert_package(
        "node_modules/real-pkg",
        LockfilePackage {
            name: Some("real-pkg".to_string()),
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/real-pkg/-/real-pkg-1.0.0.tgz".to_string()),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            ..Default::default()
        },
    );

    // Direct dependency 2: node_modules/my-alias (aliased to real-pkg)
    lock.insert_package(
        "node_modules/my-alias",
        LockfilePackage {
            name: Some("real-pkg".to_string()),
            version: Some("2.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/real-pkg/-/real-pkg-2.0.0.tgz".to_string()),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            ..Default::default()
        },
    );

    // Transitive dependency: node_modules/transitive-evil
    // Its internal name happens to be "real-pkg", but it is installed at "node_modules/transitive-evil"
    // and uses an untrusted git source!
    lock.insert_package(
        "node_modules/transitive-evil",
        LockfilePackage {
            name: Some("real-pkg".to_string()),
            version: Some("3.0.0".to_string()),
            resolved: Some("git+https://github.com/evil/real-pkg.git#1111111111111111111111111111111111111111".to_string()),
            integrity: Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string()),
            ..Default::default()
        },
    );

    let policy = IntegrityPolicy {
        allow_transitive_git: false,
        ..Default::default()
    };

    let res = verify_lockfile_integrity(&lock, &policy);
    assert!(
        res.is_err(),
        "transitive package in node_modules/transitive-evil must NOT be misclassified as direct dependency just because its name is 'real-pkg'"
    );

    match res.unwrap_err() {
        LockfileError::PoisonedDependency { package, reason } => {
            assert_eq!(package, "node_modules/transitive-evil");
            assert!(reason.contains("untrusted git source"), "reason was: {reason}");
        }
        other => panic!("expected PoisonedDependency error, got: {other:?}"),
    }
}
