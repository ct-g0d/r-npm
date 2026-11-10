//! Lockfile parsing, generation, migration, and deterministic serialization for rnpm.
//!
//! Implements npm lockfile version 3 model with deterministic sorted keys,
//! POSIX forward-slash path keys, flag preservation (dev, optional, inBundle, hasInstallScript),
//! and full migration support for legacy lockfile v1 and v2 formats.

#![allow(
    clippy::too_many_arguments,
    clippy::collapsible_match,
    clippy::field_reassign_with_default
)]

pub mod error;
pub mod integrity;
pub mod migration;
pub mod model;

pub use error::LockfileError;
pub use integrity::{verify_lockfile_integrity, IntegrityPolicy, LockfileIntegrityChecker};
pub use migration::{
    load_and_migrate, migrate_to_v3, parse_and_migrate, AnyLockfile, LegacyDependency,
};
pub use model::{LockfilePackage, LockfileV3, PackageBin, PackageEngines};
pub use rnpm_core::manifest::BundledDependencies;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const VALID_SHA512: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const VALID_SHA1: &str = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn test_lockfile_v3_deterministic_serialization() {
        let mut lockfile = LockfileV3::new("my-app", Some("1.0.0".to_string()));

        // Insert in reverse alphabetical order to verify BTreeMap sorts them deterministically
        let mut pkg_z = LockfilePackage {
            version: Some("2.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/z/-/z-2.0.0.tgz".to_string()),
            integrity: Some("sha512-zzz".to_string()),
            dev: Some(true),
            optional: Some(false), // should be omitted
            has_install_script: Some(true),
            ..Default::default()
        };
        let mut z_deps = BTreeMap::new();
        z_deps.insert("a".to_string(), "^1.0.0".to_string());
        pkg_z.dependencies = Some(z_deps);

        let pkg_a = LockfilePackage {
            version: Some("1.1.0".to_string()),
            resolved: Some("https://registry.npmjs.org/a/-/a-1.1.0.tgz".to_string()),
            integrity: Some("sha512-aaa".to_string()),
            in_bundle: Some(true),
            ..Default::default()
        };

        // Note: intentionally using Windows backslashes to test POSIX conversion
        lockfile.insert_package("node_modules\\z", pkg_z);
        lockfile.insert_package("node_modules\\a", pkg_a);

        let json1 = lockfile.to_json_string().unwrap();
        let json2 = lockfile.to_json_string().unwrap();

        // Deterministic output
        assert_eq!(json1, json2);
        assert!(json1.ends_with('\n'), "Must terminate with newline");

        // Verify key ordering: "" comes before "node_modules/a", which comes before "node_modules/z"
        let pos_root = json1.find("\"\"").unwrap();
        let pos_a = json1.find("\"node_modules/a\"").unwrap();
        let pos_z = json1.find("\"node_modules/z\"").unwrap();
        assert!(pos_root < pos_a);
        assert!(pos_a < pos_z);

        // Verify POSIX paths (no backslashes in package keys)
        assert!(!json1.contains("node_modules\\\\a"));
        assert!(!json1.contains("node_modules\\a"));

        // Verify flags: "dev": true and "hasInstallScript": true are present
        assert!(json1.contains("\"dev\": true"));
        assert!(json1.contains("\"hasInstallScript\": true"));
        assert!(json1.contains("\"inBundle\": true"));

        // Verify false boolean is omitted
        assert!(!json1.contains("\"optional\": false"));

        // Parse back and verify round-trip
        let parsed = LockfileV3::from_json_str(&json1).unwrap();
        assert_eq!(parsed.name, "my-app");
        assert_eq!(parsed.lockfile_version, 3);
        assert_eq!(parsed.packages.len(), 3);
        assert!(parsed.packages.contains_key(""));
        assert!(parsed.packages.contains_key("node_modules/a"));
        assert!(parsed.packages.contains_key("node_modules/z"));
    }

    #[test]
    fn test_migrate_lockfile_v1_to_v3() {
        let v1_json = r#"{
            "name": "legacy-app",
            "version": "0.1.0",
            "lockfileVersion": 1,
            "requires": true,
            "dependencies": {
                "parent-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/parent-pkg/-/parent-pkg-1.0.0.tgz",
                    "integrity": "sha512-parent123",
                    "dev": true,
                    "requires": {
                        "child-pkg": "^2.0.0"
                    },
                    "dependencies": {
                        "child-pkg": {
                            "version": "2.0.0",
                            "resolved": "https://registry.npmjs.org/child-pkg/-/child-pkg-2.0.0.tgz",
                            "integrity": "sha512-child123"
                        }
                    }
                }
            }
        }"#;

        let migrated = parse_and_migrate(v1_json).unwrap();
        assert_eq!(migrated.name, "legacy-app");
        assert_eq!(migrated.version, Some("0.1.0".to_string()));
        assert_eq!(migrated.lockfile_version, 3);

        // Verify root package "" exists
        let root = migrated.packages.get("").expect("Root package missing");
        assert_eq!(root.name, Some("legacy-app".to_string()));
        let root_deps = root.dependencies.as_ref().unwrap();
        assert_eq!(root_deps.get("parent-pkg"), Some(&"1.0.0".to_string()));

        // Verify flattened node_modules/parent-pkg
        let parent = migrated
            .packages
            .get("node_modules/parent-pkg")
            .expect("node_modules/parent-pkg missing");
        assert_eq!(parent.version, Some("1.0.0".to_string()));
        assert_eq!(parent.integrity, Some("sha512-parent123".to_string()));
        assert_eq!(parent.dev, Some(true));

        // Verify nested child flattened to node_modules/parent-pkg/node_modules/child-pkg
        let child = migrated
            .packages
            .get("node_modules/parent-pkg/node_modules/child-pkg")
            .expect("Nested child missing");
        assert_eq!(child.version, Some("2.0.0".to_string()));
        assert_eq!(child.integrity, Some("sha512-child123".to_string()));
    }

    #[test]
    fn test_migrate_lockfile_v2_to_v3() {
        let v2_json = r#"{
            "name": "v2-app",
            "version": "2.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": {
                    "name": "v2-app",
                    "version": "2.0.0",
                    "dependencies": {
                        "dep-one": "^1.0.0"
                    }
                },
                "node_modules/dep-one": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/dep-one/-/dep-one-1.0.0.tgz",
                    "integrity": "sha512-one123"
                }
            },
            "dependencies": {
                "dep-one": {
                    "version": "1.0.0"
                }
            }
        }"#;

        let migrated = parse_and_migrate(v2_json).unwrap();
        assert_eq!(migrated.lockfile_version, 3);
        assert_eq!(migrated.name, "v2-app");
        assert_eq!(migrated.packages.len(), 2);
        assert!(migrated.packages.contains_key(""));
        assert!(migrated.packages.contains_key("node_modules/dep-one"));

        // Serialization must not contain the legacy "dependencies" top-level block
        let serialized = migrated.to_json_string().unwrap();
        let parsed_raw: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert!(parsed_raw.get("dependencies").is_none());
        assert!(parsed_raw.get("packages").is_some());
    }

    #[test]
    fn test_malformed_lockfiles_and_unsupported_versions() {
        // 1. Invalid JSON syntax
        let bad_json = "{ \"name\": \"broken\", \"lockfileVersion\": ";
        let res_bad = parse_and_migrate(bad_json);
        assert!(matches!(res_bad, Err(LockfileError::Json(_))));

        // 2. Empty string
        let res_empty = parse_and_migrate("");
        assert!(matches!(res_empty, Err(LockfileError::Json(_))));

        // 3. Unsupported version (e.g. 0, 4, 999)
        let res_v4 = parse_and_migrate(&v4_4_json(4));
        assert!(matches!(res_v4, Err(LockfileError::UnsupportedVersion(4))));

        let v0_json = r#"{ "name": "zero-app", "lockfileVersion": 0 }"#;
        let res_v0 = parse_and_migrate(v0_json);
        assert!(matches!(res_v0, Err(LockfileError::UnsupportedVersion(0))));
    }

    #[test]
    fn test_lockfile_matches_manifest() {
        use rnpm_core::Manifest;

        let mut lockfile = LockfileV3::new("test-pkg", Some("1.0.0".to_string()));
        let mut deps = BTreeMap::new();
        deps.insert("chalk".to_string(), "^5.0.0".to_string());
        deps.insert("debug".to_string(), "^4.3.0".to_string());

        let mut dev_deps = BTreeMap::new();
        dev_deps.insert("typescript".to_string(), "^5.0.0".to_string());

        if let Some(root) = lockfile.root_package_mut() {
            root.dependencies = Some(deps.clone());
            root.dev_dependencies = Some(dev_deps.clone());
        }

        // Insert packages in lockfile
        lockfile.insert_package(
            "node_modules/chalk",
            LockfilePackage {
                version: Some("5.3.0".to_string()),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/debug",
            LockfilePackage {
                version: Some("4.3.4".to_string()),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/typescript",
            LockfilePackage {
                version: Some("5.4.2".to_string()),
                ..Default::default()
            },
        );

        let mut manifest = Manifest::default();
        manifest.name = Some("test-pkg".to_string());
        manifest.dependencies = deps;
        manifest.dev_dependencies = dev_deps;

        // 1. Matches with dev dependencies
        assert!(lockfile.matches_manifest(&manifest, true));

        // 2. Spec mismatch in manifest
        let mut modified_manifest = manifest.clone();
        modified_manifest
            .dependencies
            .insert("chalk".to_string(), "^4.0.0".to_string());
        assert!(!lockfile.matches_manifest(&modified_manifest, true));

        // 3. Extra dependency in manifest
        let mut added_dep_manifest = manifest.clone();
        added_dep_manifest
            .dependencies
            .insert("semver".to_string(), "^7.0.0".to_string());
        assert!(!lockfile.matches_manifest(&added_dep_manifest, true));

        // 4. Missing package in packages map
        let mut broken_lockfile = lockfile.clone();
        broken_lockfile.packages.remove("node_modules/chalk");
        assert!(!broken_lockfile.matches_manifest(&manifest, true));

        // 5. Dev dependency mutated in manifest (e.g. range spec changed)
        let mut dev_mutated = manifest.clone();
        dev_mutated
            .dev_dependencies
            .insert("typescript".to_string(), "^5.5.0".to_string());
        assert!(
            !lockfile.matches_manifest(&dev_mutated, true),
            "Must detect mutated devDependencies"
        );

        // 6. Dev dependency deleted from manifest but still present in lockfile
        let mut dev_deleted = manifest.clone();
        dev_deleted.dev_dependencies.remove("typescript");
        assert!(
            !lockfile.matches_manifest(&dev_deleted, true),
            "Must detect deleted devDependency"
        );

        // 7. Production dependency deleted from manifest but present in lockfile
        let mut dep_deleted = manifest.clone();
        dep_deleted.dependencies.remove("debug");
        assert!(
            !lockfile.matches_manifest(&dep_deleted, true),
            "Must detect deleted dependency"
        );

        // 8. Dependency version in packages map does not satisfy manifest spec
        let mut unsatisfied_lockfile = lockfile.clone();
        unsatisfied_lockfile
            .packages
            .get_mut("node_modules/debug")
            .unwrap()
            .version = Some("3.2.0".to_string());
        assert!(
            !unsatisfied_lockfile.matches_manifest(&manifest, true),
            "Must detect unsatisfying package version"
        );
    }

    #[test]
    fn test_bidirectional_drift_detection_comprehensive() {
        use rnpm_core::Manifest;

        let mut lockfile = LockfileV3::new("drift-app", Some("1.0.0".to_string()));
        let mut deps = BTreeMap::new();
        deps.insert("express".to_string(), "^4.18.0".to_string());
        let mut dev_deps = BTreeMap::new();
        dev_deps.insert("vitest".to_string(), "^1.0.0".to_string());
        let mut opt_deps = BTreeMap::new();
        opt_deps.insert("fsevents".to_string(), "~2.3.2".to_string());

        if let Some(root) = lockfile.root_package_mut() {
            root.dependencies = Some(deps.clone());
            root.dev_dependencies = Some(dev_deps.clone());
            root.optional_dependencies = Some(opt_deps.clone());
        }

        lockfile.insert_package(
            "node_modules/express",
            LockfilePackage {
                version: Some("4.18.2".to_string()),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/vitest",
            LockfilePackage {
                version: Some("1.2.0".to_string()),
                dev: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/fsevents",
            LockfilePackage {
                version: Some("2.3.3".to_string()),
                optional: Some(true),
                ..Default::default()
            },
        );

        let mut manifest = Manifest::default();
        manifest.name = Some("drift-app".to_string());
        manifest.version = Some("1.0.0".to_string());
        manifest.dependencies = deps;
        manifest.dev_dependencies = dev_deps;
        manifest.optional_dependencies = opt_deps;

        // Baseline: perfectly in sync
        assert!(lockfile.matches_manifest(&manifest, true));

        // Case 1: devDependencies spec changed in package.json
        let mut m1 = manifest.clone();
        m1.dev_dependencies
            .insert("vitest".to_string(), "^2.0.0".to_string());
        assert!(
            !lockfile.matches_manifest(&m1, true),
            "Dev dependency range mutation must be detected"
        );

        // Case 2: devDependency removed from package.json
        let mut m2 = manifest.clone();
        m2.dev_dependencies.remove("vitest");
        assert!(
            !lockfile.matches_manifest(&m2, true),
            "Dev dependency removal must be detected"
        );

        // Case 3: prod dependency removed from package.json
        let mut m3 = manifest.clone();
        m3.dependencies.remove("express");
        assert!(
            !lockfile.matches_manifest(&m3, true),
            "Prod dependency removal must be detected"
        );

        // Case 4: optional dependency mutated in package.json
        let mut m4 = manifest.clone();
        m4.optional_dependencies
            .insert("fsevents".to_string(), "^3.0.0".to_string());
        assert!(
            !lockfile.matches_manifest(&m4, true),
            "Optional dependency mutation must be detected"
        );

        // Case 5: optional dependency removed from package.json
        let mut m5 = manifest.clone();
        m5.optional_dependencies.remove("fsevents");
        assert!(
            !lockfile.matches_manifest(&m5, true),
            "Optional dependency removal must be detected"
        );
    }

    #[test]
    fn hidden_lockfile_preserves_indent_and_newlines() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        std::fs::write(project.join("package.json"), "\u{feff}{\r\n\t\"name\": \"app\"\r\n}\r\n").unwrap();
        let lock = LockfileV3::new("app", None);
        lock.save_hidden(project).unwrap();
        let hidden = project.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
        let text = std::fs::read_to_string(&hidden).unwrap();
        assert!(text.starts_with("{\r\n\t\"name\""), "{text:?}");
        assert!(!text.starts_with('\u{feff}'));
        // Existing lockfile formatting wins over the manifest on subsequent saves.
        std::fs::write(&hidden, "{\n    \"name\": \"app\"\n}\n").unwrap();
        lock.save_hidden(project).unwrap();
        let text = std::fs::read_to_string(hidden).unwrap();
        assert!(text.starts_with("{\n    \"name\""), "{text:?}");
    }

    #[test]
    fn test_hidden_lockfile_roundtrip_and_extra_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project_dir = temp_dir.path();

        let mut lockfile = LockfileV3::new("hidden-test", Some("1.0.0".to_string()));
        let mut extra = BTreeMap::new();
        extra.insert(
            "funding".to_string(),
            serde_json::json!({
                "type": "opencollective",
                "url": "https://opencollective.com/test"
            }),
        );

        let pkg = LockfilePackage {
            version: Some("1.2.3".to_string()),
            extra,
            ..Default::default()
        };
        // Backslash key to test POSIX conversion
        lockfile.insert_package("node_modules\\custom-pkg", pkg);

        // Save hidden lockfile to project_dir/node_modules/.package-lock.json
        lockfile.save_hidden(project_dir).unwrap();

        let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
        assert!(hidden_path.exists());

        // Verify root "" package entry is omitted from raw JSON on disk and version is 3
        let raw_json = std::fs::read_to_string(&hidden_path).unwrap();
        let parsed_raw: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        assert!(
            parsed_raw.get("packages").unwrap().get("").is_none(),
            "Hidden lockfile node_modules/.package-lock.json must omit the root \"\" entry"
        );
        assert_eq!(
            parsed_raw.get("lockfileVersion").unwrap().as_u64().unwrap(),
            3,
            "Hidden lockfile must enforce lockfileVersion 3"
        );

        // Load hidden lockfile back
        let loaded = LockfileV3::load_hidden(project_dir).unwrap();
        assert_eq!(loaded.name, "hidden-test");
        assert!(
            !loaded.packages.contains_key(""),
            "Loaded hidden lockfile must not have root entry \"\""
        );
        assert!(loaded.packages.contains_key("node_modules/custom-pkg"));

        let loaded_pkg = loaded.packages.get("node_modules/custom-pkg").unwrap();
        assert_eq!(loaded_pkg.version.as_deref(), Some("1.2.3"));
        assert!(loaded_pkg.extra.contains_key("funding"));
        assert_eq!(
            loaded_pkg.extra.get("funding").unwrap(),
            &serde_json::json!({
                "type": "opencollective",
                "url": "https://opencollective.com/test"
            })
        );
    }

    #[test]
    fn test_hidden_lockfile_platform_skipped_and_field_order() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project_dir = temp_dir.path();

        let mut lockfile = LockfileV3::new("parity-test", Some("1.0.0".to_string()));

        // Incompatible optional package (should be omitted from hidden lockfile)
        let mut skipped_pkg = LockfilePackage {
            version: Some("2.3.2".to_string()),
            resolved: Some("https://registry.npmjs.org/skipped/-/skipped-2.3.2.tgz".to_string()),
            os: Some(vec!["non_existent_os_xyz_123".to_string()]),
            ..Default::default()
        };
        skipped_pkg.set_optional(true);
        lockfile.insert_package("node_modules/skipped-pkg", skipped_pkg);

        // Regular package with multiple fields to verify npm field ordering
        let mut deps = BTreeMap::new();
        deps.insert("dep-a".to_string(), "^1.0.0".to_string());
        let mut bin_map = BTreeMap::new();
        bin_map.insert("my-cli".to_string(), "bin/cli.js".to_string());
        let mut engines_map = BTreeMap::new();
        engines_map.insert("node".to_string(), ">=14".to_string());

        let regular_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/regular/-/regular-1.0.0.tgz".to_string()),
            integrity: Some("sha512-test".to_string()),
            license: Some("MIT".to_string()),
            dependencies: Some(deps),
            bin: Some(PackageBin::Map(bin_map)),
            engines: Some(PackageEngines::Map(engines_map)),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/regular-pkg", regular_pkg);

        // Save hidden lockfile
        lockfile.save_hidden(project_dir).unwrap();

        let hidden_path = project_dir.join(LockfileV3::HIDDEN_LOCKFILE_PATH);
        assert!(hidden_path.exists());

        let raw_json = std::fs::read_to_string(&hidden_path).unwrap();
        let parsed_raw: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        let packages = parsed_raw.get("packages").unwrap().as_object().unwrap();

        // 1. Platform-skipped optional package must NOT be present
        assert!(
            !packages.contains_key("node_modules/skipped-pkg"),
            "Platform-skipped optional package must be omitted from hidden lockfile"
        );

        // 2. Regular package must be present
        assert!(packages.contains_key("node_modules/regular-pkg"));

        // 3. Field order verification:
        // Top-level order: "name", "version", "lockfileVersion", "requires", "packages"
        let pos_name = raw_json.find("\"name\": \"parity-test\"").unwrap();
        let pos_ver = raw_json.find("\"version\": \"1.0.0\"").unwrap();
        let pos_lf = raw_json.find("\"lockfileVersion\": 3").unwrap();
        let pos_pkgs = raw_json.find("\"packages\": {").unwrap();
        assert!(pos_name < pos_ver);
        assert!(pos_ver < pos_lf);
        assert!(pos_lf < pos_pkgs);

        // In regular package:
        // Scalars ("version", "resolved", "integrity", "license") come before objects ("dependencies", "bin", "engines")
        let pos_license = raw_json.find("\"license\": \"MIT\"").unwrap();
        let pos_deps = raw_json.find("\"dependencies\": {").unwrap();
        let pos_bin = raw_json.find("\"bin\": {").unwrap();
        let pos_engines = raw_json.find("\"engines\": {").unwrap();
        assert!(
            pos_license < pos_deps,
            "license (scalar) must come before dependencies (object)"
        );
        assert!(pos_deps < pos_bin, "dependencies must come before bin");
        assert!(pos_bin < pos_engines, "bin must come before engines");
    }

    fn v4_4_json(ver: u32) -> String {
        format!(r#"{{ "name": "future-app", "lockfileVersion": {ver} }}"#)
    }

    #[test]
    fn test_peer_and_peer_optional_classification_roundtrip() {
        let mut lockfile = LockfileV3::new("peer-test-app", Some("1.0.0".to_string()));

        let peer_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            peer: Some(true),
            peer_optional: Some(false), // omitted
            ..Default::default()
        };
        let peer_opt_pkg = LockfilePackage {
            version: Some("2.0.0".to_string()),
            peer: Some(true),
            peer_optional: Some(true),
            ..Default::default()
        };

        lockfile.insert_package("node_modules/peer-pkg", peer_pkg);
        lockfile.insert_package("node_modules/peer-opt-pkg", peer_opt_pkg);

        let json = lockfile.to_json_string().unwrap();
        assert!(json.contains(r#""peer": true"#));
        assert!(json.contains(r#""peerOptional": true"#));

        let parsed: LockfileV3 = serde_json::from_str(&json).unwrap();
        let p1 = parsed.packages.get("node_modules/peer-pkg").unwrap();
        assert_eq!(p1.peer, Some(true));
        assert_eq!(p1.peer_optional, None);

        let p2 = parsed.packages.get("node_modules/peer-opt-pkg").unwrap();
        assert_eq!(p2.peer, Some(true));
        assert_eq!(p2.peer_optional, Some(true));
    }

    #[test]
    fn test_integrity_checker_clean_lockfile() {
        let mut lockfile = LockfileV3::new("my-clean-app", Some("1.0.0".to_string()));
        if let Some(root) = lockfile.root_package_mut() {
            let mut deps = BTreeMap::new();
            deps.insert("chalk".to_string(), "^5.0.0".to_string());
            root.dependencies = Some(deps);
        }

        let chalk_pkg = LockfilePackage {
            version: Some("5.3.0".to_string()),
            resolved: Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/chalk", chalk_pkg);

        let policy = IntegrityPolicy::default();
        let checker = LockfileIntegrityChecker::new(policy);
        assert!(checker.verify(&lockfile).is_ok());
    }

    #[test]
    fn test_integrity_checker_missing_integrity() {
        let mut lockfile = LockfileV3::new("missing-integrity-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz".to_string()),
            integrity: None,
            ..Default::default()
        };
        lockfile.insert_package("node_modules/foo", pkg);

        let res = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res, Err(LockfileError::MissingIntegrity(ref path)) if path == "node_modules/foo")
        );

        // Permissive allows missing integrity
        assert!(verify_lockfile_integrity(&lockfile, &IntegrityPolicy::permissive()).is_ok());
    }

    #[test]
    fn test_integrity_checker_weak_integrity_flagged() {
        let mut lockfile = LockfileV3::new("weak-hash-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/bar/-/bar-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA1.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/bar", pkg);

        let res = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res, Err(LockfileError::WeakIntegrity { ref package, ref algorithm, ref required })
            if package == "node_modules/bar" && algorithm == "sha1" && required == "sha512")
        );
    }

    #[test]
    fn test_integrity_checker_insecure_http_flagged() {
        let mut lockfile = LockfileV3::new("insecure-http-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("http://registry.npmjs.org/foo/-/foo-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/foo", pkg);

        let res = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res, Err(LockfileError::InsecureResolvedUrl { ref package, ref url })
            if package == "node_modules/foo" && url.starts_with("http://"))
        );

        // Allowed when configured
        let permissive_http = IntegrityPolicy::default().with_allow_insecure_http(true);
        assert!(verify_lockfile_integrity(&lockfile, &permissive_http).is_ok());
    }

    #[test]
    fn test_integrity_checker_poisoned_name_mismatch() {
        let mut lockfile = LockfileV3::new("poison-name-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/legit-pkg", pkg);

        let res = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res, Err(LockfileError::PoisonedDependency { ref package, .. })
            if package == "node_modules/legit-pkg")
        );
    }

    #[test]
    fn test_integrity_checker_poisoned_version_mismatch() {
        let mut lockfile = LockfileV3::new("poison-version-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://registry.npmjs.org/my-pkg/-/my-pkg-2.5.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/my-pkg", pkg);

        let res = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res, Err(LockfileError::PoisonedDependency { ref package, .. })
            if package == "node_modules/my-pkg")
        );
    }

    #[test]
    fn test_integrity_checker_poisoned_transitive_git_and_file() {
        let mut lockfile = LockfileV3::new("poison-transitive-app", Some("1.0.0".to_string()));
        if let Some(root) = lockfile.root_package_mut() {
            let mut deps = BTreeMap::new();
            deps.insert("direct-pkg".to_string(), "^1.0.0".to_string());
            root.dependencies = Some(deps);
        }

        // 1. Nested transitive git injection
        let trans_git = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("git+https://github.com/attacker/malicious.git".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/direct-pkg/node_modules/trans-git", trans_git);

        let res_git = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res_git, Err(LockfileError::PoisonedDependency { ref package, .. })
            if package == "node_modules/direct-pkg/node_modules/trans-git")
        );

        // 2. Nested transitive file injection
        let mut lockfile2 = LockfileV3::new("poison-file-app", Some("1.0.0".to_string()));
        let trans_file = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("file:../../exploit/payload".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile2.insert_package("node_modules/a/node_modules/b", trans_file);

        let res_file = verify_lockfile_integrity(&lockfile2, &IntegrityPolicy::default());
        assert!(
            matches!(res_file, Err(LockfileError::PoisonedDependency { ref package, .. })
            if package == "node_modules/a/node_modules/b")
        );
    }

    #[test]
    fn test_integrity_checker_suspicious_domain_and_spoofing() {
        let mut lockfile = LockfileV3::new("suspicious-domain-app", Some("1.0.0".to_string()));

        // Raw IP address
        let ip_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://192.168.1.100/foo/-/foo-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/foo", ip_pkg);

        let res_ip = verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default());
        assert!(
            matches!(res_ip, Err(LockfileError::SuspiciousResolution { ref package, .. })
            if package == "node_modules/foo")
        );

        // Userinfo spoofing
        let mut lockfile_spoof = LockfileV3::new("spoof-app", Some("1.0.0".to_string()));
        let spoof_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some(
                "https://registry.npmjs.org@evil-domain.com/bar/-/bar-1.0.0.tgz".to_string(),
            ),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile_spoof.insert_package("node_modules/bar", spoof_pkg);

        let res_spoof = verify_lockfile_integrity(&lockfile_spoof, &IntegrityPolicy::default());
        assert!(
            matches!(res_spoof, Err(LockfileError::SuspiciousResolution { ref package, .. })
            if package == "node_modules/bar")
        );

        // Allowed registries filter
        let mut lockfile_reg = LockfileV3::new("reg-filter-app", Some("1.0.0".to_string()));
        let reg_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            resolved: Some("https://unknown-registry.com/baz/-/baz-1.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile_reg.insert_package("node_modules/baz", reg_pkg);

        let policy = IntegrityPolicy::default()
            .with_allowed_registries(vec!["registry.npmjs.org".to_string()]);
        let res_reg = verify_lockfile_integrity(&lockfile_reg, &policy);
        assert!(
            matches!(res_reg, Err(LockfileError::SuspiciousResolution { ref package, .. })
            if package == "node_modules/baz")
        );
    }

    #[test]
    fn test_integrity_checker_scoped_package_tarball_matching() {
        let mut lockfile = LockfileV3::new("scoped-app", Some("1.0.0".to_string()));
        let pkg = LockfilePackage {
            name: Some("@babel/core".to_string()),
            version: Some("7.24.0".to_string()),
            resolved: Some("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz".to_string()),
            integrity: Some(VALID_SHA512.to_string()),
            ..Default::default()
        };
        lockfile.insert_package("node_modules/@babel/core", pkg);

        assert!(verify_lockfile_integrity(&lockfile, &IntegrityPolicy::default()).is_ok());
    }

    #[test]
    fn test_exact_v3_flag_combinations_serialization_deserialization() {
        let mut lockfile = LockfileV3::new("flag-matrix-app", Some("1.0.0".to_string()));

        // 1. dev only
        lockfile.insert_package(
            "node_modules/pkg-dev",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                dev: Some(true),
                ..Default::default()
            },
        );

        // 2. optional only
        lockfile.insert_package(
            "node_modules/pkg-opt",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                optional: Some(true),
                ..Default::default()
            },
        );

        // 3. dev + optional combined -> npm v9/v10 devOptional
        lockfile.insert_package(
            "node_modules/pkg-dev-opt",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                dev: Some(true),
                optional: Some(true),
                ..Default::default()
            },
        );

        // 4. explicit devOptional
        lockfile.insert_package(
            "node_modules/pkg-dev-opt-explicit",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                dev_optional: Some(true),
                ..Default::default()
            },
        );

        // 5. peer only
        lockfile.insert_package(
            "node_modules/pkg-peer",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                peer: Some(true),
                ..Default::default()
            },
        );

        // 6. peer + peerOptional
        lockfile.insert_package(
            "node_modules/pkg-peer-opt",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                peer: Some(true),
                peer_optional: Some(true),
                ..Default::default()
            },
        );

        // 7. inBundle
        lockfile.insert_package(
            "node_modules/pkg-bundled",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                in_bundle: Some(true),
                ..Default::default()
            },
        );

        // 8. hasInstallScript
        lockfile.insert_package(
            "node_modules/pkg-script",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                has_install_script: Some(true),
                ..Default::default()
            },
        );

        // 9. hasShrinkwrap
        lockfile.insert_package(
            "node_modules/pkg-shrinkwrap",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                has_shrinkwrap: Some(true),
                ..Default::default()
            },
        );

        // 10. multi-flag combo: bundled + devOptional + hasInstallScript
        lockfile.insert_package(
            "node_modules/pkg-multi",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                in_bundle: Some(true),
                dev: Some(true),
                optional: Some(true),
                has_install_script: Some(true),
                ..Default::default()
            },
        );

        let json = lockfile.to_json_string().unwrap();

        // Verify exact flag outputs
        assert!(json.contains("\"node_modules/pkg-dev\": {\n      \"version\": \"1.0.0\",\n      \"dev\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-opt\": {\n      \"version\": \"1.0.0\",\n      \"optional\": true\n    }"));

        // Combined dev + optional serializes as dev: true and optional: true (npm 11 parity)
        assert!(json.contains("\"node_modules/pkg-dev-opt\": {\n      \"version\": \"1.0.0\",\n      \"dev\": true,\n      \"optional\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-dev-opt-explicit\": {\n      \"version\": \"1.0.0\",\n      \"devOptional\": true\n    }"));

        assert!(json.contains("\"node_modules/pkg-peer\": {\n      \"version\": \"1.0.0\",\n      \"peer\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-peer-opt\": {\n      \"version\": \"1.0.0\",\n      \"peer\": true,\n      \"peerOptional\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-bundled\": {\n      \"version\": \"1.0.0\",\n      \"inBundle\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-script\": {\n      \"version\": \"1.0.0\",\n      \"hasInstallScript\": true\n    }"));
        assert!(json.contains("\"node_modules/pkg-shrinkwrap\": {\n      \"version\": \"1.0.0\",\n      \"hasShrinkwrap\": true\n    }"));

        // Multi-flag check
        let multi_pkg = lockfile.get_package("node_modules/pkg-multi").unwrap();
        assert!(multi_pkg.is_in_bundle());
        assert!(multi_pkg.is_dev());
        assert!(multi_pkg.is_optional());
        assert!(!multi_pkg.is_dev_optional());
        assert!(multi_pkg.is_effective_dev());
        assert!(multi_pkg.is_effective_optional());
        assert!(multi_pkg.has_install_script());

        // Round-trip deserialization
        let parsed = LockfileV3::from_json_str(&json).unwrap();
        assert_eq!(
            parsed.packages.get("node_modules/pkg-dev").unwrap().dev,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-opt")
                .unwrap()
                .optional,
            Some(true)
        );
        assert_eq!(
            parsed.packages.get("node_modules/pkg-dev-opt").unwrap().dev,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-dev-opt")
                .unwrap()
                .optional,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-dev-opt")
                .unwrap()
                .dev_optional,
            None
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-dev-opt-explicit")
                .unwrap()
                .dev_optional,
            Some(true)
        );
        assert_eq!(
            parsed.packages.get("node_modules/pkg-peer").unwrap().peer,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-peer-opt")
                .unwrap()
                .peer,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-peer-opt")
                .unwrap()
                .peer_optional,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-bundled")
                .unwrap()
                .in_bundle,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-script")
                .unwrap()
                .has_install_script,
            Some(true)
        );
        assert_eq!(
            parsed
                .packages
                .get("node_modules/pkg-shrinkwrap")
                .unwrap()
                .has_shrinkwrap,
            Some(true)
        );
        let parsed_multi = parsed.packages.get("node_modules/pkg-multi").unwrap();
        assert_eq!(parsed_multi.in_bundle, Some(true));
        assert_eq!(parsed_multi.dev, Some(true));
        assert_eq!(parsed_multi.optional, Some(true));
        assert_eq!(parsed_multi.dev_optional, None);
        assert_eq!(parsed_multi.has_install_script, Some(true));
    }

    #[test]
    fn test_absence_of_false_boolean_fields_and_deterministic_ordering() {
        let mut lockfile = LockfileV3::new("false-app", Some("1.0.0".to_string()));

        // Set every boolean flag explicitly to Some(false)
        let false_pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            dev: Some(false),
            optional: Some(false),
            dev_optional: Some(false),
            peer: Some(false),
            peer_optional: Some(false),
            in_bundle: Some(false),
            has_install_script: Some(false),
            has_shrinkwrap: Some(false),
            link: Some(false),
            ..Default::default()
        };

        // Insert in arbitrary order
        lockfile.insert_package("node_modules/zzz", false_pkg.clone());
        lockfile.insert_package("node_modules/mmm", false_pkg.clone());
        lockfile.insert_package("node_modules/aaa", false_pkg);

        let json = lockfile.to_json_string().unwrap();

        // Assert that NONE of the false flags appear in JSON
        assert!(!json.contains("\"dev\": false"));
        assert!(!json.contains("\"optional\": false"));
        assert!(!json.contains("\"devOptional\": false"));
        assert!(!json.contains("\"peer\": false"));
        assert!(!json.contains("\"peerOptional\": false"));
        assert!(!json.contains("\"inBundle\": false"));
        assert!(!json.contains("\"hasInstallScript\": false"));
        assert!(!json.contains("\"hasShrinkwrap\": false"));
        assert!(!json.contains("\"link\": false"));

        // Assert deterministic key ordering
        let pos_root = json.find("\"\"").unwrap();
        let pos_aaa = json.find("\"node_modules/aaa\"").unwrap();
        let pos_mmm = json.find("\"node_modules/mmm\"").unwrap();
        let pos_zzz = json.find("\"node_modules/zzz\"").unwrap();

        assert!(pos_root < pos_aaa);
        assert!(pos_aaa < pos_mmm);
        assert!(pos_mmm < pos_zzz);

        // Multiple serialization calls are 100% byte identical
        let json2 = lockfile.to_json_string().unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_v1_migration_with_optional_peer_bundled_flags() {
        let v1_json = r#"{
            "name": "v1-edge-cases",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "requires": true,
            "dependencies": {
                "opt-dep": {
                    "version": "1.2.0",
                    "resolved": "https://registry.npmjs.org/opt-dep/-/opt-dep-1.2.0.tgz",
                    "integrity": "sha512-opt123",
                    "optional": true
                },
                "peer-dep": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/peer-dep/-/peer-dep-2.0.0.tgz",
                    "integrity": "sha512-peer123",
                    "peer": true,
                    "peerOptional": true
                },
                "bundled-dep": {
                    "version": "3.1.0",
                    "resolved": "https://registry.npmjs.org/bundled-dep/-/bundled-dep-3.1.0.tgz",
                    "integrity": "sha512-bundle123",
                    "bundled": true
                },
                "dev-opt-dep": {
                    "version": "4.0.0",
                    "resolved": "https://registry.npmjs.org/dev-opt-dep/-/dev-opt-dep-4.0.0.tgz",
                    "integrity": "sha512-devopt123",
                    "dev": true,
                    "optional": true,
                    "hasInstallScript": true
                },
                "parent-dev": {
                    "version": "5.0.0",
                    "dev": true,
                    "dependencies": {
                        "nested-bundled": {
                            "version": "1.0.0",
                            "bundled": true
                        }
                    }
                }
            }
        }"#;

        let migrated = parse_and_migrate(v1_json).unwrap();
        assert_eq!(migrated.lockfile_version, 3);

        // Check opt-dep
        let opt = migrated.packages.get("node_modules/opt-dep").unwrap();
        assert_eq!(opt.optional, Some(true));
        assert_eq!(opt.dev, None);

        // Check peer-dep
        let peer = migrated.packages.get("node_modules/peer-dep").unwrap();
        assert_eq!(peer.peer, Some(true));
        assert_eq!(peer.peer_optional, Some(true));

        // Check bundled-dep
        let bundled = migrated.packages.get("node_modules/bundled-dep").unwrap();
        assert_eq!(bundled.in_bundle, Some(true));

        // Check dev-opt-dep (dev + optional preserved as dev: true, optional: true)
        let dev_opt = migrated.packages.get("node_modules/dev-opt-dep").unwrap();
        assert_eq!(dev_opt.dev, Some(true));
        assert_eq!(dev_opt.optional, Some(true));
        assert_eq!(dev_opt.dev_optional, None);
        assert_eq!(dev_opt.has_install_script, Some(true));

        // Check nested bundled
        let nested = migrated
            .packages
            .get("node_modules/parent-dev/node_modules/nested-bundled")
            .unwrap();
        assert_eq!(nested.in_bundle, Some(true));

        // Check root package has accurately mapped descriptors
        let root = migrated.root_package().unwrap();
        assert!(root
            .optional_dependencies
            .as_ref()
            .unwrap()
            .contains_key("opt-dep"));
        assert!(root
            .peer_dependencies
            .as_ref()
            .unwrap()
            .contains_key("peer-dep"));
        assert!(root.is_peer_dep_optional("peer-dep"));
        assert!(root
            .bundled_package_names()
            .contains(&"bundled-dep".to_string()));
    }

    #[test]
    fn test_v2_migration_with_optional_peer_bundled_flags() {
        let v2_json = r#"{
            "name": "v2-edge-cases",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": true,
            "packages": {
                "": {
                    "name": "v2-edge-cases",
                    "version": "1.0.0",
                    "dependencies": {
                        "prod-dep": "^1.0.0"
                    },
                    "optionalDependencies": {
                        "opt-dep": "^2.0.0"
                    },
                    "peerDependencies": {
                        "peer-dep": "^3.0.0"
                    },
                    "peerDependenciesMeta": {
                        "peer-dep": {
                            "optional": true
                        }
                    },
                    "bundleDependencies": ["bundled-dep"]
                },
                "node_modules/prod-dep": {
                    "version": "1.0.0"
                },
                "node_modules/opt-dep": {
                    "version": "2.0.0",
                    "optional": true
                },
                "node_modules/peer-dep": {
                    "version": "3.0.0",
                    "peer": true,
                    "peerOptional": true
                },
                "node_modules/bundled-dep": {
                    "version": "4.0.0",
                    "bundled": true
                },
                "node_modules/dev-opt-dep": {
                    "version": "5.0.0",
                    "dev": true,
                    "optional": true
                }
            },
            "dependencies": {
                "prod-dep": {
                    "version": "1.0.0"
                },
                "opt-dep": {
                    "version": "2.0.0",
                    "optional": true
                },
                "peer-dep": {
                    "version": "3.0.0",
                    "peer": true,
                    "peerOptional": true
                },
                "bundled-dep": {
                    "version": "4.0.0",
                    "bundled": true
                },
                "dev-opt-dep": {
                    "version": "5.0.0",
                    "dev": true,
                    "optional": true
                }
            }
        }"#;

        let migrated = parse_and_migrate(v2_json).unwrap();
        assert_eq!(migrated.lockfile_version, 3);

        let p_opt = migrated.packages.get("node_modules/opt-dep").unwrap();
        assert_eq!(p_opt.optional, Some(true));

        let p_peer = migrated.packages.get("node_modules/peer-dep").unwrap();
        assert_eq!(p_peer.peer, Some(true));
        assert_eq!(p_peer.peer_optional, Some(true));

        let p_bundled = migrated.packages.get("node_modules/bundled-dep").unwrap();
        assert_eq!(p_bundled.in_bundle, Some(true));

        let p_dev_opt = migrated.packages.get("node_modules/dev-opt-dep").unwrap();
        assert_eq!(p_dev_opt.dev, Some(true));
        assert_eq!(p_dev_opt.optional, Some(true));
        assert_eq!(p_dev_opt.dev_optional, None);

        // Ensure serialization strips top-level dependencies
        let serialized = migrated.to_json_string().unwrap();
        assert!(!serialized.contains("\n  \"dependencies\": {\n    \"prod-dep\":"));
        assert!(serialized.contains("\"inBundle\": true"));
        assert!(serialized.contains("\"dev\": true"));
        assert!(serialized.contains("\"optional\": true"));
    }

    #[test]
    fn test_lockfile_package_helper_methods_and_npm_rules() {
        let mut pkg = LockfilePackage::default();

        // Test set_* and query methods
        pkg.set_dev(true);
        assert!(pkg.is_dev());
        assert!(pkg.is_effective_dev());
        pkg.set_dev(false);
        assert!(!pkg.is_dev());

        pkg.set_optional(true);
        assert!(pkg.is_optional());
        assert!(pkg.is_effective_optional());
        pkg.set_optional(false);
        assert!(!pkg.is_optional());

        // Test set_dependency_types
        pkg.set_dependency_types(true, true);
        assert!(pkg.is_dev());
        assert!(pkg.is_optional());
        assert!(!pkg.is_dev_optional());
        assert!(pkg.is_effective_dev());
        assert!(pkg.is_effective_optional());

        pkg.set_dependency_types(true, false);
        assert!(pkg.is_dev());
        assert!(!pkg.is_optional());
        assert!(!pkg.is_dev_optional());

        pkg.set_dependency_types(false, true);
        assert!(!pkg.is_dev());
        assert!(pkg.is_optional());
        assert!(!pkg.is_dev_optional());

        // Test peer & peerOptional
        pkg.set_peer(true);
        pkg.set_peer_optional(true);
        assert!(pkg.is_peer());
        assert!(pkg.is_peer_optional());

        // Test in_bundle
        pkg.set_in_bundle(true);
        assert!(pkg.is_in_bundle());

        // Test install scripts & shrinkwrap
        pkg.set_has_install_script(true);
        assert!(pkg.has_install_script());
        pkg.set_has_shrinkwrap(true);
        assert!(pkg.has_shrinkwrap());

        // Test peerDependenciesMeta helpers
        let mut root = LockfilePackage::default();
        assert!(!root.is_peer_dep_optional("react"));
        root.set_peer_dep_optional("react", true);
        assert!(root.is_peer_dep_optional("react"));
        root.set_peer_dep_optional("react", false);
        assert!(!root.is_peer_dep_optional("react"));

        // Test bundle_dependencies helper
        let mut b_pkg = LockfilePackage {
            dependencies: Some({
                let mut m = BTreeMap::new();
                m.insert("lib-a".to_string(), "1.0.0".to_string());
                m.insert("lib-b".to_string(), "1.0.0".to_string());
                m
            }),
            bundle_dependencies: Some(BundledDependencies::Boolean(true)),
            ..Default::default()
        };
        let names = b_pkg.bundled_package_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"lib-a".to_string()));
        assert!(names.contains(&"lib-b".to_string()));

        b_pkg.bundle_dependencies = Some(BundledDependencies::List(vec!["lib-a".to_string()]));
        assert_eq!(b_pkg.bundled_package_names(), vec!["lib-a".to_string()]);
    }

    #[test]
    fn test_lockfile_v3_helper_methods_and_iterators() {
        let mut lockfile = LockfileV3::new("helpers-app", Some("1.0.0".to_string()));

        lockfile.insert_package(
            "node_modules/dev-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                dev: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/opt-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                optional: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/dev-opt-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                dev_optional: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/peer-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                peer: Some(true),
                peer_optional: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/bundled-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                in_bundle: Some(true),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/script-pkg",
            LockfilePackage {
                version: Some("1.0.0".to_string()),
                has_install_script: Some(true),
                ..Default::default()
            },
        );

        assert_eq!(lockfile.dev_packages().count(), 1);
        assert_eq!(lockfile.optional_packages().count(), 1);
        assert_eq!(lockfile.dev_optional_packages().count(), 1);
        assert_eq!(lockfile.peer_packages().count(), 1);
        assert_eq!(lockfile.peer_optional_packages().count(), 1);
        assert_eq!(lockfile.bundled_packages().count(), 1);
        assert_eq!(lockfile.script_packages().count(), 1);

        // Test populate_package_flags
        assert!(lockfile.populate_package_flags(
            "node_modules/script-pkg",
            Some(true),
            Some(true),
            None,
            None,
            None,
            None,
            None,
        ));
        let updated = lockfile.get_package("node_modules/script-pkg").unwrap();
        assert!(updated.is_dev());
        assert!(updated.is_optional());
        assert!(!updated.is_dev_optional());
        assert!(updated.is_effective_dev());
        assert!(updated.is_effective_optional());
        assert!(updated.has_install_script());
    }

    #[test]
    fn test_matches_manifest_all_dependency_types() {
        use rnpm_core::manifest::PeerDependencyMeta;
        use rnpm_core::Manifest;

        let mut manifest = Manifest::default();
        manifest.name = Some("peer-matches-app".to_string());
        manifest.version = Some("1.0.0".to_string());

        let mut deps = BTreeMap::new();
        deps.insert("prod-pkg".to_string(), "^1.0.0".to_string());
        manifest.dependencies = deps;

        let mut dev_deps = BTreeMap::new();
        dev_deps.insert("dev-pkg".to_string(), "^2.0.0".to_string());
        manifest.dev_dependencies = dev_deps;

        let mut opt_deps = BTreeMap::new();
        opt_deps.insert("opt-pkg".to_string(), "^3.0.0".to_string());
        manifest.optional_dependencies = opt_deps;

        let mut peer_deps = BTreeMap::new();
        peer_deps.insert("peer-required".to_string(), "^4.0.0".to_string());
        peer_deps.insert("peer-optional".to_string(), "^5.0.0".to_string());
        manifest.peer_dependencies = peer_deps;

        let mut peer_meta = BTreeMap::new();
        peer_meta.insert(
            "peer-optional".to_string(),
            PeerDependencyMeta { optional: true },
        );
        manifest.peer_dependencies_meta = peer_meta;

        manifest.bundled_dependencies =
            Some(BundledDependencies::List(vec!["bundled-dep".to_string()]));

        // Construct matching LockfileV3 using from_manifest
        let mut lockfile = LockfileV3::from_manifest(&manifest);

        lockfile.insert_package(
            "node_modules/prod-pkg",
            LockfilePackage {
                version: Some("1.2.0".to_string()),
                ..Default::default()
            },
        );
        lockfile.insert_package(
            "node_modules/dev-pkg",
            LockfilePackage {
                version: Some("2.1.0".to_string()),
                dev: Some(true),
                ..Default::default()
            },
        );
        // Note: opt-pkg is missing from packages, which is permitted for optional dependencies!
        // peer-optional is missing from packages, which is permitted because it is marked optional in peerDependenciesMeta!

        // peer-required is non-optional peer, so it MUST be present
        lockfile.insert_package(
            "node_modules/peer-required",
            LockfilePackage {
                version: Some("4.2.0".to_string()),
                peer: Some(true),
                ..Default::default()
            },
        );

        // Should match perfectly
        assert!(lockfile.matches_manifest(&manifest, true));

        // Case 1: Missing non-optional peer dependency must fail
        let mut lf_missing_peer = lockfile.clone();
        lf_missing_peer
            .packages
            .remove("node_modules/peer-required");
        assert!(
            !lf_missing_peer.matches_manifest(&manifest, true),
            "Must fail if non-optional peer is missing"
        );

        // Case 2: Incompatible version for optional peer must fail if present
        let mut lf_bad_opt_peer = lockfile.clone();
        lf_bad_opt_peer.insert_package(
            "node_modules/peer-optional",
            LockfilePackage {
                version: Some("4.0.0".to_string()), // violates ^5.0.0
                peer: Some(true),
                peer_optional: Some(true),
                ..Default::default()
            },
        );
        assert!(
            !lf_bad_opt_peer.matches_manifest(&manifest, true),
            "Must fail if optional peer has unsatisfying version"
        );

        // Case 3: Compatible version for optional peer succeeds
        let mut lf_good_opt_peer = lockfile.clone();
        lf_good_opt_peer.insert_package(
            "node_modules/peer-optional",
            LockfilePackage {
                version: Some("5.2.0".to_string()),
                peer: Some(true),
                peer_optional: Some(true),
                ..Default::default()
            },
        );
        assert!(lf_good_opt_peer.matches_manifest(&manifest, true));

        // Case 4: peerDependenciesMeta mismatch must fail
        let mut lf_meta_mismatch = lockfile.clone();
        lf_meta_mismatch
            .root_package_mut()
            .unwrap()
            .peer_dependencies_meta = None;
        assert!(
            !lf_meta_mismatch.matches_manifest(&manifest, true),
            "Must fail on peerDependenciesMeta drift"
        );

        // Case 5: bundleDependencies mismatch must fail
        let mut lf_bundle_mismatch = lockfile.clone();
        lf_bundle_mismatch
            .root_package_mut()
            .unwrap()
            .bundle_dependencies = None;
        assert!(
            !lf_bundle_mismatch.matches_manifest(&manifest, true),
            "Must fail on bundleDependencies drift"
        );
    }

    #[test]
    fn test_lockfile_engines_formats_and_roundtrip() {
        let json_input = r#"{
  "name": "engines-test-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "engines-test-app",
      "version": "1.0.0"
    },
    "node_modules/concat-stream": {
      "version": "1.6.2",
      "engines": [
        "node >= 0.8",
        "npm >= 1.2"
      ]
    },
    "node_modules/string-engine": {
      "version": "1.0.0",
      "engines": "node >= 14.0.0"
    },
    "node_modules/map-engine": {
      "version": "2.0.0",
      "engines": {
        "node": ">= 18.0.0",
        "npm": ">= 8.0.0"
      }
    },
    "node_modules/uninterpreted-engine": {
      "version": "3.0.0",
      "engines": {
        "node": 18,
        "custom": true
      }
    }
  }
}"#;

        // 1. Parsing must succeed without error on all engines formats
        let lockfile: LockfileV3 = serde_json::from_str(json_input)
            .expect("Must parse lockfile with array, string, map, and arbitrary engines");

        // 2. Concat-stream with array engines
        let concat = lockfile.packages.get("node_modules/concat-stream").unwrap();
        assert!(matches!(concat.engines, Some(PackageEngines::List(_))));
        let concat_map = concat
            .engines_map()
            .expect("engines_map must parse array engines");
        assert_eq!(concat_map.get("node").map(String::as_str), Some(">= 0.8"));
        assert_eq!(concat_map.get("npm").map(String::as_str), Some(">= 1.2"));

        // 3. String engines
        let str_pkg = lockfile.packages.get("node_modules/string-engine").unwrap();
        assert!(matches!(str_pkg.engines, Some(PackageEngines::String(_))));
        let str_map = str_pkg
            .engines_map()
            .expect("engines_map must parse string engines");
        assert_eq!(str_map.get("node").map(String::as_str), Some(">= 14.0.0"));

        // 4. Map engines
        let map_pkg = lockfile.packages.get("node_modules/map-engine").unwrap();
        assert!(matches!(map_pkg.engines, Some(PackageEngines::Map(_))));
        let map_res = map_pkg
            .engines_map()
            .expect("engines_map must return map engines");
        assert_eq!(map_res.get("node").map(String::as_str), Some(">= 18.0.0"));
        assert_eq!(map_res.get("npm").map(String::as_str), Some(">= 8.0.0"));
        assert_eq!(
            concat
                .engines
                .as_ref()
                .and_then(|e| e.get("node"))
                .as_deref(),
            Some(">= 0.8")
        );
        assert_eq!(
            concat
                .engines
                .as_ref()
                .and_then(|e| e.get("npm"))
                .as_deref(),
            Some(">= 1.2")
        );
        assert_eq!(
            str_pkg
                .engines
                .as_ref()
                .and_then(|e| e.get("node"))
                .as_deref(),
            Some(">= 14.0.0")
        );
        assert_eq!(
            map_pkg
                .engines
                .as_ref()
                .and_then(|e| e.get("node"))
                .as_deref(),
            Some(">= 18.0.0")
        );

        // 5. Uninterpreted engines
        let uninterpreted_pkg = lockfile
            .packages
            .get("node_modules/uninterpreted-engine")
            .unwrap();
        assert!(matches!(
            uninterpreted_pkg.engines,
            Some(PackageEngines::Other(_))
        ));

        // 6. Roundtrip serialization preserves uninterpreted and original structures
        let serialized = lockfile.to_json_string().unwrap();
        let parsed_again: LockfileV3 =
            serde_json::from_str(&serialized).expect("Must deserialize round-tripped lockfile");

        assert_eq!(lockfile, parsed_again);
        // Verify array format was preserved in JSON
        assert!(serialized
            .contains("\"engines\": [\n        \"node >= 0.8\",\n        \"npm >= 1.2\"\n      ]"));
        // Verify string format was preserved in JSON
        assert!(serialized.contains("\"engines\": \"node >= 14.0.0\""));
        // Verify map format was preserved in JSON
        assert!(serialized.contains("\"engines\": {\n        \"node\": \">= 18.0.0\",\n        \"npm\": \">= 8.0.0\"\n      }"));
    }

    #[test]
    fn test_lockfile_metadata_arborist_alignment() {
        let mut lockfile = LockfileV3::new("arborist-app", Some("1.0.0".to_string()));

        let mut pkg = LockfilePackage {
            version: Some("1.0.0".to_string()),
            dev: Some(true),
            optional: Some(true),
            license: Some("MIT".to_string()),
            libc: Some(vec!["glibc".to_string()]),
            ..Default::default()
        };
        pkg.extra.insert(
            "directories".to_string(),
            serde_json::json!({ "lib": "dist" }),
        );
        pkg.extra
            .insert("deprecated".to_string(), serde_json::Value::Bool(false));

        lockfile.insert_package("node_modules/test-pkg", pkg);

        let stored = lockfile.packages.get("node_modules/test-pkg").unwrap();
        // dev + optional preserved as individual flags (npm 11 parity)
        assert_eq!(stored.dev, Some(true));
        assert_eq!(stored.optional, Some(true));
        assert_eq!(stored.dev_optional, None);
        // directories removed
        assert!(!stored.extra.contains_key("directories"));
        // deprecated: false removed
        assert!(!stored.extra.contains_key("deprecated"));
        // license and libc present
        assert_eq!(stored.license.as_deref(), Some("MIT"));
        assert_eq!(stored.libc.as_deref(), Some(&["glibc".to_string()][..]));

        let json = lockfile.to_json_string().unwrap();
        assert!(json.contains("\"dev\": true"));
        assert!(json.contains("\"optional\": true"));
        assert!(!json.contains("\"devOptional\""));
        assert!(!json.contains("\"directories\""));
        assert!(!json.contains("\"deprecated\""));
        assert!(json.contains("\"license\": \"MIT\""));
        assert!(json.contains("\"libc\": [\n        \"glibc\"\n      ]"));
    }

    #[test]
    fn test_dev_and_optional_roundtrip_fidelity() {
        let original_json = r#"{
  "name": "dev-opt-roundtrip",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "dev-opt-roundtrip"
    },
    "node_modules/fsevents": {
      "version": "2.3.3",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
      "integrity": "sha512-55333333333333333333333333333333333333333333333333333333333333333333333333333333333333==",
      "dev": true,
      "optional": true,
      "os": [
        "darwin"
      ]
    }
  }
}
"#;

        let parsed = LockfileV3::from_json_str(original_json).unwrap();
        let fsevents = parsed
            .packages
            .get("node_modules/fsevents")
            .expect("node_modules/fsevents must exist");

        // Validate flag states
        assert_eq!(fsevents.dev, Some(true));
        assert_eq!(fsevents.optional, Some(true));
        assert_eq!(fsevents.dev_optional, None);
        assert!(fsevents.is_dev());
        assert!(fsevents.is_optional());
        assert!(!fsevents.is_dev_optional());
        assert!(fsevents.is_effective_dev());
        assert!(fsevents.is_effective_optional());

        // Round-trip back to serialized JSON
        let serialized = parsed.to_json_string().unwrap();
        assert!(serialized.contains("\"dev\": true"));
        assert!(serialized.contains("\"optional\": true"));
        assert!(!serialized.contains("\"devOptional\""));

        // Parse serialized JSON back and verify identical structure
        let reparsed = LockfileV3::from_json_str(&serialized).unwrap();
        let reparsed_fsevents = reparsed
            .packages
            .get("node_modules/fsevents")
            .expect("node_modules/fsevents must exist after round-trip");
        assert_eq!(reparsed_fsevents.dev, Some(true));
        assert_eq!(reparsed_fsevents.optional, Some(true));
        assert_eq!(reparsed_fsevents.dev_optional, None);
        assert_eq!(parsed, reparsed);
    }
}
