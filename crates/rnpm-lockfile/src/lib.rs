//! Lockfile parsing, generation, migration, and deterministic serialization for rnpm.
//!
//! Implements npm lockfile version 3 model with deterministic sorted keys,
//! POSIX forward-slash path keys, flag preservation (dev, optional, inBundle, hasInstallScript),
//! and full migration support for legacy lockfile v1 and v2 formats.

pub mod error;
pub mod migration;
pub mod model;

pub use error::LockfileError;
pub use migration::{load_and_migrate, migrate_to_v3, parse_and_migrate, AnyLockfile, LegacyDependency};
pub use model::{LockfilePackage, LockfileV3, PackageBin};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
        lockfile.insert_package("node_modules/chalk", LockfilePackage {
            version: Some("5.3.0".to_string()),
            ..Default::default()
        });
        lockfile.insert_package("node_modules/debug", LockfilePackage {
            version: Some("4.3.4".to_string()),
            ..Default::default()
        });
        lockfile.insert_package("node_modules/typescript", LockfilePackage {
            version: Some("5.4.2".to_string()),
            ..Default::default()
        });

        let mut manifest = Manifest::default();
        manifest.name = Some("test-pkg".to_string());
        manifest.dependencies = deps;
        manifest.dev_dependencies = dev_deps;

        // 1. Matches with dev dependencies
        assert!(lockfile.matches_manifest(&manifest, true));

        // 2. Spec mismatch in manifest
        let mut modified_manifest = manifest.clone();
        modified_manifest.dependencies.insert("chalk".to_string(), "^4.0.0".to_string());
        assert!(!lockfile.matches_manifest(&modified_manifest, true));

        // 3. Extra dependency in manifest
        let mut added_dep_manifest = manifest.clone();
        added_dep_manifest.dependencies.insert("semver".to_string(), "^7.0.0".to_string());
        assert!(!lockfile.matches_manifest(&added_dep_manifest, true));

        // 4. Missing package in packages map
        let mut broken_lockfile = lockfile.clone();
        broken_lockfile.packages.remove("node_modules/chalk");
        assert!(!broken_lockfile.matches_manifest(&manifest, true));

        // 5. Dev dependency mutated in manifest (e.g. range spec changed)
        let mut dev_mutated = manifest.clone();
        dev_mutated.dev_dependencies.insert("typescript".to_string(), "^5.5.0".to_string());
        assert!(!lockfile.matches_manifest(&dev_mutated, true), "Must detect mutated devDependencies");

        // 6. Dev dependency deleted from manifest but still present in lockfile
        let mut dev_deleted = manifest.clone();
        dev_deleted.dev_dependencies.remove("typescript");
        assert!(!lockfile.matches_manifest(&dev_deleted, true), "Must detect deleted devDependency");

        // 7. Production dependency deleted from manifest but present in lockfile
        let mut dep_deleted = manifest.clone();
        dep_deleted.dependencies.remove("debug");
        assert!(!lockfile.matches_manifest(&dep_deleted, true), "Must detect deleted dependency");

        // 8. Dependency version in packages map does not satisfy manifest spec
        let mut unsatisfied_lockfile = lockfile.clone();
        unsatisfied_lockfile.packages.get_mut("node_modules/debug").unwrap().version = Some("3.2.0".to_string());
        assert!(!unsatisfied_lockfile.matches_manifest(&manifest, true), "Must detect unsatisfying package version");
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

        lockfile.insert_package("node_modules/express", LockfilePackage {
            version: Some("4.18.2".to_string()),
            ..Default::default()
        });
        lockfile.insert_package("node_modules/vitest", LockfilePackage {
            version: Some("1.2.0".to_string()),
            dev: Some(true),
            ..Default::default()
        });
        lockfile.insert_package("node_modules/fsevents", LockfilePackage {
            version: Some("2.3.3".to_string()),
            optional: Some(true),
            ..Default::default()
        });

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
        m1.dev_dependencies.insert("vitest".to_string(), "^2.0.0".to_string());
        assert!(!lockfile.matches_manifest(&m1, true), "Dev dependency range mutation must be detected");

        // Case 2: devDependency removed from package.json
        let mut m2 = manifest.clone();
        m2.dev_dependencies.remove("vitest");
        assert!(!lockfile.matches_manifest(&m2, true), "Dev dependency removal must be detected");

        // Case 3: prod dependency removed from package.json
        let mut m3 = manifest.clone();
        m3.dependencies.remove("express");
        assert!(!lockfile.matches_manifest(&m3, true), "Prod dependency removal must be detected");

        // Case 4: optional dependency mutated in package.json
        let mut m4 = manifest.clone();
        m4.optional_dependencies.insert("fsevents".to_string(), "^3.0.0".to_string());
        assert!(!lockfile.matches_manifest(&m4, true), "Optional dependency mutation must be detected");

        // Case 5: optional dependency removed from package.json
        let mut m5 = manifest.clone();
        m5.optional_dependencies.remove("fsevents");
        assert!(!lockfile.matches_manifest(&m5, true), "Optional dependency removal must be detected");
    }

    #[test]
    fn test_hidden_lockfile_roundtrip_and_extra_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project_dir = temp_dir.path();

        let mut lockfile = LockfileV3::new("hidden-test", Some("1.0.0".to_string()));
        let mut extra = BTreeMap::new();
        extra.insert("funding".to_string(), serde_json::json!({
            "type": "opencollective",
            "url": "https://opencollective.com/test"
        }));

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

        // Load hidden lockfile back
        let loaded = LockfileV3::load_hidden(project_dir).unwrap();
        assert_eq!(loaded.name, "hidden-test");
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
}
