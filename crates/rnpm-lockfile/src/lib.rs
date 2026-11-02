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

    fn v4_4_json(ver: u32) -> String {
        format!(r#"{{ "name": "future-app", "lockfileVersion": {ver} }}"#)
    }
}
