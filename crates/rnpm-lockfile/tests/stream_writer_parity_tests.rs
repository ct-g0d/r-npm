use rnpm_core::manifest::ManifestFormat;
use rnpm_core::Manifest;
use rnpm_lockfile::model::{LockfilePackage, LockfileV3, LockfileWriter, PackageBin, PackageEngines};
use rnpm_lockfile::parse_and_migrate;
use std::collections::BTreeMap;

fn make_complex_v3_lockfile() -> LockfileV3 {
    let mut lockfile = LockfileV3::new("sample-app", Some("1.2.3".to_string()));

    let mut root_deps = BTreeMap::new();
    root_deps.insert("chalk".to_string(), "^5.0.0".to_string());
    root_deps.insert("express".to_string(), "^4.18.2".to_string());
    let mut root_dev_deps = BTreeMap::new();
    root_dev_deps.insert("typescript".to_string(), "^5.3.3".to_string());
    root_dev_deps.insert("jest".to_string(), "^29.7.0".to_string());

    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(root_deps);
        root.dev_dependencies = Some(root_dev_deps);
    }

    // Package 1: chalk
    let mut chalk_engines = BTreeMap::new();
    chalk_engines.insert("node".to_string(), "^12.17.0 || >=14.0.0".to_string());
    lockfile.insert_package(
        "node_modules/chalk",
        LockfilePackage {
            version: Some("5.3.0".to_string()),
            resolved: Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz".to_string()),
            integrity: Some("sha512-chalk-integrity".to_string()),
            dev: Some(false), // normalized out
            engines: Some(PackageEngines::Map(chalk_engines)),
            ..Default::default()
        },
    );

    // Package 2: typescript
    let mut ts_bin = BTreeMap::new();
    ts_bin.insert("tsc".to_string(), "bin/tsc".to_string());
    ts_bin.insert("tsserver".to_string(), "bin/tsserver".to_string());
    lockfile.insert_package(
        "node_modules/typescript",
        LockfilePackage {
            version: Some("5.3.3".to_string()),
            resolved: Some("https://registry.npmjs.org/typescript/-/typescript-5.3.3.tgz".to_string()),
            integrity: Some("sha512-ts-integrity".to_string()),
            dev: Some(true),
            bin: Some(PackageBin::Map(ts_bin)),
            has_install_script: Some(true),
            ..Default::default()
        },
    );

    // Package 3: scoped package @types/node
    lockfile.insert_package(
        "node_modules/@types/node",
        LockfilePackage {
            version: Some("20.11.0".to_string()),
            resolved: Some("https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz".to_string()),
            integrity: Some("sha512-types-node".to_string()),
            dev: Some(true),
            ..Default::default()
        },
    );

    // Package 4: express with nested dependencies
    let mut exp_deps = BTreeMap::new();
    exp_deps.insert("accepts".to_string(), "~1.3.8".to_string());
    exp_deps.insert("body-parser".to_string(), "1.20.1".to_string());
    lockfile.insert_package(
        "node_modules/express",
        LockfilePackage {
            version: Some("4.18.2".to_string()),
            resolved: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string()),
            integrity: Some("sha512-express-integrity".to_string()),
            dependencies: Some(exp_deps),
            ..Default::default()
        },
    );

    // Package 5: nested node_modules/express/node_modules/accepts
    lockfile.insert_package(
        "node_modules/express/node_modules/accepts",
        LockfilePackage {
            version: Some("1.3.8".to_string()),
            resolved: Some("https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz".to_string()),
            integrity: Some("sha512-accepts-integrity".to_string()),
            ..Default::default()
        },
    );

    lockfile
}

#[test]
fn test_v3_standard_formatting_parity() {
    let lock = make_complex_v3_lockfile();

    let json_std = lock.to_json_string().expect("to_json_string");
    let json_fmt = lock
        .to_json_string_formatted(&ManifestFormat::default())
        .expect("to_json_string_formatted");
    let json_npm = lock.to_npm_json_string().expect("to_npm_json_string");
    let json_v3 = lock
        .to_json_string_version_formatted(3, &ManifestFormat::default())
        .expect("to_json_string_version_formatted");

    // All standard formatted outputs must be byte-for-byte identical
    assert_eq!(json_std, json_fmt);
    assert_eq!(json_std, json_npm);
    assert_eq!(json_std, json_v3);

    // Must end with a single newline
    assert!(json_std.ends_with('\n'));
    assert!(!json_std.ends_with("\n\n"));

    // Key order: root must have "name", then "version", then "lockfileVersion", then "packages"
    let pos_name = json_std.find("\"name\": \"sample-app\"").unwrap();
    let pos_ver = json_std.find("\"version\": \"1.2.3\"").unwrap();
    let pos_lf = json_std.find("\"lockfileVersion\": 3").unwrap();
    let pos_pkgs = json_std.find("\"packages\": {").unwrap();
    assert!(pos_name < pos_ver);
    assert!(pos_ver < pos_lf);
    assert!(pos_lf < pos_pkgs);

    // Packages order: "" must come before "node_modules/@types/node", then "node_modules/chalk", etc.
    let pos_root_pkg = json_std.find("\"\": {").unwrap();
    let pos_types = json_std.find("\"node_modules/@types/node\": {").unwrap();
    let pos_chalk = json_std.find("\"node_modules/chalk\": {").unwrap();
    let pos_express = json_std.find("\"node_modules/express\": {").unwrap();
    let pos_nested = json_std.find("\"node_modules/express/node_modules/accepts\": {").unwrap();
    let pos_ts = json_std.find("\"node_modules/typescript\": {").unwrap();

    assert!(pos_root_pkg < pos_types);
    assert!(pos_types < pos_chalk);
    assert!(pos_chalk < pos_express);
    assert!(pos_express < pos_nested);
    assert!(pos_nested < pos_ts);
}

#[test]
fn test_v3_crlf_parity() {
    let lock = make_complex_v3_lockfile();
    let crlf_format = ManifestFormat {
        indent: "  ".to_string(),
        newline: "\r\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let crlf_json = lock
        .to_json_string_version_formatted(3, &crlf_format)
        .expect("to_json_string_version_formatted CRLF");

    assert!(crlf_json.ends_with("\r\n"), "Must terminate with CRLF");
    assert!(crlf_json.contains("\r\n"), "Must contain CRLF");

    // Must NOT contain any lone LF without preceding CR
    let without_crlf = crlf_json.replace("\r\n", "");
    assert!(!without_crlf.contains('\n'), "Must not have lone LF in CRLF output");

    // Re-parse and verify round-trip
    let reparsed = LockfileV3::from_json_str(&crlf_json).expect("from_json_str on CRLF");
    let re_crlf = reparsed
        .to_json_string_version_formatted(3, &crlf_format)
        .expect("re-serialize CRLF");
    assert_eq!(crlf_json, re_crlf, "CRLF round-trip must be byte-for-byte identical");
}

#[test]
fn test_v3_tabs_parity() {
    let lock = make_complex_v3_lockfile();
    let tab_format = ManifestFormat {
        indent: "\t".to_string(),
        newline: "\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let tab_json = lock
        .to_json_string_version_formatted(3, &tab_format)
        .expect("to_json_string_version_formatted tabs");

    assert!(tab_json.contains("\t\"name\": \"sample-app\""));
    assert!(tab_json.contains("\t\"packages\": {"));
    assert!(tab_json.contains("\t\t\"\": {"));

    let reparsed = LockfileV3::from_json_str(&tab_json).expect("from_json_str tabs");
    let re_tab = reparsed
        .to_json_string_version_formatted(3, &tab_format)
        .expect("re-serialize tabs");
    assert_eq!(tab_json, re_tab, "Tab round-trip must be byte-for-byte identical");
}

#[test]
fn test_v3_4spaces_parity() {
    let lock = make_complex_v3_lockfile();
    let four_spaces_format = ManifestFormat {
        indent: "    ".to_string(),
        newline: "\n".to_string(),
        trailing_newline: true,
        has_bom: false,
    };

    let json4 = lock
        .to_json_string_version_formatted(3, &four_spaces_format)
        .expect("to_json_string_version_formatted 4 spaces");

    assert!(json4.contains("    \"name\": \"sample-app\""));
    assert!(json4.contains("    \"packages\": {"));
    assert!(json4.contains("        \"\": {"));

    let reparsed = LockfileV3::from_json_str(&json4).expect("from_json_str 4 spaces");
    let re_json4 = reparsed
        .to_json_string_version_formatted(3, &four_spaces_format)
        .expect("re-serialize 4 spaces");
    assert_eq!(json4, re_json4, "4-space round-trip must be byte-for-byte identical");
}

#[test]
fn test_compact_parity() {
    let lock = make_complex_v3_lockfile();

    let compact = lock.to_json_string_compact().expect("to_json_string_compact");
    let compact_v3 = lock
        .to_json_string_version_compact(3)
        .expect("to_json_string_version_compact(3)");

    assert_eq!(compact, compact_v3);
    assert!(!compact.contains('\n'), "Compact output must be single-line");
    assert!(!compact.contains('\r'), "Compact output must not contain CR");
    assert!(compact.starts_with('{'));
    assert!(compact.ends_with('}'));
    assert!(compact.contains("\"packages\":{"));

    // Round-trip parse from compact JSON
    let reparsed = LockfileV3::from_json_str(&compact).expect("parse compact");
    let recompact = reparsed.to_json_string_compact().expect("re-compact");
    assert_eq!(compact, recompact, "Compact round-trip must be byte-for-byte identical");
}

#[test]
fn test_v2_and_v1_parity() {
    let lock = make_complex_v3_lockfile();
    let fmt = ManifestFormat::default();

    // v2 lockfile
    let v2_json = lock
        .to_json_string_version_formatted(2, &fmt)
        .expect("to_json_string_version_formatted(2)");
    assert!(v2_json.contains("\"lockfileVersion\": 2"));
    assert!(v2_json.contains("\"requires\": true"));
    assert!(v2_json.contains("\"packages\": {"));
    assert!(v2_json.contains("\"dependencies\": {"));

    // Check key order: packages before dependencies
    let pos_pkgs = v2_json.find("\"packages\": {").unwrap();
    let pos_deps = v2_json.find("\"dependencies\": {").unwrap();
    assert!(pos_pkgs < pos_deps, "packages must precede dependencies in v2");

    // v2 compact
    let v2_compact = lock
        .to_json_string_version_compact(2)
        .expect("to_json_string_version_compact(2)");
    assert!(v2_compact.contains("\"lockfileVersion\":2"));
    assert!(v2_compact.contains("\"requires\":true"));
    assert!(v2_compact.contains("\"packages\":{"));
    assert!(v2_compact.contains("\"dependencies\":{"));

    // v1 lockfile
    let v1_json = lock
        .to_json_string_version_formatted(1, &fmt)
        .expect("to_json_string_version_formatted(1)");
    assert!(v1_json.contains("\"lockfileVersion\": 1"));
    assert!(v1_json.contains("\"requires\": true"));
    assert!(v1_json.contains("\"dependencies\": {"));
    assert!(!v1_json.contains("\"packages\":"), "v1 lockfile must omit packages map");

    // v1 compact
    let v1_compact = lock
        .to_json_string_version_compact(1)
        .expect("to_json_string_version_compact(1)");
    assert!(v1_compact.contains("\"lockfileVersion\":1"));
    assert!(!v1_compact.contains("\"packages\":"));

    // Migration from v2 and v1 via parse_and_migrate
    let migrated_v2 = parse_and_migrate(&v2_json).expect("migrate v2 to v3");
    assert_eq!(migrated_v2.lockfile_version, 3);
    assert!(migrated_v2.packages.contains_key("node_modules/chalk"));

    let migrated_v1 = parse_and_migrate(&v1_json).expect("migrate v1 to v3");
    assert_eq!(migrated_v1.lockfile_version, 3);
    assert!(migrated_v1.packages.contains_key("node_modules/chalk"));
}

#[test]
fn test_hidden_lockfile_parity() {
    let mut lock = make_complex_v3_lockfile();
    lock.packages.remove(""); // Hidden lockfile omits root package ""

    let fmt = ManifestFormat::default();
    let hidden_json = lock
        .to_npm_json_string_formatted(&fmt, false)
        .expect("to_npm_json_string_formatted without root_metadata");

    // Root "name" and "version" must be omitted
    assert!(!hidden_json.contains("\"name\": \"sample-app\""));
    assert!(!hidden_json.contains("\"version\": \"1.2.3\""));

    // First key must be lockfileVersion
    let pos_lf = hidden_json.find("\"lockfileVersion\": 3").unwrap();
    let pos_pkgs = hidden_json.find("\"packages\": {").unwrap();
    assert!(pos_lf < pos_pkgs);

    // Root package "" must be absent
    assert!(!hidden_json.contains("\"\": {"));
    // Installed packages must be present
    assert!(hidden_json.contains("\"node_modules/chalk\": {"));
}

#[test]
fn test_unknown_fields_and_raw_value_fidelity() {
    let custom_json = r#"{
  "name": "custom-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "custom-app",
      "version": "1.0.0",
      "custom_field_root": "preserved_root",
      "dependencies": {
        "dep-custom": "^1.0.0"
      }
    },
    "node_modules/dep-custom": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/dep-custom/-/dep-custom-1.0.0.tgz",
      "integrity": "sha512-custom512",
      "arbitrary_custom_meta": 12345,
      "nested_data": {
        "hello": "world",
        "tags": ["a", "b"]
      }
    }
  }
}
"#;

    // Load with from_json_str
    let lock = LockfileV3::from_json_str(custom_json).expect("parse custom lockfile");

    // Verify raw_value was cached
    let custom_pkg = lock.packages.get("node_modules/dep-custom").unwrap();
    assert!(custom_pkg.raw_value.is_some());

    // Serialize with streaming writer
    let out = lock.to_json_string().expect("serialize custom lockfile");

    // Unknown fields must be preserved byte-for-byte in the output
    assert!(out.contains("\"custom_field_root\": \"preserved_root\""));
    assert!(out.contains("\"arbitrary_custom_meta\": 12345"));
    assert!(out.contains("\"nested_data\": {"));
    assert!(out.contains("\"hello\": \"world\""));
    assert!(out.contains("\"tags\": [\n          \"a\",\n          \"b\"\n        ]"));
}

#[test]
fn test_from_json_str_readonly_semantic_equivalence() {
    let lock = make_complex_v3_lockfile();
    let json = lock.to_json_string().expect("to_json_string");

    let normal = LockfileV3::from_json_str(&json).expect("from_json_str");
    let readonly = LockfileV3::from_json_str_readonly(&json).expect("from_json_str_readonly");

    // Compare all semantic fields
    assert_eq!(normal.name, readonly.name);
    assert_eq!(normal.version, readonly.version);
    assert_eq!(normal.lockfile_version, readonly.lockfile_version);
    assert_eq!(normal.requires, readonly.requires);
    assert_eq!(normal.packages.len(), readonly.packages.len());

    for (k, normal_pkg) in &normal.packages {
        let readonly_pkg = readonly
            .packages
            .get(k)
            .unwrap_or_else(|| panic!("missing package {k} in readonly lockfile"));

        assert_eq!(normal_pkg.name, readonly_pkg.name, "package {k} name");
        assert_eq!(normal_pkg.version, readonly_pkg.version, "package {k} version");
        assert_eq!(normal_pkg.resolved, readonly_pkg.resolved, "package {k} resolved");
        assert_eq!(normal_pkg.integrity, readonly_pkg.integrity, "package {k} integrity");
        assert_eq!(normal_pkg.link, readonly_pkg.link, "package {k} link");
        assert_eq!(normal_pkg.dev, readonly_pkg.dev, "package {k} dev");
        assert_eq!(normal_pkg.optional, readonly_pkg.optional, "package {k} optional");
        assert_eq!(normal_pkg.dev_optional, readonly_pkg.dev_optional, "package {k} dev_optional");
        assert_eq!(normal_pkg.peer, readonly_pkg.peer, "package {k} peer");
        assert_eq!(normal_pkg.peer_optional, readonly_pkg.peer_optional, "package {k} peer_optional");
        assert_eq!(normal_pkg.in_bundle, readonly_pkg.in_bundle, "package {k} in_bundle");
        assert_eq!(normal_pkg.has_install_script, readonly_pkg.has_install_script, "package {k} has_install_script");
        assert_eq!(normal_pkg.has_shrinkwrap, readonly_pkg.has_shrinkwrap, "package {k} has_shrinkwrap");
        assert_eq!(normal_pkg.dependencies, readonly_pkg.dependencies, "package {k} dependencies");
        assert_eq!(normal_pkg.dev_dependencies, readonly_pkg.dev_dependencies, "package {k} dev_dependencies");
        assert_eq!(normal_pkg.optional_dependencies, readonly_pkg.optional_dependencies, "package {k} optional_dependencies");
        assert_eq!(normal_pkg.peer_dependencies, readonly_pkg.peer_dependencies, "package {k} peer_dependencies");
        assert_eq!(normal_pkg.peer_dependencies_meta, readonly_pkg.peer_dependencies_meta, "package {k} peer_dependencies_meta");
        assert_eq!(normal_pkg.bin, readonly_pkg.bin, "package {k} bin");
        assert_eq!(normal_pkg.engines, readonly_pkg.engines, "package {k} engines");
        assert_eq!(normal_pkg.extra, readonly_pkg.extra, "package {k} extra");

        // Normal must have raw_value, readonly must have None (zero extra DOM allocations!)
        assert!(normal_pkg.raw_value.is_some(), "normal package {k} must cache raw_value");
        assert!(readonly_pkg.raw_value.is_none(), "readonly package {k} must have None raw_value");
    }
}

#[test]
fn test_from_file_readonly_and_load_from_file() {
    let lock = make_complex_v3_lockfile();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let lock_path = temp_dir.path().join("package-lock.json");

    lock.save_to_file(&lock_path).expect("save_to_file");

    let loaded_normal = LockfileV3::load_from_file(&lock_path).expect("load_from_file");
    let loaded_alias = LockfileV3::from_file(&lock_path).expect("from_file");
    let loaded_readonly = LockfileV3::from_file_readonly(&lock_path).expect("from_file_readonly");
    let loaded_readonly_alias = LockfileV3::load_from_file_readonly(&lock_path).expect("load_from_file_readonly");

    assert_eq!(loaded_normal.name, loaded_readonly.name);
    assert_eq!(loaded_normal.version, loaded_readonly.version);
    assert_eq!(loaded_alias.name, loaded_readonly_alias.name);
    assert_eq!(loaded_normal.packages.len(), loaded_readonly.packages.len());
    assert!(loaded_readonly.packages.values().all(|p| p.raw_value.is_none()));
    assert!(loaded_normal.packages.values().all(|p| p.raw_value.is_some()));
}

#[test]
fn test_header_sniff_and_single_pass_performance() {
    // Standard v3: header sniff detects v3 and uses single pass
    let v3_json = r#"{
  "name": "sniff-v3",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "sniff-v3", "version": "1.0.0" },
    "node_modules/foo": { "version": "1.0.0" }
  }
}"#;
    let v3_migrated = parse_and_migrate(v3_json).expect("v3 migration");
    assert_eq!(v3_migrated.lockfile_version, 3);
    assert!(v3_migrated.packages.contains_key("node_modules/foo"));

    // Malformed v3: empty packages map with dependencies falls back to migration
    let malformed_v3 = r#"{
  "name": "malformed-v3",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {},
  "dependencies": {
    "recovered-dep": {
      "version": "2.0.0"
    }
  }
}"#;
    let recovered = parse_and_migrate(malformed_v3).expect("recover malformed v3");
    assert_eq!(recovered.lockfile_version, 3);
    assert!(recovered.packages.contains_key("node_modules/recovered-dep"));

    // Unsupported version 4
    let v4_json = r#"{ "name": "v4-app", "lockfileVersion": 4 }"#;
    let err = parse_and_migrate(v4_json).unwrap_err();
    assert!(matches!(err, rnpm_lockfile::LockfileError::UnsupportedVersion(4)));
}

#[test]
fn test_matches_manifest_no_allocation_hotpath() {
    let mut lockfile = LockfileV3::new("hotpath-test", Some("1.0.0".to_string()));
    let mut manifest_deps = BTreeMap::new();

    for i in 0..50 {
        let dep_name = format!("dep-{i}");
        let dep_ver = format!("1.{i}.0");
        manifest_deps.insert(dep_name.clone(), format!("^{dep_ver}"));

        lockfile.insert_package(
            &format!("node_modules/{dep_name}"),
            LockfilePackage {
                version: Some(dep_ver),
                ..Default::default()
            },
        );
    }

    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(manifest_deps.clone());
    }

    let manifest = Manifest {
        name: Some("hotpath-test".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: manifest_deps,
        ..Default::default()
    };

    // Test matches_manifest multiple times to exercise the hot-path key buffer
    for _ in 0..10 {
        assert!(lockfile.matches_manifest(&manifest, true));
        assert!(lockfile.matches_manifest_for_ci(&manifest, true));
    }

    // Introducing drift: modify a spec in manifest
    let mut drifted_manifest = manifest.clone();
    drifted_manifest.dependencies.insert("dep-0".to_string(), "^99.0.0".to_string());
    assert!(!lockfile.matches_manifest(&drifted_manifest, true));
}

#[test]
fn test_lockfile_writer_direct_api() {
    let lockfile = make_complex_v3_lockfile();
    let mut out = String::new();
    let writer = LockfileWriter::new("  ", "\n", false, true);
    writer.write_lockfile(&lockfile, 3, &mut out).expect("write_lockfile");
    assert!(out.contains("\"lockfileVersion\": 3"));
    assert!(out.contains("\"name\": \"sample-app\""));
}

/// Reference formatter replicating the pre-optimization `serde_json::to_value` + `write_value` path.
fn format_lockfile_via_reference(lockfile: &LockfileV3, indent: &str, newline: &str, compact: bool) -> String {
    let writer = LockfileWriter::new(indent, newline, compact, true);
    let mut root_map = serde_json::Map::new();
    root_map.insert("name".to_string(), serde_json::Value::String(lockfile.name.clone()));
    if let Some(ref v) = lockfile.version {
        root_map.insert("version".to_string(), serde_json::Value::String(v.clone()));
    }
    root_map.insert(
        "lockfileVersion".to_string(),
        serde_json::Value::Number(serde_json::Number::from(lockfile.lockfile_version)),
    );
    if let Some(r) = lockfile.requires {
        root_map.insert("requires".to_string(), serde_json::Value::Bool(r));
    }
    let mut pkgs_map = serde_json::Map::new();
    for (k, v) in &lockfile.packages {
        let pkg_val = if let Some(ref raw) = v.raw_value {
            raw.clone()
        } else {
            let mut cloned = v.clone();
            cloned.normalize_flags();
            serde_json::to_value(&cloned).unwrap()
        };
        pkgs_map.insert(rnpm_core::to_posix_path(k), pkg_val);
    }
    root_map.insert("packages".to_string(), serde_json::Value::Object(pkgs_map));
    let mut out = String::new();
    writer.write_value(&serde_json::Value::Object(root_map), 0, &mut out);
    if !compact {
        out.push_str(newline);
    }
    out
}

#[test]
fn test_direct_write_package_matches_serde_to_value_all_variants() {
    use rnpm_core::manifest::BundledDependencies;
    use rnpm_core::PlatformList;

    let mut lockfile = LockfileV3::new("parity\"app\\line\n\t\x08\x0c\x01", Some("1.0.0".to_string()));
    lockfile.requires = Some(true);

    // Package 1: devOptional splitting, scalar/array PlatformList, Bin Single, Bundled bool, String engines, escapes
    let mut deps_sw = BTreeMap::new();
    deps_sw.insert("zlib".to_string(), "^1.0.0".to_string());
    deps_sw.insert("version".to_string(), "^2.0.0".to_string());
    deps_sw.insert("name".to_string(), "^3.0.0".to_string());
    deps_sw.insert("dependencies".to_string(), "^4.0.0".to_string());

    let mut peer_meta = BTreeMap::new();
    peer_meta.insert("react".to_string(), serde_json::json!({ "optional": true }));

    lockfile.insert_package(
        "node_modules/pkg-all-scalars",
        LockfilePackage {
            name: Some("pkg\"one\\name".to_string()),
            version: Some("1.2.3".to_string()),
            resolved: Some("https://registry.npmjs.org/a/-/a-1.2.3.tgz".to_string()),
            integrity: Some("sha512-abc==".to_string()),
            link: Some(false),
            dev: Some(true),
            optional: Some(true),
            dev_optional: Some(true), // must clear dev & optional!
            peer: Some(true),
            peer_optional: Some(true),
            in_bundle: Some(true),
            has_install_script: Some(true),
            has_shrinkwrap: Some(true),
            extraneous: Some(true),
            license: Some("MIT\nOR\tApache-2.0".to_string()),
            os: Some(PlatformList::from("linux".to_string())),
            cpu: Some(PlatformList::from(Vec::new())), // empty -> omitted
            libc: Some(PlatformList::from(vec!["glibc".to_string(), "musl".to_string()])),
            bin: Some(PackageBin::Single("./cli.js".to_string())),
            engines: Some(PackageEngines::String("node>=18".to_string())),
            bundle_dependencies: Some(BundledDependencies::Boolean(true)),
            workspaces: Some(Vec::new()), // Some([]) -> emitted
            dependencies: Some(deps_sw),
            dev_dependencies: Some(BTreeMap::from([("vitest".to_string(), "^1.0.0".to_string())])),
            optional_dependencies: Some(BTreeMap::from([("fsevents".to_string(), "^2.3.0".to_string())])),
            peer_dependencies: Some(BTreeMap::from([("react".to_string(), ">=18".to_string())])),
            peer_dependencies_meta: Some(peer_meta),
            ..Default::default()
        },
    );

    // Package 2: Map bin, List engines, Bundled list, workspaces non-empty
    let mut bin_map = BTreeMap::new();
    bin_map.insert("version".to_string(), "bin/ver.js".to_string());
    bin_map.insert("alpha".to_string(), "bin/alpha.js".to_string());
    lockfile.insert_package(
        "node_modules/pkg-maps-and-lists",
        LockfilePackage {
            version: Some("2.0.0".to_string()),
            bin: Some(PackageBin::Map(bin_map)),
            engines: Some(PackageEngines::List(vec![serde_json::json!("node >= 16")])),
            bundle_dependencies: Some(BundledDependencies::List(vec!["sub-a".to_string(), "sub-b".to_string()])),
            workspaces: Some(vec!["packages/*".to_string()]),
            ..Default::default()
        },
    );

    // Package 3: Empty bin map, empty engines string, Boolean(false) bundled -> omitted; Other engines Object & extra with directories/deprecated + field shadow
    let mut extra = BTreeMap::new();
    extra.insert("directories".to_string(), serde_json::json!({ "lib": "src" }));
    extra.insert("deprecated".to_string(), serde_json::Value::Bool(false));
    extra.insert("funding".to_string(), serde_json::json!({ "type": "github", "url": "https://example.com" }));
    extra.insert("customNote".to_string(), serde_json::json!("hello\u{0007}"));
    extra.insert("version".to_string(), serde_json::json!("9.9.9-override"));

    lockfile.insert_package(
        "node_modules/pkg-extra-and-other",
        LockfilePackage {
            version: Some("0.1.0".to_string()),
            bin: Some(PackageBin::Map(BTreeMap::new())),
            engines: Some(PackageEngines::Other(serde_json::json!({ "node": ">=20", "strict": true }))),
            bundle_dependencies: Some(BundledDependencies::Boolean(false)),
            extra,
            ..Default::default()
        },
    );

    // Package 4: Totally empty package `{}` and engines Other(Bool(true))
    lockfile.insert_package("node_modules/pkg-empty", LockfilePackage::default());
    lockfile.insert_package(
        "node_modules/pkg-engines-bool",
        LockfilePackage {
            engines: Some(PackageEngines::Other(serde_json::Value::Bool(true))),
            bundle_dependencies: Some(BundledDependencies::List(Vec::new())),
            ..Default::default()
        },
    );

    for fmt in [
        ManifestFormat { indent: "  ".to_string(), newline: "\n".to_string(), ..Default::default() },
        ManifestFormat { indent: "    ".to_string(), newline: "\r\n".to_string(), ..Default::default() },
        ManifestFormat { indent: "\t".to_string(), newline: "\n".to_string(), ..Default::default() },
    ] {
        let actual = lockfile.to_json_string_version_formatted(3, &fmt).unwrap();
        let expected = format_lockfile_via_reference(&lockfile, &fmt.indent, &fmt.newline, false);
        assert_eq!(actual, expected, "pretty parity failed for indent={:?} newline={:?}", fmt.indent, fmt.newline);
    }

    let actual_compact = lockfile.to_json_string_version_compact(3).unwrap();
    let expected_compact = format_lockfile_via_reference(&lockfile, "", "", true);
    assert_eq!(actual_compact, expected_compact, "compact parity failed");
}

#[test]
fn test_single_pass_deserialization_and_migration_edge_cases() {
    let raw_json = r#"{
  "name": "single-pass-edge",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "single-pass-edge",
      "version": "1.0.0"
    },
    "node_modules\\win-pkg": {
      "version": "1.0.0",
      "_integrity": "sha512-alias==",
      "_hasShrinkwrap": true,
      "bundled": true,
      "dev": false,
      "directories": { "bin": "bin" },
      "deprecated": false,
      "license": { "type": "ISC", "name": "MIT" },
      "engines": { "node": ">=18", "mixed": 42 },
      "os": "darwin",
      "bin": { "cli": "bin/cli.js" }
    },
    "node_modules/arr-license": {
      "version": "2.0.0",
      "license": ["MIT", "Apache-2.0"],
      "dependencies": { "win-pkg": "^1.0.0" }
    }
  }
}"#;

    let normal = LockfileV3::from_json_str(raw_json).expect("from_json_str");
    let readonly = LockfileV3::from_json_str_readonly(raw_json).expect("from_json_str_readonly");
    let migrated = parse_and_migrate(raw_json).expect("parse_and_migrate");

    let win_norm = &normal.packages["node_modules/win-pkg"];
    let win_ro = &readonly.packages["node_modules/win-pkg"];
    assert_eq!(win_norm.integrity.as_deref(), Some("sha512-alias=="));
    assert_eq!(win_norm.has_shrinkwrap, Some(true));
    assert_eq!(win_norm.in_bundle, Some(true));
    assert_eq!(win_norm.dev, None); // normalized out of struct
    assert!(!win_norm.extra.contains_key("directories"));
    assert!(!win_norm.extra.contains_key("deprecated"));
    assert_eq!(win_norm.license.as_deref(), Some("ISC"));
    assert!(matches!(win_norm.engines, Some(PackageEngines::Other(_))));
    assert!(win_norm.os.as_ref().is_some_and(|p| p.is_scalar() && p.as_slice() == ["darwin"]));
    assert!(matches!(win_norm.bin, Some(PackageBin::Map(_))));

    // Untouched raw_value preserved on normal/migrated, None on readonly
    let raw_obj = win_norm.raw_value.as_ref().expect("raw_value cached").as_object().unwrap();
    assert_eq!(raw_obj.get("_integrity").and_then(|v| v.as_str()), Some("sha512-alias=="));
    assert_eq!(raw_obj.get("dev").and_then(|v| v.as_bool()), Some(false));
    assert!(raw_obj.contains_key("directories"));
    assert_eq!(win_ro.raw_value, None);

    let mut stripped_norm = normal.clone();
    for pkg in stripped_norm.packages.values_mut() {
        pkg.raw_value = None;
    }
    assert_eq!(stripped_norm, readonly);
    assert_eq!(normal, migrated);
    assert_eq!(normal.packages["node_modules/arr-license"].license.as_deref(), Some("MIT OR Apache-2.0"));

    // v3 with null packages must fail like serde BTreeMap
    let null_pkgs = r#"{ "name": "bad", "lockfileVersion": 3, "packages": null }"#;
    assert!(parse_and_migrate(null_pkgs).is_err());

    // packages appearing BEFORE lockfileVersion: 2 and 4
    let v2_reordered = r#"{
  "packages": {
    "node_modules\\a": { "version": "1.0.0", "dev": false }
  },
  "lockfileVersion": 2,
  "dependencies": {
    "a": { "version": "1.0.0" }
  }
}"#;
    let m2 = parse_and_migrate(v2_reordered).expect("v2 reordered");
    assert_eq!(m2.lockfile_version, 3);
    assert!(m2.packages.contains_key("node_modules/a"));

    let v4_reordered = r#"{ "packages": {}, "lockfileVersion": 4 }"#;
    assert!(matches!(parse_and_migrate(v4_reordered), Err(rnpm_lockfile::LockfileError::UnsupportedVersion(4))));
}

#[test]
fn test_package_satisfies_spec_fast_vs_general_parity() {
    let pkg = LockfilePackage {
        name: Some("foo".to_string()),
        version: Some("1.2.3".to_string()),
        ..Default::default()
    };

    for (spec, expected) in [
        ("", true),
        ("*", true),
        ("^1.2.0", true),
        ("^2.0.0", false),
        ("~1.2.0", true),
        (">=1.0.0 <2.0.0", true),
        ("1.2.3", true),
        ("1.2.4", false),
        ("v1.2.3", true),
        ("=1.2.3", true),
        ("1.x", true),
        ("1.2.3 - 2.0.0", true),
        ("^2.0.0 || ^1.2.0", true),
        ("latest", true),
        ("next-1", true),
        ("npm:foo@^1.0.0", true),
        ("npm:bar@^1.0.0", false),
        ("??invalid-spec??", false),
    ] {
        assert_eq!(
            LockfileV3::package_satisfies_spec("foo", &pkg, spec),
            expected,
            "spec={spec:?}"
        );
    }

    assert!(!LockfileV3::package_satisfies_spec("wrong-name", &pkg, "^1.2.0"));

    let bad_ver_pkg = LockfilePackage {
        name: Some("foo".to_string()),
        version: Some("not-a-semver".to_string()),
        ..Default::default()
    };
    assert!(!LockfileV3::package_satisfies_spec("foo", &bad_ver_pkg, "1.2.3"));
    assert!(!LockfileV3::package_satisfies_spec("foo", &bad_ver_pkg, "^1.0.0"));
    assert!(LockfileV3::package_satisfies_spec("foo", &bad_ver_pkg, "latest"));
}

#[test]
fn test_bundle_dependencies_object_form_capture_raw_parity() {
    use rnpm_core::manifest::BundledDependencies;

    let json = r#"{
  "name": "bundled-obj-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "bundled-obj-test",
      "version": "1.0.0"
    },
    "node_modules/a": {
      "version": "1.0.0",
      "bundleDependencies": { "foo": true, "bar": "^1.0.0" }
    }
  }
}"#;

    let full = LockfileV3::from_json_str(json).expect("from_json_str object bundleDependencies");
    let ro = LockfileV3::from_json_str_readonly(json)
        .expect("from_json_str_readonly object bundleDependencies");
    let migrated = parse_and_migrate(json).expect("parse_and_migrate object bundleDependencies");

    let expected = Some(BundledDependencies::List(vec![
        "foo".to_string(),
        "bar".to_string(),
    ]));
    assert_eq!(full.packages["node_modules/a"].bundle_dependencies, expected);
    assert_eq!(ro.packages["node_modules/a"].bundle_dependencies, expected);
    assert_eq!(
        migrated.packages["node_modules/a"].bundle_dependencies,
        expected
    );
}

