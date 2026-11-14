use crate::graph::DependencyType;
use crate::platform::Platform;
use crate::solver::{resolve_dependency_graph, ResolverOptions};
use crate::types::{InMemoryPackageProvider, PackageVersionMetadata};
use rnpm_core::manifest::{Manifest, PeerDependencyMeta};
use std::collections::BTreeMap;

#[test]
fn test_hoisting_and_deduplication() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A@1.0.0 depends on Shared@^1.0.0
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies
            .insert("shared-pkg".to_string(), "^1.0.0".to_string());
    });

    // Package B@1.0.0 depends on Shared@~1.2.0
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies
            .insert("shared-pkg".to_string(), "~1.2.0".to_string());
    });

    // Shared package versions
    provider.add_version("shared-pkg", "1.0.0", |_| {});
    provider.add_version("shared-pkg", "1.2.3", |_| {});

    // Root project depends on pkg-a and pkg-b
    let mut manifest = Manifest::default();
    manifest.name = Some("test-project".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-b".to_string(), "^1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // Both pkg-a and pkg-b are hoisted to root node_modules
    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));

    // shared-pkg is hoisted to root node_modules
    assert!(graph.nodes.contains_key("node_modules/shared-pkg"));
    let shared_node = graph.nodes.get("node_modules/shared-pkg").unwrap();
    // 1.2.3 is compatible with both ^1.0.0 and ~1.2.0
    assert_eq!(shared_node.version, "1.2.3");

    // Deduplication check: no nested shared-pkg exists!
    assert!(!graph
        .nodes
        .contains_key("node_modules/pkg-a/node_modules/shared-pkg"));
    assert!(!graph
        .nodes
        .contains_key("node_modules/pkg-b/node_modules/shared-pkg"));

    // Check edges
    let pkg_a_edges = graph.get_outgoing_edges("node_modules/pkg-a");
    assert_eq!(pkg_a_edges.len(), 1);
    assert_eq!(pkg_a_edges[0].to_location, "node_modules/shared-pkg");

    let pkg_b_edges = graph.get_outgoing_edges("node_modules/pkg-b");
    assert_eq!(pkg_b_edges.len(), 1);
    assert_eq!(pkg_b_edges[0].to_location, "node_modules/shared-pkg");
}

#[test]
fn test_conflict_nesting() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A requires dep@^1.0.0
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies
            .insert("conflict-dep".to_string(), "^1.0.0".to_string());
    });

    // Package B requires dep@^2.0.0
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies
            .insert("conflict-dep".to_string(), "^2.0.0".to_string());
    });

    provider.add_version("conflict-dep", "1.5.0", |_| {});
    provider.add_version("conflict-dep", "2.1.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("test-project".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-b".to_string(), "^1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // Both pkg-a and pkg-b hoisted
    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));

    // One version of conflict-dep hoisted to root
    assert!(graph.nodes.contains_key("node_modules/conflict-dep"));
    let root_conflict = graph.nodes.get("node_modules/conflict-dep").unwrap();
    assert_eq!(root_conflict.version, "1.5.0");

    // Incompatible version nested under pkg-b
    let nested_path = "node_modules/pkg-b/node_modules/conflict-dep";
    assert!(
        graph.nodes.contains_key(nested_path),
        "Expected nested node at {}",
        nested_path
    );
    let nested_conflict = graph.nodes.get(nested_path).unwrap();
    assert_eq!(nested_conflict.version, "2.1.0");

    // Lockfile check
    let lockfile = graph.to_lockfile_v3("test-project", Some("1.0.0"));
    assert!(lockfile.packages.contains_key("node_modules/conflict-dep"));
    assert!(lockfile.packages.contains_key(nested_path));
}

#[test]
fn test_npm_aliases() {
    let mut provider = InMemoryPackageProvider::new();

    // Real package is "chalk" at version "5.3.0"
    provider.add_version("chalk", "5.3.0", |v| {
        v.dist_tarball = Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz".to_string());
        v.dist_integrity = Some("sha512-mockintegrity".to_string());
    });

    // Root project defines alias "my-chalk": "npm:chalk@^5.0.0"
    let mut manifest = Manifest::default();
    manifest.name = Some("alias-project".to_string());
    manifest
        .dependencies
        .insert("my-chalk".to_string(), "npm:chalk@^5.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // The node is placed at "node_modules/my-chalk"
    assert!(graph.nodes.contains_key("node_modules/my-chalk"));
    let node = graph.nodes.get("node_modules/my-chalk").unwrap();
    assert_eq!(node.install_name, "my-chalk");
    assert_eq!(node.name, "chalk");
    assert_eq!(node.version, "5.3.0");

    // In lockfile v3, name is serialized as "chalk" because folder name differs
    let lockfile = graph.to_lockfile_v3("alias-project", Some("1.0.0"));
    let lock_pkg = lockfile.packages.get("node_modules/my-chalk").unwrap();
    assert_eq!(lock_pkg.name.as_deref(), Some("chalk"));
    assert_eq!(lock_pkg.version.as_deref(), Some("5.3.0"));
    assert_eq!(
        lock_pkg.resolved.as_deref(),
        Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz")
    );
}

#[test]
fn test_package_overrides() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies
            .insert("semver".to_string(), "^6.0.0".to_string());
        v.dependencies
            .insert("sub-dep".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("sub-dep", "1.0.0", |v| {
        v.dependencies
            .insert("deep-target".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("other-pkg", "1.0.0", |v| {
        v.dependencies
            .insert("deep-target".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("semver", "6.3.0", |_| {});
    provider.add_version("semver", "7.5.4", |_| {});
    provider.add_version("deep-target", "1.0.0", |_| {});
    provider.add_version("deep-target", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("overrides-project".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("other-pkg".to_string(), "1.0.0".to_string());

    // Configure overrides:
    // 1. Global: semver -> 7.5.4
    // 2. Nested: pkg-a -> deep-target -> 2.0.0
    let overrides_json = serde_json::json!({
        "semver": "7.5.4",
        "pkg-a": {
            "deep-target": "2.0.0"
        }
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // 1. Check global override: semver should be 7.5.4 even though pkg-a requested ^6.0.0
    let semver_node = graph.nodes.get("node_modules/semver").unwrap();
    assert_eq!(semver_node.version, "7.5.4");

    // 2. Check nested override: deep-target under pkg-a is overridden to 2.0.0
    // while other-pkg uses 1.0.0
    let other_edges = graph.get_outgoing_edges("node_modules/other-pkg");
    let other_target_edge = other_edges
        .iter()
        .find(|e| e.install_name == "deep-target")
        .unwrap();
    let other_target_node = graph.nodes.get(&other_target_edge.to_location).unwrap();
    assert_eq!(other_target_node.version, "1.0.0");

    let sub_edges = graph.get_outgoing_edges("node_modules/sub-dep");
    let pkg_a_target_edge = sub_edges
        .iter()
        .find(|e| e.install_name == "deep-target")
        .unwrap();
    let pkg_a_target_node = graph.nodes.get(&pkg_a_target_edge.to_location).unwrap();
    assert_eq!(pkg_a_target_node.version, "2.0.0");
}

#[test]
fn test_platform_filters_optional_dependencies() {
    let mut provider = InMemoryPackageProvider::new();

    // Package for darwin only
    provider.add_version("darwin-native", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
    });

    // Package for windows (win32) only
    provider.add_version("win32-native", "1.0.0", |v| {
        v.os = Some(vec!["win32".to_string()]);
    });

    // Package for x64 cpu only
    provider.add_version("x64-native", "1.0.0", |v| {
        v.cpu = Some(vec!["x64".to_string()]);
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("platform-test".to_string());
    manifest
        .optional_dependencies
        .insert("darwin-native".to_string(), "^1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("win32-native".to_string(), "^1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("x64-native".to_string(), "^1.0.0".to_string());

    // Scenario A: simulated Windows x64 host
    let win_options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let win_graph = resolve_dependency_graph(&manifest, &provider, &win_options).unwrap();
    assert!(win_graph.nodes.contains_key("node_modules/win32-native"));
    assert!(win_graph.nodes.contains_key("node_modules/x64-native"));
    assert!(win_graph.nodes.contains_key("node_modules/darwin-native"));
    assert!(win_graph.is_skipped("darwin-native"));
    let win_lockfile = win_graph.to_lockfile_v3("platform-test", Some("1.0.0"));
    let darwin_lock_entry = win_lockfile
        .packages
        .get("node_modules/darwin-native")
        .expect("incompatible optional package must remain in lockfile");
    assert_eq!(
        darwin_lock_entry.os.as_deref(),
        Some(&["darwin".to_string()][..])
    );
    assert_eq!(darwin_lock_entry.optional, Some(true));

    // Scenario B: simulated macOS arm64 host
    let mac_options = ResolverOptions {
        platform: Platform::new("darwin", "arm64"),
        ..Default::default()
    };
    let mac_graph = resolve_dependency_graph(&manifest, &provider, &mac_options).unwrap();
    assert!(mac_graph.nodes.contains_key("node_modules/darwin-native"));
    assert!(mac_graph.nodes.contains_key("node_modules/win32-native"));
    assert!(mac_graph.nodes.contains_key("node_modules/x64-native"));
    assert!(mac_graph.is_skipped("win32-native"));
    assert!(mac_graph.is_skipped("x64-native"));
}

#[test]
fn test_peer_dependencies_and_cycles() {
    let mut provider = InMemoryPackageProvider::new();

    // Cyclic peer dependencies: react peers react-dom, react-dom peers react
    provider.add_version("react", "18.2.0", |v| {
        v.peer_dependencies
            .insert("react-dom".to_string(), "^18.0.0".to_string());
    });

    provider.add_version("react-dom", "18.2.0", |v| {
        v.peer_dependencies
            .insert("react".to_string(), "^18.0.0".to_string());
    });

    // Optional peer dependency: canvas
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies
            .insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-test".to_string());
    manifest
        .dependencies
        .insert("react".to_string(), "18.2.0".to_string());
    manifest
        .dependencies
        .insert("chart-pkg".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    // Must resolve cleanly without infinite loop or stack overflow!
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/react"));
    assert!(graph.nodes.contains_key("node_modules/react-dom"));
    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    // Optional peer canvas is not in registry/provider, so omitted without error!
    assert!(!graph.nodes.contains_key("node_modules/canvas"));
}

#[test]
fn test_manifest_platform_parsing() {
    // 1. Array representation
    let json_array = r#"{
        "name": "array-pkg",
        "version": "1.0.0",
        "os": ["darwin", "linux"],
        "cpu": ["x64", "arm64"],
        "libc": ["glibc"]
    }"#;
    let meta_arr = PackageVersionMetadata::from_manifest_slice(json_array.as_bytes()).unwrap();
    assert_eq!(meta_arr.name, "array-pkg");
    assert_eq!(meta_arr.version, "1.0.0");
    assert_eq!(
        meta_arr.os.as_deref(),
        Some(&["darwin".to_string(), "linux".to_string()][..])
    );
    assert_eq!(
        meta_arr.cpu.as_deref(),
        Some(&["x64".to_string(), "arm64".to_string()][..])
    );
    assert_eq!(meta_arr.libc.as_deref(), Some(&["glibc".to_string()][..]));

    // 2. Single string representation (e.g. "os": "darwin")
    let json_str = r#"{
        "name": "str-pkg",
        "version": "2.0.0",
        "os": "darwin",
        "cpu": "arm64",
        "libc": "musl"
    }"#;
    let meta_str = PackageVersionMetadata::from_manifest_slice(json_str.as_bytes()).unwrap();
    assert_eq!(meta_str.os.as_deref(), Some(&["darwin".to_string()][..]));
    assert_eq!(meta_str.cpu.as_deref(), Some(&["arm64".to_string()][..]));
    assert_eq!(meta_str.libc.as_deref(), Some(&["musl".to_string()][..]));

    // 3. Omitted platform fields
    let json_none = r#"{"name": "any-pkg", "version": "3.0.0"}"#;
    let meta_none = PackageVersionMetadata::from_manifest_slice(json_none.as_bytes()).unwrap();
    assert!(meta_none.os.is_none());
    assert!(meta_none.cpu.is_none());
    assert!(meta_none.libc.is_none());
}

#[test]
fn test_platform_libc_filtering_optional_dependencies() {
    let mut provider = InMemoryPackageProvider::new();

    // Package for glibc only
    provider.add_version("glibc-pkg", "1.0.0", |v| {
        v.os = Some(vec!["linux".to_string()]);
        v.libc = Some(vec!["glibc".to_string()]);
    });

    // Package for musl only
    provider.add_version("musl-pkg", "1.0.0", |v| {
        v.os = Some(vec!["linux".to_string()]);
        v.libc = Some(vec!["musl".to_string()]);
    });

    // Package for non-musl (!musl)
    provider.add_version("not-musl-pkg", "1.0.0", |v| {
        v.libc = Some(vec!["!musl".to_string()]);
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("libc-test".to_string());
    manifest
        .optional_dependencies
        .insert("glibc-pkg".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("musl-pkg".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("not-musl-pkg".to_string(), "1.0.0".to_string());

    // Host 1: Linux with glibc
    let glibc_opts = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("glibc".to_string())),
        ..Default::default()
    };
    let graph1 = resolve_dependency_graph(&manifest, &provider, &glibc_opts).unwrap();
    assert!(graph1.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(graph1.nodes.contains_key("node_modules/not-musl-pkg"));
    assert!(graph1.nodes.contains_key("node_modules/musl-pkg"));
    assert!(graph1.is_skipped("musl-pkg"));

    // Host 2: Linux with musl (Alpine)
    let musl_opts = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("musl".to_string())),
        ..Default::default()
    };
    let graph2 = resolve_dependency_graph(&manifest, &provider, &musl_opts).unwrap();
    assert!(graph2.nodes.contains_key("node_modules/musl-pkg"));
    assert!(graph2.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(graph2.nodes.contains_key("node_modules/not-musl-pkg"));
    assert!(graph2.is_skipped("glibc-pkg"));
    assert!(graph2.is_skipped("not-musl-pkg"));

    // Host 3: Windows (no libc)
    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph3 = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();
    assert!(graph3.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(graph3.nodes.contains_key("node_modules/musl-pkg"));
    assert!(graph3.nodes.contains_key("node_modules/not-musl-pkg"));
    assert!(graph3.is_skipped("glibc-pkg"));
    assert!(graph3.is_skipped("musl-pkg"));
}

#[test]
fn test_transitive_optional_dependency_platform_skipping() {
    let mut provider = InMemoryPackageProvider::new();

    // Incompatible optional parent depends on child-pkg
    provider.add_version("darwin-parent", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
        v.dependencies
            .insert("child-pkg".to_string(), "1.0.0".to_string());
    });

    provider.add_version("child-pkg", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("transitive-opt".to_string());
    manifest
        .optional_dependencies
        .insert("darwin-parent".to_string(), "1.0.0".to_string());

    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();

    // The incompatible optional subtree remains in the graph for lockfile
    // parity, and descendants inherit skipped/optional reachability.
    assert!(graph.nodes.contains_key("node_modules/darwin-parent"));
    assert!(graph.nodes.contains_key("node_modules/child-pkg"));
    assert!(graph.is_skipped("darwin-parent"));
    assert!(graph.is_skipped("child-pkg"));
}

#[test]
fn test_circular_dependencies_termination() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A depends on Package B
    provider.add_version("pkg-circ-a", "1.0.0", |v| {
        v.dependencies
            .insert("pkg-circ-b".to_string(), "1.0.0".to_string());
    });

    // Package B depends on Package A (direct cycle)
    provider.add_version("pkg-circ-b", "1.0.0", |v| {
        v.dependencies
            .insert("pkg-circ-a".to_string(), "1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("circ-test".to_string());
    manifest
        .dependencies
        .insert("pkg-circ-a".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/pkg-circ-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-circ-b"));
}

#[test]
fn test_missing_optional_dependency_isolation() {
    let provider = InMemoryPackageProvider::new();

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-missing".to_string());
    // "nonexistent-pkg" does not exist in provider
    manifest
        .optional_dependencies
        .insert("nonexistent-pkg".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // Resolves successfully without failing!
    assert!(!graph.nodes.contains_key("node_modules/nonexistent-pkg"));
    assert!(graph.is_skipped("nonexistent-pkg"));
}

#[test]
fn test_empty_manifest_resolution() {
    let provider = InMemoryPackageProvider::new();
    let manifest = Manifest::default();

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // Root node exists at ""
    assert!(graph.nodes.contains_key(""));
    assert_eq!(graph.nodes.len(), 1);
}

#[test]
fn test_dependency_graph_prune_unreferenced() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A requires B
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies
            .insert("pkg-b".to_string(), "^1.0.0".to_string());
    });
    // Package B requires C
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies
            .insert("pkg-c".to_string(), "^1.0.0".to_string());
    });
    // Package C
    provider.add_version("pkg-c", "1.0.0", |_| {});

    // Package D (independent)
    provider.add_version("pkg-d", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("prune-test".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-d".to_string(), "^1.0.0".to_string());

    let options = ResolverOptions::default();
    let mut graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));
    assert!(graph.nodes.contains_key("node_modules/pkg-c"));
    assert!(graph.nodes.contains_key("node_modules/pkg-d"));

    // Remove pkg-a
    assert!(graph.remove_root_dependency("pkg-a"));
    let pruned = graph.prune_unreferenced();

    // pkg-a, pkg-b, pkg-c should all be pruned
    assert!(pruned.contains("node_modules/pkg-a"));
    assert!(pruned.contains("node_modules/pkg-b"));
    assert!(pruned.contains("node_modules/pkg-c"));
    assert!(!pruned.contains("node_modules/pkg-d"));

    assert!(!graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(!graph.nodes.contains_key("node_modules/pkg-b"));
    assert!(!graph.nodes.contains_key("node_modules/pkg-c"));
    assert!(graph.nodes.contains_key("node_modules/pkg-d"));
}

#[test]
fn test_workspace_protocol_dependencies_and_topo_sort() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Member A: leaf package (1.0.0)
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // Member B: depends on pkg-a via workspace:*
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("2.0.0".to_string());
    manifest_b
        .dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("2.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    // Member C: depends on pkg-b via workspace:^ and pkg-a via workspace:~
    let mut manifest_c = Manifest::default();
    manifest_c.name = Some("pkg-c".to_string());
    manifest_c.version = Some("3.0.0".to_string());
    manifest_c
        .dependencies
        .insert("pkg-b".to_string(), "workspace:^".to_string());
    manifest_c
        .dependencies
        .insert("pkg-a".to_string(), "workspace:~".to_string());
    let member_c = WorkspaceMember {
        name: "pkg-c".to_string(),
        version: Some("3.0.0".to_string()),
        path: PathBuf::from("packages/pkg-c"),
        relative_path: "packages/pkg-c".to_string(),
        manifest: manifest_c,
    };

    let members = vec![member_c, member_a, member_b]; // unordered input
    let ws_graph = WorkspaceDependencyGraph::construct(&members).unwrap();

    // Verify topological order: leaf pkg-a must be first, then pkg-b, then pkg-c
    assert_eq!(
        ws_graph.topological_order,
        vec![
            "pkg-a".to_string(),
            "pkg-b".to_string(),
            "pkg-c".to_string()
        ]
    );
}

#[test]
fn test_workspace_circular_dependencies_detected() {
    use crate::error::SolverError;
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // A -> B and B -> A cycle
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let result = WorkspaceDependencyGraph::construct(&[member_a, member_b]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        SolverError::CycleDetected(msg) => {
            assert!(msg.contains("Circular workspace dependency detected"));
            assert!(msg.contains("pkg-a"));
            assert!(msg.contains("pkg-b"));
        }
        other => panic!("Expected CycleDetected error, got: {:?}", other),
    }

    // 3-node cycle: A -> B -> C -> A
    let mut m_a = Manifest::default();
    m_a.name = Some("a".to_string());
    m_a.dependencies
        .insert("b".to_string(), "workspace:*".to_string());
    let member_a3 = WorkspaceMember {
        name: "a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/a"),
        relative_path: "packages/a".to_string(),
        manifest: m_a,
    };

    let mut m_b = Manifest::default();
    m_b.name = Some("b".to_string());
    m_b.dependencies
        .insert("c".to_string(), "workspace:*".to_string());
    let member_b3 = WorkspaceMember {
        name: "b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/b"),
        relative_path: "packages/b".to_string(),
        manifest: m_b,
    };

    let mut m_c = Manifest::default();
    m_c.name = Some("c".to_string());
    m_c.dependencies
        .insert("a".to_string(), "workspace:*".to_string());
    let member_c3 = WorkspaceMember {
        name: "c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/c"),
        relative_path: "packages/c".to_string(),
        manifest: m_c,
    };

    let err3 = WorkspaceDependencyGraph::construct(&[member_a3, member_b3, member_c3]).unwrap_err();
    if let SolverError::CycleDetected(msg) = err3 {
        assert!(msg.contains("Circular workspace dependency detected"));
    } else {
        panic!("Expected CycleDetected error for 3-node cycle");
    }

    // Self cycle: A -> A
    let mut m_self = Manifest::default();
    m_self.name = Some("self-pkg".to_string());
    m_self
        .dependencies
        .insert("self-pkg".to_string(), "workspace:*".to_string());
    let member_self = WorkspaceMember {
        name: "self-pkg".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/self"),
        relative_path: "packages/self".to_string(),
        manifest: m_self,
    };

    let err_self = WorkspaceDependencyGraph::construct(&[member_self]).unwrap_err();
    if let SolverError::CycleDetected(msg) = err_self {
        assert!(msg.contains("self-pkg -> self-pkg"));
    } else {
        panic!("Expected self cycle detection");
    }
}

#[test]
fn test_workspace_protocol_edge_cases() {
    use crate::error::SolverError;
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Missing sibling workspace member
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a
        .dependencies
        .insert("ghost-pkg".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    let err = WorkspaceDependencyGraph::construct(&[member_a]).unwrap_err();
    assert!(matches!(err, SolverError::UnresolvedDependency { .. }));

    // Incompatible workspace range: sibling is 1.0.0, required workspace:^2.0.0
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let mut manifest_c = Manifest::default();
    manifest_c.name = Some("pkg-c".to_string());
    manifest_c.version = Some("1.0.0".to_string());
    manifest_c
        .dependencies
        .insert("pkg-b".to_string(), "workspace:^2.0.0".to_string());
    let member_c = WorkspaceMember {
        name: "pkg-c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-c"),
        relative_path: "packages/pkg-c".to_string(),
        manifest: manifest_c,
    };

    let err_ver = WorkspaceDependencyGraph::construct(&[member_b, member_c]).unwrap_err();
    assert!(matches!(err_ver, SolverError::UnresolvedDependency { .. }));
}

#[test]
fn test_workspace_graph_resolution_with_hoisting() {
    use crate::workspace::resolve_workspace_graph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("shared-lib", "4.17.21", |_| {});

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("monorepo-root".to_string());

    // Member A depends on shared-lib
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("shared-lib".to_string(), "^4.0.0".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // Member B depends on pkg-a via workspace:*
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let options = ResolverOptions::default();
    let graph = resolve_workspace_graph(&root_manifest, &[member_a, member_b], &provider, &options)
        .unwrap();

    // Sibling workspace packages linked under root node_modules
    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));
    let node_a = graph.nodes.get("node_modules/pkg-a").unwrap();
    assert!(node_a.flags.link);
    assert_eq!(node_a.resolved.as_deref(), Some("packages/pkg-a"));

    // Physical workspace locations
    assert!(graph.nodes.contains_key("packages/pkg-a"));
    assert!(graph.nodes.contains_key("packages/pkg-b"));

    // Hoisted third-party dependency
    assert!(graph.nodes.contains_key("node_modules/shared-lib"));
    let shared = graph.nodes.get("node_modules/shared-lib").unwrap();
    assert_eq!(shared.version, "4.17.21");

    // Lockfile v3 generation
    let lockfile = graph.to_lockfile_v3("monorepo-root", Some("1.0.0"));
    let lock_a = lockfile.packages.get("node_modules/pkg-a").unwrap();
    assert_eq!(lock_a.link, Some(true));
    assert_eq!(lock_a.resolved.as_deref(), Some("packages/pkg-a"));
}

#[test]
fn test_workspace_diamond_dependency() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Diamond structure:
    //      Top (A)
    //     /       \
    //   B           C
    //     \       /
    //     Bottom (D)

    // D: Leaf
    let mut m_d = Manifest::default();
    m_d.name = Some("pkg-d".to_string());
    m_d.version = Some("1.0.0".to_string());
    let member_d = WorkspaceMember {
        name: "pkg-d".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-d"),
        relative_path: "packages/pkg-d".to_string(),
        manifest: m_d,
    };

    // B depends on D
    let mut m_b = Manifest::default();
    m_b.name = Some("pkg-b".to_string());
    m_b.version = Some("1.0.0".to_string());
    m_b.dependencies
        .insert("pkg-d".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: m_b,
    };

    // C depends on D
    let mut m_c = Manifest::default();
    m_c.name = Some("pkg-c".to_string());
    m_c.version = Some("1.0.0".to_string());
    m_c.dependencies
        .insert("pkg-d".to_string(), "workspace:*".to_string());
    let member_c = WorkspaceMember {
        name: "pkg-c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-c"),
        relative_path: "packages/pkg-c".to_string(),
        manifest: m_c,
    };

    // A depends on B and C
    let mut m_a = Manifest::default();
    m_a.name = Some("pkg-a".to_string());
    m_a.version = Some("1.0.0".to_string());
    m_a.dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    m_a.dependencies
        .insert("pkg-c".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: m_a,
    };

    let ws_graph =
        WorkspaceDependencyGraph::construct(&[member_a, member_c, member_b, member_d]).unwrap();

    let order = &ws_graph.topological_order;
    let pos_d = order.iter().position(|x| x == "pkg-d").unwrap();
    let pos_b = order.iter().position(|x| x == "pkg-b").unwrap();
    let pos_c = order.iter().position(|x| x == "pkg-c").unwrap();
    let pos_a = order.iter().position(|x| x == "pkg-a").unwrap();

    // D must precede both B and C
    assert!(pos_d < pos_b);
    assert!(pos_d < pos_c);
    // B and C must precede A
    assert!(pos_b < pos_a);
    assert!(pos_c < pos_a);
}

#[test]
fn test_workspace_disconnected_components() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Component 1: A -> B
    let mut m_b = Manifest::default();
    m_b.name = Some("comp1-b".to_string());
    let member_b = WorkspaceMember {
        name: "comp1-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/comp1-b"),
        relative_path: "packages/comp1-b".to_string(),
        manifest: m_b,
    };

    let mut m_a = Manifest::default();
    m_a.name = Some("comp1-a".to_string());
    m_a.dependencies
        .insert("comp1-b".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "comp1-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/comp1-a"),
        relative_path: "packages/comp1-a".to_string(),
        manifest: m_a,
    };

    // Component 2: Standalone package C
    let mut m_c = Manifest::default();
    m_c.name = Some("standalone-c".to_string());
    let member_c = WorkspaceMember {
        name: "standalone-c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/standalone-c"),
        relative_path: "packages/standalone-c".to_string(),
        manifest: m_c,
    };

    let ws_graph = WorkspaceDependencyGraph::construct(&[member_a, member_c, member_b]).unwrap();
    let order = &ws_graph.topological_order;
    assert_eq!(order.len(), 3);

    let pos_b = order.iter().position(|x| x == "comp1-b").unwrap();
    let pos_a = order.iter().position(|x| x == "comp1-a").unwrap();
    assert!(pos_b < pos_a);
}

#[test]
fn test_fast_path_resolution_matching_lockfile() {
    use crate::solver::{resolve_dependency_graph_with_lockfile, resolve_fast_path};
    use rnpm_lockfile::{LockfilePackage, LockfileV3};

    let mut manifest = Manifest::default();
    manifest.name = Some("fast-app".to_string());
    manifest
        .dependencies
        .insert("chalk".to_string(), "^5.0.0".to_string());
    manifest
        .dev_dependencies
        .insert("typescript".to_string(), "^5.0.0".to_string());

    let mut lockfile = LockfileV3::new("fast-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("chalk".to_string(), "^5.0.0".to_string());
    let mut lock_dev_deps = BTreeMap::new();
    lock_dev_deps.insert("typescript".to_string(), "^5.0.0".to_string());

    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
        root.dev_dependencies = Some(lock_dev_deps);
    }
    lockfile.insert_package(
        "node_modules/chalk",
        LockfilePackage {
            version: Some("5.3.0".to_string()),
            resolved: Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz".to_string()),
            integrity: Some("sha512-chalk123".to_string()),
            ..Default::default()
        },
    );
    lockfile.insert_package(
        "node_modules/typescript",
        LockfilePackage {
            version: Some("5.4.2".to_string()),
            dev: Some(true),
            ..Default::default()
        },
    );

    let options = ResolverOptions::default();

    // 1. Direct resolve_fast_path test
    let fast_graph =
        resolve_fast_path(&manifest, &lockfile, &options).expect("Fast path should succeed");
    assert!(fast_graph.nodes.contains_key("node_modules/chalk"));
    assert!(fast_graph.nodes.contains_key("node_modules/typescript"));
    assert_eq!(
        fast_graph.nodes.get("node_modules/chalk").unwrap().version,
        "5.3.0"
    );

    // 2. resolve_dependency_graph_with_lockfile using EMPTY provider (would fail if provider was queried!)
    let empty_provider = InMemoryPackageProvider::new();
    let graph = resolve_dependency_graph_with_lockfile(
        &manifest,
        &empty_provider,
        &options,
        Some(&lockfile),
    )
    .expect("Resolution must succeed via fast-path without querying provider");

    assert!(graph.nodes.contains_key("node_modules/chalk"));
    assert!(graph.nodes.contains_key("node_modules/typescript"));

    // 3. When manifest changes (spec drift), fast-path returns None and solver queries provider (fails on empty)
    let mut drifted_manifest = manifest.clone();
    drifted_manifest
        .dependencies
        .insert("chalk".to_string(), "^6.0.0".to_string());
    assert!(resolve_fast_path(&drifted_manifest, &lockfile, &options).is_none());

    let drifted_res = resolve_dependency_graph_with_lockfile(
        &drifted_manifest,
        &empty_provider,
        &options,
        Some(&lockfile),
    );
    assert!(
        drifted_res.is_err(),
        "Must fall back to provider and fail on missing metadata"
    );
}

#[test]
fn test_peer_dependency_conflict_diagnostic_error() {
    let mut provider = InMemoryPackageProvider::new();

    // React 18 is installed at root
    provider.add_version("react", "18.2.0", |_| {});

    // Plugin requires react peer ^16.0.0 || ^17.0.0
    provider.add_version("legacy-plugin", "1.0.0", |v| {
        v.peer_dependencies
            .insert("react".to_string(), "^17.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-conflict-app".to_string());
    manifest
        .dependencies
        .insert("react".to_string(), "18.2.0".to_string());
    manifest
        .dependencies
        .insert("legacy-plugin".to_string(), "1.0.0".to_string());

    // Scenario A: Strict mode (default) -> ERESOLVE peer conflict error
    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();

    let err_msg = err.to_string();
    assert!(err_msg
        .contains("ERESOLVE: Conflicting peer dependency 'react' required by 'legacy-plugin'"));
    assert!(err_msg.contains("peer react@\"^17.0.0\" from legacy-plugin"));
    assert!(err_msg.contains("Found: react@18.2.0 at node_modules/react"));
    assert!(err_msg.contains("Suggested resolutions:"));
    assert!(
        err_msg.contains("Add an override in package.json: \"overrides\": { \"react\": \"...\" }")
    );
    assert!(err_msg.contains("--legacy-peer-deps"));

    let suggestions = err.suggested_resolutions();
    assert_eq!(suggestions.len(), 3);
    assert!(suggestions[0].contains("overrides"));
    assert!(suggestions[1].contains("--legacy-peer-deps"));

    // Scenario B: Non-strict mode / legacy_peer_deps -> succeeds with warning
    let non_strict_options = ResolverOptions {
        strict_peers: false,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &non_strict_options)
        .expect("Non-strict mode should bypass peer conflict");
    assert!(graph.nodes.contains_key("node_modules/react"));
    assert!(graph.nodes.contains_key("node_modules/legacy-plugin"));

    // Scenario C: legacy_peer_deps: true -> succeeds
    let legacy_options = ResolverOptions {
        legacy_peer_deps: true,
        ..Default::default()
    };
    let legacy_graph = resolve_dependency_graph(&manifest, &provider, &legacy_options)
        .expect("legacy_peer_deps should completely ignore peer dependencies");
    assert!(legacy_graph.nodes.contains_key("node_modules/react"));
    assert!(legacy_graph
        .nodes
        .contains_key("node_modules/legacy-plugin"));
}

#[test]
fn test_hidden_tree_metadata_preservation_in_graph() {
    use crate::graph::DependencyGraph;
    use rnpm_lockfile::{LockfilePackage, LockfileV3};

    let mut lockfile = LockfileV3::new("meta-app", Some("1.0.0".to_string()));
    let mut extra = BTreeMap::new();
    extra.insert(
        "funding".to_string(),
        serde_json::json!("https://example.com/fund"),
    );
    extra.insert(
        "deprecated".to_string(),
        serde_json::json!("legacy package"),
    );

    lockfile.insert_package(
        "node_modules/custom",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            extra: extra.clone(),
            ..Default::default()
        },
    );

    // from_lockfile_v3 preserves extra into Node
    let graph = DependencyGraph::from_lockfile_v3(&lockfile);
    let node = graph
        .nodes
        .get("node_modules/custom")
        .expect("Node missing");
    assert_eq!(node.extra.get("funding"), extra.get("funding"));
    assert_eq!(node.extra.get("deprecated"), extra.get("deprecated"));

    // to_lockfile_v3 writes it back into LockfilePackage
    let generated_lock = graph.to_lockfile_v3("meta-app", Some("1.0.0"));
    let gen_pkg = generated_lock
        .packages
        .get("node_modules/custom")
        .expect("Package missing");
    assert_eq!(gen_pkg.extra.get("funding"), extra.get("funding"));
    assert_eq!(gen_pkg.extra.get("deprecated"), extra.get("deprecated"));
}

#[test]
fn test_lockfile_preserves_package_metadata_and_normalizes_bins() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("meta-pkg", "1.0.0", |version| {
        version.license = Some("MIT".to_string());
        version
            .engines
            .insert("node".to_string(), ">=18".to_string());
        version.bin = Some(rnpm_lockfile::PackageBin::Map(BTreeMap::from([(
            "meta".to_string(),
            "./bin/meta.js".to_string(),
        )])));
        version.extra.insert(
            "funding".to_string(),
            serde_json::json!({ "type": "github", "url": "https://github.com/sponsors/example" }),
        );
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("metadata-app".to_string());
    manifest
        .dependencies
        .insert("meta-pkg".to_string(), "1.0.0".to_string());
    let graph =
        resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();
    let lockfile = graph.to_lockfile_v3("metadata-app", Some("1.0.0"));
    let package = lockfile.packages.get("node_modules/meta-pkg").unwrap();

    assert_eq!(package.license.as_deref(), Some("MIT"));
    assert_eq!(
        package
            .engines
            .as_ref()
            .and_then(|m| m.get("node"))
            .as_deref(),
        Some(">=18")
    );
    assert_eq!(
        package.bin,
        Some(rnpm_lockfile::PackageBin::Map(BTreeMap::from([(
            "meta".to_string(),
            "bin/meta.js".to_string()
        ),])))
    );
    assert!(package.extra.contains_key("funding"));
}

#[test]
fn test_fast_path_detects_lockfile_drift_missing_transitive_dep() {
    use crate::solver::resolve_fast_path;
    use rnpm_lockfile::{LockfilePackage, LockfileV3};

    let mut manifest = Manifest::default();
    manifest.name = Some("drift-app".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());

    let mut lockfile = LockfileV3::new("drift-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
    }

    // pkg-a is in lockfile, and declares dependency on missing-b
    let mut a_deps = BTreeMap::new();
    a_deps.insert("missing-b".to_string(), "^1.0.0".to_string());
    lockfile.insert_package(
        "node_modules/pkg-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(a_deps),
            ..Default::default()
        },
    );
    // Note: missing-b is intentionally NOT added to lockfile.packages!

    let options = ResolverOptions::default();
    // Fast path must detect drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_fast_path_detects_lockfile_version_constraint_mismatch() {
    use crate::solver::resolve_fast_path;
    use rnpm_lockfile::{LockfilePackage, LockfileV3};

    let mut manifest = Manifest::default();
    manifest.name = Some("drift-mismatch-app".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());

    let mut lockfile = LockfileV3::new("drift-mismatch-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
    }

    let mut a_deps = BTreeMap::new();
    a_deps.insert("dep-b".to_string(), "^2.0.0".to_string());
    lockfile.insert_package(
        "node_modules/pkg-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            dependencies: Some(a_deps),
            ..Default::default()
        },
    );

    // dep-b is locked at 1.5.0, which violates ^2.0.0 constraint
    lockfile.insert_package(
        "node_modules/dep-b",
        LockfilePackage {
            version: Some("1.5.0".to_string()),
            ..Default::default()
        },
    );

    let options = ResolverOptions::default();
    // Fast path must detect version mismatch drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_fast_path_detects_overrides_drift() {
    use crate::solver::resolve_fast_path;
    use rnpm_lockfile::{LockfilePackage, LockfileV3};

    let mut manifest = Manifest::default();
    manifest.name = Some("overrides-drift-app".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    // Manifest adds an override for dep-b -> 2.5.0
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "dep-b": "2.5.0"
        }),
    );

    let mut lockfile = LockfileV3::new("overrides-drift-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
        // Lockfile has no overrides in extra
    }

    lockfile.insert_package(
        "node_modules/pkg-a",
        LockfilePackage {
            version: Some("1.0.0".to_string()),
            ..Default::default()
        },
    );

    let options = ResolverOptions::default();
    // Fast path must detect overrides drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_intermediate_ancestor_hoisting() {
    use crate::graph::Node;
    use crate::hoisting::{determine_placement, PlacementDecision};
    use rnpm_core::semver::Range;
    use rnpm_core::spec::PackageTarget;

    let mut graph = crate::graph::DependencyGraph::new();

    // Root node_modules has C@1.0.0
    graph.nodes.insert(
        "node_modules/C".to_string(),
        Node {
            location: "node_modules/C".to_string(),
            install_name: "C".to_string(),
            name: "C".to_string(),
            version: "1.0.0".to_string(),
            parsed_version: rnpm_core::semver::Version::parse("1.0.0").ok(),
            ..Default::default()
        },
    );

    // Node A is at node_modules/A
    graph.nodes.insert(
        "node_modules/A".to_string(),
        Node {
            location: "node_modules/A".to_string(),
            install_name: "A".to_string(),
            name: "A".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        },
    );

    // Node B is nested at node_modules/A/node_modules/B
    graph.nodes.insert(
        "node_modules/A/node_modules/B".to_string(),
        Node {
            location: "node_modules/A/node_modules/B".to_string(),
            install_name: "B".to_string(),
            name: "B".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        },
    );

    // Dependent B requires C@^2.0.0
    let target = PackageTarget::Range(Range::parse("^2.0.0").unwrap());
    let decision = determine_placement(&graph, "node_modules/A/node_modules/B", "C", "C", &target);

    // Root has incompatible C@1.0.0, so C@^2.0.0 hoists to intermediate ancestor node_modules/A/node_modules/C!
    assert_eq!(
        decision,
        PlacementDecision::PlaceNew("node_modules/A/node_modules/C".to_string())
    );
}

#[test]
fn test_multi_node_peer_cycles_3_node() {
    let mut provider = InMemoryPackageProvider::new();

    // 3-node peer cycle:
    // pkg-a peers pkg-b (^1.0.0)
    // pkg-b peers pkg-c (^1.0.0)
    // pkg-c peers pkg-a (^1.0.0)
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("pkg-b".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.peer_dependencies
            .insert("pkg-c".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("pkg-c", "1.0.0", |v| {
        v.peer_dependencies
            .insert("pkg-a".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-cycle-3-app".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("3-node cyclic peer dependencies must resolve without stack overflow or error");

    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));
    assert!(graph.nodes.contains_key("node_modules/pkg-c"));
}

#[test]
fn test_optional_peer_when_present_and_compatible() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("canvas", "2.8.0", |_| {});
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies
            .insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-present".to_string());
    // Both chart-pkg and canvas installed explicitly
    manifest
        .dependencies
        .insert("chart-pkg".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("canvas".to_string(), "2.8.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    assert!(graph.nodes.contains_key("node_modules/canvas"));

    // Edge from chart-pkg to canvas exists
    let edges = graph.get_outgoing_edges("node_modules/chart-pkg");
    let canvas_edge = edges.iter().find(|e| e.package_name == "canvas");
    assert!(canvas_edge.is_some());
    assert_eq!(canvas_edge.unwrap().to_location, "node_modules/canvas");
}

#[test]
fn test_optional_peer_when_present_and_incompatible() {
    let mut provider = InMemoryPackageProvider::new();

    // canvas installed at 1.0.0
    provider.add_version("canvas", "1.0.0", |_| {});
    // chart-pkg optionally peers canvas ^2.0.0
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies
            .insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-incompat".to_string());
    manifest
        .dependencies
        .insert("chart-pkg".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("canvas".to_string(), "1.0.0".to_string());

    // In strict mode (strict_peers: true), incompatible optional peer must NOT fail with ERESOLVE!
    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Incompatible optional peer must be omitted silently, not fail resolution");

    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    assert!(graph.nodes.contains_key("node_modules/canvas"));
    assert_eq!(
        graph.nodes.get("node_modules/canvas").unwrap().version,
        "1.0.0"
    );
}

#[test]
fn test_optional_peer_absent_not_auto_downloaded() {
    let mut provider = InMemoryPackageProvider::new();

    // canvas exists in registry provider
    provider.add_version("canvas", "2.8.0", |_| {});
    // chart-pkg optionally peers canvas ^2.0.0
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies
            .insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-absent".to_string());
    manifest
        .dependencies
        .insert("chart-pkg".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // chart-pkg is installed, but canvas was NOT auto-downloaded
    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    assert!(!graph.nodes.contains_key("node_modules/canvas"));
}

#[test]
fn test_extreme_monorepo_50_fixture() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::discover_workspaces;
    use std::path::PathBuf;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/fixtures/extreme-monorepo-50");
    if !fixture_dir.exists() {
        return;
    }

    let members = discover_workspaces(&fixture_dir)
        .expect("Must discover all workspace members in extreme-monorepo-50");
    assert_eq!(
        members.len(),
        52,
        "Must discover exactly 52 workspace packages"
    );

    // Construct DAG and compute topological order
    let graph = WorkspaceDependencyGraph::construct(&members)
        .expect("WorkspaceDependencyGraph must construct without errors for extreme-monorepo-50");

    assert_eq!(graph.topological_order.len(), 52);

    let pos = |name: &str| {
        graph
            .topological_order
            .iter()
            .position(|p| p == name)
            .unwrap_or_else(|| panic!("Package {} missing in topological order", name))
    };

    // Verify critical lifecycle ordering
    assert!(pos("pkg-01") < pos("pkg-15"), "pkg-01 must precede pkg-15");
    assert!(pos("pkg-15") < pos("pkg-49"), "pkg-15 must precede pkg-49");
    assert!(pos("pkg-49") < pos("pkg-52"), "pkg-49 must precede pkg-52");
    assert!(pos("pkg-50") < pos("pkg-52"), "pkg-50 must precede pkg-52");
    assert!(pos("pkg-51") < pos("pkg-52"), "pkg-51 must precede pkg-52");

    // Tier 0 packages must precede Tier 1
    assert!(pos("pkg-01") < pos("pkg-11"));
    assert!(pos("pkg-02") < pos("pkg-12"));
    assert!(pos("pkg-05") < pos("pkg-15"));

    // Tier 1 packages must precede Tier 2 diamonds
    assert!(pos("pkg-11") < pos("pkg-26"));
    assert!(pos("pkg-12") < pos("pkg-26"));
}

#[test]
fn test_extreme_circular_monorepo_fixture() {
    use crate::error::SolverError;
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::discover_workspaces;
    use std::path::PathBuf;

    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/fixtures/extreme-circular-monorepo");
    if !fixture_dir.exists() {
        return;
    }

    let members = discover_workspaces(&fixture_dir)
        .expect("Must discover workspace members in extreme-circular-monorepo");
    assert_eq!(
        members.len(),
        2,
        "Must discover exactly 2 workspace packages"
    );

    let result = WorkspaceDependencyGraph::construct(&members);
    assert!(result.is_err(), "Must detect circular dependency");
    match result.unwrap_err() {
        SolverError::CycleDetected(msg) => {
            assert!(msg.contains("Circular workspace dependency detected"));
            assert!(msg.contains("circ-a"));
            assert!(msg.contains("circ-b"));
        }
        other => panic!("Expected CycleDetected error, got: {:?}", other),
    }
}

#[test]
fn test_peer_conflict_rich_diagnostics() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("react", "18.2.0", |_| {});
    provider.add_version("plugin", "1.0.0", |v| {
        v.peer_dependencies
            .insert("react".to_string(), "^17.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("app".to_string());
    manifest
        .dependencies
        .insert("react".to_string(), "18.2.0".to_string());
    manifest
        .dependencies
        .insert("plugin".to_string(), "1.0.0".to_string());

    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();

    assert!(err.is_peer_conflict());
    let (parent, peer, req_spec, found_ver, found_loc, req_by, msg) =
        err.peer_conflict_details().expect("Should be PeerConflict");
    assert_eq!(parent, "plugin");
    assert_eq!(peer, "react");
    assert_eq!(req_spec, "^17.0.0");
    assert_eq!(found_ver, Some("18.2.0"));
    assert_eq!(found_loc, Some("node_modules/react"));
    assert_eq!(req_by, &["app".to_string(), "plugin".to_string()][..]);
    assert!(msg.contains("does not satisfy peer constraint"));

    let err_str = err.to_string();
    // Verify no duplicated parent in chain: "app -> plugin", not "app -> plugin -> plugin"
    assert!(err_str.contains("app -> plugin\n"));
    assert!(!err_str.contains("plugin -> plugin"));
}

#[test]
fn test_platform_filtering_isolation_before_download() {
    let mut provider = InMemoryPackageProvider::new();

    // Incompatible platform package with transitive dependencies
    provider.add_version("linux-bundle", "1.0.0", |v| {
        v.os = Some(vec!["linux".to_string()]);
        v.libc = Some(vec!["glibc".to_string()]);
        v.dependencies
            .insert("cuda-driver".to_string(), "1.0.0".to_string());
        v.dependencies
            .insert("large-weights".to_string(), "1.0.0".to_string());
    });
    provider.add_version("cuda-driver", "1.0.0", |_| {});
    provider.add_version("large-weights", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("platform-isolation-test".to_string());
    manifest
        .optional_dependencies
        .insert("linux-bundle".to_string(), "1.0.0".to_string());

    // Host: Windows x64
    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();

    // Verify complete isolation: linux-bundle is marked skipped
    assert!(graph.is_skipped("linux-bundle"));
    // linux-bundle and its transitive dependencies remain in the graph for
    // cross-platform lockfile parity, but are skipped on this host.
    assert!(graph.nodes.contains_key("node_modules/linux-bundle"));
    assert!(graph.nodes.contains_key("node_modules/cuda-driver"));
    assert!(graph.nodes.contains_key("node_modules/large-weights"));
    assert!(graph.is_skipped("cuda-driver"));
    assert!(graph.is_skipped("large-weights"));
}

#[test]
fn test_root_peer_dependencies_auto_installed() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("react", "18.2.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("root-peer-app".to_string());
    manifest
        .peer_dependencies
        .insert("react".to_string(), "^18.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/react"));
    assert_eq!(
        graph.nodes.get("node_modules/react").unwrap().version,
        "18.2.0"
    );
}

#[test]
fn test_deep_transitive_resolution_100_plus_dependencies_diamond_intersections() {
    use crate::solver::resolve_fast_path;
    use rnpm_lockfile::LockfileV3;

    let mut provider = InMemoryPackageProvider::new();

    // 1. Shared utilities at the bottom of the graph
    provider.add_version("shared-utils", "1.0.0", |_| {});
    provider.add_version("shared-utils", "1.5.0", |_| {});
    provider.add_version("shared-utils", "2.0.0", |_| {});

    // 2. Convergent diamond hubs that bridge across different branches
    provider.add_version("diamond-hub-core", "1.0.0", |v| {
        v.dependencies
            .insert("shared-utils".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("diamond-hub-crypto", "1.0.0", |v| {
        v.dependencies
            .insert("shared-utils".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("diamond-hub-telemetry", "1.0.0", |v| {
        v.dependencies
            .insert("shared-utils".to_string(), "^1.0.0".to_string());
    });

    // 3. Construct 12 layers with 10 packages per layer (120 layer packages)
    // Connecting each layer to the next in an interlocking diamond lattice:
    // pkg-l{L}-{i} depends on pkg-l{L+1}-{i} and pkg-l{L+1}-{(i+1)%10}.
    // Additionally, layers connect to diamond hubs.
    const NUM_LAYERS: usize = 12;
    const PKGS_PER_LAYER: usize = 10;

    for l in 0..NUM_LAYERS {
        for i in 0..PKGS_PER_LAYER {
            let pkg_name = format!("pkg-l{}-{}", l, i);
            provider.add_version(&pkg_name, "1.0.0", |v| {
                if l + 1 < NUM_LAYERS {
                    // Diamond intersection: 2 edges down to next layer
                    let next_a = format!("pkg-l{}-{}", l + 1, i);
                    let next_b = format!("pkg-l{}-{}", l + 1, (i + 1) % PKGS_PER_LAYER);
                    v.dependencies.insert(next_a, "1.0.0".to_string());
                    v.dependencies.insert(next_b, "1.0.0".to_string());
                } else {
                    // Bottom layer: all depend on shared-utils ^1.0.0
                    v.dependencies
                        .insert("shared-utils".to_string(), "^1.0.0".to_string());
                }

                // Cross-cutting diamond hub intersections
                if l % 3 == 0 && i % 3 == 0 {
                    v.dependencies
                        .insert("diamond-hub-core".to_string(), "^1.0.0".to_string());
                }
                if l % 4 == 0 && i % 4 == 0 {
                    v.dependencies
                        .insert("diamond-hub-crypto".to_string(), "^1.0.0".to_string());
                }
                if l % 5 == 0 && i % 5 == 0 {
                    v.dependencies
                        .insert("diamond-hub-telemetry".to_string(), "^1.0.0".to_string());
                }

                // Sub-branch conflict: layer 8, pkg 5 requires incompatible shared-utils ^2.0.0
                if l == 8 && i == 5 {
                    v.dependencies
                        .insert("shared-utils".to_string(), "^2.0.0".to_string());
                }
            });
        }
    }

    // Root project depends on the 10 packages in layer 0
    let mut manifest = Manifest::default();
    manifest.name = Some("stress-100-project".to_string());
    for i in 0..PKGS_PER_LAYER {
        manifest
            .dependencies
            .insert(format!("pkg-l0-{}", i), "1.0.0".to_string());
    }

    let start = std::time::Instant::now();
    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Resolution of 100+ dependency diamond stress graph must succeed");
    let elapsed = start.elapsed();
    println!("Resolved {} nodes in {:?}", graph.nodes.len(), elapsed);

    // Assert graph size exceeds 100 dependencies (120 layer pkgs + 3 hubs + shared-utils + root)
    assert!(
        graph.nodes.len() > 100,
        "Graph nodes count {} must exceed 100",
        graph.nodes.len()
    );

    // Verify root-hoisted shared-utils resolved to 1.5.0 (highest matching ^1.0.0)
    assert!(graph.nodes.contains_key("node_modules/shared-utils"));
    let root_shared = graph.nodes.get("node_modules/shared-utils").unwrap();
    assert_eq!(root_shared.version, "1.5.0");

    // Verify diamond hubs are hoisted to root node_modules
    assert!(graph.nodes.contains_key("node_modules/diamond-hub-core"));
    assert!(graph.nodes.contains_key("node_modules/diamond-hub-crypto"));
    assert!(graph
        .nodes
        .contains_key("node_modules/diamond-hub-telemetry"));

    // Verify conflict-nested shared-utils@2.0.0 exists for pkg-l8-5
    let nested_node = graph.nodes.iter().find(|(path, node)| {
        node.name == "shared-utils" && node.version == "2.0.0" && path.contains("pkg-l8-5")
    });
    assert!(
        nested_node.is_some(),
        "Expected conflict-nested shared-utils@2.0.0 under pkg-l8-5"
    );

    // Verify Lockfile v3 generation and deterministic serialization
    let lockfile = graph.to_lockfile_v3("stress-100-project", Some("1.0.0"));
    assert!(
        lockfile.packages.len() > 100,
        "Lockfile packages count {} must exceed 100",
        lockfile.packages.len()
    );

    // All paths in lockfile must be POSIX
    for path in lockfile.packages.keys() {
        assert!(
            !path.contains('\\'),
            "Lockfile key {} contains backslash",
            path
        );
    }

    let lock_json = lockfile.to_json_string().unwrap();
    let parsed_lock = LockfileV3::from_json_str(&lock_json).unwrap();
    assert_eq!(parsed_lock.packages.len(), lockfile.packages.len());

    // Verify fast-path resolution with lockfile
    let fast_graph = resolve_fast_path(&manifest, &parsed_lock, &options)
        .expect("Fast-path resolution must succeed from lockfile");
    assert_eq!(fast_graph.nodes.len(), graph.nodes.len());
}

#[test]
fn test_cyclic_peer_resolution_extreme_density_clique() {
    let mut provider = InMemoryPackageProvider::new();

    // 6-node dense peer clique: P0 through P5
    // Every package has peer dependencies on all 5 other packages (30 mutual peer edges)
    let packages = [
        "clique-p0",
        "clique-p1",
        "clique-p2",
        "clique-p3",
        "clique-p4",
        "clique-p5",
    ];

    for &pkg in &packages {
        provider.add_version(pkg, "1.0.0", |v| {
            for &peer in &packages {
                if peer != pkg {
                    v.peer_dependencies
                        .insert(peer.to_string(), "^1.0.0".to_string());
                }
            }
        });
    }

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-clique-app".to_string());
    // Root depends on the first node
    manifest
        .dependencies
        .insert("clique-p0".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Dense 6-node peer clique (30 edges) must resolve cleanly without stack overflow");

    // All 6 packages must be installed in root node_modules
    for &pkg in &packages {
        let loc = format!("node_modules/{}", pkg);
        assert!(
            graph.nodes.contains_key(&loc),
            "Missing clique node: {}",
            loc
        );
    }

    // Verify peer dependency edges exist between the clique members
    let p0_edges = graph.get_outgoing_edges("node_modules/clique-p0");
    assert_eq!(
        p0_edges.len(),
        5,
        "P0 must have 5 peer edges to other clique members"
    );
    for edge in p0_edges {
        assert_eq!(edge.dep_type, DependencyType::Peer);
        assert!(packages.contains(&edge.package_name.as_str()));
    }
}

#[test]
fn test_cyclic_peer_resolution_multi_level_overlapping_requirements() {
    let mut provider = InMemoryPackageProvider::new();

    // Multi-level overlapping peer cycles:
    // Cycle 1: alpha <-> beta
    // Cycle 2: beta <-> gamma <-> delta (overlaps at beta)
    // Cycle 3: delta <-> epsilon <-> alpha (overlaps at delta and alpha)
    // Multi-level: beta also has a regular production dependency on sub-widget,
    // which itself has a peer dependency on gamma!

    provider.add_version("alpha", "1.0.0", |v| {
        v.peer_dependencies
            .insert("beta".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("epsilon".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("beta", "1.0.0", |v| {
        v.peer_dependencies
            .insert("alpha".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("gamma".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("sub-widget".to_string(), "1.0.0".to_string());
    });

    provider.add_version("gamma", "1.0.0", |v| {
        v.peer_dependencies
            .insert("beta".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("delta".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("delta", "1.0.0", |v| {
        v.peer_dependencies
            .insert("gamma".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("epsilon".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("epsilon", "1.0.0", |v| {
        v.peer_dependencies
            .insert("delta".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("alpha".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("sub-widget", "1.0.0", |v| {
        v.peer_dependencies
            .insert("gamma".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("multi-level-peer-app".to_string());
    manifest
        .dependencies
        .insert("alpha".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Multi-level overlapping cyclic peers must resolve cleanly");

    assert!(graph.nodes.contains_key("node_modules/alpha"));
    assert!(graph.nodes.contains_key("node_modules/beta"));
    assert!(graph.nodes.contains_key("node_modules/gamma"));
    assert!(graph.nodes.contains_key("node_modules/delta"));
    assert!(graph.nodes.contains_key("node_modules/epsilon"));
    assert!(graph.nodes.contains_key("node_modules/sub-widget"));
}

#[test]
fn test_cyclic_peer_resolution_dense_mixed_optional_and_conflicts() {
    let mut provider = InMemoryPackageProvider::new();

    // Node A peers B (required), C (optional present), D (optional absent)
    provider.add_version("node-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("node-b".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("opt-present".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("opt-absent".to_string(), "^1.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "opt-present".to_string(),
            PeerDependencyMeta { optional: true },
        );
        meta.insert(
            "opt-absent".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    // Node B peers Node A (cyclic) and opt-present (cyclic optional)
    provider.add_version("node-b", "1.0.0", |v| {
        v.peer_dependencies
            .insert("node-a".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("opt-present".to_string(), "^1.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "opt-present".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    // opt-present is in provider and peers node-a
    provider.add_version("opt-present", "1.0.0", |v| {
        v.peer_dependencies
            .insert("node-a".to_string(), "^1.0.0".to_string());
    });
    // Note: opt-absent is NOT in provider

    let mut manifest = Manifest::default();
    manifest.name = Some("dense-mixed-peer-app".to_string());
    manifest
        .dependencies
        .insert("node-a".to_string(), "1.0.0".to_string());
    // Explicitly include opt-present in root so it is present in scope
    manifest
        .dependencies
        .insert("opt-present".to_string(), "1.0.0".to_string());

    // Scenario 1: Clean resolution with mixed optional cyclic peers
    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Dense mixed optional cyclic peers must resolve cleanly");

    assert!(graph.nodes.contains_key("node_modules/node-a"));
    assert!(graph.nodes.contains_key("node_modules/node-b"));
    assert!(graph.nodes.contains_key("node_modules/opt-present"));
    assert!(!graph.nodes.contains_key("node_modules/opt-absent"));

    // Scenario 2: Strict peer conflict within cyclic relationship
    // Create an incompatible node-b-v2 requiring node-a@^2.0.0
    provider.add_version("node-b-conflict", "1.0.0", |v| {
        v.peer_dependencies
            .insert("node-a".to_string(), "^2.0.0".to_string());
    });

    let mut conflict_manifest = Manifest::default();
    conflict_manifest.name = Some("peer-conflict-app".to_string());
    conflict_manifest
        .dependencies
        .insert("node-a".to_string(), "1.0.0".to_string());
    conflict_manifest
        .dependencies
        .insert("node-b-conflict".to_string(), "1.0.0".to_string());

    let strict_opts = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&conflict_manifest, &provider, &strict_opts).unwrap_err();
    assert!(err.is_peer_conflict());
    let err_str = err.to_string();
    assert!(err_str.contains("ERESOLVE: Conflicting peer dependency 'node-a'"));

    // Scenario 3: Legacy peer deps bypasses conflict
    let legacy_opts = ResolverOptions {
        legacy_peer_deps: true,
        ..Default::default()
    };
    let legacy_graph = resolve_dependency_graph(&conflict_manifest, &provider, &legacy_opts)
        .expect("legacy_peer_deps must bypass peer conflict");
    assert!(legacy_graph.nodes.contains_key("node_modules/node-a"));
    assert!(legacy_graph
        .nodes
        .contains_key("node_modules/node-b-conflict"));
}

#[test]
fn test_pathological_overrides_deep_scoped_and_spec_targeted() {
    let mut provider = InMemoryPackageProvider::new();

    // 5-level deep chain: app -> lev1 -> lev2 -> lev3 -> lev4 -> deep-target
    provider.add_version("lev1", "1.0.0", |v| {
        v.dependencies
            .insert("lev2".to_string(), "1.0.0".to_string());
    });
    provider.add_version("lev2", "1.0.0", |v| {
        v.dependencies
            .insert("lev3".to_string(), "1.0.0".to_string());
    });
    provider.add_version("lev3", "1.0.0", |v| {
        v.dependencies
            .insert("lev4".to_string(), "1.0.0".to_string());
    });
    provider.add_version("lev4", "1.0.0", |v| {
        v.dependencies
            .insert("deep-target".to_string(), "^1.0.0".to_string());
    });

    // Another branch: app -> other-lev1 -> lev2 -> lev3 -> lev4 -> deep-target
    provider.add_version("other-lev1", "1.0.0", |v| {
        v.dependencies
            .insert("lev2".to_string(), "1.0.0".to_string());
    });

    provider.add_version("deep-target", "1.0.0", |_| {});
    provider.add_version("deep-target", "5.0.0", |_| {});

    // Wildcard-overridden target
    provider.add_version("wildcard-pkg", "1.0.0", |_| {});
    provider.add_version("wildcard-pkg", "3.0.0", |_| {});

    // Range-overridden target
    provider.add_version("range-pkg", "1.2.0", |_| {});
    provider.add_version("range-pkg", "2.9.9", |_| {});

    // Reference-overridden target ($canon-pkg)
    provider.add_version("canon-pkg", "4.2.0", |_| {});
    provider.add_version("shadow-pkg", "1.0.0", |_| {});
    provider.add_version("shadow-pkg", "4.2.0", |_| {});

    // Scoped package override
    provider.add_version("@deep/scoped-pkg", "1.0.0", |_| {});
    provider.add_version("@deep/scoped-pkg", "1.9.9", |_| {});

    // Package that uses all these
    provider.add_version("consumer-pkg", "1.0.0", |v| {
        v.dependencies
            .insert("wildcard-pkg".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("range-pkg".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("shadow-pkg".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("@deep/scoped-pkg".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("pathological-overrides-app".to_string());
    manifest
        .dependencies
        .insert("lev1".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("canon-pkg".to_string(), "4.2.0".to_string());
    manifest
        .dependencies
        .insert("consumer-pkg".to_string(), "1.0.0".to_string());

    // Configure pathological overrides:
    // 1. Deep 4-level nested override: lev1 -> lev2 -> lev3 -> lev4 -> deep-target = 5.0.0
    // 2. Wildcard spec override: wildcard-pkg@* = 3.0.0
    // 3. Range spec override: range-pkg@>=1.0.0 <2.0.0 = 2.9.9
    // 4. Reference override: shadow-pkg = $canon-pkg (pulls 4.2.0)
    // 5. Scoped package override: @deep/scoped-pkg@^1.0.0 = 1.9.9
    let overrides_json = serde_json::json!({
        "lev1": {
            "lev2": {
                "lev3": {
                    "lev4": {
                        "deep-target": "5.0.0"
                    }
                }
            }
        },
        "wildcard-pkg@*": "3.0.0",
        "range-pkg@>=1.0.0 <2.0.0": "2.9.9",
        "shadow-pkg": "$canon-pkg",
        "@deep/scoped-pkg@^1.0.0": "1.9.9"
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Pathological overrides resolution must succeed");

    // 1. Verify deep nested override
    let deep_node = graph
        .nodes
        .values()
        .find(|n| n.name == "deep-target")
        .unwrap();
    assert_eq!(deep_node.version, "5.0.0");

    // 2. Verify wildcard spec override
    let wildcard_node = graph.nodes.get("node_modules/wildcard-pkg").unwrap();
    assert_eq!(wildcard_node.version, "3.0.0");

    // 3. Verify range spec override
    let range_node = graph.nodes.get("node_modules/range-pkg").unwrap();
    assert_eq!(range_node.version, "2.9.9");

    // 4. Verify reference override ($canon-pkg -> 4.2.0)
    let shadow_node = graph.nodes.get("node_modules/shadow-pkg").unwrap();
    assert_eq!(shadow_node.version, "4.2.0");

    // 5. Verify scoped package override
    let scoped_node = graph.nodes.get("node_modules/@deep/scoped-pkg").unwrap();
    assert_eq!(scoped_node.version, "1.9.9");
}

#[test]
fn test_pathological_scoped_aliases_and_overrides() {
    let mut provider = InMemoryPackageProvider::new();

    // Provider versions
    provider.add_version("@org/real-core", "1.0.0", |_| {});
    provider.add_version("@org/real-core", "1.8.8", |_| {});

    provider.add_version("@org/real-client", "2.0.0", |_| {});
    provider.add_version("@org/real-client", "2.9.0", |_| {});

    provider.add_version("unscoped-lib", "3.1.5+build.2024", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("alias-overrides-app".to_string());

    // 1. Scoped alias pointing to scoped package:
    // "@scope/alias-core": "npm:@org/real-core@^1.0.0"
    manifest.dependencies.insert(
        "@scope/alias-core".to_string(),
        "npm:@org/real-core@^1.0.0".to_string(),
    );

    // 2. Unscoped alias pointing to scoped package:
    // "alias-client": "npm:@org/real-client@^2.0.0"
    manifest.dependencies.insert(
        "alias-client".to_string(),
        "npm:@org/real-client@^2.0.0".to_string(),
    );

    // 3. Scoped alias pointing to unscoped package with build tag:
    // "@scope/alias-lib": "npm:unscoped-lib@~3.1.0"
    manifest.dependencies.insert(
        "@scope/alias-lib".to_string(),
        "npm:unscoped-lib@~3.1.0".to_string(),
    );

    // Overrides:
    // - Override @org/real-core (real package name) to 1.8.8
    // - Override alias-client (install name) to npm:@org/real-client@2.9.0
    let overrides_json = serde_json::json!({
        "@org/real-core": "1.8.8",
        "alias-client": "npm:@org/real-client@2.9.0"
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Scoped aliases with overrides must resolve cleanly");

    // 1. @scope/alias-core is placed at node_modules/@scope/alias-core
    // Real package is @org/real-core, overridden to 1.8.8
    assert!(graph.nodes.contains_key("node_modules/@scope/alias-core"));
    let node_core = graph.nodes.get("node_modules/@scope/alias-core").unwrap();
    assert_eq!(node_core.install_name, "@scope/alias-core");
    assert_eq!(node_core.name, "@org/real-core");
    assert_eq!(node_core.version, "1.8.8");

    // 2. alias-client is placed at node_modules/alias-client
    // Real package is @org/real-client, overridden to 2.9.0
    assert!(graph.nodes.contains_key("node_modules/alias-client"));
    let node_client = graph.nodes.get("node_modules/alias-client").unwrap();
    assert_eq!(node_client.install_name, "alias-client");
    assert_eq!(node_client.name, "@org/real-client");
    assert_eq!(node_client.version, "2.9.0");

    // 3. @scope/alias-lib is placed at node_modules/@scope/alias-lib
    // Real package is unscoped-lib with build tag
    assert!(graph.nodes.contains_key("node_modules/@scope/alias-lib"));
    let node_lib = graph.nodes.get("node_modules/@scope/alias-lib").unwrap();
    assert_eq!(node_lib.install_name, "@scope/alias-lib");
    assert_eq!(node_lib.name, "unscoped-lib");
    assert_eq!(node_lib.version, "3.1.5+build.2024");

    // Verify Lockfile v3 serialization preserves alias real names and POSIX paths
    let lockfile = graph.to_lockfile_v3("alias-overrides-app", Some("1.0.0"));
    let pkg_core = lockfile
        .packages
        .get("node_modules/@scope/alias-core")
        .unwrap();
    assert_eq!(pkg_core.name.as_deref(), Some("@org/real-core"));
    assert_eq!(pkg_core.version.as_deref(), Some("1.8.8"));

    let pkg_client = lockfile.packages.get("node_modules/alias-client").unwrap();
    assert_eq!(pkg_client.name.as_deref(), Some("@org/real-client"));
    assert_eq!(pkg_client.version.as_deref(), Some("2.9.0"));

    let pkg_lib = lockfile
        .packages
        .get("node_modules/@scope/alias-lib")
        .unwrap();
    assert_eq!(pkg_lib.name.as_deref(), Some("unscoped-lib"));
    assert_eq!(pkg_lib.version.as_deref(), Some("3.1.5+build.2024"));
}

#[test]
fn test_stress_cyclic_peer_web_mesh() {
    let mut provider = InMemoryPackageProvider::new();

    // 8-node cyclic peer mesh:
    // P0 -> P1, P2
    // P1 -> P2, P3
    // P2 -> P3, P4
    // P3 -> P4, P5
    // P4 -> P5, P6
    // P5 -> P6, P7
    // P6 -> P7, P0 (back-edge completing 7-node ring)
    // P7 -> P0, P3 (cross-mesh shortcuts)
    let packages = [
        ("mesh-p0", vec!["mesh-p1", "mesh-p2"]),
        ("mesh-p1", vec!["mesh-p2", "mesh-p3"]),
        ("mesh-p2", vec!["mesh-p3", "mesh-p4"]),
        ("mesh-p3", vec!["mesh-p4", "mesh-p5"]),
        ("mesh-p4", vec!["mesh-p5", "mesh-p6"]),
        ("mesh-p5", vec!["mesh-p6", "mesh-p7"]),
        ("mesh-p6", vec!["mesh-p7", "mesh-p0"]),
        ("mesh-p7", vec!["mesh-p0", "mesh-p3"]),
    ];

    for (pkg, peers) in &packages {
        provider.add_version(*pkg, "1.0.0", |v| {
            for peer in peers {
                v.peer_dependencies
                    .insert(peer.to_string(), "^1.0.0".to_string());
            }
        });
    }

    let mut manifest = Manifest::default();
    manifest.name = Some("stress-cyclic-mesh-app".to_string());
    manifest
        .dependencies
        .insert("mesh-p0".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Complex 8-node cyclic peer mesh must resolve cleanly without stack overflow");

    for (pkg, _) in &packages {
        let loc = format!("node_modules/{pkg}");
        assert!(graph.nodes.contains_key(&loc), "Missing mesh node: {loc}");
    }

    // Verify all peer edges exist in graph
    for (pkg, peers) in &packages {
        let from_loc = format!("node_modules/{pkg}");
        let outgoing = graph.get_outgoing_edges(&from_loc);
        for peer in peers {
            let edge = outgoing.iter().find(|e| e.package_name == *peer);
            assert!(edge.is_some(), "Edge from {pkg} to {peer} must exist");
            assert_eq!(edge.unwrap().dep_type, DependencyType::Peer);
        }
    }
}

#[test]
fn test_stress_deep_peer_deduplication_and_ancestor_hoisting() {
    let mut provider = InMemoryPackageProvider::new();

    // Deep 6-level linear chain:
    // app -> deep-l1 -> deep-l2 -> deep-l3 -> deep-l4 -> deep-l5 -> deep-l6
    provider.add_version("deep-l1", "1.0.0", |v| {
        v.dependencies
            .insert("deep-l2".to_string(), "1.0.0".to_string());
    });
    provider.add_version("deep-l2", "1.0.0", |v| {
        v.dependencies
            .insert("deep-l3".to_string(), "1.0.0".to_string());
    });
    provider.add_version("deep-l3", "1.0.0", |v| {
        v.dependencies
            .insert("deep-l4".to_string(), "1.0.0".to_string());
        // deep-l3 peers root-peer@^1.0.0
        v.peer_dependencies
            .insert("root-peer".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("deep-l4", "1.0.0", |v| {
        v.dependencies
            .insert("deep-l5".to_string(), "1.0.0".to_string());
    });
    provider.add_version("deep-l5", "1.0.0", |v| {
        v.dependencies
            .insert("deep-l6".to_string(), "1.0.0".to_string());
    });
    provider.add_version("deep-l6", "1.0.0", |v| {
        // deep-l6 also peers root-peer@^1.0.0
        v.peer_dependencies
            .insert("root-peer".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("root-peer", "1.2.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("deep-peer-dedup-app".to_string());
    manifest
        .dependencies
        .insert("deep-l1".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("root-peer".to_string(), "1.2.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Deep peer deduplication through 6 ancestor scopes must succeed");

    // root-peer is hoisted at root node_modules/root-peer
    assert!(graph.nodes.contains_key("node_modules/root-peer"));
    assert_eq!(
        graph.nodes.get("node_modules/root-peer").unwrap().version,
        "1.2.0"
    );

    // Both deep-l3 and deep-l6 must reuse the root instance (no duplicate nested root-peer)
    for (loc, node) in &graph.nodes {
        if node.name == "root-peer" {
            assert_eq!(
                loc, "node_modules/root-peer",
                "root-peer must only exist at root, found at {loc}"
            );
        }
    }

    // Verify outgoing edges from both deep-l3 and deep-l6 point directly to node_modules/root-peer
    let l3_edges = graph.get_outgoing_edges("node_modules/deep-l3");
    let l3_peer_edge = l3_edges
        .iter()
        .find(|e| e.package_name == "root-peer")
        .unwrap();
    assert_eq!(l3_peer_edge.to_location, "node_modules/root-peer");

    let l6_edges = graph.get_outgoing_edges("node_modules/deep-l6");
    let l6_peer_edge = l6_edges
        .iter()
        .find(|e| e.package_name == "root-peer")
        .unwrap();
    assert_eq!(l6_peer_edge.to_location, "node_modules/root-peer");
}

#[test]
fn test_stress_overrides_arrow_syntax_and_nested_spec_ranges() {
    let mut provider = InMemoryPackageProvider::new();

    // Packages
    provider.add_version("builder", "1.0.0", |v| {
        v.dependencies
            .insert("bundler".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("@core/plugin".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("bundler", "1.0.0", |_| {});
    provider.add_version("bundler", "2.0.0", |_| {});

    provider.add_version("@core/plugin", "1.0.0", |_| {});
    provider.add_version("@core/plugin", "1.5.0", |_| {});

    // Scoped multi-hop: @scope/framework -> @scope/nested-dep -> deep-leaf
    provider.add_version("@scope/framework", "1.0.0", |v| {
        v.dependencies
            .insert("@scope/nested-dep".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("@scope/nested-dep", "1.0.0", |v| {
        v.dependencies
            .insert("deep-leaf".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("deep-leaf", "1.0.0", |_| {});
    provider.add_version("deep-leaf", "3.2.1", |_| {});

    // Independent consumer requesting bundler and deep-leaf
    provider.add_version("standard-consumer", "1.0.0", |v| {
        v.dependencies
            .insert("bundler".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("deep-leaf".to_string(), "^1.0.0".to_string());
    });

    // Spec-targeted override on target-tool
    provider.add_version("consumer-old-tool", "1.0.0", |v| {
        v.dependencies
            .insert("target-tool".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("consumer-new-tool", "1.0.0", |v| {
        v.dependencies
            .insert("target-tool".to_string(), "^2.0.0".to_string());
    });
    provider.add_version("target-tool", "1.0.0", |_| {});
    provider.add_version("target-tool", "2.0.0", |_| {});
    provider.add_version("target-tool", "2.9.9", |_| {});

    // Mixed nested object + arrow: server -> engine -> worker
    provider.add_version("server", "1.0.0", |v| {
        v.dependencies
            .insert("engine".to_string(), "1.0.0".to_string());
    });
    provider.add_version("engine", "1.0.0", |v| {
        v.dependencies
            .insert("worker".to_string(), "1.0.0".to_string());
    });
    provider.add_version("worker", "1.0.0", |_| {});
    provider.add_version("worker", "4.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("arrow-stress-app".to_string());
    manifest
        .dependencies
        .insert("builder".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("@scope/framework".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("consumer-old-tool".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("consumer-new-tool".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("server".to_string(), "1.0.0".to_string());

    let overrides_json = serde_json::json!({
        "builder > bundler": "2.0.0",
        "builder > @core/plugin": "1.5.0",
        "@scope/framework > @scope/nested-dep > deep-leaf": "3.2.1",
        "target-tool@^2.0.0": "2.9.9",
        "server": {
            "engine > worker": "4.0.0"
        }
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Arrow syntax and spec-targeted overrides must resolve cleanly");

    // 1. builder > bundler overridden to 2.0.0
    let builder_edges = graph.get_outgoing_edges("node_modules/builder");
    let bundler_edge = builder_edges
        .iter()
        .find(|e| e.package_name == "bundler")
        .unwrap();
    let bundler_node = graph.nodes.get(&bundler_edge.to_location).unwrap();
    assert_eq!(bundler_node.version, "2.0.0");

    // 2. builder > @core/plugin overridden to 1.5.0
    let plugin_edge = builder_edges
        .iter()
        .find(|e| e.package_name == "@core/plugin")
        .unwrap();
    let plugin_node = graph.nodes.get(&plugin_edge.to_location).unwrap();
    assert_eq!(plugin_node.version, "1.5.0");

    // 3. Multi-hop scoped: @scope/framework > @scope/nested-dep > deep-leaf overridden to 3.2.1
    let nested_edges = graph.get_outgoing_edges("node_modules/@scope/nested-dep");
    let leaf_edge = nested_edges
        .iter()
        .find(|e| e.package_name == "deep-leaf")
        .unwrap();
    let leaf_node = graph.nodes.get(&leaf_edge.to_location).unwrap();
    assert_eq!(leaf_node.version, "3.2.1");

    // 4. Spec-targeted override on target-tool@^2.0.0 -> 2.9.9, while ^1.0.0 -> 1.0.0
    let old_tool_edges = graph.get_outgoing_edges("node_modules/consumer-old-tool");
    let old_edge = old_tool_edges
        .iter()
        .find(|e| e.package_name == "target-tool")
        .unwrap();
    let old_node = graph.nodes.get(&old_edge.to_location).unwrap();
    assert_eq!(old_node.version, "1.0.0");

    let new_tool_edges = graph.get_outgoing_edges("node_modules/consumer-new-tool");
    let new_edge = new_tool_edges
        .iter()
        .find(|e| e.package_name == "target-tool")
        .unwrap();
    let new_node = graph.nodes.get(&new_edge.to_location).unwrap();
    assert_eq!(new_node.version, "2.9.9");

    // 5. Nested object + arrow key: server -> engine -> worker overridden to 4.0.0
    let engine_edges = graph.get_outgoing_edges("node_modules/engine");
    let worker_edge = engine_edges
        .iter()
        .find(|e| e.package_name == "worker")
        .unwrap();
    let worker_node = graph.nodes.get(&worker_edge.to_location).unwrap();
    assert_eq!(worker_node.version, "4.0.0");
}

#[test]
fn test_stress_npm_aliases_with_peers_and_overrides() {
    let mut provider = InMemoryPackageProvider::new();

    // Real package react
    provider.add_version("react", "18.0.0", |_| {});
    provider.add_version("react", "18.2.0", |_| {});
    provider.add_version("react", "18.3.1", |_| {});

    // Package react-router peers "react"
    provider.add_version("react-router", "6.14.0", |v| {
        v.peer_dependencies
            .insert("react".to_string(), "^18.0.0".to_string());
    });

    // Package custom-ui peers alias name "my-react"
    provider.add_version("custom-ui", "1.0.0", |v| {
        v.peer_dependencies
            .insert("my-react".to_string(), "^18.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("alias-peer-override-app".to_string());
    // Install react via npm: alias "my-react"
    manifest
        .dependencies
        .insert("my-react".to_string(), "npm:react@^18.0.0".to_string());
    manifest
        .dependencies
        .insert("react-router".to_string(), "6.14.0".to_string());
    manifest
        .dependencies
        .insert("custom-ui".to_string(), "1.0.0".to_string());

    // Override real package react to 18.3.1
    let overrides_json = serde_json::json!({
        "react": "18.3.1"
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("npm: alias combined with peers and overrides must resolve cleanly");

    // my-react is placed at node_modules/my-react with name="react" and version="18.3.1"
    assert!(graph.nodes.contains_key("node_modules/my-react"));
    let react_node = graph.nodes.get("node_modules/my-react").unwrap();
    assert_eq!(react_node.install_name, "my-react");
    assert_eq!(react_node.name, "react");
    assert_eq!(react_node.version, "18.3.1");

    // react-router is placed at node_modules/react-router
    assert!(graph.nodes.contains_key("node_modules/react-router"));
    let rr_edges = graph.get_outgoing_edges("node_modules/react-router");
    let rr_peer_edge = rr_edges.iter().find(|e| e.package_name == "react").unwrap();
    assert_eq!(rr_peer_edge.to_location, "node_modules/my-react");
    assert_eq!(rr_peer_edge.dep_type, DependencyType::Peer);

    // custom-ui is placed at node_modules/custom-ui
    assert!(graph.nodes.contains_key("node_modules/custom-ui"));
    let ui_edges = graph.get_outgoing_edges("node_modules/custom-ui");
    let ui_peer_edge = ui_edges
        .iter()
        .find(|e| {
            e.install_name == "my-react"
                || e.package_name == "my-react"
                || e.package_name == "react"
        })
        .unwrap();
    assert_eq!(ui_peer_edge.to_location, "node_modules/my-react");
    assert_eq!(ui_peer_edge.dep_type, DependencyType::Peer);

    // Lockfile check: node_modules/my-react records name: "react"
    let lockfile = graph.to_lockfile_v3("alias-peer-override-app", Some("1.0.0"));
    let lock_pkg = lockfile.packages.get("node_modules/my-react").unwrap();
    assert_eq!(lock_pkg.name.as_deref(), Some("react"));
    assert_eq!(lock_pkg.version.as_deref(), Some("18.3.1"));
}

#[test]
fn test_stress_platform_filters_matrix_glibc_musl_darwin_win32() {
    let mut provider = InMemoryPackageProvider::new();

    // Linux glibc optional addon + heavy subdependencies
    provider.add_version("addon-linux-glibc", "1.0.0", |v| {
        v.os = Some(vec!["linux".to_string()]);
        v.cpu = Some(vec!["x64".to_string()]);
        v.libc = Some(vec!["glibc".to_string()]);
        v.dependencies
            .insert("cuda-core".to_string(), "1.0.0".to_string());
        v.dependencies
            .insert("blas".to_string(), "1.0.0".to_string());
    });
    provider.add_version("cuda-core", "1.0.0", |_| {});
    provider.add_version("blas", "1.0.0", |_| {});

    // Linux musl optional addon + subdependency
    provider.add_version("addon-linux-musl", "1.0.0", |v| {
        v.os = Some(vec!["linux".to_string()]);
        v.cpu = Some(vec!["x64".to_string()]);
        v.libc = Some(vec!["musl".to_string()]);
        v.dependencies
            .insert("musl-shim".to_string(), "1.0.0".to_string());
    });
    provider.add_version("musl-shim", "1.0.0", |_| {});

    // macOS arm64 optional addon + subdependency
    provider.add_version("addon-darwin-arm64", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
        v.cpu = Some(vec!["arm64".to_string()]);
        v.dependencies
            .insert("metal-framework".to_string(), "1.0.0".to_string());
    });

    // macOS x64 optional addon + subdependency
    provider.add_version("addon-darwin-x64", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
        v.cpu = Some(vec!["x64".to_string()]);
        v.dependencies
            .insert("metal-framework".to_string(), "1.0.0".to_string());
    });
    provider.add_version("metal-framework", "1.0.0", |_| {});

    // Windows x64 optional addon + subdependency
    provider.add_version("addon-win32-x64", "1.0.0", |v| {
        v.os = Some(vec!["win32".to_string()]);
        v.cpu = Some(vec!["x64".to_string()]);
        v.dependencies
            .insert("directx-helper".to_string(), "1.0.0".to_string());
    });
    provider.add_version("directx-helper", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("platform-matrix-app".to_string());
    manifest
        .optional_dependencies
        .insert("addon-linux-glibc".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("addon-linux-musl".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("addon-darwin-arm64".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("addon-darwin-x64".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("addon-win32-x64".to_string(), "1.0.0".to_string());

    // Host 1: Linux x64 glibc
    let opts_glibc = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("glibc".to_string())),
        ..Default::default()
    };
    let graph1 = resolve_dependency_graph(&manifest, &provider, &opts_glibc).unwrap();
    assert!(graph1.nodes.contains_key("node_modules/addon-linux-glibc"));
    assert!(graph1.nodes.contains_key("node_modules/cuda-core"));
    assert!(graph1.nodes.contains_key("node_modules/blas"));
    assert!(graph1.nodes.contains_key("node_modules/addon-linux-musl"));
    assert!(graph1.nodes.contains_key("node_modules/musl-shim"));
    assert!(graph1.is_skipped("musl-shim"));
    assert!(graph1.nodes.contains_key("node_modules/addon-darwin-arm64"));
    assert!(graph1.nodes.contains_key("node_modules/addon-win32-x64"));
    assert!(graph1.is_skipped("addon-linux-musl"));
    assert!(graph1.is_skipped("addon-darwin-arm64"));
    assert!(graph1.is_skipped("addon-win32-x64"));

    // Host 2: Linux x64 musl (Alpine)
    let opts_musl = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("musl".to_string())),
        ..Default::default()
    };
    let graph2 = resolve_dependency_graph(&manifest, &provider, &opts_musl).unwrap();
    assert!(graph2.nodes.contains_key("node_modules/addon-linux-musl"));
    assert!(graph2.nodes.contains_key("node_modules/musl-shim"));
    assert!(graph2.nodes.contains_key("node_modules/addon-linux-glibc"));
    assert!(graph2.nodes.contains_key("node_modules/cuda-core"));
    assert!(graph2.nodes.contains_key("node_modules/blas"));
    assert!(graph2.is_skipped("cuda-core"));
    assert!(graph2.is_skipped("blas"));
    assert!(graph2.is_skipped("addon-linux-glibc"));

    // Host 3: macOS arm64 (Apple Silicon)
    let opts_mac = ResolverOptions {
        platform: Platform::new("darwin", "arm64"),
        ..Default::default()
    };
    let graph3 = resolve_dependency_graph(&manifest, &provider, &opts_mac).unwrap();
    assert!(graph3.nodes.contains_key("node_modules/addon-darwin-arm64"));
    assert!(graph3.nodes.contains_key("node_modules/metal-framework"));
    assert!(graph3.nodes.contains_key("node_modules/addon-darwin-x64"));
    assert!(graph3.nodes.contains_key("node_modules/addon-linux-glibc"));
    assert!(graph3.nodes.contains_key("node_modules/addon-win32-x64"));
    assert!(graph3.is_skipped("addon-darwin-x64"));
    assert!(graph3.is_skipped("addon-linux-glibc"));
    assert!(graph3.is_skipped("addon-win32-x64"));

    // Host 4: Windows x64
    let opts_win = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph4 = resolve_dependency_graph(&manifest, &provider, &opts_win).unwrap();
    assert!(graph4.nodes.contains_key("node_modules/addon-win32-x64"));
    assert!(graph4.nodes.contains_key("node_modules/directx-helper"));
    assert!(graph4.nodes.contains_key("node_modules/addon-linux-glibc"));
    assert!(graph4.nodes.contains_key("node_modules/addon-linux-musl"));
    assert!(graph4.nodes.contains_key("node_modules/addon-darwin-arm64"));
    assert!(graph4.is_skipped("addon-linux-glibc"));
    assert!(graph4.is_skipped("addon-linux-musl"));
    assert!(graph4.is_skipped("addon-darwin-arm64"));
}

#[test]
fn test_adversarial_dense_5_node_peer_clique() {
    let mut provider = InMemoryPackageProvider::new();

    // 5-node dense peer clique: c1, c2, c3, c4, c5
    // Each package has peer dependencies on all other 4 packages (20 edges total)
    let packages = [
        "clique5-c1",
        "clique5-c2",
        "clique5-c3",
        "clique5-c4",
        "clique5-c5",
    ];

    for &pkg in &packages {
        provider.add_version(pkg, "1.0.0", |v| {
            for &peer in &packages {
                if peer != pkg {
                    v.peer_dependencies
                        .insert(peer.to_string(), "^1.0.0".to_string());
                }
            }
        });
    }

    let mut manifest = Manifest::default();
    manifest.name = Some("adversarial-clique5-app".to_string());
    manifest
        .dependencies
        .insert("clique5-c1".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Dense 5-node peer clique must resolve cleanly");

    // All 5 packages must be installed in root node_modules
    for &pkg in &packages {
        let loc = format!("node_modules/{pkg}");
        assert!(graph.nodes.contains_key(&loc), "Missing clique node: {loc}");
    }

    // Verify all 20 peer dependency edges exist
    let mut total_peer_edges = 0;
    for &pkg in &packages {
        let loc = format!("node_modules/{pkg}");
        let outgoing = graph.get_outgoing_edges(&loc);
        for edge in outgoing {
            if edge.dep_type == DependencyType::Peer {
                total_peer_edges += 1;
                assert!(packages.contains(&edge.package_name.as_str()));
            }
        }
    }
    assert_eq!(
        total_peer_edges, 20,
        "5-node clique must have exactly 20 peer edges"
    );
}

#[test]
fn test_adversarial_multitier_cyclic_peer_diamond_cross_edges() {
    let mut provider = InMemoryPackageProvider::new();

    // Top tier: diamond top branches
    provider.add_version("tier1-left", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tier2-hub".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("tier1-right", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tier2-hub".to_string(), "^1.0.0".to_string());
    });

    // Middle tier: hub
    provider.add_version("tier2-hub", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tier3-alpha".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("tier3-beta".to_string(), "^1.0.0".to_string());
    });

    // Bottom tier: diamond cross edges and back-edges
    // tier3-alpha peers tier2-hub (cycle) and tier3-beta (diamond cross edge)
    provider.add_version("tier3-alpha", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tier2-hub".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("tier3-beta".to_string(), "^1.0.0".to_string());
    });

    // tier3-beta peers tier1-left (back-edge to top tier) and tier3-alpha (cross-edge)
    provider.add_version("tier3-beta", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tier1-left".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("tier3-alpha".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("multitier-diamond-peer-app".to_string());
    manifest
        .dependencies
        .insert("tier1-left".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("tier1-right".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).expect(
        "Multi-tier cyclic peer dependencies with diamond cross-edges must resolve cleanly",
    );

    for node_name in [
        "tier1-left",
        "tier1-right",
        "tier2-hub",
        "tier3-alpha",
        "tier3-beta",
    ] {
        let loc = format!("node_modules/{node_name}");
        assert!(graph.nodes.contains_key(&loc), "Expected node at {loc}");
    }

    // Verify cross-edge tier3-alpha -> tier3-beta exists
    let alpha_edges = graph.get_outgoing_edges("node_modules/tier3-alpha");
    assert!(alpha_edges
        .iter()
        .any(|e| e.package_name == "tier3-beta" && e.dep_type == DependencyType::Peer));
    assert!(alpha_edges
        .iter()
        .any(|e| e.package_name == "tier2-hub" && e.dep_type == DependencyType::Peer));

    // Verify back-edge tier3-beta -> tier1-left exists
    let beta_edges = graph.get_outgoing_edges("node_modules/tier3-beta");
    assert!(beta_edges
        .iter()
        .any(|e| e.package_name == "tier1-left" && e.dep_type == DependencyType::Peer));
}

#[test]
fn test_adversarial_strict_peer_conflict_cyclic_dependencies() {
    use crate::error::SolverError;
    let mut provider = InMemoryPackageProvider::new();

    // Cyclic peer dependency with version conflict:
    // cyclic-strict-a@1.0.0 peers cyclic-strict-b@^1.0.0
    provider.add_version("cyclic-strict-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("cyclic-strict-b".to_string(), "^1.0.0".to_string());
    });
    // cyclic-strict-b@1.0.0 peers cyclic-strict-a@^2.0.0 (conflicts with 1.0.0!)
    provider.add_version("cyclic-strict-b", "1.0.0", |v| {
        v.peer_dependencies
            .insert("cyclic-strict-a".to_string(), "^2.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("strict-cyclic-conflict-app".to_string());
    manifest
        .dependencies
        .insert("cyclic-strict-a".to_string(), "1.0.0".to_string());

    // 1. With strict_peers: true, MUST fail with SolverError::PeerConflict
    let strict_opts = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &strict_opts)
        .expect_err("Strict peer resolution must fail on cyclic incompatible peer constraint");

    match err {
        SolverError::PeerConflict {
            parent,
            peer,
            required_spec,
            found_version,
            ..
        } => {
            assert_eq!(parent, "cyclic-strict-b");
            assert_eq!(peer, "cyclic-strict-a");
            assert_eq!(required_spec, "^2.0.0");
            assert_eq!(found_version, Some("1.0.0".to_string()));
        }
        other => panic!("Expected SolverError::PeerConflict, got {:?}", other),
    }

    // 2. With strict_peers: false, non-strict mode warns and succeeds
    let non_strict_opts = ResolverOptions {
        strict_peers: false,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &non_strict_opts)
        .expect("Non-strict mode must succeed despite cyclic peer constraint mismatch");
    assert!(graph.nodes.contains_key("node_modules/cyclic-strict-a"));
    assert!(graph.nodes.contains_key("node_modules/cyclic-strict-b"));
}

#[test]
fn test_adversarial_disjoint_branches_peer_resolution() {
    let mut provider = InMemoryPackageProvider::new();

    // Disjoint branches:
    // Branch 1: root -> branch-left -> tool-alpha (peers plugin-beta@^1.0.0)
    // Branch 2: root -> branch-right -> plugin-beta (peers tool-alpha@^1.0.0)
    provider.add_version("branch-left", "1.0.0", |v| {
        v.dependencies
            .insert("tool-alpha".to_string(), "1.0.0".to_string());
    });
    provider.add_version("tool-alpha", "1.0.0", |v| {
        v.peer_dependencies
            .insert("plugin-beta".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("branch-right", "1.0.0", |v| {
        v.dependencies
            .insert("plugin-beta".to_string(), "1.0.0".to_string());
    });
    provider.add_version("plugin-beta", "1.0.0", |v| {
        v.peer_dependencies
            .insert("tool-alpha".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("disjoint-branches-app".to_string());
    manifest
        .dependencies
        .insert("branch-left".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("branch-right".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Disjoint branches with mutual peer requirements must resolve without false cycle detection");

    assert!(graph.nodes.contains_key("node_modules/branch-left"));
    assert!(graph.nodes.contains_key("node_modules/branch-right"));
    assert!(graph.nodes.contains_key("node_modules/tool-alpha"));
    assert!(graph.nodes.contains_key("node_modules/plugin-beta"));
}

#[test]
fn test_adversarial_dual_prod_and_optional_peer_dependencies() {
    let mut provider = InMemoryPackageProvider::new();

    // Package dual-dep has BOTH a direct prod dependency AND an optional peer dependency on shared-util
    provider.add_version("dual-dep-pkg", "1.0.0", |v| {
        v.dependencies
            .insert("shared-util".to_string(), "1.0.0".to_string());
        v.peer_dependencies
            .insert("shared-util".to_string(), "^1.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "shared-util".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    provider.add_version("shared-util", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("dual-prod-peer-app".to_string());
    manifest
        .dependencies
        .insert("dual-dep-pkg".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Dual prod and optional peer dependencies must resolve cleanly");

    // shared-util must be installed in root node_modules
    assert!(graph.nodes.contains_key("node_modules/shared-util"));

    // The edge from dual-dep-pkg to shared-util must be DependencyType::Prod, NOT Peer/PeerOptional
    let outgoing = graph.get_outgoing_edges("node_modules/dual-dep-pkg");
    let shared_edge = outgoing
        .iter()
        .find(|e| e.package_name == "shared-util")
        .expect("Edge from dual-dep-pkg to shared-util must exist");

    assert_eq!(
        shared_edge.dep_type,
        DependencyType::Prod,
        "Direct production dependency must not be overwritten by optional peer dependency"
    );
}

#[test]
fn test_adversarial_select_version_semver_not_lexicographical() {
    let mut provider = InMemoryPackageProvider::new();

    // Package with version 9.0.0 and 10.0.0. Lexicographically '9.0.0' > '10.0.0'.
    // SemVer-aware max must select 10.0.0!
    provider.add_version("sort-test-pkg", "9.0.0", |_| {});
    provider.add_version("sort-test-pkg", "10.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("sort-test-app".to_string());
    // Use workspace:* which triggers select_max_semver_version
    manifest
        .dependencies
        .insert("sort-test-pkg".to_string(), "workspace:*".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("SemVer version selection must succeed");

    let node = graph
        .nodes
        .get("node_modules/sort-test-pkg")
        .expect("Node must be installed");
    assert_eq!(
        node.version, "10.0.0",
        "SemVer-aware selection must pick 10.0.0 over 9.0.0"
    );
}

#[test]
fn test_registry_latest_tag_wins_when_range_allows_it() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("tagged-pkg", "1.3.0", |_| {});
    provider.add_version("tagged-pkg", "1.3.1", |_| {});
    provider.set_dist_tag("tagged-pkg", "latest", "1.3.0");

    let mut manifest = Manifest::default();
    manifest.name = Some("tagged-app".to_string());
    manifest
        .dependencies
        .insert("tagged-pkg".to_string(), "^1.0.0".to_string());

    let graph =
        resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();
    assert_eq!(graph.nodes["node_modules/tagged-pkg"].version, "1.3.0");
}

#[test]
fn test_dev_reachability_marks_transitive_lockfile_entries() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("dev-tool", "1.0.0", |v| {
        v.dependencies
            .insert("dev-helper".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("dev-helper", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("dev-flags-app".to_string());
    manifest
        .dev_dependencies
        .insert("dev-tool".to_string(), "^1.0.0".to_string());

    let graph =
        resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();
    let lockfile = graph.to_lockfile_v3("dev-flags-app", Some("1.0.0"));
    assert_eq!(lockfile.packages["node_modules/dev-tool"].dev, Some(true));
    assert_eq!(lockfile.packages["node_modules/dev-helper"].dev, Some(true));
}

#[test]
fn test_workspace_cycle_detection_clean_messages() {
    use crate::error::SolverError;
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // 1. Direct 2-node cycle: pkg-a -> pkg-b -> pkg-a
    let mut ma = Manifest::default();
    ma.name = Some("pkg-a".to_string());
    ma.version = Some("1.0.0".to_string());
    ma.dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    let mem_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: ma,
    };

    let mut mb = Manifest::default();
    mb.name = Some("pkg-b".to_string());
    mb.version = Some("1.0.0".to_string());
    mb.dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let mem_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: mb,
    };

    let err2 = WorkspaceDependencyGraph::construct(&[mem_a, mem_b]).unwrap_err();
    match err2 {
        SolverError::CycleDetected(msg) => {
            assert_eq!(
                msg,
                "Circular workspace dependency detected: pkg-a -> pkg-b -> pkg-a"
            );
        }
        other => panic!("Expected CycleDetected, got: {other:?}"),
    }

    // 2. 3-node cycle: a -> b -> c -> a
    let mut m1 = Manifest::default();
    m1.name = Some("a".to_string());
    m1.dependencies
        .insert("b".to_string(), "workspace:*".to_string());
    let mem1 = WorkspaceMember {
        name: "a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/a"),
        relative_path: "packages/a".to_string(),
        manifest: m1,
    };

    let mut m2 = Manifest::default();
    m2.name = Some("b".to_string());
    m2.dependencies
        .insert("c".to_string(), "workspace:*".to_string());
    let mem2 = WorkspaceMember {
        name: "b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/b"),
        relative_path: "packages/b".to_string(),
        manifest: m2,
    };

    let mut m3 = Manifest::default();
    m3.name = Some("c".to_string());
    m3.dependencies
        .insert("a".to_string(), "workspace:*".to_string());
    let mem3 = WorkspaceMember {
        name: "c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/c"),
        relative_path: "packages/c".to_string(),
        manifest: m3,
    };

    let err3 = WorkspaceDependencyGraph::construct(&[mem1, mem2, mem3]).unwrap_err();
    match err3 {
        SolverError::CycleDetected(msg) => {
            assert_eq!(
                msg,
                "Circular workspace dependency detected: a -> b -> c -> a"
            );
        }
        other => panic!("Expected CycleDetected, got: {other:?}"),
    }

    // 3. Self cycle: self-pkg -> self-pkg
    let mut ms = Manifest::default();
    ms.name = Some("self-pkg".to_string());
    ms.dependencies
        .insert("self-pkg".to_string(), "workspace:*".to_string());
    let mem_s = WorkspaceMember {
        name: "self-pkg".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/self"),
        relative_path: "packages/self".to_string(),
        manifest: ms,
    };

    let err_s = WorkspaceDependencyGraph::construct(&[mem_s]).unwrap_err();
    match err_s {
        SolverError::CycleDetected(msg) => {
            assert_eq!(
                msg,
                "Circular workspace dependency detected: self-pkg -> self-pkg"
            );
        }
        other => panic!("Expected CycleDetected, got: {other:?}"),
    }

    // 4. Cycle with non-cycle prefix: entry -> pkg-x -> pkg-y -> pkg-x
    // The entry package should be stripped from the cycle report
    let mut m_entry = Manifest::default();
    m_entry.name = Some("entry".to_string());
    m_entry
        .dependencies
        .insert("pkg-x".to_string(), "workspace:*".to_string());
    let mem_entry = WorkspaceMember {
        name: "entry".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/entry"),
        relative_path: "packages/entry".to_string(),
        manifest: m_entry,
    };

    let mut mx = Manifest::default();
    mx.name = Some("pkg-x".to_string());
    mx.dependencies
        .insert("pkg-y".to_string(), "workspace:*".to_string());
    let mem_x = WorkspaceMember {
        name: "pkg-x".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-x"),
        relative_path: "packages/pkg-x".to_string(),
        manifest: mx,
    };

    let mut my = Manifest::default();
    my.name = Some("pkg-y".to_string());
    my.dependencies
        .insert("pkg-x".to_string(), "workspace:*".to_string());
    let mem_y = WorkspaceMember {
        name: "pkg-y".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-y"),
        relative_path: "packages/pkg-y".to_string(),
        manifest: my,
    };

    let err_prefix = WorkspaceDependencyGraph::construct(&[mem_entry, mem_x, mem_y]).unwrap_err();
    match err_prefix {
        SolverError::CycleDetected(msg) => {
            assert_eq!(
                msg,
                "Circular workspace dependency detected: pkg-x -> pkg-y -> pkg-x"
            );
        }
        other => panic!("Expected CycleDetected, got: {other:?}"),
    }
}

#[test]
fn test_workspace_protocol_resolution_stress_50_plus_packages() {
    use crate::solver::ResolverOptions;
    use crate::types::InMemoryPackageProvider;
    use crate::workspace::{resolve_workspace_graph, WorkspaceDependencyGraph};
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Create 60 workspace packages organized into 6 tiers
    // Tier 0 (00..09): Base leaf packages (no deps), version 1.0.0
    // Tier 1 (10..19): Depend on Tier 0 via workspace:*, version 1.1.0
    // Tier 2 (20..29): Depend on Tier 1 via workspace:^, version 1.2.0
    // Tier 3 (30..39): Depend on Tier 2 via workspace:~, version 1.3.0
    // Tier 4 (40..49): Diamond nodes, depend on Tier 3 via workspace:* and Tier 2 via workspace:^, version 1.4.0
    // Tier 5 (50..59): Top root nodes, depend on Tier 4 via workspace:~, version 2.0.0
    const TOTAL_PKGS: usize = 60;
    let mut members = Vec::new();

    for i in 0..TOTAL_PKGS {
        let name = format!("pkg-{:02}", i);
        let mut manifest = Manifest::default();
        manifest.name = Some(name.clone());

        let ver = if i < 10 {
            "1.0.0"
        } else if i < 20 {
            "1.1.0"
        } else if i < 30 {
            "1.2.0"
        } else if i < 40 {
            "1.3.0"
        } else if i < 50 {
            "1.4.0"
        } else {
            "2.0.0"
        };
        manifest.version = Some(ver.to_string());

        if (10..20).contains(&i) {
            // workspace:* dependency on Tier 0
            let dep = format!("pkg-{:02}", i - 10);
            manifest.dependencies.insert(dep, "workspace:*".to_string());
        } else if (20..30).contains(&i) {
            // workspace:^ dependency on Tier 1
            let dep = format!("pkg-{:02}", i - 10);
            manifest.dependencies.insert(dep, "workspace:^".to_string());
        } else if (30..40).contains(&i) {
            // workspace:~ dependency on Tier 2
            let dep = format!("pkg-{:02}", i - 10);
            manifest.dependencies.insert(dep, "workspace:~".to_string());
        } else if (40..50).contains(&i) {
            // Diamond: depends on Tier 3 via workspace:* and Tier 2 via workspace:^
            let dep1 = format!("pkg-{:02}", i - 10);
            let dep2 = format!("pkg-{:02}", i - 20);
            manifest
                .dependencies
                .insert(dep1, "workspace:*".to_string());
            manifest
                .dependencies
                .insert(dep2, "workspace:^".to_string());
        } else if i >= 50 {
            // Top tier: depends on Tier 4 via workspace:~
            let dep = format!("pkg-{:02}", i - 10);
            manifest.dependencies.insert(dep, "workspace:~".to_string());
        }

        members.push(WorkspaceMember {
            name: name.clone(),
            version: Some(ver.to_string()),
            path: PathBuf::from(format!("packages/{name}")),
            relative_path: format!("packages/{name}"),
            manifest,
        });
    }

    // Shuffle input members to verify order-independence
    let mut shuffled = members.clone();
    shuffled.reverse();

    let ws_graph = WorkspaceDependencyGraph::construct(&shuffled)
        .expect("WorkspaceDependencyGraph must resolve 60 packages across workspace:*, workspace:^, workspace:~");

    assert_eq!(ws_graph.topological_order.len(), TOTAL_PKGS);

    // Verify all dependencies appear before their dependents in topological_order
    let pos_of = |pkg: &str| -> usize {
        ws_graph
            .topological_order
            .iter()
            .position(|p| p == pkg)
            .unwrap()
    };

    for member in &members {
        let member_pos = pos_of(&member.name);
        for dep in member.manifest.dependencies.keys() {
            let dep_pos = pos_of(dep);
            assert!(
                dep_pos < member_pos,
                "Dependency {dep} (pos {dep_pos}) must precede {member_name} (pos {member_pos})",
                member_name = member.name
            );
        }
    }

    // Verify full workspace graph resolution and lockfile v3 generation
    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("extreme-workspace-root".to_string());
    root_manifest.version = Some("1.0.0".to_string());

    let provider = InMemoryPackageProvider::new();
    let options = ResolverOptions::default();

    let dep_graph = resolve_workspace_graph(&root_manifest, &members, &provider, &options)
        .expect("resolve_workspace_graph must succeed for 60 packages");

    for i in 0..TOTAL_PKGS {
        let name = format!("pkg-{:02}", i);
        let link_loc = format!("node_modules/{name}");
        let phys_loc = format!("packages/{name}");

        assert!(
            dep_graph.nodes.contains_key(&link_loc),
            "Missing link node: {link_loc}"
        );
        assert!(
            dep_graph.nodes.contains_key(&phys_loc),
            "Missing physical node: {phys_loc}"
        );

        let link_node = dep_graph.nodes.get(&link_loc).unwrap();
        assert!(link_node.flags.link);
        assert_eq!(link_node.resolved.as_deref(), Some(phys_loc.as_str()));
    }

    let lockfile = dep_graph.to_lockfile_v3("extreme-workspace-root", Some("1.0.0"));
    assert_eq!(lockfile.packages.len(), TOTAL_PKGS * 2 + 1); // 60 links + 60 physical + 1 root
}

#[test]
fn test_workspace_circular_dev_dependencies_prod_to_dev() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // pkg-a depends on pkg-b in production (dependencies)
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // pkg-b depends on pkg-a in development (devDependencies)
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dev_dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let ws_graph = WorkspaceDependencyGraph::construct(&[member_a, member_b])
        .expect("Circular devDependencies must resolve successfully without failing");

    // Production dependency pkg-a -> pkg-b means pkg-b is a dependency of pkg-a.
    // In leaf-first execution order, pkg-b must be built BEFORE pkg-a!
    let pos_a = ws_graph
        .topological_order
        .iter()
        .position(|x| x == "pkg-a")
        .unwrap();
    let pos_b = ws_graph
        .topological_order
        .iter()
        .position(|x| x == "pkg-b")
        .unwrap();
    assert!(
        pos_b < pos_a,
        "Leaf dependency pkg-b must precede dependent pkg-a"
    );

    // Verify dependencies separation
    assert!(ws_graph.dependencies["pkg-a"].contains_key("pkg-b"));
    assert!(!ws_graph.dependencies["pkg-b"].contains_key("pkg-a"));
    assert!(ws_graph.dev_dependencies["pkg-b"].contains_key("pkg-a"));
}

#[test]
fn test_workspace_mutual_dev_dependencies_cycle() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // pkg-a dev-depends on pkg-b
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dev_dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // pkg-b dev-depends on pkg-a
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dev_dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let ws_graph = WorkspaceDependencyGraph::construct(&[member_a, member_b])
        .expect("Mutual devDependencies cycle must resolve gracefully");

    // Both members must be present in topological order
    assert_eq!(ws_graph.topological_order.len(), 2);
    assert!(ws_graph.topological_order.contains(&"pkg-a".to_string()));
    assert!(ws_graph.topological_order.contains(&"pkg-b".to_string()));

    // Production dependencies are empty, dev_dependencies contain each other
    assert!(ws_graph.dependencies["pkg-a"].is_empty());
    assert!(ws_graph.dependencies["pkg-b"].is_empty());
    assert!(ws_graph.dev_dependencies["pkg-a"].contains_key("pkg-b"));
    assert!(ws_graph.dev_dependencies["pkg-b"].contains_key("pkg-a"));
}

#[test]
fn test_workspace_protocol_variations() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Sibling package target: 1.2.3
    let mut target_m = Manifest::default();
    target_m.name = Some("target-pkg".to_string());
    target_m.version = Some("1.2.3".to_string());
    let target_member = WorkspaceMember {
        name: "target-pkg".to_string(),
        version: Some("1.2.3".to_string()),
        path: PathBuf::from("packages/target-pkg"),
        relative_path: "packages/target-pkg".to_string(),
        manifest: target_m,
    };

    // Test cases that MUST succeed
    let valid_specs = [
        "workspace:*",
        "workspace:^",
        "workspace:~",
        "workspace:^1.0.0",
        "workspace:~1.2.0",
        "workspace:>=1.0.0 <2.0.0",
        "workspace:1.2.3",
        "workspace:../target-pkg",
    ];

    for spec in &valid_specs {
        let mut consumer_m = Manifest::default();
        consumer_m.name = Some("consumer-pkg".to_string());
        consumer_m.version = Some("1.0.0".to_string());
        consumer_m
            .dependencies
            .insert("target-pkg".to_string(), spec.to_string());
        let consumer_member = WorkspaceMember {
            name: "consumer-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            path: PathBuf::from("packages/consumer-pkg"),
            relative_path: "packages/consumer-pkg".to_string(),
            manifest: consumer_m,
        };

        let result = WorkspaceDependencyGraph::construct(&[target_member.clone(), consumer_member]);
        assert!(
            result.is_ok(),
            "Expected spec '{}' to validate successfully, but got error: {:?}",
            spec,
            result.err()
        );
    }

    // Test cases that MUST fail
    let invalid_specs = [
        "workspace:^2.0.0",          // Sibling is 1.2.3
        "workspace:~1.1.0",          // Sibling is 1.2.3
        "workspace:2.0.0",           // Sibling is 1.2.3
        "workspace:../other-dir",    // Path does not resolve to target-pkg
        "workspace:../../../escape", // Escapes workspace root
        "workspace:invalid-semver!", // Malformed constraint
    ];

    for spec in &invalid_specs {
        let mut consumer_m = Manifest::default();
        consumer_m.name = Some("consumer-pkg".to_string());
        consumer_m.version = Some("1.0.0".to_string());
        consumer_m
            .dependencies
            .insert("target-pkg".to_string(), spec.to_string());
        let consumer_member = WorkspaceMember {
            name: "consumer-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            path: PathBuf::from("packages/consumer-pkg"),
            relative_path: "packages/consumer-pkg".to_string(),
            manifest: consumer_m,
        };

        let result = WorkspaceDependencyGraph::construct(&[target_member.clone(), consumer_member]);
        assert!(
            result.is_err(),
            "Expected spec '{}' to fail validation, but it succeeded!",
            spec
        );
    }
}

#[test]
fn test_workspace_complex_dag_diamond_with_dev_back_edges() {
    use crate::workspace::WorkspaceDependencyGraph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    // Diamond DAG in production:
    //         app
    //        /   \
    //       ui    api
    //        \   /
    //        core
    // Plus devDependency back-edges:
    // - core dev-depends on app (for e2e integration tests)
    // - ui dev-depends on app (for demo app)
    // - api dev-depends on ui (for ui client test)

    let mut m_core = Manifest::default();
    m_core.name = Some("pkg-core".to_string());
    m_core.version = Some("1.0.0".to_string());
    m_core
        .dev_dependencies
        .insert("pkg-app".to_string(), "workspace:*".to_string());
    let member_core = WorkspaceMember {
        name: "pkg-core".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/core"),
        relative_path: "packages/core".to_string(),
        manifest: m_core,
    };

    let mut m_ui = Manifest::default();
    m_ui.name = Some("pkg-ui".to_string());
    m_ui.version = Some("1.0.0".to_string());
    m_ui.dependencies
        .insert("pkg-core".to_string(), "workspace:^1.0.0".to_string());
    m_ui.dev_dependencies
        .insert("pkg-app".to_string(), "workspace:*".to_string());
    let member_ui = WorkspaceMember {
        name: "pkg-ui".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/ui"),
        relative_path: "packages/ui".to_string(),
        manifest: m_ui,
    };

    let mut m_api = Manifest::default();
    m_api.name = Some("pkg-api".to_string());
    m_api.version = Some("1.0.0".to_string());
    m_api
        .dependencies
        .insert("pkg-core".to_string(), "workspace:^1.0.0".to_string());
    m_api
        .dev_dependencies
        .insert("pkg-ui".to_string(), "workspace:*".to_string());
    let member_api = WorkspaceMember {
        name: "pkg-api".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/api"),
        relative_path: "packages/api".to_string(),
        manifest: m_api,
    };

    let mut m_app = Manifest::default();
    m_app.name = Some("pkg-app".to_string());
    m_app.version = Some("1.0.0".to_string());
    m_app
        .dependencies
        .insert("pkg-ui".to_string(), "workspace:^1.0.0".to_string());
    m_app
        .dependencies
        .insert("pkg-api".to_string(), "workspace:^1.0.0".to_string());
    let member_app = WorkspaceMember {
        name: "pkg-app".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/app"),
        relative_path: "packages/app".to_string(),
        manifest: m_app,
    };

    // Unordered input
    let members = vec![member_app, member_ui, member_api, member_core];
    let ws_graph = WorkspaceDependencyGraph::construct(&members).expect(
        "Complex 4-package workspace DAG with diamond and dev back-edges must resolve cleanly",
    );

    let order = &ws_graph.topological_order;
    assert_eq!(order.len(), 4);

    let pos_core = order.iter().position(|x| x == "pkg-core").unwrap();
    let pos_ui = order.iter().position(|x| x == "pkg-ui").unwrap();
    let pos_api = order.iter().position(|x| x == "pkg-api").unwrap();
    let pos_app = order.iter().position(|x| x == "pkg-app").unwrap();

    // Leaf pkg-core must precede both pkg-ui and pkg-api
    assert!(pos_core < pos_ui, "pkg-core must precede pkg-ui");
    assert!(pos_core < pos_api, "pkg-core must precede pkg-api");

    // Intermediate nodes pkg-ui and pkg-api must precede root pkg-app
    assert!(pos_ui < pos_app, "pkg-ui must precede pkg-app");
    assert!(pos_api < pos_app, "pkg-api must precede pkg-app");
}

#[test]
fn test_workspace_cross_workspace_hoisting_conflicting_external_versions() {
    use crate::workspace::resolve_workspace_graph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("shared-lib", "1.2.0", |_| {});
    provider.add_version("shared-lib", "2.1.0", |_| {});

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("monorepo-root".to_string());

    // pkg-a requires shared-lib@^1.0.0
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("shared-lib".to_string(), "^1.0.0".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // pkg-b requires conflicting shared-lib@^2.0.0
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dependencies
        .insert("shared-lib".to_string(), "^2.0.0".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let options = ResolverOptions::default();
    let graph = resolve_workspace_graph(&root_manifest, &[member_a, member_b], &provider, &options)
        .expect("Resolution with cross-workspace conflicting external versions must succeed");

    // Both versions of shared-lib must exist in the graph!
    let v1_node = graph
        .nodes
        .values()
        .find(|n| n.name == "shared-lib" && n.version == "1.2.0");
    let v2_node = graph
        .nodes
        .values()
        .find(|n| n.name == "shared-lib" && n.version == "2.1.0");

    assert!(
        v1_node.is_some(),
        "shared-lib@1.2.0 must be present in graph"
    );
    assert!(
        v2_node.is_some(),
        "shared-lib@2.1.0 must be present in graph"
    );

    // One version is hoisted to root node_modules/shared-lib
    assert!(graph.nodes.contains_key("node_modules/shared-lib"));
    let root_shared = graph.nodes.get("node_modules/shared-lib").unwrap();

    // The conflicting version is nested under its member's node_modules
    if root_shared.version == "1.2.0" {
        assert!(graph
            .nodes
            .contains_key("packages/pkg-b/node_modules/shared-lib"));
        assert_eq!(
            graph
                .nodes
                .get("packages/pkg-b/node_modules/shared-lib")
                .unwrap()
                .version,
            "2.1.0"
        );
    } else {
        assert_eq!(root_shared.version, "2.1.0");
        assert!(graph
            .nodes
            .contains_key("packages/pkg-a/node_modules/shared-lib"));
        assert_eq!(
            graph
                .nodes
                .get("packages/pkg-a/node_modules/shared-lib")
                .unwrap()
                .version,
            "1.2.0"
        );
    }

    // Outgoing edges from members point to their respective versions
    let edges_a = graph.get_outgoing_edges("packages/pkg-a");
    let edge_a = edges_a
        .iter()
        .find(|e| e.package_name == "shared-lib")
        .unwrap();
    let target_a = graph.nodes.get(&edge_a.to_location).unwrap();
    assert_eq!(target_a.version, "1.2.0");

    let edges_b = graph.get_outgoing_edges("packages/pkg-b");
    let edge_b = edges_b
        .iter()
        .find(|e| e.package_name == "shared-lib")
        .unwrap();
    let target_b = graph.nodes.get(&edge_b.to_location).unwrap();
    assert_eq!(target_b.version, "2.1.0");
}

#[test]
fn test_adversarial_bipartite_peer_mesh_with_optional_and_strict() {
    let mut provider = InMemoryPackageProvider::new();

    // 4 Core Engines
    provider.add_version("core-engine", "2.0.0", |_| {});
    provider.add_version("core-renderer", "3.5.0", |_| {});
    provider.add_version("core-database", "1.8.0", |_| {});
    provider.add_version("core-telemetry", "5.1.0", |_| {});

    // 4 Plugins forming a bipartite peer web with mixed required and optional peers
    // 1. plugin-ui: strict peer core-engine (^2.0.0), strict peer core-renderer (^3.0.0), optional peer core-telemetry (^5.0.0)
    provider.add_version("plugin-ui", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-engine".to_string(), "^2.0.0".to_string());
        v.peer_dependencies
            .insert("core-renderer".to_string(), "^3.0.0".to_string());
        v.peer_dependencies
            .insert("core-telemetry".to_string(), "^5.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "core-telemetry".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    // 2. plugin-store: strict peer core-engine (^2.0.0), strict peer core-database (^1.0.0), optional peer core-renderer (^3.0.0)
    provider.add_version("plugin-store", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-engine".to_string(), "^2.0.0".to_string());
        v.peer_dependencies
            .insert("core-database".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("core-renderer".to_string(), "^3.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "core-renderer".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    // 3. plugin-analytics: strict peer core-telemetry (^5.0.0), optional peer core-database (^1.0.0), optional peer core-engine (^2.0.0)
    provider.add_version("plugin-analytics", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-telemetry".to_string(), "^5.0.0".to_string());
        v.peer_dependencies
            .insert("core-database".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("core-engine".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "core-database".to_string(),
            PeerDependencyMeta { optional: true },
        );
        meta.insert(
            "core-engine".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    // 4. plugin-export: strict peer core-renderer (^3.0.0), strict peer core-database (^1.0.0), optional absent peer core-opt-missing (^1.0.0)
    provider.add_version("plugin-export", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-renderer".to_string(), "^3.0.0".to_string());
        v.peer_dependencies
            .insert("core-database".to_string(), "^1.0.0".to_string());
        v.peer_dependencies
            .insert("core-opt-missing".to_string(), "^1.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "core-opt-missing".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("bipartite-peer-app".to_string());
    manifest
        .dependencies
        .insert("core-engine".to_string(), "2.0.0".to_string());
    manifest
        .dependencies
        .insert("core-renderer".to_string(), "3.5.0".to_string());
    manifest
        .dependencies
        .insert("core-database".to_string(), "1.8.0".to_string());
    manifest
        .dependencies
        .insert("core-telemetry".to_string(), "5.1.0".to_string());
    manifest
        .dependencies
        .insert("plugin-ui".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-store".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-analytics".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-export".to_string(), "1.0.0".to_string());

    // Phase 1: Successful resolution under strict_peers: true
    let strict_opts = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &strict_opts)
        .expect("Bipartite peer mesh with mixed optional and strict peers must resolve cleanly under strict_peers");

    for name in &[
        "core-engine",
        "core-renderer",
        "core-database",
        "core-telemetry",
        "plugin-ui",
        "plugin-store",
        "plugin-analytics",
        "plugin-export",
    ] {
        let loc = format!("node_modules/{name}");
        assert!(graph.nodes.contains_key(&loc), "Expected node at {loc}");
    }
    assert!(!graph.nodes.contains_key("node_modules/core-opt-missing"));

    // Verify plugin-ui edges
    let ui_edges = graph.get_outgoing_edges("node_modules/plugin-ui");
    let ui_engine = ui_edges
        .iter()
        .find(|e| e.package_name == "core-engine")
        .unwrap();
    assert_eq!(ui_engine.dep_type, DependencyType::Peer);
    let ui_renderer = ui_edges
        .iter()
        .find(|e| e.package_name == "core-renderer")
        .unwrap();
    assert_eq!(ui_renderer.dep_type, DependencyType::Peer);
    let ui_telemetry = ui_edges
        .iter()
        .find(|e| e.package_name == "core-telemetry")
        .unwrap();
    assert_eq!(ui_telemetry.dep_type, DependencyType::PeerOptional);

    // Verify plugin-store edges
    let store_edges = graph.get_outgoing_edges("node_modules/plugin-store");
    let store_engine = store_edges
        .iter()
        .find(|e| e.package_name == "core-engine")
        .unwrap();
    assert_eq!(store_engine.dep_type, DependencyType::Peer);
    let store_db = store_edges
        .iter()
        .find(|e| e.package_name == "core-database")
        .unwrap();
    assert_eq!(store_db.dep_type, DependencyType::Peer);
    let store_renderer = store_edges
        .iter()
        .find(|e| e.package_name == "core-renderer")
        .unwrap();
    assert_eq!(store_renderer.dep_type, DependencyType::PeerOptional);

    // Verify plugin-analytics edges
    let analytics_edges = graph.get_outgoing_edges("node_modules/plugin-analytics");
    let an_telemetry = analytics_edges
        .iter()
        .find(|e| e.package_name == "core-telemetry")
        .unwrap();
    assert_eq!(an_telemetry.dep_type, DependencyType::Peer);
    let an_db = analytics_edges
        .iter()
        .find(|e| e.package_name == "core-database")
        .unwrap();
    assert_eq!(an_db.dep_type, DependencyType::PeerOptional);
    let an_engine = analytics_edges
        .iter()
        .find(|e| e.package_name == "core-engine")
        .unwrap();
    assert_eq!(an_engine.dep_type, DependencyType::PeerOptional);

    // Verify plugin-export edges
    let export_edges = graph.get_outgoing_edges("node_modules/plugin-export");
    let exp_renderer = export_edges
        .iter()
        .find(|e| e.package_name == "core-renderer")
        .unwrap();
    assert_eq!(exp_renderer.dep_type, DependencyType::Peer);
    let exp_db = export_edges
        .iter()
        .find(|e| e.package_name == "core-database")
        .unwrap();
    assert_eq!(exp_db.dep_type, DependencyType::Peer);
    assert!(!export_edges
        .iter()
        .any(|e| e.package_name == "core-opt-missing"));

    // Phase 2: Adversarial strict peer conflict in the bipartite mesh
    provider.add_version("plugin-strict-conflict", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-engine".to_string(), "^3.0.0".to_string());
        v.peer_dependencies
            .insert("core-renderer".to_string(), "^3.0.0".to_string());
    });
    let mut conflict_manifest = manifest.clone();
    conflict_manifest
        .dependencies
        .insert("plugin-strict-conflict".to_string(), "1.0.0".to_string());

    let err = resolve_dependency_graph(&conflict_manifest, &provider, &strict_opts).unwrap_err();
    assert!(err.is_peer_conflict());
    assert!(err
        .to_string()
        .contains("Conflicting peer dependency 'core-engine'"));

    // Phase 3: Adversarial optional peer conflict in the bipartite mesh
    provider.add_version("plugin-optional-conflict", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-renderer".to_string(), "^3.0.0".to_string());
        v.peer_dependencies
            .insert("core-engine".to_string(), "^3.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert(
            "core-engine".to_string(),
            PeerDependencyMeta { optional: true },
        );
        v.peer_dependencies_meta = meta;
    });
    let mut opt_conflict_manifest = manifest.clone();
    opt_conflict_manifest
        .dependencies
        .insert("plugin-optional-conflict".to_string(), "1.0.0".to_string());

    let opt_graph = resolve_dependency_graph(&opt_conflict_manifest, &provider, &strict_opts)
        .expect("Incompatible optional peer must be omitted and not fail strict resolution");
    let opt_edges = opt_graph.get_outgoing_edges("node_modules/plugin-optional-conflict");
    assert!(opt_edges
        .iter()
        .any(|e| e.package_name == "core-renderer" && e.dep_type == DependencyType::Peer));
    assert!(
        !opt_edges.iter().any(|e| e.package_name == "core-engine"),
        "Incompatible optional peer must be omitted"
    );
}

#[test]
fn test_adversarial_deep_transitive_nested_overrides() {
    let mut provider = InMemoryPackageProvider::new();

    // Branch Alpha: 5-level deep chain: root -> alpha-1 -> alpha-2 -> alpha-3 -> alpha-4 -> alpha-5
    provider.add_version("alpha-1", "1.0.0", |v| {
        v.dependencies
            .insert("alpha-2".to_string(), "1.0.0".to_string());
    });
    provider.add_version("alpha-2", "1.0.0", |v| {
        v.dependencies
            .insert("alpha-3".to_string(), "1.0.0".to_string());
    });
    provider.add_version("alpha-3", "1.0.0", |v| {
        v.dependencies
            .insert("alpha-4".to_string(), "1.0.0".to_string());
    });
    provider.add_version("alpha-4", "1.0.0", |v| {
        v.dependencies
            .insert("alpha-5".to_string(), "1.0.0".to_string());
    });
    provider.add_version("alpha-5", "1.0.0", |v| {
        v.dependencies
            .insert("shared-lib".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("metric-tracker".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("logger".to_string(), "^1.0.0".to_string());
    });

    // Branch Beta: 5-level deep chain: root -> beta-1 -> beta-2 -> beta-3 -> beta-4 -> beta-5
    provider.add_version("beta-1", "1.0.0", |v| {
        v.dependencies
            .insert("beta-2".to_string(), "1.0.0".to_string());
    });
    provider.add_version("beta-2", "1.0.0", |v| {
        v.dependencies
            .insert("beta-3".to_string(), "1.0.0".to_string());
    });
    provider.add_version("beta-3", "1.0.0", |v| {
        v.dependencies
            .insert("beta-4".to_string(), "1.0.0".to_string());
    });
    provider.add_version("beta-4", "1.0.0", |v| {
        v.dependencies
            .insert("beta-5".to_string(), "1.0.0".to_string());
    });
    provider.add_version("beta-5", "1.0.0", |v| {
        v.dependencies
            .insert("shared-lib".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("metric-tracker".to_string(), "^1.0.0".to_string());
        v.dependencies
            .insert("logger".to_string(), "^1.0.0".to_string());
    });

    // Shared packages available in provider
    provider.add_version("shared-lib", "1.0.0", |_| {});
    provider.add_version("shared-lib", "2.0.0", |_| {});
    provider.add_version("shared-lib", "3.0.0", |_| {});

    provider.add_version("metric-tracker", "1.0.0", |_| {});
    provider.add_version("metric-tracker", "2.5.0", |_| {});
    provider.add_version("metric-tracker", "4.0.0", |_| {});

    provider.add_version("logger", "1.0.0", |_| {});
    provider.add_version("logger", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("deep-transitive-overrides-app".to_string());
    manifest
        .dependencies
        .insert("alpha-1".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("beta-1".to_string(), "1.0.0".to_string());

    // Configure 5-level deep nested and spec-targeted overrides:
    // - Branch Alpha: nested object syntax overrides shared-lib@^1.0.0 to 2.0.0;
    //                 arrow syntax overrides metric-tracker@^1.0.0 to 4.0.0
    // - Branch Beta:  nested object syntax overrides shared-lib@^1.0.0 to 3.0.0;
    //                 arrow syntax overrides metric-tracker@^1.0.0 to 2.5.0
    // - logger is un-overridden on both branches and should cleanly resolve to 1.0.0
    let overrides_json = serde_json::json!({
        "alpha-1": {
            "alpha-2": {
                "alpha-3": {
                    "alpha-4": {
                        "alpha-5": {
                            "shared-lib@^1.0.0": "2.0.0"
                        }
                    }
                }
            }
        },
        "alpha-1 > alpha-2 > alpha-3 > alpha-4 > alpha-5 > metric-tracker@^1.0.0": "4.0.0",
        "beta-1": {
            "beta-2": {
                "beta-3": {
                    "beta-4": {
                        "beta-5": {
                            "shared-lib@^1.0.0": "3.0.0"
                        }
                    }
                }
            }
        },
        "beta-1 > beta-2 > beta-3 > beta-4 > beta-5 > metric-tracker@^1.0.0": "2.5.0"
    });
    manifest
        .extra
        .insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Deep transitive nested overrides resolution must succeed");

    // Both 2.0.0 and 3.0.0 of shared-lib must exist in the resolved graph
    let shared_nodes: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.name == "shared-lib")
        .collect();
    assert_eq!(
        shared_nodes.len(),
        2,
        "Both overridden versions of shared-lib must exist"
    );
    assert!(shared_nodes.iter().any(|n| n.version == "2.0.0"));
    assert!(shared_nodes.iter().any(|n| n.version == "3.0.0"));

    // Both 4.0.0 and 2.5.0 of metric-tracker must exist in the resolved graph
    let metric_nodes: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.name == "metric-tracker")
        .collect();
    assert_eq!(
        metric_nodes.len(),
        2,
        "Both overridden versions of metric-tracker must exist"
    );
    assert!(metric_nodes.iter().any(|n| n.version == "4.0.0"));
    assert!(metric_nodes.iter().any(|n| n.version == "2.5.0"));

    // Verify Branch Alpha: outgoing edges from alpha-5 must resolve to 2.0.0 and 4.0.0 without leaking Beta's overrides
    let alpha_5_node = graph.nodes.values().find(|n| n.name == "alpha-5").unwrap();
    let alpha_5_edges = graph.get_outgoing_edges(&alpha_5_node.location);

    let alpha_shared_edge = alpha_5_edges
        .iter()
        .find(|e| e.package_name == "shared-lib")
        .unwrap();
    let alpha_shared_target = graph.nodes.get(&alpha_shared_edge.to_location).unwrap();
    assert_eq!(
        alpha_shared_target.version, "2.0.0",
        "Alpha branch must resolve shared-lib to overridden 2.0.0"
    );

    let alpha_metric_edge = alpha_5_edges
        .iter()
        .find(|e| e.package_name == "metric-tracker")
        .unwrap();
    let alpha_metric_target = graph.nodes.get(&alpha_metric_edge.to_location).unwrap();
    assert_eq!(
        alpha_metric_target.version, "4.0.0",
        "Alpha branch must resolve metric-tracker to overridden 4.0.0"
    );

    let alpha_logger_edge = alpha_5_edges
        .iter()
        .find(|e| e.package_name == "logger")
        .unwrap();
    let alpha_logger_target = graph.nodes.get(&alpha_logger_edge.to_location).unwrap();
    assert_eq!(
        alpha_logger_target.version, "1.0.0",
        "Alpha branch must resolve logger to un-overridden 1.0.0"
    );

    // Verify Branch Beta: outgoing edges from beta-5 must resolve to 3.0.0 and 2.5.0 without leaking Alpha's overrides
    let beta_5_node = graph.nodes.values().find(|n| n.name == "beta-5").unwrap();
    let beta_5_edges = graph.get_outgoing_edges(&beta_5_node.location);

    let beta_shared_edge = beta_5_edges
        .iter()
        .find(|e| e.package_name == "shared-lib")
        .unwrap();
    let beta_shared_target = graph.nodes.get(&beta_shared_edge.to_location).unwrap();
    assert_eq!(
        beta_shared_target.version, "3.0.0",
        "Beta branch must resolve shared-lib to overridden 3.0.0"
    );

    let beta_metric_edge = beta_5_edges
        .iter()
        .find(|e| e.package_name == "metric-tracker")
        .unwrap();
    let beta_metric_target = graph.nodes.get(&beta_metric_edge.to_location).unwrap();
    assert_eq!(
        beta_metric_target.version, "2.5.0",
        "Beta branch must resolve metric-tracker to overridden 2.5.0"
    );

    let beta_logger_edge = beta_5_edges
        .iter()
        .find(|e| e.package_name == "logger")
        .unwrap();
    let beta_logger_target = graph.nodes.get(&beta_logger_edge.to_location).unwrap();
    assert_eq!(
        beta_logger_target.version, "1.0.0",
        "Beta branch must resolve logger to un-overridden 1.0.0"
    );

    // Un-overridden logger is hoisted and shared at root node_modules/logger
    assert_eq!(
        alpha_logger_edge.to_location, beta_logger_edge.to_location,
        "Un-overridden logger must be deduplicated across branches"
    );
    assert_eq!(alpha_logger_edge.to_location, "node_modules/logger");
}

#[test]
fn test_adversarial_workspace_circular_dev_with_peer_chains() {
    use crate::error::SolverError;
    use crate::workspace::{resolve_workspace_graph, WorkspaceDependencyGraph};
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("shared-logger", "2.0.0", |_| {});

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("ws-peer-cycle-root".to_string());
    root_manifest
        .dependencies
        .insert("shared-logger".to_string(), "^2.0.0".to_string());

    // Package A (core engine) depends on Package B in production
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("pkg-b".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    // Package B (plugin runner) has devDependency on Package C AND Package A (dev cycle: A -> B -> A)
    let mut manifest_b = Manifest::default();
    manifest_b.name = Some("pkg-b".to_string());
    manifest_b.version = Some("1.0.0".to_string());
    manifest_b
        .dev_dependencies
        .insert("pkg-c".to_string(), "workspace:*".to_string());
    manifest_b
        .dev_dependencies
        .insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    // Package C (plugin) has peerDependency on Package A (^1.0.0) and peerDependency on external shared-logger (^2.0.0)
    let mut manifest_c = Manifest::default();
    manifest_c.name = Some("pkg-c".to_string());
    manifest_c.version = Some("1.0.0".to_string());
    manifest_c
        .peer_dependencies
        .insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest_c
        .peer_dependencies
        .insert("shared-logger".to_string(), "^2.0.0".to_string());
    let member_c = WorkspaceMember {
        name: "pkg-c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-c"),
        relative_path: "packages/pkg-c".to_string(),
        manifest: manifest_c.clone(),
    };

    // 1. Verify that WorkspaceDependencyGraph::construct gracefully breaks the circular devDependency back-edge (pkg-b -> pkg-a)
    let ws_graph = WorkspaceDependencyGraph::construct(&[
        member_a.clone(),
        member_b.clone(),
        member_c.clone(),
    ])
    .expect("Circular devDependencies in workspace must construct and topo sort successfully");

    // Sibling dependencies separation
    assert!(ws_graph.dependencies["pkg-a"].contains_key("pkg-b"));
    assert!(ws_graph.dev_dependencies["pkg-b"].contains_key("pkg-a"));
    assert!(ws_graph.dev_dependencies["pkg-b"].contains_key("pkg-c"));

    // In topological order, leaf pkg-b must precede dependent pkg-a
    let pos_a = ws_graph
        .topological_order
        .iter()
        .position(|x| x == "pkg-a")
        .unwrap();
    let pos_b = ws_graph
        .topological_order
        .iter()
        .position(|x| x == "pkg-b")
        .unwrap();
    assert!(
        pos_b < pos_a,
        "Leaf dependency pkg-b must precede dependent pkg-a"
    );

    // 2. Full workspace graph resolution with peer satisfaction
    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let graph = resolve_workspace_graph(
        &root_manifest,
        &[member_a.clone(), member_b.clone(), member_c.clone()],
        &provider,
        &options,
    )
    .expect("Workspace resolution must preserve peer satisfaction despite dev cycle breaking");

    // All workspace links and locations exist
    assert!(graph.nodes.contains_key("node_modules/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/pkg-b"));
    assert!(graph.nodes.contains_key("node_modules/pkg-c"));
    assert!(graph.nodes.contains_key("packages/pkg-a"));
    assert!(graph.nodes.contains_key("packages/pkg-b"));
    assert!(graph.nodes.contains_key("packages/pkg-c"));

    // External dependency shared-logger hoisted to root node_modules
    assert!(graph.nodes.contains_key("node_modules/shared-logger"));

    // Verify edges from pkg-a: prod edge to pkg-b
    let edges_a = graph.get_outgoing_edges("packages/pkg-a");
    let edge_a_to_b = edges_a.iter().find(|e| e.package_name == "pkg-b").unwrap();
    assert_eq!(edge_a_to_b.dep_type, DependencyType::Prod);
    assert_eq!(edge_a_to_b.to_location, "node_modules/pkg-b");

    // Verify edges from pkg-b: dev edges to pkg-c and pkg-a
    let edges_b = graph.get_outgoing_edges("packages/pkg-b");
    let edge_b_to_c = edges_b.iter().find(|e| e.package_name == "pkg-c").unwrap();
    assert_eq!(edge_b_to_c.dep_type, DependencyType::Dev);
    assert_eq!(edge_b_to_c.to_location, "node_modules/pkg-c");

    let edge_b_to_a = edges_b.iter().find(|e| e.package_name == "pkg-a").unwrap();
    assert_eq!(edge_b_to_a.dep_type, DependencyType::Dev);
    assert_eq!(edge_b_to_a.to_location, "node_modules/pkg-a");

    // Verify edges from pkg-c: peer satisfaction to pkg-a AND external shared-logger
    let edges_c = graph.get_outgoing_edges("packages/pkg-c");
    let peer_edge_a = edges_c
        .iter()
        .find(|e| e.package_name == "pkg-a")
        .expect("pkg-c must have resolved peer dependency edge to pkg-a");
    assert_eq!(peer_edge_a.dep_type, DependencyType::Peer);
    assert_eq!(peer_edge_a.to_location, "node_modules/pkg-a");

    let peer_edge_logger = edges_c
        .iter()
        .find(|e| e.package_name == "shared-logger")
        .expect("pkg-c must have resolved peer dependency edge to shared-logger");
    assert_eq!(peer_edge_logger.dep_type, DependencyType::Peer);
    assert_eq!(peer_edge_logger.to_location, "node_modules/shared-logger");

    // 3. Strict peer conflict verification: if pkg-c requires incompatible pkg-a (^2.0.0)
    let mut manifest_c_bad = manifest_c.clone();
    manifest_c_bad
        .peer_dependencies
        .insert("pkg-a".to_string(), "^2.0.0".to_string());
    let member_c_bad = WorkspaceMember {
        name: "pkg-c".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-c"),
        relative_path: "packages/pkg-c".to_string(),
        manifest: manifest_c_bad,
    };

    let strict_err = resolve_workspace_graph(
        &root_manifest,
        &[member_a, member_b, member_c_bad],
        &provider,
        &options,
    )
    .unwrap_err();
    assert!(strict_err.is_peer_conflict());
    match strict_err {
        SolverError::PeerConflict { peer, .. } => {
            assert_eq!(peer, "pkg-a");
        }
        other => panic!("Expected PeerConflict, got {other:?}"),
    }
}

#[test]
fn test_required_platform_incompatibility_fails_ebadplatform() {
    use crate::overrides::Overrides;
    use crate::solver::Solver;
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("darwin-only", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
        v.cpu = Some(vec!["arm64".to_string()]);
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("my-app".to_string());
    manifest
        .dependencies
        .insert("darwin-only".to_string(), "^1.0.0".to_string());

    let mut options = ResolverOptions::default();
    options.platform = Platform {
        os: "linux".to_string(),
        cpu: "x64".to_string(),
        libc: Some("glibc".to_string()),
    };

    let solver = Solver::new(&provider, options, Overrides::default());
    let err = solver.resolve(&manifest).unwrap_err();
    assert!(
        err.is_platform_incompatible(),
        "Must be platform incompatible error"
    );
    let err_str = err.to_string();
    assert!(
        err_str.contains("EBADPLATFORM"),
        "Error must contain EBADPLATFORM: {err_str}"
    );
    assert!(
        err_str.contains("darwin-only"),
        "Error must mention package: {err_str}"
    );
}

#[test]
fn test_optional_platform_incompatibility_is_skipped() {
    use crate::overrides::Overrides;
    use crate::solver::Solver;
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("darwin-opt", "1.0.0", |v| {
        v.os = Some(vec!["darwin".to_string()]);
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("my-app".to_string());
    manifest
        .optional_dependencies
        .insert("darwin-opt".to_string(), "^1.0.0".to_string());

    let mut options = ResolverOptions::default();
    options.platform = Platform {
        os: "linux".to_string(),
        cpu: "x64".to_string(),
        libc: Some("glibc".to_string()),
    };

    let solver = Solver::new(&provider, options, Overrides::default());
    let graph = solver
        .resolve(&manifest)
        .expect("Optional incompatible platform should succeed and skip");
    assert!(
        graph.is_skipped("darwin-opt"),
        "darwin-opt must be in skipped set"
    );
}

#[test]
fn test_lockfile_v3_preserves_peer_dependencies_meta_and_overrides() {
    use crate::overrides::Overrides;
    use crate::solver::Solver;
    use rnpm_core::manifest::PeerDependencyMeta;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("my-plugin", "1.0.0", |v| {
        v.peer_dependencies
            .insert("react".to_string(), "^18.0.0".to_string());
        v.peer_dependencies_meta
            .insert("react".to_string(), PeerDependencyMeta { optional: true });
    });
    provider.add_version("react", "18.2.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("root-app".to_string());
    manifest
        .dependencies
        .insert("my-plugin".to_string(), "1.0.0".to_string());
    manifest
        .peer_dependencies
        .insert("root-peer".to_string(), "^2.0.0".to_string());
    manifest.peer_dependencies_meta.insert(
        "root-peer".to_string(),
        PeerDependencyMeta { optional: true },
    );
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "react": "18.2.0" }),
    );

    let options = ResolverOptions::default();
    let overrides = Overrides::from_manifest(&manifest).unwrap();
    let solver = Solver::new(&provider, options, overrides);
    let graph = solver.resolve(&manifest).unwrap();

    let lockfile = graph.to_lockfile_v3("root-app", Some("1.0.0"));
    let root_pkg = lockfile.packages.get("").expect("Root package must exist");
    assert!(
        !root_pkg.extra.contains_key("overrides"),
        "Root overrides must not be emitted into lockfile extra"
    );
    assert!(
        !root_pkg.extra.contains_key("directories"),
        "Root directories must not be emitted into lockfile extra"
    );
    assert!(root_pkg
        .peer_dependencies
        .as_ref()
        .unwrap()
        .contains_key("root-peer"));
    assert!(root_pkg
        .peer_dependencies_meta
        .as_ref()
        .unwrap()
        .contains_key("root-peer"));

    let plugin_pkg = lockfile
        .packages
        .get("node_modules/my-plugin")
        .expect("my-plugin node must exist");
    assert!(plugin_pkg
        .peer_dependencies
        .as_ref()
        .unwrap()
        .contains_key("react"));
    assert!(plugin_pkg
        .peer_dependencies_meta
        .as_ref()
        .unwrap()
        .contains_key("react"));
}

#[test]
fn test_arborist_lockfile_metadata_alignment() {
    let mut provider = InMemoryPackageProvider::new();

    // Dev tool watcher with an optional native addon
    provider.add_version("dev-watcher", "1.0.0", |v| {
        v.optional_dependencies
            .insert("dev-opt-addon".to_string(), "1.0.0".to_string());
    });

    // Package 1: Dev + optional combined dependency (e.g. dev tool optional addon)
    provider.add_version("dev-opt-addon", "1.0.0", |v| {
        v.license = Some("Apache-2.0".to_string());
        v.libc = Some(vec!["glibc".to_string()]);
        v.extra.insert(
            "directories".to_string(),
            serde_json::json!({ "doc": "docs" }),
        );
        v.extra
            .insert("deprecated".to_string(), serde_json::Value::Bool(false));
    });

    // Package 2: Deprecated package with a message
    provider.add_version("deprecated-pkg", "2.0.0", |v| {
        v.deprecated = Some("Deprecated in favor of new-pkg".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("meta-alignment-app".to_string());
    // Dev watcher is a dev dependency
    manifest
        .dev_dependencies
        .insert("dev-watcher".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("deprecated-pkg".to_string(), "2.0.0".to_string());

    // Root spurious extra fields that npm Arborist omits
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "foo": "1.0.0" }),
    );
    manifest.extra.insert(
        "directories".to_string(),
        serde_json::json!({ "bin": "bin" }),
    );
    manifest
        .extra
        .insert("deprecated".to_string(), serde_json::Value::Bool(false));
    manifest.extra.insert(
        "funding".to_string(),
        serde_json::json!({ "type": "individual", "url": "https://example.com" }),
    );

    let options = ResolverOptions::default();
    let solver =
        crate::solver::Solver::new(&provider, options, crate::overrides::Overrides::default());
    let graph = solver.resolve(&manifest).unwrap();
    let lockfile = graph.to_lockfile_v3("meta-alignment-app", Some("1.0.0"));

    // 1. Root package checks
    let root_pkg = lockfile.packages.get("").expect("Root package must exist");
    assert!(
        !root_pkg.extra.contains_key("overrides"),
        "Root must not emit overrides in lockfile extra"
    );
    assert!(
        !root_pkg.extra.contains_key("directories"),
        "Root must not emit directories in lockfile extra"
    );
    assert!(
        !root_pkg.extra.contains_key("deprecated"),
        "Root must not emit deprecated: false in lockfile extra"
    );
    assert!(
        root_pkg.extra.contains_key("funding"),
        "Root must preserve valid funding in lockfile extra"
    );

    // 2. Normal package: dev-opt-addon
    let addon_pkg = lockfile
        .packages
        .get("node_modules/dev-opt-addon")
        .expect("dev-opt-addon must exist");
    assert_eq!(
        addon_pkg.license.as_deref(),
        Some("Apache-2.0"),
        "License must be set correctly"
    );
    assert_eq!(
        addon_pkg.libc.as_deref(),
        Some(&["glibc".to_string()][..]),
        "Libc must be set correctly"
    );
    assert_eq!(
        addon_pkg.dev,
        Some(true),
        "Must emit dev: true when both dev and optional"
    );
    assert_eq!(
        addon_pkg.optional,
        Some(true),
        "Must emit optional: true when both dev and optional"
    );
    assert_eq!(
        addon_pkg.dev_optional, None,
        "Must not emit devOptional in fresh v3 lockfiles"
    );
    assert!(
        !addon_pkg.extra.contains_key("directories"),
        "Must omit directories from lockfile package entries"
    );
    assert!(
        !addon_pkg.extra.contains_key("deprecated"),
        "Must omit deprecated: false from lockfile package entries"
    );

    // 3. Normal package: deprecated-pkg
    let dep_pkg = lockfile
        .packages
        .get("node_modules/deprecated-pkg")
        .expect("deprecated-pkg must exist");
    assert_eq!(
        dep_pkg.extra.get("deprecated").and_then(|v| v.as_str()),
        Some("Deprecated in favor of new-pkg"),
        "Must preserve real string deprecation messages"
    );
}

#[test]
fn test_default_peer_resolution_auto_installs_transitive_peer() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("core-lib", "1.2.0", |_| {});
    provider.add_version("plugin-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-lib".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("default-peer-auto-install".to_string());
    manifest
        .dependencies
        .insert("plugin-a".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/plugin-a"));
    assert!(graph.nodes.contains_key("node_modules/core-lib"));
    let core_node = graph.nodes.get("node_modules/core-lib").unwrap();
    assert_eq!(core_node.version, "1.2.0");
    assert!(
        core_node.flags.peer,
        "Auto-installed peer dependency must have peer flag set"
    );

    let peer_edge = graph
        .edges
        .iter()
        .find(|e| e.package_name == "core-lib")
        .unwrap();
    assert_eq!(peer_edge.from_location, "node_modules/plugin-a");
    assert_eq!(peer_edge.to_location, "node_modules/core-lib");
    assert_eq!(peer_edge.dep_type, DependencyType::Peer);
}

#[test]
fn test_default_peer_resolution_fails_on_conflict_with_eresolve() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("core-lib", "1.0.0", |_| {});
    provider.add_version("core-lib", "2.0.0", |_| {});
    provider.add_version("plugin-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-lib".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-conflict-default".to_string());
    manifest
        .dependencies
        .insert("core-lib".to_string(), "2.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-a".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();

    assert!(err.is_peer_conflict());
    let err_str = err.to_string();
    assert!(
        err_str.contains("ERESOLVE: Conflicting peer dependency 'core-lib' required by 'plugin-a'")
    );
    assert!(err_str.contains("peer core-lib@\"^1.0.0\" from plugin-a"));
    assert!(err_str.contains("Found: core-lib@2.0.0 at node_modules/core-lib"));
    assert!(err_str.contains("--legacy-peer-deps"));
}

#[test]
fn test_default_peer_resolution_with_overrides_resolves_conflict() {
    use crate::overrides::Overrides;
    use crate::solver::Solver;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("core-lib", "1.0.0", |_| {});
    provider.add_version("core-lib", "2.0.0", |_| {});
    provider.add_version("plugin-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-lib".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-conflict-override".to_string());
    manifest
        .dependencies
        .insert("core-lib".to_string(), "2.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-a".to_string(), "1.0.0".to_string());
    manifest.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "core-lib": "2.0.0" }),
    );

    let options = ResolverOptions::default();
    let overrides = Overrides::from_manifest(&manifest).unwrap();
    let solver = Solver::new(&provider, options, overrides);
    let graph = solver
        .resolve(&manifest)
        .expect("Overrides must resolve conflicting peer dependency");

    assert!(graph.nodes.contains_key("node_modules/core-lib"));
    assert_eq!(
        graph.nodes.get("node_modules/core-lib").unwrap().version,
        "2.0.0"
    );
}

#[test]
fn test_legacy_peer_deps_completely_bypasses_peer_dependencies_and_conflicts() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("core-lib", "1.0.0", |_| {});
    provider.add_version("core-lib", "2.0.0", |_| {});
    provider.add_version("plugin-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-lib".to_string(), "^1.0.0".to_string());
    });
    // Root also declares peerDependencies that should be ignored
    let mut manifest = Manifest::default();
    manifest.name = Some("legacy-peer-app".to_string());
    manifest
        .dependencies
        .insert("core-lib".to_string(), "2.0.0".to_string());
    manifest
        .dependencies
        .insert("plugin-a".to_string(), "1.0.0".to_string());
    manifest
        .peer_dependencies
        .insert("uninstalled-peer".to_string(), "^1.0.0".to_string());

    let options = ResolverOptions {
        legacy_peer_deps: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("legacy_peer_deps must succeed and completely bypass peer checks");

    assert!(graph.nodes.contains_key("node_modules/core-lib"));
    assert!(graph.nodes.contains_key("node_modules/plugin-a"));
    assert!(
        !graph.nodes.contains_key("node_modules/uninstalled-peer"),
        "Root peer must not be auto-installed in legacy mode"
    );
    // Ensure no peer edges exist
    assert!(graph
        .edges
        .iter()
        .all(|e| e.dep_type != DependencyType::Peer && e.dep_type != DependencyType::PeerOptional));
}

#[test]
fn test_legacy_peer_deps_bypasses_missing_and_cyclic_peers() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("cyclic-a", "1.0.0", |v| {
        v.peer_dependencies
            .insert("cyclic-b".to_string(), "^2.0.0".to_string());
        v.peer_dependencies
            .insert("missing-pkg".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("cyclic-b", "1.0.0", |v| {
        v.peer_dependencies
            .insert("cyclic-a".to_string(), "^2.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("legacy-cyclic-test".to_string());
    manifest
        .dependencies
        .insert("cyclic-a".to_string(), "1.0.0".to_string());

    let legacy_opts = ResolverOptions {
        legacy_peer_deps: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &legacy_opts)
        .expect("legacy_peer_deps must succeed even with cyclic and missing peers");
    assert!(graph.nodes.contains_key("node_modules/cyclic-a"));
    assert!(!graph.nodes.contains_key("node_modules/missing-pkg"));

    // Under strict_peer_deps, it MUST fail
    let strict_opts = ResolverOptions {
        strict_peer_deps: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &strict_opts).unwrap_err();
    assert!(err.is_peer_conflict());
}

#[test]
fn test_strict_peer_deps_fails_on_missing_peer_package() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("lib-with-missing-peer", "1.0.0", |v| {
        v.peer_dependencies
            .insert("ghost-pkg".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("strict-missing-peer".to_string());
    manifest
        .dependencies
        .insert("lib-with-missing-peer".to_string(), "1.0.0".to_string());

    let options = ResolverOptions {
        strict_peer_deps: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();
    assert!(err.is_peer_conflict());
    let err_str = err.to_string();
    assert!(err_str.contains("ERESOLVE: Conflicting peer dependency 'ghost-pkg'"));
    assert!(
        err_str.contains("Peer package '^1.0.0' not found in registry")
            || err_str.contains("ghost-pkg")
    );
}

#[test]
fn test_dev_optional_lockfile_v3_emission_matches_arborist() {
    let mut provider = InMemoryPackageProvider::new();

    // 1. Dev tool that has an optional dependency (dev && optional)
    provider.add_version("dev-tool", "1.0.0", |v| {
        v.optional_dependencies
            .insert("dev-and-opt-addon".to_string(), "1.0.0".to_string());
        v.dependencies
            .insert("shared-helper".to_string(), "1.0.0".to_string());
    });
    provider.add_version("dev-and-opt-addon", "1.0.0", |_| {});

    // 2. Optional tool that also depends on shared-helper (making shared-helper reachable from dev and opt)
    provider.add_version("opt-tool", "1.0.0", |v| {
        v.dependencies
            .insert("shared-helper".to_string(), "1.0.0".to_string());
    });
    provider.add_version("shared-helper", "1.0.0", |_| {});

    // 3. Prod tool that also depends on prod-shared (making prod-shared reachable from prod, dev, and opt)
    provider.add_version("prod-tool", "1.0.0", |v| {
        v.dependencies
            .insert("prod-shared".to_string(), "1.0.0".to_string());
    });
    provider.add_version("prod-shared", "1.0.0", |_| {});

    provider.add_version("dev-tool-2", "1.0.0", |v| {
        v.dependencies
            .insert("prod-shared".to_string(), "1.0.0".to_string());
    });
    provider.add_version("opt-tool-2", "1.0.0", |v| {
        v.dependencies
            .insert("prod-shared".to_string(), "1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("dev-opt-alignment-app".to_string());
    manifest
        .dev_dependencies
        .insert("dev-tool".to_string(), "1.0.0".to_string());
    manifest
        .dev_dependencies
        .insert("dev-tool-2".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("opt-tool".to_string(), "1.0.0".to_string());
    manifest
        .optional_dependencies
        .insert("opt-tool-2".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("prod-tool".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let solver =
        crate::solver::Solver::new(&provider, options, crate::overrides::Overrides::default());
    let graph = solver.resolve(&manifest).unwrap();
    let lockfile = graph.to_lockfile_v3("dev-opt-alignment-app", Some("1.0.0"));

    // Case 1: dev-tool is exclusively dev
    let dev_pkg = lockfile
        .packages
        .get("node_modules/dev-tool")
        .expect("dev-tool must exist");
    assert_eq!(dev_pkg.dev, Some(true));
    assert_eq!(dev_pkg.optional, None);
    assert_eq!(dev_pkg.dev_optional, None);

    // Case 2: opt-tool is exclusively optional
    let opt_pkg = lockfile
        .packages
        .get("node_modules/opt-tool")
        .expect("opt-tool must exist");
    assert_eq!(opt_pkg.dev, None);
    assert_eq!(opt_pkg.optional, Some(true));
    assert_eq!(opt_pkg.dev_optional, None);

    // Case 3: dev-and-opt-addon is reachable only through dev-tool via an optional edge.
    // It is both dev and optional (`dev && optional`): emit `dev: true, optional: true` and omit `devOptional`.
    let addon_pkg = lockfile
        .packages
        .get("node_modules/dev-and-opt-addon")
        .expect("dev-and-opt-addon must exist");
    assert_eq!(
        addon_pkg.dev,
        Some(true),
        "Must emit dev: true when both dev and optional"
    );
    assert_eq!(
        addon_pkg.optional,
        Some(true),
        "Must emit optional: true when both dev and optional"
    );
    assert_eq!(
        addon_pkg.dev_optional, None,
        "Must NOT emit devOptional when both dev and optional"
    );

    // Case 4: shared-helper is reached by dev-tool (dev path) and opt-tool (optional path),
    // but neither is pure prod, and it is neither exclusively dev nor exclusively optional.
    // Emit `devOptional: true` (and omit `dev` and `optional`).
    let helper_pkg = lockfile
        .packages
        .get("node_modules/shared-helper")
        .expect("shared-helper must exist");
    assert_eq!(
        helper_pkg.dev_optional,
        Some(true),
        "Must emit devOptional: true when reachable from dev and optional paths"
    );
    assert_eq!(
        helper_pkg.dev, None,
        "Must NOT emit dev when devOptional is true"
    );
    assert_eq!(
        helper_pkg.optional, None,
        "Must NOT emit optional when devOptional is true"
    );

    // Case 5: prod-shared is reached by dev-tool-2, opt-tool-2, AND prod-tool.
    // Because it is reachable by a pure prod path, omit dev, optional, and devOptional.
    let prod_shared_pkg = lockfile
        .packages
        .get("node_modules/prod-shared")
        .expect("prod-shared must exist");
    assert_eq!(prod_shared_pkg.dev, None);
    assert_eq!(prod_shared_pkg.optional, None);
    assert_eq!(prod_shared_pkg.dev_optional, None);

    // Verify round-trip via from_lockfile_v3
    let reimported_graph = crate::graph::DependencyGraph::from_lockfile_v3(&lockfile);
    let helper_node = reimported_graph
        .nodes
        .get("node_modules/shared-helper")
        .expect("shared-helper node");
    assert!(helper_node.flags.dev_optional);
    assert!(!helper_node.flags.dev);
    assert!(!helper_node.flags.optional);

    let addon_node = reimported_graph
        .nodes
        .get("node_modules/dev-and-opt-addon")
        .expect("addon node");
    assert!(addon_node.flags.dev);
    assert!(addon_node.flags.optional);
    assert!(!addon_node.flags.dev_optional);

    let reserialized_lockfile =
        reimported_graph.to_lockfile_v3("dev-opt-alignment-app", Some("1.0.0"));
    let reserialized_helper = reserialized_lockfile
        .packages
        .get("node_modules/shared-helper")
        .unwrap();
    assert_eq!(reserialized_helper.dev_optional, Some(true));
    assert_eq!(reserialized_helper.dev, None);
    assert_eq!(reserialized_helper.optional, None);
}

#[test]
fn test_strict_peer_deps_fails_on_no_matching_version() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("peer-lib", "1.0.0", |_| {});
    provider.add_version("pkg-requiring-v5", "1.0.0", |v| {
        v.peer_dependencies
            .insert("peer-lib".to_string(), "^5.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("strict-no-version".to_string());
    manifest
        .dependencies
        .insert("pkg-requiring-v5".to_string(), "1.0.0".to_string());

    let options = ResolverOptions {
        strict_peer_deps: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();
    assert!(err.is_peer_conflict());
    let err_str = err.to_string();
    assert!(err_str.contains("No version satisfying '^5.0.0'"));
}

#[test]
fn test_strict_peer_deps_succeeds_when_peers_are_satisfied() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("core-lib", "1.5.0", |_| {});
    provider.add_version("plugin-ok", "1.0.0", |v| {
        v.peer_dependencies
            .insert("core-lib".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("strict-satisfied".to_string());
    manifest
        .dependencies
        .insert("core-lib".to_string(), "1.5.0".to_string());
    manifest
        .dependencies
        .insert("plugin-ok".to_string(), "1.0.0".to_string());

    let options = ResolverOptions {
        strict_peer_deps: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("strict_peer_deps must succeed when peer constraints are satisfied");
    assert!(graph.nodes.contains_key("node_modules/core-lib"));
    assert!(graph.nodes.contains_key("node_modules/plugin-ok"));
}

#[test]
fn test_root_bundled_dependencies_preserved_in_lockfile() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("bundled-dep", "1.0.0", |_| {});
    provider.add_version("regular-dep", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("bundled-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest.bundled_dependencies = Some(rnpm_core::manifest::BundledDependencies::List(vec![
        "bundled-dep".to_string(),
    ]));
    manifest
        .dependencies
        .insert("bundled-dep".to_string(), "^1.0.0".to_string());
    manifest
        .dependencies
        .insert("regular-dep".to_string(), "^1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    let node_bundled = graph.nodes.get("node_modules/bundled-dep").unwrap();
    assert!(node_bundled.flags.bundled);

    let node_regular = graph.nodes.get("node_modules/regular-dep").unwrap();
    assert!(!node_regular.flags.bundled);

    let lockfile = graph.to_lockfile_v3("bundled-app", Some("1.0.0"));
    let root_entry = lockfile.packages.get("").unwrap();
    assert_eq!(
        root_entry.bundled_package_names(),
        vec!["bundled-dep".to_string()]
    );

    let bundled_entry = lockfile.packages.get("node_modules/bundled-dep").unwrap();
    assert_eq!(bundled_entry.in_bundle, Some(true));

    let regular_entry = lockfile.packages.get("node_modules/regular-dep").unwrap();
    assert_eq!(regular_entry.in_bundle, None);
}

#[test]
fn test_root_lifecycle_scripts_set_has_install_script_in_lockfile() {
    let provider = InMemoryPackageProvider::new();

    let mut manifest = Manifest::default();
    manifest.name = Some("lifecycle-app".to_string());
    manifest.version = Some("1.0.0".to_string());
    manifest
        .scripts
        .insert("postinstall".to_string(), "echo ok".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    let root_node = graph.nodes.get("").unwrap();
    assert!(root_node.flags.has_install_script);

    let lockfile = graph.to_lockfile_v3("lifecycle-app", Some("1.0.0"));
    let root_entry = lockfile.packages.get("").unwrap();
    assert_eq!(root_entry.has_install_script, Some(true));
}

#[test]
fn test_workspace_lockfile_package_names_and_prune_reachability() {
    use crate::workspace::resolve_workspace_graph;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("extra-dep", "1.0.0", |_| {});
    provider.add_version("sub-dep", "1.0.0", |_| {});

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("ws-prune-root".to_string());
    root_manifest.version = Some("1.0.0".to_string());
    root_manifest
        .dependencies
        .insert("extra-dep".to_string(), "^1.0.0".to_string());

    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("@scope/pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a
        .dependencies
        .insert("sub-dep".to_string(), "^1.0.0".to_string());

    let member_a = WorkspaceMember {
        name: "@scope/pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: manifest_a,
    };

    let options = ResolverOptions::default();
    let mut graph = resolve_workspace_graph(&root_manifest, &[member_a], &provider, &options).unwrap();

    // Verify lockfile generation has "name" for non-standard location packages/pkg-a
    let lockfile = graph.to_lockfile_v3("ws-prune-root", Some("1.0.0"));
    let pkg_a_lock = lockfile.packages.get("packages/pkg-a").expect("packages/pkg-a in lockfile");
    assert_eq!(pkg_a_lock.name.as_deref(), Some("@scope/pkg-a"));

    // Verify prune_unreferenced after removing root dependency extra-dep
    assert!(graph.remove_root_dependency("extra-dep"));
    let pruned = graph.prune_unreferenced();
    assert!(pruned.contains("node_modules/extra-dep"));

    // packages/pkg-a, node_modules/@scope/pkg-a link, and sub-dep MUST NOT be pruned!
    assert!(!pruned.contains("packages/pkg-a"));
    assert!(!pruned.contains("node_modules/@scope/pkg-a"));
    assert!(!pruned.contains("node_modules/sub-dep"));

    assert!(graph.nodes.contains_key("packages/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/@scope/pkg-a"));
    assert!(graph.nodes.contains_key("node_modules/sub-dep"));
}

#[test]
fn test_lockfile_normalizes_single_bin_string_to_map() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("@scope/parser", "1.0.0", |version| {
        version.bin = Some(rnpm_lockfile::PackageBin::Single("./bin/parser.js".to_string()));
    });
    provider.add_version("single-tool", "1.0.0", |version| {
        version.bin = Some(rnpm_lockfile::PackageBin::Single("bin/tool.js".to_string()));
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("single-bin-app".to_string());
    manifest
        .dependencies
        .insert("@scope/parser".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("single-tool".to_string(), "1.0.0".to_string());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();
    let lockfile = graph.to_lockfile_v3("single-bin-app", Some("1.0.0"));

    let scoped_pkg = lockfile.packages.get("node_modules/@scope/parser").unwrap();
    assert_eq!(
        scoped_pkg.bin,
        Some(rnpm_lockfile::PackageBin::Map(BTreeMap::from([(
            "parser".to_string(),
            "bin/parser.js".to_string(),
        )])))
    );

    let unscoped_pkg = lockfile.packages.get("node_modules/single-tool").unwrap();
    assert_eq!(
        unscoped_pkg.bin,
        Some(rnpm_lockfile::PackageBin::Map(BTreeMap::from([(
            "single-tool".to_string(),
            "bin/tool.js".to_string(),
        )])))
    );
}

#[test]
fn test_lockfile_omits_name_for_nested_node_modules_standard_packages() {
    use crate::graph::DependencyGraph;
    use crate::graph::Node;

    let mut graph = DependencyGraph::new();
    graph.nodes.insert(
        "".to_string(),
        Node {
            location: "".to_string(),
            name: "root-app".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        },
    );
    // Nested package: node_modules/parent/node_modules/child
    graph.nodes.insert(
        "node_modules/parent/node_modules/child".to_string(),
        Node {
            location: "node_modules/parent/node_modules/child".to_string(),
            name: "child".to_string(),
            install_name: "child".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        },
    );
    // Nested scoped package: node_modules/parent/node_modules/@scope/scoped-child
    graph.nodes.insert(
        "node_modules/parent/node_modules/@scope/scoped-child".to_string(),
        Node {
            location: "node_modules/parent/node_modules/@scope/scoped-child".to_string(),
            name: "@scope/scoped-child".to_string(),
            install_name: "@scope/scoped-child".to_string(),
            version: "2.0.0".to_string(),
            ..Default::default()
        },
    );

    let lockfile = graph.to_lockfile_v3("root-app", Some("1.0.0"));

    let child_lock = lockfile
        .packages
        .get("node_modules/parent/node_modules/child")
        .expect("child lock entry");
    assert_eq!(
        child_lock.name, None,
        "Standard nested package location must omit name in lockfile"
    );

    let scoped_child_lock = lockfile
        .packages
        .get("node_modules/parent/node_modules/@scope/scoped-child")
        .expect("scoped child lock entry");
    assert_eq!(
        scoped_child_lock.name, None,
        "Standard nested scoped package location must omit name in lockfile"
    );
}

#[test]
fn test_breadth_first_dependency_depth_prevents_premature_hoisting_from_deep_branches() {
    let mut provider = InMemoryPackageProvider::new();

    // pkg-a (alphabetically earlier) has deep transitive dep on shared@2.0.0 (depth 3)
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies
            .insert("sub-a".to_string(), "1.0.0".to_string());
    });
    provider.add_version("sub-a", "1.0.0", |v| {
        v.dependencies
            .insert("shared".to_string(), "^2.0.0".to_string());
    });
    provider.add_version("shared", "2.0.0", |_| {});

    // pkg-b (alphabetically later) has direct dependency on shared@1.0.0 (depth 2)
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies
            .insert("shared".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("shared", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("bfs-app".to_string());
    manifest
        .dependencies
        .insert("pkg-a".to_string(), "1.0.0".to_string());
    manifest
        .dependencies
        .insert("pkg-b".to_string(), "1.0.0".to_string());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();

    // Shallower branch (pkg-b -> shared@1.0.0 at depth 2) must claim root node_modules/shared
    let root_shared = graph
        .nodes
        .get("node_modules/shared")
        .expect("root node_modules/shared");
    assert_eq!(
        root_shared.version, "1.0.0",
        "Shallower dependency branch must claim root slot before deeper transitive branch"
    );

    // Deeper branch (pkg-a -> sub-a -> shared@2.0.0 at depth 3) must be nested
    assert!(
        graph.nodes.contains_key("node_modules/sub-a/node_modules/shared")
            || graph.nodes.contains_key("node_modules/pkg-a/node_modules/sub-a/node_modules/shared")
            || graph.nodes.contains_key("node_modules/pkg-a/node_modules/shared")
    );
}


#[test]
fn test_peer_set_resolves_root_dev_edge_with_peer_range_as_advisory() {
    // svelte's dev manifest: dts-buddy peers typescript ">=5.0.4 <5.8" while the
    // root asks for typescript ^5.5.4. npm places dts-buddy first and resolves
    // the root edge guided by the peer range, choosing 5.7.3 instead of 5.9.3.
    use crate::overrides::Overrides;
    use crate::solver::Solver;

    let mut provider = InMemoryPackageProvider::new();
    for version in ["5.5.4", "5.7.3", "5.9.3"] {
        provider.add_version("typescript", version, |_| {});
    }
    provider.add_version("dts-buddy", "0.5.5", |v| {
        v.peer_dependencies
            .insert("typescript".to_string(), ">=5.0.4 <5.8".to_string());
    });
    let mut manifest = Manifest::default();
    manifest.name = Some("svelte-like".to_string());
    manifest.dev_dependencies.insert("dts-buddy".to_string(), "^0.5.5".to_string());
    manifest.dev_dependencies.insert("typescript".to_string(), "^5.5.4".to_string());

    let overrides = Overrides::from_manifest(&manifest).unwrap();
    let graph = Solver::new(&provider, ResolverOptions::default(), overrides)
        .resolve(&manifest)
        .expect("npm resolves this tree without ERESOLVE");
    assert_eq!(graph.nodes["node_modules/typescript"].version, "5.7.3");
    assert_eq!(
        graph.edges.iter().filter(|e| e.from_location.is_empty() && e.install_name == "typescript").count(),
        1,
        "the root edge is recorded once"
    );
}

#[test]
fn test_dependency_with_conflicting_root_peer_nests_instead_of_eresolve() {
    // webpack's dev tree: a transitive dependency peers on a version the root
    // pins differently. npm's can-place-dep treats the root as a CONFLICT, so
    // the dependency nests under the parent and npm overrides the peer with
    // a warning instead of ERESOLVE.
    use crate::overrides::Overrides;
    use crate::solver::Solver;

    let mut provider = InMemoryPackageProvider::new();
    for version in ["17.0.0", "18.0.0"] {
        provider.add_version("react", version, |_| {});
    }
    provider.add_version("lib", "1.0.0", |v| {
        v.peer_dependencies.insert("react".to_string(), "^18.0.0".to_string());
    });
    provider.add_version("a", "1.0.0", |v| {
        v.dependencies.insert("lib".to_string(), "^1.0.0".to_string());
    });
    let mut manifest = Manifest::default();
    manifest.name = Some("webpack-like".to_string());
    manifest.dependencies.insert("react".to_string(), "17.0.0".to_string());
    manifest.dependencies.insert("a".to_string(), "^1.0.0".to_string());

    let overrides = Overrides::from_manifest(&manifest).unwrap();
    let graph = Solver::new(&provider, ResolverOptions::default(), overrides)
        .resolve(&manifest)
        .expect("npm resolves this tree without ERESOLVE");
    assert_eq!(graph.nodes["node_modules/react"].version, "17.0.0");
    assert!(!graph.nodes.contains_key("node_modules/lib"));
    assert_eq!(graph.nodes["node_modules/a/node_modules/lib"].version, "1.0.0");
    // Like webpack's babel-preset-current-node-syntax plugins: the peer is
    // overridden by the visible root node, not duplicated beside the owner.
    assert!(!graph.nodes.contains_key("node_modules/a/node_modules/react"));
}

#[test]
fn test_peer_conflict_fatality_depends_on_requester_is_mine() {
    // #1: Peer conflict fatality depends on who requested the package:
    // root/workspace = fatal ERESOLVE, else warn and keep visible node (build-ideal-tree conflictOK)
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("peer-pkg", "1.0.0", |_| {});
    provider.add_version("peer-pkg", "2.0.0", |_| {});
    provider.add_version("parent-pkg", "1.0.0", |v| {
        v.dependencies.insert("transitive".to_string(), "1.0.0".to_string());
    });
    provider.add_version("transitive", "1.0.0", |v| {
        v.peer_dependencies.insert("peer-pkg".to_string(), "^2.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("root-pkg".to_string());
    manifest.dependencies.insert("peer-pkg".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("parent-pkg".to_string(), "1.0.0".to_string());

    // Transitive requester is NOT root (is_mine = false) -> non-fatal, keeps visible node
    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Transitive peer conflict must not be fatal in standard mode");
    assert_eq!(graph.nodes["node_modules/peer-pkg"].version, "1.0.0");
    assert_eq!(graph.nodes["node_modules/parent-pkg"].version, "1.0.0");

    // But when root directly requests a package with a conflicting peer, is_mine = true -> fatal ERESOLVE
    provider.add_version("direct-pkg", "1.0.0", |v| {
        v.peer_dependencies.insert("peer-pkg".to_string(), "^2.0.0".to_string());
    });
    manifest.dependencies.insert("direct-pkg".to_string(), "1.0.0".to_string());
    let err = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect_err("Direct root peer conflict must be fatal");
    assert!(matches!(err, crate::error::SolverError::PeerConflict { .. }));
}

#[test]
fn test_target_peer_conflicts_intermediate_ancestor_scopes() {
    // #2: target_peer_conflicts checks intermediate ancestor scopes and reuse targets
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("peer-dep", "1.0.0", |_| {});
    provider.add_version("peer-dep", "2.0.0", |_| {});
    provider.add_version("leaf", "1.0.0", |v| {
        v.peer_dependencies.insert("peer-dep".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("leaf", "2.0.0", |_| {});
    provider.add_version("sub", "1.0.0", |v| {
        v.dependencies.insert("leaf".to_string(), "1.0.0".to_string());
    });
    provider.add_version("sub", "2.0.0", |_| {});
    provider.add_version("tool", "1.0.0", |v| {
        v.dependencies.insert("sub".to_string(), "1.0.0".to_string());
        v.dependencies.insert("peer-dep".to_string(), "2.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("app".to_string());
    manifest.dependencies.insert("peer-dep".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("leaf".to_string(), "2.0.0".to_string());
    manifest.dependencies.insert("sub".to_string(), "2.0.0".to_string());
    manifest.dependencies.insert("tool".to_string(), "1.0.0".to_string());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Resolution should succeed by nesting leaf under sub");
    assert_eq!(graph.nodes["node_modules/leaf"].version, "2.0.0");
    assert_eq!(graph.nodes["node_modules/tool/node_modules/sub"].version, "1.0.0");
    assert_eq!(graph.nodes["node_modules/tool/node_modules/peer-dep"].version, "2.0.0");
    // leaf@1.0.0 requires peer-dep ^1.0.0. Visible peer at intermediate scope 'tool' is 2.0.0 (incompatible).
    // Because target_peer_conflicts checks intermediate ancestor scopes, leaf@1.0.0 is not placed at
    // tool/node_modules/leaf, but correctly nests under tool/node_modules/sub/node_modules/leaf:
    assert!(graph.nodes.contains_key("node_modules/tool/node_modules/sub/node_modules/leaf"));
}

#[test]
fn test_load_peer_set_workspace_and_omit_dev() {
    // #3: loadPeerSet advisory resolution supports workspaces and respects omit_dev
    use rnpm_core::manifest::PackageWorkspaces;
    use rnpm_core::workspace::WorkspaceMember;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    for v in ["1.0.0", "1.1.0", "1.2.0"] {
        provider.add_version("shared-pkg", v, |_| {});
    }
    provider.add_version("plugin-pkg", "1.0.0", |v| {
        v.peer_dependencies.insert("shared-pkg".to_string(), "1.1.0".to_string());
    });

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("workspace-root".to_string());
    root_manifest.workspaces = Some(PackageWorkspaces::List(vec!["packages/*".to_string()]));

    let mut member_manifest = Manifest::default();
    member_manifest.name = Some("member-a".to_string());
    member_manifest.version = Some("1.0.0".to_string());
    member_manifest.dependencies.insert("shared-pkg".to_string(), "^1.0.0".to_string());
    member_manifest.dependencies.insert("plugin-pkg".to_string(), "1.0.0".to_string());

    let members = vec![WorkspaceMember {
        name: "member-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/a"),
        relative_path: "packages/a".to_string(),
        manifest: member_manifest,
    }];

    let graph = crate::workspace::resolve_workspace_graph(
        &root_manifest,
        &members,
        &provider,
        &ResolverOptions::default(),
    )
    .expect("Workspace resolution with loadPeerSet should succeed");

    // The advisory second edge from plugin-pkg@1.0.0 selects 1.1.0 for shared-pkg
    assert_eq!(graph.nodes["node_modules/shared-pkg"].version, "1.1.0");
}

#[test]
fn test_override_reference_unresolvable_fails_and_caller_fallback_succeeds() {
    // #4: Unresolved $name reference errors, and caller dependencies fallback works
    use crate::overrides::Overrides;
    use crate::solver::Solver;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("shared-dep", "2.0.0", |_| {});
    provider.add_version("caller-pkg", "1.0.0", |v| {
        v.dependencies.insert("callee".to_string(), "^1.0.0".to_string());
        v.peer_dependencies.insert("shared-dep".to_string(), "2.0.0".to_string());
    });
    provider.add_version("callee", "1.0.0", |_| {});
    provider.add_version("callee", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("test-overrides".to_string());
    manifest.dependencies.insert("caller-pkg".to_string(), "1.0.0".to_string());

    // 1. Unresolvable reference override errors with SolverError::InvalidOverride
    let bad_overrides = Overrides::from_json_value(
        Some(&serde_json::json!({ "callee": "$nonexistent" })),
        BTreeMap::new(),
    );
    let err = Solver::new(&provider, ResolverOptions::default(), bad_overrides)
        .resolve(&manifest)
        .expect_err("Unresolvable override reference must error");
    assert!(err.to_string().contains("Unable to resolve reference $nonexistent"));

    // 2. Reference override falls back to caller dependencies when missing from root
    let caller_overrides = Overrides::from_json_value(
        Some(&serde_json::json!({ "callee": "$shared-dep" })),
        BTreeMap::new(),
    );
    let graph = Solver::new(&provider, ResolverOptions::default(), caller_overrides)
        .resolve(&manifest)
        .expect("Caller fallback override must succeed");
    assert_eq!(graph.nodes["node_modules/callee"].version, "2.0.0");
}

#[test]
fn test_ci_omit_peer_and_legacy_peer_deps() {
    // #5: legacy_peer_deps bypasses peer resolution during solver traversal,
    // whereas standard resolution marks peer dependencies with peer flags.
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("pkg-with-peer", "1.0.0", |v| {
        v.peer_dependencies.insert("peer-lib".to_string(), "1.0.0".to_string());
    });
    provider.add_version("peer-lib", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("app".to_string());
    manifest.dependencies.insert("pkg-with-peer".to_string(), "1.0.0".to_string());

    // Standard mode resolves peer-lib and marks it as peer
    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Standard resolution must succeed");
    assert!(graph.nodes.contains_key("node_modules/peer-lib"));
    assert!(graph.nodes["node_modules/peer-lib"].flags.peer);

    // legacy-peer-deps bypasses peer resolution completely
    let legacy_opts = ResolverOptions {
        legacy_peer_deps: true,
        ..Default::default()
    };
    let legacy_graph = resolve_dependency_graph(&manifest, &provider, &legacy_opts)
        .expect("Legacy peer resolution must succeed");
    assert!(!legacy_graph.nodes.contains_key("node_modules/peer-lib"));
}

#[test]
fn test_rehome_transitive_root_node_migrates_nested_children_and_edges() {
    // #6: rehome_transitive_root_node migrates nested child nodes and updates all edges
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("parent-a", "1.0.0", |v| {
        v.dependencies.insert("shared-sub".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("shared-sub", "1.0.0", |v| {
        v.dependencies.insert("leaf-child".to_string(), "1.0.0".to_string());
    });
    provider.add_version("leaf-child", "1.0.0", |_| {});
    provider.add_version("parent-b", "1.0.0", |v| {
        v.dependencies.insert("shared-sub".to_string(), "^2.0.0".to_string());
    });
    provider.add_version("shared-sub", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("rehome-test".to_string());
    manifest.dependencies.insert("parent-a".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("parent-b".to_string(), "1.0.0".to_string());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Tree resolution should succeed");
    // Verify no dangling edges point to non-existent nodes
    for edge in &graph.edges {
        if !edge.from_location.is_empty() {
            assert!(
                graph.nodes.contains_key(&edge.from_location),
                "Edge from_location '{}' must exist in graph nodes",
                edge.from_location
            );
        }
        assert!(
            graph.nodes.contains_key(&edge.to_location),
            "Edge to_location '{}' must exist in graph nodes",
            edge.to_location
        );
    }
}

#[test]
fn test_reference_specs_follow_arborist_lookup_order() {
    // edge.js #calculateReferentialOverrideSpec: dev, optional, dependencies,
    // peer; an empty spec is falsy and never resolves.
    let mut node = crate::graph::Node::default();
    node.peer_dependencies.insert("a".into(), "peer".into());
    node.dependencies.insert("a".into(), "prod".into());
    node.dev_dependencies.insert("a".into(), "dev".into());
    node.dependencies.insert("b".into(), "prod".into());
    node.peer_dependencies.insert("b".into(), "peer".into());
    node.dev_dependencies.insert("c".into(), String::new());
    let specs = node.all_dependency_specs();
    assert_eq!(specs.get("a").map(String::as_str), Some("dev"));
    assert_eq!(specs.get("b").map(String::as_str), Some("prod"));
    assert_eq!(specs.get("c"), None);
}
