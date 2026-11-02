use std::collections::BTreeMap;
use rnpm_core::manifest::{Manifest, PeerDependencyMeta};
use crate::platform::Platform;
use crate::solver::{resolve_dependency_graph, ResolverOptions};
use crate::types::InMemoryPackageProvider;

#[test]
fn test_hoisting_and_deduplication() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A@1.0.0 depends on Shared@^1.0.0
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies.insert("shared-pkg".to_string(), "^1.0.0".to_string());
    });

    // Package B@1.0.0 depends on Shared@~1.2.0
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies.insert("shared-pkg".to_string(), "~1.2.0".to_string());
    });

    // Shared package versions
    provider.add_version("shared-pkg", "1.0.0", |_| {});
    provider.add_version("shared-pkg", "1.2.3", |_| {});

    // Root project depends on pkg-a and pkg-b
    let mut manifest = Manifest::default();
    manifest.name = Some("test-project".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("pkg-b".to_string(), "^1.0.0".to_string());

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
    assert!(!graph.nodes.contains_key("node_modules/pkg-a/node_modules/shared-pkg"));
    assert!(!graph.nodes.contains_key("node_modules/pkg-b/node_modules/shared-pkg"));

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
        v.dependencies.insert("conflict-dep".to_string(), "^1.0.0".to_string());
    });

    // Package B requires dep@^2.0.0
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies.insert("conflict-dep".to_string(), "^2.0.0".to_string());
    });

    provider.add_version("conflict-dep", "1.5.0", |_| {});
    provider.add_version("conflict-dep", "2.1.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("test-project".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("pkg-b".to_string(), "^1.0.0".to_string());

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
    manifest.dependencies.insert(
        "my-chalk".to_string(),
        "npm:chalk@^5.0.0".to_string(),
    );

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
        v.dependencies.insert("semver".to_string(), "^6.0.0".to_string());
        v.dependencies.insert("sub-dep".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("sub-dep", "1.0.0", |v| {
        v.dependencies.insert("deep-target".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("other-pkg", "1.0.0", |v| {
        v.dependencies.insert("deep-target".to_string(), "^1.0.0".to_string());
    });

    provider.add_version("semver", "6.3.0", |_| {});
    provider.add_version("semver", "7.5.4", |_| {});
    provider.add_version("deep-target", "1.0.0", |_| {});
    provider.add_version("deep-target", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("overrides-project".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("other-pkg".to_string(), "1.0.0".to_string());

    // Configure overrides:
    // 1. Global: semver -> 7.5.4
    // 2. Nested: pkg-a -> deep-target -> 2.0.0
    let overrides_json = serde_json::json!({
        "semver": "7.5.4",
        "pkg-a": {
            "deep-target": "2.0.0"
        }
    });
    manifest.extra.insert("overrides".to_string(), overrides_json);

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // 1. Check global override: semver should be 7.5.4 even though pkg-a requested ^6.0.0
    let semver_node = graph.nodes.get("node_modules/semver").unwrap();
    assert_eq!(semver_node.version, "7.5.4");

    // 2. Check nested override: deep-target under pkg-a is overridden to 2.0.0
    // while other-pkg uses 1.0.0
    let other_edges = graph.get_outgoing_edges("node_modules/other-pkg");
    let other_target_edge = other_edges.iter().find(|e| e.install_name == "deep-target").unwrap();
    let other_target_node = graph.nodes.get(&other_target_edge.to_location).unwrap();
    assert_eq!(other_target_node.version, "1.0.0");

    let sub_edges = graph.get_outgoing_edges("node_modules/sub-dep");
    let pkg_a_target_edge = sub_edges.iter().find(|e| e.install_name == "deep-target").unwrap();
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
    manifest.optional_dependencies.insert("darwin-native".to_string(), "^1.0.0".to_string());
    manifest.optional_dependencies.insert("win32-native".to_string(), "^1.0.0".to_string());
    manifest.optional_dependencies.insert("x64-native".to_string(), "^1.0.0".to_string());

    // Scenario A: simulated Windows x64 host
    let win_options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let win_graph = resolve_dependency_graph(&manifest, &provider, &win_options).unwrap();
    assert!(win_graph.nodes.contains_key("node_modules/win32-native"));
    assert!(win_graph.nodes.contains_key("node_modules/x64-native"));
    assert!(!win_graph.nodes.contains_key("node_modules/darwin-native"));

    // Scenario B: simulated macOS arm64 host
    let mac_options = ResolverOptions {
        platform: Platform::new("darwin", "arm64"),
        ..Default::default()
    };
    let mac_graph = resolve_dependency_graph(&manifest, &provider, &mac_options).unwrap();
    assert!(mac_graph.nodes.contains_key("node_modules/darwin-native"));
    assert!(!mac_graph.nodes.contains_key("node_modules/win32-native"));
    assert!(!mac_graph.nodes.contains_key("node_modules/x64-native"));
}

#[test]
fn test_peer_dependencies_and_cycles() {
    let mut provider = InMemoryPackageProvider::new();

    // Cyclic peer dependencies: react peers react-dom, react-dom peers react
    provider.add_version("react", "18.2.0", |v| {
        v.peer_dependencies.insert("react-dom".to_string(), "^18.0.0".to_string());
    });

    provider.add_version("react-dom", "18.2.0", |v| {
        v.peer_dependencies.insert("react".to_string(), "^18.0.0".to_string());
    });

    // Optional peer dependency: canvas
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies.insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-test".to_string());
    manifest.dependencies.insert("react".to_string(), "18.2.0".to_string());
    manifest.dependencies.insert("chart-pkg".to_string(), "1.0.0".to_string());

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
fn test_dependency_graph_prune_unreferenced() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A requires B
    provider.add_version("pkg-a", "1.0.0", |v| {
        v.dependencies.insert("pkg-b".to_string(), "^1.0.0".to_string());
    });
    // Package B requires C
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.dependencies.insert("pkg-c".to_string(), "^1.0.0".to_string());
    });
    // Package C
    provider.add_version("pkg-c", "1.0.0", |_| {});

    // Package D (independent)
    provider.add_version("pkg-d", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("prune-test".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    manifest.dependencies.insert("pkg-d".to_string(), "^1.0.0".to_string());

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
