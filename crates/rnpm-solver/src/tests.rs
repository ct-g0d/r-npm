use std::collections::BTreeMap;
use rnpm_core::manifest::{Manifest, PeerDependencyMeta};
use crate::platform::Platform;
use crate::solver::{resolve_dependency_graph, ResolverOptions};
use crate::types::{InMemoryPackageProvider, PackageVersionMetadata};

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
    assert_eq!(meta_arr.os.as_deref(), Some(&["darwin".to_string(), "linux".to_string()][..]));
    assert_eq!(meta_arr.cpu.as_deref(), Some(&["x64".to_string(), "arm64".to_string()][..]));
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
    manifest.optional_dependencies.insert("glibc-pkg".to_string(), "1.0.0".to_string());
    manifest.optional_dependencies.insert("musl-pkg".to_string(), "1.0.0".to_string());
    manifest.optional_dependencies.insert("not-musl-pkg".to_string(), "1.0.0".to_string());

    // Host 1: Linux with glibc
    let glibc_opts = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("glibc".to_string())),
        ..Default::default()
    };
    let graph1 = resolve_dependency_graph(&manifest, &provider, &glibc_opts).unwrap();
    assert!(graph1.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(graph1.nodes.contains_key("node_modules/not-musl-pkg"));
    assert!(!graph1.nodes.contains_key("node_modules/musl-pkg"));
    assert!(graph1.is_skipped("musl-pkg"));

    // Host 2: Linux with musl (Alpine)
    let musl_opts = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("musl".to_string())),
        ..Default::default()
    };
    let graph2 = resolve_dependency_graph(&manifest, &provider, &musl_opts).unwrap();
    assert!(graph2.nodes.contains_key("node_modules/musl-pkg"));
    assert!(!graph2.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(!graph2.nodes.contains_key("node_modules/not-musl-pkg"));
    assert!(graph2.is_skipped("glibc-pkg"));
    assert!(graph2.is_skipped("not-musl-pkg"));

    // Host 3: Windows (no libc)
    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph3 = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();
    assert!(!graph3.nodes.contains_key("node_modules/glibc-pkg"));
    assert!(!graph3.nodes.contains_key("node_modules/musl-pkg"));
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
        v.dependencies.insert("child-pkg".to_string(), "1.0.0".to_string());
    });

    provider.add_version("child-pkg", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("transitive-opt".to_string());
    manifest.optional_dependencies.insert("darwin-parent".to_string(), "1.0.0".to_string());

    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();

    // Neither darwin-parent NOR its child-pkg should be placed in node_modules!
    assert!(!graph.nodes.contains_key("node_modules/darwin-parent"));
    assert!(!graph.nodes.contains_key("node_modules/child-pkg"));
    assert!(graph.is_skipped("darwin-parent"));
}

#[test]
fn test_circular_dependencies_termination() {
    let mut provider = InMemoryPackageProvider::new();

    // Package A depends on Package B
    provider.add_version("pkg-circ-a", "1.0.0", |v| {
        v.dependencies.insert("pkg-circ-b".to_string(), "1.0.0".to_string());
    });

    // Package B depends on Package A (direct cycle)
    provider.add_version("pkg-circ-b", "1.0.0", |v| {
        v.dependencies.insert("pkg-circ-a".to_string(), "1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("circ-test".to_string());
    manifest.dependencies.insert("pkg-circ-a".to_string(), "1.0.0".to_string());

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
    manifest.optional_dependencies.insert("nonexistent-pkg".to_string(), "1.0.0".to_string());

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

#[test]
fn test_workspace_protocol_dependencies_and_topo_sort() {
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::WorkspaceDependencyGraph;
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
    manifest_b.dependencies.insert("pkg-a".to_string(), "workspace:*".to_string());
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
    manifest_c.dependencies.insert("pkg-b".to_string(), "workspace:^".to_string());
    manifest_c.dependencies.insert("pkg-a".to_string(), "workspace:~".to_string());
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
        vec!["pkg-a".to_string(), "pkg-b".to_string(), "pkg-c".to_string()]
    );
}

#[test]
fn test_workspace_circular_dependencies_detected() {
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::WorkspaceDependencyGraph;
    use crate::error::SolverError;
    use std::path::PathBuf;

    // A -> B and B -> A cycle
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a.dependencies.insert("pkg-b".to_string(), "workspace:*".to_string());
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
    manifest_b.dependencies.insert("pkg-a".to_string(), "workspace:*".to_string());
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
    m_a.dependencies.insert("b".to_string(), "workspace:*".to_string());
    let member_a3 = WorkspaceMember {
        name: "a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/a"),
        relative_path: "packages/a".to_string(),
        manifest: m_a,
    };

    let mut m_b = Manifest::default();
    m_b.name = Some("b".to_string());
    m_b.dependencies.insert("c".to_string(), "workspace:*".to_string());
    let member_b3 = WorkspaceMember {
        name: "b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/b"),
        relative_path: "packages/b".to_string(),
        manifest: m_b,
    };

    let mut m_c = Manifest::default();
    m_c.name = Some("c".to_string());
    m_c.dependencies.insert("a".to_string(), "workspace:*".to_string());
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
    m_self.dependencies.insert("self-pkg".to_string(), "workspace:*".to_string());
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
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::WorkspaceDependencyGraph;
    use crate::error::SolverError;
    use std::path::PathBuf;

    // Missing sibling workspace member
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.dependencies.insert("ghost-pkg".to_string(), "workspace:*".to_string());
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
    manifest_c.dependencies.insert("pkg-b".to_string(), "workspace:^2.0.0".to_string());
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
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::resolve_workspace_graph;
    use std::path::PathBuf;

    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("shared-lib", "4.17.21", |_| {});

    let mut root_manifest = Manifest::default();
    root_manifest.name = Some("monorepo-root".to_string());

    // Member A depends on shared-lib
    let mut manifest_a = Manifest::default();
    manifest_a.name = Some("pkg-a".to_string());
    manifest_a.version = Some("1.0.0".to_string());
    manifest_a.dependencies.insert("shared-lib".to_string(), "^4.0.0".to_string());
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
    manifest_b.dependencies.insert("pkg-a".to_string(), "workspace:*".to_string());
    let member_b = WorkspaceMember {
        name: "pkg-b".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-b"),
        relative_path: "packages/pkg-b".to_string(),
        manifest: manifest_b,
    };

    let options = ResolverOptions::default();
    let graph = resolve_workspace_graph(
        &root_manifest,
        &[member_a, member_b],
        &provider,
        &options,
    ).unwrap();

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
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::WorkspaceDependencyGraph;
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
    m_b.dependencies.insert("pkg-d".to_string(), "workspace:*".to_string());
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
    m_c.dependencies.insert("pkg-d".to_string(), "workspace:*".to_string());
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
    m_a.dependencies.insert("pkg-b".to_string(), "workspace:*".to_string());
    m_a.dependencies.insert("pkg-c".to_string(), "workspace:*".to_string());
    let member_a = WorkspaceMember {
        name: "pkg-a".to_string(),
        version: Some("1.0.0".to_string()),
        path: PathBuf::from("packages/pkg-a"),
        relative_path: "packages/pkg-a".to_string(),
        manifest: m_a,
    };

    let ws_graph = WorkspaceDependencyGraph::construct(&[member_a, member_c, member_b, member_d]).unwrap();

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
    use rnpm_core::workspace::WorkspaceMember;
    use crate::workspace::WorkspaceDependencyGraph;
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
    m_a.dependencies.insert("comp1-b".to_string(), "workspace:*".to_string());
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
    use rnpm_lockfile::{LockfilePackage, LockfileV3};
    use crate::solver::{resolve_dependency_graph_with_lockfile, resolve_fast_path};

    let mut manifest = Manifest::default();
    manifest.name = Some("fast-app".to_string());
    manifest.dependencies.insert("chalk".to_string(), "^5.0.0".to_string());
    manifest.dev_dependencies.insert("typescript".to_string(), "^5.0.0".to_string());

    let mut lockfile = LockfileV3::new("fast-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("chalk".to_string(), "^5.0.0".to_string());
    let mut lock_dev_deps = BTreeMap::new();
    lock_dev_deps.insert("typescript".to_string(), "^5.0.0".to_string());

    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
        root.dev_dependencies = Some(lock_dev_deps);
    }
    lockfile.insert_package("node_modules/chalk", LockfilePackage {
        version: Some("5.3.0".to_string()),
        resolved: Some("https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz".to_string()),
        integrity: Some("sha512-chalk123".to_string()),
        ..Default::default()
    });
    lockfile.insert_package("node_modules/typescript", LockfilePackage {
        version: Some("5.4.2".to_string()),
        dev: Some(true),
        ..Default::default()
    });

    let options = ResolverOptions::default();

    // 1. Direct resolve_fast_path test
    let fast_graph = resolve_fast_path(&manifest, &lockfile, &options).expect("Fast path should succeed");
    assert!(fast_graph.nodes.contains_key("node_modules/chalk"));
    assert!(fast_graph.nodes.contains_key("node_modules/typescript"));
    assert_eq!(fast_graph.nodes.get("node_modules/chalk").unwrap().version, "5.3.0");

    // 2. resolve_dependency_graph_with_lockfile using EMPTY provider (would fail if provider was queried!)
    let empty_provider = InMemoryPackageProvider::new();
    let graph = resolve_dependency_graph_with_lockfile(
        &manifest,
        &empty_provider,
        &options,
        Some(&lockfile),
    ).expect("Resolution must succeed via fast-path without querying provider");

    assert!(graph.nodes.contains_key("node_modules/chalk"));
    assert!(graph.nodes.contains_key("node_modules/typescript"));

    // 3. When manifest changes (spec drift), fast-path returns None and solver queries provider (fails on empty)
    let mut drifted_manifest = manifest.clone();
    drifted_manifest.dependencies.insert("chalk".to_string(), "^6.0.0".to_string());
    assert!(resolve_fast_path(&drifted_manifest, &lockfile, &options).is_none());

    let drifted_res = resolve_dependency_graph_with_lockfile(
        &drifted_manifest,
        &empty_provider,
        &options,
        Some(&lockfile),
    );
    assert!(drifted_res.is_err(), "Must fall back to provider and fail on missing metadata");
}

#[test]
fn test_peer_dependency_conflict_diagnostic_error() {
    let mut provider = InMemoryPackageProvider::new();

    // React 18 is installed at root
    provider.add_version("react", "18.2.0", |_| {});

    // Plugin requires react peer ^16.0.0 || ^17.0.0
    provider.add_version("legacy-plugin", "1.0.0", |v| {
        v.peer_dependencies.insert("react".to_string(), "^17.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-conflict-app".to_string());
    manifest.dependencies.insert("react".to_string(), "18.2.0".to_string());
    manifest.dependencies.insert("legacy-plugin".to_string(), "1.0.0".to_string());

    // Scenario A: Strict mode (default) -> ERESOLVE peer conflict error
    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let err = resolve_dependency_graph(&manifest, &provider, &options).unwrap_err();

    let err_msg = err.to_string();
    assert!(err_msg.contains("ERESOLVE: Conflicting peer dependency 'react' required by 'legacy-plugin'"));
    assert!(err_msg.contains("peer react@\"^17.0.0\" from legacy-plugin"));
    assert!(err_msg.contains("Found: react@18.2.0 at node_modules/react"));
    assert!(err_msg.contains("Suggested resolutions:"));
    assert!(err_msg.contains("Add an override in package.json: \"overrides\": { \"react\": \"...\" }"));
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
    assert!(legacy_graph.nodes.contains_key("node_modules/legacy-plugin"));
}

#[test]
fn test_hidden_tree_metadata_preservation_in_graph() {
    use rnpm_lockfile::{LockfilePackage, LockfileV3};
    use crate::graph::DependencyGraph;

    let mut lockfile = LockfileV3::new("meta-app", Some("1.0.0".to_string()));
    let mut extra = BTreeMap::new();
    extra.insert("funding".to_string(), serde_json::json!("https://example.com/fund"));
    extra.insert("deprecated".to_string(), serde_json::json!("legacy package"));

    lockfile.insert_package("node_modules/custom", LockfilePackage {
        version: Some("1.0.0".to_string()),
        extra: extra.clone(),
        ..Default::default()
    });

    // from_lockfile_v3 preserves extra into Node
    let graph = DependencyGraph::from_lockfile_v3(&lockfile);
    let node = graph.nodes.get("node_modules/custom").expect("Node missing");
    assert_eq!(node.extra.get("funding"), extra.get("funding"));
    assert_eq!(node.extra.get("deprecated"), extra.get("deprecated"));

    // to_lockfile_v3 writes it back into LockfilePackage
    let generated_lock = graph.to_lockfile_v3("meta-app", Some("1.0.0"));
    let gen_pkg = generated_lock.packages.get("node_modules/custom").expect("Package missing");
    assert_eq!(gen_pkg.extra.get("funding"), extra.get("funding"));
    assert_eq!(gen_pkg.extra.get("deprecated"), extra.get("deprecated"));
}

#[test]
fn test_fast_path_detects_lockfile_drift_missing_transitive_dep() {
    use rnpm_lockfile::{LockfilePackage, LockfileV3};
    use crate::solver::resolve_fast_path;

    let mut manifest = Manifest::default();
    manifest.name = Some("drift-app".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());

    let mut lockfile = LockfileV3::new("drift-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
    }

    // pkg-a is in lockfile, and declares dependency on missing-b
    let mut a_deps = BTreeMap::new();
    a_deps.insert("missing-b".to_string(), "^1.0.0".to_string());
    lockfile.insert_package("node_modules/pkg-a", LockfilePackage {
        version: Some("1.0.0".to_string()),
        dependencies: Some(a_deps),
        ..Default::default()
    });
    // Note: missing-b is intentionally NOT added to lockfile.packages!

    let options = ResolverOptions::default();
    // Fast path must detect drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_fast_path_detects_lockfile_version_constraint_mismatch() {
    use rnpm_lockfile::{LockfilePackage, LockfileV3};
    use crate::solver::resolve_fast_path;

    let mut manifest = Manifest::default();
    manifest.name = Some("drift-mismatch-app".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());

    let mut lockfile = LockfileV3::new("drift-mismatch-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
    }

    let mut a_deps = BTreeMap::new();
    a_deps.insert("dep-b".to_string(), "^2.0.0".to_string());
    lockfile.insert_package("node_modules/pkg-a", LockfilePackage {
        version: Some("1.0.0".to_string()),
        dependencies: Some(a_deps),
        ..Default::default()
    });

    // dep-b is locked at 1.5.0, which violates ^2.0.0 constraint
    lockfile.insert_package("node_modules/dep-b", LockfilePackage {
        version: Some("1.5.0".to_string()),
        ..Default::default()
    });

    let options = ResolverOptions::default();
    // Fast path must detect version mismatch drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_fast_path_detects_overrides_drift() {
    use rnpm_lockfile::{LockfilePackage, LockfileV3};
    use crate::solver::resolve_fast_path;

    let mut manifest = Manifest::default();
    manifest.name = Some("overrides-drift-app".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    // Manifest adds an override for dep-b -> 2.5.0
    manifest.extra.insert("overrides".to_string(), serde_json::json!({
        "dep-b": "2.5.0"
    }));

    let mut lockfile = LockfileV3::new("overrides-drift-app", Some("1.0.0".to_string()));
    let mut lock_deps = BTreeMap::new();
    lock_deps.insert("pkg-a".to_string(), "^1.0.0".to_string());
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(lock_deps);
        // Lockfile has no overrides in extra
    }

    lockfile.insert_package("node_modules/pkg-a", LockfilePackage {
        version: Some("1.0.0".to_string()),
        ..Default::default()
    });

    let options = ResolverOptions::default();
    // Fast path must detect overrides drift and return None
    assert!(resolve_fast_path(&manifest, &lockfile, &options).is_none());
}

#[test]
fn test_intermediate_ancestor_hoisting() {
    use crate::hoisting::{determine_placement, PlacementDecision};
    use crate::graph::Node;
    use rnpm_core::spec::PackageTarget;
    use rnpm_core::semver::Range;

    let mut graph = crate::graph::DependencyGraph::new();

    // Root node_modules has C@1.0.0
    graph.nodes.insert("node_modules/C".to_string(), Node {
        location: "node_modules/C".to_string(),
        install_name: "C".to_string(),
        name: "C".to_string(),
        version: "1.0.0".to_string(),
        parsed_version: rnpm_core::semver::Version::parse("1.0.0").ok(),
        ..Default::default()
    });

    // Node A is at node_modules/A
    graph.nodes.insert("node_modules/A".to_string(), Node {
        location: "node_modules/A".to_string(),
        install_name: "A".to_string(),
        name: "A".to_string(),
        version: "1.0.0".to_string(),
        ..Default::default()
    });

    // Node B is nested at node_modules/A/node_modules/B
    graph.nodes.insert("node_modules/A/node_modules/B".to_string(), Node {
        location: "node_modules/A/node_modules/B".to_string(),
        install_name: "B".to_string(),
        name: "B".to_string(),
        version: "1.0.0".to_string(),
        ..Default::default()
    });

    // Dependent B requires C@^2.0.0
    let target = PackageTarget::Range(Range::parse("^2.0.0").unwrap());
    let decision = determine_placement(
        &graph,
        "node_modules/A/node_modules/B",
        "C",
        "C",
        &target,
    );

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
        v.peer_dependencies.insert("pkg-b".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("pkg-b", "1.0.0", |v| {
        v.peer_dependencies.insert("pkg-c".to_string(), "^1.0.0".to_string());
    });
    provider.add_version("pkg-c", "1.0.0", |v| {
        v.peer_dependencies.insert("pkg-a".to_string(), "^1.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("peer-cycle-3-app".to_string());
    manifest.dependencies.insert("pkg-a".to_string(), "1.0.0".to_string());

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
        v.peer_dependencies.insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-present".to_string());
    // Both chart-pkg and canvas installed explicitly
    manifest.dependencies.insert("chart-pkg".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("canvas".to_string(), "2.8.0".to_string());

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
        v.peer_dependencies.insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-incompat".to_string());
    manifest.dependencies.insert("chart-pkg".to_string(), "1.0.0".to_string());
    manifest.dependencies.insert("canvas".to_string(), "1.0.0".to_string());

    // In strict mode (strict_peers: true), incompatible optional peer must NOT fail with ERESOLVE!
    let options = ResolverOptions {
        strict_peers: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Incompatible optional peer must be omitted silently, not fail resolution");

    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    assert!(graph.nodes.contains_key("node_modules/canvas"));
    assert_eq!(graph.nodes.get("node_modules/canvas").unwrap().version, "1.0.0");
}

#[test]
fn test_optional_peer_absent_not_auto_downloaded() {
    let mut provider = InMemoryPackageProvider::new();

    // canvas exists in registry provider
    provider.add_version("canvas", "2.8.0", |_| {});
    // chart-pkg optionally peers canvas ^2.0.0
    provider.add_version("chart-pkg", "1.0.0", |v| {
        v.peer_dependencies.insert("canvas".to_string(), "^2.0.0".to_string());
        let mut meta = BTreeMap::new();
        meta.insert("canvas".to_string(), PeerDependencyMeta { optional: true });
        v.peer_dependencies_meta = meta;
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("opt-peer-absent".to_string());
    manifest.dependencies.insert("chart-pkg".to_string(), "1.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    // chart-pkg is installed, but canvas was NOT auto-downloaded
    assert!(graph.nodes.contains_key("node_modules/chart-pkg"));
    assert!(!graph.nodes.contains_key("node_modules/canvas"));
}

#[test]
fn test_peer_conflict_rich_diagnostics() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("react", "18.2.0", |_| {});
    provider.add_version("plugin", "1.0.0", |v| {
        v.peer_dependencies.insert("react".to_string(), "^17.0.0".to_string());
    });

    let mut manifest = Manifest::default();
    manifest.name = Some("app".to_string());
    manifest.dependencies.insert("react".to_string(), "18.2.0".to_string());
    manifest.dependencies.insert("plugin".to_string(), "1.0.0".to_string());

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
        v.dependencies.insert("cuda-driver".to_string(), "1.0.0".to_string());
        v.dependencies.insert("large-weights".to_string(), "1.0.0".to_string());
    });
    provider.add_version("cuda-driver", "1.0.0", |_| {});
    provider.add_version("large-weights", "1.0.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("platform-isolation-test".to_string());
    manifest.optional_dependencies.insert("linux-bundle".to_string(), "1.0.0".to_string());

    // Host: Windows x64
    let win_opts = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &win_opts).unwrap();

    // Verify complete isolation: linux-bundle is marked skipped
    assert!(graph.is_skipped("linux-bundle"));
    // Neither linux-bundle NOR its transitive dependencies exist in graph
    assert!(!graph.nodes.contains_key("node_modules/linux-bundle"));
    assert!(!graph.nodes.contains_key("node_modules/cuda-driver"));
    assert!(!graph.nodes.contains_key("node_modules/large-weights"));
}

#[test]
fn test_root_peer_dependencies_auto_installed() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("react", "18.2.0", |_| {});

    let mut manifest = Manifest::default();
    manifest.name = Some("root-peer-app".to_string());
    manifest.peer_dependencies.insert("react".to_string(), "^18.0.0".to_string());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes.contains_key("node_modules/react"));
    assert_eq!(graph.nodes.get("node_modules/react").unwrap().version, "18.2.0");
}

