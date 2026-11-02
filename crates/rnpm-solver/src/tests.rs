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
