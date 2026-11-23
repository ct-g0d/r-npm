//! Offline regression and stress tests for rnpm-solver covering borderline corpus patterns:
//! - Diamond dependency greedy root-hoisting and nested conflict placement & edge verification
//! - SemVer prerelease range selection and standard range exclusion
//! - SemVer caret zero boundary (^0.0.x and ^0.x.y)
//! - Optional dependency platform (OS, CPU, libc) filtering & skip propagation (explicit + host current)
//! - Optional dependency negated platform filters (!win32, !arm64) end-to-end
//! - Bundled dependencies metadata & placement (List and Boolean) with lockfile v3 serialization
//! - Npm alias resolution (standard, scoped, bare, and multi-version co-existence with unaliased)
//! - Dedicated alias lockfile reuse and alias prefer_dedupe scope hierarchy verification
//! - Deduplication / hoist boundary cases (prefer_dedupe: false vs true, nested conflict placement)
//! - Deprecated version avoidance and fallback
//! - Missing version range and nonexistent package error handling with explicit field checks
//!
//! All tests are 100% deterministic, offline, cross-platform, and execute in memory.

use std::sync::Arc;

use rnpm_core::manifest::{BundledDependencies, Manifest};
use rnpm_core::PlatformList;
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use rnpm_solver::{
    resolve_dependency_graph, DependencySpec, InMemoryPackageProvider, Platform,
    ResolverOptions, SolverError,
};

// ============================================================================
// 1. SEMVER RESOLUTION & DIAMOND DEPENDENCY HOISTING / NESTING
// ============================================================================

#[test]
fn test_diamond_dependency_greedy_hoist_and_nested_conflict() {
    let mut provider = InMemoryPackageProvider::new();

    // c has multiple versions
    for ver in ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "2.0.0"] {
        provider.add_version("c", ver, |_| {});
    }

    // a requires c@^1.0.0 (compatible with 1.0, 1.1, 1.2, 1.3)
    provider.add_version("a", "1.0.0", |v| {
        v.dependencies.insert("c".into(), "^1.0.0".into());
    });

    // b restricts c to >=1.1.0 <1.3.0 (compatible only with 1.1.0, 1.2.0)
    provider.add_version("b", "1.0.0", |v| {
        v.dependencies.insert("c".into(), ">=1.1.0 <1.3.0".into());
    });

    let mut manifest = Manifest::default();
    manifest.dependencies.insert("a".into(), "1.0.0".into());
    manifest.dependencies.insert("b".into(), "1.0.0".into());

    let options = ResolverOptions::default();
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Diamond dependency resolution should succeed");

    // c should be greedily hoisted to root satisfying a's ^1.0.0 with highest 1.3.0
    assert!(
        graph.nodes.contains_key("node_modules/c"),
        "c should be hoisted to top-level node_modules/c"
    );
    let resolved_c = &graph.nodes["node_modules/c"];
    assert_eq!(
        resolved_c.version, "1.3.0",
        "Top-level c resolves to 1.3.0 satisfying a's ^1.0.0"
    );

    // Because b requires c@>=1.1.0 <1.3.0 which doesn't match top-level 1.3.0,
    // b gets its own nested copy of c@1.2.0 under node_modules/b/node_modules/c
    assert!(
        graph.nodes.contains_key("node_modules/b/node_modules/c"),
        "b should have nested node_modules/b/node_modules/c"
    );
    let nested_c = &graph.nodes["node_modules/b/node_modules/c"];
    assert_eq!(
        nested_c.version, "1.2.0",
        "Nested c resolves to 1.2.0 satisfying b's >=1.1.0 <1.3.0"
    );

    // Verify graph edges
    let root_edges = graph.get_outgoing_edges("");
    assert!(
        root_edges
            .iter()
            .any(|e| e.to_location == "node_modules/a" && e.package_name == "a"),
        "Root must have edge to a"
    );
    assert!(
        root_edges
            .iter()
            .any(|e| e.to_location == "node_modules/b" && e.package_name == "b"),
        "Root must have edge to b"
    );

    let a_edges = graph.get_outgoing_edges("node_modules/a");
    assert!(
        a_edges
            .iter()
            .any(|e| e.to_location == "node_modules/c" && e.package_name == "c" && e.spec == "^1.0.0"),
        "a must have edge to hoisted c@1.3.0"
    );

    let b_edges = graph.get_outgoing_edges("node_modules/b");
    assert!(
        b_edges.iter().any(|e| {
            e.to_location == "node_modules/b/node_modules/c"
                && e.package_name == "c"
                && e.spec == ">=1.1.0 <1.3.0"
        }),
        "b must have edge to nested c@1.2.0"
    );
}

#[test]
fn test_semver_prerelease_range_selection() {
    let mut provider = InMemoryPackageProvider::new();
    for ver in [
        "1.0.0-alpha.1",
        "1.0.0-beta.1",
        "1.0.0-beta.2",
        "1.0.0-rc.1",
        "1.0.0",
        "1.1.0",
        "1.2.0-alpha.1",
        "2.0.0-alpha.1",
    ] {
        provider.add_version("tool", ver, |_| {});
    }

    // 1. Explicitly targeting prerelease beta range
    let mut manifest_prerelease = Manifest::default();
    manifest_prerelease
        .dependencies
        .insert("tool".into(), ">=1.0.0-beta.1 <1.0.0-rc.1".into());

    let graph_prerelease =
        resolve_dependency_graph(&manifest_prerelease, &provider, &ResolverOptions::default())
            .expect("Prerelease resolution should succeed");
    assert_eq!(
        graph_prerelease.nodes["node_modules/tool"].version, "1.0.0-beta.2",
        "Should select highest prerelease matching the explicit prerelease bound"
    );

    // 2. Standard ranges (^1.0.0, 1.x) must EXCLUDE prereleases even when newer than stable
    let mut manifest_caret = Manifest::default();
    manifest_caret
        .dependencies
        .insert("tool".into(), "^1.0.0".into());
    let graph_caret =
        resolve_dependency_graph(&manifest_caret, &provider, &ResolverOptions::default())
            .expect("Caret range resolution");
    assert_eq!(
        graph_caret.nodes["node_modules/tool"].version, "1.1.0",
        "^1.0.0 must select latest stable 1.1.0 and exclude 1.2.0-alpha.1"
    );

    let mut manifest_x = Manifest::default();
    manifest_x
        .dependencies
        .insert("tool".into(), "1.x".into());
    let graph_x =
        resolve_dependency_graph(&manifest_x, &provider, &ResolverOptions::default())
            .expect("1.x range resolution");
    assert_eq!(
        graph_x.nodes["node_modules/tool"].version, "1.1.0",
        "1.x must select latest stable 1.1.0 and exclude 1.2.0-alpha.1"
    );
}

#[test]
fn test_semver_caret_zero_boundary() {
    let mut provider = InMemoryPackageProvider::new();
    for ver in ["0.0.1", "0.0.2", "0.1.0", "0.1.1", "0.2.0"] {
        provider.add_version("zero-lib", ver, |_| {});
    }

    // ^0.0.1 in npm strictly matches only 0.0.1
    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("zero-lib".into(), "^0.0.1".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Caret zero resolution");
    assert_eq!(graph.nodes["node_modules/zero-lib"].version, "0.0.1");

    // ^0.1.0 in npm matches 0.1.0 and 0.1.1, but not 0.2.0
    let mut manifest2 = Manifest::default();
    manifest2
        .dependencies
        .insert("zero-lib".into(), "^0.1.0".into());

    let graph2 = resolve_dependency_graph(&manifest2, &provider, &ResolverOptions::default())
        .expect("Caret 0.1.0 resolution");
    assert_eq!(graph2.nodes["node_modules/zero-lib"].version, "0.1.1");
}

// ============================================================================
// 2. OPTIONAL DEPENDENCY PLATFORM (OS, CPU, LIBC) FILTERING & SKIP PROPAGATION
// ============================================================================

#[test]
fn test_optional_dep_platform_os_explicit_target_and_host_current() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("opt-win", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["win32".into()]));
    });
    provider.add_version("opt-darwin", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["darwin".into()]));
    });
    provider.add_version("opt-linux", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["linux".into()]));
    });

    let mut manifest = Manifest::default();
    manifest
        .optional_dependencies
        .insert("opt-win".into(), "1.0.0".into());
    manifest
        .optional_dependencies
        .insert("opt-darwin".into(), "1.0.0".into());
    manifest
        .optional_dependencies
        .insert("opt-linux".into(), "1.0.0".into());

    // Part A: Explicit Windows x64 platform
    let options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Graph resolution with explicit platform");

    let win_node = &graph.nodes["node_modules/opt-win"];
    let darwin_node = &graph.nodes["node_modules/opt-darwin"];
    let linux_node = &graph.nodes["node_modules/opt-linux"];

    assert!(!win_node.flags.skipped, "win32 package should NOT be skipped on win32");
    assert_eq!(win_node.flags.platform_skipped, Some(false));

    assert!(darwin_node.flags.skipped, "darwin package should be skipped on win32");
    assert_eq!(darwin_node.flags.platform_skipped, Some(true));

    assert!(linux_node.flags.skipped, "linux package should be skipped on win32");
    assert_eq!(linux_node.flags.platform_skipped, Some(true));

    // Part B: Dynamic host platform resolution via Platform::current()
    let options_host = ResolverOptions {
        platform: Platform::current(),
        ..Default::default()
    };
    let graph_host = resolve_dependency_graph(&manifest, &provider, &options_host)
        .expect("Graph resolution with Platform::current()");

    let current_os = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };

    let host_matching_key = match current_os {
        "win32" => "node_modules/opt-win",
        "darwin" => "node_modules/opt-darwin",
        "linux" => "node_modules/opt-linux",
        _ => "none",
    };

    if host_matching_key != "none" {
        let matching_node = &graph_host.nodes[host_matching_key];
        assert!(
            !matching_node.flags.skipped,
            "Package matching current host OS ({current_os}) must NOT be skipped"
        );
        assert_eq!(matching_node.flags.platform_skipped, Some(false));
    }
}

#[test]
fn test_optional_dep_cpu_and_libc_filtering() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("bin-linux-x64-gnu", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["linux".into()]));
        v.cpu = Some(PlatformList::from(vec!["x64".into()]));
        v.libc = Some(PlatformList::from(vec!["glibc".into()]));
    });
    provider.add_version("bin-linux-x64-musl", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["linux".into()]));
        v.cpu = Some(PlatformList::from(vec!["x64".into()]));
        v.libc = Some(PlatformList::from(vec!["musl".into()]));
    });
    provider.add_version("bin-linux-arm64-gnu", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["linux".into()]));
        v.cpu = Some(PlatformList::from(vec!["arm64".into()]));
        v.libc = Some(PlatformList::from(vec!["glibc".into()]));
    });

    let mut manifest = Manifest::default();
    manifest
        .optional_dependencies
        .insert("bin-linux-x64-gnu".into(), "1.0.0".into());
    manifest
        .optional_dependencies
        .insert("bin-linux-x64-musl".into(), "1.0.0".into());
    manifest
        .optional_dependencies
        .insert("bin-linux-arm64-gnu".into(), "1.0.0".into());

    // Target Linux x64 glibc
    let options = ResolverOptions {
        platform: Platform::with_libc("linux", "x64", Some("glibc".into())),
        ..Default::default()
    };

    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    let gnu_node = &graph.nodes["node_modules/bin-linux-x64-gnu"];
    assert!(!gnu_node.flags.skipped);
    assert_eq!(gnu_node.flags.platform_skipped, Some(false));

    let musl_node = &graph.nodes["node_modules/bin-linux-x64-musl"];
    assert!(musl_node.flags.skipped);
    assert_eq!(musl_node.flags.platform_skipped, Some(true));

    let arm_node = &graph.nodes["node_modules/bin-linux-arm64-gnu"];
    assert!(arm_node.flags.skipped);
    assert_eq!(arm_node.flags.platform_skipped, Some(true));
}

#[test]
fn test_optional_dep_negated_platform_filters() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("pkg-not-win", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["!win32".into()]));
    });
    provider.add_version("pkg-not-arm", "1.0.0", |v| {
        v.cpu = Some(PlatformList::from(vec!["!arm64".into()]));
    });

    let mut manifest = Manifest::default();
    manifest
        .optional_dependencies
        .insert("pkg-not-win".into(), "1.0.0".into());
    manifest
        .optional_dependencies
        .insert("pkg-not-arm".into(), "1.0.0".into());

    // 1. On Windows x64: !win32 is skipped, !arm64 is supported
    let options_win = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let graph_win = resolve_dependency_graph(&manifest, &provider, &options_win).unwrap();
    assert!(graph_win.nodes["node_modules/pkg-not-win"].flags.skipped);
    assert_eq!(
        graph_win.nodes["node_modules/pkg-not-win"].flags.platform_skipped,
        Some(true)
    );
    assert!(!graph_win.nodes["node_modules/pkg-not-arm"].flags.skipped);
    assert_eq!(
        graph_win.nodes["node_modules/pkg-not-arm"].flags.platform_skipped,
        Some(false)
    );

    // 2. On macOS arm64: !win32 is supported, !arm64 is skipped
    let options_mac = ResolverOptions {
        platform: Platform::new("darwin", "arm64"),
        ..Default::default()
    };
    let graph_mac = resolve_dependency_graph(&manifest, &provider, &options_mac).unwrap();
    assert!(!graph_mac.nodes["node_modules/pkg-not-win"].flags.skipped);
    assert_eq!(
        graph_mac.nodes["node_modules/pkg-not-win"].flags.platform_skipped,
        Some(false)
    );
    assert!(graph_mac.nodes["node_modules/pkg-not-arm"].flags.skipped);
    assert_eq!(
        graph_mac.nodes["node_modules/pkg-not-arm"].flags.platform_skipped,
        Some(true)
    );

    // 3. On Linux x64: both !win32 and !arm64 are supported
    let options_linux = ResolverOptions {
        platform: Platform::new("linux", "x64"),
        ..Default::default()
    };
    let graph_linux = resolve_dependency_graph(&manifest, &provider, &options_linux).unwrap();
    assert!(!graph_linux.nodes["node_modules/pkg-not-win"].flags.skipped);
    assert_eq!(
        graph_linux.nodes["node_modules/pkg-not-win"].flags.platform_skipped,
        Some(false)
    );
    assert!(!graph_linux.nodes["node_modules/pkg-not-arm"].flags.skipped);
    assert_eq!(
        graph_linux.nodes["node_modules/pkg-not-arm"].flags.platform_skipped,
        Some(false)
    );
}

#[test]
fn test_optional_dep_skip_propagation_exclusive_vs_shared_child() {
    let mut provider = InMemoryPackageProvider::new();

    // Exclusive child of unsupported optional package
    provider.add_version("exclusive-leaf", "1.0.0", |_| {});
    // Shared child needed by both unsupported optional package and a supported active package
    provider.add_version("shared-leaf", "1.0.0", |_| {});

    provider.add_version("unsupported-parent", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["darwin".into()]));
        v.dependencies.insert("exclusive-leaf".into(), "1.0.0".into());
        v.dependencies.insert("shared-leaf".into(), "1.0.0".into());
    });

    provider.add_version("supported-parent", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["win32".into()]));
        v.dependencies.insert("shared-leaf".into(), "1.0.0".into());
    });

    let mut manifest = Manifest::default();
    manifest
        .optional_dependencies
        .insert("unsupported-parent".into(), "1.0.0".into());
    manifest
        .dependencies
        .insert("supported-parent".into(), "1.0.0".into());

    let options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };

    let graph = resolve_dependency_graph(&manifest, &provider, &options).unwrap();

    assert!(graph.nodes["node_modules/unsupported-parent"].flags.skipped);
    assert!(
        graph.nodes["node_modules/exclusive-leaf"].flags.skipped,
        "Exclusive child of skipped parent must be skipped"
    );
    assert!(
        !graph.nodes["node_modules/shared-leaf"].flags.skipped,
        "Shared child reached by active supported parent must NOT be skipped"
    );
}

#[test]
fn test_required_incompatible_platform_fails_without_force() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("darwin-only-required", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["darwin".into()]));
    });

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("darwin-only-required".into(), "1.0.0".into());

    // Without --force, required package on wrong platform must return PlatformIncompatible error
    let options_strict = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        force: false,
        ..Default::default()
    };
    let result = resolve_dependency_graph(&manifest, &provider, &options_strict);
    match result {
        Err(SolverError::PlatformIncompatible {
            package,
            version,
            wanted,
            current,
            ..
        }) => {
            assert_eq!(package, "darwin-only-required");
            assert_eq!(version, "1.0.0");
            assert!(
                wanted.contains("darwin"),
                "Wanted platform must mention darwin, got {wanted}"
            );
            assert!(
                current.contains("win32"),
                "Current platform must mention win32, got {current}"
            );
        }
        other => panic!("Expected PlatformIncompatible error, got {:?}", other),
    }

    // With --force, installation proceeds and node is NOT skipped
    let options_forced = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        force: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options_forced)
        .expect("Force mode should bypass platform incompatibility");
    let node = &graph.nodes["node_modules/darwin-only-required"];
    assert!(!node.flags.skipped, "Under --force, required node must NOT be skipped");
    assert_eq!(node.flags.platform_skipped, Some(false));
}

// ============================================================================
// 3. BUNDLED DEPENDENCIES (LIST AND BOOLEAN) & LOCKFILE V3 SERIALIZATION
// ============================================================================

#[test]
fn test_bundled_dependencies_node_flagging() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("bundled-dep", "1.0.0", |_| {});
    provider.add_version("regular-dep", "1.0.0", |_| {});

    // Part A: BundledDependencies::List
    let mut manifest_list = Manifest {
        name: Some("bundle-list-app".into()),
        version: Some("1.0.0".into()),
        bundled_dependencies: Some(BundledDependencies::List(vec!["bundled-dep".into()])),
        ..Default::default()
    };
    manifest_list
        .dependencies
        .insert("bundled-dep".into(), "1.0.0".into());
    manifest_list
        .dependencies
        .insert("regular-dep".into(), "1.0.0".into());

    let graph_list = resolve_dependency_graph(&manifest_list, &provider, &ResolverOptions::default())
        .expect("Bundle list resolution");

    let bundled_node = &graph_list.nodes["node_modules/bundled-dep"];
    assert!(
        bundled_node.flags.bundled,
        "Bundled dependency must have flags.bundled set to true"
    );

    let regular_node = &graph_list.nodes["node_modules/regular-dep"];
    assert!(
        !regular_node.flags.bundled,
        "Regular dependency must have flags.bundled set to false"
    );

    let lockfile_list = graph_list.to_lockfile_v3("bundle-list-app", Some("1.0.0"));
    let root_entry = lockfile_list.packages.get("").unwrap();
    assert_eq!(
        root_entry.bundled_package_names(),
        vec!["bundled-dep".to_string()]
    );
    assert_eq!(
        lockfile_list.packages["node_modules/bundled-dep"].in_bundle,
        Some(true)
    );
    assert_eq!(
        lockfile_list.packages["node_modules/regular-dep"].in_bundle,
        None
    );

    // Part B: BundledDependencies::Boolean(true) bundles all dependencies
    let mut manifest_bool = Manifest {
        name: Some("bundle-bool-app".into()),
        version: Some("1.0.0".into()),
        bundled_dependencies: Some(BundledDependencies::Boolean(true)),
        ..Default::default()
    };
    manifest_bool
        .dependencies
        .insert("bundled-dep".into(), "1.0.0".into());
    manifest_bool
        .dependencies
        .insert("regular-dep".into(), "1.0.0".into());

    let graph_bool = resolve_dependency_graph(&manifest_bool, &provider, &ResolverOptions::default())
        .expect("Bundle bool resolution");

    assert!(graph_bool.nodes["node_modules/bundled-dep"].flags.bundled);
    assert!(graph_bool.nodes["node_modules/regular-dep"].flags.bundled);

    let lockfile_bool = graph_bool.to_lockfile_v3("bundle-bool-app", Some("1.0.0"));
    assert_eq!(
        lockfile_bool.packages["node_modules/bundled-dep"].in_bundle,
        Some(true)
    );
    assert_eq!(
        lockfile_bool.packages["node_modules/regular-dep"].in_bundle,
        Some(true)
    );
}

// ============================================================================
// 4. NPM ALIAS RESOLUTION, COEXISTENCE, LOCKFILE REUSE & PREFER_DEDUPE
// ============================================================================

#[test]
fn test_npm_alias_dependency_spec_parsing() {
    // Standard package alias
    let spec = DependencySpec::parse("my-chalk", "npm:chalk@^5.0.0").unwrap();
    assert_eq!(spec.install_name, "my-chalk");
    assert_eq!(spec.package_name, "chalk");
    assert!(spec.is_alias);

    // Scoped package alias
    let spec_scoped = DependencySpec::parse("custom-types", "npm:@types/node@^20.0.0").unwrap();
    assert_eq!(spec_scoped.install_name, "custom-types");
    assert_eq!(spec_scoped.package_name, "@types/node");
    assert!(spec_scoped.is_alias);

    // Bare package alias (no explicit target defaults to *)
    let spec_bare = DependencySpec::parse("my-lodash", "npm:lodash").unwrap();
    assert_eq!(spec_bare.install_name, "my-lodash");
    assert_eq!(spec_bare.package_name, "lodash");
    assert!(spec_bare.is_alias);

    // Non-alias regular dependency
    let spec_normal = DependencySpec::parse("express", "^4.18.2").unwrap();
    assert_eq!(spec_normal.install_name, "express");
    assert_eq!(spec_normal.package_name, "express");
    assert!(!spec_normal.is_alias);
}

#[test]
fn test_npm_alias_graph_resolution_multiple_versions_and_coexistence() {
    let mut provider = InMemoryPackageProvider::new();

    // Three different versions of shared-engine in registry
    provider.add_version("shared-engine", "1.0.0", |_| {});
    provider.add_version("shared-engine", "2.0.0", |_| {});
    provider.add_version("shared-engine", "3.0.0", |_| {});

    let mut manifest = Manifest {
        name: Some("alias-multi-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    // Alias engine-v1 to shared-engine@1.0.0, engine-v2 to shared-engine@2.0.0,
    // and also include unaliased shared-engine@^3.0.0
    manifest
        .dependencies
        .insert("engine-v1".into(), "npm:shared-engine@1.0.0".into());
    manifest
        .dependencies
        .insert("engine-v2".into(), "npm:shared-engine@2.0.0".into());
    manifest
        .dependencies
        .insert("shared-engine".into(), "^3.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Alias resolution with multiple versions and unaliased coexistence");

    let node_v1 = &graph.nodes["node_modules/engine-v1"];
    let node_v2 = &graph.nodes["node_modules/engine-v2"];
    let node_unaliased = &graph.nodes["node_modules/shared-engine"];

    assert_eq!(node_v1.install_name, "engine-v1");
    assert_eq!(node_v1.name, "shared-engine");
    assert_eq!(node_v1.version, "1.0.0");

    assert_eq!(node_v2.install_name, "engine-v2");
    assert_eq!(node_v2.name, "shared-engine");
    assert_eq!(node_v2.version, "2.0.0");

    assert_eq!(node_unaliased.install_name, "shared-engine");
    assert_eq!(node_unaliased.name, "shared-engine");
    assert_eq!(node_unaliased.version, "3.0.0");

    // In lockfile v3 serialization, aliased entries have package name in `name` field,
    // while unaliased entry has None (since folder matches package name)
    let lockfile = graph.to_lockfile_v3("alias-multi-app", Some("1.0.0"));
    assert_eq!(
        lockfile.packages["node_modules/engine-v1"].name.as_deref(),
        Some("shared-engine")
    );
    assert_eq!(
        lockfile.packages["node_modules/engine-v2"].name.as_deref(),
        Some("shared-engine")
    );
    assert_eq!(
        lockfile.packages["node_modules/shared-engine"].name.as_deref(),
        None
    );
}

#[test]
fn test_alias_lockfile_reuse_during_resolution() {
    let mut provider = InMemoryPackageProvider::new();

    // Registry has both 5.1.0 and newer 5.3.0
    provider.add_version("chalk", "5.1.0", |_| {});
    provider.add_version("chalk", "5.3.0", |_| {});

    // Create a lockfile that has node_modules/my-chalk locked to 5.1.0
    let mut lockfile = LockfileV3::new("alias-lock-app", Some("1.0.0".to_string()));
    lockfile.packages.insert(
        "node_modules/my-chalk".into(),
        LockfilePackage {
            name: Some("chalk".into()),
            version: Some("5.1.0".into()),
            resolved: Some("https://registry.npmjs.org/chalk/-/chalk-5.1.0.tgz".into()),
            ..Default::default()
        },
    );

    let mut manifest = Manifest {
        name: Some("alias-lock-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    manifest
        .dependencies
        .insert("my-chalk".into(), "npm:chalk@^5.0.0".into());

    let options = ResolverOptions {
        lockfile: Some(Arc::new(lockfile)),
        ..Default::default()
    };

    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Resolution with alias lockfile reuse");

    // Must reuse locked 5.1.0 instead of pulling newer 5.3.0
    assert_eq!(
        graph.nodes["node_modules/my-chalk"].version, "5.1.0",
        "Aliased dependency must reuse version from lockfile"
    );
}

#[test]
fn test_alias_prefer_dedupe_scope_hierarchy() {
    let mut provider = InMemoryPackageProvider::new();

    for v in ["1.0.0", "1.2.0", "1.9.0", "2.0.0"] {
        provider.add_version("util-tool", v, |_| {});
    }

    // dep-first has my-util as alias to util-tool@1.2.0
    provider.add_version("dep-first", "1.0.0", |v| {
        v.dependencies
            .insert("my-util".into(), "npm:util-tool@1.2.0".into());
    });

    // dep-second has my-util as alias to util-tool@^1.0.0
    provider.add_version("dep-second", "1.0.0", |v| {
        v.dependencies
            .insert("my-util".into(), "npm:util-tool@^1.0.0".into());
    });

    let mut manifest = Manifest::default();
    // Root has my-util as alias to util-tool@2.0.0 occupying root node_modules/my-util
    manifest
        .dependencies
        .insert("my-util".into(), "npm:util-tool@2.0.0".into());
    manifest
        .dependencies
        .insert("dep-first".into(), "1.0.0".into());
    manifest
        .dependencies
        .insert("dep-second".into(), "1.0.0".into());

    // Without prefer_dedupe: dep-second selects latest 1.9.0
    let graph_no_dedupe =
        resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default()).unwrap();
    assert_eq!(
        graph_no_dedupe.nodes["node_modules/dep-second/node_modules/my-util"].version,
        "1.9.0",
        "Without prefer_dedupe, dep-second picks latest 1.9.0"
    );

    // With prefer_dedupe: dep-second reuses already placed 1.2.0 for aliased dependency!
    let options_dedupe = ResolverOptions {
        prefer_dedupe: true,
        ..Default::default()
    };
    let graph_dedupe = resolve_dependency_graph(&manifest, &provider, &options_dedupe).unwrap();
    assert_eq!(
        graph_dedupe.nodes["node_modules/dep-second/node_modules/my-util"].version,
        "1.2.0",
        "Aliased dependency must dedupe to existing compatible version in placed nodes"
    );
}

// ============================================================================
// 5. DEDUPE & HOISTING BOUNDARY CASES
// ============================================================================

#[test]
fn test_prefer_dedupe_reuses_placed_compatible_version() {
    let mut provider = InMemoryPackageProvider::new();

    for v in ["1.0.0", "1.2.0", "1.9.0", "2.0.0"] {
        provider.add_version("util-lib", v, |_| {});
    }

    // dep-first gets placed first and uses 1.2.0
    provider.add_version("dep-first", "1.0.0", |v| {
        v.dependencies.insert("util-lib".into(), "1.2.0".into());
    });

    // dep-second needs ^1.0.0.
    provider.add_version("dep-second", "1.0.0", |v| {
        v.dependencies.insert("util-lib".into(), "^1.0.0".into());
    });

    let mut manifest = Manifest::default();
    // Root demands util-lib@2.0.0, occupying root node_modules/util-lib
    manifest
        .dependencies
        .insert("util-lib".into(), "2.0.0".into());
    manifest
        .dependencies
        .insert("dep-first".into(), "1.0.0".into());
    manifest
        .dependencies
        .insert("dep-second".into(), "1.0.0".into());

    // Part A: prefer_dedupe = false (default).
    // Root has util-lib@2.0.0.
    // dep-first places nested node_modules/dep-first/node_modules/util-lib @ 1.2.0.
    // dep-second selects 1.9.0 (highest matching ^1.0.0) and places nested node_modules/dep-second/node_modules/util-lib @ 1.9.0!
    let options_no_dedupe = ResolverOptions {
        prefer_dedupe: false,
        ..Default::default()
    };
    let graph_no_dedupe =
        resolve_dependency_graph(&manifest, &provider, &options_no_dedupe).unwrap();
    assert_eq!(
        graph_no_dedupe.nodes["node_modules/util-lib"].version,
        "2.0.0"
    );
    assert_eq!(
        graph_no_dedupe.nodes["node_modules/dep-first/node_modules/util-lib"].version,
        "1.2.0"
    );
    assert_eq!(
        graph_no_dedupe.nodes["node_modules/dep-second/node_modules/util-lib"].version,
        "1.9.0",
        "Without prefer_dedupe, dep-second selects latest matching 1.9.0"
    );

    // Part B: prefer_dedupe = true.
    // dep-second reuses already-placed util-lib@1.2.0 rather than fetching 1.9.0!
    let options_dedupe = ResolverOptions {
        prefer_dedupe: true,
        ..Default::default()
    };
    let graph_dedupe = resolve_dependency_graph(&manifest, &provider, &options_dedupe).unwrap();
    assert_eq!(
        graph_dedupe.nodes["node_modules/util-lib"].version,
        "2.0.0"
    );
    assert_eq!(
        graph_dedupe.nodes["node_modules/dep-first/node_modules/util-lib"].version,
        "1.2.0"
    );
    assert_eq!(
        graph_dedupe.nodes["node_modules/dep-second/node_modules/util-lib"].version,
        "1.2.0",
        "With prefer_dedupe, dep-second reuses already-placed 1.2.0 instead of 1.9.0"
    );
}

#[test]
fn test_hoisting_conflict_forces_nested_placement() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("conflict-target", "1.0.0", |_| {});
    provider.add_version("conflict-target", "2.0.0", |_| {});

    // Parent requires conflict-target@2.0.0
    provider.add_version("parent-pkg", "1.0.0", |v| {
        v.dependencies
            .insert("conflict-target".into(), "2.0.0".into());
    });

    let mut manifest = Manifest::default();
    // Root requires conflict-target@1.0.0 (placed at node_modules/conflict-target)
    manifest
        .dependencies
        .insert("conflict-target".into(), "1.0.0".into());
    // Root also requires parent-pkg@1.0.0
    manifest
        .dependencies
        .insert("parent-pkg".into(), "1.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Conflict nesting resolution");

    // Root node_modules must have version 1.0.0
    assert_eq!(
        graph.nodes["node_modules/conflict-target"].version,
        "1.0.0"
    );

    // parent-pkg must have nested conflict-target@2.0.0
    let nested_key = "node_modules/parent-pkg/node_modules/conflict-target";
    assert!(
        graph.nodes.contains_key(nested_key),
        "Nested conflict-target must be placed under parent-pkg/node_modules"
    );
    assert_eq!(graph.nodes[nested_key].version, "2.0.0");
}

// ============================================================================
// 6. DEPRECATED, MISSING & ERROR BOUNDARY CASES
// ============================================================================

#[test]
fn test_deprecated_version_avoidance_in_range_resolution() {
    let mut provider = InMemoryPackageProvider::new();

    // 1.0.0 and 1.1.0 are normal, 1.2.0 is deprecated
    provider.add_version("deprec-pkg", "1.0.0", |_| {});
    provider.add_version("deprec-pkg", "1.1.0", |_| {});
    provider.add_version("deprec-pkg", "1.2.0", |v| {
        v.deprecated = Some("Deprecated: Use 2.0 instead".into());
    });

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("deprec-pkg".into(), "^1.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Range resolution with deprecated version");

    assert_eq!(
        graph.nodes["node_modules/deprec-pkg"].version, "1.1.0",
        "Should pick highest undeprecated version (1.1.0) over higher deprecated version (1.2.0)"
    );
}

#[test]
fn test_deprecated_version_fallback_when_all_matching_deprecated() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("all-deprec", "1.0.0", |v| {
        v.deprecated = Some("v1.0 is deprecated".into());
    });
    provider.add_version("all-deprec", "1.1.0", |v| {
        v.deprecated = Some("v1.1 is also deprecated".into());
    });

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("all-deprec".into(), "^1.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Fallback to deprecated when all match are deprecated");

    assert_eq!(
        graph.nodes["node_modules/all-deprec"].version, "1.1.0",
        "Should fall back to highest matching deprecated version"
    );
}

#[test]
fn test_unresolved_dependency_error_on_missing_version_range() {
    let mut provider = InMemoryPackageProvider::new();
    provider.add_version("finite-lib", "1.0.0", |_| {});
    provider.add_version("finite-lib", "1.1.0", |_| {});

    let mut manifest = Manifest::default();
    // Demanding ^2.0.0 which does not exist
    manifest
        .dependencies
        .insert("finite-lib".into(), "^2.0.0".into());

    let result = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default());
    match result {
        Err(SolverError::UnresolvedDependency { name, spec, message }) => {
            assert_eq!(name, "finite-lib");
            assert_eq!(spec, "^2.0.0");
            assert!(!message.is_empty(), "Error message must not be empty");
        }
        other => panic!("Expected UnresolvedDependency error, got {:?}", other),
    }
}

#[test]
fn test_unresolved_dependency_error_on_nonexistent_package() {
    let provider = InMemoryPackageProvider::new();

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("ghost-pkg-that-does-not-exist".into(), "^1.0.0".into());

    let result = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default());
    match result {
        Err(SolverError::UnresolvedDependency { name, spec, message }) => {
            assert_eq!(name, "ghost-pkg-that-does-not-exist");
            assert_eq!(spec, "^1.0.0");
            assert!(!message.is_empty(), "Error message must not be empty");
        }
        other => panic!("Expected UnresolvedDependency error, got {:?}", other),
    }
}
