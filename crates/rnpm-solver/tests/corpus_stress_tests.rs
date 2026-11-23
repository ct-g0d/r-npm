//! Offline regression and stress tests for rnpm-solver covering borderline corpus patterns:
//! - Complex semver backtracking & diamond dependency resolution
//! - Optional dependency platform (OS, CPU, libc) filtering & skip propagation
//! - Bundled dependencies metadata & placement
//! - Npm alias resolution (standard, scoped, bare, and multi-version co-existence)
//! - Deduplication / hoist boundary cases (prefer_dedupe, nested conflict placement)
//! - Deprecated version avoidance and missing/nonexistent package error handling
//!
//! All tests are 100% deterministic, offline, cross-platform, and execute in memory.

use rnpm_core::manifest::{BundledDependencies, Manifest};
use rnpm_core::PlatformList;
use rnpm_solver::{
    is_platform_compatible, resolve_dependency_graph, DependencySpec,
    InMemoryPackageProvider, Platform, ResolverOptions, SolverError,
};

// ============================================================================
// 1. COMPLEX SEMVER BACKTRACKING & DIAMOND DEPENDENCY RESOLUTION
// ============================================================================

#[test]
fn test_complex_semver_backtracking_diamond_dependency() {
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

    // c should be hoisted to root satisfying a's ^1.0.0 with highest 1.3.0
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
        "1.1.0-beta.1",
    ] {
        provider.add_version("tool", ver, |_| {});
    }

    let mut manifest = Manifest::default();
    // Explicitly targeting prerelease beta
    manifest
        .dependencies
        .insert("tool".into(), ">=1.0.0-beta.1 <1.0.0-rc.1".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Prerelease resolution should succeed");

    assert_eq!(
        graph.nodes["node_modules/tool"].version, "1.0.0-beta.2",
        "Should select highest prerelease matching the bound"
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
fn test_optional_dep_platform_os_filtering_current_vs_foreign() {
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

    // Simulate Windows x64 platform
    let options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };

    let graph = resolve_dependency_graph(&manifest, &provider, &options)
        .expect("Graph resolution with optional platform packages");

    let win_node = &graph.nodes["node_modules/opt-win"];
    let darwin_node = &graph.nodes["node_modules/opt-darwin"];
    let linux_node = &graph.nodes["node_modules/opt-linux"];

    assert!(!win_node.flags.skipped, "win32 package should NOT be skipped on win32");
    assert_eq!(win_node.flags.platform_skipped, Some(false));

    assert!(darwin_node.flags.skipped, "darwin package should be skipped on win32");
    assert_eq!(darwin_node.flags.platform_skipped, Some(true));

    assert!(linux_node.flags.skipped, "linux package should be skipped on win32");
    assert_eq!(linux_node.flags.platform_skipped, Some(true));
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

    assert!(!graph.nodes["node_modules/bin-linux-x64-gnu"].flags.skipped);
    assert!(graph.nodes["node_modules/bin-linux-x64-musl"].flags.skipped);
    assert!(graph.nodes["node_modules/bin-linux-arm64-gnu"].flags.skipped);
}

#[test]
fn test_optional_dep_negated_platform_filters() {
    let p_win = Platform::new("win32", "x64");
    let p_mac = Platform::new("darwin", "arm64");
    let p_linux = Platform::new("linux", "x64");

    let not_win = vec!["!win32".into()];
    assert!(!is_platform_compatible(&p_win, Some(&not_win), None, None));
    assert!(is_platform_compatible(&p_mac, Some(&not_win), None, None));
    assert!(is_platform_compatible(&p_linux, Some(&not_win), None, None));

    let not_arm = vec!["!arm64".into()];
    assert!(is_platform_compatible(&p_win, None, Some(&not_arm), None));
    assert!(!is_platform_compatible(&p_mac, None, Some(&not_arm), None));
    assert!(is_platform_compatible(&p_linux, None, Some(&not_arm), None));
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

    // Without --force, required package on wrong platform must return error
    let options_strict = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        force: false,
        ..Default::default()
    };
    let result = resolve_dependency_graph(&manifest, &provider, &options_strict);
    assert!(
        matches!(result, Err(SolverError::PlatformIncompatible { .. })),
        "Required package on incompatible platform must fail with PlatformIncompatible"
    );

    // With --force, installation proceeds
    let options_forced = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        force: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options_forced)
        .expect("Force mode should bypass platform incompatibility");
    assert!(graph.nodes.contains_key("node_modules/darwin-only-required"));
}

// ============================================================================
// 3. BUNDLED DEPENDENCIES
// ============================================================================

#[test]
fn test_bundled_dependencies_node_flagging() {
    let mut provider = InMemoryPackageProvider::new();

    provider.add_version("bundled-dep", "1.0.0", |_| {});
    provider.add_version("regular-dep", "1.0.0", |_| {});

    let mut manifest = Manifest {
        name: Some("bundle-app".into()),
        version: Some("1.0.0".into()),
        bundled_dependencies: Some(BundledDependencies::List(vec!["bundled-dep".into()])),
        ..Default::default()
    };
    manifest
        .dependencies
        .insert("bundled-dep".into(), "1.0.0".into());
    manifest
        .dependencies
        .insert("regular-dep".into(), "1.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Bundle resolution");

    let bundled_node = graph
        .nodes
        .get("node_modules/bundled-dep")
        .expect("bundled-dep must exist in graph");
    assert!(
        bundled_node.flags.bundled,
        "Bundled dependency must have flags.bundled set to true"
    );

    let regular_node = graph
        .nodes
        .get("node_modules/regular-dep")
        .expect("regular-dep must exist in graph");
    assert!(
        !regular_node.flags.bundled,
        "Regular dependency must have flags.bundled set to false"
    );

    let lockfile = graph.to_lockfile_v3("bundle-app", Some("1.0.0"));
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

// ============================================================================
// 4. NPM ALIAS RESOLUTION
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
fn test_npm_alias_graph_resolution_multiple_versions() {
    let mut provider = InMemoryPackageProvider::new();

    // Two different versions of shared-engine in registry
    provider.add_version("shared-engine", "1.0.0", |_| {});
    provider.add_version("shared-engine", "2.0.0", |_| {});

    let mut manifest = Manifest::default();
    // Alias engine-v1 to shared-engine@1.0.0 and engine-v2 to shared-engine@2.0.0
    manifest
        .dependencies
        .insert("engine-v1".into(), "npm:shared-engine@1.0.0".into());
    manifest
        .dependencies
        .insert("engine-v2".into(), "npm:shared-engine@2.0.0".into());

    let graph = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default())
        .expect("Alias resolution with multiple versions");

    let node_v1 = &graph.nodes["node_modules/engine-v1"];
    let node_v2 = &graph.nodes["node_modules/engine-v2"];

    assert_eq!(node_v1.install_name, "engine-v1");
    assert_eq!(node_v1.name, "shared-engine");
    assert_eq!(node_v1.version, "1.0.0");

    assert_eq!(node_v2.install_name, "engine-v2");
    assert_eq!(node_v2.name, "shared-engine");
    assert_eq!(node_v2.version, "2.0.0");
}

// ============================================================================
// 5. DEDUPE & HOISTING BOUNDARY CASES
// ============================================================================

#[test]
fn test_prefer_dedupe_reuses_placed_compatible_version() {
    let mut provider = InMemoryPackageProvider::new();

    for v in ["1.0.0", "1.2.0", "1.9.0"] {
        provider.add_version("util-lib", v, |_| {});
    }

    // dep-first gets placed first and uses 1.2.0
    provider.add_version("dep-first", "1.0.0", |v| {
        v.dependencies.insert("util-lib".into(), "1.2.0".into());
    });

    // dep-second needs ^1.0.0.
    // If prefer_dedupe is true, it reuses 1.2.0 rather than picking 1.9.0
    provider.add_version("dep-second", "1.0.0", |v| {
        v.dependencies.insert("util-lib".into(), "^1.0.0".into());
    });

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("dep-first".into(), "1.0.0".into());
    manifest
        .dependencies
        .insert("dep-second".into(), "1.0.0".into());

    let options_dedupe = ResolverOptions {
        prefer_dedupe: true,
        ..Default::default()
    };
    let graph = resolve_dependency_graph(&manifest, &provider, &options_dedupe).unwrap();

    // util-lib should be placed at root node_modules/util-lib with 1.2.0
    assert_eq!(
        graph.nodes["node_modules/util-lib"].version, "1.2.0",
        "util-lib should be deduped to existing 1.2.0 rather than fetching 1.9.0"
    );
    assert!(
        !graph
            .nodes
            .contains_key("node_modules/dep-second/node_modules/util-lib"),
        "dep-second should reuse hoisted util-lib"
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
    assert!(
        result.is_err(),
        "Missing version range must return an error"
    );
    assert!(matches!(
        result.unwrap_err(),
        SolverError::UnresolvedDependency { .. }
    ));
}

#[test]
fn test_unresolved_dependency_error_on_nonexistent_package() {
    let provider = InMemoryPackageProvider::new();

    let mut manifest = Manifest::default();
    manifest
        .dependencies
        .insert("ghost-pkg-that-does-not-exist".into(), "^1.0.0".into());

    let result = resolve_dependency_graph(&manifest, &provider, &ResolverOptions::default());
    assert!(
        result.is_err(),
        "Nonexistent package must return SolverError::UnresolvedDependency"
    );
    assert!(matches!(
        result.unwrap_err(),
        SolverError::UnresolvedDependency { .. }
    ));
}
