//! Release-mode performance benchmark suite for `rnpm-solver` covering:
//! - Small resolution (fixed per-solve overhead, diamonds, peers, aliases)
//! - Medium resolution (~120 packages, multi-version diamonds, overrides, optional platform deps)
//! - Large resolution (~600 packages, hoisting contention, deep chains, 60-version packuments, peers)
//! - Monorepo workspace resolution (60 workspace members + multi-tier DAG + 300 external deps)
//! - Lockfile fast-path + graph conversion (from_lockfile_v3, resolve_fast_path, to_lockfile_v3)

use rnpm_core::manifest::Manifest;
use rnpm_core::workspace::WorkspaceMember;
use rnpm_core::PlatformList;
use rnpm_solver::{
    resolve_dependency_graph, resolve_fast_path, resolve_workspace_graph, DependencyGraph,
    InMemoryPackageProvider, Platform, ResolverOptions,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn build_small_workload() -> (Manifest, InMemoryPackageProvider) {
    let mut provider = InMemoryPackageProvider::new();
    for ver in ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"] {
        provider.add_version("shared-util", ver, |_| {});
        provider.add_version("logger", ver, |v| {
            v.dependencies.insert("shared-util".into(), "^1.0.0".into());
        });
    }
    provider.add_version("core", "1.4.0", |v| {
        v.dependencies.insert("shared-util".into(), "^1.0.0".into());
        v.dependencies.insert("logger".into(), "^1.0.0".into());
    });
    provider.add_version("plugin-a", "2.0.0", |v| {
        v.peer_dependencies.insert("core".into(), "^1.0.0".into());
        v.dependencies.insert("shared-util".into(), "^2.0.0".into());
    });
    provider.add_version("plugin-b", "1.0.0", |v| {
        v.peer_dependencies.insert("core".into(), "^1.0.0".into());
        v.dependencies
            .insert("util-alias".into(), "npm:shared-util@^1.1.0".into());
    });
    for i in 0..10 {
        let name = format!("leaf-{i}");
        provider.add_version(&name, "1.0.0", |v| {
            v.dependencies.insert("shared-util".into(), "^1.0.0".into());
        });
    }

    let mut manifest = Manifest {
        name: Some("small-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    manifest.dependencies.insert("core".into(), "^1.0.0".into());
    manifest
        .dependencies
        .insert("plugin-a".into(), "^2.0.0".into());
    manifest
        .dependencies
        .insert("plugin-b".into(), "^1.0.0".into());
    for i in 0..10 {
        manifest
            .dependencies
            .insert(format!("leaf-{i}"), "^1.0.0".into());
    }
    (manifest, provider)
}

fn add_many_versions(
    provider: &mut InMemoryPackageProvider,
    name: &str,
    majors: &[u64],
    minors_per_major: u64,
    patches_per_minor: u64,
    configure: impl Fn(&mut rnpm_solver::PackageVersionMetadata, u64, u64, u64),
) {
    for &maj in majors {
        for min in 0..minors_per_major {
            for pat in 0..patches_per_minor {
                let ver = format!("{maj}.{min}.{pat}");
                provider.add_version(name, &ver, |v| {
                    configure(v, maj, min, pat);
                });
            }
        }
    }
}

fn build_medium_workload() -> (Manifest, InMemoryPackageProvider) {
    let mut provider = InMemoryPackageProvider::new();

    // Shared ecosystem packages with realistic version history (36 versions each)
    for hot in [
        "ms",
        "debug",
        "supports-color",
        "chalk",
        "semver",
        "lru-cache",
        "tslib",
        "@types/node",
    ] {
        add_many_versions(&mut provider, hot, &[1, 2, 3], 4, 3, |v, maj, _min, _pat| {
            if hot == "debug" {
                v.dependencies
                    .insert("ms".into(), format!("^{maj}.0.0"));
            } else if hot == "chalk" {
                v.dependencies
                    .insert("supports-color".into(), format!("^{maj}.0.0"));
            }
        });
    }

    // 100 mid-tier & leaf packages forming diamonds, nested conflicts, peers, and optional platform skips
    for i in 0..100 {
        let pkg = format!("med-pkg-{i:03}");
        for maj in [1u64, 2u64] {
            for pat in 0..5u64 {
                let ver = format!("{maj}.0.{pat}");
                provider.add_version(&pkg, &ver, |v| {
                    if i + 1 < 100 {
                        v.dependencies
                            .insert(format!("med-pkg-{:03}", i + 1), "^1.0.0".into());
                    }
                    if i + 7 < 100 {
                        v.dependencies
                            .insert(format!("med-pkg-{:03}", i + 7), format!("^{maj}.0.0"));
                    }
                    if i % 3 == 0 {
                        v.dependencies.insert(
                            "debug".into(),
                            if i % 6 == 0 { "^2.0.0" } else { "^3.0.0" }.into(),
                        );
                    }
                    if i % 4 == 0 {
                        v.dependencies.insert("chalk".into(), "^2.0.0".into());
                    }
                    if i % 5 == 0 {
                        v.dependencies.insert("semver".into(), "^1.0.0".into());
                    }
                    if i % 11 == 0 {
                        v.peer_dependencies.insert("@types/node".into(), "^2.0.0".into());
                    }
                    if i % 17 == 0 {
                        v.optional_dependencies
                            .insert("opt-native-linux".into(), "1.0.0".into());
                    }
                });
            }
        }
    }

    provider.add_version("opt-native-linux", "1.0.0", |v| {
        v.os = Some(PlatformList::from(vec!["linux".into()]));
        v.cpu = Some(PlatformList::from(vec!["x64".into()]));
    });

    let mut manifest = Manifest {
        name: Some("medium-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    manifest
        .dependencies
        .insert("@types/node".into(), "^2.0.0".into());
    manifest.dependencies.insert("debug".into(), "^3.0.0".into());
    for root_idx in (0..100).step_by(10) {
        manifest
            .dependencies
            .insert(format!("med-pkg-{root_idx:03}"), "^1.0.0".into());
    }
    manifest
        .dev_dependencies
        .insert("med-pkg-005".into(), "^2.0.0".into());
    manifest.extra.insert(
        "overrides".into(),
        serde_json::json!({
            "lru-cache": "3.3.2",
            "med-pkg-020 > debug": "^2.0.0"
        }),
    );

    (manifest, provider)
}

fn build_large_workload() -> (Manifest, InMemoryPackageProvider) {
    let mut provider = InMemoryPackageProvider::new();

    // 12 ultra-hot shared packages with 60 versions each (matching real npm packuments)
    let hot_pkgs = [
        "lodash",
        "debug",
        "ms",
        "semver",
        "chalk",
        "supports-color",
        "ansi-styles",
        "minimatch",
        "glob",
        "brace-expansion",
        "picomatch",
        "tslib",
    ];
    for (idx, &hot) in hot_pkgs.iter().enumerate() {
        add_many_versions(&mut provider, hot, &[1, 2, 3, 4], 5, 3, |v, maj, _min, _pat| {
            if idx > 0 && idx < 6 {
                let prev = hot_pkgs[idx - 1];
                v.dependencies.insert(prev.into(), format!("^{maj}.0.0"));
            }
        });
    }

    // 550 packages in multi-level overlapping DAG with version conflicts forcing intermediate hoisting & nesting
    const TOTAL: usize = 550;
    for i in 0..TOTAL {
        let pkg = format!("lg-pkg-{i:04}");
        for maj in [1u64, 2u64] {
            for pat in 0..4u64 {
                let ver = format!("{maj}.0.{pat}");
                provider.add_version(&pkg, &ver, |v| {
                    if i + 1 < TOTAL && (i % 15 != 14) {
                        v.dependencies
                            .insert(format!("lg-pkg-{:04}", i + 1), format!("^{maj}.0.0"));
                    }
                    if i + 3 < TOTAL && i % 2 == 0 {
                        let req_maj = if i % 8 == 0 { 2 } else { 1 };
                        v.dependencies
                            .insert(format!("lg-pkg-{:04}", i + 3), format!("^{req_maj}.0.0"));
                    }
                    if i + 13 < TOTAL && i % 5 == 0 {
                        v.dependencies
                            .insert(format!("lg-pkg-{:04}", i + 13), "^1.0.0".into());
                    }
                    // Heavy fan-in to hot shared packages with conflicting major ranges
                    let hot_a = hot_pkgs[i % hot_pkgs.len()];
                    let hot_b = hot_pkgs[(i + 5) % hot_pkgs.len()];
                    let range_a = match i % 4 {
                        0 => "^1.0.0",
                        1 => "^2.0.0",
                        2 => "^3.0.0",
                        _ => "^4.0.0",
                    };
                    v.dependencies.insert(hot_a.into(), range_a.into());
                    v.dependencies.insert(hot_b.into(), "^2.0.0".into());

                    if i % 12 == 0 && i + 2 < TOTAL {
                        v.peer_dependencies
                            .insert(format!("lg-pkg-{:04}", i + 2), "^1.0.0".into());
                    }
                    if i % 23 == 0 {
                        v.peer_dependencies
                            .insert("lodash".into(), "^4.0.0".into());
                        v.peer_dependencies_meta.insert(
                            "lodash".into(),
                            rnpm_core::manifest::PeerDependencyMeta { optional: true },
                        );
                    }
                });
            }
        }
    }

    let mut manifest = Manifest {
        name: Some("large-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    manifest.dependencies.insert("lodash".into(), "^4.0.0".into());
    manifest.dependencies.insert("debug".into(), "^4.0.0".into());
    for root_idx in (0..TOTAL).step_by(20) {
        manifest
            .dependencies
            .insert(format!("lg-pkg-{root_idx:04}"), "^1.0.0".into());
    }
    for dev_idx in (10..TOTAL).step_by(35) {
        manifest
            .dev_dependencies
            .insert(format!("lg-pkg-{dev_idx:04}"), "^2.0.0".into());
    }

    (manifest, provider)
}

fn build_monorepo_workload() -> (Manifest, Vec<WorkspaceMember>, InMemoryPackageProvider) {
    let mut provider = InMemoryPackageProvider::new();

    // External packages used across workspaces with version contention
    for ext in [
        "react",
        "react-dom",
        "typescript",
        "zod",
        "lodash",
        "debug",
        "ms",
        "chalk",
        "picomatch",
        "semver",
    ] {
        add_many_versions(&mut provider, ext, &[1, 2, 3, 4], 4, 3, |v, maj, _min, _pat| {
            if ext == "react-dom" {
                v.peer_dependencies.insert("react".into(), format!("^{maj}.0.0"));
            }
            if ext == "debug" {
                v.dependencies.insert("ms".into(), format!("^{maj}.0.0"));
            }
        });
    }

    // 180 transitive external packages
    for i in 0..180 {
        let pkg = format!("ws-ext-{i:03}");
        for maj in [1u64, 2u64] {
            for pat in 0..3u64 {
                let ver = format!("{maj}.0.{pat}");
                provider.add_version(&pkg, &ver, |v| {
                    if i + 1 < 180 && i % 6 != 5 {
                        v.dependencies
                            .insert(format!("ws-ext-{:03}", i + 1), format!("^{maj}.0.0"));
                    }
                    if i % 3 == 0 {
                        v.dependencies.insert("debug".into(), "^3.0.0".into());
                    }
                    if i % 4 == 0 {
                        v.dependencies.insert("lodash".into(), "^4.0.0".into());
                    }
                });
            }
        }
    }

    // 60 workspace members in a 4-tier DAG with dev cycles and external dependencies
    let mut members = Vec::with_capacity(60);
    for i in 0..60 {
        let name = format!("@mono/pkg-{i:02}");
        let mut m = Manifest {
            name: Some(name.clone()),
            version: Some("1.0.0".into()),
            ..Default::default()
        };
        // Inter-workspace DAG dependencies (higher index depends on lower index)
        if i >= 10 {
            m.dependencies
                .insert(format!("@mono/pkg-{:02}", i % 10), "workspace:*".into());
        }
        if i >= 25 {
            m.dependencies.insert(
                format!("@mono/pkg-{:02}", 10 + (i % 15)),
                "workspace:^1.0.0".into(),
            );
        }
        // Circular devDependency back-edges
        if i < 10 && i + 25 < 60 {
            m.dev_dependencies.insert(
                format!("@mono/pkg-{:02}", i + 25),
                "workspace:*".into(),
            );
        }
        // Cross-workspace peer dependency
        if i >= 15 {
            m.peer_dependencies
                .insert("@mono/pkg-00".into(), "^1.0.0".into());
        }
        // External dependencies per workspace member
        let ext_base = (i * 3) % 180;
        m.dependencies
            .insert(format!("ws-ext-{ext_base:03}"), "^1.0.0".into());
        m.dependencies
            .insert(format!("ws-ext-{:03}", (ext_base + 1) % 180), "^2.0.0".into());
        m.dependencies.insert("zod".into(), "^3.0.0".into());
        m.dependencies.insert(
            "semver".into(),
            if i % 5 == 0 { "^2.0.0" } else { "^4.0.0" }.into(),
        );
        m.dev_dependencies
            .insert("typescript".into(), "^4.0.0".into());

        members.push(WorkspaceMember {
            name,
            version: Some("1.0.0".into()),
            path: PathBuf::from(format!("packages/pkg-{i:02}")),
            relative_path: format!("packages/pkg-{i:02}"),
            manifest: m,
        });
    }

    let mut root_manifest = Manifest {
        name: Some("monorepo-root".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    root_manifest
        .dependencies
        .insert("react".into(), "^4.0.0".into());
    root_manifest
        .dependencies
        .insert("react-dom".into(), "^4.0.0".into());
    root_manifest
        .dependencies
        .insert("semver".into(), "^4.0.0".into());
    root_manifest
        .dev_dependencies
        .insert("typescript".into(), "^4.0.0".into());

    (root_manifest, members, provider)
}

fn median_duration(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
fn bench_solver_workloads() {
    let options = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };

    println!("=== RNPM-SOLVER BENCHMARK RESULTS (median) ===");

    // 1. Small workload
    let (small_m, small_p) = build_small_workload();
    // Warmup
    let small_graph = resolve_dependency_graph(&small_m, &small_p, &options).unwrap();
    assert!(small_graph.nodes.len() >= 14);
    let mut small_samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let t0 = Instant::now();
        let g = resolve_dependency_graph(&small_m, &small_p, &options).unwrap();
        small_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let small_med = median_duration(small_samples);
    println!(
        "small      (nodes={:4}, edges={:4}): {:>8.3} ms",
        small_graph.nodes.len(),
        small_graph.edges.len(),
        small_med.as_secs_f64() * 1000.0
    );

    // 2. Medium workload
    let (med_m, med_p) = build_medium_workload();
    let med_graph = resolve_dependency_graph(&med_m, &med_p, &options).unwrap();
    assert!(med_graph.nodes.len() >= 100);
    let mut med_samples = Vec::with_capacity(25);
    for _ in 0..25 {
        let t0 = Instant::now();
        let g = resolve_dependency_graph(&med_m, &med_p, &options).unwrap();
        med_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let med_med = median_duration(med_samples);
    println!(
        "medium     (nodes={:4}, edges={:4}): {:>8.3} ms",
        med_graph.nodes.len(),
        med_graph.edges.len(),
        med_med.as_secs_f64() * 1000.0
    );

    // 3. Large workload
    let (lg_m, lg_p) = build_large_workload();
    let lg_graph = resolve_dependency_graph(&lg_m, &lg_p, &options).unwrap();
    assert!(lg_graph.nodes.len() >= 550);
    let mut lg_samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let t0 = Instant::now();
        let g = resolve_dependency_graph(&lg_m, &lg_p, &options).unwrap();
        lg_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let lg_med = median_duration(lg_samples);
    println!(
        "large      (nodes={:4}, edges={:4}): {:>8.3} ms",
        lg_graph.nodes.len(),
        lg_graph.edges.len(),
        lg_med.as_secs_f64() * 1000.0
    );

    // 4. Monorepo workload
    let (mono_m, mono_members, mono_p) = build_monorepo_workload();
    let mono_graph = resolve_workspace_graph(&mono_m, &mono_members, &mono_p, &options).unwrap();
    assert!(mono_graph.nodes.len() >= 250);
    let mut mono_samples = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        let g = resolve_workspace_graph(&mono_m, &mono_members, &mono_p, &options).unwrap();
        mono_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let mono_med = median_duration(mono_samples);
    println!(
        "monorepo   (nodes={:4}, edges={:4}): {:>8.3} ms",
        mono_graph.nodes.len(),
        mono_graph.edges.len(),
        mono_med.as_secs_f64() * 1000.0
    );

    // 5. Lockfile fast-path + conversion workload (on medium & large graphs)
    let lg_lockfile = lg_graph.to_lockfile_v3("large-app", Some("1.0.0"));
    let mut to_lf_samples = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        let lf = lg_graph.to_lockfile_v3("large-app", Some("1.0.0"));
        to_lf_samples.push(t0.elapsed());
        std::hint::black_box(lf.packages.len());
    }
    let to_lf_med = median_duration(to_lf_samples);
    println!(
        "to_lockfile_v3   (pkgs={:4}):       {:>8.3} ms",
        lg_lockfile.packages.len(),
        to_lf_med.as_secs_f64() * 1000.0
    );

    let mut from_lf_samples = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        let g = DependencyGraph::from_lockfile_v3(&lg_lockfile);
        from_lf_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let from_lf_med = median_duration(from_lf_samples);
    println!(
        "from_lockfile_v3 (pkgs={:4}):       {:>8.3} ms",
        lg_lockfile.packages.len(),
        from_lf_med.as_secs_f64() * 1000.0
    );

    // Build a clean lockfile without conflicting overrides/optional-peer overrides for fast_path
    let mut fp_provider = InMemoryPackageProvider::new();
    for i in 0..500usize {
        let pkg = format!("fp-pkg-{i:04}");
        fp_provider.add_version(&pkg, "1.2.3", |v| {
            if i + 1 < 500 && i % 10 != 9 {
                v.dependencies
                    .insert(format!("fp-pkg-{:04}", i + 1), "^1.0.0".into());
            }
            if i + 3 < 500 && i % 4 == 0 {
                v.dependencies
                    .insert(format!("fp-pkg-{:04}", i + 3), "^1.0.0".into());
            }
        });
    }
    let mut fp_manifest = Manifest {
        name: Some("fp-app".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    for i in (0..500).step_by(10) {
        fp_manifest
            .dependencies
            .insert(format!("fp-pkg-{i:04}"), "^1.0.0".into());
    }
    let fp_graph = resolve_dependency_graph(&fp_manifest, &fp_provider, &options).unwrap();
    let fp_lockfile = fp_graph.to_lockfile_v3("fp-app", Some("1.0.0"));

    let mut fast_path_samples = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        let g = resolve_fast_path(&fp_manifest, &fp_lockfile, &options).unwrap();
        fast_path_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let fast_path_med = median_duration(fast_path_samples);
    println!(
        "resolve_fast_path(pkgs={:4}):       {:>8.3} ms",
        fp_lockfile.packages.len(),
        fast_path_med.as_secs_f64() * 1000.0
    );

    let mut norm_flags_samples = Vec::with_capacity(15);
    for _ in 0..15 {
        let mut g = lg_graph.clone();
        let t0 = Instant::now();
        g.normalize_dependency_flags();
        norm_flags_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let norm_flags_med = median_duration(norm_flags_samples);
    println!(
        "normalize_flags  (nodes={:4}):      {:>8.3} ms",
        lg_graph.nodes.len(),
        norm_flags_med.as_secs_f64() * 1000.0
    );
}

#[test]
fn bench_solver_overrides_and_prefer_dedupe() {
    let (mut med_m, med_p) = build_medium_workload();
    med_m.extra.insert(
        "overrides".to_string(),
        serde_json::json!({
            "ms": "^2.0.0",
            "chalk > supports-color": "^2.0.0",
            "med-pkg-001": "$med-pkg-001"
        }),
    );

    let options_ov = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        ..Default::default()
    };
    let ov_warmup = resolve_dependency_graph(&med_m, &med_p, &options_ov).unwrap();
    let rounds = if cfg!(debug_assertions) { 3 } else { 25 };
    let mut ov_samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let g = resolve_dependency_graph(&med_m, &med_p, &options_ov).unwrap();
        ov_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let ov_med = median_duration(ov_samples);

    let (lg_m, lg_p) = build_large_workload();
    let options_dedupe = ResolverOptions {
        platform: Platform::new("win32", "x64"),
        prefer_dedupe: true,
        ..Default::default()
    };
    let dedupe_warmup = resolve_dependency_graph(&lg_m, &lg_p, &options_dedupe).unwrap();
    let dedupe_rounds = if cfg!(debug_assertions) { 1 } else { 7 };
    let mut dedupe_samples = Vec::with_capacity(dedupe_rounds);
    for _ in 0..dedupe_rounds {
        let t0 = Instant::now();
        let g = resolve_dependency_graph(&lg_m, &lg_p, &options_dedupe).unwrap();
        dedupe_samples.push(t0.elapsed());
        std::hint::black_box(g.nodes.len());
    }
    let dedupe_med = median_duration(dedupe_samples);

    println!("=== RNPM-SOLVER OVERRIDES & PREFER_DEDUPE BENCHMARK (median) ===");
    println!(
        "medium+overrides (nodes={:4}, edges={:4}): {:>8.3} ms",
        ov_warmup.nodes.len(),
        ov_warmup.edges.len(),
        ov_med.as_secs_f64() * 1000.0
    );
    println!(
        "large+dedupe     (nodes={:4}, edges={:4}): {:>8.3} ms",
        dedupe_warmup.nodes.len(),
        dedupe_warmup.edges.len(),
        dedupe_med.as_secs_f64() * 1000.0
    );
}
