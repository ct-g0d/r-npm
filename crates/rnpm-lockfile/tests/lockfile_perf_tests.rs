use rnpm_core::manifest::Manifest;
use rnpm_lockfile::{parse_and_migrate_readonly, LockfileV3};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn build_large_v3_lockfile(count: usize) -> (LockfileV3, Manifest) {
    let mut lockfile = LockfileV3::new("bench-app", Some("1.0.0".to_string()));
    let mut root_deps = BTreeMap::new();
    for i in 0..count.min(40) {
        root_deps.insert(format!("pkg-{i:04}"), "^1.0.0".to_string());
    }
    if let Some(root) = lockfile.root_package_mut() {
        root.dependencies = Some(root_deps.clone());
    }

    for i in 0..count {
        let name = format!("pkg-{i:04}");
        let loc = if i >= 40 && i % 5 == 0 {
            format!("node_modules/pkg-{:04}/node_modules/{name}", i - 1)
        } else {
            format!("node_modules/{name}")
        };
        let mut deps = BTreeMap::new();
        if i + 1 < count {
            deps.insert(format!("pkg-{:04}", i + 1), "^1.0.0".to_string());
        }
        if i + 3 < count && i % 2 == 0 {
            deps.insert(format!("pkg-{:04}", i + 3), ">=1.0.0 <2.0.0".to_string());
        }
        lockfile.packages.insert(
            loc,
            rnpm_lockfile::LockfilePackage {
                version: Some(format!("1.{}.{}", i % 10, i % 5)),
                resolved: Some(format!(
                    "https://registry.npmjs.org/{name}/-/{name}-1.{}.{}.tgz",
                    i % 10,
                    i % 5
                )),
                integrity: Some(
                    "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                        .to_string(),
                ),
                dev: if i % 7 == 0 { Some(true) } else { None },
                has_install_script: if i % 11 == 0 { Some(true) } else { None },
                dependencies: if deps.is_empty() { None } else { Some(deps) },
                license: Some("MIT".to_string()),
                ..Default::default()
            },
        );
    }

    let manifest = Manifest {
        name: Some("bench-app".to_string()),
        version: Some("1.0.0".to_string()),
        dependencies: root_deps,
        ..Default::default()
    };

    (lockfile, manifest)
}

fn median_duration(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
fn bench_lockfile_parse_write_migrate_drift() {
    let pkg_count = if cfg!(debug_assertions) { 200 } else { 1500 };
    let rounds = if cfg!(debug_assertions) { 5 } else { 15 };
    let (lf, manifest) = build_large_v3_lockfile(pkg_count);
    let v3_json = lf.to_json_string().unwrap();
    let v2_json = lf.to_json_string_version(2).unwrap();

    // Correctness sanity check
    let parsed_full = LockfileV3::from_json_str(&v3_json).unwrap();
    let parsed_ro = LockfileV3::from_json_str_readonly(&v3_json).unwrap();
    assert_eq!(parsed_full.packages.len(), parsed_ro.packages.len());
    assert!(parsed_ro.matches_manifest(&manifest, true));

    println!("=== RNPM-LOCKFILE BENCHMARK RESULTS (pkgs={pkg_count}, median) ===");

    let mut s_parse_full = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let parsed = LockfileV3::from_json_str(&v3_json).unwrap();
        s_parse_full.push(t0.elapsed());
        std::hint::black_box(parsed.packages.len());
    }
    println!(
        "from_json_str             : {:>8.3} ms",
        median_duration(s_parse_full).as_secs_f64() * 1000.0
    );

    let mut s_parse_ro = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let parsed = LockfileV3::from_json_str_readonly(&v3_json).unwrap();
        s_parse_ro.push(t0.elapsed());
        std::hint::black_box(parsed.packages.len());
    }
    println!(
        "from_json_str_readonly    : {:>8.3} ms",
        median_duration(s_parse_ro).as_secs_f64() * 1000.0
    );

    let mut s_write_pretty = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let out = parsed_ro.to_json_string().unwrap();
        s_write_pretty.push(t0.elapsed());
        std::hint::black_box(out.len());
    }
    println!(
        "to_json_string (pretty)   : {:>8.3} ms",
        median_duration(s_write_pretty).as_secs_f64() * 1000.0
    );

    let mut s_write_raw = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let out = parsed_full.to_json_string().unwrap();
        s_write_raw.push(t0.elapsed());
        std::hint::black_box(out.len());
    }
    println!(
        "to_json_string (raw_val)  : {:>8.3} ms",
        median_duration(s_write_raw).as_secs_f64() * 1000.0
    );

    let mut s_write_compact = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let out = parsed_ro.to_json_string_compact().unwrap();
        s_write_compact.push(t0.elapsed());
        std::hint::black_box(out.len());
    }
    println!(
        "to_json_string_compact    : {:>8.3} ms",
        median_duration(s_write_compact).as_secs_f64() * 1000.0
    );

    let mut s_migrate_v2 = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let m = parse_and_migrate_readonly(&v2_json).unwrap();
        s_migrate_v2.push(t0.elapsed());
        std::hint::black_box(m.packages.len());
    }
    println!(
        "parse_and_migrate_ro (v2) : {:>8.3} ms",
        median_duration(s_migrate_v2).as_secs_f64() * 1000.0
    );

    let mut s_matches = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        let ok = parsed_ro.matches_manifest(&manifest, true);
        s_matches.push(t0.elapsed());
        std::hint::black_box(ok);
    }
    println!(
        "matches_manifest          : {:>8.3} ms",
        median_duration(s_matches).as_secs_f64() * 1000.0
    );
}
