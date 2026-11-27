use rnpm_core::integrity::Integrity;
use rnpm_core::manifest::Manifest;
use rnpm_core::overrides::Overrides;
use rnpm_core::spec::PackageSpec;
use std::time::{Duration, Instant};

fn build_realistic_manifest_json() -> String {
    let mut deps = String::new();
    for i in 0..40 {
        if i > 0 {
            deps.push_str(",\n");
        }
        deps.push_str(&format!("    \"@org/dep-{i:02}\": \"^{}.0.0\"", (i % 5) + 1));
    }
    let mut dev_deps = String::new();
    for i in 0..25 {
        if i > 0 {
            dev_deps.push_str(",\n");
        }
        dev_deps.push_str(&format!("    \"dev-tool-{i:02}\": \"~{}.{}.0\"", (i % 3) + 1, i % 10));
    }
    format!(
        r#"{{
  "name": "@acme/web-app",
  "version": "2.4.1",
  "description": "Realistic package manifest for benchmarking",
  "main": "./dist/index.js",
  "bin": {{
    "acme-cli": "./bin/cli.js",
    "acme-dev": "./bin/dev.js"
  }},
  "files": ["dist", "bin", "README.md"],
  "scripts": {{
    "build": "tsc -p tsconfig.json",
    "test": "vitest run",
    "lint": "eslint src/",
    "format": "prettier --check ."
  }},
  "dependencies": {{
{deps}
  }},
  "devDependencies": {{
{dev_deps}
  }},
  "peerDependencies": {{
    "react": "^18.0.0",
    "typescript": ">=5.0.0"
  }},
  "peerDependenciesMeta": {{
    "typescript": {{ "optional": true }}
  }},
  "optionalDependencies": {{
    "fsevents": "~2.3.3"
  }},
  "engines": {{
    "node": ">=18.18.0",
    "npm": ">=10.0.0"
  }},
  "os": ["linux", "darwin", "win32"],
  "cpu": ["x64", "arm64"],
  "keywords": ["cli", "monorepo", "tooling"],
  "license": "MIT",
  "repository": {{
    "type": "git",
    "url": "https://github.com/acme/web-app.git"
  }},
  "funding": "https://github.com/sponsors/acme",
  "overrides": {{
    "@org/dep-01": "1.2.3",
    "@org/dep-02@^3.0.0": "3.1.0",
    "@org/dep-03 > @org/dep-04": "2.0.0",
    "@org/dep-05": "$@org/dep-05"
  }}
}}
"#
    )
}

fn median_duration(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
fn bench_core_manifest_overrides_spec_integrity() {
    let raw = build_realistic_manifest_json();
    let iters = if cfg!(debug_assertions) { 50 } else { 500 };

    // Warmup & correctness check
    let parsed_full = Manifest::from_str(&raw).unwrap();
    let parsed_ro = Manifest::from_str_readonly(&raw).unwrap();
    assert_eq!(parsed_full.dependencies, parsed_ro.dependencies);
    let roundtrip = parsed_full.to_json_string().unwrap();
    assert_eq!(
        Manifest::from_str_readonly(&roundtrip).unwrap().dependencies,
        parsed_full.dependencies
    );

    println!("=== RNPM-CORE BENCHMARK RESULTS (median per batch of {iters}) ===");

    let mut s_from_str = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for _ in 0..iters {
            let m = Manifest::from_str(&raw).unwrap();
            std::hint::black_box(m.dependencies.len());
        }
        s_from_str.push(t0.elapsed());
    }
    println!(
        "Manifest::from_str          : {:>8.3} ms",
        median_duration(s_from_str).as_secs_f64() * 1000.0
    );

    let mut s_from_str_ro = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for _ in 0..iters {
            let m = Manifest::from_str_readonly(&raw).unwrap();
            std::hint::black_box(m.dependencies.len());
        }
        s_from_str_ro.push(t0.elapsed());
    }
    println!(
        "Manifest::from_str_readonly : {:>8.3} ms",
        median_duration(s_from_str_ro).as_secs_f64() * 1000.0
    );

    let mut s_to_json = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for _ in 0..iters {
            let s = parsed_full.to_json_string().unwrap();
            std::hint::black_box(s.len());
        }
        s_to_json.push(t0.elapsed());
    }
    println!(
        "Manifest::to_json_string    : {:>8.3} ms",
        median_duration(s_to_json).as_secs_f64() * 1000.0
    );

    let ov = Overrides::from_manifest(&parsed_ro).unwrap();
    let ov_iters = iters * 40;
    let ancestors = ["@org/dep-00".to_string(), "@org/dep-03".to_string()];
    let mut s_overrides = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for i in 0..ov_iters {
            let name = match i % 5 {
                0 => "@org/dep-01",
                1 => "@org/dep-02",
                2 => "@org/dep-04",
                3 => "@org/dep-10",
                _ => "transitive-miss",
            };
            let r = ov
                .resolve_override_precompiled_with_caller(name, "^3.0.0", &ancestors, None)
                .unwrap();
            std::hint::black_box(r);
        }
        s_overrides.push(t0.elapsed());
    }
    println!(
        "Overrides::resolve (x40)    : {:>8.3} ms",
        median_duration(s_overrides).as_secs_f64() * 1000.0
    );

    let specs = [
        "express@^4.18.2",
        "@types/node@>=18.0.0",
        "lodash@4.17.21",
        "typescript@latest",
        "alias@npm:real-pkg@~1.2.3",
    ];
    let spec_iters = iters * 20;
    let mut s_spec = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for _ in 0..spec_iters {
            for sp in &specs {
                let p = PackageSpec::parse(sp).unwrap();
                std::hint::black_box(p.name);
            }
            let d = PackageSpec::parse_dependency("react", "^18.2.0").unwrap();
            std::hint::black_box(d.name);
        }
        s_spec.push(t0.elapsed());
    }
    println!(
        "PackageSpec::parse (x20)    : {:>8.3} ms",
        median_duration(s_spec).as_secs_f64() * 1000.0
    );

    let sri = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let mut s_int = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for _ in 0..spec_iters {
            let parsed = Integrity::parse(sri).unwrap();
            std::hint::black_box(parsed.entries.len());
        }
        s_int.push(t0.elapsed());
    }
    println!(
        "Integrity::parse (x20)      : {:>8.3} ms",
        median_duration(s_int).as_secs_f64() * 1000.0
    );
}
