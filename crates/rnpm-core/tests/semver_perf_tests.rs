use rnpm_core::semver::{Comparator, Op, PrereleaseId, Range, Version};

#[test]
fn test_semver_fast_path_version_parse() {
    // Zero-allocation common case: major.minor.patch
    let v1 = Version::parse("1.2.3").unwrap();
    assert_eq!(v1.major, 1);
    assert_eq!(v1.minor, 2);
    assert_eq!(v1.patch, 3);
    assert!(v1.prerelease.is_empty());
    assert!(v1.build.is_empty());

    let v_zero = Version::parse("0.0.0").unwrap();
    assert_eq!(v_zero.major, 0);
    assert_eq!(v_zero.minor, 0);
    assert_eq!(v_zero.patch, 0);

    let v_large = Version::parse("14.21.0").unwrap();
    assert_eq!(v_large.major, 14);
    assert_eq!(v_large.minor, 21);
    assert_eq!(v_large.patch, 0);

    // Loose prefixes on strict parse
    let v_v = Version::parse("v1.2.3").unwrap();
    assert_eq!(v_v, v1);
    let v_cap_v = Version::parse("V1.2.3").unwrap();
    assert_eq!(v_cap_v, v1);
    let v_eq = Version::parse("=1.2.3").unwrap();
    assert_eq!(v_eq, v1);
    let v_eq_v = Version::parse("=v1.2.3").unwrap();
    assert_eq!(v_eq_v, v1);
    let v_spaces = Version::parse("  v1.2.3  ").unwrap();
    assert_eq!(v_spaces, v1);

    // Prerelease and build
    let v_pre = Version::parse("1.2.3-alpha.1").unwrap();
    assert_eq!(v_pre.major, 1);
    assert_eq!(v_pre.minor, 2);
    assert_eq!(v_pre.patch, 3);
    assert_eq!(
        v_pre.prerelease,
        vec![
            PrereleaseId::Alpha("alpha".to_string()),
            PrereleaseId::Numeric(1),
        ]
    );

    let v_build = Version::parse("1.2.3+sha.exp.01").unwrap();
    assert_eq!(v_build.major, 1);
    assert_eq!(v_build.minor, 2);
    assert_eq!(v_build.patch, 3);
    assert_eq!(v_build.build, vec!["sha".to_string(), "exp".to_string(), "01".to_string()]);
}

#[test]
fn test_semver_leading_zero_rejection() {
    assert!(Version::parse("01.2.3").is_err());
    assert!(Version::parse("1.02.3").is_err());
    assert!(Version::parse("1.2.03").is_err());
    assert!(Version::parse("1.2.3-01").is_err());
    assert!(Version::parse("00.0.0").is_err());

    assert!(Range::parse("01.2.3").is_err());
    assert!(Range::parse("^01.2.3").is_err());
    assert!(Range::parse("~01.2.3").is_err());
    assert!(Range::parse(">=01.2.3").is_err());

    // Loose version parse allows leading zeroes on numeric segments
    let v_loose = Version::parse_loose("01.02.03").unwrap();
    assert_eq!(v_loose.major, 1);
    assert_eq!(v_loose.minor, 2);
    assert_eq!(v_loose.patch, 3);
}

#[test]
fn test_semver_prerelease_visibility_rules() {
    // Node-semver rule: prereleases only satisfy if comparator has same major.minor.patch with prerelease
    let r_caret_pre = Range::parse("^1.2.3-alpha.1").unwrap();

    // Same tuple 1.2.3 with higher prerelease: satisfies
    assert!(r_caret_pre.satisfies(&Version::parse("1.2.3-alpha.1").unwrap()));
    assert!(r_caret_pre.satisfies(&Version::parse("1.2.3-alpha.2").unwrap()));
    assert!(r_caret_pre.satisfies(&Version::parse("1.2.3-beta.0").unwrap()));
    assert!(r_caret_pre.satisfies(&Version::parse("1.2.3").unwrap()));

    // Different tuple 1.2.4 with prerelease: DOES NOT SATISFY!
    assert!(!r_caret_pre.satisfies(&Version::parse("1.2.4-alpha.0").unwrap()));
    assert!(!r_caret_pre.satisfies(&Version::parse("1.3.0-alpha.0").unwrap()));

    // Non-prerelease 1.2.4: satisfies
    assert!(r_caret_pre.satisfies(&Version::parse("1.2.4").unwrap()));
    assert!(r_caret_pre.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r_caret_pre.satisfies(&Version::parse("2.0.0").unwrap()));

    // Range without prerelease comparator rejects all prereleases
    let r_no_pre = Range::parse("^1.2.3").unwrap();
    assert!(!r_no_pre.satisfies(&Version::parse("1.2.3-alpha.0").unwrap()));
    assert!(!r_no_pre.satisfies(&Version::parse("1.2.4-alpha.0").unwrap()));
    assert!(r_no_pre.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_no_pre.satisfies(&Version::parse("1.2.4").unwrap()));
}

#[test]
fn test_semver_hyphen_ranges() {
    let r1 = Range::parse("1.0.0 - 2.0.0").unwrap();
    assert!(r1.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(r1.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r1.satisfies(&Version::parse("0.9.9").unwrap()));
    assert!(!r1.satisfies(&Version::parse("2.0.1").unwrap()));

    // Partial right hand side: "1.0.0 - 2" := ">=1.0.0 <3.0.0-0"
    let r2 = Range::parse("1.0.0 - 2").unwrap();
    assert!(r2.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r2.satisfies(&Version::parse("3.0.0").unwrap()));

    // Partial right hand side: "1.0.0 - 2.3" := ">=1.0.0 <2.4.0-0"
    let r3 = Range::parse("1.0.0 - 2.3").unwrap();
    assert!(r3.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r3.satisfies(&Version::parse("2.3.9").unwrap()));
    assert!(!r3.satisfies(&Version::parse("2.4.0").unwrap()));

    // Hyphen range with prerelease
    let r4 = Range::parse("1.2.3-alpha.1 - 2.0.0").unwrap();
    assert!(r4.satisfies(&Version::parse("1.2.3-alpha.2").unwrap()));
    assert!(!r4.satisfies(&Version::parse("1.2.4-alpha").unwrap()));
}

#[test]
fn test_semver_wildcards() {
    let r_star = Range::parse("*").unwrap();
    assert!(r_star.is_wildcard());
    assert!(r_star.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_star.satisfies(&Version::parse("99.99.99").unwrap()));
    assert!(!r_star.satisfies(&Version::parse("1.0.0-alpha").unwrap()));

    let r_empty = Range::parse("").unwrap();
    assert!(r_empty.is_wildcard());

    let r_x = Range::parse("x").unwrap();
    assert!(r_x.is_wildcard());
    let r_cap_x = Range::parse("X").unwrap();
    assert!(r_cap_x.is_wildcard());

    let r_1x = Range::parse("1.x").unwrap();
    assert!(r_1x.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r_1x.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r_1x.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r_1x.satisfies(&Version::parse("0.9.9").unwrap()));

    let r_1_2_x = Range::parse("1.2.X").unwrap();
    assert!(r_1_2_x.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r_1_2_x.satisfies(&Version::parse("1.2.9").unwrap()));
    assert!(!r_1_2_x.satisfies(&Version::parse("1.3.0").unwrap()));
}

#[test]
fn test_semver_caret_and_tilde_on_zeros() {
    // ^0.2.3 := >=0.2.3 <0.3.0-0
    let r_c1 = Range::parse("^0.2.3").unwrap();
    assert!(r_c1.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r_c1.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_c1.satisfies(&Version::parse("0.2.2").unwrap()));
    assert!(!r_c1.satisfies(&Version::parse("0.3.0").unwrap()));

    // ^0.0.3 := >=0.0.3 <0.0.4-0
    let r_c2 = Range::parse("^0.0.3").unwrap();
    assert!(r_c2.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(!r_c2.satisfies(&Version::parse("0.0.2").unwrap()));
    assert!(!r_c2.satisfies(&Version::parse("0.0.4").unwrap()));

    // ^0.0.0 := >=0.0.0 <0.0.1-0
    let r_c3 = Range::parse("^0.0.0").unwrap();
    assert!(r_c3.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(!r_c3.satisfies(&Version::parse("0.0.1").unwrap()));

    // ~0.2.3 := >=0.2.3 <0.3.0-0
    let r_t1 = Range::parse("~0.2.3").unwrap();
    assert!(r_t1.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r_t1.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_t1.satisfies(&Version::parse("0.3.0").unwrap()));

    // ~0.0.3 := >=0.0.3 <0.1.0-0
    let r_t2 = Range::parse("~0.0.3").unwrap();
    assert!(r_t2.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(r_t2.satisfies(&Version::parse("0.0.9").unwrap()));
    assert!(!r_t2.satisfies(&Version::parse("0.1.0").unwrap()));
}

#[test]
fn test_semver_or_unions() {
    let r_union = Range::parse("<1.0.0 || >=2.0.0").unwrap();
    assert!(r_union.satisfies(&Version::parse("0.9.0").unwrap()));
    assert!(r_union.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_union.satisfies(&Version::parse("3.0.0").unwrap()));
    assert!(!r_union.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(!r_union.satisfies(&Version::parse("1.5.0").unwrap()));

    // Union with wildcard collapses
    let r_wild = Range::parse("^1.0.0 || *").unwrap();
    assert!(r_wild.is_wildcard());

    let r_multi = Range::parse("^1.0.0 || ^2.0.0 || ^3.0.0").unwrap();
    assert!(r_multi.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_multi.satisfies(&Version::parse("2.0.1").unwrap()));
    assert!(r_multi.satisfies(&Version::parse("3.4.5").unwrap()));
    assert!(!r_multi.satisfies(&Version::parse("4.0.0").unwrap()));
}

#[test]
fn test_semver_build_metadata_ignored_in_precedence() {
    let v1 = Version::parse("1.2.3+build.1").unwrap();
    let v2 = Version::parse("1.2.3+build.2").unwrap();
    assert_eq!(v1, v2);
    assert_eq!(v1.cmp(&v2), std::cmp::Ordering::Equal);

    let r = Range::parse("=1.2.3").unwrap();
    assert!(r.satisfies(&v1));
    assert!(r.satisfies(&v2));

    let r_caret = Range::parse("^1.2.3").unwrap();
    assert!(r_caret.satisfies(&v1));
}

#[test]
fn test_semver_u64_overflow_rejection() {
    assert!(Version::parse("999999999999999999999999999999.0.0").is_err());
    assert!(Version::parse("0.999999999999999999999999999999.0").is_err());
    assert!(Version::parse("0.0.999999999999999999999999999999").is_err());

    let max_str = u64::MAX.to_string();
    assert!(Range::parse(&format!("^{max_str}.0.0")).is_err());
    assert!(Range::parse(&format!("^0.{max_str}.0")).is_err());
    assert!(Range::parse(&format!("^0.0.{max_str}")).is_err());
    assert!(Range::parse(&format!("~{max_str}")).is_err());
    assert!(Range::parse(&format!("~{max_str}.x")).is_err());
    assert!(Range::parse(&format!("~1.{max_str}.0")).is_err());
    assert!(Range::parse(&format!(">{max_str}.x")).is_err());
}

#[test]
fn test_comparator_and_range_fast_paths_ast_parity() {
    // Fast path caret vs general parser caret
    let r_fast = Range::parse("^1.2.3").unwrap();
    assert_eq!(r_fast.sets.len(), 1);
    assert_eq!(r_fast.sets[0].comparators.len(), 2);
    assert_eq!(r_fast.sets[0].comparators[0].op, Op::Gte);
    assert_eq!(r_fast.sets[0].comparators[0].version, Version::new(1, 2, 3));
    assert_eq!(r_fast.sets[0].comparators[1].op, Op::Lt);
    assert_eq!(r_fast.sets[0].comparators[1].version.major, 2);
    assert_eq!(r_fast.sets[0].comparators[1].version.minor, 0);
    assert_eq!(r_fast.sets[0].comparators[1].version.patch, 0);
    assert_eq!(
        r_fast.sets[0].comparators[1].version.prerelease,
        vec![PrereleaseId::Numeric(0)]
    );

    // Fast path tilde
    let r_tilde = Range::parse("~1.2.3").unwrap();
    assert_eq!(r_tilde.sets[0].comparators[0].op, Op::Gte);
    assert_eq!(r_tilde.sets[0].comparators[0].version, Version::new(1, 2, 3));
    assert_eq!(r_tilde.sets[0].comparators[1].op, Op::Lt);
    assert_eq!(r_tilde.sets[0].comparators[1].version.major, 1);
    assert_eq!(r_tilde.sets[0].comparators[1].version.minor, 3);
    assert_eq!(r_tilde.sets[0].comparators[1].version.patch, 0);
    assert_eq!(
        r_tilde.sets[0].comparators[1].version.prerelease,
        vec![PrereleaseId::Numeric(0)]
    );

    // Comparator::parse fast path
    let c = Comparator::parse(">=1.2.3").unwrap();
    assert_eq!(c.op, Op::Gte);
    assert_eq!(c.version, Version::new(1, 2, 3));
}

#[test]
fn test_semver_high_throughput_inner_loops() {
    let versions = [
        "1.2.3",
        "0.0.1",
        "14.21.0",
        "v2.0.0",
        "=3.1.4",
        "1.0.0-alpha.1",
        "2.3.4+build.99",
    ];
    let ranges = [
        "^1.2.3",
        "~1.2.3",
        "1.2.3",
        ">=1.0.0 <2.0.0",
        "*",
        "^1.0.0 || ^2.0.0",
        "1.0.0 - 2.0.0",
    ];

    let parsed_versions: Vec<Version> = versions.iter().map(|s| Version::parse(s).unwrap()).collect();
    let parsed_ranges: Vec<Range> = ranges.iter().map(|s| Range::parse(s).unwrap()).collect();

    let start = std::time::Instant::now();
    let iterations = 20_000;
    for _ in 0..iterations {
        for s in &versions {
            let _ = Version::parse(s).unwrap();
        }
        for s in &ranges {
            let _ = Range::parse(s).unwrap();
        }
        for r in &parsed_ranges {
            for v in &parsed_versions {
                let _ = r.satisfies(v);
            }
        }
    }
    let elapsed = start.elapsed();
    println!("Completed {iterations} iterations in {:?}", elapsed);
}
