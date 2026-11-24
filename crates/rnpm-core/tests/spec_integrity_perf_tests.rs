use rnpm_core::integrity::{Algorithm, Integrity, IntegrityHasher};
use rnpm_core::semver::{Range, Version};
use rnpm_core::spec::{is_scp_git_url, unsupported_protocol, PackageSpec, PackageTarget};
use rnpm_core::IntegrityError;
use std::io::Cursor;

#[test]
fn test_registry_specs_fast_path() {
    // 1. Caret range
    let spec1 = PackageSpec::parse("express@^4.18.0").unwrap();
    assert_eq!(spec1.name, "express");
    assert_eq!(
        spec1.target,
        PackageTarget::Range(Range::parse("^4.18.0").unwrap())
    );

    // 2. Tilde range
    let spec2 = PackageSpec::parse("react@~18.2.0").unwrap();
    assert_eq!(spec2.name, "react");
    assert_eq!(
        spec2.target,
        PackageTarget::Range(Range::parse("~18.2.0").unwrap())
    );

    // 3. Exact version
    let spec3 = PackageSpec::parse("lodash@1.2.3").unwrap();
    assert_eq!(spec3.name, "lodash");
    assert_eq!(
        spec3.target,
        PackageTarget::Version(Version::new(1, 2, 3))
    );

    // 4. Dist-tag
    let spec4 = PackageSpec::parse("typescript@latest").unwrap();
    assert_eq!(spec4.name, "typescript");
    assert_eq!(spec4.target, PackageTarget::Tag("latest".to_string()));

    // 5. Star / any range
    let spec5 = PackageSpec::parse("pkg@*").unwrap();
    assert_eq!(spec5.name, "pkg");
    assert_eq!(
        spec5.target,
        PackageTarget::Range(Range::parse("*").unwrap())
    );

    // 6. Compound comparator range
    let spec6 = PackageSpec::parse("pkg@>=1.0.0 <2.0.0").unwrap();
    assert_eq!(spec6.name, "pkg");
    assert_eq!(
        spec6.target,
        PackageTarget::Range(Range::parse(">=1.0.0 <2.0.0").unwrap())
    );

    // 7. Hyphen range
    let spec7 = PackageSpec::parse("pkg@1.0.0 - 2.0.0").unwrap();
    assert_eq!(spec7.name, "pkg");
    assert_eq!(
        spec7.target,
        PackageTarget::Range(Range::parse("1.0.0 - 2.0.0").unwrap())
    );

    // 8. Version with 'v' prefix
    let spec8 = PackageSpec::parse("pkg@v1.2.3").unwrap();
    assert_eq!(spec8.name, "pkg");
    assert_eq!(
        spec8.target,
        PackageTarget::Version(Version::new(1, 2, 3))
    );

    // 9. Version with '=' prefix
    let spec9 = PackageSpec::parse("pkg@=1.2.3").unwrap();
    assert_eq!(spec9.name, "pkg");
    assert_eq!(
        spec9.target,
        PackageTarget::Version(Version::new(1, 2, 3))
    );

    // 10. parse_dependency fast path
    let dep = PackageSpec::parse_dependency("fast-dep", "^2.1.0").unwrap();
    assert_eq!(dep.name, "fast-dep");
    assert_eq!(
        dep.target,
        PackageTarget::Range(Range::parse("^2.1.0").unwrap())
    );
}

#[test]
fn test_scoped_specs() {
    let s1 = PackageSpec::parse("@scope/pkg@^1.0.0").unwrap();
    assert_eq!(s1.name, "@scope/pkg");
    assert_eq!(
        s1.target,
        PackageTarget::Range(Range::parse("^1.0.0").unwrap())
    );

    let s2 = PackageSpec::parse("@types/node@18.0.0").unwrap();
    assert_eq!(s2.name, "@types/node");
    assert_eq!(
        s2.target,
        PackageTarget::Version(Version::new(18, 0, 0))
    );

    let s3 = PackageSpec::parse("@my-org/my-pkg@latest").unwrap();
    assert_eq!(s3.name, "@my-org/my-pkg");
    assert_eq!(s3.target, PackageTarget::Tag("latest".to_string()));

    let s4 = PackageSpec::parse("@scope/bare").unwrap();
    assert_eq!(s4.name, "@scope/bare");
    assert_eq!(s4.target, PackageTarget::Tag("latest".to_string()));
}

#[test]
fn test_aliases() {
    // Direct npm: alias
    let a1 = PackageSpec::parse("npm:foo@^1.0.0").unwrap();
    assert_eq!(a1.name, "foo");
    assert_eq!(
        a1.target,
        PackageTarget::Alias {
            name: "foo".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("^1.0.0").unwrap())),
        }
    );

    // Scoped npm: alias
    let a2 = PackageSpec::parse("npm:@scope/pkg@^1.0.0").unwrap();
    assert_eq!(a2.name, "@scope/pkg");
    assert_eq!(
        a2.target,
        PackageTarget::Alias {
            name: "@scope/pkg".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("^1.0.0").unwrap())),
        }
    );

    // Named package with npm: alias
    let a3 = PackageSpec::parse("my-pkg@npm:real-pkg@~2.0.0").unwrap();
    assert_eq!(a3.name, "my-pkg");
    assert_eq!(
        a3.target,
        PackageTarget::Alias {
            name: "real-pkg".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("~2.0.0").unwrap())),
        }
    );

    // Bare alias without version defaults to tag latest
    let a4 = PackageSpec::parse("npm:bar").unwrap();
    assert_eq!(a4.name, "bar");
    assert_eq!(
        a4.target,
        PackageTarget::Alias {
            name: "bar".to_string(),
            target: Box::new(PackageTarget::Tag("latest".to_string())),
        }
    );
}

#[test]
fn test_git_and_github_shorthand_specs() {
    // GitHub shorthand
    let g1 = PackageSpec::parse("user/repo").unwrap();
    assert_eq!(g1.name, "repo");
    assert_eq!(
        g1.target,
        PackageTarget::Git {
            url: "github:user/repo".to_string(),
            committish: None,
            subdir: None,
        }
    );

    // GitHub shorthand with tag
    let g2 = PackageSpec::parse("user/repo#v1.0.0").unwrap();
    assert_eq!(g2.name, "repo");
    assert_eq!(
        g2.target,
        PackageTarget::Git {
            url: "github:user/repo".to_string(),
            committish: Some("v1.0.0".to_string()),
            subdir: None,
        }
    );

    // GitHub shorthand with semver
    let g3 = PackageSpec::parse("user/repo#semver:^1.0.0").unwrap();
    assert_eq!(g3.name, "repo");
    assert_eq!(
        g3.target,
        PackageTarget::Git {
            url: "github:user/repo".to_string(),
            committish: Some("semver:^1.0.0".to_string()),
            subdir: None,
        }
    );

    // Subdirectory path via #path:
    let g4 = PackageSpec::parse("github:user/repo#main::path:packages/foo").unwrap();
    assert_eq!(g4.name, "repo");
    assert_eq!(
        g4.target,
        PackageTarget::Git {
            url: "github:user/repo".to_string(),
            committish: Some("main".to_string()),
            subdir: Some("packages/foo".to_string()),
        }
    );

    // SCP git URL
    let scp = "git@github.com:org/repo.git#v1.0.0";
    assert!(is_scp_git_url(scp));
    let g5 = PackageSpec::parse(scp).unwrap();
    assert_eq!(g5.name, "repo");
    assert_eq!(
        g5.target,
        PackageTarget::Git {
            url: "git@github.com:org/repo.git".to_string(),
            committish: Some("v1.0.0".to_string()),
            subdir: None,
        }
    );

    // git+https with semver
    let g6 = PackageSpec::parse_dependency(
        "my-dep",
        "git+https://github.com/org/repo.git#semver:^2.0.0",
    )
    .unwrap();
    assert_eq!(g6.name, "my-dep");
    assert_eq!(
        g6.target,
        PackageTarget::Git {
            url: "git+https://github.com/org/repo.git".to_string(),
            committish: Some("semver:^2.0.0".to_string()),
            subdir: None,
        }
    );
}

#[test]
fn test_file_workspace_and_unsupported_protocols() {
    let f1 = PackageSpec::parse("foo@file:../bar").unwrap();
    assert_eq!(f1.name, "foo");
    assert!(matches!(f1.target, PackageTarget::File(_)));

    let f2 = PackageSpec::parse("file:../bar").unwrap();
    assert!(matches!(f2.target, PackageTarget::File(_)));

    let w1 = PackageSpec::parse("workspace:*").unwrap();
    assert_eq!(w1.name, "workspace");
    assert_eq!(w1.target, PackageTarget::Workspace("*".to_string()));

    let w2 = PackageSpec::parse("foo@workspace:^1.0.0").unwrap();
    assert_eq!(w2.name, "foo");
    assert_eq!(w2.target, PackageTarget::Workspace("^1.0.0".to_string()));

    // unsupported_protocol checks
    assert_eq!(
        unsupported_protocol("link:../x").as_deref(),
        Some("link:")
    );
    assert_eq!(
        unsupported_protocol("catalog:").as_deref(),
        Some("catalog:")
    );
    assert_eq!(
        unsupported_protocol("portal:../y").as_deref(),
        Some("portal:")
    );
    assert_eq!(unsupported_protocol("^1.0.0"), None);
    assert_eq!(unsupported_protocol("express@^4.18.0"), None);
}

#[test]
fn test_multi_hash_sri_and_precedence() {
    let payload = b"critical test payload for integrity verification";

    let int_sha1 = Integrity::from_bytes(payload, Algorithm::Sha1);
    let int_sha256 = Integrity::from_bytes(payload, Algorithm::Sha256);
    let int_sha512 = Integrity::from_bytes(payload, Algorithm::Sha512);

    // Multi-hash SRI string
    let multi_str = format!("{int_sha1} {int_sha256} {int_sha512}");
    let parsed_multi = Integrity::parse(&multi_str).unwrap();

    assert_eq!(parsed_multi.entries.len(), 3);
    assert_eq!(
        parsed_multi.strongest_algorithm(),
        Some(Algorithm::Sha512)
    );
    assert!(parsed_multi.verify(payload).is_ok());

    // Tampered data must be rejected by strongest algorithm
    let tampered = b"critical test payload for integrity verification - TAMPERED";
    let res = parsed_multi.verify(tampered);
    assert!(matches!(
        res,
        Err(IntegrityError::Mismatch {
            ref algorithm,
            ..
        }) if algorithm == "sha512"
    ));

    // Attack case: sha1 matches, but sha512 is forged -> MUST FAIL!
    let forged_sha512 =
        "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let attack_str = format!("{int_sha1} {forged_sha512}");
    let attack_integrity = Integrity::parse(&attack_str).unwrap();
    let attack_res = attack_integrity.verify(payload);
    assert!(
        attack_res.is_err(),
        "Must reject forged sha512 even if sha1 matches"
    );
    if let Err(IntegrityError::Mismatch { algorithm, .. }) = attack_res {
        assert_eq!(algorithm, "sha512");
    } else {
        panic!("Expected Mismatch on sha512");
    }
}

#[test]
fn test_invalid_sri_rejection() {
    // 1. Empty string
    assert_eq!(Integrity::parse(""), Err(IntegrityError::Empty));
    assert_eq!(Integrity::parse("   "), Err(IntegrityError::Empty));

    // 2. Missing hyphen
    assert!(matches!(
        Integrity::parse("sha512"),
        Err(IntegrityError::InvalidFormat(_))
    ));

    // 3. Unsupported algorithm
    assert!(matches!(
        Integrity::parse("md5-abc=="),
        Err(IntegrityError::UnsupportedAlgorithm(_))
    ));

    // 4. Invalid base64 characters
    assert!(matches!(
        Integrity::parse("sha512-not_valid_base64!!!"),
        Err(IntegrityError::InvalidBase64(_))
    ));
}

#[test]
fn test_streaming_vs_slice_hashing_parity() {
    // Test across various payload sizes: small (10 bytes), medium (1 KB), large (128 KB multi-chunk)
    let sizes = [10, 1024, 131072];

    for &size in &sizes {
        let mut data = Vec::with_capacity(size);
        for i in 0..size {
            data.push(((i * 31 + 7) % 256) as u8);
        }

        for algo in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            // Slice hashing
            let slice_int = Integrity::from_bytes(&data, algo);

            // Streaming hashing via from_reader
            let stream_int = Integrity::from_reader(Cursor::new(&data), algo).unwrap();

            assert_eq!(
                slice_int, stream_int,
                "Streaming from_reader must exactly match slice from_bytes for {algo} on {size} bytes"
            );

            // verify vs verify_reader
            assert!(
                slice_int.verify(&data).is_ok(),
                "Slice verify must pass"
            );
            assert!(
                slice_int
                    .verify_reader(Cursor::new(&data))
                    .is_ok(),
                "Stream verify_reader must pass"
            );

            // Verify with tampered data
            let mut tampered = data.clone();
            tampered[size / 2] ^= 0xFF;
            assert!(slice_int.verify(&tampered).is_err());
            assert!(slice_int.verify_reader(Cursor::new(&tampered)).is_err());

            // IntegrityHasher chunked update parity
            let mut hasher = IntegrityHasher::new(algo);
            for chunk in data.chunks(4096) {
                hasher.update(chunk);
            }
            let chunked_int = hasher.finalize_integrity(algo);
            assert_eq!(
                slice_int, chunked_int,
                "Chunked IntegrityHasher must match slice integrity for {algo}"
            );
        }
    }
}
