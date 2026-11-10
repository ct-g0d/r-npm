use crate::error::{IntegrityError, SemverError};
use crate::integrity::{Algorithm, Integrity};
use crate::manifest::Manifest;
use crate::semver::{Comparator, Op, PrereleaseId, Range, Version};
use crate::spec::{PackageSpec, PackageTarget};
use std::path::PathBuf;

#[test]
fn test_semver_version_parsing_and_order() {
    let v1 = Version::parse("1.2.3").unwrap();
    assert_eq!(v1.major, 1);
    assert_eq!(v1.minor, 2);
    assert_eq!(v1.patch, 3);
    assert!(v1.prerelease.is_empty());
    assert!(v1.build.is_empty());

    // Loose parsing with v and =
    let v2 = Version::parse("  v1.2.3  ").unwrap();
    assert_eq!(v1, v2);

    let v3 = Version::parse("=1.2.3").unwrap();
    assert_eq!(v1, v3);

    // Prerelease and build
    let vp1 = Version::parse("1.0.0-alpha.1+build.123").unwrap();
    assert_eq!(vp1.to_string(), "1.0.0-alpha.1+build.123");
    assert!(vp1.is_prerelease());

    // Semver precedence rules
    let va = Version::parse("1.0.0-alpha").unwrap();
    let va1 = Version::parse("1.0.0-alpha.1").unwrap();
    let va_beta = Version::parse("1.0.0-alpha.beta").unwrap();
    let vb = Version::parse("1.0.0-beta").unwrap();
    let vb2 = Version::parse("1.0.0-beta.2").unwrap();
    let vb11 = Version::parse("1.0.0-beta.11").unwrap();
    let vrc1 = Version::parse("1.0.0-rc.1").unwrap();
    let v_final = Version::parse("1.0.0").unwrap();

    assert!(va < va1);
    assert!(va1 < va_beta);
    assert!(va_beta < vb);
    assert!(vb < vb2);
    assert!(vb2 < vb11);
    assert!(vb11 < vrc1);
    assert!(vrc1 < v_final);

    // Numeric prerelease lower than alphanumeric
    let v_num = Version::parse("1.0.0-1").unwrap();
    let v_str = Version::parse("1.0.0-alpha").unwrap();
    assert!(v_num < v_str);

    // Build metadata is ignored in precedence
    let vb1 = Version::parse("1.0.0+20130313144700").unwrap();
    let vb2 = Version::parse("1.0.0+exp.sha.5114f85").unwrap();
    assert_eq!(vb1.cmp(&vb2), std::cmp::Ordering::Equal);
}

#[test]
fn test_semver_inc_node_semver_rules() {
    let v = Version::parse("1.2.3").unwrap();
    assert_eq!(v.inc("major", None).unwrap().to_string(), "2.0.0");
    assert_eq!(v.inc("minor", None).unwrap().to_string(), "1.3.0");
    assert_eq!(v.inc("patch", None).unwrap().to_string(), "1.2.4");
    assert_eq!(v.inc("prerelease", None).unwrap().to_string(), "1.2.4-0");
    assert_eq!(
        v.inc("prepatch", Some("beta")).unwrap().to_string(),
        "1.2.4-beta.0"
    );
    assert_eq!(
        v.inc("preminor", Some("beta")).unwrap().to_string(),
        "1.3.0-beta.0"
    );
    assert_eq!(
        v.inc("premajor", Some("beta")).unwrap().to_string(),
        "2.0.0-beta.0"
    );

    let v_pre = Version::parse("1.0.0-alpha").unwrap();
    assert_eq!(v_pre.inc("major", None).unwrap().to_string(), "1.0.0");

    let v_pre_minor = Version::parse("1.2.0-alpha").unwrap();
    assert_eq!(v_pre_minor.inc("minor", None).unwrap().to_string(), "1.2.0");

    let v_pre_patch = Version::parse("1.2.3-alpha").unwrap();
    assert_eq!(v_pre_patch.inc("patch", None).unwrap().to_string(), "1.2.3");

    let v_b0 = Version::parse("1.2.3-beta.0").unwrap();
    assert_eq!(
        v_b0.inc("prerelease", None).unwrap().to_string(),
        "1.2.3-beta.1"
    );
    assert_eq!(
        v_b0.inc("prerelease", Some("beta")).unwrap().to_string(),
        "1.2.3-beta.1"
    );
    assert_eq!(
        v_b0.inc("prerelease", Some("alpha")).unwrap().to_string(),
        "1.2.3-alpha.0"
    );

    let v_b = Version::parse("1.2.3-beta").unwrap();
    assert_eq!(
        v_b.inc("prerelease", None).unwrap().to_string(),
        "1.2.3-beta.0"
    );
    assert_eq!(
        v_b.inc("prerelease", Some("beta")).unwrap().to_string(),
        "1.2.3-beta.0"
    );
}

#[test]
fn test_semver_range_caret() {
    let r1 = Range::parse("^1.2.3").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r1.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.2.2").unwrap()));

    // Caret 0.x
    let r2 = Range::parse("^0.2.3").unwrap();
    assert!(r2.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r2.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r2.satisfies(&Version::parse("0.3.0").unwrap()));

    // Caret 0.0.x
    let r3 = Range::parse("^0.0.3").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(!r3.satisfies(&Version::parse("0.0.4").unwrap()));
}

#[test]
fn test_semver_range_tilde_and_x() {
    let r1 = Range::parse("~1.2.3").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.2.8").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.3.0").unwrap()));

    let r2 = Range::parse("1.x").unwrap();
    assert!(r2.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("1.99.0").unwrap()));
    assert!(!r2.satisfies(&Version::parse("2.0.0").unwrap()));

    let r3 = Range::parse("*").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(r3.satisfies(&Version::parse("99.9.9").unwrap()));
}

#[test]
fn test_semver_range_hyphen_and_or() {
    let r = Range::parse("1.2.3 - 2.3.4").unwrap();
    assert!(r.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r.satisfies(&Version::parse("2.3.5").unwrap()));

    let r_or = Range::parse("^1.0.0 || >=2.5.0 <3.0.0").unwrap();
    assert!(r_or.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_or.satisfies(&Version::parse("2.6.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("3.0.0").unwrap()));
}

#[test]
fn test_semver_prerelease_matching_rule() {
    let r = Range::parse("^1.2.3").unwrap();
    // Prerelease not allowed when range has no prerelease on tuple
    assert!(!r.satisfies(&Version::parse("1.2.4-alpha").unwrap()));

    // But if range explicitly targets prerelease on tuple
    let r_pre = Range::parse("^1.2.3-alpha.1").unwrap();
    assert!(r_pre.satisfies(&Version::parse("1.2.3-alpha.2").unwrap()));
    assert!(r_pre.satisfies(&Version::parse("1.2.4").unwrap()));
    // Tuple mismatch with prerelease should not match
    assert!(!r_pre.satisfies(&Version::parse("1.2.4-beta").unwrap()));
}

#[test]
fn test_package_spec_parsing() {
    // Ordinary package
    let s1 = PackageSpec::parse("express").unwrap();
    assert_eq!(s1.name, "express");
    assert_eq!(s1.target, PackageTarget::Tag("latest".to_string()));

    // Exact version
    let s2 = PackageSpec::parse("express@4.18.2").unwrap();
    assert_eq!(s2.name, "express");
    assert_eq!(
        s2.target,
        PackageTarget::Version(Version::parse("4.18.2").unwrap())
    );

    // Semver range
    let s3 = PackageSpec::parse("express@^4.18.0").unwrap();
    assert_eq!(s3.name, "express");
    assert_eq!(
        s3.target,
        PackageTarget::Range(Range::parse("^4.18.0").unwrap())
    );

    // Scoped package
    let s4 = PackageSpec::parse("@types/node@^18.0.0").unwrap();
    assert_eq!(s4.name, "@types/node");
    assert_eq!(
        s4.target,
        PackageTarget::Range(Range::parse("^18.0.0").unwrap())
    );

    // npm: alias
    let s5 = PackageSpec::parse("my-react@npm:react@^18.2.0").unwrap();
    assert_eq!(s5.name, "my-react");
    assert_eq!(
        s5.target,
        PackageTarget::Alias {
            name: "react".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("^18.2.0").unwrap())),
        }
    );

    // direct npm: alias
    let s5_direct = PackageSpec::parse("npm:react@^18.2.0").unwrap();
    assert_eq!(s5_direct.name, "react");

    // file: specifier
    let s6 = PackageSpec::parse("foo@file:../local-pkg").unwrap();
    assert_eq!(s6.name, "foo");
    assert_eq!(
        s6.target,
        PackageTarget::File(PathBuf::from("../local-pkg"))
    );

    // parse_dependency helper
    let s7 = PackageSpec::parse_dependency("aliased", "npm:@scope/lib@~1.0.0").unwrap();
    assert_eq!(s7.name, "aliased");
    assert_eq!(
        s7.target,
        PackageTarget::Alias {
            name: "@scope/lib".to_string(),
            target: Box::new(PackageTarget::Range(Range::parse("~1.0.0").unwrap())),
        }
    );

    // Git dependency: github:user/repo
    let s8 = PackageSpec::parse("github:user/repo").unwrap();
    assert_eq!(s8.name, "repo");
    assert_eq!(
        s8.target,
        PackageTarget::Git {
            url: "github:user/repo".to_string(),
            committish: None,
        }
    );

    // Git dependency: git+https://...#v1.0.0
    let s9 = PackageSpec::parse_dependency("my-lib", "git+https://github.com/org/repo.git#v1.0.0")
        .unwrap();
    assert_eq!(s9.name, "my-lib");
    assert_eq!(
        s9.target,
        PackageTarget::Git {
            url: "git+https://github.com/org/repo.git".to_string(),
            committish: Some("v1.0.0".to_string()),
        }
    );
    assert_eq!(
        s9.target.git_clone_url().unwrap(),
        "https://github.com/org/repo.git"
    );

    // Remote tarball URL dependency
    let s10 =
        PackageSpec::parse_dependency("pkg", "https://cdn.example.com/packages/pkg-1.0.0.tgz")
            .unwrap();
    assert_eq!(s10.name, "pkg");
    assert_eq!(
        s10.target,
        PackageTarget::Url(
            url::Url::parse("https://cdn.example.com/packages/pkg-1.0.0.tgz").unwrap()
        )
    );
}

#[test]
fn test_git_spec_edge_cases_and_clone_urls() {
    use url::Url;

    // 1. github with tag
    let t1 = PackageTarget::parse("github:facebook/react#v18.2.0").unwrap();
    assert_eq!(t1.git().unwrap().0, "github:facebook/react");
    assert_eq!(t1.git().unwrap().1, Some("v18.2.0"));
    assert_eq!(
        t1.git_clone_url().unwrap(),
        "https://github.com/facebook/react.git"
    );
    assert_eq!(t1.git_committish(), Some("v18.2.0"));

    // 2. gitlab with commit sha
    let t2 = PackageTarget::parse("gitlab:gitlab-org/gitlab#abcdef123456").unwrap();
    assert_eq!(
        t2.git_clone_url().unwrap(),
        "https://gitlab.com/gitlab-org/gitlab.git"
    );
    assert_eq!(t2.git_committish(), Some("abcdef123456"));

    // 3. bitbucket with branch
    let t3 = PackageTarget::parse("bitbucket:atlassian/repo#feature-branch").unwrap();
    assert_eq!(
        t3.git_clone_url().unwrap(),
        "https://bitbucket.org/atlassian/repo.git"
    );
    assert_eq!(t3.git_committish(), Some("feature-branch"));

    // 4. git+ssh
    let t4 = PackageTarget::parse("git+ssh://git@github.com/owner/repo.git#main").unwrap();
    assert_eq!(
        t4.git_clone_url().unwrap(),
        "ssh://git@github.com/owner/repo.git"
    );
    assert_eq!(t4.git_committish(), Some("main"));

    // 5. git://
    let t5 = PackageTarget::parse("git://github.com/owner/repo.git").unwrap();
    assert_eq!(
        t5.git_clone_url().unwrap(),
        "git://github.com/owner/repo.git"
    );
    assert_eq!(t5.git_committish(), None);

    // 6. Direct HTTP URL
    let u1 = PackageTarget::parse("https://cdn.example.com/packages/pkg-1.0.0.tgz").unwrap();
    assert!(u1.is_url());
    assert_eq!(
        u1.url().unwrap(),
        &Url::parse("https://cdn.example.com/packages/pkg-1.0.0.tgz").unwrap()
    );

    // 7. Display roundtrip
    assert_eq!(t1.to_string(), "github:facebook/react#v18.2.0");
    assert_eq!(
        t4.to_string(),
        "git+ssh://git@github.com/owner/repo.git#main"
    );
    assert_eq!(
        u1.to_string(),
        "https://cdn.example.com/packages/pkg-1.0.0.tgz"
    );

    assert_eq!(PackageTarget::parse(&t1.to_string()).unwrap(), t1);
    assert_eq!(PackageTarget::parse(&t4.to_string()).unwrap(), t4);
    assert_eq!(PackageTarget::parse(&u1.to_string()).unwrap(), u1);
}

#[test]
fn test_ssri_integrity_verification_and_precedence() {
    let data = b"hello world integrity test payload";

    let integrity_sha1 = Integrity::from_bytes(data, Algorithm::Sha1);
    let integrity_sha512 = Integrity::from_bytes(data, Algorithm::Sha512);

    // Valid single hash verification
    assert!(integrity_sha512.verify(data).is_ok());

    // Corrupted data detection
    let corrupted = b"corrupted payload";
    assert!(matches!(
        integrity_sha512.verify(corrupted),
        Err(IntegrityError::Mismatch { .. })
    ));

    // Multi-hash parsing and strongest algorithm precedence:
    // Format: "sha512-... sha1-..."
    let combined_str = format!("{} {}", integrity_sha512, integrity_sha1);
    let combined = Integrity::parse(&combined_str).unwrap();
    assert_eq!(combined.strongest_algorithm(), Some(Algorithm::Sha512));
    assert!(combined.verify(data).is_ok());

    // CRUCIAL: Weak hash matches, but strongest hash fails!
    // A corrupted sha512 with a valid sha1: MUST FAIL!
    let fake_sha512 = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let attack_str = format!("{} {}", fake_sha512, integrity_sha1);
    let attack_integrity = Integrity::parse(&attack_str).unwrap();
    let result = attack_integrity.verify(data);
    assert!(
        result.is_err(),
        "Strongest hash failure must reject even if weaker hash matches"
    );
    if let Err(IntegrityError::Mismatch { algorithm, .. }) = result {
        assert_eq!(algorithm, "sha512");
    } else {
        panic!("Expected Mismatch error");
    }
}

#[test]
fn test_manifest_parsing_and_bom_tolerance() {
    let json_text = r#"{
        "name": "@myorg/my-pkg",
        "version": "1.2.3",
        "description": "A test package",
        "bin": {
            "cli": "./bin/cli.js"
        },
        "scripts": {
            "test": "echo test"
        },
        "dependencies": {
            "react": "^18.2.0"
        },
        "devDependencies": {
            "typescript": "^5.0.0"
        },
        "peerDependencies": {
            "react-dom": "^18.2.0"
        },
        "optionalDependencies": {
            "fsevents": "^2.3.2"
        },
        "bundleDependencies": ["react"]
    }"#;

    // Normal parse
    let manifest = Manifest::from_str(json_text).unwrap();
    assert_eq!(manifest.name.as_deref(), Some("@myorg/my-pkg"));
    assert_eq!(manifest.version.as_deref(), Some("1.2.3"));
    assert_eq!(manifest.dependencies.get("react").unwrap(), "^18.2.0");
    assert_eq!(
        manifest.bin_entries(),
        vec![("cli".to_string(), "./bin/cli.js".to_string())]
    );
    assert_eq!(manifest.bundled_package_names(), vec!["react".to_string()]);

    // UTF-8 BOM tolerance on bytes
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(json_text.as_bytes());
    let manifest_bom = Manifest::from_slice(&bom_bytes).unwrap();
    assert_eq!(manifest_bom.name.as_deref(), Some("@myorg/my-pkg"));

    // UTF-8 BOM tolerance on string
    let bom_str = format!("\u{feff}{json_text}");
    let manifest_str_bom = Manifest::from_str(&bom_str).unwrap();
    assert_eq!(manifest_str_bom.name.as_deref(), Some("@myorg/my-pkg"));

    // Single bin string normalization
    let single_bin_json = r#"{
        "name": "@myorg/my-tool",
        "version": "1.0.0",
        "bin": "./dist/cli.js"
    }"#;
    let single_bin_manifest = Manifest::from_str(single_bin_json).unwrap();
    assert_eq!(
        single_bin_manifest.bin_entries(),
        vec![("my-tool".to_string(), "./dist/cli.js".to_string())]
    );

    // Malformed JSON diagnostic
    let malformed = r#"{ "name": "bad", "version": 1.2.3 }"#;
    let err = Manifest::from_str(malformed).unwrap_err();
    assert!(matches!(
        err,
        crate::error::ManifestError::MalformedJson { .. }
    ));
}

#[test]
fn test_workspace_spec_parsing() {
    let t_star = PackageTarget::parse("workspace:*").unwrap();
    assert_eq!(t_star, PackageTarget::Workspace("*".to_string()));
    assert_eq!(t_star.to_string(), "workspace:*");

    let t_caret = PackageTarget::parse("workspace:^").unwrap();
    assert_eq!(t_caret, PackageTarget::Workspace("^".to_string()));
    assert_eq!(t_caret.to_string(), "workspace:^");

    let t_tilde = PackageTarget::parse("workspace:~").unwrap();
    assert_eq!(t_tilde, PackageTarget::Workspace("~".to_string()));
    assert_eq!(t_tilde.to_string(), "workspace:~");

    let t_range = PackageTarget::parse("workspace:^1.2.0").unwrap();
    assert_eq!(t_range, PackageTarget::Workspace("^1.2.0".to_string()));

    let spec = PackageSpec::parse("pkg-a@workspace:*").unwrap();
    assert_eq!(spec.name, "pkg-a");
    assert_eq!(spec.target, PackageTarget::Workspace("*".to_string()));

    let dep_spec = PackageSpec::parse_dependency("pkg-b", "workspace:^").unwrap();
    assert_eq!(dep_spec.name, "pkg-b");
    assert_eq!(dep_spec.target, PackageTarget::Workspace("^".to_string()));
}

#[test]
fn test_workspace_discovery() {
    use crate::workspace::discover_workspaces;
    use std::fs;
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let root = temp.path();

    let root_json = r#"{
        "name": "my-monorepo",
        "private": true,
        "workspaces": [
            "packages/*",
            "apps/**",
            "!packages/ignored"
        ]
    }"#;
    fs::write(root.join("package.json"), root_json).unwrap();

    // Create packages/pkg-a
    let pkg_a_dir = root.join("packages").join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Create packages/pkg-b
    let pkg_b_dir = root.join("packages").join("pkg-b");
    fs::create_dir_all(&pkg_b_dir).unwrap();
    fs::write(
        pkg_b_dir.join("package.json"),
        r#"{"name": "pkg-b", "version": "2.1.0", "dependencies": {"pkg-a": "workspace:*"}}"#,
    )
    .unwrap();

    // Create packages/ignored
    let ignored_dir = root.join("packages").join("ignored");
    fs::create_dir_all(&ignored_dir).unwrap();
    fs::write(
        ignored_dir.join("package.json"),
        r#"{"name": "ignored", "version": "0.0.1"}"#,
    )
    .unwrap();

    // Create apps/nested/app-1
    let app_1_dir = root.join("apps").join("nested").join("app-1");
    fs::create_dir_all(&app_1_dir).unwrap();
    fs::write(
        app_1_dir.join("package.json"),
        r#"{"name": "@myorg/app-1", "version": "0.1.0"}"#,
    )
    .unwrap();

    let members = discover_workspaces(root).unwrap();
    assert_eq!(members.len(), 3);

    let member_names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
    assert!(member_names.contains(&"pkg-a"));
    assert!(member_names.contains(&"pkg-b"));
    assert!(member_names.contains(&"@myorg/app-1"));
    assert!(!member_names.contains(&"ignored"));

    let pkg_b_member = members.iter().find(|m| m.name == "pkg-b").unwrap();
    assert_eq!(pkg_b_member.relative_path, "packages/pkg-b");
    assert_eq!(pkg_b_member.version.as_deref(), Some("2.1.0"));
    assert_eq!(
        pkg_b_member.manifest.dependencies.get("pkg-a").unwrap(),
        "workspace:*"
    );

    let app_1_member = members.iter().find(|m| m.name == "@myorg/app-1").unwrap();
    assert_eq!(app_1_member.relative_path, "apps/nested/app-1");
}

#[test]
fn test_workspace_discovery_duplicate_names_error() {
    use crate::error::WorkspaceError;
    use crate::workspace::discover_workspaces;
    use std::fs;
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let root = temp.path();

    fs::write(
        root.join("package.json"),
        r#"{"name": "root", "workspaces": ["packages/*"]}"#,
    )
    .unwrap();

    let d1 = root.join("packages").join("dir-1");
    let d2 = root.join("packages").join("dir-2");
    fs::create_dir_all(&d1).unwrap();
    fs::create_dir_all(&d2).unwrap();

    fs::write(
        d1.join("package.json"),
        r#"{"name": "conflict-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        d2.join("package.json"),
        r#"{"name": "conflict-pkg", "version": "2.0.0"}"#,
    )
    .unwrap();

    let result = discover_workspaces(root);
    assert!(result.is_err());
    match result.unwrap_err() {
        WorkspaceError::DuplicatePackage { name, .. } => {
            assert_eq!(name, "conflict-pkg");
        }
        other => panic!("Expected DuplicatePackage error, got: {:?}", other),
    }
}

#[test]
fn test_workspace_discovery_malformed_json_error() {
    use crate::error::WorkspaceError;
    use crate::workspace::discover_workspaces;
    use std::fs;
    use tempfile::tempdir;

    let temp = tempdir().unwrap();
    let root = temp.path();

    fs::write(
        root.join("package.json"),
        r#"{"name": "root", "workspaces": ["packages/*"]}"#,
    )
    .unwrap();

    let d = root.join("packages").join("broken");
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("package.json"), r#"{"name": "broken", invalid_json"#).unwrap();

    let result = discover_workspaces(root);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), WorkspaceError::Manifest(_)));
}

#[test]
fn test_semver_pathological_ranges_and_build_tags() {
    // 1. Wildcards: bare and partial
    let r_bare_star = Range::parse("*").unwrap();
    let r_bare_x = Range::parse("x").unwrap();
    let r_bare_cap_x = Range::parse("X").unwrap();
    let r_empty = Range::parse("").unwrap();
    let test_ver = Version::parse("3.14.159").unwrap();
    assert!(r_bare_star.satisfies(&test_ver));
    assert!(r_bare_x.satisfies(&test_ver));
    assert!(r_bare_cap_x.satisfies(&test_ver));
    assert!(r_empty.satisfies(&test_ver));

    let r_1_x = Range::parse("1.x").unwrap();
    let r_1_cap_x = Range::parse("1.X").unwrap();
    let r_1_star = Range::parse("1.*").unwrap();
    let v_1_5_0 = Version::parse("1.5.0").unwrap();
    let v_2_0_0 = Version::parse("2.0.0").unwrap();
    assert!(r_1_x.satisfies(&v_1_5_0));
    assert!(r_1_cap_x.satisfies(&v_1_5_0));
    assert!(r_1_star.satisfies(&v_1_5_0));
    assert!(!r_1_x.satisfies(&v_2_0_0));

    let r_1_2_star = Range::parse("1.2.*").unwrap();
    let r_1_2_x = Range::parse("1.2.x").unwrap();
    let r_1_2_cap_x = Range::parse("1.2.X").unwrap();
    let v_1_2_9 = Version::parse("1.2.9").unwrap();
    let v_1_3_0 = Version::parse("1.3.0").unwrap();
    assert!(r_1_2_star.satisfies(&v_1_2_9));
    assert!(r_1_2_x.satisfies(&v_1_2_9));
    assert!(r_1_2_cap_x.satisfies(&v_1_2_9));
    assert!(!r_1_2_star.satisfies(&v_1_3_0));

    // Multi-segment wildcards
    let r_xxx = Range::parse("x.x.x").unwrap();
    let r_stars = Range::parse("*.*.*").unwrap();
    assert!(r_xxx.satisfies(&v_1_5_0));
    assert!(r_stars.satisfies(&v_1_5_0));

    // 2. Build tags equality and precedence (SemVer 2.0.0)
    let v_b1 = Version::parse("1.0.0+build.1").unwrap();
    let v_b2 = Version::parse("1.0.0+build.2").unwrap();
    let v_plain = Version::parse("1.0.0").unwrap();
    assert_eq!(v_b1, v_b2);
    assert_eq!(v_b1, v_plain);
    assert_eq!(v_b1.cmp(&v_b2), std::cmp::Ordering::Equal);

    let v_next = Version::parse("1.0.1+exp.sha.123").unwrap();
    assert!(v_b1 < v_next);

    // Range matching with build tags in range and versions
    let r_caret_build = Range::parse("^1.2.3+build.1").unwrap();
    assert!(r_caret_build.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_caret_build.satisfies(&Version::parse("1.2.4+build.99").unwrap()));
    assert!(!r_caret_build.satisfies(&Version::parse("2.0.0").unwrap()));

    let r_hyphen_build = Range::parse("1.0.0+build1 - 2.0.0+build2").unwrap();
    assert!(r_hyphen_build.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r_hyphen_build.satisfies(&Version::parse("1.5.0+xyz").unwrap()));
    assert!(r_hyphen_build.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r_hyphen_build.satisfies(&Version::parse("2.0.1").unwrap()));

    // 3. Multi-hyphen ranges & multiple hyphens in prereleases
    let r_multi_hyphen = Range::parse("1.0.0 - 2.0.0 || 3.0.0 - 4.0.0 || 5.0.0 - 6.0.0").unwrap();
    assert!(r_multi_hyphen.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(!r_multi_hyphen.satisfies(&Version::parse("2.5.0").unwrap()));
    assert!(r_multi_hyphen.satisfies(&Version::parse("3.5.0").unwrap()));
    assert!(!r_multi_hyphen.satisfies(&Version::parse("4.5.0").unwrap()));
    assert!(r_multi_hyphen.satisfies(&Version::parse("5.5.0").unwrap()));

    let r_pre_hyphens = Range::parse("1.0.0-rc-1.0 - 2.0.0-rc-2.0").unwrap();
    let v_pre1 = Version::parse("1.0.0-rc-1.0").unwrap();
    let v_pre_mid = Version::parse("1.5.0").unwrap();
    let v_pre2 = Version::parse("2.0.0-rc-2.0").unwrap();
    assert!(r_pre_hyphens.satisfies(&v_pre1));
    assert!(r_pre_hyphens.satisfies(&v_pre_mid));
    assert!(r_pre_hyphens.satisfies(&v_pre2));

    let v_multi_dash = Version::parse("1.0.0-alpha-beta-gamma.1").unwrap();
    assert_eq!(v_multi_dash.to_string(), "1.0.0-alpha-beta-gamma.1");
    let r_multi_dash = Range::parse("^1.0.0-alpha-beta-gamma.1").unwrap();
    assert!(r_multi_dash.satisfies(&v_multi_dash));
}

#[test]
fn test_pathological_scoped_alias_targets() {
    // Scoped alias pointing to scoped package
    let s1 = PackageSpec::parse_dependency("@client/core", "npm:@infra/core@^2.1.0").unwrap();
    assert_eq!(s1.name, "@client/core");
    match s1.target {
        PackageTarget::Alias { name, target } => {
            assert_eq!(name, "@infra/core");
            assert!(matches!(*target, PackageTarget::Range(_)));
        }
        other => panic!("Expected Alias target, got: {:?}", other),
    }

    // Bare scoped alias (implicit latest)
    let s2 = PackageSpec::parse_dependency("local-helper", "npm:@company/helper").unwrap();
    assert_eq!(s2.name, "local-helper");
    match s2.target {
        PackageTarget::Alias { name, target } => {
            assert_eq!(name, "@company/helper");
            assert_eq!(*target, PackageTarget::Tag("latest".to_string()));
        }
        other => panic!("Expected Alias target, got: {:?}", other),
    }

    // Scoped alias with build tag
    let s3 = PackageSpec::parse_dependency("@alias/lib", "npm:@target/lib@1.2.3+sha.abc").unwrap();
    assert_eq!(s3.name, "@alias/lib");
    match s3.target {
        PackageTarget::Alias { name, target } => {
            assert_eq!(name, "@target/lib");
            assert!(matches!(*target, PackageTarget::Version(_)));
        }
        other => panic!("Expected Alias target, got: {:?}", other),
    }
}

#[test]
fn test_semver_loose_version_parsing() {
    // Partial versions defaulting missing minor/patch to 0
    let v1 = Version::parse_loose("1").unwrap();
    assert_eq!((v1.major, v1.minor, v1.patch), (1, 0, 0));
    assert!(v1.prerelease.is_empty());
    assert!(v1.build.is_empty());

    let v2 = Version::parse_loose("1.2").unwrap();
    assert_eq!((v2.major, v2.minor, v2.patch), (1, 2, 0));

    let v3 = Version::parse_loose("1.2.3").unwrap();
    assert_eq!((v3.major, v3.minor, v3.patch), (1, 2, 3));

    // Prefixes "v", "V", "=", and extra whitespace
    let v_v = Version::parse_loose("v1").unwrap();
    assert_eq!(v_v, v1);

    let v_cap_v = Version::parse_loose("V1.2").unwrap();
    assert_eq!(v_cap_v, v2);

    let v_eq = Version::parse_loose("=1.2.3").unwrap();
    assert_eq!(v_eq, v3);

    let v_messy = Version::parse_loose("   =  v  1.2   ").unwrap();
    assert_eq!(v_messy, v2);

    // Prerelease on partial versions
    let v_pre1 = Version::parse_loose("1-alpha.1").unwrap();
    assert_eq!((v_pre1.major, v_pre1.minor, v_pre1.patch), (1, 0, 0));
    assert_eq!(
        v_pre1.prerelease,
        vec![
            PrereleaseId::Alpha("alpha".to_string()),
            PrereleaseId::Numeric(1)
        ]
    );

    let v_pre2 = Version::parse_loose("v1.2-beta.2+build.99").unwrap();
    assert_eq!((v_pre2.major, v_pre2.minor, v_pre2.patch), (1, 2, 0));
    assert_eq!(
        v_pre2.prerelease,
        vec![
            PrereleaseId::Alpha("beta".to_string()),
            PrereleaseId::Numeric(2)
        ]
    );
    assert_eq!(v_pre2.build, vec!["build".to_string(), "99".to_string()]);

    // Build metadata on partial version
    let v_build = Version::parse_loose("2+build-metadata.1").unwrap();
    assert_eq!((v_build.major, v_build.minor, v_build.patch), (2, 0, 0));
    assert_eq!(
        v_build.build,
        vec!["build-metadata".to_string(), "1".to_string()]
    );

    // Negative tests for invalid versions
    assert!(Version::parse_loose("").is_err());
    assert!(Version::parse_loose("   ").is_err());
    assert!(Version::parse_loose("abc").is_err());
    assert!(Version::parse_loose("1.2.3.4").is_err());
    assert!(Version::parse_loose("1.2.3-").is_err());
}

#[test]
fn test_semver_hyphen_ranges_comprehensive() {
    // 1. '1.2.3 - 2.3.4' -> >=1.2.3 <=2.3.4
    let r1 = Range::parse("1.2.3 - 2.3.4").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.3.0").unwrap()));
    assert!(r1.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(!r1.satisfies(&Version::parse("2.3.5").unwrap()));

    // 2. '1.2 - 2.3.4' -> >=1.2.0 <=2.3.4
    let r2 = Range::parse("1.2 - 2.3.4").unwrap();
    assert!(r2.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("1.2.1").unwrap()));
    assert!(r2.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r2.satisfies(&Version::parse("1.1.9").unwrap()));
    assert!(!r2.satisfies(&Version::parse("2.3.5").unwrap()));

    // 3. '1.2.3 - 2' -> >=1.2.3 <3.0.0-0
    let r3 = Range::parse("1.2.3 - 2").unwrap();
    assert!(r3.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r3.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r3.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r3.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(!r3.satisfies(&Version::parse("3.0.0").unwrap()));
    assert!(!r3.satisfies(&Version::parse("3.0.0-0").unwrap()));
    assert!(!r3.satisfies(&Version::parse("3.0.0-alpha").unwrap()));

    // 4. '1.2 - 2' -> >=1.2.0 <3.0.0-0
    let r4 = Range::parse("1.2 - 2").unwrap();
    assert!(r4.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r4.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r4.satisfies(&Version::parse("2.99.99").unwrap()));
    assert!(!r4.satisfies(&Version::parse("1.1.9").unwrap()));
    assert!(!r4.satisfies(&Version::parse("3.0.0").unwrap()));
    assert!(!r4.satisfies(&Version::parse("3.0.0-alpha").unwrap()));

    // 5. '1.2.3 - *' -> >=1.2.3
    let r5 = Range::parse("1.2.3 - *").unwrap();
    assert!(r5.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r5.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r5.satisfies(&Version::parse("99.0.0").unwrap()));
    assert!(!r5.satisfies(&Version::parse("1.2.2").unwrap()));

    // Additional hyphen range combinations
    // '1.2.3 - 2.3' -> >=1.2.3 <2.4.0-0
    let r6 = Range::parse("1.2.3 - 2.3").unwrap();
    assert!(r6.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r6.satisfies(&Version::parse("2.3.0").unwrap()));
    assert!(r6.satisfies(&Version::parse("2.3.9").unwrap()));
    assert!(!r6.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(!r6.satisfies(&Version::parse("2.4.0").unwrap()));
    assert!(!r6.satisfies(&Version::parse("2.4.0-0").unwrap()));

    // '1 - 2' -> >=1.0.0 <3.0.0-0
    let r7 = Range::parse("1 - 2").unwrap();
    assert!(r7.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r7.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(r7.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r7.satisfies(&Version::parse("0.9.9").unwrap()));
    assert!(!r7.satisfies(&Version::parse("3.0.0").unwrap()));

    // '* - 2.3.4' -> >=0.0.0 <=2.3.4
    let r8 = Range::parse("* - 2.3.4").unwrap();
    assert!(r8.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r8.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r8.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r8.satisfies(&Version::parse("2.3.5").unwrap()));

    // '* - *' -> >=0.0.0
    let r9 = Range::parse("* - *").unwrap();
    assert!(r9.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r9.satisfies(&Version::parse("99.9.9").unwrap()));

    // Hyphen range with prereleases
    let r10 = Range::parse("1.0.0-alpha.1 - 2.0.0").unwrap();
    assert!(r10.satisfies(&Version::parse("1.0.0-alpha.1").unwrap()));
    assert!(r10.satisfies(&Version::parse("1.0.0-alpha.2").unwrap()));
    assert!(r10.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(r10.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r10.satisfies(&Version::parse("1.0.0-alpha.0").unwrap()));
    assert!(!r10.satisfies(&Version::parse("2.0.1").unwrap()));
}

#[test]
fn test_semver_prerelease_precedence_deep() {
    // 1. Exact node-semver requirement chain:
    // 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
    let v_alpha1 = Version::parse("1.0.0-alpha.1").unwrap();
    let v_alpha_beta = Version::parse("1.0.0-alpha.beta").unwrap();
    let v_beta = Version::parse("1.0.0-beta").unwrap();
    let v_beta2 = Version::parse("1.0.0-beta.2").unwrap();
    let v_beta11 = Version::parse("1.0.0-beta.11").unwrap();
    let v_rc1 = Version::parse("1.0.0-rc.1").unwrap();
    let v_final = Version::parse("1.0.0").unwrap();

    assert!(v_alpha1 < v_alpha_beta);
    assert!(v_alpha_beta < v_beta);
    assert!(v_beta < v_beta2);
    assert!(v_beta2 < v_beta11);
    assert!(v_beta11 < v_rc1);
    assert!(v_rc1 < v_final);

    // 2. Numeric vs numeric: 2 < 11 numerically (unlike lexical ASCII where "11" < "2")
    assert_eq!(v_beta2.cmp(&v_beta11), std::cmp::Ordering::Less);
    let v_0 = Version::parse("1.0.0-0").unwrap();
    let v_1 = Version::parse("1.0.0-1").unwrap();
    assert!(v_0 < v_1);

    // 3. Numeric vs alphanumeric: numeric identifiers always lower precedence than alphanumeric
    let v_num = Version::parse("1.0.0-999999").unwrap();
    let v_alph = Version::parse("1.0.0-a").unwrap();
    assert!(v_num < v_alph);

    let v_dot_num = Version::parse("1.0.0-alpha.1").unwrap();
    let v_dot_alph = Version::parse("1.0.0-alpha.a").unwrap();
    assert!(v_dot_num < v_dot_alph);

    // 4. Dot component count precedence (larger set has higher precedence when prefixes equal)
    let v_a = Version::parse("1.0.0-alpha").unwrap();
    assert!(v_a < v_alpha1);
    let v_alpha11 = Version::parse("1.0.0-alpha.1.1").unwrap();
    assert!(v_alpha1 < v_alpha11);

    // 5. Normal versions always higher precedence than prereleases of same tuple
    assert!(Version::parse("1.0.0-zzzzzz").unwrap() < Version::parse("1.0.0").unwrap());

    // 6. Major / minor / patch precedence takes priority over prerelease
    assert!(Version::parse("0.9.9").unwrap() < Version::parse("1.0.0-alpha").unwrap());
    assert!(Version::parse("1.0.0-alpha").unwrap() < Version::parse("1.0.1").unwrap());
    assert!(Version::parse("1.0.0").unwrap() < Version::parse("1.1.0-alpha").unwrap());
    assert!(Version::parse("1.0.0-rc.9").unwrap() < Version::parse("2.0.0-alpha.1").unwrap());
}

#[test]
fn test_semver_caret_0x_and_00x_rules() {
    // ^0.2.3 matches >=0.2.3 <0.3.0-0
    let r_0_2_3 = Range::parse("^0.2.3").unwrap();
    assert!(r_0_2_3.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r_0_2_3.satisfies(&Version::parse("0.2.4").unwrap()));
    assert!(r_0_2_3.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_0_2_3.satisfies(&Version::parse("0.2.2").unwrap()));
    assert!(!r_0_2_3.satisfies(&Version::parse("0.3.0").unwrap()));
    assert!(!r_0_2_3.satisfies(&Version::parse("0.3.0-0").unwrap()));
    assert!(!r_0_2_3.satisfies(&Version::parse("0.3.0-alpha").unwrap()));
    assert!(!r_0_2_3.satisfies(&Version::parse("0.2.4-alpha").unwrap()));

    // ^0.0.3 matches >=0.0.3 <0.0.4-0
    let r_0_0_3 = Range::parse("^0.0.3").unwrap();
    assert!(r_0_0_3.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(r_0_0_3.satisfies(&Version::parse("0.0.3+build.1").unwrap()));
    assert!(!r_0_0_3.satisfies(&Version::parse("0.0.2").unwrap()));
    assert!(!r_0_0_3.satisfies(&Version::parse("0.0.4").unwrap()));
    assert!(!r_0_0_3.satisfies(&Version::parse("0.0.4-0").unwrap()));
    assert!(!r_0_0_3.satisfies(&Version::parse("0.0.4-alpha").unwrap()));

    // ^0.0 matches >=0.0.0 <0.1.0-0
    let r_0_0 = Range::parse("^0.0").unwrap();
    assert!(r_0_0.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_0_0.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(r_0_0.satisfies(&Version::parse("0.0.99").unwrap()));
    assert!(!r_0_0.satisfies(&Version::parse("0.1.0").unwrap()));
    assert!(!r_0_0.satisfies(&Version::parse("0.1.0-0").unwrap()));
    assert!(!r_0_0.satisfies(&Version::parse("0.1.0-alpha").unwrap()));

    // ^0 matches >=0.0.0 <1.0.0-0
    let r_0 = Range::parse("^0").unwrap();
    assert!(r_0.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_0.satisfies(&Version::parse("0.1.0").unwrap()));
    assert!(r_0.satisfies(&Version::parse("0.99.99").unwrap()));
    assert!(!r_0.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(!r_0.satisfies(&Version::parse("1.0.0-0").unwrap()));
    assert!(!r_0.satisfies(&Version::parse("1.0.0-alpha").unwrap()));

    // Variations: ^0.x, ^0.0.x, ^0.2.x, ^0.2, ^0.0.0
    let r_0_x = Range::parse("^0.x").unwrap();
    assert!(r_0_x.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_0_x.satisfies(&Version::parse("0.9.9").unwrap()));
    assert!(!r_0_x.satisfies(&Version::parse("1.0.0").unwrap()));

    let r_0_0_x = Range::parse("^0.0.x").unwrap();
    assert!(r_0_0_x.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_0_0_x.satisfies(&Version::parse("0.0.9").unwrap()));
    assert!(!r_0_0_x.satisfies(&Version::parse("0.1.0").unwrap()));

    let r_0_2_x = Range::parse("^0.2.x").unwrap();
    assert!(r_0_2_x.satisfies(&Version::parse("0.2.0").unwrap()));
    assert!(r_0_2_x.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_0_2_x.satisfies(&Version::parse("0.3.0").unwrap()));

    let r_0_2 = Range::parse("^0.2").unwrap();
    assert!(r_0_2.satisfies(&Version::parse("0.2.0").unwrap()));
    assert!(r_0_2.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_0_2.satisfies(&Version::parse("0.3.0").unwrap()));

    let r_0_0_0 = Range::parse("^0.0.0").unwrap();
    assert!(r_0_0_0.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(!r_0_0_0.satisfies(&Version::parse("0.0.1").unwrap()));
}

#[test]
fn test_semver_operator_spaces_and_comparator_combos() {
    // Spaces between operators and versions
    let r_gt_space = Range::parse("> 1.2.3").unwrap();
    assert!(r_gt_space.satisfies(&Version::parse("1.2.4").unwrap()));
    assert!(!r_gt_space.satisfies(&Version::parse("1.2.3").unwrap()));

    let r_gte_lt_space = Range::parse(">= 1.2.3 < 2.0.0").unwrap();
    assert!(r_gte_lt_space.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_gte_lt_space.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r_gte_lt_space.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(!r_gte_lt_space.satisfies(&Version::parse("2.0.0").unwrap()));

    let r_split_op = Range::parse("> = 1.2.3 < = 2.0.0").unwrap();
    assert!(r_split_op.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_split_op.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r_split_op.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(!r_split_op.satisfies(&Version::parse("2.0.1").unwrap()));

    let r_tilde_space = Range::parse("~ 1.2.3").unwrap();
    assert!(r_tilde_space.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_tilde_space.satisfies(&Version::parse("1.2.9").unwrap()));
    assert!(!r_tilde_space.satisfies(&Version::parse("1.3.0").unwrap()));

    let r_tilde_gt = Range::parse("~> 1.2.3").unwrap();
    assert!(r_tilde_gt.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r_tilde_gt.satisfies(&Version::parse("1.2.9").unwrap()));
    assert!(!r_tilde_gt.satisfies(&Version::parse("1.3.0").unwrap()));

    let r_caret_space = Range::parse("^ 0.2.3").unwrap();
    assert!(r_caret_space.satisfies(&Version::parse("0.2.3").unwrap()));
    assert!(r_caret_space.satisfies(&Version::parse("0.2.9").unwrap()));
    assert!(!r_caret_space.satisfies(&Version::parse("0.3.0").unwrap()));

    let r_eq_space = Range::parse("= 1.2.3").unwrap();
    assert!(r_eq_space.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(!r_eq_space.satisfies(&Version::parse("1.2.4").unwrap()));

    // Comparator::parse tests
    let c1 = Comparator::parse(">= 1").unwrap();
    assert_eq!(c1.op, Op::Gte);
    assert_eq!(c1.version, Version::new(1, 0, 0));

    let c2 = Comparator::parse("<= 1.2").unwrap();
    assert_eq!(c2.op, Op::Lte);
    assert_eq!(c2.version, Version::new(1, 2, 0));

    let c3 = Comparator::parse("= 2").unwrap();
    assert_eq!(c3.op, Op::Eq);
    assert_eq!(c3.version, Version::new(2, 0, 0));
}

#[test]
fn test_semver_node_semver_official_fixtures() {
    // Official test fixtures from node-semver repository
    // Tilde ranges
    let r_tilde1 = Range::parse("~1.2.2").unwrap();
    assert!(r_tilde1.satisfies(&Version::parse("1.2.2").unwrap()));
    assert!(r_tilde1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(!r_tilde1.satisfies(&Version::parse("1.2.1").unwrap()));
    assert!(!r_tilde1.satisfies(&Version::parse("1.3.0").unwrap()));

    let r_tilde2 = Range::parse("~1.2").unwrap();
    assert!(r_tilde2.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r_tilde2.satisfies(&Version::parse("1.2.9").unwrap()));
    assert!(!r_tilde2.satisfies(&Version::parse("1.1.9").unwrap()));
    assert!(!r_tilde2.satisfies(&Version::parse("1.3.0").unwrap()));

    let r_tilde3 = Range::parse("~1").unwrap();
    assert!(r_tilde3.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r_tilde3.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r_tilde3.satisfies(&Version::parse("0.9.9").unwrap()));
    assert!(!r_tilde3.satisfies(&Version::parse("2.0.0").unwrap()));

    let r_tilde4 = Range::parse("~0.2").unwrap();
    assert!(r_tilde4.satisfies(&Version::parse("0.2.0").unwrap()));
    assert!(r_tilde4.satisfies(&Version::parse("0.2.5").unwrap()));
    assert!(!r_tilde4.satisfies(&Version::parse("0.1.9").unwrap()));
    assert!(!r_tilde4.satisfies(&Version::parse("0.3.0").unwrap()));

    let r_tilde5 = Range::parse("~0.0.3").unwrap();
    assert!(r_tilde5.satisfies(&Version::parse("0.0.3").unwrap()));
    assert!(r_tilde5.satisfies(&Version::parse("0.0.4").unwrap()));
    assert!(!r_tilde5.satisfies(&Version::parse("0.1.0").unwrap()));

    // Range union ||
    let r_or = Range::parse("<1.0.0 || >=2.0.0").unwrap();
    assert!(r_or.satisfies(&Version::parse("0.5.0").unwrap()));
    assert!(r_or.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_or.satisfies(&Version::parse("3.0.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(!r_or.satisfies(&Version::parse("1.5.0").unwrap()));

    // Multi-segment wildcards
    let r_2xx = Range::parse("2.x.x").unwrap();
    assert!(r_2xx.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_2xx.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r_2xx.satisfies(&Version::parse("1.9.9").unwrap()));
    assert!(!r_2xx.satisfies(&Version::parse("3.0.0").unwrap()));

    let r_2star = Range::parse("2.*.*").unwrap();
    assert!(r_2star.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r_2star.satisfies(&Version::parse("2.5.0").unwrap()));
    assert!(!r_2star.satisfies(&Version::parse("3.0.0").unwrap()));

    // Strict node-semver prerelease matching:
    // A version with a prerelease is rejected unless the comparator explicitly allows prerelease on tuple
    let r_strict_pre = Range::parse(">=1.0.0 <2.0.0").unwrap();
    assert!(!r_strict_pre.satisfies(&Version::parse("1.5.0-alpha").unwrap()));
    assert!(!r_strict_pre.satisfies(&Version::parse("2.0.0-alpha").unwrap()));

    let r_star = Range::parse("*").unwrap();
    assert!(!r_star.satisfies(&Version::parse("1.0.0-alpha").unwrap()));
    assert!(r_star.satisfies(&Version::parse("1.0.0").unwrap()));
}

#[test]
fn test_semver_integer_overflow_prevention() {
    let overflow_ranges = [
        format!("^{}.0.0", u64::MAX),
        format!("^0.{}.0", u64::MAX),
        format!("^0.0.{}", u64::MAX),
        format!("~{}", u64::MAX),
        format!("~{}.x", u64::MAX),
        format!("~1.{}.0", u64::MAX),
        format!("~{}.{}.0", u64::MAX, u64::MAX),
        format!("{}.x", u64::MAX),
        format!("1.{}.x", u64::MAX),
        format!("={}.x", u64::MAX),
        format!("=1.{}.x", u64::MAX),
        format!(">{}.x", u64::MAX),
        format!(">1.{}.x", u64::MAX),
        format!("<={}.x", u64::MAX),
        format!("<=1.{}.x", u64::MAX),
        format!("1.0.0 - {}", u64::MAX),
        format!("1.0.0 - 1.{}", u64::MAX),
    ];

    for r_str in &overflow_ranges {
        let res = Range::parse(r_str);
        assert!(
            res.is_err(),
            "Expected overflow error for range '{r_str}', but got: {res:?}"
        );
        match res.unwrap_err() {
            SemverError::InvalidRange(msg) => {
                assert!(
                    msg.contains("Version number overflow:"),
                    "Expected message to contain 'Version number overflow:', got: '{msg}'"
                );
            }
            other => panic!("Expected SemverError::InvalidRange, got {other:?}"),
        }
    }
}

#[test]
fn test_semver_wildcard_operators_and_hyphen() {
    let wildcards = [
        "*", "x", "X", "=*", "= *", "=x", "=X", "<= *", "<=* ", "<=x", "<=X",
    ];
    let test_versions = ["0.0.0", "1.0.0", "1.2.3", "99.99.99"];

    for w in &wildcards {
        let r = Range::parse(w).unwrap_or_else(|e| panic!("Failed to parse wildcard '{w}': {e}"));
        for v_str in &test_versions {
            let v = Version::parse(v_str).unwrap();
            assert!(
                r.satisfies(&v),
                "Wildcard range '{w}' should satisfy '{v_str}'"
            );
        }
    }

    // Hyphen range with wildcards: * - 2.0.0
    let r_star_hyphen = Range::parse("* - 2.0.0").unwrap();
    assert!(r_star_hyphen.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_star_hyphen.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(r_star_hyphen.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(!r_star_hyphen.satisfies(&Version::parse("2.0.1").unwrap()));
    assert!(!r_star_hyphen.satisfies(&Version::parse("3.0.0").unwrap()));

    // Hyphen range: * - *
    let r_star_star = Range::parse("* - *").unwrap();
    assert!(r_star_star.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_star_star.satisfies(&Version::parse("5.0.0").unwrap()));

    // Hyphen range: 1.0.0 - *
    let r_star_upper = Range::parse("1.0.0 - *").unwrap();
    assert!(!r_star_upper.satisfies(&Version::parse("0.9.9").unwrap()));
    assert!(r_star_upper.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r_star_upper.satisfies(&Version::parse("5.0.0").unwrap()));
}

#[test]
fn test_semver_reject_bare_operators() {
    let bare_ops = [
        ">", "<", "=", ">=", "<=", "~", "^", "~>", "> =", "< =", "> || <", "1.0.0 >", "1.0.0 <",
        "1.0.0 =",
    ];

    for op in &bare_ops {
        let res = Range::parse(op);
        assert!(
            res.is_err(),
            "Expected bare operator '{op}' to be rejected, but got: {res:?}"
        );
        match res.unwrap_err() {
            SemverError::InvalidRange(_) => {}
            other => panic!("Expected SemverError::InvalidRange for '{op}', got {other:?}"),
        }
    }
}

#[test]
fn test_semver_reject_trailing_empty_prerelease_and_segments() {
    let invalid_pre = [
        "1.0.0-",
        "1.0.0-.",
        "^1.0.0-",
        "~1.0.0-",
        ">=1.0.0-",
        "1.0.0-alpha.",
        "1.0.0-..1",
    ];

    for r_str in &invalid_pre {
        let res = Range::parse(r_str);
        assert!(
            res.is_err(),
            "Expected invalid prerelease '{r_str}' to be rejected, got: {res:?}"
        );
    }
    assert!(Version::parse("1.0.0-").is_err());
    assert!(Version::parse_loose("1.0.0-").is_err());

    let invalid_segments = [
        "1.2.3.4",
        "^1.2.3.4",
        "~1.2.3.4",
        ">=1.2.3.4",
        "1.2.3.4.5",
        "1.0.0 - 1.2.3.4",
    ];

    for r_str in &invalid_segments {
        let res = Range::parse(r_str);
        assert!(
            res.is_err(),
            "Expected 4+ segments '{r_str}' to be rejected, got: {res:?}"
        );
    }
    assert!(Version::parse("1.2.3.4").is_err());
    assert!(Version::parse_loose("1.2.3.4").is_err());
}

#[test]
fn test_semver_pathological_fragmented_range_unions() {
    let range_str = ">1.0.0 <=1.2.0 || >1.3.0 <=1.4.0 || >=2.0.0-0 <3.0.0-0";
    let r = Range::parse(range_str).unwrap();

    // Check boundary matches
    assert!(!r.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r.satisfies(&Version::parse("1.1.0").unwrap()));
    assert!(r.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(!r.satisfies(&Version::parse("1.2.1").unwrap()));
    assert!(!r.satisfies(&Version::parse("1.3.0").unwrap()));
    assert!(r.satisfies(&Version::parse("1.3.5").unwrap()));
    assert!(r.satisfies(&Version::parse("1.4.0").unwrap()));
    assert!(!r.satisfies(&Version::parse("1.5.0").unwrap()));
    assert!(r.satisfies(&Version::parse("2.0.0-0").unwrap()));
    assert!(r.satisfies(&Version::parse("2.0.0-alpha.1").unwrap()));
    assert!(r.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r.satisfies(&Version::parse("3.0.0-0").unwrap()));
    assert!(!r.satisfies(&Version::parse("3.0.0").unwrap()));
}

#[test]
fn test_semver_zero_version_cascades() {
    // ^0.0.1 := >=0.0.1 <0.0.2-0
    let r1 = Range::parse("^0.0.1").unwrap();
    assert!(r1.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(!r1.satisfies(&Version::parse("0.0.2").unwrap()));
    assert!(!r1.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(!r1.satisfies(&Version::parse("0.1.0").unwrap()));

    // ^0.1.0 := >=0.1.0 <0.2.0-0
    let r2 = Range::parse("^0.1.0").unwrap();
    assert!(r2.satisfies(&Version::parse("0.1.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("0.1.5").unwrap()));
    assert!(!r2.satisfies(&Version::parse("0.2.0").unwrap()));
    assert!(!r2.satisfies(&Version::parse("0.0.9").unwrap()));

    // ~0.0.4 := >=0.0.4 <0.1.0-0
    let r3 = Range::parse("~0.0.4").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.4").unwrap()));
    assert!(r3.satisfies(&Version::parse("0.0.9").unwrap()));
    assert!(!r3.satisfies(&Version::parse("0.1.0").unwrap()));
    assert!(!r3.satisfies(&Version::parse("0.0.3").unwrap()));
}
#[test]
fn file_specs_normalize_relative_current_directory_components() {
    use crate::spec::{PackageSpec, PackageTarget};
    for input in ["file:./realname-1.0.0.tgz", "alias@file:./realname-1.0.0.tgz"] {
        let spec = PackageSpec::parse(input).unwrap();
        assert_eq!(spec.target, PackageTarget::File("realname-1.0.0.tgz".into()));
    }
    assert_eq!(PackageTarget::parse("file:../sibling.tgz").unwrap(), PackageTarget::File("../sibling.tgz".into()));
    assert_eq!(PackageTarget::parse("file:x").unwrap(), PackageTarget::File("x".into()));
    assert_eq!(PackageTarget::parse("file:./x").unwrap(), PackageTarget::File("x".into()));
    #[cfg(windows)]
    {
        assert_eq!(
            PackageTarget::parse("file:///C:/packages/foo").unwrap(),
            PackageTarget::File(std::path::PathBuf::from(r"C:\packages\foo"))
        );
        assert_eq!(
            PackageTarget::parse("file://localhost/C:/packages/foo").unwrap(),
            PackageTarget::File(std::path::PathBuf::from(r"C:\packages\foo"))
        );
    }
    #[cfg(not(windows))]
    {
        assert_eq!(
            PackageTarget::parse("file:///packages/foo").unwrap(),
            PackageTarget::File(std::path::PathBuf::from("/packages/foo"))
        );
    }
}

#[test]
fn test_manifest_compact_single_line_roundtrip() {
    let single_line = r#"{"name":"compact-pkg","version":"1.0.0","dependencies":{"react":"^18.2.0"}}"#;
    let manifest = Manifest::from_str(single_line).unwrap();
    assert_eq!(manifest.format.indent, "");
    assert_eq!(manifest.format.newline, "");
    let serialized = manifest.to_json_string().unwrap();
    assert_eq!(serialized, single_line);
}

