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
            subdir: None,
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
            subdir: None,
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
fn test_git_spec_path_subdirectory_support() {
    // 1. #path:<subdir> without committish
    let t1 = PackageTarget::parse("github:user/repo#path:packages/foo").unwrap();
    assert_eq!(t1.git_committish(), None);
    assert_eq!(t1.git_subdir(), Some("packages/foo"));
    assert_eq!(t1.git_path(), Some("packages/foo"));
    assert_eq!(t1.to_string(), "github:user/repo#path:packages/foo");
    assert_eq!(PackageTarget::parse(&t1.to_string()).unwrap(), t1);

    // 2. #<committish>::path:<subdir>
    let t2 = PackageTarget::parse(
        "git+https://github.com/org/repo.git#v1.0.0::path:packages/bar",
    )
    .unwrap();
    assert_eq!(t2.git_committish(), Some("v1.0.0"));
    assert_eq!(t2.git_subdir(), Some("packages/bar"));
    assert_eq!(t2.git_path(), Some("packages/bar"));
    assert_eq!(
        t2.to_string(),
        "git+https://github.com/org/repo.git#v1.0.0::path:packages/bar"
    );
    assert_eq!(PackageTarget::parse(&t2.to_string()).unwrap(), t2);

    // 3. git+file with #path:
    let t3 = PackageTarget::parse("git+file:///path/to/repo#path:nested/pkg").unwrap();
    assert_eq!(t3.git_committish(), None);
    assert_eq!(t3.git_subdir(), Some("nested/pkg"));
    assert_eq!(t3.git_clone_url().unwrap(), "file:///path/to/repo");

    // 4. git+file with #branch::path:
    let t4 = PackageTarget::parse("git+file:///path/to/repo#main::path:nested/pkg").unwrap();
    assert_eq!(t4.git_committish(), Some("main"));
    assert_eq!(t4.git_subdir(), Some("nested/pkg"));

    // 5. Semver committish with ::path:
    let t5 = PackageTarget::parse(
        "git+ssh://git@github.com/org/repo.git#semver:^1.0.0::path:packages/core",
    )
    .unwrap();
    assert_eq!(t5.git_committish(), Some("semver:^1.0.0"));
    assert_eq!(t5.git_subdir(), Some("packages/core"));

    // 6. PackageSpec parsing with #path:
    let spec1 = PackageSpec::parse("git+https://github.com/org/repo.git#path:packages/foo").unwrap();
    assert_eq!(spec1.target.git_subdir(), Some("packages/foo"));
    assert_eq!(spec1.target.git_committish(), None);

    let spec2 = PackageSpec::parse_dependency(
        "my-sub-pkg",
        "github:user/repo#main::path:packages/my-sub-pkg",
    )
    .unwrap();
    assert_eq!(spec2.name, "my-sub-pkg");
    assert_eq!(spec2.target.git_committish(), Some("main"));
    assert_eq!(spec2.target.git_subdir(), Some("packages/my-sub-pkg"));
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
fn test_path_matches_workspace_patterns_semantics() {
    use crate::workspace::path_matches_workspace_patterns;

    let patterns = vec![
        "packages/*".to_string(),
        "apps/**".to_string(),
        "modules/**/pkg".to_string(),
        "tools/cli".to_string(),
        "!packages/ignored".to_string(),
        "!apps/ignored-app/**".to_string(),
    ];

    // Single wildcard
    assert!(path_matches_workspace_patterns("packages/pkg-a", &patterns));
    assert!(path_matches_workspace_patterns("packages/pkg-b", &patterns));
    assert!(!path_matches_workspace_patterns("packages", &patterns));
    assert!(!path_matches_workspace_patterns("packages/nested/pkg", &patterns));

    // Recursive trailing wildcard
    assert!(path_matches_workspace_patterns("apps/web", &patterns));
    assert!(path_matches_workspace_patterns("apps/web/client", &patterns));

    // Non-trailing ** (Round 1 Finding 4 parity)
    assert!(path_matches_workspace_patterns("modules/pkg", &patterns)); // 0 levels
    assert!(path_matches_workspace_patterns("modules/a/pkg", &patterns)); // 1 level
    assert!(path_matches_workspace_patterns("modules/a/b/c/pkg", &patterns)); // multi level
    assert!(!path_matches_workspace_patterns("modules/a/b/other", &patterns));

    // Exact match
    assert!(path_matches_workspace_patterns("tools/cli", &patterns));
    assert!(!path_matches_workspace_patterns("tools/other", &patterns));

    // Negative exclusions
    assert!(!path_matches_workspace_patterns("packages/ignored", &patterns));
    assert!(!path_matches_workspace_patterns("apps/ignored-app/sub", &patterns));

    // Disallowed directory segments (node_modules, dot-dirs under wildcards),
    // while build/dist/target remain valid workspace package names.
    assert!(!path_matches_workspace_patterns("packages/pkg-a/node_modules/dep", &patterns));
    assert!(!path_matches_workspace_patterns("node_modules/pkg-a", &patterns));
    assert!(!path_matches_workspace_patterns("apps/.hidden/client", &patterns));
    assert!(path_matches_workspace_patterns("apps/target/client", &patterns));
    assert!(path_matches_workspace_patterns("packages/build", &patterns));
    assert!(path_matches_workspace_patterns("packages/dist", &patterns));

    // Path normalization
    assert!(path_matches_workspace_patterns("./packages/pkg-a", &patterns));
    assert!(path_matches_workspace_patterns("packages\\pkg-a", &patterns));
    assert!(path_matches_workspace_patterns("packages/pkg-a/", &patterns));
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
    for input in [
        "file:./realname-1.0.0.tgz",
        "alias@file:./realname-1.0.0.tgz",
    ] {
        let spec = PackageSpec::parse(input).unwrap();
        assert_eq!(
            spec.target,
            PackageTarget::File("realname-1.0.0.tgz".into())
        );
    }
    assert_eq!(
        PackageTarget::parse("file:../sibling.tgz").unwrap(),
        PackageTarget::File("../sibling.tgz".into())
    );
    assert_eq!(
        PackageTarget::parse("file:x").unwrap(),
        PackageTarget::File("x".into())
    );
    assert_eq!(
        PackageTarget::parse("file:./x").unwrap(),
        PackageTarget::File("x".into())
    );
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
    let single_line =
        r#"{"name":"compact-pkg","version":"1.0.0","dependencies":{"react":"^18.2.0"}}"#;
    let manifest = Manifest::from_str(single_line).unwrap();
    assert_eq!(manifest.format.indent, "");
    assert_eq!(manifest.format.newline, "");
    let serialized = manifest.to_json_string().unwrap();
    assert_eq!(serialized, single_line);
}

#[test]
fn test_hyphen_range_with_partial_upper_is_not_a_version() {
    use crate::semver::Version;
    use crate::spec::PackageTarget;
    assert!(Version::parse("2.5.0 - 3").is_err());
    match PackageTarget::parse("2.5.0 - 3").unwrap() {
        PackageTarget::Range(range) => {
            assert!(range.satisfies(&Version::parse("3.2.4").unwrap()));
            assert!(!range.satisfies(&Version::parse("4.0.0").unwrap()));
        }
        other => panic!("expected a range, got {other:?}"),
    }
}

#[test]
fn test_semver_inc_overflow_protection() {
    let max_v = Version::new(u64::MAX, 0, 0);
    assert!(max_v.inc("major", None).is_err());

    let max_patch = Version::new(1, 0, u64::MAX);
    assert!(max_patch.inc("patch", None).is_err());
}

#[test]
fn test_semver_parse_loose_prerelease_leading_zero() {
    // In strict mode, leading zeroes in numeric prereleases are rejected
    assert!(Version::parse("1.2.3-01").is_err());

    // In loose mode, leading zeroes parse as numeric, preserving numeric comparison
    let v_loose = Version::parse_loose("1.2.3-01").unwrap();
    assert_eq!(v_loose.major, 1);
    assert_eq!(v_loose.minor, 2);
    assert_eq!(v_loose.patch, 3);
    assert_eq!(v_loose.prerelease.len(), 1);
    assert_eq!(v_loose.prerelease[0], crate::semver::version::PrereleaseId::Numeric(1));
}

#[test]
fn test_spec_gist_and_git_protocols() {
    let spec_gist = PackageSpec::parse("gist:123456#main").unwrap();
    assert_eq!(spec_gist.name, "123456");
    assert_eq!(
        spec_gist.target.git_clone_url(),
        Some("https://gist.github.com/123456.git".to_string())
    );
    assert_eq!(spec_gist.target.git_committish(), Some("main"));

    let spec_rsync = PackageSpec::parse("git+rsync://example.com/repo.git").unwrap();
    assert_eq!(spec_rsync.name, "repo");
    assert_eq!(
        spec_rsync.target.git_clone_url(),
        Some("rsync://example.com/repo.git".to_string())
    );
}

#[test]
fn test_package_target_helpers() {
    let file_target = PackageTarget::File(std::path::PathBuf::from("local-pkg.tgz"));
    assert!(file_target.is_file());
    assert!(file_target.is_tarball_archive());
    assert_eq!(
        file_target.file_path(),
        Some(std::path::Path::new("local-pkg.tgz"))
    );

    let url_target = PackageTarget::Url(url::Url::parse("https://cdn.example.com/pkg.tgz").unwrap());
    assert!(url_target.is_url());
    assert!(url_target.is_tarball_archive());
    assert!(!url_target.is_file());
}

#[test]
fn test_manifest_files_string_and_array() {
    // 'files' as single string in package.json
    let json_str_files = r#"{"name":"test-pkg","version":"1.0.0","files":"dist"}"#;
    let manifest_str = Manifest::from_str(json_str_files).unwrap();
    assert_eq!(manifest_str.files, Some(vec!["dist".to_string()]));

    // 'files' as array in package.json
    let json_arr_files = r#"{"name":"test-pkg","version":"1.0.0","files":["dist","src"]}"#;
    let manifest_arr = Manifest::from_str(json_arr_files).unwrap();
    assert_eq!(
        manifest_arr.files,
        Some(vec!["dist".to_string(), "src".to_string()])
    );
}

#[test]
fn test_pkg_bracket_escaping_and_append_validation() {
    use crate::pkg::{parse_path, pkg_get, pkg_set, PathSegment};

    // Bracket unescaping
    let segs = parse_path(r"scripts[build\:prod]").unwrap();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0], PathSegment::Key("scripts".to_string()));
    assert_eq!(segs[1], PathSegment::Key("build:prod".to_string()));

    let temp_dir = tempfile::tempdir().unwrap();
    let pkg_json = temp_dir.path().join("package.json");
    std::fs::write(&pkg_json, r#"{"name":"test-pkg","scripts":{"build":"tsc"}}"#).unwrap();

    // pkg_get with empty brackets must fail with EINVALIDSYNTAX
    let get_res = pkg_get(&pkg_json, &["scripts[]".to_string()], false);
    assert!(get_res.is_err());
    assert!(get_res.unwrap_err().to_string().contains("Empty brackets are not valid syntax"));

    // pkg_set append to non-array element must fail with ENOAPPEND
    let set_res = pkg_set(&pkg_json, &["scripts[]=webpack".to_string()]);
    assert!(set_res.is_err());
    assert!(set_res.unwrap_err().to_string().contains("Can't use append syntax in non-Array element"));

    // pkg_set append to new array succeeds
    pkg_set(&pkg_json, &["keywords[]=cli".to_string()]).unwrap();
    let content = std::fs::read_to_string(&pkg_json).unwrap();
    assert!(content.contains(r#""keywords": ["#) || content.contains(r#""keywords":["#));
    assert!(content.contains(r#""cli""#));
}

#[test]
fn test_manifest_raw_json_contract_and_readonly() {
    let raw = r#"{
  "name": "perf-pkg",
  "version": "1.0.0",
  "dependencies": {
    "zebra": "^1.0.0",
    "alpha": "^2.0.0",
    "beta": "^3.0.0"
  },
  "devDependencies": {
    "omega": "^9.0.0",
    "gamma": "^4.0.0"
  }
}
"#;

    // Single pass parse from str: raw_json is always populated for callers needing DOM
    let mut manifest = Manifest::from_str(raw).unwrap();
    assert!(manifest.raw_json.is_some());
    assert_eq!(manifest.raw_text.as_deref(), Some(raw));

    // Exact declaration order is preserved
    assert_eq!(
        manifest.dependency_order,
        vec!["zebra".to_string(), "alpha".to_string(), "beta".to_string()]
    );
    assert_eq!(
        manifest.dev_dependency_order,
        vec!["omega".to_string(), "gamma".to_string()]
    );

    // BTreeMap has sorted keys
    let dep_keys: Vec<&String> = manifest.dependencies.keys().collect();
    assert_eq!(dep_keys, vec!["alpha", "beta", "zebra"]);

    // Saving preserves byte-for-byte fidelity and formatting
    let output = manifest.to_json_string().unwrap();
    assert_eq!(output, raw);

    // ensure_raw_json returns existing raw_json
    let raw_val = manifest.ensure_raw_json();
    assert!(raw_val.is_some());

    // Readonly parsing bypasses raw_json DOM creation
    let ro_manifest = Manifest::from_str_readonly(raw).unwrap();
    assert!(ro_manifest.raw_json.is_none());
    assert!(ro_manifest.raw_text.is_none());
    assert_eq!(ro_manifest.dependency_order, manifest.dependency_order);
    assert_eq!(ro_manifest.dev_dependency_order, manifest.dev_dependency_order);
    assert_eq!(ro_manifest.dependencies, manifest.dependencies);
    assert_eq!(ro_manifest.dev_dependencies, manifest.dev_dependencies);
}

#[test]
fn test_manifest_duplicate_dependencies_preserves_first_order_last_wins_value() {
    let raw = r#"{
  "name": "dup-pkg",
  "dependencies": {
    "react": "^17.0.0",
    "lodash": "^4.0.0",
    "react": "^18.2.0"
  }
}
"#;
    let manifest = Manifest::from_str(raw).unwrap();
    // Unique keys in dependency_order, preserving first occurrence
    assert_eq!(
        manifest.dependency_order,
        vec!["react".to_string(), "lodash".to_string()]
    );
    // Last-wins value in dependencies map
    assert_eq!(manifest.dependencies.get("react").unwrap(), "^18.2.0");
    assert_eq!(manifest.dependencies.get("lodash").unwrap(), "^4.0.0");
    assert_eq!(manifest.dependency_order.len(), manifest.dependencies.len());

    let ro = Manifest::from_str_readonly(raw).unwrap();
    assert_eq!(ro.dependency_order, manifest.dependency_order);
    assert_eq!(ro.dependencies, manifest.dependencies);
}

#[test]
fn test_overrides_equality_default_and_mutation_index_invalidation() {
    use crate::overrides::{OverrideValue, Overrides};
    use std::collections::BTreeMap;

    // Overrides::default() == Overrides::new(BTreeMap::new(), BTreeMap::new())
    let default_ov = Overrides::default();
    let new_ov = Overrides::new(BTreeMap::new(), BTreeMap::new());
    assert_eq!(default_ov, new_ov);

    // Direct mutation of rules must invalidate/re-check the index
    let mut overrides = Overrides::default();
    overrides.rules.insert(
        "foo".to_string(),
        OverrideValue::Exact("1.2.3".to_string()),
    );

    // Mentions and resolve_override must pick up the newly inserted rule
    assert!(overrides.mentions("foo"));
    assert_eq!(
        overrides.resolve_override("foo", "^1.0.0", &[]).unwrap(),
        Some("1.2.3".to_string())
    );

    // Unrelated package not mentioned
    assert!(!overrides.mentions("bar"));
    assert_eq!(
        overrides.resolve_override("bar", "^1.0.0", &[]).unwrap(),
        None
    );
}

#[test]
fn test_overrides_indexed_fast_reject_and_precompiled_specs() {
    use crate::overrides::Overrides;
    use std::collections::BTreeMap;

    let json = serde_json::json!({
        "debug@^2.0.0": "2.6.9",
        "foo > bar": "2.0.0",
        "nested > a > b@workspace:^1.0.0": "1.2.3",
        "url-pkg@#semver:^4.0.0": "4.1.2"
    });

    let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

    // 1. Fast O(1) rejection: package not in overrides at all
    assert!(!overrides.mentions("unrelated-pkg"));
    assert_eq!(
        overrides
            .resolve_override("unrelated-pkg", "^1.0.0", &[])
            .unwrap(),
        None
    );
    assert_eq!(
        overrides
            .resolve_override("unrelated-pkg", "^1.0.0", &["foo", "bar", "baz"])
            .unwrap(),
        None
    );

    // 2. Pre-parsed spec matching (debug@^2.0.0)
    assert!(overrides.mentions("debug"));
    assert_eq!(
        overrides
            .resolve_override("debug", "^2.1.0", &[])
            .unwrap(),
        Some("2.6.9".to_string())
    );
    assert_eq!(
        overrides
            .resolve_override("debug", "^4.0.0", &[])
            .unwrap(),
        None
    );

    // 3. Pre-parsed workspace: prefix stripping
    assert!(overrides.mentions("b"));
    assert_eq!(
        overrides
            .resolve_override("b", "^1.0.0", &["nested", "a"])
            .unwrap(),
        Some("1.2.3".to_string())
    );

    // 4. Pre-parsed #semver: decoded spec
    assert!(overrides.mentions("url-pkg"));
    assert_eq!(
        overrides
            .resolve_override("url-pkg", "^4.0.0", &[])
            .unwrap(),
        Some("4.1.2".to_string())
    );
}

#[test]
fn test_workspace_deep_glob_no_backtracking_and_order_preservation() {
    use crate::workspace::match_glob_patterns;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    // Create deep directories: depth 6
    let deep_dir = root.join("packages/deep/a/b/c/pkg");
    std::fs::create_dir_all(&deep_dir).unwrap();
    std::fs::write(deep_dir.join("package.json"), r#"{"name":"deep-pkg"}"#).unwrap();

    let tools_dir = root.join("tools/cli");
    std::fs::create_dir_all(&tools_dir).unwrap();
    std::fs::write(tools_dir.join("package.json"), r#"{"name":"cli-tool"}"#).unwrap();

    let git_dir = root.join("packages/.git/inner");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("package.json"), r#"{"name":"git-pkg"}"#).unwrap();

    let nm_dir = root.join("packages/node_modules/inner");
    std::fs::create_dir_all(&nm_dir).unwrap();
    std::fs::write(nm_dir.join("package.json"), r#"{"name":"nm-pkg"}"#).unwrap();

    // Patterns with ** and declaration order: tools first, then packages/**
    let patterns = vec![
        "tools/*".to_string(),
        "packages/**/pkg".to_string(),
        "!packages/**/ignored".to_string(),
    ];

    let matched = match_glob_patterns(root, &patterns).unwrap();
    assert_eq!(matched.len(), 2);
    // Tools declared first, so cli-tool should be first
    assert_eq!(matched[0], tools_dir);
    assert_eq!(matched[1], deep_dir);
}

#[test]
fn test_manifest_from_str_array_bin_parity() {
    use crate::manifest::PackageBin;
    let json = r#"{
  "name": "arr-bin-pkg",
  "version": "1.0.0",
  "bin": ["./bin/a.js", "./bin/b.js"]
}"#;
    let m_raw = Manifest::from_str(json).expect("Manifest::from_str array bin");
    let m_ro = Manifest::from_str_readonly(json).expect("Manifest::from_str_readonly array bin");
    let m_serde: Manifest = serde_json::from_str(json).expect("serde_json array bin");

    let mut expected_map = std::collections::BTreeMap::new();
    expected_map.insert("a.js".to_string(), "./bin/a.js".to_string());
    expected_map.insert("b.js".to_string(), "./bin/b.js".to_string());
    let expected = Some(PackageBin::Map(expected_map));

    assert_eq!(m_raw.bin, expected);
    assert_eq!(m_ro.bin, expected);
    assert_eq!(m_serde.bin, expected);
}

#[test]
fn test_manifest_engines_float_formatting_parity() {
    let json = r#"{
  "name": "engines-float-pkg",
  "version": "1.0.0",
  "engines": { "node": 18.0, "npm": 10 }
}"#;
    let m_raw = Manifest::from_str(json).expect("Manifest::from_str");
    let m_ro = Manifest::from_str_readonly(json).expect("Manifest::from_str_readonly");
    assert_eq!(m_raw.engines, m_ro.engines);
    assert_eq!(m_ro.engines.get("node").map(String::as_str), Some("18.0"));
    assert_eq!(m_ro.engines.get("npm").map(String::as_str), Some("10"));
}

#[test]
fn test_overrides_nested_without_dot_falls_back_to_global_parity() {
    use crate::overrides::Overrides;
    use std::collections::BTreeMap;
    let json = serde_json::json!({
        "foo": "1.0.0",
        "a": {
            "foo": {
                "bar": "2.0.0"
            }
        }
    });
    let ov = Overrides::from_json_value(Some(&json), BTreeMap::new());
    assert_eq!(
        ov.resolve_override("foo", "^1.0.0", &["a"]).unwrap(),
        Some("1.0.0".to_string())
    );
    assert_eq!(
        ov.resolve_override_precompiled_with_caller("foo", "^1.0.0", &["a"], None)
            .unwrap(),
        Some("1.0.0".to_string())
    );
    assert_eq!(
        ov.resolve_override_precompiled_with_caller("bar", "^2.0.0", &["a", "foo"], None)
            .unwrap(),
        Some("2.0.0".to_string())
    );
}

#[test]
fn test_manifest_readonly_neg_zero_extra_parity() {
    let json = r#"{"name": "neg-zero", "custom": -0}"#;
    let m_raw = Manifest::from_str(json).expect("Manifest::from_str");
    let m_ro = Manifest::from_str_readonly(json).expect("Manifest::from_str_readonly");
    assert_eq!(m_raw.extra.get("custom"), m_ro.extra.get("custom"));
}

#[test]
fn test_caret_wildcard_cascade_parity() {
    let v = crate::semver::Version::parse("0.0.1").unwrap();
    let parsed = crate::semver::Range::parse("^0.x.5").unwrap();
    assert!(parsed.satisfies(&v));
    assert_eq!(
        crate::semver::Range::satisfies_str("^0.x.5", &v).unwrap(),
        parsed.satisfies(&v)
    );
}

#[test]
fn test_manifest_edge_cases_unicode_surrogates_bom_bundled_bin_platform_parity() {
    use crate::{BundledDependencies, PackageBin};
    let raw = "\u{feff}{\n  \"name\": \"edge-\\u0061\\uD83D\\uDE00\",\n  \"name\": \"edge-final\",\n  \"description\": \"quote:\\\" slash:\\\\ ctrl:\\t\",\n  \"bin\": [\"./cli/one.js\", \"./cli/two.js\"],\n  \"bundleDependencies\": {\"pkg-a\": true, \"pkg-b\": false},\n  \"os\": [\"!win32\", \"linux\"],\n  \"cpu\": \"!ia32\",\n  \"libc\": [\"glibc\", \"!musl\"],\n  \"dependencies\": {\n    \"foo\": \"^1.0.0\",\n    \"bar\": \">=1.0.0 <2.0.0\"\n  },\n  \"funding\": {\"type\": \"individual\", \"url\": \"https://example.com\"},\n  \"negZero\": -0\n}\n";

    let m = Manifest::from_str(raw).unwrap();
    let ro = Manifest::from_str_readonly(raw).unwrap();

    assert!(m.format.has_bom);
    assert!(m.raw_json.is_some());
    assert_eq!(m.name.as_deref(), Some("edge-final"));
    assert_eq!(ro.name, m.name);
    assert_eq!(m.description, ro.description);
    assert_eq!(
        m.description.as_deref(),
        Some("quote:\" slash:\\ ctrl:\t")
    );
    assert_eq!(m.bin, ro.bin);
    assert!(matches!(m.bin, Some(PackageBin::Map(_))));
    assert_eq!(m.bundled_dependencies, ro.bundled_dependencies);
    assert_eq!(
        m.bundled_dependencies,
        Some(BundledDependencies::List(vec![
            "pkg-a".to_string(),
            "pkg-b".to_string()
        ]))
    );
    assert_eq!(m.os, ro.os);
    assert_eq!(m.cpu, ro.cpu);
    assert_eq!(m.libc, ro.libc);
    assert_eq!(m.dependencies, ro.dependencies);
    assert_eq!(m.dependency_order, ro.dependency_order);
    assert_eq!(m.extra.get("negZero"), ro.extra.get("negZero"));

    let written = m.to_json_string().unwrap();
    assert!(written.starts_with('\u{feff}'));
    let reparsed = Manifest::from_str(&written).unwrap();
    assert_eq!(reparsed.name, m.name);
    assert_eq!(reparsed.description, m.description);
    assert_eq!(reparsed.dependencies, m.dependencies);
    assert_eq!(reparsed.os, m.os);
    assert_eq!(reparsed.cpu, m.cpu);
    assert_eq!(reparsed.libc, m.libc);
}

#[test]
fn test_manifest_bundled_dependencies_bool_and_array_and_bin_string_map() {
    use crate::{BundledDependencies, PackageBin};
    let raw_bool = r#"{"name": "b1", "bin": "./index.js", "bundledDependencies": true}"#;
    let m1 = Manifest::from_str(raw_bool).unwrap();
    let r1 = Manifest::from_str_readonly(raw_bool).unwrap();
    assert_eq!(m1.bin, Some(PackageBin::Single("./index.js".to_string())));
    assert_eq!(m1.bin, r1.bin);
    assert_eq!(
        m1.bundled_dependencies,
        Some(BundledDependencies::Boolean(true))
    );
    assert_eq!(m1.bundled_dependencies, r1.bundled_dependencies);

    let raw_map =
        r#"{"name": "b2", "bin": {"a": "./a.js", "b": "./b.js"}, "bundleDependencies": ["x"]}"#;
    let m2 = Manifest::from_str(raw_map).unwrap();
    let r2 = Manifest::from_str_readonly(raw_map).unwrap();
    assert_eq!(m2.bin, r2.bin);
    assert_eq!(
        m2.bundled_dependencies,
        Some(BundledDependencies::List(vec!["x".to_string()]))
    );
    assert_eq!(m2.bundled_dependencies, r2.bundled_dependencies);
}

#[test]
fn test_overrides_helpers_and_ref_shadowing_and_compound_range_fast_path() {
    use crate::overrides::Overrides;
    use crate::semver::{Range, Version};
    use std::collections::BTreeMap;

    let mut root_deps = BTreeMap::new();
    root_deps.insert("bar".to_string(), "^2.3.4".to_string());
    let json = serde_json::json!({
        "bar": "1.0.0",
        "foo": {
            "bar": "$bar"
        }
    });
    let ov = Overrides::from_json_value(Some(&json), root_deps);
    assert!(ov.has_target("bar"));
    assert!(ov.has_nested_target("bar"));
    assert!(ov.has_references());
    assert!(!ov.has_nested_target("foo"));
    assert!(!ov.has_target("missing"));

    assert_eq!(
        ov.resolve_override_precompiled_in_context(
            "bar",
            "^1.0.0",
            &["foo"],
            &ov.root_dependencies,
            None,
        )
        .unwrap(),
        Some("^2.3.4".to_string())
    );
    assert_eq!(
        ov.resolve_override_precompiled_in_context(
            "bar",
            "^1.0.0",
            &["other"],
            &ov.root_dependencies,
            None,
        )
        .unwrap(),
        Some("1.0.0".to_string())
    );

    // Compound & hyphen range fast path parity
    for expr in &[
        ">=1.0.0 <2.0.0",
        "1.0.0 - 2.0.0",
        "1.0 - 2.0",
        "^1.0.0 || >=2.0.0 <3.0.0",
    ] {
        let r = Range::parse(expr).unwrap();
        let v15 = Version::parse("1.5.0").unwrap();
        let v25 = Version::parse("2.5.0").unwrap();
        assert_eq!(r.satisfies(&v15), Range::satisfies_str(expr, &v15).unwrap());
        assert_eq!(r.satisfies(&v25), Range::satisfies_str(expr, &v25).unwrap());
    }
}

#[test]
fn test_manifest_to_json_string_reflects_mutations_and_clears() {
    use crate::manifest::{Manifest, PackageBin, PackageWorkspaces};
    use crate::PlatformList;

    let raw = r#"{
  "name": "orig-pkg",
  "version": "1.0.0",
  "description": "old desc",
  "main": "old.js",
  "bin": { "cli": "./old-cli.js" },
  "files": ["old-dist"],
  "scripts": { "test": "vitest" },
  "workspaces": ["packages/*"],
  "os": ["linux"],
  "cpu": ["x64"],
  "libc": ["glibc"],
  "engines": { "node": ">=18" },
  "overrides": { "foo": "1.0.0" },
  "license": "MIT"
}
"#;
    let mut m = Manifest::from_str(raw).unwrap();

    // Mutate bin, files, os, cpu, libc, engines, extra (overrides + new exports), and delete license
    m.bin = Some(PackageBin::Single("./new-bin.js".to_string()));
    m.files = Some(vec!["dist".to_string(), "README.md".to_string()]);
    m.os = Some(PlatformList::from(vec!["darwin".to_string(), "linux".to_string()]));
    m.cpu = Some(PlatformList::from("arm64".to_string()));
    m.libc = None;
    m.engines.insert("node".to_string(), ">=20".to_string());
    m.engines.insert("npm".to_string(), ">=10".to_string());
    m.extra.insert(
        "overrides".to_string(),
        serde_json::json!({ "foo": "2.0.0" }),
    );
    m.extra
        .insert("exports".to_string(), serde_json::json!({ ".": "./dist/index.js" }));
    m.extra.remove("license");

    // Clear name, version, description, main, scripts, workspaces
    m.name = None;
    m.version = None;
    m.description = None;
    m.main = None;
    m.scripts.clear();
    m.workspaces = None;

    let serialized = m.to_json_string().unwrap();
    let reparsed = Manifest::from_str_readonly(&serialized).unwrap();
    assert_eq!(reparsed.name, None);
    assert_eq!(reparsed.version, None);
    assert_eq!(reparsed.description, None);
    assert_eq!(reparsed.main, None);
    assert!(reparsed.scripts.is_empty());
    assert_eq!(reparsed.workspaces, None);
    assert_eq!(reparsed.libc, None);
    assert_eq!(reparsed.bin, Some(PackageBin::Single("./new-bin.js".to_string())));
    assert_eq!(
        reparsed.files,
        Some(vec!["dist".to_string(), "README.md".to_string()])
    );
    assert_eq!(
        reparsed.os.as_deref(),
        Some(&["darwin".to_string(), "linux".to_string()][..])
    );
    assert_eq!(reparsed.cpu.as_deref(), Some(&["arm64".to_string()][..]));
    assert_eq!(reparsed.engines.get("node").map(String::as_str), Some(">=20"));
    assert_eq!(reparsed.engines.get("npm").map(String::as_str), Some(">=10"));
    assert_eq!(
        reparsed.extra.get("overrides"),
        Some(&serde_json::json!({ "foo": "2.0.0" }))
    );
    assert_eq!(
        reparsed.extra.get("exports"),
        Some(&serde_json::json!({ ".": "./dist/index.js" }))
    );
    assert!(!reparsed.extra.contains_key("license"));

    // Also verify adding previously absent optional fields on a minimal manifest
    let mut minimal = Manifest::from_str("{\"name\":\"min\"}\n").unwrap();
    minimal.bin = Some(PackageBin::Single("./cli.js".to_string()));
    minimal.files = Some(vec!["dist".to_string()]);
    minimal.os = Some(PlatformList::from(vec!["linux".to_string()]));
    minimal.cpu = Some(PlatformList::from(vec!["x64".to_string()]));
    minimal.libc = Some(PlatformList::from(vec!["glibc".to_string()]));
    minimal.engines.insert("node".to_string(), ">=18".to_string());
    minimal.workspaces = Some(PackageWorkspaces::List(vec!["pkgs/*".to_string()]));
    let min_out = minimal.to_json_string().unwrap();
    let min_reparsed = Manifest::from_str_readonly(&min_out).unwrap();
    assert_eq!(min_reparsed.bin, minimal.bin);
    assert_eq!(min_reparsed.files, minimal.files);
    assert_eq!(min_reparsed.os, minimal.os);
    assert_eq!(min_reparsed.cpu, minimal.cpu);
    assert_eq!(min_reparsed.libc, minimal.libc);
    assert_eq!(min_reparsed.engines, minimal.engines);
    assert_eq!(min_reparsed.workspaces, minimal.workspaces);
}

#[test]
fn test_pkg_delete_interleaved_array_indices_and_nested_no_panic() {
    use crate::pkg::pkg_delete;

    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = tmp.path().join("package.json");
    std::fs::write(
        &manifest_path,
        r#"{
  "name": "pkg-delete-order",
  "keywords": ["k0", "k1", "k2", "k3"],
  "matrix": [["a0", "a1"], ["b0", "b1"]]
}
"#,
    )
    .unwrap();

    // Interleaved paths previously panicked due to non-transitive sort_by comparator
    pkg_delete(
        &manifest_path,
        &[
            "keywords[0]".to_string(),
            "name".to_string(),
            "keywords[2]".to_string(),
            "keywords[0]".to_string(),
            "matrix[0]".to_string(),
            "matrix[0][0]".to_string(),
        ],
    )
    .unwrap();

    let updated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(updated.get("name").is_none());
    assert_eq!(updated["keywords"], serde_json::json!(["k1", "k3"]));
    assert_eq!(updated["matrix"], serde_json::json!([["b0", "b1"]]));
}

#[test]
fn test_overrides_versioned_ancestors_closer_precedence_and_global_fallback() {
    use crate::overrides::{OverrideValue, Overrides};
    use std::collections::BTreeMap;

    let json = serde_json::json!({
        "bar": "9.0.0",
        "foo@1.0.0": {
            "bar": "2.0.0"
        },
        "outer": {
            "baz": "1.0.0",
            "bar": {
                "qux": "3.0.0"
            }
        },
        "inner": {
            "baz": "4.0.0"
        }
    });
    let mut ov = Overrides::from_json_value(Some(&json), BTreeMap::new());

    // 1. Version-scoped ancestor: foo@1.0.0 matches bar->2.0.0, foo@2.0.0 falls back to global 9.0.0
    assert_eq!(
        ov.resolve_override("bar", "^1.0.0", &["foo@1.0.0"]).unwrap(),
        Some("2.0.0".to_string())
    );
    assert_eq!(
        ov.resolve_override("bar", "^1.0.0", &["foo@2.0.0"]).unwrap(),
        Some("9.0.0".to_string())
    );

    // 2. Closer parent takes precedence over outer ancestor
    assert_eq!(
        ov.resolve_override("baz", "^1.0.0", &["outer@1.0.0", "inner@1.0.0"])
            .unwrap(),
        Some("4.0.0".to_string())
    );

    // 3. Nested map lacking "." does NOT block global fallback
    assert_eq!(
        ov.resolve_override("bar", "^1.0.0", &["outer@1.0.0"]).unwrap(),
        Some("9.0.0".to_string())
    );
    assert_eq!(
        ov.resolve_override("qux", "^1.0.0", &["outer@1.0.0", "bar@1.0.0"])
            .unwrap(),
        Some("3.0.0".to_string())
    );

    // 4. Direct in-place mutation of existing key invalidates fast index via generation counter
    ov.rules
        .insert("bar".to_string(), OverrideValue::Exact("8.0.0".to_string()));
    assert_eq!(
        ov.resolve_override("bar", "^1.0.0", &["foo@2.0.0"]).unwrap(),
        Some("8.0.0".to_string())
    );
}

#[test]
fn test_range_or_wildcard_preserves_prerelease_set() {
    use crate::semver::{Range, Version};

    let range = Range::parse("1.0.0-alpha.1 || *").unwrap();
    let alpha1 = Version::parse("1.0.0-alpha.1").unwrap();
    let alpha2 = Version::parse("1.0.0-alpha.2").unwrap();
    let stable = Version::parse("2.0.0").unwrap();

    assert!(range.satisfies(&alpha1));
    assert!(!range.satisfies(&alpha2));
    assert!(range.satisfies(&stable));
    assert!(Range::satisfies_str("1.0.0-alpha.1 || *", &alpha1).unwrap());
    assert!(!Range::satisfies_str("1.0.0-alpha.1 || *", &alpha2).unwrap());
}

#[test]
fn test_workspace_discovery_includes_build_dist_target_dirs() {
    use crate::workspace::{discover_workspaces, path_matches_workspace_patterns};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{"name": "root", "workspaces": ["packages/*"]}"#,
    )
    .unwrap();
    for dir in ["build", "dist", "target"] {
        let pkg_dir = root.join("packages").join(dir);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(r#"{{"name": "@repo/{dir}", "version": "1.0.0"}}"#),
        )
        .unwrap();
    }

    let members = discover_workspaces(root).unwrap();
    let rels: Vec<&str> = members.iter().map(|m| m.relative_path.as_str()).collect();
    assert_eq!(rels, vec!["packages/build", "packages/dist", "packages/target"]);

    let explicit = vec!["packages/build".to_string()];
    assert!(path_matches_workspace_patterns("packages/build", &explicit));
}

#[test]
fn test_overrides_deeper_chain_beats_shallower_rule_at_same_parent() {
    use crate::overrides::Overrides;
    use std::collections::BTreeMap;

    let json = serde_json::json!({
        "inner": { "leaf": "2.0.0" },
        "outer": {
            "inner": { "leaf": "3.0.0" },
            "mid": {
                "inner": { "leaf": "4.0.0" }
            }
        }
    });
    let ov = Overrides::from_json_value(Some(&json), BTreeMap::new());
    let empty_refs = BTreeMap::new();

    // `outer > inner` (depth 2) must beat shallower `inner` (depth 1) for `["outer@1.0.0", "inner@1.0.0"]`
    assert_eq!(
        ov.resolve_override_precompiled_with_caller(
            "leaf",
            "^1.0.0",
            &["outer@1.0.0", "inner@1.0.0"],
            Some(&empty_refs),
        )
        .unwrap(),
        Some("3.0.0".to_string())
    );

    // `outer > mid > inner` (depth 3) must beat `outer > inner` (depth 2) and `inner` (depth 1)
    assert_eq!(
        ov.resolve_override_precompiled_with_caller(
            "leaf",
            "^1.0.0",
            &["outer@1.0.0", "mid@1.0.0", "inner@1.0.0"],
            Some(&empty_refs),
        )
        .unwrap(),
        Some("4.0.0".to_string())
    );

    // Standalone `inner` still wins when outer is absent
    assert_eq!(
        ov.resolve_override_precompiled_with_caller(
            "leaf",
            "^1.0.0",
            &["other@1.0.0", "inner@1.0.0"],
            Some(&empty_refs),
        )
        .unwrap(),
        Some("2.0.0".to_string())
    );
}
