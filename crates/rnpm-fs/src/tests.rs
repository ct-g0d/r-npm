use std::fs;
use std::io::Cursor;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Builder, Header};
use tempfile::tempdir;
use crate::atomic::extract_and_replace;
use crate::error::FsError;
use crate::junction::{create_junction, is_junction, remove_junction};
use crate::tarball::{extract_tar_gz, TarLimits};

fn create_test_tarball(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        for &(path, data, mode) in entries {
            let mut header = Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(mode);
            let path_bytes = path.as_bytes();
            header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
            header.set_cksum();
            builder.append(&header, Cursor::new(data)).unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn test_safe_tarball_extraction_and_package_prefix_stripping() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("extracted");

    // Standard npm tarball with "package/" prefix
    let tar_bytes = create_test_tarball(&[
        ("package/package.json", br#"{"name":"test-pkg","version":"1.0.0"}"#, 0o644),
        ("package/index.js", b"console.log('hello');", 0o644),
        ("package/sub/util.js", b"module.exports = {};", 0o644),
    ]);

    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 3);

    // Verify "package/" was stripped:
    assert!(dest.join("package.json").exists());
    assert!(dest.join("index.js").exists());
    assert!(dest.join("sub/util.js").exists());

    let pkg_content = fs::read_to_string(dest.join("package.json")).unwrap();
    assert!(pkg_content.contains("test-pkg"));
}

#[test]
fn test_security_rejection_path_traversal() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let tar_bytes = create_test_tarball(&[
        ("package/../../evil.js", b"malicious code", 0o644),
    ]);

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(matches!(res, Err(FsError::PathTraversal { .. })));
}

#[test]
fn test_security_rejection_windows_device_names() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Reserved device names: CON, PRN, AUX, NUL, COM1..9, LPT1..9
    let test_names = ["package/con.txt", "package/aux", "package/NUL.json", "package/com1.js", "package/lpt2"];
    for bad_name in test_names {
        let tar_bytes = create_test_tarball(&[(bad_name, b"dummy", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::WindowsReservedDeviceName { .. })),
            "Expected WindowsReservedDeviceName for {bad_name}, got: {res:?}"
        );
    }
}

#[test]
fn test_security_rejection_trailing_dots_and_spaces() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Trailing dot
    let tar_dot = create_test_tarball(&[("package/bad_file.", b"content", 0o644)]);
    let res_dot = extract_tar_gz(Cursor::new(&tar_dot), &dest, None);
    assert!(matches!(res_dot, Err(FsError::TrailingDotOrSpace { .. })));

    // Trailing space
    let tar_space = create_test_tarball(&[("package/bad_file ", b"content", 0o644)]);
    let res_space = extract_tar_gz(Cursor::new(&tar_space), &dest, None);
    assert!(matches!(res_space, Err(FsError::TrailingDotOrSpace { .. })));
}

#[test]
fn test_security_rejection_suid_sgid_bits() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // SUID bit = 0o4000
    let tar_suid = create_test_tarball(&[("package/root_binary", b"binary", 0o4755)]);
    let res_suid = extract_tar_gz(Cursor::new(&tar_suid), &dest, None);
    assert!(matches!(res_suid, Err(FsError::ForbiddenModeBits { .. })));

    // SGID bit = 0o2000
    let tar_sgid = create_test_tarball(&[("package/group_binary", b"binary", 0o2755)]);
    let res_sgid = extract_tar_gz(Cursor::new(&tar_sgid), &dest, None);
    assert!(matches!(res_sgid, Err(FsError::ForbiddenModeBits { .. })));
}

#[test]
fn test_tar_bomb_entry_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let entries = [
        ("package/file1.txt", b"hello".as_slice(), 0o644),
        ("package/file2.txt", b"world".as_slice(), 0o644),
        ("package/file3.txt", b"extra".as_slice(), 0o644),
    ];
    let tar_bytes = create_test_tarball(&entries);

    // Limit to max 2 entries
    let limits = TarLimits {
        max_entries: 2,
        max_uncompressed_size: 1_000_000,
        max_compression_ratio: 100.0,
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(matches!(res, Err(FsError::TarBombLimitExceeded { .. })));
}

#[test]
fn test_tar_bomb_size_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let big_data = vec![b'A'; 20_000];
    let entries = [
        ("package/big_file.txt", big_data.as_slice(), 0o644),
    ];
    let tar_bytes = create_test_tarball(&entries);

    // Limit to max 10,000 bytes uncompressed
    let limits = TarLimits {
        max_entries: 100,
        max_uncompressed_size: 10_000,
        max_compression_ratio: 100.0,
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(matches!(res, Err(FsError::TarBombLimitExceeded { .. })));
}

#[test]
fn test_atomic_replacement() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("installed_pkg");

    // 1. Initial version
    let tar_v1 = create_test_tarball(&[
        ("package/version.txt", b"v1.0.0", 0o644),
    ]);
    extract_and_replace(Cursor::new(&tar_v1), &dest, None).unwrap();
    assert_eq!(
        fs::read_to_string(dest.join("version.txt")).unwrap(),
        "v1.0.0"
    );

    // 2. Atomically replace with version 2
    let tar_v2 = create_test_tarball(&[
        ("package/version.txt", b"v2.0.0", 0o644),
        ("package/new_feature.txt", b"cool feature", 0o644),
    ]);
    extract_and_replace(Cursor::new(&tar_v2), &dest, None).unwrap();
    assert_eq!(
        fs::read_to_string(dest.join("version.txt")).unwrap(),
        "v2.0.0"
    );
    assert!(dest.join("new_feature.txt").exists());
}

#[test]
fn test_junction_creation_and_safe_deletion() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target_dir");
    let link = dir.path().join("link_dir");

    fs::create_dir_all(&target).unwrap();
    let file_path = target.join("important_file.txt");
    fs::write(&file_path, "important data").unwrap();

    // Create junction
    create_junction(&link, &target).unwrap();
    assert!(is_junction(&link).unwrap());

    // Verify reading through junction works
    let link_file_path = link.join("important_file.txt");
    assert!(link_file_path.exists());
    let read_data = fs::read_to_string(&link_file_path).unwrap();
    assert_eq!(read_data, "important data");

    // CRUCIAL: Safe deletion of junction
    remove_junction(&link).unwrap();

    // Verify the link itself is removed
    assert!(!link.exists());

    // Verify the target directory AND its contents are COMPLETELY PRESERVED!
    assert!(target.exists(), "Target directory must not be deleted when junction is removed");
    assert!(file_path.exists(), "Target contents must not be deleted when junction is removed");
    assert_eq!(fs::read_to_string(&file_path).unwrap(), "important data");
}

#[test]
fn test_pack_directory_tarball_generation_and_integrity() {
    let dir = tempdir().unwrap();
    let pkg_dir = dir.path().join("my-test-package");
    fs::create_dir_all(&pkg_dir).unwrap();

    // Setup package.json
    let package_json = serde_json::json!({
        "name": "@my-scope/test-pack",
        "version": "1.2.3",
        "description": "Testing pack functionality",
        "main": "index.js",
        "bin": {
            "my-cli": "./bin/cli.js"
        }
    });
    fs::write(pkg_dir.join("package.json"), package_json.to_string()).unwrap();
    fs::write(pkg_dir.join("index.js"), "module.exports = 42;\n").unwrap();
    fs::create_dir_all(pkg_dir.join("bin")).unwrap();
    fs::write(pkg_dir.join("bin/cli.js"), "#!/usr/bin/env node\nconsole.log(42);\n").unwrap();
    fs::write(pkg_dir.join("README.md"), "# Test Package\n").unwrap();
    fs::write(pkg_dir.join("LICENSE"), "MIT License\n").unwrap();

    // Files that MUST be excluded
    fs::create_dir_all(pkg_dir.join("node_modules/dep")).unwrap();
    fs::write(pkg_dir.join("node_modules/dep/index.js"), "evil").unwrap();
    fs::create_dir_all(pkg_dir.join(".git")).unwrap();
    fs::write(pkg_dir.join(".git/config"), "secret").unwrap();
    fs::write(pkg_dir.join("package-lock.json"), "{}").unwrap();
    fs::write(pkg_dir.join(".npmrc"), "//token").unwrap();

    let dest_tarball = dir.path().join("output.tgz");
    let (summary, compressed_bytes) = crate::tarball::pack_directory(&pkg_dir, Some(&dest_tarball)).unwrap();

    assert_eq!(summary.name, "@my-scope/test-pack");
    assert_eq!(summary.version, "1.2.3");
    assert_eq!(summary.filename, "my-scope-test-pack-1.2.3.tgz");
    assert!(dest_tarball.exists());

    // Verify SSRI integrity
    let integrity = rnpm_core::integrity::Integrity::parse(&summary.integrity).unwrap();
    integrity.verify(&compressed_bytes).unwrap();

    // Verify tarball contents by extracting with extract_tar_gz
    let extract_dir = dir.path().join("extracted");
    let extraction = crate::tarball::extract_tar_gz(Cursor::new(&compressed_bytes), &extract_dir, None).unwrap();

    assert!(extract_dir.join("package.json").exists());
    assert!(extract_dir.join("index.js").exists());
    assert!(extract_dir.join("bin/cli.js").exists());
    assert!(extract_dir.join("README.md").exists());
    assert!(extract_dir.join("LICENSE").exists());

    // Verify exclusions
    assert!(!extract_dir.join("node_modules").exists());
    assert!(!extract_dir.join(".git").exists());
    assert!(!extract_dir.join("package-lock.json").exists());
    assert!(!extract_dir.join(".npmrc").exists());

    assert_eq!(extraction.entries_extracted, summary.entry_count);
}

#[test]
fn test_pack_files_array_and_ignore_rules() {
    let dir = tempdir().unwrap();
    let pkg_dir = dir.path().join("files-pkg");
    fs::create_dir_all(pkg_dir.join("src")).unwrap();
    fs::create_dir_all(pkg_dir.join("test")).unwrap();

    let package_json = serde_json::json!({
        "name": "files-pkg",
        "version": "2.0.0",
        "files": ["src", "extra.txt"]
    });
    fs::write(pkg_dir.join("package.json"), package_json.to_string()).unwrap();
    fs::write(pkg_dir.join("src/index.js"), "src").unwrap();
    fs::write(pkg_dir.join("src/utils.js"), "util").unwrap();
    fs::write(pkg_dir.join("extra.txt"), "extra").unwrap();
    fs::write(pkg_dir.join("test/test.js"), "test").unwrap();
    fs::write(pkg_dir.join("README.txt"), "readme text").unwrap();

    // .npmignore inside src
    fs::write(pkg_dir.join(".npmignore"), "src/utils.js\n").unwrap();

    let (_summary, compressed_bytes) = crate::tarball::pack_directory(&pkg_dir, None).unwrap();

    let extract_dir = dir.path().join("extracted");
    crate::tarball::extract_tar_gz(Cursor::new(&compressed_bytes), &extract_dir, None).unwrap();

    // Should include: package.json (always), README.txt (always), src/index.js, extra.txt
    assert!(extract_dir.join("package.json").exists());
    assert!(extract_dir.join("README.txt").exists());
    assert!(extract_dir.join("src/index.js").exists());
    assert!(extract_dir.join("extra.txt").exists());

    // Should NOT include: src/utils.js (ignored by .npmignore), test/test.js (not in files)
    assert!(!extract_dir.join("src/utils.js").exists());
    assert!(!extract_dir.join("test/test.js").exists());
}

#[test]
fn test_pack_edge_cases_and_error_handling() {
    let dir = tempdir().unwrap();

    // 1. Missing package.json
    let empty_dir = dir.path().join("empty");
    fs::create_dir_all(&empty_dir).unwrap();
    assert!(crate::tarball::pack_directory(&empty_dir, None).is_err());

    // 2. Malformed package.json
    let malformed_dir = dir.path().join("malformed");
    fs::create_dir_all(&malformed_dir).unwrap();
    fs::write(malformed_dir.join("package.json"), "NOT VALID JSON {{{{").unwrap();
    assert!(crate::tarball::pack_directory(&malformed_dir, None).is_err());

    // 3. Fallback to .gitignore when .npmignore is absent
    let gitignore_dir = dir.path().join("gitignore-fallback");
    fs::create_dir_all(&gitignore_dir).unwrap();
    fs::write(gitignore_dir.join("package.json"), r#"{"name":"gi-fallback","version":"1.0.0"}"#).unwrap();
    fs::write(gitignore_dir.join("kept.js"), "kept").unwrap();
    fs::write(gitignore_dir.join("ignored.log"), "log").unwrap();
    fs::write(gitignore_dir.join(".gitignore"), "*.log\n").unwrap();

    let (summary, compressed) = crate::tarball::pack_directory(&gitignore_dir, None).unwrap();
    assert_eq!(summary.name, "gi-fallback");
    let extract_dir = dir.path().join("gi-extract");
    crate::tarball::extract_tar_gz(Cursor::new(&compressed), &extract_dir, None).unwrap();
    assert!(extract_dir.join("kept.js").exists());
    assert!(!extract_dir.join("ignored.log").exists());
    assert!(!extract_dir.join(".gitignore").exists());
}


