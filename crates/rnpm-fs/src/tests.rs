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
            if path_bytes.len() <= 100 {
                header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
                header.set_cksum();
                builder.append(&header, Cursor::new(data)).unwrap();
            } else {
                header.set_cksum();
                builder.append_data(&mut header, path, Cursor::new(data)).unwrap();
            }
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
        ..Default::default()
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
        ..Default::default()
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
fn test_security_rejection_escaping_symlink() {
    use crate::tarball::validate_link_target;
    use std::path::Path;

    let dest = Path::new("C:/test/dest");
    let link_path = Path::new("sub/my_link");

    // Traversal escaping root: link in sub/ pointing to ../../secret
    let res1 = validate_link_target(link_path, Path::new("../../secret"), dest);
    assert!(matches!(res1, Err(FsError::EscapingSymlink { .. })));

    // Absolute Unix path
    let res2 = validate_link_target(link_path, Path::new("/etc/passwd"), dest);
    assert!(matches!(res2, Err(FsError::AbsolutePath { .. })));

    // Drive-relative root path on Windows
    let res3 = validate_link_target(link_path, Path::new(r"\Windows\System32"), dest);
    assert!(matches!(res3, Err(FsError::AbsolutePath { .. })));

    // Windows drive-prefixed path
    let res4 = validate_link_target(link_path, Path::new(r"C:\Windows\System32"), dest);
    assert!(matches!(res4, Err(FsError::AbsolutePath { .. })));

    // Safe relative target within extraction directory
    let res_ok = validate_link_target(link_path, Path::new("../other_file.js"), dest);
    assert!(res_ok.is_ok());
}

#[test]
fn test_security_rejection_colon_and_null_bytes() {
    use crate::tarball::validate_entry_path;
    use std::path::Path;

    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Alternate Data Stream syntax
    let tar_colon = create_test_tarball(&[("package/file.txt:stream", b"ads content", 0o644)]);
    let res_colon = extract_tar_gz(Cursor::new(&tar_colon), &dest, None);
    assert!(matches!(res_colon, Err(FsError::PathTraversal { .. })));

    // Direct path validation with null byte and colon
    assert!(matches!(
        validate_entry_path(Path::new("file\0hidden.txt")),
        Err(FsError::PathTraversal { .. })
    ));
    assert!(matches!(
        validate_entry_path(Path::new("file.txt:stream")),
        Err(FsError::PathTraversal { .. })
    ));
}

#[test]
fn test_security_rejection_conin_conout() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    for bad_name in ["package/conin$.txt", "package/CONOUT$", "package/aux.d"] {
        let tar_bytes = create_test_tarball(&[(bad_name, b"dummy", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(matches!(res, Err(FsError::WindowsReservedDeviceName { .. })));
    }
}

#[test]
fn test_corrupted_tarball_handling() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. Truncated gzip stream (unexpected EOF during gzip decompression)
    let valid_tar = create_test_tarball(&[("package/index.js", b"console.log(1);", 0o644)]);
    let truncated_tar = &valid_tar[..valid_tar.len() / 2];
    let res_trunc = extract_tar_gz(Cursor::new(truncated_tar), &dest, None);
    assert!(res_trunc.is_err(), "Truncated gzip must return error");

    // 2. Completely corrupt/random bytes
    let random_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78];
    let res_random = extract_tar_gz(Cursor::new(&random_bytes), &dest, None);
    assert!(res_random.is_err(), "Corrupted bytes must return error");

    // 3. Zero-byte input
    let res_empty = extract_tar_gz(Cursor::new(&[]), &dest, None);
    assert!(res_empty.is_err(), "Empty stream must return error");
}

#[test]
fn test_junction_nonexistent_path_safety() {
    let dir = tempdir().unwrap();
    let non_existent = dir.path().join("does_not_exist");

    // Removing nonexistent path must be idempotent and succeed
    assert!(remove_junction(&non_existent).is_ok());
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
fn test_tar_bomb_ratio_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Create a 200KB repeating payload which compresses down to under 500 bytes (>400:1 ratio)
    let bomb_data = vec![b'0'; 200_000];
    let entries = [
        ("package/bomb.txt", bomb_data.as_slice(), 0o644),
    ];
    let tar_bytes = create_test_tarball(&entries);

    // Limit to max 20.0 compression ratio
    let limits = TarLimits {
        max_entries: 10_000,
        max_uncompressed_size: 10_000_000,
        max_compression_ratio: 20.0,
        ..Default::default()
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "compression ratio"),
        "Expected TarBombLimitExceeded for compression ratio, got: {res:?}"
    );
}

#[test]
fn test_security_rejection_backslash_path_traversal() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let tar_bytes = create_test_tarball(&[
        (r"package\..\evil.js", b"malicious", 0o644),
    ]);

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(matches!(res, Err(FsError::PathTraversal { .. })));
}

#[test]
fn test_parallel_batch_extraction() {
    use crate::parallel::{extract_batch_parallel, BatchExtractionItem};

    let dir = tempdir().unwrap();

    let mut items = Vec::new();
    for i in 1..=6 {
        let pkg_content = format!("package-{i}-content");
        let tar_bytes = create_test_tarball(&[
            ("package/index.js", pkg_content.as_bytes(), 0o644),
            ("package/package.json", format!("{{\"name\": \"pkg-{i}\"}}").as_bytes(), 0o644),
        ]);
        let dest = dir.path().join(format!("pkg-{i}"));
        items.push(BatchExtractionItem::new(
            Cursor::new(tar_bytes),
            dest,
            None,
        ));
    }

    let summaries = extract_batch_parallel(items, 3);
    assert_eq!(summaries.len(), 6);
    for (i, summary_res) in summaries.into_iter().enumerate() {
        let idx = i + 1;
        let summary = summary_res.unwrap();
        assert_eq!(summary.entries_extracted, 2);

        let pkg_dir = dir.path().join(format!("pkg-{idx}"));
        assert!(pkg_dir.join("index.js").exists());
        assert!(pkg_dir.join("package.json").exists());
        let read_content = fs::read_to_string(pkg_dir.join("index.js")).unwrap();
        assert_eq!(read_content, format!("package-{idx}-content"));
    }
}

#[test]
fn test_extraction_throughput_benchmark() {
    use crate::parallel::{extract_batch_parallel, BatchExtractionItem};
    use std::time::Instant;

    let dir = tempdir().unwrap();
    let num_packages = 40;
    let mut tarballs = Vec::new();

    for i in 0..num_packages {
        let content_1 = vec![b'x'; 20_000];
        let content_2 = vec![b'y'; 40_000];
        let content_3 = vec![b'z'; 10_000];
        let tb = create_test_tarball(&[
            ("package/index.js", &content_1, 0o644),
            ("package/lib/large.js", &content_2, 0o644),
            ("package/lib/util.js", &content_3, 0o644),
            ("package/package.json", format!("{{\"name\":\"bench-pkg-{i}\",\"version\":\"1.0.0\"}}").as_bytes(), 0o644),
        ]);
        tarballs.push(tb);
    }

    // 1. Sequential extraction (concurrency = 1)
    let seq_dir = dir.path().join("sequential");
    fs::create_dir_all(&seq_dir).unwrap();
    let seq_items: Vec<_> = tarballs
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            BatchExtractionItem::new(
                Cursor::new(bytes.clone()),
                seq_dir.join(format!("pkg-{i}")),
                None,
            )
        })
        .collect();

    let t0 = Instant::now();
    let seq_res = extract_batch_parallel(seq_items, 1);
    let seq_time = t0.elapsed();
    assert_eq!(seq_res.len(), num_packages);

    // 2. Parallel extraction (bounded concurrency = 8)
    let par_dir = dir.path().join("parallel");
    fs::create_dir_all(&par_dir).unwrap();
    let par_items: Vec<_> = tarballs
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            BatchExtractionItem::new(
                Cursor::new(bytes.clone()),
                par_dir.join(format!("pkg-{i}")),
                None,
            )
        })
        .collect();

    let t1 = Instant::now();
    let par_res = extract_batch_parallel(par_items, 8);
    let par_time = t1.elapsed();
    assert_eq!(par_res.len(), num_packages);

    println!(
        "\n[EXTRACTION BENCHMARK] 40 packages (70KB uncompressed each, 2.8MB total):\n  Sequential (concurrency=1): {:?}\n  Parallel (concurrency=8): {:?}\n  Speedup: {:.2}x\n",
        seq_time,
        par_time,
        seq_time.as_secs_f64() / par_time.as_secs_f64()
    );
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

#[test]
fn test_security_rejection_symlink_slip_through_ancestor() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    // Create a symlink/junction inside dest pointing to an external directory
    let outside_dir = dir.path().join("outside_target");
    fs::create_dir_all(&outside_dir).unwrap();
    let link_in_dest = dest.join("symlink_dir");
    create_junction(&link_in_dest, &outside_dir).unwrap();

    // Attempt to extract a file through symlink_dir: package/symlink_dir/evil.txt
    let tar_bytes = create_test_tarball(&[
        ("package/symlink_dir/evil.txt", b"evil content", 0o644),
    ]);

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(
        matches!(res, Err(FsError::EscapingSymlink { .. })),
        "Expected EscapingSymlink when writing through ancestor symlink, got: {res:?}"
    );
    assert!(!outside_dir.join("evil.txt").exists(), "Must not write through symlink to outside target");
}

#[test]
fn test_security_extended_windows_reserved_device_names() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let device_names = [
        "package/com0.js",
        "package/lpt0.txt",
        "package/clock$",
        "package/aux .txt",
        "package/con.tar.gz",
        "package/COM\u{00B9}.dat",
        "package/LPT\u{00B2}.log",
    ];

    for dev in device_names {
        let tar_bytes = create_test_tarball(&[(dev, b"device data", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::WindowsReservedDeviceName { .. })),
            "Expected WindowsReservedDeviceName for {dev}, got: {res:?}"
        );
    }
}

#[test]
fn test_security_rejection_ascii_control_characters() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let ctrl_names = [
        "package/file\x01test.js",
        "package/test\x1F.txt",
        "package/line\nbreak.js",
        "package/return\r.js",
    ];

    for name in ctrl_names {
        let tar_bytes = create_test_tarball(&[(name, b"ctrl", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::PathTraversal { .. })),
            "Expected PathTraversal for control char in {name:?}, got: {res:?}"
        );
    }
}

#[test]
fn test_tar_bomb_single_entry_size_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let data = vec![b'X'; 50_000];
    let tar_bytes = create_test_tarball(&[("package/huge_entry.bin", &data, 0o644)]);

    let limits = TarLimits {
        max_single_entry_size: 20_000,
        ..Default::default()
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "entry size"),
        "Expected TarBombLimitExceeded for single entry size, got: {res:?}"
    );
}

#[test]
fn test_tar_bomb_symlink_count_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        // Base file
        let mut h0 = Header::new_gnu();
        h0.set_size(4);
        h0.set_mode(0o644);
        let path0 = b"package/base.txt";
        h0.as_mut_bytes()[..path0.len()].copy_from_slice(path0);
        h0.set_cksum();
        builder.append(&h0, Cursor::new(b"base")).unwrap();

        // 5 symlinks
        for i in 1..=5 {
            let mut h = Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            let link_path = format!("package/link{i}.txt");
            h.as_mut_bytes()[..link_path.len()].copy_from_slice(link_path.as_bytes());
            h.set_link_name("base.txt").unwrap();
            h.set_cksum();
            builder.append(&h, Cursor::new(&[])).unwrap();
        }
        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let limits = TarLimits {
        max_symlinks: 3,
        ..Default::default()
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "symlink count"),
        "Expected TarBombLimitExceeded for symlink count, got: {res:?}"
    );
}

#[test]
fn test_strip_package_prefix_handles_leading_dot_slash() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let tar_bytes = create_test_tarball(&[
        ("./package/index.js", b"console.log('dot slash');", 0o644),
    ]);

    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 1);
    assert!(dest.join("index.js").exists(), "Must extract to index.js, stripping ./package/");
    assert!(!dest.join("package").exists());
}

#[test]
fn test_remove_junction_refuses_regular_dir() {
    let dir = tempdir().unwrap();
    let regular_dir = dir.path().join("regular_dir");
    fs::create_dir_all(&regular_dir).unwrap();
    fs::write(regular_dir.join("file.txt"), "keep me").unwrap();

    let res = remove_junction(&regular_dir);
    assert!(res.is_err(), "remove_junction must refuse to remove a regular directory");
    assert!(regular_dir.exists(), "Regular directory must still exist");
    assert!(regular_dir.join("file.txt").exists());
}

#[test]
fn test_safe_remove_dir_all_with_nested_junctions() {
    let dir = tempdir().unwrap();
    let external_target = dir.path().join("external_workspace_pkg");
    fs::create_dir_all(&external_target).unwrap();
    let external_file = external_target.join("important_src.ts");
    fs::write(&external_file, "console.log('precious');").unwrap();

    let parent = dir.path().join("node_modules");
    let nested = parent.join("@scope");
    fs::create_dir_all(&nested).unwrap();

    let link_path = nested.join("pkg");
    create_junction(&link_path, &external_target).unwrap();
    assert!(is_junction(&link_path).unwrap());
    assert!(link_path.join("important_src.ts").exists());

    // Also create regular files and directories inside parent
    let regular_sub = parent.join("regular-pkg");
    fs::create_dir_all(&regular_sub).unwrap();
    fs::write(regular_sub.join("index.js"), "regular").unwrap();

    // Now call remove_dir_all_safe on parent
    crate::junction::remove_dir_all_safe(&parent).unwrap();

    // Verify parent and all nested node_modules are deleted
    assert!(!parent.exists(), "Parent node_modules must be deleted");
    assert!(!link_path.exists(), "Junction link must be deleted");

    // CRUCIAL: External target directory and its files must be completely preserved!
    assert!(external_target.exists(), "External target directory must NOT be deleted");
    assert!(external_file.exists(), "External target file must NOT be deleted");
    assert_eq!(fs::read_to_string(&external_file).unwrap(), "console.log('precious');");
}

#[test]
fn test_replace_dir_with_retries_replaces_junction() {
    let dir = tempdir().unwrap();
    let external_target = dir.path().join("ext_target");
    fs::create_dir_all(&external_target).unwrap();
    fs::write(external_target.join("ext.txt"), "external data").unwrap();

    let dest = dir.path().join("destination_junction");
    create_junction(&dest, &external_target).unwrap();
    assert!(is_junction(&dest).unwrap());

    // Create staging directory with regular content
    let staging = dir.path().join("staging_dir");
    fs::create_dir_all(&staging).unwrap();
    fs::write(staging.join("new.txt"), "new data").unwrap();

    // Atomically replace destination junction with staging directory
    crate::atomic::replace_dir_with_retries(&staging, &dest, 5).unwrap();

    // Verify destination is now a regular directory containing new.txt
    assert!(dest.exists());
    assert!(!is_junction(&dest).unwrap());
    assert!(dest.join("new.txt").exists());

    // Verify external target was NOT destroyed during atomic replacement!
    assert!(external_target.exists());
    assert!(external_target.join("ext.txt").exists());
}

#[test]
fn test_extreme_archive_zero_byte_tarball() {
    let dir = tempdir().unwrap();
    let dest_extract = dir.path().join("dest_extract");
    let dest_replace = dir.path().join("dest_replace");

    // 1. Raw 0-byte buffer: extract_tar_gz must return error (unexpected EOF on gzip header)
    let res_empty = extract_tar_gz(Cursor::new(&[]), &dest_extract, None);
    assert!(res_empty.is_err(), "0-byte tarball must fail extraction");

    // 2. extract_and_replace with 0-byte buffer: destination is clean and no temp files remain
    let replace_res = extract_and_replace(Cursor::new(&[]), &dest_replace, None);
    assert!(replace_res.is_err(), "0-byte extract_and_replace must fail");
    assert!(!dest_replace.exists(), "Destination should not exist after 0-byte failure");

    // Verify parent directory has no leftover staging tempdirs
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".rnpm-staging-") && !name.starts_with(".rnpm-trash-"),
            "No leftover staging directories should remain: {name}"
        );
    }

    // 3. Valid gzip stream containing 0 bytes of tar data (empty archive)
    let empty_gz = GzEncoder::new(Vec::new(), Compression::default());
    let empty_gz_bytes = empty_gz.finish().unwrap();
    let summary = extract_tar_gz(Cursor::new(&empty_gz_bytes), &dest_extract, None).unwrap();
    assert_eq!(summary.entries_extracted, 0);
    assert_eq!(summary.total_uncompressed_bytes, 0);
}

#[test]
fn test_extreme_archive_truncated_tarball() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest_trunc");

    let full_content = vec![b'T'; 40_000];
    let valid_tar = create_test_tarball(&[
        ("package/package.json", br#"{"name":"trunc-test","version":"1.0.0"}"#, 0o644),
        ("package/large_file.dat", &full_content, 0o644),
        ("package/index.js", b"console.log('done');", 0o644),
    ]);

    // Test truncation at multiple cut points:
    // a. 10 bytes (mid-gzip header)
    assert!(extract_tar_gz(Cursor::new(&valid_tar[..10]), &dest, None).is_err());

    // b. 100 bytes (mid gzip compressed block)
    assert!(extract_tar_gz(Cursor::new(&valid_tar[..100]), &dest, None).is_err());

    // c. 50% truncation (mid tar stream)
    assert!(extract_tar_gz(Cursor::new(&valid_tar[..valid_tar.len() / 2]), &dest, None).is_err());

    // d. Truncated by last 15 bytes (missing gzip trailer/crc)
    assert!(extract_tar_gz(Cursor::new(&valid_tar[..valid_tar.len() - 15]), &dest, None).is_err());

    // Test extract_and_replace with truncated tarball:
    // Verify rollback / non-destructive behavior: existing destination remains untouched
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("precious.txt"), "precious data").unwrap();

    let res = extract_and_replace(Cursor::new(&valid_tar[..valid_tar.len() / 2]), &dest, None);
    assert!(res.is_err(), "Truncated tarball must fail in extract_and_replace");

    // Existing data was NOT corrupted or lost!
    assert_eq!(fs::read_to_string(dest.join("precious.txt")).unwrap(), "precious data");
}

struct TarStreamOfMillionEntries {
    entry_index: usize,
    total_entries: usize,
    current_header: [u8; 512],
    header_offset: usize,
}

impl TarStreamOfMillionEntries {
    fn new(total_entries: usize) -> Self {
        Self {
            entry_index: 0,
            total_entries,
            current_header: [0u8; 512],
            header_offset: 512,
        }
    }

    fn prepare_next_header(&mut self) -> bool {
        if self.entry_index >= self.total_entries {
            return false;
        }
        let i = self.entry_index;
        self.entry_index += 1;

        let mut header = Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        let path = format!("package/f_{i}.txt");
        let path_bytes = path.as_bytes();
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();

        self.current_header.copy_from_slice(header.as_bytes());
        self.header_offset = 0;
        true
    }
}

impl std::io::Read for TarStreamOfMillionEntries {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.header_offset >= 512 {
            if !self.prepare_next_header() {
                return Ok(0);
            }
        }

        let available = 512 - self.header_offset;
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.current_header[self.header_offset..self.header_offset + to_copy]);
        self.header_offset += to_copy;
        Ok(to_copy)
    }
}

#[test]
fn test_extreme_archive_millions_of_entries_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest_entries_bomb");

    // 1. With an archive streaming 1,000,000 tiny entries, test entry count limit enforcement
    // halts promptly at entry 501 without exhausting memory, file handles, or disk space
    let start = std::time::Instant::now();
    let stream_1 = flate2::read::GzEncoder::new(TarStreamOfMillionEntries::new(1_000_000), Compression::none());
    let limits_500 = TarLimits {
        max_entries: 500,
        ..Default::default()
    };
    let res = extract_tar_gz(stream_1, &dest, Some(limits_500));
    let elapsed = start.elapsed();
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "entry count"),
        "Must trigger entry count limit for 1,000,000 entries stream: {res:?}"
    );
    assert!(elapsed < std::time::Duration::from_secs(3), "Must halt fast without processing all 1M entries: {:?}", elapsed);

    // 2. With extract_and_replace: verify staging directory is cleaned up and no files leaked to dest
    let stream_replace = flate2::read::GzEncoder::new(TarStreamOfMillionEntries::new(1_000_000), Compression::none());
    let dest_replace = dir.path().join("dest_replace_bomb");
    let limits_replace = TarLimits {
        max_entries: 200,
        ..Default::default()
    };
    let replace_res = extract_and_replace(stream_replace, &dest_replace, Some(limits_replace));
    assert!(replace_res.is_err());
    assert!(!dest_replace.exists(), "Destination should not exist after entry bomb failure");

    // 3. Low limit (50 entries), halts at entry 51 in under 300ms!
    let start_low = std::time::Instant::now();
    let stream_low = flate2::read::GzEncoder::new(TarStreamOfMillionEntries::new(1_000_000), Compression::none());
    let low_limit = TarLimits {
        max_entries: 50,
        ..Default::default()
    };
    let res_low = extract_tar_gz(stream_low, &dest, Some(low_limit));
    let elapsed_low = start_low.elapsed();
    assert!(
        matches!(res_low, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "entry count"),
        "Must trigger entry count limit for low_limit: {res_low:?}"
    );
    assert!(elapsed_low < std::time::Duration::from_millis(300), "Must fail fast: took {:?}", elapsed_low);
}

#[test]
fn test_deeply_nested_paths_exceeding_max_path() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("deep_dest");

    // Construct a deeply nested path exceeding standard Windows MAX_PATH (260 characters).
    // E.g. package/ + 12 levels of 25 characters + filename -> total length > 350 chars
    let mut deep_rel = String::from("package");
    for i in 0..12 {
        deep_rel.push_str(&format!("/level_{i}_abcdefghijklmnop"));
    }
    deep_rel.push_str("/very_long_nested_filename_exceeding_windows_max_path_260_limit.txt");

    let expected_content = b"deeply nested payload content that survived long path extraction";
    let tar_bytes = create_test_tarball(&[
        ("package/package.json", br#"{"name":"deep-pkg","version":"1.0.0"}"#, 0o644),
        (&deep_rel, expected_content, 0o644),
    ]);

    // 1. Extract with extract_and_replace
    let summary = extract_and_replace(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 2);

    // Verify file exists and content matches
    let sub_path = deep_rel.strip_prefix("package/").unwrap();
    let extracted_file = dest.join(sub_path);
    assert!(extracted_file.exists(), "Deeply nested file must exist on disk");
    let read_back = fs::read(&extracted_file).unwrap();
    assert_eq!(read_back, expected_content);

    // Total path string length should be > 260 characters
    let full_path_str = extracted_file.to_string_lossy();
    assert!(
        full_path_str.len() > 260,
        "Test path length was {} (expected > 260): {}",
        full_path_str.len(),
        full_path_str
    );

    // 2. Safe recursive deletion must handle paths > MAX_PATH without error
    crate::junction::remove_dir_all_safe(&dest).unwrap();
    assert!(!dest.exists(), "Deeply nested directory must be completely removed");
}

#[test]
fn test_stress_atomic_replacement_under_antivirus_contention() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let dest = dir.path().join("av_contended_package");

    // Initialize version 1
    let tar_v1 = create_test_tarball(&[
        ("package/package.json", br#"{"name":"av-pkg","version":"1.0.0"}"#, 0o644),
        ("package/index.js", b"console.log('v1.0.0');", 0o644),
        ("package/lib/helper.js", b"module.exports = 1;", 0o644),
    ]);
    extract_and_replace(Cursor::new(&tar_v1), &dest, None).unwrap();

    let running = Arc::new(AtomicBool::new(true));

    // Anti-virus simulator thread:
    // Repeatedly opens files inside dest with exclusive access for 5-10ms bursts
    let dest_av = dest.clone();
    let r_av = Arc::clone(&running);
    let av_handle = thread::spawn(move || {
        let targets = ["index.js", "package.json", "lib/helper.js"];
        let mut idx = 0;
        while r_av.load(Ordering::Relaxed) {
            let target_rel = targets[idx % targets.len()];
            idx += 1;
            let file_path = dest_av.join(target_rel);
            if let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(&file_path) {
                // Hold lock for 8ms simulating AV scan
                thread::sleep(Duration::from_millis(8));
                drop(file);
            }
            thread::sleep(Duration::from_millis(3));
        }
    });

    // 3 parallel worker threads racing to atomically replace dest with different versions
    let mut workers = Vec::new();
    for worker_id in 0..3 {
        let dest_w = dest.clone();
        let w_handle = thread::spawn(move || {
            for v in 1..=4 {
                let v_str = format!("2.{worker_id}.{v}");
                let pkg_json = format!(r#"{{"name":"av-pkg","version":"{v_str}"}}"#);
                let idx_js = format!("console.log('{v_str}');");
                let tar_bytes = create_test_tarball(&[
                    ("package/package.json", pkg_json.as_bytes(), 0o644),
                    ("package/index.js", idx_js.as_bytes(), 0o644),
                    ("package/lib/helper.js", b"helper code", 0o644),
                ]);

                // extract_and_replace must succeed despite transient AV sharing violations
                let res = extract_and_replace(Cursor::new(&tar_bytes), &dest_w, None);
                assert!(
                    res.is_ok(),
                    "Worker {worker_id} iter {v} failed atomic replacement under AV contention: {:?}",
                    res.err()
                );
            }
        });
        workers.push(w_handle);
    }

    for w in workers {
        w.join().expect("Worker thread panicked under AV contention");
    }

    // Stop anti-virus simulation thread
    running.store(false, Ordering::Relaxed);
    av_handle.join().unwrap();

    // Verify destination is intact, contains valid files, and no temp files remain
    assert!(dest.join("package.json").exists());
    assert!(dest.join("index.js").exists());
    assert!(dest.join("lib/helper.js").exists());

    let final_pkg = fs::read_to_string(dest.join("package.json")).unwrap();
    assert!(final_pkg.contains("av-pkg"));

    // Verify no .rnpm-trash or .rnpm-staging leftover directories
    let parent = dest.parent().unwrap();
    for entry in fs::read_dir(parent).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".rnpm-trash-") && !name.starts_with(".rnpm-staging-"),
            "Leftover staging/trash dir found: {name}"
        );
    }
}

#[test]
fn test_stress_ntfs_junction_handling_under_high_parallel_contention() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create 4 target packages with precious contents
    let mut targets = Vec::new();
    for t in 0..4 {
        let target_dir = root.join(format!("target_pkg_{t}"));
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("data.txt"), format!("precious data {t}")).unwrap();
        targets.push(target_dir);
    }

    let running = Arc::new(AtomicBool::new(true));

    // AV scanner thread continuously reading target files
    let targets_clone = targets.clone();
    let r_av = Arc::clone(&running);
    let av_handle = thread::spawn(move || {
        while r_av.load(Ordering::Relaxed) {
            for t in &targets_clone {
                let _ = fs::read(t.join("data.txt"));
            }
            thread::sleep(Duration::from_millis(3));
        }
    });

    let targets_arc = Arc::new(targets);
    let mut junction_threads = Vec::new();

    // 8 parallel threads creating, reading through, and safely removing junctions
    for thread_id in 0..8 {
        let t_arc = Arc::clone(&targets_arc);
        let link_parent = root.join(format!("links_thread_{thread_id}"));
        fs::create_dir_all(&link_parent).unwrap();

        let h = thread::spawn(move || {
            for iter in 0..6 {
                let target = &t_arc[iter % t_arc.len()];
                let link = link_parent.join(format!("link_iter_{iter}"));

                // 1. Create junction
                create_junction(&link, target).expect("Failed to create junction");
                assert!(is_junction(&link).unwrap());

                // 2. Read through junction
                let data = fs::read_to_string(link.join("data.txt")).expect("Failed to read through junction");
                assert!(data.starts_with("precious data"));

                // 3. Safely remove junction
                remove_junction(&link).expect("Failed to safely remove junction");
                assert!(!link.exists());
            }

            // Cleanup links directory using remove_dir_all_safe
            crate::junction::remove_dir_all_safe(&link_parent).expect("Failed to clean link parent");
        });
        junction_threads.push(h);
    }

    for h in junction_threads {
        h.join().expect("Junction thread panicked");
    }

    running.store(false, Ordering::Relaxed);
    av_handle.join().unwrap();

    // CRITICAL: Verify ALL target directories and files are 100% untouched and intact!
    for (t, target_dir) in targets_arc.iter().enumerate() {
        assert!(target_dir.exists(), "Target directory must NOT be deleted");
        let data = fs::read_to_string(target_dir.join("data.txt")).unwrap();
        assert_eq!(data, format!("precious data {t}"), "Target data must never be modified or destroyed");
    }
}

#[test]
fn test_readonly_file_overwriting_and_removal() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("readonly_pkg");
    fs::create_dir_all(&dest).unwrap();

    // 1. Create existing read-only file in destination
    let test_file = dest.join("file.txt");
    fs::write(&test_file, b"initial content").unwrap();

    #[cfg(windows)]
    {
        let mut perms = fs::metadata(&test_file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&test_file, perms).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&test_file).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&test_file, perms).unwrap();
    }

    // 2. Extract tarball that overwrites the existing read-only file
    let tar_bytes = create_test_tarball(&[
        ("package/package.json", br#"{"name":"ro-pkg","version":"1.0.0"}"#, 0o644),
        ("package/file.txt", b"overwritten content with new permissions", 0o644),
    ]);

    let summary = extract_and_replace(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 2);

    let content = fs::read(&dest.join("file.txt")).unwrap();
    assert_eq!(content, b"overwritten content with new permissions");

    // 3. Mark extracted file as read-only again
    #[cfg(windows)]
    {
        let mut perms = fs::metadata(&test_file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&test_file, perms).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&test_file).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&test_file, perms).unwrap();
    }

    // 4. Safe removal of tree containing read-only file must succeed cleanly
    crate::junction::remove_dir_all_safe(&dest).unwrap();
    assert!(!dest.exists());
}

#[test]
fn test_atomic_write_recovery_cleans_abandoned_staging_and_trash() {
    let dir = tempdir().unwrap();
    let parent = dir.path();

    // Simulate abandoned staging and trash directories left behind by a killed process
    let stale_trash1 = parent.join(".rnpm-trash-999-12345-1");
    let stale_staging1 = parent.join(".rnpm-staging-999-12345-2");
    fs::create_dir_all(&stale_trash1).unwrap();
    fs::create_dir_all(&stale_staging1).unwrap();
    fs::write(stale_trash1.join("orphan.txt"), b"orphaned trash content").unwrap();
    fs::write(stale_staging1.join("orphan.txt"), b"orphaned staging content").unwrap();

    assert!(stale_trash1.exists());
    assert!(stale_staging1.exists());

    // Recover atomic writes
    crate::atomic::recover_atomic_writes(parent);

    assert!(!stale_trash1.exists(), "Stale trash directory must be cleaned up");
    assert!(!stale_staging1.exists(), "Stale staging directory must be cleaned up");
}

#[test]
fn test_broken_junction_safe_removal() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target_dir");
    fs::create_dir_all(&target).unwrap();

    let link = dir.path().join("junction_link");
    create_junction(&link, &target).unwrap();
    assert!(is_junction(&link).unwrap());

    // Delete target, making the junction broken
    fs::remove_dir_all(&target).unwrap();
    assert!(!target.exists());

    // remove_junction must still safely unlink the broken junction
    remove_junction(&link).unwrap();
    assert!(!link.exists());
}

#[test]
fn test_security_rejection_special_device_entries() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Test FIFO, Block special, and Character special
    let special_types = [
        (tar::EntryType::Fifo, "package/my_fifo"),
        (tar::EntryType::Block, "package/my_block"),
        (tar::EntryType::Char, "package/my_char"),
    ];

    for (entry_type, path) in special_types {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = Builder::new(&mut gz);
            let mut header = Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, Cursor::new(&[])).unwrap();
            builder.finish().unwrap();
        }
        let tar_bytes = gz.finish().unwrap();

        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::ForbiddenSpecialEntry { .. })),
            "Expected ForbiddenSpecialEntry for {:?} ({}), got: {:?}",
            entry_type,
            path,
            res
        );
    }
}

#[test]
fn test_security_rejection_windows_illegal_characters() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let illegal_names = [
        "package/star*name.js",
        "package/question?mark.js",
        "package/quote\"test.js",
        "package/left<angle.js",
        "package/right>angle.js",
        "package/pipe|test.js",
    ];

    for bad in illegal_names {
        let tar_bytes = create_test_tarball(&[(bad, b"dummy content", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::PathTraversal { .. })),
            "Expected PathTraversal for {}, got: {:?}",
            bad,
            res
        );
    }
}

#[test]
fn test_security_hardlink_attacks_rejection() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. Hardlink pointing outside extraction directory
    let mut gz1 = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz1);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_link(&mut header, "package/evil_hardlink.js", "package/../../etc/passwd").unwrap();
        builder.finish().unwrap();
    }
    let tar_outside = gz1.finish().unwrap();
    let res_outside = extract_tar_gz(Cursor::new(&tar_outside), &dest, None);
    assert!(
        matches!(res_outside, Err(FsError::EscapingSymlink { .. })),
        "Expected EscapingSymlink for hardlink escaping destination, got: {:?}",
        res_outside
    );

    // 2. Hardlink pointing to a symlink
    let mut gz2 = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz2);

        // First append regular file
        let mut h_file = Header::new_gnu();
        h_file.set_size(12);
        h_file.set_mode(0o644);
        h_file.set_cksum();
        builder.append_data(&mut h_file, "package/target.txt", Cursor::new(b"hello target")).unwrap();

        // Second append symlink pointing to regular file
        let mut h_sym = Header::new_gnu();
        h_sym.set_entry_type(tar::EntryType::Symlink);
        h_sym.set_size(0);
        h_sym.set_mode(0o777);
        h_sym.set_cksum();
        builder.append_link(&mut h_sym, "package/sub/symlink.js", "../target.txt").unwrap();

        // Third append hardlink pointing to the symlink
        let mut h_hard = Header::new_gnu();
        h_hard.set_entry_type(tar::EntryType::Link);
        h_hard.set_size(0);
        h_hard.set_mode(0o644);
        h_hard.set_cksum();
        builder.append_link(&mut h_hard, "package/hardlink_to_sym.js", "package/sub/symlink.js").unwrap();

        builder.finish().unwrap();
    }
    let tar_sym = gz2.finish().unwrap();
    let res_sym = extract_tar_gz(Cursor::new(&tar_sym), &dest, None);
    assert!(
        matches!(res_sym, Err(FsError::EscapingSymlink { .. })),
        "Expected EscapingSymlink for hardlink pointing to a symlink, got: {:?}",
        res_sym
    );
}

#[test]
fn test_case_insensitive_package_prefix_extraction() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let tar_bytes = create_test_tarball(&[
        ("PACKAGE/upper.txt", b"uppercase prefix", 0o644),
        ("Package/mixed.txt", b"mixed case prefix", 0o644),
        ("pAcKaGe/sub/strange.txt", b"strange case prefix", 0o644),
    ]);

    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 3);

    assert!(dest.join("upper.txt").exists());
    assert!(dest.join("mixed.txt").exists());
    assert!(dest.join("sub/strange.txt").exists());
    assert_eq!(fs::read_to_string(dest.join("upper.txt")).unwrap(), "uppercase prefix");
}

#[test]
fn test_windows_junction_cleanup_before_unpacking() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    let external_target = dir.path().join("external_target");
    fs::create_dir_all(&dest).unwrap();
    fs::create_dir_all(&external_target).unwrap();
    fs::write(external_target.join("important.txt"), b"do not delete me!").unwrap();

    // Create a junction inside dest at dest/my_file
    let junction_path = dest.join("my_file");
    create_junction(&junction_path, &external_target).unwrap();
    assert!(is_junction(&junction_path).unwrap());

    // Extract a tarball where "package/my_file" is a file replacing the pre-existing directory junction.
    // On Windows, fs::remove_file fails on directory junctions, but unlink_target_path uses remove_junction.
    let tar_bytes = create_test_tarball(&[
        ("package/my_file", b"new file content", 0o644),
    ]);
    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 1);

    // Verify extracted file exists and replaced the junction
    assert!(dest.join("my_file").is_file());
    assert_eq!(
        fs::read_to_string(dest.join("my_file")).unwrap(),
        "new file content"
    );

    // Verify external target was NOT destroyed or overwritten
    assert!(external_target.join("important.txt").exists());
    assert_eq!(
        fs::read_to_string(external_target.join("important.txt")).unwrap(),
        "do not delete me!"
    );
}

#[test]
fn test_zip_slip_escapes_comprehensive() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Absolute Unix path
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mut header = Header::new_gnu();
        header.set_size(10);
        header.set_mode(0o644);
        let path_bytes = b"/etc/passwd";
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();
        builder.append(&header, Cursor::new(b"evil data!")).unwrap();
        builder.finish().unwrap();
    }
    let tar_abs = gz.finish().unwrap();
    let res_abs = extract_tar_gz(Cursor::new(&tar_abs), &dest, None);
    assert!(
        matches!(res_abs, Err(FsError::AbsolutePath { .. })),
        "Expected AbsolutePath for /etc/passwd, got: {:?}",
        res_abs
    );

    // Drive colon path (e.g. C:/evil.js)
    let tar_drive = create_test_tarball(&[("C:/evil.js", b"evil", 0o644)]);
    let res_drive = extract_tar_gz(Cursor::new(&tar_drive), &dest, None);
    assert!(
        matches!(res_drive, Err(FsError::PathTraversal { .. }) | Err(FsError::AbsolutePath { .. })),
        "Expected PathTraversal/AbsolutePath for drive colon, got: {:?}",
        res_drive
    );

    // Prefix traversal (package/../secret.js)
    let tar_prefix = create_test_tarball(&[("package/../secret.js", b"evil", 0o644)]);
    let res_prefix = extract_tar_gz(Cursor::new(&tar_prefix), &dest, None);
    assert!(
        matches!(res_prefix, Err(FsError::PathTraversal { .. })),
        "Expected PathTraversal for prefix traversal, got: {:?}",
        res_prefix
    );
}

#[test]
fn test_windows_reserved_names_and_dot_space_comprehensive() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let reserved = [
        "package/aux.js",
        "package/COM¹",
        "package/com1.json",
        "package/LPT9.dat",
        "package/PRN",
        "package/CLOCK$",
    ];
    for name in reserved {
        let tar_bytes = create_test_tarball(&[(name, b"dummy", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::WindowsReservedDeviceName { .. })),
            "Expected WindowsReservedDeviceName for {name}, got: {:?}",
            res
        );
    }

    let dot_space = [
        "package/foo.",
        "package/bar ",
    ];
    for name in dot_space {
        let tar_bytes = create_test_tarball(&[(name, b"dummy", 0o644)]);
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(
            matches!(res, Err(FsError::TrailingDotOrSpace { .. })),
            "Expected TrailingDotOrSpace for {name}, got: {:?}",
            res
        );
    }
}

#[test]
fn test_windows_case_collision_detection() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. Exact case collision between two files: foo.js and FOO.JS
    let tar_files = create_test_tarball(&[
        ("package/foo.js", b"console.log('lower');", 0o644),
        ("package/FOO.JS", b"console.log('upper');", 0o644),
    ]);
    let res_files = extract_tar_gz(Cursor::new(&tar_files), &dest, None);
    assert!(
        matches!(res_files, Err(FsError::CaseCollision { .. })),
        "Expected CaseCollision for foo.js and FOO.JS, got: {res_files:?}"
    );

    // 2. Directory vs file collision: package/my_dir/file.txt and package/MY_DIR
    let tar_dir_file = create_test_tarball(&[
        ("package/my_dir/file.txt", b"child content", 0o644),
        ("package/MY_DIR", b"file content", 0o644),
    ]);
    let dest2 = dir.path().join("dest2");
    let res_dir_file = extract_tar_gz(Cursor::new(&tar_dir_file), &dest2, None);
    assert!(
        matches!(res_dir_file, Err(FsError::CaseCollision { .. })),
        "Expected CaseCollision for dir my_dir vs file MY_DIR, got: {res_dir_file:?}"
    );

    // 3. File first, then directory collision: package/item and package/ITEM/child.txt
    let tar_file_dir = create_test_tarball(&[
        ("package/item", b"file content", 0o644),
        ("package/ITEM/child.txt", b"child content", 0o644),
    ]);
    let dest3 = dir.path().join("dest3");
    let res_file_dir = extract_tar_gz(Cursor::new(&tar_file_dir), &dest3, None);
    assert!(
        matches!(res_file_dir, Err(FsError::CaseCollision { .. })),
        "Expected CaseCollision for file item vs dir ITEM, got: {res_file_dir:?}"
    );
}

#[test]
fn test_security_rejection_sparse_files() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. GNU sparse file entry (type 'S')
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(0);
        header.set_mode(0o644);
        header.as_gnu_mut().unwrap().set_real_size(0);
        let path_bytes = b"package/sparse.bin";
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();
        builder.append(&header, Cursor::new(&[])).unwrap();
        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(
        matches!(res, Err(FsError::ForbiddenSparseFile { .. })),
        "Expected ForbiddenSparseFile for entry_type b'S', got: {res:?}"
    );

    // 2. PAX sparse attributes (GNU.sparse.*)
    let mut gz_pax = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz_pax);
        builder.append_pax_extensions([("GNU.sparse.size", b"1024".as_slice())]).unwrap();

        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        let path_bytes = b"package/pax_sparse.bin";
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();
        builder.append(&header, Cursor::new(b"data")).unwrap();
        builder.finish().unwrap();
    }
    let tar_pax = gz_pax.finish().unwrap();
    let dest_pax = dir.path().join("dest_pax");
    let res_pax = extract_tar_gz(Cursor::new(&tar_pax), &dest_pax, None);
    assert!(
        matches!(res_pax, Err(FsError::ForbiddenSparseFile { .. })),
        "Expected ForbiddenSparseFile for PAX sparse attributes, got: {res_pax:?}"
    );
}

#[test]
fn test_tar_bomb_path_depth_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. Path exceeding default limit (> 32 components): 33 components
    let mut deep_path = String::from("package");
    for i in 1..=33 {
        deep_path.push_str(&format!("/d{i}"));
    }
    deep_path.push_str("/file.txt");

    let tar_bytes = create_test_tarball(&[
        (&deep_path, b"content", 0o644),
    ]);

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "path depth"),
        "Expected TarBombLimitExceeded with limit_type 'path depth', got: {res:?}"
    );

    // 2. Custom small limit: max_path_depth = 4
    let limits = TarLimits {
        max_path_depth: 4,
        ..Default::default()
    };
    let tar_shallow = create_test_tarball(&[
        ("package/1/2/3/4/5/file.txt", b"shallow", 0o644),
    ]);
    let dest2 = dir.path().join("dest2");
    let res2 = extract_tar_gz(Cursor::new(&tar_shallow), &dest2, Some(limits));
    assert!(
        matches!(res2, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "path depth"),
        "Expected TarBombLimitExceeded for custom path depth limit, got: {res2:?}"
    );
}

#[test]
fn test_tar_bomb_directory_count_limit() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        // Create 4 directory entries
        for i in 1..=4 {
            let mut header = Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            let dir_path = format!("package/dir_{i}/");
            header.as_mut_bytes()[..dir_path.len()].copy_from_slice(dir_path.as_bytes());
            header.set_cksum();
            builder.append(&header, Cursor::new(&[])).unwrap();
        }
        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let limits = TarLimits {
        max_directories: 3,
        ..Default::default()
    };

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, Some(limits));
    assert!(
        matches!(res, Err(FsError::TarBombLimitExceeded { ref limit_type, .. }) if limit_type == "directory count"),
        "Expected TarBombLimitExceeded with limit_type 'directory count', got: {res:?}"
    );
}

#[test]
fn test_security_rejection_dangling_and_circular_hardlinks() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // 1. Dangling hardlink pointing to non-existent target
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_link(&mut header, "package/dangling_link.js", "package/ghost.js").unwrap();
        builder.finish().unwrap();
    }
    let tar_dangling = gz.finish().unwrap();
    let res_dangling = extract_tar_gz(Cursor::new(&tar_dangling), &dest, None);
    assert!(
        matches!(res_dangling, Err(FsError::DanglingHardlink { .. })),
        "Expected DanglingHardlink error, got: {res_dangling:?}"
    );

    // 2. Circular hardlink pointing to itself
    let mut gz_circ = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz_circ);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_link(&mut header, "package/self_loop.js", "package/self_loop.js").unwrap();
        builder.finish().unwrap();
    }
    let tar_circ = gz_circ.finish().unwrap();
    let dest_circ = dir.path().join("dest_circ");
    let res_circ = extract_tar_gz(Cursor::new(&tar_circ), &dest_circ, None);
    assert!(
        matches!(res_circ, Err(FsError::CircularHardlink { .. })),
        "Expected CircularHardlink error, got: {res_circ:?}"
    );
}

#[test]
fn test_hardlink_target_resolution_from_archive_root() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Hardlink inside package/bin/sub/tool.js pointing to package/lib/source.js.
    // In tar archives, hardlink targets are relative to archive root, NOT relative to link parent dir.
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);

        // 1. Regular file at lib/source.js
        let mut h_file = Header::new_gnu();
        let content = b"console.log('root hardlink success');";
        h_file.set_size(content.len() as u64);
        h_file.set_mode(0o644);
        h_file.set_cksum();
        builder.append_data(&mut h_file, "package/lib/source.js", Cursor::new(content)).unwrap();

        // 2. Hardlink at bin/sub/tool.js pointing to lib/source.js (or package/lib/source.js)
        let mut h_link = Header::new_gnu();
        h_link.set_entry_type(tar::EntryType::Link);
        h_link.set_size(0);
        h_link.set_mode(0o644);
        h_link.set_cksum();
        builder.append_link(&mut h_link, "package/bin/sub/tool.js", "package/lib/source.js").unwrap();

        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 2);

    let src_path = dest.join("lib/source.js");
    let link_path = dest.join("bin/sub/tool.js");

    assert!(src_path.exists(), "Source file must exist");
    assert!(link_path.exists(), "Hardlink target must exist at resolved path");

    let link_content = fs::read(&link_path).unwrap();
    assert_eq!(link_content, b"console.log('root hardlink success');");
}

#[test]
fn test_security_rejection_non_utf8_path() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        // Raw bytes with invalid UTF-8 sequence 0xFF 0xFE
        let path_bytes = b"package/bad_\xff\xfe_file.txt";
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_cksum();
        builder.append(&header, Cursor::new(b"data")).unwrap();
        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(
        matches!(res, Err(FsError::InvalidUtf8Path { .. })),
        "Expected InvalidUtf8Path error, got: {res:?}"
    );
}

#[test]
fn test_skip_xglobal_header_without_validation_failure() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);

        // 1. XGlobalHeader entry (type 'g')
        let mut h_global = Header::new_gnu();
        h_global.set_entry_type(tar::EntryType::XGlobalHeader);
        let global_data = b"comment=rnpm global pax header\n";
        h_global.set_size(global_data.len() as u64);
        h_global.set_mode(0o644);
        let path_bytes = b"pax_global_header";
        h_global.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        h_global.set_cksum();
        builder.append(&h_global, Cursor::new(global_data)).unwrap();

        // 2. Regular entry
        let mut h_file = Header::new_gnu();
        let content = b"console.log('xglobal skipped successfully');";
        h_file.set_size(content.len() as u64);
        h_file.set_mode(0o644);
        h_file.set_cksum();
        builder.append_data(&mut h_file, "package/index.js", Cursor::new(content)).unwrap();

        builder.finish().unwrap();
    }
    let tar_bytes = gz.finish().unwrap();

    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 1);
    assert!(dest.join("index.js").exists());
}


