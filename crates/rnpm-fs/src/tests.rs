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
