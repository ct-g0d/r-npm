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
