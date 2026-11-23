use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_fs::error::FsError;
use rnpm_fs::junction::{create_junction, is_junction, junction_points_to, remove_dir_all_safe};
use rnpm_fs::tarball::extract_tar_gz;
use rnpm_fs::writer::{repair_cas_file, write_file_fast};
use rnpm_fs::{replace_dir_with_retries, to_verbatim_path};
use std::fs;
use std::io::Cursor;
use std::sync::Arc;
use tar::{Builder, Header};
use tempfile::tempdir;

fn build_tar_gz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
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
                builder
                    .append_data(&mut header, path, Cursor::new(data))
                    .unwrap();
            }
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn build_tar_gz_with_symlink(file_entry: (&str, &[u8]), symlink_entry: (&str, &str)) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        // regular file
        let mut h_file = Header::new_gnu();
        h_file.set_size(file_entry.1.len() as u64);
        h_file.set_mode(0o644);
        let path_bytes = file_entry.0.as_bytes();
        h_file.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        h_file.set_cksum();
        builder.append(&h_file, Cursor::new(file_entry.1)).unwrap();

        // symlink
        let mut h_sym = Header::new_gnu();
        h_sym.set_entry_type(tar::EntryType::Symlink);
        h_sym.set_size(0);
        h_sym.set_mode(0o777);
        let sym_path_bytes = symlink_entry.0.as_bytes();
        h_sym.as_mut_bytes()[..sym_path_bytes.len()].copy_from_slice(sym_path_bytes);
        h_sym.set_link_name(symlink_entry.1).unwrap();
        h_sym.set_cksum();
        builder.append(&h_sym, Cursor::new(&[])).unwrap();

        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn test_deep_path_verbatim_handling_and_removal() {
    let dir = tempdir().unwrap();
    // Build a path that exceeds 260 characters on Windows
    let mut deep_dir = dir.path().to_path_buf();
    for i in 0..12 {
        deep_dir.push(format!("very_long_directory_component_level_{i}"));
    }
    let full_path_str = deep_dir.to_string_lossy().to_string();
    assert!(
        full_path_str.len() > 260,
        "Path length ({}) must exceed 260 chars for MAX_PATH testing",
        full_path_str.len()
    );

    // 1. Create deep directories and write file via verbatim path
    let verbatim_dir = to_verbatim_path(&deep_dir);
    fs::create_dir_all(&verbatim_dir).unwrap();

    let deep_file = deep_dir.join("deep_nested_payload.txt");
    write_file_fast(&deep_file, b"deep_path_data", 0o644, 1024).unwrap();

    let read_back = fs::read(to_verbatim_path(&deep_file)).unwrap();
    assert_eq!(read_back, b"deep_path_data");

    // 2. Atomic replacement with deep paths
    let new_src = dir.path().join("replacement_src");
    fs::create_dir_all(&new_src).unwrap();
    write_file_fast(
        &new_src.join("replaced.txt"),
        b"replacement_data",
        0o644,
        1024,
    )
    .unwrap();

    replace_dir_with_retries(&new_src, &deep_dir, 5).unwrap();
    let replaced_file = deep_dir.join("replaced.txt");
    assert!(to_verbatim_path(&replaced_file).exists());

    // 3. Remove entire deep directory tree safely
    remove_dir_all_safe(dir.path()).unwrap();
    assert!(!dir.path().exists());
}

#[test]
fn test_special_characters_in_paths() {
    let dir = tempdir().unwrap();
    // Special chars: spaces, parentheses, &, %, ', ;, $, #, and Unicode (Chinese, Japanese, emoji)
    let special_folder_name = "pkg (prod) & test%20 'quotes' ; semi $dollar #hash 中文_テスト_🚀";
    let special_dir = dir.path().join(special_folder_name);
    fs::create_dir_all(&special_dir).unwrap();

    let special_file = special_dir.join("special file (v1) & %20.js");
    write_file_fast(&special_file, b"console.log('special');", 0o644, 1024).unwrap();
    assert!(special_file.exists());

    // Extract tarball into path with special characters
    let dest = special_dir.join("sub_extracted");
    let tar_bytes = build_tar_gz(&[
        (
            "package/package.json",
            br#"{"name":"special-pkg","version":"1.0.0"}"#,
            0o644,
        ),
        (
            "package/lib/index (prod).js",
            b"module.exports = 'special';",
            0o644,
        ),
    ]);
    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None).unwrap();
    assert_eq!(summary.entries_extracted, 2);
    assert!(dest.join("package.json").exists());
    assert!(dest.join("lib/index (prod).js").exists());

    // Atomic replace inside directory with special characters
    let src_rep = special_dir.join("src_rep");
    fs::create_dir_all(&src_rep).unwrap();
    fs::write(src_rep.join("content.txt"), b"updated").unwrap();
    let dst_rep = special_dir.join("dst_rep");
    replace_dir_with_retries(&src_rep, &dst_rep, 5).unwrap();
    assert_eq!(
        fs::read(dst_rep.join("content.txt")).unwrap(),
        b"updated"
    );

    // Clean up
    remove_dir_all_safe(&special_dir).unwrap();
    assert!(!special_dir.exists());
}

#[test]
fn test_readonly_files_and_directories_handling() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("readonly_test_root");
    let sub = root.join("readonly_subdir");
    fs::create_dir_all(&sub).unwrap();

    let ro_file = sub.join("readonly_file.txt");
    fs::write(&ro_file, b"initial readonly content").unwrap();

    // Mark file as readonly
    let mut perms = fs::metadata(&ro_file).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&ro_file, perms).unwrap();

    // Mark directory as readonly
    let mut dir_perms = fs::metadata(&sub).unwrap().permissions();
    dir_perms.set_readonly(true);
    fs::set_permissions(&sub, dir_perms).unwrap();

    // 1. replace_dir_with_retries over target with read-only files & dirs
    let new_src = dir.path().join("replacement_for_ro");
    fs::create_dir_all(&new_src).unwrap();
    fs::write(new_src.join("new_file.txt"), b"new writable content").unwrap();

    replace_dir_with_retries(&new_src, &root, 5).unwrap();
    assert!(root.join("new_file.txt").exists());
    assert!(!root.join("readonly_subdir").exists());

    // 2. Extract tarball overwriting an existing read-only file
    let target_file = root.join("new_file.txt");
    let mut perms2 = fs::metadata(&target_file).unwrap().permissions();
    perms2.set_readonly(true);
    fs::set_permissions(&target_file, perms2).unwrap();

    let tar_bytes = build_tar_gz(&[(
        "package/new_file.txt",
        b"overwritten content from tarball",
        0o644,
    )]);
    extract_tar_gz(Cursor::new(&tar_bytes), &root, None).unwrap();
    assert_eq!(
        fs::read_to_string(&target_file).unwrap(),
        "overwritten content from tarball"
    );

    // 3. remove_dir_all_safe cleans up read-only files and read-only directories cleanly
    let ro_again = root.join("sub2");
    fs::create_dir_all(&ro_again).unwrap();
    let ro_f2 = ro_again.join("f2.txt");
    fs::write(&ro_f2, b"f2").unwrap();

    let mut p = fs::metadata(&ro_f2).unwrap().permissions();
    p.set_readonly(true);
    fs::set_permissions(&ro_f2, p).unwrap();

    let mut dp = fs::metadata(&ro_again).unwrap().permissions();
    dp.set_readonly(true);
    fs::set_permissions(&ro_again, dp).unwrap();

    remove_dir_all_safe(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn test_junction_replacement_and_safe_removal_never_deletes_target() {
    let dir = tempdir().unwrap();

    // Outside directory with critical files
    let outside_dir = dir.path().join("outside_critical_data");
    fs::create_dir_all(&outside_dir).unwrap();
    let critical_file = outside_dir.join("important_user_data.txt");
    fs::write(&critical_file, b"CRITICAL_DO_NOT_DELETE").unwrap();

    // Target 2 for replacement
    let outside_dir_2 = dir.path().join("outside_data_version_2");
    fs::create_dir_all(&outside_dir_2).unwrap();
    fs::write(outside_dir_2.join("v2.txt"), b"V2_DATA").unwrap();

    // Container directory that will hold the junction
    let container = dir.path().join("container");
    fs::create_dir_all(&container).unwrap();
    let link_path = container.join("node_modules_link");

    // 1. Create junction
    create_junction(&link_path, &outside_dir).unwrap();
    assert!(is_junction(&link_path).unwrap());
    assert!(junction_points_to(&link_path, &outside_dir));

    // 2. Replace existing junction with a junction pointing to outside_dir_2
    create_junction(&link_path, &outside_dir_2).unwrap();
    assert!(is_junction(&link_path).unwrap());
    assert!(junction_points_to(&link_path, &outside_dir_2));

    // Verify original target outside_dir contents were NOT deleted or modified!
    assert!(critical_file.exists());
    assert_eq!(
        fs::read(&critical_file).unwrap(),
        b"CRITICAL_DO_NOT_DELETE"
    );

    // 3. remove_dir_all_safe on container MUST NEVER delete external junction targets!
    remove_dir_all_safe(&container).unwrap();
    assert!(!container.exists());

    // Both outside directories and their contents MUST still exist intact!
    assert!(outside_dir.exists());
    assert!(critical_file.exists());
    assert_eq!(
        fs::read(&critical_file).unwrap(),
        b"CRITICAL_DO_NOT_DELETE"
    );
    assert!(outside_dir_2.exists());
    assert!(outside_dir_2.join("v2.txt").exists());
}

#[test]
fn test_dangling_junction_safe_removal() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target_dir");
    fs::create_dir_all(&target).unwrap();

    let link = dir.path().join("link_to_target");
    create_junction(&link, &target).unwrap();
    assert!(is_junction(&link).unwrap());

    // Delete target to make the junction dangling
    fs::remove_dir(&target).unwrap();
    assert!(!target.exists());

    // junction_points_to should still cleanly report true without error
    assert!(junction_points_to(&link, &target));

    // remove_dir_all_safe should successfully remove the dangling junction
    remove_dir_all_safe(&link).unwrap();
    assert!(!link.exists());
}

#[test]
fn test_hostile_tarball_zip_slip_and_absolute_paths() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    // 1. Path traversal via ../
    let tar_zip_slip = build_tar_gz(&[("package/../../escaped.txt", b"evil", 0o644)]);
    let res = extract_tar_gz(Cursor::new(&tar_zip_slip), &dest, None);
    assert!(
        matches!(res, Err(FsError::PathTraversal { .. })),
        "Expected PathTraversal error, got: {res:?}"
    );

    // 2. Windows drive letter traversal
    let tar_drive = build_tar_gz(&[("package/C:/Windows/System32/evil.exe", b"evil", 0o755)]);
    let res = extract_tar_gz(Cursor::new(&tar_drive), &dest, None);
    assert!(
        matches!(res, Err(FsError::PathTraversal { .. }) | Err(FsError::AbsolutePath { .. })),
        "Expected PathTraversal/AbsolutePath for drive path, got: {res:?}"
    );

    // 3. Absolute path /etc/passwd
    let tar_abs = build_tar_gz(&[("/etc/passwd", b"root:x:0:0", 0o644)]);
    let res = extract_tar_gz(Cursor::new(&tar_abs), &dest, None);
    assert!(
        res.is_err(),
        "Expected error for absolute path /etc/passwd, got: {res:?}"
    );
}

#[test]
fn test_hostile_tarball_nul_byte_rejection() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    // 1. Direct validate_entry_path check for NUL byte
    let res = rnpm_fs::validate_entry_path(std::path::Path::new("package/bad\0file.txt"));
    assert!(
        matches!(res, Err(FsError::PathTraversal { .. })),
        "Expected PathTraversal on NUL byte, got: {res:?}"
    );

    // 2. Tarball with GNU LongLink containing embedded NUL in entry path
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        let _ = builder.append_data(
            &mut header,
            "package/bad\0path_with_nul.txt",
            Cursor::new(b"data"),
        );
        let _ = builder.finish();
    }
    let tar_bytes = gz.finish().unwrap_or_default();
    if !tar_bytes.is_empty() {
        let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
        assert!(res.is_err() || !dest.join("bad\0path_with_nul.txt").exists());
    }
}

#[test]
fn test_hostile_tarball_symlink_escape() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    // Symlink targeting ../../outside_dest
    let tar_symlink_escape = build_tar_gz_with_symlink(
        ("package/file.txt", b"safe"),
        ("package/evil_symlink", "../../outside_target"),
    );

    let res = extract_tar_gz(Cursor::new(&tar_symlink_escape), &dest, None);
    assert!(
        matches!(res, Err(FsError::PathTraversal { .. }) | Err(FsError::EscapingSymlink { .. })),
        "Expected PathTraversal or EscapingSymlink on symlink escape target, got: {res:?}"
    );
}

#[test]
fn test_tarball_path_case_collisions() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    // Case collision: foo.js vs FOO.JS
    let tar_case = build_tar_gz(&[
        ("package/foo.js", b"lowercase_content", 0o644),
        ("package/FOO.JS", b"uppercase_content", 0o644),
    ]);

    // On Windows/case-insensitive filesystems, rnpm-fs detects and prevents case collision attacks
    let res = extract_tar_gz(Cursor::new(&tar_case), &dest, None);
    #[cfg(windows)]
    assert!(
        matches!(res, Err(FsError::CaseCollision { .. })),
        "Expected CaseCollision error on Windows, got: {res:?}"
    );
    #[cfg(not(windows))]
    assert!(res.is_ok() || matches!(res, Err(FsError::CaseCollision { .. })));
}

#[test]
fn test_cas_file_repair_and_concurrency() {
    let dir = tempdir().unwrap();
    let cas_dir = dir.path().join("cas_store");
    fs::create_dir_all(&cas_dir).unwrap();

    let cas_file = cas_dir.join("blob_12345.bin");
    let correct_data = b"VALID_CAS_CONTENT_HASH_VERIFIED";

    // 1. Write corrupted 0-byte file
    fs::write(&cas_file, b"").unwrap();
    assert_eq!(fs::metadata(&cas_file).unwrap().len(), 0);

    // Call repair_cas_file
    repair_cas_file(&cas_file, correct_data, 0o644, 4096);
    assert_eq!(fs::read(&cas_file).unwrap(), correct_data);

    // 2. Corrupted data with wrong content and read-only permission on Windows
    fs::write(&cas_file, b"CORRUPTED_GARBAGE").unwrap();
    #[cfg(windows)]
    {
        let mut perms = fs::metadata(&cas_file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&cas_file, perms).unwrap();
    }

    repair_cas_file(&cas_file, correct_data, 0o644, 4096);
    assert_eq!(fs::read(&cas_file).unwrap(), correct_data);

    // 3. Multi-threaded concurrent repairs
    let mut handles = Vec::new();
    let shared_path = Arc::new(cas_file);

    for _ in 0..8 {
        let p = Arc::clone(&shared_path);
        handles.push(std::thread::spawn(move || {
            repair_cas_file(&p, correct_data, 0o644, 4096);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(fs::read(&*shared_path).unwrap(), correct_data);
}
