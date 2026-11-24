use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_fs::error::FsError;
use rnpm_fs::parallel::{extract_batch_parallel, BatchExtractionItem};
use rnpm_fs::tarball::{extract_tar_gz, pack_directory};
use std::fs;
use std::io::Cursor;
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

fn build_tar_gz_with_symlink_overwrite_attempt(
    symlink_path: &str,
    symlink_target_dir: &str,
    target_write_path: &str,
    target_content: &[u8],
) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);

        // 1. Directory entry for target
        let mut h_dir = Header::new_gnu();
        h_dir.set_entry_type(tar::EntryType::Directory);
        h_dir.set_size(0);
        h_dir.set_mode(0o755);
        h_dir.set_cksum();
        builder
            .append_data(&mut h_dir, symlink_target_dir, Cursor::new(&[]))
            .unwrap();

        // 2. Symlink entry pointing to target directory
        let mut h_sym = Header::new_gnu();
        h_sym.set_entry_type(tar::EntryType::Symlink);
        h_sym.set_size(0);
        h_sym.set_mode(0o777);
        h_sym.set_cksum();
        builder
            .append_link(&mut h_sym, symlink_path, "safe_target")
            .unwrap();

        // 3. Attempt to overwrite/write through the symlink
        let mut h_file = Header::new_gnu();
        h_file.set_size(target_content.len() as u64);
        h_file.set_mode(0o644);
        h_file.set_cksum();
        builder
            .append_data(&mut h_file, target_write_path, Cursor::new(target_content))
            .unwrap();

        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
fn test_multi_directory_deduplicated_extraction() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Build tarball with 60 files across deeply nested and shared directory hierarchies
    let mut expected_files = Vec::new();

    for dir_idx in 0..6 {
        for file_idx in 0..10 {
            let path = format!("package/dist/module_{dir_idx}/sub_{}/file_{file_idx}.js", file_idx % 3);
            let content = format!("export const val = {dir_idx}_{file_idx}; // padding data for realism");
            expected_files.push((path, content));
        }
    }

    let entry_slices: Vec<(&str, &[u8], u32)> = expected_files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_bytes(), 0o644))
        .collect();

    let tar_bytes = build_tar_gz(&entry_slices);
    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None)
        .expect("Multi-directory extraction must succeed");

    assert_eq!(summary.entries_extracted, 60);

    for (p, expected_content) in &expected_files {
        let rel = p.strip_prefix("package/").unwrap();
        let file_path = dest.join(rel);
        assert!(file_path.is_file(), "File must exist: {}", file_path.display());
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(&content, expected_content);
    }
}

#[test]
fn test_duplicate_and_overlapping_entries() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Later entry with exact same normalized path must overwrite earlier entry (npm behavior)
    let entries = [
        ("package/index.js", b"version 1" as &[u8], 0o644),
        ("package/helper.js", b"helper code", 0o644),
        ("package/index.js", b"version 2 final", 0o644),
    ];

    let tar_bytes = build_tar_gz(&entries);
    let summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None)
        .expect("Duplicate entries extraction must succeed");

    assert_eq!(summary.entries_extracted, 3);

    let index_content = fs::read(dest.join("index.js")).unwrap();
    assert_eq!(
        index_content,
        b"version 2 final",
        "Later entry must win and overwrite earlier entry"
    );
    let helper_content = fs::read(dest.join("helper.js")).unwrap();
    assert_eq!(helper_content, b"helper code");
}

#[test]
fn test_symlink_overwrite_protection() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("dest");

    // Verify protection against symlink overwrite / symlink slip within the archive
    let tar_bytes = build_tar_gz_with_symlink_overwrite_attempt(
        "package/link_dir",
        "package/safe_target/",
        "package/link_dir/exploit.txt",
        b"exploit payload through symlink",
    );

    let res = extract_tar_gz(Cursor::new(&tar_bytes), &dest, None);
    assert!(
        matches!(res, Err(FsError::EscapingSymlink { .. })),
        "Symlink overwrite protection must reject write through earlier symlink, got: {res:?}"
    );

    // Verify exploit file was never created
    assert!(!dest.join("safe_target/exploit.txt").exists());
}

#[test]
fn test_byte_for_byte_parity_roundtrip() {
    let dir = tempdir().unwrap();
    let pkg_dir = dir.path().join("package");
    fs::create_dir_all(pkg_dir.join("lib/nested")).unwrap();

    // Create package.json
    fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "perf-test-pkg", "version": "1.2.3", "main": "lib/index.js"}"#,
    )
    .unwrap();

    // 0-byte file
    fs::write(pkg_dir.join("lib/empty.js"), b"").unwrap();

    // Small file
    fs::write(pkg_dir.join("lib/small.js"), b"console.log('small');\n").unwrap();

    // Generate non-trivial payload with realistic compression ratio (~2.5:1)
    let med_data: Vec<u8> = (0..64 * 1024)
        .map(|i| ((i * 17 + (i >> 3)) % 251) as u8)
        .collect();
    fs::write(pkg_dir.join("lib/medium.dat"), &med_data).unwrap();

    let large_data: Vec<u8> = (0..128 * 1024)
        .map(|i| ((i * 31 + (i >> 5)) % 241) as u8)
        .collect();
    fs::write(pkg_dir.join("lib/nested/large.dat"), &large_data).unwrap();

    // Pack directory
    let (summary, tar_bytes) = pack_directory(&pkg_dir, None).expect("pack_directory must succeed");
    assert_eq!(summary.name, "perf-test-pkg");
    assert_eq!(summary.version, "1.2.3");

    // Extract to destination
    let dest_dir = dir.path().join("extracted");
    let ext_summary = extract_tar_gz(Cursor::new(&tar_bytes), &dest_dir, None)
        .expect("extract_tar_gz must succeed");

    assert_eq!(ext_summary.entries_extracted, summary.entry_count);

    // Verify byte-for-byte matching
    assert_eq!(fs::read(dest_dir.join("lib/empty.js")).unwrap(), b"");
    assert_eq!(
        fs::read(dest_dir.join("lib/small.js")).unwrap(),
        b"console.log('small');\n"
    );
    assert_eq!(fs::read(dest_dir.join("lib/medium.dat")).unwrap(), med_data);
    assert_eq!(
        fs::read(dest_dir.join("lib/nested/large.dat")).unwrap(),
        large_data
    );
}

#[test]
fn test_parallel_batch_extraction_parity() {
    let dir = tempdir().unwrap();

    let mut items = Vec::new();
    for i in 1..=4 {
        let pkg_content = format!("parallel-package-{i}-payload");
        let tar_bytes = build_tar_gz(&[
            ("package/index.js", pkg_content.as_bytes(), 0o644),
            (
                "package/package.json",
                format!(r#"{{"name": "batch-pkg-{i}"}}"#).as_bytes(),
                0o644,
            ),
        ]);
        let dest = dir.path().join(format!("pkg_{i}"));
        items.push(BatchExtractionItem::new(Cursor::new(tar_bytes), dest, None));
    }

    let results = extract_batch_parallel(items, 2);
    assert_eq!(results.len(), 4);

    for (i, res) in results.into_iter().enumerate() {
        let idx = i + 1;
        let summary = res.expect("Each batch item must extract successfully");
        assert_eq!(summary.entries_extracted, 2);

        let dest = dir.path().join(format!("pkg_{idx}"));
        let index_file = dest.join("index.js");
        assert!(index_file.is_file());
        let content = fs::read_to_string(&index_file).unwrap();
        assert_eq!(content, format!("parallel-package-{idx}-payload"));
    }
}
