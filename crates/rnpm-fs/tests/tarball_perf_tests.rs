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

#[test]
#[ignore]
fn bench_rnpm_fs_hot_paths() {
    use rnpm_fs::junction::remove_dir_all_safe;
    use rnpm_fs::writer::{
        determine_writer_config, extract_packages_direct_parallel, extract_tarball_direct,
        materialize_files_parallel, precreate_directories, BatchDirectItem, MaterializeFile,
    };
    use std::sync::Arc;
    use std::time::Instant;

    println!("\n=== rnpm-fs Release Performance Benchmark ===");

    let tarballs: Vec<Vec<u8>> = (0..40)
        .map(|pkg_idx| {
            let mut entries: Vec<(String, Vec<u8>, u32)> = Vec::with_capacity(36);
            entries.push((
                "package/package.json".to_string(),
                format!("{{\"name\":\"fs-pkg-{pkg_idx}\",\"version\":\"1.0.0\"}}").into_bytes(),
                0o644,
            ));
            for f in 0..35 {
                let path = format!("package/src/mod_{}/file_{f}.js", f % 8);
                let payload = vec![b'x'; 2048];
                entries.push((path, payload, 0o644));
            }
            let refs: Vec<(&str, &[u8], u32)> = entries
                .iter()
                .map(|(p, d, m)| (p.as_str(), d.as_slice(), *m))
                .collect();
            build_tar_gz(&refs)
        })
        .collect();

    // 1. Sequential extract_tar_gz (40 pkgs)
    let dir1 = tempdir().unwrap();
    let t0 = Instant::now();
    for (i, tgz) in tarballs.iter().enumerate() {
        let dest = dir1.path().join(format!("pkg-{i}"));
        extract_tar_gz(Cursor::new(tgz), &dest, None).unwrap();
    }
    let extract_tar_gz_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 2. Sequential extract_tarball_direct (40 pkgs)
    let dir2 = tempdir().unwrap();
    let cfg2 = determine_writer_config(dir2.path(), None);
    let t0 = Instant::now();
    for (i, tgz) in tarballs.iter().enumerate() {
        let dest = dir2.path().join(format!("pkg-{i}"));
        extract_tarball_direct(Cursor::new(tgz), &dest, None, Some(&cfg2)).unwrap();
    }
    let extract_direct_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 3. Parallel extract_packages_direct_parallel (40 pkgs)
    let dir3 = tempdir().unwrap();
    let cfg3 = determine_writer_config(dir3.path(), None);
    let batch: Vec<BatchDirectItem<Cursor<&[u8]>>> = tarballs
        .iter()
        .enumerate()
        .map(|(i, tgz)| BatchDirectItem {
            reader: Cursor::new(tgz.as_slice()),
            destination: dir3.path().join(format!("pkg-{i}")),
            package_id: format!("fs-pkg-{i}"),
            limits: None,
        })
        .collect();
    let t0 = Instant::now();
    let res = extract_packages_direct_parallel(batch, dir3.path(), Some(&cfg3));
    let extract_parallel_ms = t0.elapsed().as_secs_f64() * 1000.0;
    for r in res {
        r.unwrap();
    }

    // 4. precreate_directories + materialize_files_parallel (1440 files across 40 pkgs)
    let dir4 = tempdir().unwrap();
    let cfg4 = determine_writer_config(dir4.path(), None);
    let mut mat_files = Vec::with_capacity(40 * 36);
    let mut mat_dirs = Vec::with_capacity(40 * 9);
    let payload_2k = Arc::new(vec![b'y'; 2048]);
    for i in 0..40 {
        let pkg_dir = dir4.path().join(format!("pkg-{i}"));
        mat_dirs.push(pkg_dir.clone());
        for m in 0..8 {
            mat_dirs.push(pkg_dir.join("src").join(format!("mod_{m}")));
        }
        mat_files.push(MaterializeFile {
            path: pkg_dir.join("package.json"),
            data: Arc::clone(&payload_2k),
            mode: 0o644,
            package_id: Some(format!("pkg-{i}")),
        });
        for f in 0..35 {
            mat_files.push(MaterializeFile {
                path: pkg_dir
                    .join("src")
                    .join(format!("mod_{}", f % 8))
                    .join(format!("file_{f}.js")),
                data: Arc::clone(&payload_2k),
                mode: 0o644,
                package_id: Some(format!("pkg-{i}")),
            });
        }
    }
    let t0 = Instant::now();
    let dir_refs: Vec<&std::path::Path> = mat_dirs.iter().map(|p| p.as_path()).collect();
    precreate_directories(dir_refs).unwrap();
    let precreate_dirs_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t0 = Instant::now();
    materialize_files_parallel(mat_files, &cfg4).unwrap();
    let materialize_parallel_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 5. remove_dir_all_safe on dir1, dir2, dir3, dir4
    let t0 = Instant::now();
    remove_dir_all_safe(dir1.path()).unwrap();
    remove_dir_all_safe(dir2.path()).unwrap();
    let remove_dir_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!("| Benchmark | Duration (ms) |");
    println!("|---|---:|");
    println!("| fs_extract_tar_gz (40 pkgs) | {extract_tar_gz_ms:.2} |");
    println!("| fs_extract_tarball_direct (40 pkgs) | {extract_direct_ms:.2} |");
    println!("| fs_extract_packages_direct_parallel (40 pkgs) | {extract_parallel_ms:.2} |");
    println!("| fs_precreate_directories (360 dirs) | {precreate_dirs_ms:.2} |");
    println!("| fs_materialize_files_parallel (1440 files) | {materialize_parallel_ms:.2} |");
    println!("| fs_remove_dir_all_safe (2x 40 pkgs) | {remove_dir_ms:.2} |");
}
