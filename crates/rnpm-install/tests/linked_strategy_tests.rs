use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;
use tempfile::tempdir;

use rnpm_install::isolated::{ensure_link, unpack_store_package};

fn create_valid_package_tarball(name: &str, version: &str) -> Vec<u8> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(enc);

    let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    let mut header = tar::Header::new_gnu();
    header.set_size(pkg_json.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "package/package.json", pkg_json.as_bytes()).unwrap();

    let index_js = b"module.exports = 'hello';\n";
    let mut header2 = tar::Header::new_gnu();
    header2.set_size(index_js.len() as u64);
    header2.set_mode(0o644);
    header2.set_cksum();
    tar.append_data(&mut header2, "package/index.js", &index_js[..]).unwrap();

    tar.into_inner().unwrap().finish().unwrap()
}

#[test]
fn test_ensure_link_hard_error_on_missing_target() {
    let dir = tempdir().unwrap();
    let link_path = dir.path().join("node_modules/my-link");
    let missing_target = dir.path().join("non_existent_folder");

    let res = ensure_link(&link_path, &missing_target);
    assert!(res.is_err(), "ensure_link must return Err on nonexistent target");
    assert!(!link_path.exists(), "ensure_link must not silently copy or leave a target on error");
}

#[test]
fn test_atomic_store_extraction_failure_cleans_up_staging() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("node_modules/.store/broken@1.0.0/node_modules/broken");

    let corrupt_bytes = b"truncated-tarball-garbage-bytes";
    let res = unpack_store_package(&dest, corrupt_bytes, None);

    assert!(res.is_err(), "unpacking corrupted tarball must fail");
    assert!(!dest.exists(), "dest must not exist after failed unpack");

    let parent = dest.parent().unwrap();
    if parent.exists() {
        let entries: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            entries.is_empty(),
            "parent must have no leftover temporary staging folders or markers: found {:?}",
            entries
        );
    }
}

#[test]
fn test_atomic_store_extraction_success_leaves_no_stray_files() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("node_modules/.store/my-dep@2.0.0-hash123/node_modules/my-dep");

    let tarball = create_valid_package_tarball("my-dep", "2.0.0");
    let res = unpack_store_package(&dest, &tarball, None);

    assert!(res.is_ok(), "unpacking valid package must succeed: {:?}", res.err());
    assert!(dest.join("package.json").is_file(), "package.json must exist in dest");
    assert!(dest.join("index.js").is_file(), "index.js must exist in dest");

    // Parent must contain ONLY the package directory (no temp files, no markers, no trash)
    let parent = dest.parent().unwrap();
    let entries: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        entries,
        vec!["my-dep".to_string()],
        "parent directory must contain exclusively the package directory and no stray files"
    );
}

#[test]
fn test_atomic_store_extraction_incomplete_tarball_without_package_json() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("node_modules/.store/no-manifest@1.0.0/node_modules/no-manifest");

    // Tarball with index.js but NO package.json
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(enc);
    let index_js = b"console.log('no manifest');\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(index_js.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "package/index.js", &index_js[..]).unwrap();
    let tar_bytes = tar.into_inner().unwrap().finish().unwrap();

    let res = unpack_store_package(&dest, &tar_bytes, None);
    assert!(res.is_err(), "unpacking tarball missing package.json must fail");
    assert!(!dest.exists(), "dest must not exist when package.json is missing");

    let parent = dest.parent().unwrap();
    if parent.exists() {
        let entries: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .flatten()
            .collect();
        assert!(entries.is_empty(), "no staging directory should be left behind on missing package.json");
    }
}
