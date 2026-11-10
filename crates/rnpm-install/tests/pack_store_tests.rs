use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_install::{InstallOptions, Installer};
use rnpm_lockfile::LockfileV3;
use std::fs;
use tar::{Builder, Header};
use tempfile::tempdir;

fn build_mock_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut builder = Builder::new(&mut gz);
        for &(rel_path, content) in files {
            let full_path = format!("package/{rel_path}");
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, content)
                .unwrap();
        }
        builder.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[tokio::test]
async fn test_pack_store_two_files_per_package_and_warm_ci_read() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let cache_dir = root.join("cache");

    // Create tarball with small and large files (64 KiB)
    let large_payload: Vec<u8> = (0..65536).map(|i| ((i * 37 + 13) % 256) as u8).collect(); // 64 KiB
    let tarball_bytes = build_mock_tarball(&[
        (
            "package.json",
            br#"{"name":"omega-core","version":"2.5.0","main":"lib/index.js"}"#,
        ),
        ("lib/index.js", b"module.exports = { version: '2.5.0' };"),
        ("data/blob.bin", &large_payload),
    ]);

    let pkgs_dir = root.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    let tarball_path = pkgs_dir.join("omega-core-2.5.0.tgz");
    fs::write(&tarball_path, &tarball_bytes).unwrap();

    let project_dir = root.join("consumer-project");
    fs::create_dir_all(&project_dir).unwrap();
    let manifest = serde_json::json!({
        "name": "consumer",
        "version": "1.0.0",
        "dependencies": {
            "omega-core": "file:../pkgs/omega-core-2.5.0.tgz"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        cache_dir: Some(cache_dir.clone()),
        offline: true,
        ..Default::default()
    };

    // 1. Cold install creates .pack and .idx in PackStore
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    let lock_pkg = lockfile
        .packages
        .get("node_modules/omega-core")
        .expect("lockfile package");
    let integrity = lock_pkg.integrity.as_ref().expect("integrity");

    let pack_store = installer.pack_store();
    assert!(pack_store.has_package_pack(integrity));

    let (pack_path, idx_path) = pack_store.pack_paths(integrity);
    assert!(
        pack_path.is_file(),
        "pack file exists: {}",
        pack_path.display()
    );
    assert!(
        idx_path.is_file(),
        "idx file exists: {}",
        idx_path.display()
    );

    // Exit criterion check: adding a package to store creates exactly 2 files (pack + idx) in prefix folder
    let prefix_dir = pack_path.parent().unwrap();
    let files_in_prefix = fs::read_dir(prefix_dir).unwrap().count();
    assert_eq!(
        files_in_prefix, 2,
        "Adding package must create exactly 2 files in store prefix dir"
    );

    // Verify 4 KiB alignment of every file in the pack
    let pack = pack_store.get_package_pack(integrity).unwrap().unwrap();
    assert_eq!(pack.index.files.len(), 3);
    for file_entry in &pack.index.files {
        assert!(
            file_entry.is_4k_aligned(),
            "Offset {} must be 4 KiB aligned",
            file_entry.offset
        );
        assert_eq!(file_entry.offset % 4096, 0);
    }
    assert_eq!(
        pack.get_file_slice("lib/index.js").unwrap(),
        b"module.exports = { version: '2.5.0' };"
    );
    assert_eq!(
        pack.get_file_slice("data/blob.bin").unwrap(),
        &large_payload[..]
    );

    // 2. Wipe node_modules completely and remove original tarball archive
    fs::remove_dir_all(project_dir.join("node_modules")).unwrap();
    assert!(!project_dir.join("node_modules").exists());
    fs::remove_file(&tarball_path).unwrap();
    assert!(!tarball_path.exists());

    // 3. Warm CI run: reads only packs, does not require tarball on disk!
    let mut ci_installer = Installer::new(options).unwrap();
    let ci_summary = ci_installer.run_ci().await.unwrap();
    assert_eq!(ci_summary.packages_installed, 1);

    // Verify direct materialization from the pack store
    let installed_main = project_dir
        .join("node_modules")
        .join("omega-core")
        .join("lib")
        .join("index.js");
    let installed_blob = project_dir
        .join("node_modules")
        .join("omega-core")
        .join("data")
        .join("blob.bin");
    assert!(installed_main.is_file());
    assert!(installed_blob.is_file());
    assert_eq!(
        fs::read_to_string(&installed_main).unwrap(),
        "module.exports = { version: '2.5.0' };"
    );
    assert_eq!(fs::read(&installed_blob).unwrap(), large_payload);
}

#[tokio::test]
async fn test_pack_store_crash_recovery_truncated_or_deleted_pack() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let cache_dir = root.join("cache");

    let tarball_bytes = build_mock_tarball(&[
        (
            "package.json",
            br#"{"name":"omega-core","version":"2.5.0","main":"lib/index.js"}"#,
        ),
        ("lib/index.js", b"module.exports = { version: '2.5.0' };"),
    ]);

    let project_dir = root.join("test-recovery-project");
    let pkgs_dir = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    let tarball_path = pkgs_dir.join("omega-core-2.5.0.tgz");
    fs::write(&tarball_path, &tarball_bytes).unwrap();

    let manifest = serde_json::json!({
        "name": "test-recovery",
        "version": "1.0.0",
        "dependencies": {
            "omega-core": "file:./pkgs/omega-core-2.5.0.tgz"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let options = InstallOptions {
        project_dir: project_dir.clone(),
        cache_dir: Some(cache_dir.clone()),
        ..Default::default()
    };

    // 1. Initial install populates store
    let mut installer = Installer::new(options.clone()).unwrap();
    let summary = installer.run().await.unwrap();
    assert_eq!(summary.packages_installed, 1);

    let lockfile = LockfileV3::load_from_file(&project_dir.join("package-lock.json")).unwrap();
    let integrity = lockfile
        .packages
        .get("node_modules/omega-core")
        .unwrap()
        .integrity
        .as_ref()
        .unwrap();
    let pack_store = installer.pack_store();
    let (pack_path, idx_path) = pack_store.pack_paths(integrity);
    assert!(pack_path.is_file());
    assert!(idx_path.is_file());

    // 2. Truncate .pack file to half size (simulating crash during write)
    let pack_bytes = fs::read(&pack_path).unwrap();
    assert!(pack_bytes.len() > 10);
    fs::write(&pack_path, &pack_bytes[..pack_bytes.len() / 2]).unwrap();

    // Remove node_modules
    fs::remove_dir_all(project_dir.join("node_modules")).unwrap();
    assert!(!project_dir.join("node_modules").exists());

    // Run install: must detect corrupted/truncated pack, recover, and produce correct node_modules
    let mut installer2 = Installer::new(options.clone()).unwrap();
    let summary2 = installer2.run_ci().await.unwrap();
    assert_eq!(summary2.packages_installed, 1);
    let installed_main = project_dir
        .join("node_modules")
        .join("omega-core")
        .join("lib")
        .join("index.js");
    assert_eq!(
        fs::read_to_string(&installed_main).unwrap(),
        "module.exports = { version: '2.5.0' };"
    );

    // 3. Delete .pack entirely leaving only .idx (simulating crash before pack written or pack deleted)
    fs::remove_file(&pack_path).unwrap();
    assert!(!pack_path.exists());
    assert!(idx_path.exists());

    // Remove node_modules
    fs::remove_dir_all(project_dir.join("node_modules")).unwrap();
    assert!(!project_dir.join("node_modules").exists());

    // Run install: must detect missing pack, recover, and produce correct node_modules
    let mut installer3 = Installer::new(options.clone()).unwrap();
    let summary3 = installer3.run_ci().await.unwrap();
    assert_eq!(summary3.packages_installed, 1);
    assert_eq!(
        fs::read_to_string(&installed_main).unwrap(),
        "module.exports = { version: '2.5.0' };"
    );
}
