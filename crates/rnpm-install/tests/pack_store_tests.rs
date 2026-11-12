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

fn rnpm_bin_path() -> std::path::PathBuf {
    // 1. Cargo integration test standard env var
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_rnpm") {
        let pb = std::path::PathBuf::from(p);
        if pb.is_file() {
            return pb;
        }
    }
    // 2. Bin adjacent to current test runner exe (matches debug or release profile of the current test run)
    let current_exe = std::env::current_exe().unwrap();
    let mut dir = current_exe.parent().unwrap();
    if dir.file_name().and_then(|n| n.to_str()) == Some("deps") {
        dir = dir.parent().unwrap();
    }
    let candidate = dir.join(if cfg!(windows) { "rnpm.exe" } else { "rnpm" });
    if candidate.is_file() {
        return candidate;
    }
    // 3. Match profile based on debug_assertions
    let ws_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let active_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let active_path = ws_root
        .join("target")
        .join(active_profile)
        .join(if cfg!(windows) { "rnpm.exe" } else { "rnpm" });
    if active_path.is_file() {
        return active_path;
    }
    panic!(
        "Could not locate current built rnpm binary for subprocess test at '{}'",
        active_path.display()
    );
}

#[test]
fn test_subprocess_io_failure_pack_persistence_fails() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();

    let tarball_bytes = build_mock_tarball(&[
        (
            "package.json",
            br#"{"name":"omega-core","version":"2.5.0","main":"lib/index.js"}"#,
        ),
        ("lib/index.js", b"module.exports = { version: '2.5.0' };"),
    ]);

    let project_dir = root.join("repro-project");
    let pkgs_dir = project_dir.join("pkgs");
    fs::create_dir_all(&pkgs_dir).unwrap();
    let tarball_path = pkgs_dir.join("omega-core-2.5.0.tgz");
    fs::write(&tarball_path, &tarball_bytes).unwrap();

    let manifest = serde_json::json!({
        "name": "repro-app",
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

    let valid_cache = root.join("valid-cache");
    let valid_store = root.join("valid-store");

    // First generate valid lockfile
    let bin = rnpm_bin_path();
    let initial_status = std::process::Command::new(&bin)
        .arg("install")
        .current_dir(&project_dir)
        .env("RNPM_STORE_DIR", &valid_store)
        .env("npm_config_cache", &valid_cache)
        .status()
        .expect("Failed to run initial rnpm install");
    assert!(initial_status.success());
    assert!(project_dir.join("package-lock.json").is_file());

    // Wipe node_modules to ensure a fresh cold CI run
    let nm = project_dir.join("node_modules");
    if nm.exists() {
        fs::remove_dir_all(&nm).unwrap();
    }

    // Create broken store directory where store/packs/00..ff are regular files instead of directories
    let broken_store = root.join("broken-store");
    let broken_packs = broken_store.join("packs");
    fs::create_dir_all(&broken_packs).unwrap();
    for b in 0..=255u8 {
        let file_path = broken_packs.join(format!("{b:02x}"));
        fs::write(&file_path, b"not a directory!").unwrap();
    }

    let broken_cache = root.join("broken-cache");
    fs::create_dir_all(&broken_cache).unwrap();

    // Run rnpm ci with the broken store in subprocess: must fail with nonzero exit!
    let output = std::process::Command::new(&bin)
        .arg("ci")
        .current_dir(&project_dir)
        .env("RNPM_STORE_DIR", &broken_store)
        .env("npm_config_cache", &broken_cache)
        .output()
        .expect("Failed to execute rnpm ci subprocess");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "Expected rnpm ci to fail on pack store IO failure, but exited with success! stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit status 1 on pack persistence failure"
    );
    assert!(
        stderr.contains("Failed to persist pack")
            || stderr.contains("Failed to create pack prefix directory"),
        "Expected error message indicating pack persistence failure, got:\n{stderr}"
    );
    assert!(
        stderr.contains("omega-core"),
        "Expected error message to mention package name, got:\n{stderr}"
    );
}

#[tokio::test]
async fn test_pack_store_atomic_repair_corrupt_cas() {
    let tmp = tempdir().unwrap();
    let root = tmp.path();
    let store_dir = root.join("repair-store");
    let store = rnpm_cache::PackStore::new(&store_dir).unwrap();

    let files = vec![rnpm_cache::PackInputFile {
        path: "index.js".to_string(),
        mode: 0o644,
        data: b"console.log('hello repair');",
    }];

    let integrity = "sha512-testrepairintegrity1234567890abcdef";
    let index = store.put_package_pack(integrity, &files).unwrap();
    assert_eq!(index.files.len(), 1);

    let pack = store.get_package_pack(integrity).unwrap().unwrap();
    assert_eq!(pack.index.files.len(), 1);
    let cas_path = pack.index.files[0].cas_path.as_ref().unwrap();
    assert!(cas_path.is_file());

    // Corrupt the CAS file by overwriting with invalid content
    fs::write(cas_path, b"corrupted data").unwrap();

    // Clear mmap cache to force re-reading from disk and re-verifying
    store.clear_mmap_cache();
    let recovered_pack = store.get_package_pack(integrity).unwrap().unwrap();
    assert_eq!(recovered_pack.index.files.len(), 1);
    assert!(recovered_pack.index.files[0].cas_verified);

    // Verify CAS file was atomically repaired with correct data
    let repaired_data = fs::read(cas_path).unwrap();
    assert_eq!(repaired_data, b"console.log('hello repair');");
}
