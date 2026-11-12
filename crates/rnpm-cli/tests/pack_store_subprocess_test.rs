use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn build_mock_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = Builder::new(&mut enc);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            let entry_path = format!("package/{name}");
            tar.append_data(&mut header, entry_path, *content).unwrap();
        }
        tar.finish().unwrap();
    }
    enc.finish().unwrap()
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

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let initial_cache = root.join("initial-cache");
    let initial_store = root.join("initial-store");

    // 1. Run initial rnpm install to generate a valid package-lock.json
    let init_res = Command::new(rnpm_bin)
        .arg("install")
        .arg("--no-audit")
        .arg("--no-fund")
        .arg("--cache")
        .arg(&initial_cache)
        .env("RNPM_STORE_DIR", &initial_store)
        .current_dir(&project_dir)
        .output()
        .expect("Failed to execute initial rnpm install");
    assert!(
        init_res.status.success(),
        "Initial install must succeed to generate lockfile: {}",
        String::from_utf8_lossy(&init_res.stderr)
    );
    assert!(project_dir.join("package-lock.json").is_file());

    // 2. Remove node_modules to force a full cold CI installation
    let nm = project_dir.join("node_modules");
    if nm.exists() {
        fs::remove_dir_all(&nm).unwrap();
    }

    // 3. Create broken store directory where store/packs/00..ff are regular files instead of directories
    let broken_store = root.join("broken-store");
    let broken_packs = broken_store.join("packs");
    fs::create_dir_all(&broken_packs).unwrap();
    for b in 0..=255u8 {
        let file_path = broken_packs.join(format!("{b:02x}"));
        fs::write(&file_path, b"not a directory!").unwrap();
    }

    let broken_cache = root.join("broken-cache");

    // 4. Run rnpm ci with the broken store in subprocess: must fail with nonzero exit!
    let output = Command::new(rnpm_bin)
        .arg("ci")
        .arg("--no-audit")
        .arg("--no-fund")
        .arg("--cache")
        .arg(&broken_cache)
        .env("RNPM_STORE_DIR", &broken_store)
        .current_dir(&project_dir)
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
            || stderr.contains("Failed to create pack prefix directory")
            || stderr.contains("os error"),
        "Expected error message indicating pack persistence failure, got:\n{stderr}"
    );
    assert!(
        stderr.contains("omega-core"),
        "Expected error message to mention package name, got:\n{stderr}"
    );
}
