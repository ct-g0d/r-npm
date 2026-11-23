use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_no_bin_links_flag_and_toggle() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    let root = temp.path();

    let pkg_a_dir = root.join("pkg-a");
    fs::create_dir_all(pkg_a_dir.join("bin")).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0", "bin": {"my-cli": "./bin/cli.js"}}"#,
    )
    .unwrap();
    fs::write(
        pkg_a_dir.join("bin/cli.js"),
        "#!/usr/bin/env node\nconsole.log('cli');\n",
    )
    .unwrap();

    let pkg_a_spec = "file:./pkg-a";
    fs::write(
        root.join("package.json"),
        format!(
            r#"{{"name": "test-app", "version": "1.0.0", "dependencies": {{"pkg-a": "{}"}}}}"#,
            pkg_a_spec
        ),
    )
    .unwrap();

    // 1. Install with --no-bin-links
    let output = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["install", "--no-bin-links"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bin_dir = root.join("node_modules/.bin");
    let count = if bin_dir.exists() {
        fs::read_dir(&bin_dir).unwrap().count()
    } else {
        0
    };
    assert_eq!(
        count, 0,
        "--no-bin-links must create zero files in node_modules/.bin"
    );

    // 2. Switching back to --bin-links creates them without a stale fast-path hit
    let output2 = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["install", "--bin-links"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        bin_dir.exists(),
        "node_modules/.bin must exist after --bin-links"
    );
    assert!(
        fs::read_dir(&bin_dir).unwrap().count() > 0,
        "node_modules/.bin must have shims created"
    );
}

#[test]
fn test_cli_npmrc_bin_links_false_and_toggle() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    let root = temp.path();

    let pkg_a_dir = root.join("pkg-a");
    fs::create_dir_all(pkg_a_dir.join("bin")).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{"name": "pkg-a", "version": "1.0.0", "bin": {"my-cli": "./bin/cli.js"}}"#,
    )
    .unwrap();
    fs::write(
        pkg_a_dir.join("bin/cli.js"),
        "#!/usr/bin/env node\nconsole.log('cli');\n",
    )
    .unwrap();

    let pkg_a_spec = "file:./pkg-a";
    fs::write(
        root.join("package.json"),
        format!(
            r#"{{"name": "test-app", "version": "1.0.0", "dependencies": {{"pkg-a": "{}"}}}}"#,
            pkg_a_spec
        ),
    )
    .unwrap();

    // 1. Install with .npmrc bin-links=false
    fs::write(root.join(".npmrc"), "bin-links=false\n").unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bin_dir = root.join("node_modules/.bin");
    let count = if bin_dir.exists() {
        fs::read_dir(&bin_dir).unwrap().count()
    } else {
        0
    };
    assert_eq!(
        count, 0,
        ".npmrc bin-links=false must create zero files in node_modules/.bin"
    );

    // 2. Switch back to bin-links=true by changing .npmrc
    fs::write(root.join(".npmrc"), "bin-links=true\n").unwrap();

    let output2 = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        bin_dir.exists(),
        "node_modules/.bin must exist after switching .npmrc to bin-links=true"
    );
    assert!(
        fs::read_dir(&bin_dir).unwrap().count() > 0,
        "node_modules/.bin must have shims created"
    );

    // 3. Switch back to bin-links=false: stale shims removed
    fs::write(root.join(".npmrc"), "bin-links=false\n").unwrap();
    let output3 = Command::new(rnpm_bin)
        .current_dir(root)
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm");
    assert!(
        output3.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output3.stderr)
    );
    let count3 = if bin_dir.exists() {
        fs::read_dir(&bin_dir).unwrap().count()
    } else {
        0
    };
    assert_eq!(
        count3, 0,
        "switching back to bin-links=false must remove stale shims, leaving 0 files in .bin"
    );
}
