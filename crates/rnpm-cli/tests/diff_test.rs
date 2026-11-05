use std::fs;
use std::io::Write;
use std::process::Command;
use flate2::write::GzEncoder;
use flate2::Compression;
use tempfile::tempdir;

fn create_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(100000);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{name}"), *content)
                .unwrap();
        }
        builder.finish().unwrap();
    }

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

#[test]
fn test_diff_directories_modifications() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("index.js"), "const a = 1;\nconst b = 2;\n").unwrap();
    fs::write(dir_b.join("index.js"), "const a = 1;\nconst b = 3;\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .output()
        .expect("Failed to execute rnpm diff");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff --git a/index.js b/index.js"));
    assert!(stdout.contains("--- a/index.js"));
    assert!(stdout.contains("+++ b/index.js"));
    assert!(stdout.contains("-const b = 2;"));
    assert!(stdout.contains("+const b = 3;"));
}

#[test]
fn test_diff_added_and_deleted_files() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("old.txt"), "goodbye world\n").unwrap();
    fs::write(dir_b.join("new.txt"), "hello world\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .output()
        .expect("Failed to execute rnpm diff");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // new.txt
    assert!(stdout.contains("diff --git a/new.txt b/new.txt"));
    assert!(stdout.contains("--- /dev/null"));
    assert!(stdout.contains("+++ b/new.txt"));
    assert!(stdout.contains("+hello world"));

    // old.txt
    assert!(stdout.contains("diff --git a/old.txt b/old.txt"));
    assert!(stdout.contains("--- a/old.txt"));
    assert!(stdout.contains("+++ /dev/null"));
    assert!(stdout.contains("-goodbye world"));
}

#[test]
fn test_diff_identical_directories_empty_output() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("foo.js"), "console.log('same');\n").unwrap();
    fs::write(dir_b.join("foo.js"), "console.log('same');\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .output()
        .expect("Failed to execute rnpm diff");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn test_diff_name_only_flag() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("changed.js"), "v1\n").unwrap();
    fs::write(dir_b.join("changed.js"), "v2\n").unwrap();
    fs::write(dir_b.join("added.js"), "new\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .arg("--diff-name-only")
        .output()
        .expect("Failed to execute rnpm diff");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, vec!["added.js", "changed.js"]);
}

#[test]
fn test_diff_ignore_all_space_flag() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("style.js"), "const x = 1;\n").unwrap();
    fs::write(dir_b.join("style.js"), "const   x   =   1;  \n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Without ignore-all-space -> diff detected
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .output()
        .unwrap();
    assert!(!output.stdout.is_empty());

    // With ignore-all-space -> no diff detected
    let output_ignore = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .arg("--diff-ignore-all-space")
        .output()
        .unwrap();
    assert!(output_ignore.status.success());
    assert!(output_ignore.stdout.is_empty());
}

#[test]
fn test_diff_no_prefix_and_custom_prefix() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("main.rs"), "fn one() {}\n").unwrap();
    fs::write(dir_b.join("main.rs"), "fn two() {}\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // --diff-no-prefix
    let output_noprefix = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .arg("--diff-no-prefix")
        .output()
        .unwrap();
    let stdout_noprefix = String::from_utf8_lossy(&output_noprefix.stdout);
    assert!(stdout_noprefix.contains("diff --git main.rs main.rs"));
    assert!(stdout_noprefix.contains("--- main.rs"));
    assert!(stdout_noprefix.contains("+++ main.rs"));

    // --diff-src-prefix and --diff-dst-prefix
    let output_custom = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .arg("--diff-src-prefix=source/")
        .arg("--diff-dst-prefix=target/")
        .output()
        .unwrap();
    let stdout_custom = String::from_utf8_lossy(&output_custom.stdout);
    assert!(stdout_custom.contains("diff --git source/main.rs target/main.rs"));
    assert!(stdout_custom.contains("--- source/main.rs"));
    assert!(stdout_custom.contains("+++ target/main.rs"));
}

#[test]
fn test_diff_flag_multiple_specs() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("file.txt"), "first\n").unwrap();
    fs::write(dir_b.join("file.txt"), "second\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(format!("--diff={}", dir_a.display()))
        .arg(format!("--diff={}", dir_b.display()))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff --git a/file.txt b/file.txt"));
    assert!(stdout.contains("-first"));
    assert!(stdout.contains("+second"));
}

#[test]
fn test_diff_tarball_archives() {
    let tmp = tempdir().unwrap();
    let tgz_a = tmp.path().join("pkg-a.tgz");
    let tgz_b = tmp.path().join("pkg-b.tgz");

    let bytes_a = create_tarball(&[("readme.md", b"# Version 1\n")]);
    let bytes_b = create_tarball(&[("readme.md", b"# Version 2\n")]);

    fs::write(&tgz_a, bytes_a).unwrap();
    fs::write(&tgz_b, bytes_b).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&tgz_a)
        .arg(&tgz_b)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff --git a/readme.md b/readme.md"));
    assert!(stdout.contains("-# Version 1"));
    assert!(stdout.contains("+# Version 2"));
}

#[test]
fn test_diff_one_spec_vs_current_dir() {
    let tmp = tempdir().unwrap();
    let base_dir = tmp.path().join("base");
    let current_dir = tmp.path().join("curr");
    fs::create_dir_all(&base_dir).unwrap();
    fs::create_dir_all(&current_dir).unwrap();

    fs::write(base_dir.join("app.js"), "console.log('base');\n").unwrap();
    fs::write(current_dir.join("app.js"), "console.log('modified');\n").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .current_dir(&current_dir)
        .arg("diff")
        .arg(&base_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff --git a/app.js b/app.js"));
    assert!(stdout.contains("-console.log('base');"));
    assert!(stdout.contains("+console.log('modified');"));
}

#[test]
fn test_diff_binary_files() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    fs::write(dir_a.join("image.png"), vec![0x89, b'P', b'N', b'G', 0x00, 0x01]).unwrap();
    fs::write(dir_b.join("image.png"), vec![0x89, b'P', b'N', b'G', 0x00, 0x02]).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let output = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("diff --git a/image.png b/image.png"));
    assert!(stdout.contains("Binary files a/image.png and b/image.png differ"));
}

#[test]
fn test_diff_unified_context_lines() {
    let tmp = tempdir().unwrap();
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    let a_content = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    let b_content = "1\n2\n3\n4\nX\n6\n7\n8\n9\n10\n";
    fs::write(dir_a.join("lines.txt"), a_content).unwrap();
    fs::write(dir_b.join("lines.txt"), b_content).unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Unified = 1 line of context
    let output_u1 = Command::new(rnpm_bin)
        .arg("diff")
        .arg(&dir_a)
        .arg(&dir_b)
        .arg("--diff-unified=1")
        .output()
        .unwrap();
    let stdout_u1 = String::from_utf8_lossy(&output_u1.stdout);
    assert!(stdout_u1.contains("@@ -4,3 +4,3 @@"));
    assert!(stdout_u1.contains(" 4\n-5\n+X\n 6"));
    assert!(!stdout_u1.contains(" 3\n"));
}
