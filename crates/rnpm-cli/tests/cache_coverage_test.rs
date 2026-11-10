use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cache_add_and_ls_and_verify() {
    let tmp = tempdir().unwrap();
    let cache_dir = tmp.path().join("cache");
    let sample_file = tmp.path().join("sample.tgz");
    fs::write(&sample_file, b"sample package archive content").unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test cache add
    let add_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "add",
            sample_file.to_str().unwrap(),
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache add");

    assert!(add_output.status.success(), "cache add failed: {}", String::from_utf8_lossy(&add_output.stderr));
    let stdout = String::from_utf8_lossy(&add_output.stdout);
    assert!(stdout.contains("Added"));

    // Test cache ls
    let ls_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "ls",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache ls");

    assert!(ls_output.status.success(), "cache ls failed: {}", String::from_utf8_lossy(&ls_output.stderr));
    let ls_stdout = String::from_utf8_lossy(&ls_output.stdout);
    assert!(ls_stdout.contains("_cacache") || !ls_stdout.is_empty());

    // Test cache verify
    let verify_output = Command::new(rnpm_bin)
        .current_dir(tmp.path())
        .args([
            "cache",
            "verify",
            "--cache",
            cache_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run rnpm cache verify");

    assert!(verify_output.status.success(), "cache verify failed: {}", String::from_utf8_lossy(&verify_output.stderr));
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("Cache verified"));
}
