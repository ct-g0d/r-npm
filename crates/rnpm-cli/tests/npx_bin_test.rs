use rnpm_cli::npx::{is_npx_argv0, translate_npx_args};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_argv0_stem_detection_unit() {
    assert!(is_npx_argv0("npx"));
    assert!(is_npx_argv0("npx.exe"));
    assert!(is_npx_argv0("NPX"));
    assert!(is_npx_argv0("NPX.EXE"));
    assert!(is_npx_argv0("rnpm-npx"));
    assert!(is_npx_argv0("rnpm-npx.exe"));
    assert!(is_npx_argv0("/usr/local/bin/npx"));
    assert!(is_npx_argv0("/usr/bin/rnpm-npx"));
    assert!(is_npx_argv0("C:\\Program Files\\nodejs\\npx.exe"));
    assert!(is_npx_argv0("C:\\rnpm\\rnpm-npx.exe"));
    assert!(is_npx_argv0("./npx"));
    assert!(is_npx_argv0(".\\npx.exe"));

    assert!(!is_npx_argv0("rnpm"));
    assert!(!is_npx_argv0("rnpm.exe"));
    assert!(!is_npx_argv0("npm"));
    assert!(!is_npx_argv0("node"));
    assert!(!is_npx_argv0("my-npx-tool"));
}

#[test]
fn test_npx_argument_translation_unit() {
    // 1. Tool followed by --help and other flags: flags are preserved after --
    let args = vec![
        "mytool".to_string(),
        "--help".to_string(),
        "--custom-flag".to_string(),
        "value".to_string(),
    ];
    assert_eq!(
        translate_npx_args(&args),
        vec!["exec", "--", "mytool", "--help", "--custom-flag", "value"]
    );

    // 2. -y and --yes
    assert_eq!(
        translate_npx_args(&["-y".into(), "cowsay".into(), "moo".into()]),
        vec!["exec", "--yes", "--", "cowsay", "moo"]
    );
    assert_eq!(
        translate_npx_args(&["--yes".into(), "cowsay".into()]),
        vec!["exec", "--yes", "--", "cowsay"]
    );

    // 3. --no, --no-yes, --no-install
    assert_eq!(
        translate_npx_args(&["--no".into(), "cowsay".into()]),
        vec!["exec", "--no-yes", "--", "cowsay"]
    );
    assert_eq!(
        translate_npx_args(&["--no-yes".into(), "cowsay".into()]),
        vec!["exec", "--no-yes", "--", "cowsay"]
    );
    assert_eq!(
        translate_npx_args(&["--no-install".into(), "nonexistent-pkg".into()]),
        vec!["exec", "--yes=false", "--", "nonexistent-pkg"]
    );

    // 4. -p / --package
    assert_eq!(
        translate_npx_args(&["-p".into(), "local-pkg".into(), "mytool".into()]),
        vec!["exec", "--package", "local-pkg", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--package=local-pkg".into(), "mytool".into()]),
        vec!["exec", "--package=local-pkg", "--", "mytool"]
    );

    // 5. -c / --call
    assert_eq!(
        translate_npx_args(&["-c".into(), "mytool arg1".into()]),
        vec!["exec", "--call", "mytool arg1"]
    );
    assert_eq!(
        translate_npx_args(&["--call=mytool arg1".into()]),
        vec!["exec", "--call=mytool arg1"]
    );

    // 6. -q / --quiet
    assert_eq!(
        translate_npx_args(&["-q".into(), "mytool".into()]),
        vec!["exec", "--quiet", "--", "mytool"]
    );

    // 7. --offline, --prefer-offline, --prefer-online
    assert_eq!(
        translate_npx_args(&["--offline".into(), "mytool".into()]),
        vec!["exec", "--offline", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--prefer-offline".into(), "mytool".into()]),
        vec!["exec", "--prefer-offline", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--prefer-online".into(), "mytool".into()]),
        vec!["exec", "--prefer-online", "--", "mytool"]
    );

    // 8. --registry, --cache, --userconfig
    assert_eq!(
        translate_npx_args(&[
            "--registry".into(),
            "https://registry.example.org".into(),
            "mytool".into()
        ]),
        vec![
            "exec",
            "--registry",
            "https://registry.example.org",
            "--",
            "mytool"
        ]
    );
    assert_eq!(
        translate_npx_args(&["--cache=/tmp/cache".into(), "mytool".into()]),
        vec!["exec", "--cache=/tmp/cache", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--userconfig=/tmp/.npmrc".into(), "mytool".into()]),
        vec!["exec", "--userconfig=/tmp/.npmrc", "--", "mytool"]
    );

    // 9. -w / --workspace / --workspaces
    assert_eq!(
        translate_npx_args(&["-w".into(), "pkg-a".into(), "mytool".into()]),
        vec!["exec", "--workspace", "pkg-a", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--workspaces".into(), "mytool".into()]),
        vec!["exec", "--workspaces", "--", "mytool"]
    );

    // 10. --ignore-existing / --no-prefer-local
    assert_eq!(
        translate_npx_args(&["--ignore-existing".into(), "mytool".into()]),
        vec!["exec", "--", "mytool"]
    );
    assert_eq!(
        translate_npx_args(&["--no-prefer-local".into(), "mytool".into()]),
        vec!["exec", "--no-prefer-local", "--", "mytool"]
    );

    // 11. -- separator
    assert_eq!(
        translate_npx_args(&["--".into(), "mytool".into(), "--yes".into()]),
        vec!["exec", "--", "mytool", "--yes"]
    );

    // 12. --version and --help standalone
    assert_eq!(
        translate_npx_args(&["--version".into()]),
        vec!["exec", "--version"]
    );
    assert_eq!(
        translate_npx_args(&["-v".into()]),
        vec!["exec", "--version"]
    );
    assert_eq!(
        translate_npx_args(&["--help".into()]),
        vec!["exec", "--help"]
    );
    assert_eq!(
        translate_npx_args(&["-h".into()]),
        vec!["exec", "--help"]
    );
}

fn create_mock_local_tool(dir: &std::path::Path, name: &str) {
    let bin_dir = dir.join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    #[cfg(windows)]
    {
        let cmd_script = format!(
            "@echo off\r\necho {name}_CALLED\r\necho ARGS: %*\r\n"
        );
        fs::write(bin_dir.join(format!("{name}.cmd")), cmd_script).unwrap();
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let sh_script = format!(
            "#!/bin/sh\necho \"{name}_CALLED\"\necho \"ARGS: $@\"\n"
        );
        let script_path = bin_dir.join(name);
        fs::write(&script_path, sh_script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
    }
}

#[test]
fn test_compiled_npx_version_and_help() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");

    // npx --version
    let output = Command::new(npx_bin)
        .arg("--version")
        .output()
        .expect("failed to execute npx --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("11.20.0"));

    // npx -v
    let output = Command::new(npx_bin)
        .arg("-v")
        .output()
        .expect("failed to execute npx -v");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("11.20.0"));

    // npx --help
    let output = Command::new(npx_bin)
        .arg("--help")
        .output()
        .expect("failed to execute npx --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exec") || stdout.contains("Run arbitrary package binaries") || stdout.contains("Run a command"));
}

#[test]
fn test_compiled_npx_runs_local_bin_with_forwarded_flags() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    create_mock_local_tool(temp_path, "mytool");

    // Ensure package.json exists so project root is recognized
    fs::write(temp_path.join("package.json"), r#"{"name":"test-proj","version":"1.0.0"}"#).unwrap();

    // Run `npx mytool --help --custom-flag value`
    // CRITICAL: --help must go to mytool, NOT be consumed by npx!
    let output = Command::new(npx_bin)
        .current_dir(temp_path)
        .args(["mytool", "--help", "--custom-flag", "value"])
        .output()
        .expect("failed to execute npx mytool");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Command failed! Stderr: {stderr}, Stdout: {stdout}"
    );
    assert!(
        stdout.contains("mytool_CALLED"),
        "mytool was not executed! Stdout: {stdout}"
    );
    assert!(
        stdout.contains("--help"),
        "--help was not forwarded to mytool! Stdout: {stdout}"
    );
    assert!(
        stdout.contains("--custom-flag value"),
        "--custom-flag value was not forwarded! Stdout: {stdout}"
    );
}

#[test]
fn test_compiled_npx_call_option() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    create_mock_local_tool(temp_path, "mytool");
    fs::write(temp_path.join("package.json"), r#"{"name":"test-call","version":"1.0.0"}"#).unwrap();

    // Test npx -c "mytool arg1"
    let output = Command::new(npx_bin)
        .current_dir(temp_path)
        .args(["-c", "mytool arg1"])
        .output()
        .expect("failed to execute npx -c");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("mytool_CALLED"));
    assert!(stdout.contains("arg1"));
}

#[test]
fn test_compiled_npx_package_option() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    // Prepare mock package in custom cache _npx/local-pkg
    let cache_dir = temp_path.join("cache");
    let npx_pkg_dir = cache_dir.join("_npx").join("local-pkg");
    create_mock_local_tool(&npx_pkg_dir, "mytool");

    fs::write(temp_path.join("package.json"), r#"{"name":"test-pkg-opt","version":"1.0.0"}"#).unwrap();

    // Test npx -p local-pkg mytool
    let output = Command::new(npx_bin)
        .current_dir(temp_path)
        .args([
            &format!("--cache={}", cache_dir.display()),
            "-p",
            "local-pkg",
            "mytool",
            "arg_from_p",
        ])
        .output()
        .expect("failed to execute npx -p");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("mytool_CALLED"));
    assert!(stdout.contains("arg_from_p"));
}

#[test]
fn test_compiled_npx_no_install() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    // Run npx --no-install nonexistent-pkg
    let output = Command::new(npx_bin)
        .current_dir(temp_path)
        .args(["--no-install", "nonexistent-pkg-w3-2-random-xyz"])
        .output()
        .expect("failed to execute npx --no-install");

    // Must fail cleanly without fetching
    assert!(!output.status.success());
}

#[test]
fn test_compiled_npx_dashdash_separator_forwarding() {
    let npx_bin = env!("CARGO_BIN_EXE_npx");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    create_mock_local_tool(temp_path, "mytool");
    fs::write(temp_path.join("package.json"), r#"{"name":"test-dashdash","version":"1.0.0"}"#).unwrap();

    // Run npx -- mytool --yes
    let output = Command::new(npx_bin)
        .current_dir(temp_path)
        .args(["--", "mytool", "--yes"])
        .output()
        .expect("failed to execute npx --");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("mytool_CALLED"));
    assert!(stdout.contains("--yes"));
}

#[test]
fn test_rnpm_argv0_dispatch_as_npx() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    let temp_path = temp.path();

    create_mock_local_tool(temp_path, "mytool");
    fs::write(temp_path.join("package.json"), r#"{"name":"test-argv0","version":"1.0.0"}"#).unwrap();

    // Copy rnpm as npx (or npx.exe) in temp_path
    let npx_target = if cfg!(windows) {
        temp_path.join("npx.exe")
    } else {
        temp_path.join("npx")
    };
    fs::copy(rnpm_bin, &npx_target).unwrap();

    // Test that running copied rnpm as npx dispatches to npx mode!
    let output = Command::new(&npx_target)
        .arg("--version")
        .output()
        .expect("failed to run copied npx binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("11.20.0"));

    // Test tool execution with copied npx
    let output = Command::new(&npx_target)
        .current_dir(temp_path)
        .args(["mytool", "--help", "custom_val"])
        .output()
        .expect("failed to run tool via copied npx");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mytool_CALLED"));
    assert!(stdout.contains("--help"));
    assert!(stdout.contains("custom_val"));
}
