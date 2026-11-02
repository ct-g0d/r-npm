use crate::*;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_generate_shims_content() {
    let posix = generate_posix_shim("typescript/bin/tsc.js");
    assert!(posix.starts_with("#!/bin/sh"));
    assert!(posix.contains("\"$basedir/../typescript/bin/tsc.js\""));

    let cmd = generate_cmd_shim("typescript/bin/tsc.js");
    assert!(cmd.starts_with("@ECHO off"));
    assert!(cmd.contains("%dp0%\\..\\typescript\\bin\\tsc.js"));

    let ps1 = generate_ps1_shim("typescript/bin/tsc.js");
    assert!(ps1.starts_with("#!/usr/bin/env pwsh"));
    assert!(ps1.contains("$basedir/../typescript/bin/tsc.js"));
    assert!(ps1.contains("$MyInvocation.ExpectingInput"));
}

#[test]
fn test_create_shims_on_disk() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    create_shims(&bin_dir, "tsc", "typescript/bin/tsc.js").unwrap();

    assert!(bin_dir.join("tsc").exists());
    assert!(bin_dir.join("tsc.cmd").exists());
    assert!(bin_dir.join("tsc.ps1").exists());
}

#[test]
fn test_normalize_shebang() {
    let dir = tempdir().unwrap();
    let script = dir.path().join("cli.js");
    fs::write(&script, b"#!/usr/bin/env node\r\nconsole.log(1);\r\n").unwrap();

    normalize_shebang(&script).unwrap();
    let content = fs::read(&script).unwrap();
    assert_eq!(&content[..20], b"#!/usr/bin/env node\n");
}

#[test]
fn test_path_and_argument_escaping_special_chars() {
    // 1. Path with spaces and special chars
    let weird_path = r#"special dir/with $var & `backticks` "quotes"/cli.js"#;

    let posix = generate_posix_shim(weird_path);
    assert!(posix.contains(r#"special dir/with \$var & \`backticks\` \"quotes\"/cli.js"#));

    let cmd = generate_cmd_shim(weird_path);
    assert!(!cmd.contains(r#""quotes""#)); // Quotes inside target stripped in cmd path

    let ps1 = generate_ps1_shim(weird_path);
    assert!(ps1.contains(r#"special dir/with `$var & ``backticks`` `"quotes`"/cli.js"#));

    // 2. Argument escaping tests
    // Empty strings
    assert_eq!(escape_posix_arg(""), "''");
    assert_eq!(escape_cmd_arg(""), "\"\"");
    assert_eq!(escape_ps1_arg(""), "''");

    // Arguments with spaces
    assert_eq!(escape_posix_arg("hello world"), "'hello world'");
    assert_eq!(escape_cmd_arg("hello world"), "\"hello world\"");
    assert_eq!(escape_ps1_arg("hello world"), "'hello world'");

    // Arguments with quotes and special characters
    assert_eq!(escape_posix_arg("it's a test"), r"'it'\''s a test'");
    assert_eq!(escape_cmd_arg(r#"quote "inside""#), r#""quote \"inside\"""#);
    assert_eq!(escape_ps1_arg("single 'quote'"), "'single ''quote'''");

    // Arguments with spaces and trailing backslash before quote
    assert_eq!(escape_cmd_arg(r#"C:\path with space\to\"#), r#""C:\path with space\to\\""#);
}
