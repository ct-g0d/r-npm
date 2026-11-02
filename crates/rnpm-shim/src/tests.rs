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

    // 3. Shell metacharacters and injection vectors
    // Batch variable / parameter expansions (%VAR%, %1, !VAR!)
    assert_eq!(escape_cmd_arg("%PATH%"), "\"%PATH%\"");
    assert_eq!(escape_cmd_arg("%1"), "\"%1\"");
    assert_eq!(escape_cmd_arg("!EXPAND!"), "\"!EXPAND!\"");

    // Batch compound command delimiters and operators (&, |, <, >, ^, (, ))
    assert_eq!(escape_cmd_arg("foo & calc.exe"), "\"foo & calc.exe\"");
    assert_eq!(escape_cmd_arg("foo | calc.exe"), "\"foo | calc.exe\"");
    assert_eq!(escape_cmd_arg("foo > out.txt"), "\"foo > out.txt\"");
    assert_eq!(escape_cmd_arg("foo < in.txt"), "\"foo < in.txt\"");
    assert_eq!(escape_cmd_arg("foo ^ bar"), "\"foo ^ bar\"");
    assert_eq!(escape_cmd_arg("(nested)"), "\"(nested)\"");

    // Batch argument delimiters (comma, semicolon, equals)
    assert_eq!(escape_cmd_arg("a,b"), "\"a,b\"");
    assert_eq!(escape_cmd_arg("a;b"), "\"a;b\"");
    assert_eq!(escape_cmd_arg("key=value"), "\"key=value\"");

    // PowerShell injection vectors: subexpression, variable expansion, backticks
    assert_eq!(escape_ps1_arg("$(calc.exe)"), "'$(calc.exe)'");
    assert_eq!(escape_ps1_arg("$env:PATH"), "'$env:PATH'");
    assert_eq!(escape_ps1_arg("`whoami`"), "'`whoami`'");
    assert_eq!(escape_ps1_arg("foo; Start-Process calc"), "'foo; Start-Process calc'");
    assert_eq!(escape_ps1_arg("foo | Out-File"), "'foo | Out-File'");

    // Safe flags preserved without extra quotes
    assert_eq!(escape_ps1_arg("--production"), "--production");
    assert_eq!(escape_ps1_arg("-v"), "-v");

    // Null byte stripping to prevent C string truncation
    assert_eq!(escape_cmd_arg("safe\0evil"), "safeevil");
    assert_eq!(escape_cmd_arg("safe\0 evil"), "\"safe evil\"");
    assert_eq!(escape_ps1_arg("safe\0evil"), "safeevil");
    assert_eq!(escape_posix_arg("safe\0evil"), "safeevil");

    // Path % escaping in cmd to prevent batch expansion
    let path_with_pct = "my-%var%/bin/cli.js";
    let cmd_pct = generate_cmd_shim(path_with_pct);
    assert!(cmd_pct.contains(r"%dp0%\..\my-%%var%%\bin\cli.js"));

    // Path $ and ` escaping in ps1
    let path_with_subexpr = "my-$(dir)/`bin`/cli.js";
    let ps1_sub = generate_ps1_shim(path_with_subexpr);
    assert!(ps1_sub.contains(r"my-`$(dir)/``bin``/cli.js"));
}

#[test]
fn test_normalize_shebang_with_bom_and_crlf() {
    let dir = tempdir().unwrap();

    // 1. Shebang with UTF-8 BOM and CRLF
    let bom_script = dir.path().join("bom_script.js");
    fs::write(&bom_script, b"\xEF\xBB\xBF#!/usr/bin/env node\r\nconsole.log(1);\r\n").unwrap();
    normalize_shebang(&bom_script).unwrap();
    let content = fs::read(&bom_script).unwrap();
    assert_eq!(&content[..23], b"\xEF\xBB\xBF#!/usr/bin/env node\n");

    // 2. Already normalized shebang with LF
    let lf_script = dir.path().join("lf_script.js");
    fs::write(&lf_script, b"#!/usr/bin/env node\nconsole.log(1);\n").unwrap();
    normalize_shebang(&lf_script).unwrap();
    let content_lf = fs::read(&lf_script).unwrap();
    assert_eq!(&content_lf[..20], b"#!/usr/bin/env node\n");

    // 3. File without shebang should not be altered
    let no_shebang = dir.path().join("no_shebang.js");
    let original = b"const x = 1;\r\nconsole.log(x);\r\n";
    fs::write(&no_shebang, original).unwrap();
    normalize_shebang(&no_shebang).unwrap();
    let content_none = fs::read(&no_shebang).unwrap();
    assert_eq!(content_none, original);
}

#[test]
fn test_workspace_directory_junction_linking_unprivileged() {
    let dir = tempdir().unwrap();
    let member_dir = dir.path().join("packages").join("pkg-a");
    let link_dir = dir.path().join("node_modules").join("pkg-a");

    fs::create_dir_all(&member_dir).unwrap();
    fs::write(member_dir.join("index.js"), "module.exports = 'pkg-a';").unwrap();

    // Create junction without elevation
    rnpm_fs::create_junction(&link_dir, &member_dir).unwrap();
    assert!(rnpm_fs::is_junction(&link_dir).unwrap(), "Junction reparse point must be detected");

    // Reading through junction
    let read_file = fs::read_to_string(link_dir.join("index.js")).unwrap();
    assert_eq!(read_file, "module.exports = 'pkg-a';");

    // Safe deletion: removes junction, keeps source files intact
    rnpm_fs::remove_junction(&link_dir).unwrap();
    assert!(!link_dir.exists(), "Junction link should be gone");
    assert!(member_dir.exists(), "Target workspace package must remain intact");
    assert!(member_dir.join("index.js").exists(), "Target files must remain intact");
}
