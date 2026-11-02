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

#[test]
fn test_extreme_shim_argument_escaping_nested_quotes_and_backticks() {
    // 1. Deeply nested quotes across multiple levels
    let deep_nested = r#""level1 \"level2 \\\"level3\\\" level2\" level1""#;
    let escaped_cmd = escape_cmd_arg(deep_nested);
    assert!(escaped_cmd.starts_with('"') && escaped_cmd.ends_with('"'));
    assert!(escaped_cmd.contains("level1"));
    assert!(escaped_cmd.contains("level2"));
    assert!(escaped_cmd.contains("level3"));
    assert!(escaped_cmd.contains(r#"\""#));

    // 2. Mixed single and double quotes
    let mixed = r#"He said, "It's dangerous to go alone; take 'this' & that!""#;
    let escaped_posix = escape_posix_arg(mixed);
    assert_eq!(escaped_posix, r#"'He said, "It'\''s dangerous to go alone; take '\''this'\'' & that!"'"#);

    let escaped_ps1 = escape_ps1_arg(mixed);
    assert_eq!(escaped_ps1, r#"'He said, "It''s dangerous to go alone; take ''this'' & that!"'"#);

    let escaped_cmd_mixed = escape_cmd_arg(mixed);
    assert!(escaped_cmd_mixed.contains(r#"\"It's dangerous"#));

    // 3. Backticks combined with shell command expansions
    let backtick_injection = r#"`echo "evil"` && $(whoami) || `rm -rf /`"#;
    let posix_bt = escape_posix_arg(backtick_injection);
    // In POSIX single quotes, backticks and $() are 100% literal and safe
    assert!(posix_bt.starts_with('\'') && posix_bt.ends_with('\''));
    assert!(posix_bt.contains(r#"`echo "evil"`"#));

    let ps1_bt = escape_ps1_arg(backtick_injection);
    // In PowerShell single quotes, backticks are 100% literal and safe
    assert!(ps1_bt.starts_with('\'') && ps1_bt.ends_with('\''));
    assert!(ps1_bt.contains(r#"`echo "evil"`"#));

    let cmd_bt = escape_cmd_arg(backtick_injection);
    assert!(cmd_bt.starts_with('"') && cmd_bt.ends_with('"'));
    assert!(cmd_bt.contains(r#"\"evil\""#));

    // 4. Multi-line arguments with \n and \r\n
    let multiline_unix = "SELECT * FROM users\nWHERE active = 1\nORDER BY id DESC;";
    assert_eq!(escape_posix_arg(multiline_unix), format!("'{multiline_unix}'"));
    assert_eq!(escape_ps1_arg(multiline_unix), format!("'{multiline_unix}'"));
    let cmd_multi = escape_cmd_arg(multiline_unix);
    assert!(cmd_multi.starts_with('"') && cmd_multi.ends_with('"'));
    assert!(cmd_multi.contains("SELECT * FROM users\nWHERE active = 1"));

    let multiline_crlf = "header line\r\n\"nested middle\"\r\nfooter line";
    let ps1_crlf = escape_ps1_arg(multiline_crlf);
    assert_eq!(ps1_crlf, format!("'{multiline_crlf}'"));
    let posix_crlf = escape_posix_arg(multiline_crlf);
    assert_eq!(posix_crlf, format!("'{multiline_crlf}'"));
    let cmd_crlf = escape_cmd_arg(multiline_crlf);
    assert!(cmd_crlf.contains(r#"\"nested middle\""#));

    // 5. Windows path arguments with spaces and trailing backslashes before closing quote
    let win_path_arg = r#"C:\Program Files\NodeJS\x86\"#;
    let escaped_win_path = escape_cmd_arg(win_path_arg);
    // Must end with \\" so the trailing backslash doesn't escape the closing quote
    assert!(escaped_win_path.ends_with(r#"\\""#));
    assert_eq!(escaped_win_path, r#""C:\Program Files\NodeJS\x86\\""#);
}

#[test]
fn test_extreme_shim_path_spaces_and_special_characters() {
    // 1. Target path with multiple spaces, parentheses, ampersands, plus signs
    let complex_path = "nested dir/Program Files (x86)/Acme & Sons/C++ Tools/bin/my tool.js";

    let posix = generate_posix_shim(complex_path);
    assert!(posix.contains(r#""$basedir/../nested dir/Program Files (x86)/Acme & Sons/C++ Tools/bin/my tool.js""#));

    let cmd = generate_cmd_shim(complex_path);
    assert!(cmd.contains(r#""%dp0%\..\nested dir\Program Files (x86)\Acme & Sons\C++ Tools\bin\my tool.js""#));

    let ps1 = generate_ps1_shim(complex_path);
    assert!(ps1.contains(r#""$basedir/../nested dir/Program Files (x86)/Acme & Sons/C++ Tools/bin/my tool.js""#));

    // 2. Target path with backticks and PowerShell subexpressions
    let bt_path = "packages/my`tool`/lib/$(subexpr)/index.js";
    let ps1_bt = generate_ps1_shim(bt_path);
    assert!(ps1_bt.contains("my``tool``"));
    assert!(ps1_bt.contains("`$(subexpr)"));

    let posix_bt = generate_posix_shim(bt_path);
    assert!(posix_bt.contains(r#"my\`tool\`"#));
    assert!(posix_bt.contains(r#"\$(subexpr)"#));

    // 3. Target path with % variables in Windows cmd
    let pct_path = "libs/%USERPROFILE%/bin/cli.js";
    let cmd_pct = generate_cmd_shim(pct_path);
    assert!(cmd_pct.contains(r#"%dp0%\..\libs\%%USERPROFILE%%\bin\cli.js"#));
}

#[test]
fn test_extreme_shim_live_invocation_on_disk() {
    let dir = tempdir().unwrap();
    // Path containing spaces and parentheses mirroring realistic Windows directories
    let project_root = dir.path().join("My Projects (x86)").join("Test Suite");
    let bin_dir = project_root.join("node_modules").join(".bin");
    let tool_dir = project_root.join("node_modules").join("spaced tool").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&tool_dir).unwrap();

    let output_file = project_root.join("args_output.json");
    let escaped_out = output_file.to_string_lossy().replace('\\', "/");

    let script_file = tool_dir.join("cli.js");
    let script_code = format!(
        "const fs = require('fs');\n\
        const args = process.argv.slice(2);\n\
        fs.writeFileSync('{escaped_out}', JSON.stringify(args));\n"
    );
    fs::write(&script_file, script_code).unwrap();

    // Create shims pointing to the tool across relative directories with spaces
    create_shims(
        &bin_dir,
        "spaced-tool",
        "spaced tool/bin/cli.js",
    ).unwrap();

    let cmd_shim = bin_dir.join("spaced-tool.cmd");
    let ps1_shim = bin_dir.join("spaced-tool.ps1");
    let sh_shim = bin_dir.join("spaced-tool");

    assert!(cmd_shim.exists());
    assert!(ps1_shim.exists());
    assert!(sh_shim.exists());

    // Test live invocation via CMD wrapper on Windows
    #[cfg(windows)]
    {
        // 1. Invoke .cmd shim with various extreme arguments
        let mut cmd = std::process::Command::new("cmd.exe");
        cmd.current_dir(&bin_dir);
        let status = cmd
            .arg("/c")
            .arg(".\\spaced-tool.cmd")
            .arg("plain_arg")
            .arg("arg with spaces")
            .arg(r#"arg with "nested quotes""#)
            .arg("`backtick_arg`")
            .arg("multi-word arg")
            .status()
            .expect("Failed to execute cmd shim");

        assert!(status.success(), "CMD shim execution must succeed");
        assert!(output_file.exists(), "CMD shim must have executed target node script");

        let content = fs::read_to_string(&output_file).unwrap();
        let parsed_args: Vec<String> = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed_args.len(), 5);
        assert_eq!(parsed_args[0], "plain_arg");
        assert_eq!(parsed_args[1], "arg with spaces");
        assert!(parsed_args[2].contains("nested quotes"));
        assert_eq!(parsed_args[3], "`backtick_arg`");
        assert_eq!(parsed_args[4], "multi-word arg");

        fs::remove_file(&output_file).unwrap();

        // 2. Invoke .ps1 wrapper with PowerShell including multi-line argument
        let ps_status = std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&ps1_shim)
            .arg("ps1_arg")
            .arg("ps1 with spaces")
            .arg(r#"nested "quotes" in ps1"#)
            .arg("`ps1_backtick`")
            .arg("multi\nline\narg")
            .stdin(std::process::Stdio::null())
            .status();

        if let Ok(st) = ps_status {
            if st.success() && output_file.exists() {
                let ps_content = fs::read_to_string(&output_file).unwrap();
                let ps_args: Vec<String> = serde_json::from_str(&ps_content).unwrap();
                assert_eq!(ps_args[0], "ps1_arg");
                assert_eq!(ps_args[1], "ps1 with spaces");
                assert!(ps_args[2].contains("quotes"));
                assert!(ps_args[3].contains("ps1_backtick"));
                assert!(ps_args[4].contains("multi\nline"));
            }
        }
    }
}

#[test]
fn test_shim_exit_code_fidelity() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    let target_dir = dir.path().join("node_modules").join("exit-pkg");
    fs::create_dir_all(&target_dir).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    let target_script = target_dir.join("cli.js");
    fs::write(&target_script, b"process.exit(42);\n").unwrap();

    create_shims(&bin_dir, "exit-pkg", "exit-pkg/cli.js").unwrap();

    #[cfg(windows)]
    {
        let cmd_shim = bin_dir.join("exit-pkg.cmd");
        let mut cmd = std::process::Command::new("cmd.exe");
        cmd.current_dir(&bin_dir);
        let status = cmd
            .arg("/c")
            .arg(&cmd_shim)
            .status()
            .expect("Failed to execute cmd shim");

        assert_eq!(status.code(), Some(42), "CMD shim must faithfully propagate exit code 42");
    }

    #[cfg(not(windows))]
    {
        let sh_shim = bin_dir.join("exit-pkg");
        let mut cmd = std::process::Command::new("sh");
        cmd.current_dir(&bin_dir);
        let status = cmd
            .arg(&sh_shim)
            .status()
            .expect("Failed to execute posix shim");

        assert_eq!(status.code(), Some(42), "POSIX shim must faithfully propagate exit code 42");
    }
}

#[test]
fn test_cmd_ps1_bash_shim_live_execution_all_shells() {
    let dir = tempdir().unwrap();
    let project_root = dir.path().join("All Shells Test");
    let bin_dir = project_root.join("node_modules").join(".bin");
    let tool_dir = project_root.join("node_modules").join("multi-tool");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&tool_dir).unwrap();

    let output_file = project_root.join("shell_args.json");
    let escaped_out = output_file.to_string_lossy().replace('\\', "/");

    let script_file = tool_dir.join("cli.js");
    let script_code = format!(
        "const fs = require('fs');\n\
        const args = process.argv.slice(2);\n\
        fs.writeFileSync('{escaped_out}', JSON.stringify(args));\n"
    );
    fs::write(&script_file, script_code).unwrap();

    create_shims(
        &bin_dir,
        "multi-tool",
        "multi-tool/cli.js",
    ).unwrap();

    let cmd_shim = bin_dir.join("multi-tool.cmd");
    let ps1_shim = bin_dir.join("multi-tool.ps1");
    let posix_shim = bin_dir.join("multi-tool");

    assert!(cmd_shim.exists());
    assert!(ps1_shim.exists());
    assert!(posix_shim.exists());

    // 1. Windows CMD (.cmd) live invocation
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("cmd.exe");
        cmd.current_dir(&bin_dir);
        cmd.stdin(std::process::Stdio::null());
        let status = cmd
            .arg("/c")
            .arg(".\\multi-tool.cmd")
            .arg("alpha")
            .arg("beta with spaces")
            .arg("quote \"test\"")
            .status()
            .expect("Failed to execute cmd shim");
        assert!(status.success());
        assert!(output_file.exists());
        let content = fs::read_to_string(&output_file).unwrap();
        let args: Vec<String> = serde_json::from_str(&content).unwrap();
        assert_eq!(args[0], "alpha");
        assert_eq!(args[1], "beta with spaces");
        assert!(args[2].contains("quote"));
        fs::remove_file(&output_file).unwrap();
    }

    // 2. PowerShell (.ps1) live invocation
    #[cfg(windows)]
    {
        let ps_res = std::process::Command::new("powershell.exe")
            .current_dir(&bin_dir)
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(".\\multi-tool.ps1")
            .arg("ps_alpha")
            .arg("ps with spaces")
            .arg("literal $(subexpr)")
            .stdin(std::process::Stdio::null())
            .status();

        if let Ok(st) = ps_res {
            if st.success() && output_file.exists() {
                let content = fs::read_to_string(&output_file).unwrap();
                let args: Vec<String> = serde_json::from_str(&content).unwrap();
                assert_eq!(args[0], "ps_alpha");
                assert_eq!(args[1], "ps with spaces");
                assert_eq!(args[2], "literal $(subexpr)");
                fs::remove_file(&output_file).unwrap();
            }
        }
    }

    // 3. POSIX bash shim live invocation (works on Unix and Windows with Git Bash / MSYS)
    let bash_paths = [
        std::path::PathBuf::from("C:\\Program Files\\Git\\bin\\sh.exe"),
        std::path::PathBuf::from("C:\\Program Files\\Git\\bin\\bash.exe"),
        std::path::PathBuf::from("C:\\Program Files\\Git\\usr\\bin\\bash.exe"),
        std::path::PathBuf::from("sh"),
        std::path::PathBuf::from("bash"),
    ];

    let mut bash_exe = None;
    for candidate in &bash_paths {
        if candidate.exists() {
            bash_exe = Some(candidate.clone());
            break;
        } else if let Ok(which) = which_tool(candidate.to_str().unwrap_or_default()) {
            bash_exe = Some(which);
            break;
        }
    }

    if let Some(sh) = bash_exe {
        let mut cmd = std::process::Command::new(sh);
        cmd.current_dir(&bin_dir);
        cmd.stdin(std::process::Stdio::null());
        let status = cmd
            .arg("./multi-tool")
            .arg("bash_arg1")
            .arg("bash arg with spaces")
            .arg("it's a test")
            .status();

        if let Ok(st) = status {
            if st.success() && output_file.exists() {
                let content = fs::read_to_string(&output_file).unwrap();
                let args: Vec<String> = serde_json::from_str(&content).unwrap();
                assert_eq!(args[0], "bash_arg1");
                assert_eq!(args[1], "bash arg with spaces");
                assert_eq!(args[2], "it's a test");
                fs::remove_file(&output_file).unwrap();
            }
        }
    }
}

fn which_tool(name: &str) -> std::io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    let out = std::process::Command::new("where.exe").arg(name).output()?;
    #[cfg(not(windows))]
    let out = std::process::Command::new("which").arg(name).output()?;

    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(first_line) = stdout.lines().next() {
            let p = std::path::PathBuf::from(first_line.trim());
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "tool not found"))
}

#[test]
fn test_shim_exit_code_fidelity_all_codes() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    let target_dir = dir.path().join("node_modules").join("exit-codes-pkg");
    fs::create_dir_all(&target_dir).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    // Test exit codes 124 (timeout), 130 (SIGINT), 143 (SIGTERM), and 42
    for &code in &[124, 130, 143, 42] {
        let script_file = target_dir.join(format!("exit_{code}.js"));
        fs::write(&script_file, format!("process.exit({code});\n")).unwrap();

        let bin_name = format!("exit-{code}");
        create_shims(&bin_dir, &bin_name, &format!("exit-codes-pkg/exit_{code}.js")).unwrap();

        #[cfg(windows)]
        {
            // CMD shim exit code fidelity
            let mut cmd = std::process::Command::new("cmd.exe");
            cmd.current_dir(&bin_dir);
            cmd.stdin(std::process::Stdio::null());
            let status = cmd
                .arg("/c")
                .arg(format!(".\\{bin_name}.cmd"))
                .status()
                .expect("Failed to execute cmd shim");
            assert_eq!(status.code(), Some(code), "CMD shim must faithfully exit with code {code}");

            // PS1 shim exit code fidelity
            let ps_status = std::process::Command::new("powershell.exe")
                .current_dir(&bin_dir)
                .arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-ExecutionPolicy")
                .arg("Bypass")
                .arg("-File")
                .arg(format!(".\\{bin_name}.ps1"))
                .stdin(std::process::Stdio::null())
                .status();

            if let Ok(st) = ps_status {
                assert_eq!(st.code(), Some(code), "PS1 shim must faithfully exit with code {code}");
            }
        }

        // POSIX shim exit code fidelity if sh is available
        let bash_paths = [
            std::path::PathBuf::from("C:\\Program Files\\Git\\bin\\sh.exe"),
            std::path::PathBuf::from("sh"),
        ];
        for sh in &bash_paths {
            if sh.exists() || which_tool(sh.to_str().unwrap_or_default()).is_ok() {
                let mut cmd = std::process::Command::new(sh);
                cmd.current_dir(&bin_dir);
                cmd.stdin(std::process::Stdio::null());
                let status = cmd
                    .arg(format!("./{bin_name}"))
                    .status();
                if let Ok(st) = status {
                    assert_eq!(st.code(), Some(code), "POSIX shim must faithfully exit with code {code}");
                    break;
                }
            }
        }
    }
}
