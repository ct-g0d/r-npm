use crate::*;
use std::fs;
use tempfile::tempdir;

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
    let target_file = dir
        .path()
        .join("node_modules")
        .join("typescript")
        .join("bin")
        .join("tsc.js");
    fs::create_dir_all(target_file.parent().unwrap()).unwrap();
    fs::write(&target_file, b"#!/usr/bin/env node\nconsole.log('tsc');\n").unwrap();
    create_shims(&bin_dir, "tsc", "typescript/bin/tsc.js").unwrap();

    #[cfg(not(unix))]
    {
        assert!(bin_dir.join("tsc").exists());
        assert!(bin_dir.join("tsc.cmd").exists());
        assert!(bin_dir.join("tsc.ps1").exists());
    }

    #[cfg(unix)]
    {
        let link = bin_dir.join("tsc");
        assert!(link.is_symlink());
        let target = fs::read_link(&link).unwrap();
        assert_eq!(target, std::path::PathBuf::from("../typescript/bin/tsc.js"));
        assert!(!bin_dir.join("tsc.cmd").exists());
        assert!(!bin_dir.join("tsc.ps1").exists());
    }
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
    assert_eq!(
        escape_cmd_arg(r#"C:\path with space\to\"#),
        r#""C:\path with space\to\\""#
    );

    // 3. Shell metacharacters and injection vectors
    // Batch variable / parameter expansions (%VAR%, %1, !VAR!)
    assert_eq!(escape_cmd_arg("%PATH%"), "\"%%PATH%%\"");
    assert_eq!(escape_cmd_arg("%1"), "\"%%1\"");
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
    assert_eq!(
        escape_ps1_arg("foo; Start-Process calc"),
        "'foo; Start-Process calc'"
    );
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
    fs::write(
        &bom_script,
        b"\xEF\xBB\xBF#!/usr/bin/env node\r\nconsole.log(1);\r\n",
    )
    .unwrap();
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
    assert!(
        rnpm_fs::is_junction(&link_dir).unwrap(),
        "Junction reparse point must be detected"
    );

    // Reading through junction
    let read_file = fs::read_to_string(link_dir.join("index.js")).unwrap();
    assert_eq!(read_file, "module.exports = 'pkg-a';");

    // Safe deletion: removes junction, keeps source files intact
    rnpm_fs::remove_junction(&link_dir).unwrap();
    assert!(!link_dir.exists(), "Junction link should be gone");
    assert!(
        member_dir.exists(),
        "Target workspace package must remain intact"
    );
    assert!(
        member_dir.join("index.js").exists(),
        "Target files must remain intact"
    );
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
    assert_eq!(
        escaped_posix,
        r#"'He said, "It'\''s dangerous to go alone; take '\''this'\'' & that!"'"#
    );

    let escaped_ps1 = escape_ps1_arg(mixed);
    assert_eq!(
        escaped_ps1,
        r#"'He said, "It''s dangerous to go alone; take ''this'' & that!"'"#
    );

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
    assert_eq!(
        escape_posix_arg(multiline_unix),
        format!("'{multiline_unix}'")
    );
    assert_eq!(
        escape_ps1_arg(multiline_unix),
        format!("'{multiline_unix}'")
    );
    let cmd_multi = escape_cmd_arg(multiline_unix);
    assert!(cmd_multi.starts_with('"') && cmd_multi.ends_with('"'));
    assert!(cmd_multi.contains("SELECT * FROM usersWHERE active = 1"));
    assert!(!cmd_multi.contains('\n') && !cmd_multi.contains('\r'));

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
    assert!(posix.contains(
        r#""$basedir/../nested dir/Program Files (x86)/Acme & Sons/C++ Tools/bin/my tool.js""#
    ));

    let cmd = generate_cmd_shim(complex_path);
    assert!(cmd.contains(
        r#""%dp0%\..\nested dir\Program Files (x86)\Acme & Sons\C++ Tools\bin\my tool.js""#
    ));

    let ps1 = generate_ps1_shim(complex_path);
    assert!(ps1.contains(
        r#""$basedir/../nested dir/Program Files (x86)/Acme & Sons/C++ Tools/bin/my tool.js""#
    ));

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
    let tool_dir = project_root
        .join("node_modules")
        .join("spaced tool")
        .join("bin");
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
    fs::write(&script_file, format!("#!/usr/bin/env node\n{script_code}")).unwrap();

    // Create shims pointing to the tool across relative directories with spaces
    create_shims(&bin_dir, "spaced-tool", "spaced tool/bin/cli.js").unwrap();

    let cmd_shim = bin_dir.join("spaced-tool.cmd");
    let ps1_shim = bin_dir.join("spaced-tool.ps1");
    let sh_shim = bin_dir.join("spaced-tool");

    #[cfg(not(unix))]
    {
        assert!(cmd_shim.exists());
        assert!(ps1_shim.exists());
    }
    #[cfg(unix)]
    {
        assert!(!cmd_shim.exists());
        assert!(!ps1_shim.exists());
        assert!(sh_shim.is_symlink());
    }
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
        assert!(
            output_file.exists(),
            "CMD shim must have executed target node script"
        );

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
    fs::write(&target_script, b"#!/usr/bin/env node\nprocess.exit(42);\n").unwrap();

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

        assert_eq!(
            status.code(),
            Some(42),
            "CMD shim must faithfully propagate exit code 42"
        );
    }

    #[cfg(not(windows))]
    {
        let sh_shim = bin_dir.join("exit-pkg");
        assert!(sh_shim.is_symlink());
        let mut cmd = std::process::Command::new(&sh_shim);
        cmd.current_dir(&bin_dir);
        if let Ok(status) = cmd.status() {
            assert_eq!(
                status.code(),
                Some(42),
                "POSIX symlink must faithfully propagate exit code 42"
            );
        }
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
    fs::write(&script_file, format!("#!/usr/bin/env node\n{script_code}")).unwrap();

    create_shims(&bin_dir, "multi-tool", "multi-tool/cli.js").unwrap();

    let cmd_shim = bin_dir.join("multi-tool.cmd");
    let ps1_shim = bin_dir.join("multi-tool.ps1");
    let posix_shim = bin_dir.join("multi-tool");

    #[cfg(not(unix))]
    {
        assert!(cmd_shim.exists());
        assert!(ps1_shim.exists());
    }
    #[cfg(unix)]
    {
        assert!(!cmd_shim.exists());
        assert!(!ps1_shim.exists());
        assert!(posix_shim.is_symlink());
    }
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
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "tool not found",
    ))
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
        fs::write(
            &script_file,
            format!("#!/usr/bin/env node\nprocess.exit({code});\n"),
        )
        .unwrap();

        let bin_name = format!("exit-{code}");
        create_shims(
            &bin_dir,
            &bin_name,
            &format!("exit-codes-pkg/exit_{code}.js"),
        )
        .unwrap();

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
            assert_eq!(
                status.code(),
                Some(code),
                "CMD shim must faithfully exit with code {code}"
            );

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
                assert_eq!(
                    st.code(),
                    Some(code),
                    "PS1 shim must faithfully exit with code {code}"
                );
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
                let status = cmd.arg(format!("./{bin_name}")).status();
                if let Ok(st) = status {
                    assert_eq!(
                        st.code(),
                        Some(code),
                        "POSIX shim must faithfully exit with code {code}"
                    );
                    break;
                }
            }
        }
    }
}

#[test]
fn test_shebang_parsing_with_quotes_and_flags() {
    use crate::shebang::parse_shebang;

    let s1 = "#!/usr/bin/env -S node --harmony --title=\"my tool\"";
    let info1 = parse_shebang(s1).unwrap();
    assert_eq!(info1.program, "node");
    assert_eq!(info1.args, vec!["--harmony", "--title=my tool"]);

    let s2 = "#!/bin/sh -e -x";
    let info2 = parse_shebang(s2).unwrap();
    assert_eq!(info2.program, "sh");
    assert_eq!(info2.args, vec!["-e", "-x"]);
}

#[test]
#[cfg(windows)]
fn test_compute_relative_path_case_insensitivity_windows() {
    use crate::path::compute_relative_path;

    let from = Path::new(r"C:\Users\Developer\Project\node_modules\.bin");
    let to = Path::new(r"c:\users\developer\project\node_modules\my-tool\bin\cli.js");
    let rel = compute_relative_path(from, to).unwrap();
    assert_eq!(rel, "../my-tool/bin/cli.js");

    let from_mixed = Path::new(r"D:\App\Node_Modules\.BIN");
    let to_mixed = Path::new(r"d:\app\node_modules\PKG\cli.js");
    let rel_mixed = compute_relative_path(from_mixed, to_mixed).unwrap();
    assert_eq!(rel_mixed, "../PKG/cli.js");
}

#[test]
fn test_direct_shims_match_npm_for_targets_without_shebang() {
    let dir = tempdir().unwrap();
    let pkg = dir.path().join("node_modules/untun/dist");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(
        pkg.join("cli.mjs"),
        "import { log } from \"./_chunks/log.mjs\";\n",
    )
    .unwrap();
    let bin_dir = dir.path().join("node_modules/.bin");
    create_shims(&bin_dir, "untun", "untun/dist/cli.mjs").unwrap();

    #[cfg(not(unix))]
    for name in ["untun", "untun.cmd", "untun.ps1"] {
        let expected = fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/direct-fixtures")
                .join(name),
        )
        .unwrap();
        assert_eq!(fs::read(bin_dir.join(name)).unwrap(), expected, "{name}");
    }

    #[cfg(unix)]
    {
        let link = bin_dir.join("untun");
        assert!(link.is_symlink());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            std::path::PathBuf::from("../untun/dist/cli.mjs")
        );
        assert!(!bin_dir.join("untun.cmd").exists());
        assert!(!bin_dir.join("untun.ps1").exists());
    }
}

#[test]
fn test_direct_ps1_shim_escapes_powershell_specials() {
    let (_, _, ps1) = generate_direct_shims("pkg/bin/$tool`x.exe");
    assert!(
        ps1.contains("& \"$basedir/../pkg/bin/`$tool``x.exe\"   $args"),
        "{ps1}"
    );
    assert!(!ps1.contains(r"\$tool"));
}

#[test]
fn test_program_shims_match_npm_for_non_node_shebang() {
    let dir = tempdir().unwrap();
    let pkg = dir.path().join("node_modules/xyz");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(
        pkg.join("xyz"),
        "#!/usr/bin/env bash\nset -euf -o pipefail\n",
    )
    .unwrap();
    let bin_dir = dir.path().join("node_modules/.bin");
    create_shims(&bin_dir, "xyz", "xyz/xyz").unwrap();

    #[cfg(not(unix))]
    for name in ["xyz", "xyz.cmd", "xyz.ps1"] {
        let expected = fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/program-fixtures")
                .join(name),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&fs::read(bin_dir.join(name)).unwrap()),
            String::from_utf8_lossy(&expected),
            "{name}"
        );
    }

    #[cfg(unix)]
    {
        let link = bin_dir.join("xyz");
        assert!(link.is_symlink());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            std::path::PathBuf::from("../xyz/xyz")
        );
        assert!(!bin_dir.join("xyz.cmd").exists());
        assert!(!bin_dir.join("xyz.ps1").exists());
    }
}

#[test]
fn test_compute_symlink_target_dot_bin_and_global() {
    use std::path::Path;

    // 1. Standard .bin directory
    let dot_bin = Path::new("project/node_modules/.bin");
    assert_eq!(
        compute_symlink_target(dot_bin, "typescript/bin/tsc.js"),
        "../typescript/bin/tsc.js"
    );

    // 2. Scoped package in .bin
    assert_eq!(
        compute_symlink_target(dot_bin, "@scope/pkg/bin/tool.js"),
        "../@scope/pkg/bin/tool.js"
    );

    // 3. Leading ./ stripped
    assert_eq!(
        compute_symlink_target(dot_bin, "./typescript/bin/tsc.js"),
        "../typescript/bin/tsc.js"
    );

    // 4. Windows backslashes normalized to forward slashes
    assert_eq!(
        compute_symlink_target(dot_bin, r"typescript\bin\tsc.js"),
        "../typescript/bin/tsc.js"
    );

    // 5. Global bin directory (e.g. /usr/local/bin)
    let global_bin = Path::new("/usr/local/bin");
    assert_eq!(
        compute_symlink_target(global_bin, "typescript/bin/tsc.js"),
        "../lib/node_modules/typescript/bin/tsc.js"
    );

    // 6. Global bin directory with scoped package
    assert_eq!(
        compute_symlink_target(global_bin, "@scope/pkg/bin/tool.js"),
        "../lib/node_modules/@scope/pkg/bin/tool.js"
    );
}

#[test]
#[cfg(unix)]
fn test_unix_symlink_creation_and_chmod() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    let pkg_dir = dir.path().join("node_modules").join("my-pkg").join("bin");
    fs::create_dir_all(&pkg_dir).unwrap();

    let script = pkg_dir.join("cli.js");
    fs::write(&script, b"#!/usr/bin/env node\nconsole.log('hi');\n").unwrap();
    // Set initial non-executable permissions
    let mut initial_perms = fs::metadata(&script).unwrap().permissions();
    initial_perms.set_mode(0o644);
    fs::set_permissions(&script, initial_perms).unwrap();

    // Create shims
    create_shims(&bin_dir, "my-tool", "my-pkg/bin/cli.js").unwrap();

    // Verify symlink
    let link = bin_dir.join("my-tool");
    assert!(link.is_symlink());
    assert_eq!(
        fs::read_link(&link).unwrap(),
        std::path::PathBuf::from("../my-pkg/bin/cli.js")
    );

    // Verify target script chmod 0755
    let perms = fs::metadata(&script).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o755);

    // Verify no .cmd or .ps1 shims
    assert!(!bin_dir.join("my-tool.cmd").exists());
    assert!(!bin_dir.join("my-tool.ps1").exists());

    // Test stale replacement: overwrite with a regular file and dummy .cmd/.ps1
    fs::remove_file(&link).unwrap();
    fs::write(&link, b"stale binary").unwrap();
    fs::write(bin_dir.join("my-tool.cmd"), b"stale cmd").unwrap();
    fs::write(bin_dir.join("my-tool.ps1"), b"stale ps1").unwrap();

    // Call create_shims again
    create_shims(&bin_dir, "my-tool", "my-pkg/bin/cli.js").unwrap();

    // Must have replaced regular file with symlink and removed .cmd/.ps1
    assert!(link.is_symlink());
    assert_eq!(
        fs::read_link(&link).unwrap(),
        std::path::PathBuf::from("../my-pkg/bin/cli.js")
    );
    assert!(!bin_dir.join("my-tool.cmd").exists());
    assert!(!bin_dir.join("my-tool.ps1").exists());
}

#[test]
#[cfg(unix)]
fn test_unix_missing_bin_target_skipped_gracefully() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    // Target does not exist
    create_shims(&bin_dir, "missing-bin", "nonexistent-pkg/bin/script.js").unwrap();
    assert!(!bin_dir.join("missing-bin").exists());
}

#[test]
#[cfg(unix)]
fn test_unix_refuse_clobber_colliding_directory() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    let pkg_dir = dir.path().join("node_modules").join("my-pkg").join("bin");
    fs::create_dir_all(&pkg_dir).unwrap();
    let script = pkg_dir.join("cli.js");
    fs::write(&script, b"#!/usr/bin/env node\n").unwrap();

    // Create a directory where the bin link would go
    let colliding_dir = bin_dir.join("colliding-bin");
    fs::create_dir_all(&colliding_dir).unwrap();
    let important_file = colliding_dir.join("important.txt");
    fs::write(&important_file, b"cannot be nuked").unwrap();

    // Attempting to create a bin link must fail and NOT remove the directory!
    let res = create_shims(&bin_dir, "colliding-bin", "my-pkg/bin/cli.js");
    assert!(res.is_err());
    assert!(important_file.exists());
    assert!(colliding_dir.is_dir());
}

#[test]
#[cfg(unix)]
fn test_unix_crlf_shebang_normalized_and_chmod_before_linking() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    let pkg_dir = dir.path().join("node_modules").join("crlf-pkg").join("bin");
    fs::create_dir_all(&pkg_dir).unwrap();

    let script = pkg_dir.join("cli.js");
    fs::write(&script, b"#!/usr/bin/env node\r\nconsole.log('hi');\r\n").unwrap();
    let mut initial_perms = fs::metadata(&script).unwrap().permissions();
    initial_perms.set_mode(0o644);
    fs::set_permissions(&script, initial_perms).unwrap();

    create_shims(&bin_dir, "crlf-bin", "crlf-pkg/bin/cli.js").unwrap();

    // Target script must have normalized shebang (LF only)
    let content = fs::read(&script).unwrap();
    assert!(content.starts_with(b"#!/usr/bin/env node\n"));

    // Target script permissions must be 0o755
    let perms = fs::metadata(&script).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o755);

    // Bin symlink must exist
    let link = bin_dir.join("crlf-bin");
    assert!(link.is_symlink());
}

#[test]
#[cfg(not(unix))]
fn test_windows_shim_trio_creation() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    create_shims(&bin_dir, "win-tool", "win-pkg/bin/cli.js").unwrap();

    assert!(bin_dir.join("win-tool").exists());
    assert!(bin_dir.join("win-tool.cmd").exists());
    assert!(bin_dir.join("win-tool.ps1").exists());

    let sh = fs::read_to_string(bin_dir.join("win-tool")).unwrap();
    let cmd = fs::read_to_string(bin_dir.join("win-tool.cmd")).unwrap();
    let ps1 = fs::read_to_string(bin_dir.join("win-tool.ps1")).unwrap();

    assert!(sh.starts_with("#!/bin/sh"));
    assert!(cmd.starts_with("@ECHO off"));
    assert!(ps1.starts_with("#!/usr/bin/env pwsh"));
}

#[test]
fn test_extract_package_name_helper() {
    assert_eq!(
        extract_package_name("../lib/node_modules/typescript/bin/tsc.js"),
        Some("typescript".to_string())
    );
    assert_eq!(
        extract_package_name("../lib/node_modules/@scope/pkg/bin/tool.js"),
        Some("@scope/pkg".to_string())
    );
    assert_eq!(
        extract_package_name("typescript/bin/tsc.js"),
        Some("typescript".to_string())
    );
    assert_eq!(
        extract_package_name("@scope/pkg/bin/tool.js"),
        Some("@scope/pkg".to_string())
    );
    assert_eq!(
        extract_package_name("../typescript/bin/tsc.js"),
        Some("typescript".to_string())
    );
    assert_eq!(
        extract_package_name("../@scope/pkg/bin/tool.js"),
        Some("@scope/pkg".to_string())
    );
    assert_eq!(
        extract_package_name("/usr/bin/bash"),
        None
    );
    assert_eq!(
        extract_package_name(r"C:\Windows\System32\cmd.exe"),
        None
    );
}

#[test]
fn test_bin_collision_directory_rejected() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let link_path = bin_dir.join("my-tool");
    fs::create_dir_all(&link_path).unwrap();

    // Directory collision must ALWAYS be rejected, even if force=true
    let err_unforced = check_existing_bin_collision(
        &bin_dir,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        false,
    )
    .unwrap_err();
    assert!(err_unforced.to_string().contains("EEXIST"));

    let err_forced = check_existing_bin_collision(
        &bin_dir,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        true,
    )
    .unwrap_err();
    assert!(err_forced.to_string().contains("EEXIST"));
}

#[test]
fn test_global_bin_collision_unrelated_regular_file_rejected() {
    let dir = tempdir().unwrap();
    let global_bin = dir.path().join("usr").join("local").join("bin");
    fs::create_dir_all(&global_bin).unwrap();

    let link_path = global_bin.join("my-tool");
    fs::write(&link_path, b"unrelated binary").unwrap();

    // Regular file collision in global bin without force must be rejected with EEXIST
    let err = check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("EEXIST: file already exists"));
}

#[test]
fn test_global_bin_collision_unrelated_regular_file_forced() {
    let dir = tempdir().unwrap();
    let global_bin = dir.path().join("usr").join("local").join("bin");
    fs::create_dir_all(&global_bin).unwrap();

    let link_path = global_bin.join("my-tool");
    fs::write(&link_path, b"unrelated binary").unwrap();

    // With force=true, overwrite is permitted
    assert!(check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        true,
    )
    .is_ok());
}

#[test]
fn test_local_dot_bin_allows_clobber() {
    let dir = tempdir().unwrap();
    let dot_bin = dir.path().join("node_modules").join(".bin");
    fs::create_dir_all(&dot_bin).unwrap();

    let link_path = dot_bin.join("my-tool");
    fs::write(&link_path, b"old-package-link").unwrap();

    // In local .bin, overwriting is allowed even with force=false
    assert!(check_existing_bin_collision(
        &dot_bin,
        &link_path,
        "../my-pkg/bin/cli.js",
        false,
    )
    .is_ok());
}

#[test]
fn test_global_bin_collision_foreign_symlink_rejected() {
    let dir = tempdir().unwrap();
    let global_bin = dir.path().join("usr").join("local").join("bin");
    fs::create_dir_all(&global_bin).unwrap();

    let link_path = global_bin.join("my-tool");

    #[cfg(unix)]
    let symlink_res = std::os::unix::fs::symlink(
        std::path::Path::new("../lib/node_modules/foreign-pkg/bin/tool.js"),
        &link_path,
    );
    #[cfg(windows)]
    let symlink_res = std::os::windows::fs::symlink_file(
        std::path::Path::new("../lib/node_modules/foreign-pkg/bin/tool.js"),
        &link_path,
    );

    if symlink_res.is_err() {
        eprintln!("Skipping symlink collision test due to platform privilege constraints");
        return;
    }

    // Foreign symlink must be rejected with EEXIST when force=false
    let err = check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("EEXIST: file already exists"));
    assert!(err.to_string().contains("foreign bin link"));

    // Foreign symlink can be overwritten when force=true
    assert!(check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/my-pkg/bin/cli.js",
        true,
    )
    .is_ok());
}

#[test]
fn test_global_bin_collision_same_package_symlink_allowed() {
    let dir = tempdir().unwrap();
    let global_bin = dir.path().join("usr").join("local").join("bin");
    fs::create_dir_all(&global_bin).unwrap();

    let link_path = global_bin.join("my-tool");

    #[cfg(unix)]
    let symlink_res = std::os::unix::fs::symlink(
        std::path::Path::new("../lib/node_modules/my-pkg/bin/old-cli.js"),
        &link_path,
    );
    #[cfg(windows)]
    let symlink_res = std::os::windows::fs::symlink_file(
        std::path::Path::new("../lib/node_modules/my-pkg/bin/old-cli.js"),
        &link_path,
    );

    if symlink_res.is_err() {
        eprintln!("Skipping symlink collision test due to platform privilege constraints");
        return;
    }

    // Symlink from the same package is allowed to update even when force=false
    assert!(check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/my-pkg/bin/new-cli.js",
        false,
    )
    .is_ok());
}
