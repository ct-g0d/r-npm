use rnpm_shim::{
    create_shims, create_shims_with_force, escape_cmd_arg, escape_cmd_path, escape_posix_arg,
    escape_posix_path, escape_ps1_arg, escape_ps1_path, normalize_shebang,
    parse_shim_target_and_pkg,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_special_characters_in_shim_targets() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    // Target containing spaces, parentheses, &, %, ', ;, $, #, and Unicode
    let target = "my pkg (v1) & test%20 'quotes' ; semi $dollar #hash 中文_🚀/bin/cli.js";
    let bin_name = "special-tool";

    create_shims(&bin_dir, bin_name, target).unwrap();

    #[cfg(not(unix))]
    {
        let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
        let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));
        let sh_path = bin_dir.join(bin_name);

        assert!(cmd_path.exists());
        assert!(ps1_path.exists());
        assert!(sh_path.exists());

        // Read .cmd content and verify % is escaped to %%
        let cmd_content = fs::read_to_string(&cmd_path).unwrap();
        assert!(cmd_content.contains("%%20"), "Cmd shim must escape % to %%");

        // Parse target back from .cmd
        let (parsed_cmd_target, _) = parse_shim_target_and_pkg(&cmd_content).expect("Failed to parse .cmd shim");
        assert!(
            parsed_cmd_target.contains("my pkg (v1) & test%20 'quotes' ; semi $dollar #hash 中文_🚀"),
            "Parsed .cmd target mismatch: {parsed_cmd_target}"
        );

        // Parse target back from .ps1
        let ps1_content = fs::read_to_string(&ps1_path).unwrap();
        let (parsed_ps1_target, _) = parse_shim_target_and_pkg(&ps1_content).expect("Failed to parse .ps1 shim");
        assert!(
            parsed_ps1_target.contains("my pkg (v1) & test%20 'quotes' ; semi $dollar #hash 中文_🚀"),
            "Parsed .ps1 target mismatch: {parsed_ps1_target}"
        );

        // Parse target back from .sh
        let sh_content = fs::read_to_string(&sh_path).unwrap();
        let (parsed_sh_target, _) = parse_shim_target_and_pkg(&sh_content).expect("Failed to parse .sh shim");
        assert!(
            parsed_sh_target.contains("my pkg (v1) & test%20 'quotes' ; semi $dollar #hash 中文_🚀"),
            "Parsed .sh target mismatch: {parsed_sh_target}"
        );
    }

    #[cfg(unix)]
    {
        let sh_path = bin_dir.join(bin_name);
        assert!(sh_path.exists());
    }
}

#[test]
fn test_overwrite_readonly_shims() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let bin_name = "readonly-cli";
    let target1 = "pkg1/bin/cli.js";
    let target2 = "pkg1/bin/cli-v2.js";

    // 1. First creation
    create_shims(&bin_dir, bin_name, target1).unwrap();

    // 2. Mark existing shims as read-only
    #[cfg(not(unix))]
    {
        let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
        let ps1_path = bin_dir.join(format!("{bin_name}.ps1"));
        let sh_path = bin_dir.join(bin_name);

        for path in [&cmd_path, &ps1_path, &sh_path] {
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_readonly(true);
            fs::set_permissions(path, perms).unwrap();
        }
    }
    #[cfg(unix)]
    {
        let sh_path = bin_dir.join(bin_name);
        let mut perms = fs::metadata(&sh_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&sh_path, perms).unwrap();
    }

    // 3. Overwrite with target2 with force
    create_shims_with_force(&bin_dir, bin_name, target2, true).unwrap();

    #[cfg(not(unix))]
    {
        let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));
        let content = fs::read_to_string(cmd_path).unwrap();
        assert!(content.contains("cli-v2.js"));
    }
}

#[test]
#[cfg(windows)]
fn test_overwrite_existing_reparse_point_or_junction() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let dummy_target = dir.path().join("dummy_target");
    fs::create_dir_all(&dummy_target).unwrap();

    let bin_name = "junction-clobber";
    let cmd_path = bin_dir.join(format!("{bin_name}.cmd"));

    // Create a directory junction where the .cmd file should be
    rnpm_fs::create_junction(&cmd_path, &dummy_target).unwrap();
    assert!(rnpm_fs::is_junction(&cmd_path).unwrap());

    // create_shims should safely detect directory reparse point, remove junction, and write file
    create_shims_with_force(&bin_dir, bin_name, "foo/cli.js", true).unwrap();
    assert!(cmd_path.is_file());
    assert!(!rnpm_fs::is_junction(&cmd_path).unwrap());
    assert!(dummy_target.exists(), "Target directory must remain untouched!");
}

#[test]
fn test_argument_escaping_extreme_cases() {
    // 1. Win32 cmd escaping
    assert_eq!(escape_cmd_arg(""), "\"\"");
    assert_eq!(escape_cmd_arg("simple"), "simple");
    assert_eq!(escape_cmd_arg("hello world"), "\"hello world\"");
    assert_eq!(escape_cmd_arg("foo&bar"), "\"foo&bar\"");
    assert_eq!(escape_cmd_arg("%VAR%"), "\"%%VAR%%\"");
    assert_eq!(
        escape_cmd_arg(r#"C:\path with spaces\"#),
        r#""C:\path with spaces\\""#
    );
    assert_eq!(
        escape_cmd_arg(r#"quote "inside""#),
        r#""quote \"inside\"""#
    );

    // 2. POSIX shell escaping
    assert_eq!(escape_posix_arg(""), "''");
    assert_eq!(escape_posix_arg("simple_123"), "simple_123");
    assert_eq!(escape_posix_arg("hello world"), "'hello world'");
    assert_eq!(escape_posix_arg("don't"), r"'don'\''t'");
    assert_eq!(escape_posix_arg("$HOME"), "'$HOME'");

    // 3. PowerShell escaping
    assert_eq!(escape_ps1_arg(""), "''");
    assert_eq!(escape_ps1_arg("simple"), "simple");
    assert_eq!(escape_ps1_arg("hello world"), "'hello world'");
    assert_eq!(escape_ps1_arg("it's cool"), "'it''s cool'");

    // 4. Path escaping
    assert_eq!(escape_cmd_path("foo/bar%20/baz"), "foo\\bar%%20\\baz");
    assert_eq!(
        escape_posix_path("foo\\bar\"quote\"$var`sub`"),
        "foo/bar\\\"quote\\\"\\$var\\`sub\\`"
    );
    assert_eq!(
        escape_ps1_path("foo\\bar\"quote\"$var`sub`"),
        "foo/bar`\"quote`\"`$var``sub``"
    );
}

#[test]
fn test_normalize_shebang_extreme() {
    let dir = tempdir().unwrap();
    let script = dir.path().join("script.js");

    // Script with UTF-8 BOM + CRLF shebang
    let content = b"\xEF\xBB\xBF#!/usr/bin/env node\r\nconsole.log('hello');\r\n";
    fs::write(&script, content).unwrap();

    // Mark as read-only
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&script, perms).unwrap();

    normalize_shebang(&script).unwrap();

    let updated = fs::read(&script).unwrap();
    assert!(updated.starts_with(b"\xEF\xBB\xBF#!/usr/bin/env node\n"));
    assert!(!updated.starts_with(b"\xEF\xBB\xBF#!/usr/bin/env node\r\n"));
    assert!(updated.ends_with(b"console.log('hello');\r\n"));
}

#[test]
fn test_parse_shim_target_and_pkg_scoped() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let target = "@my-org/my-pkg/bin/run.js";
    create_shims(&bin_dir, "my-pkg-cli", target).unwrap();

    #[cfg(not(unix))]
    {
        let cmd_path = bin_dir.join("my-pkg-cli.cmd");
        let content = fs::read_to_string(cmd_path).unwrap();
        let (parsed_target, parsed_pkg) = parse_shim_target_and_pkg(&content).unwrap();
        assert!(parsed_target.contains("@my-org/my-pkg/bin/run.js"));
        assert_eq!(parsed_pkg.as_deref(), Some("@my-org/my-pkg"));
    }
}

#[test]
fn test_bin_collision_detection() {
    let dir = tempdir().unwrap();
    let global_bin = dir.path().join("bin");
    fs::create_dir_all(&global_bin).unwrap();

    let link_path = global_bin.join("my-cmd");

    // 1. Existing regular directory should ALWAYS fail collision check even with force
    fs::create_dir_all(&link_path).unwrap();
    let res = rnpm_shim::check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/pkgA/cli.js",
        true,
    );
    assert!(res.is_err(), "Must refuse to overwrite a directory");
    fs::remove_dir(&link_path).unwrap();

    // 2. Existing shim pointing to pkgA: collision check allows same package without force
    fs::write(
        &link_path,
        r#"@ECHO off
"%dp0%\..\lib\node_modules\pkgA\cli.js" %*
"#,
    )
    .unwrap();

    let res_same = rnpm_shim::check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/pkgA/cli.js",
        false,
    );
    assert!(res_same.is_ok(), "Must allow overwrite from same package");

    // 3. Collision check refuses foreign package pkgB without force
    let res_foreign = rnpm_shim::check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/pkgB/cli.js",
        false,
    );
    assert!(
        res_foreign.is_err(),
        "Must refuse foreign package overwrite without force"
    );

    // 4. Force allows foreign package overwrite
    let res_force = rnpm_shim::check_existing_bin_collision(
        &global_bin,
        &link_path,
        "../lib/node_modules/pkgB/cli.js",
        true,
    );
    assert!(res_force.is_ok(), "Must allow foreign package overwrite with force");
}

#[test]
fn test_direct_shims_generation() {
    let (sh, cmd, ps1) = rnpm_shim::generate_direct_shims("my-pkg/bin/tool");
    assert!(sh.contains("\"$basedir/../my-pkg/bin/tool\""));
    assert!(cmd.contains("%dp0%\\..\\my-pkg\\bin\\tool"));
    assert!(ps1.contains("\"$basedir/../my-pkg/bin/tool\""));
}
