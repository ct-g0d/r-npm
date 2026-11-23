use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn create_isolated_rnpm(dir: &Path) -> Command {
    let cache_dir = dir.join("cache");
    let prefix_dir = dir.join("prefix");
    let userconfig = dir.join(".npmrc");
    let globalconfig = dir.join("global.npmrc");
    let appdata = dir.join("appdata");
    let localappdata = dir.join("localappdata");
    let logs_dir = dir.join("logs");

    let _ = fs::create_dir_all(&cache_dir);
    let _ = fs::create_dir_all(&prefix_dir);
    let _ = fs::create_dir_all(&appdata);
    let _ = fs::create_dir_all(&localappdata);
    let _ = fs::create_dir_all(&logs_dir);

    if !userconfig.exists() {
        let _ = fs::write(&userconfig, "registry=http://127.0.0.1:4873\n");
    }
    if !globalconfig.exists() {
        let _ = fs::write(&globalconfig, "");
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rnpm"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .env("NPM_CONFIG_LOGS_DIR", &logs_dir)
        .env("npm_config_logs_dir", &logs_dir)
        .env("NPM_CONFIG_REGISTRY", "http://127.0.0.1:4873")
        .env("npm_config_registry", "http://127.0.0.1:4873")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
    cmd
}

fn create_isolated_npx(dir: &Path) -> Command {
    let cache_dir = dir.join("cache");
    let prefix_dir = dir.join("prefix");
    let userconfig = dir.join(".npmrc");
    let globalconfig = dir.join("global.npmrc");
    let appdata = dir.join("appdata");
    let localappdata = dir.join("localappdata");
    let logs_dir = dir.join("logs");

    let _ = fs::create_dir_all(&cache_dir);
    let _ = fs::create_dir_all(&prefix_dir);
    let _ = fs::create_dir_all(&appdata);
    let _ = fs::create_dir_all(&localappdata);
    let _ = fs::create_dir_all(&logs_dir);

    if !userconfig.exists() {
        let _ = fs::write(&userconfig, "registry=http://127.0.0.1:4873\n");
    }
    if !globalconfig.exists() {
        let _ = fs::write(&globalconfig, "");
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_npx"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("NPM_CONFIG_CACHE", &cache_dir)
        .env("npm_config_cache", &cache_dir)
        .env("CACHE", &cache_dir)
        .env("NPM_CONFIG_PREFIX", &prefix_dir)
        .env("PREFIX", &prefix_dir)
        .env("NPM_CONFIG_USERCONFIG", &userconfig)
        .env("USERCONFIG", &userconfig)
        .env("npm_config_userconfig", &userconfig)
        .env("NPM_CONFIG_GLOBALCONFIG", &globalconfig)
        .env("GLOBALCONFIG", &globalconfig)
        .env("npm_config_globalconfig", &globalconfig)
        .env("APPDATA", &appdata)
        .env("LOCALAPPDATA", &localappdata)
        .env("NPM_CONFIG_LOGS_DIR", &logs_dir)
        .env("npm_config_logs_dir", &logs_dir)
        .env("NPM_CONFIG_REGISTRY", "http://127.0.0.1:4873")
        .env("npm_config_registry", "http://127.0.0.1:4873")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
    cmd
}

// ============================================================================
// 1. CLI TORTURE: -- ARGUMENT FORWARDING IN RUN, EXEC, NPX
// ============================================================================

#[test]
fn test_cli_run_script_double_dash_forwarding() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "test-double-dash",
        "version": "1.0.0",
        "scripts": {
            "echo-args": "node -e \"console.log(process.argv.slice(1).join(' '))\" --"
        }
    }"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["run", "echo-args", "--", "--alpha", "beta", "--gamma=delta"])
        .output()
        .expect("Failed to execute rnpm run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--alpha beta --gamma=delta"),
        "stdout should contain forwarded args, got: {stdout}"
    );
}

#[test]
fn test_cli_exec_double_dash_forwarding() {
    let tmp = tempdir().unwrap();
    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args([
            "exec",
            "--",
            "node",
            "-e",
            "console.log('FORWARD_TEST:' + process.argv.slice(1).join(','))",
            "--",
            "arg1",
            "--flag2",
            "val3",
        ])
        .output()
        .expect("Failed to execute rnpm exec");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FORWARD_TEST:arg1,--flag2,val3"),
        "stdout should forward args, got: {stdout}"
    );
}

#[test]
fn test_cli_npx_double_dash_forwarding() {
    let tmp = tempdir().unwrap();
    let mut cmd = create_isolated_npx(tmp.path());
    let output = cmd
        .args([
            "--",
            "node",
            "-e",
            "console.log('NPX_OK:' + process.argv.slice(1).join(' '))",
            "--",
            "--foo",
            "bar",
        ])
        .output()
        .expect("Failed to execute npx");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NPX_OK:--foo bar"),
        "stdout should contain forwarded flags, got: {stdout}"
    );
}

// ============================================================================
// 2. CLI TORTURE: --NO-* NEGATION FLAGS
// ============================================================================

#[test]
fn test_cli_no_audit_and_no_fund_flags() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "test-no-flags",
        "version": "1.0.0"
    }"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["install", "--no-audit", "--no-fund", "--offline"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("looking for funding"),
        "funding message should be suppressed by --no-fund"
    );
    assert!(
        !stdout.contains("vulnerabilities"),
        "vulnerability check should be omitted by --no-audit"
    );
}

#[test]
fn test_cli_no_package_lock_flag() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "test-no-lock",
        "version": "1.0.0"
    }"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();

    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["install", "--no-package-lock", "--offline"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !tmp.path().join("package-lock.json").exists(),
        "package-lock.json must not be created when --no-package-lock is given"
    );
}

#[test]
fn test_cli_no_save_flag() {
    let tmp = tempdir().unwrap();
    let initial_pkg = r#"{
  "name": "test-no-save",
  "version": "1.0.0"
}
"#;
    fs::write(tmp.path().join("package.json"), initial_pkg).unwrap();

    // Create a local dependency package
    let local_dep = tmp.path().join("local-dep");
    fs::create_dir_all(&local_dep).unwrap();
    fs::write(
        local_dep.join("package.json"),
        r#"{"name": "local-dep", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["install", "./local-dep", "--no-save", "--offline"])
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after_content = fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(
        initial_pkg, after_content,
        "package.json must not be mutated when --no-save is provided"
    );
}

// ============================================================================
// 3. CLI TORTURE: NPM_CONFIG_* CASE-SENSITIVITY AND ENV PRECEDENCE
// ============================================================================

#[test]
fn test_cli_npm_config_precedence_and_case() {
    let tmp = tempdir().unwrap();
    let userconfig = tmp.path().join(".npmrc");
    fs::write(&userconfig, "fund=false\naudit=false\n").unwrap();

    // 1. Env variable overrides .npmrc
    let mut cmd = create_isolated_rnpm(tmp.path());
    cmd.env("NPM_CONFIG_FUND", "true");
    cmd.args(["config", "get", "fund"]);
    let out = cmd.output().expect("Failed to run config get fund");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        "true",
        "NPM_CONFIG_FUND environment variable must override .npmrc"
    );

    // 2. Lowercase env variable npm_config_* is also respected
    let mut cmd_lower = create_isolated_rnpm(tmp.path());
    cmd_lower.env("npm_config_fund", "true");
    cmd_lower.args(["config", "get", "fund"]);
    let out_lower = cmd_lower
        .output()
        .expect("Failed to run config get fund with lowercase env");
    assert!(out_lower.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out_lower.stdout).trim(),
        "true",
        "Lowercase npm_config_fund must be recognized"
    );
}

// ============================================================================
// 4. CLI TORTURE: RNPM PACK --DRY-RUN --JSON
// ============================================================================

#[test]
fn test_cli_pack_dry_run_json() {
    let tmp = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "pack-dry-run-test",
        "version": "2.4.6",
        "description": "Testing pack dry run",
        "main": "index.js",
        "files": ["index.js", "lib/"]
    }"#;
    fs::write(tmp.path().join("package.json"), pkg_json).unwrap();
    fs::write(tmp.path().join("index.js"), "console.log('hello');").unwrap();
    fs::create_dir_all(tmp.path().join("lib")).unwrap();
    fs::write(tmp.path().join("lib").join("util.js"), "module.exports = 1;").unwrap();

    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["pack", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute rnpm pack");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Failed to parse pack --json stdout: {e}\nStdout was:\n{stdout}"));

    assert!(parsed.is_array(), "pack --json must emit a JSON array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let item = &arr[0];
    assert_eq!(item["name"], "pack-dry-run-test");
    assert_eq!(item["version"], "2.4.6");
    assert_eq!(item["id"], "pack-dry-run-test@2.4.6");
    assert!(item["filename"].as_str().unwrap().contains("pack-dry-run-test-2.4.6.tgz"));
    assert!(item["size"].is_number());
    assert!(item["unpackedSize"].is_number());
    assert!(item["entryCount"].as_u64().unwrap() >= 2);

    // Verify dry-run did NOT create the tarball file on disk
    let expected_tarball = tmp.path().join("pack-dry-run-test-2.4.6.tgz");
    assert!(
        !expected_tarball.exists(),
        "Dry run pack must not write tarball to disk"
    );
}

// ============================================================================
// 5. CLI TORTURE: RNPM CONFIG LIST --JSON
// ============================================================================

#[test]
fn test_cli_config_list_json() {
    let tmp = tempdir().unwrap();
    let mut cmd = create_isolated_rnpm(tmp.path());
    let output = cmd
        .args(["config", "list", "--json"])
        .output()
        .expect("Failed to execute rnpm config list --json");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("Failed to parse config list --json: {e}\nStdout:\n{stdout}")
    });

    assert!(parsed.is_object(), "config list --json must return an object");
    assert!(
        parsed.get("cache").is_some() || parsed.get("prefix").is_some(),
        "config list --json should report configuration fields"
    );
}

// ============================================================================
// 6. CLI TORTURE: RNPM HELP / COMPLETION / UNKNOWN COMMANDS
// ============================================================================

#[test]
fn test_cli_help_and_completion_and_unknown() {
    let tmp = tempdir().unwrap();

    // 1. Help command succeeds
    let mut cmd_help = create_isolated_rnpm(tmp.path());
    let out_help = cmd_help.arg("help").output().expect("rnpm help failed");
    assert!(out_help.status.success());
    let help_stdout = String::from_utf8_lossy(&out_help.stdout);
    assert!(help_stdout.contains("npm <command>"));

    // 2. Completion command succeeds with MSYSTEM/Git bash or powershell argument
    let mut cmd_comp = create_isolated_rnpm(tmp.path());
    cmd_comp.env("MSYSTEM", "MINGW64");
    let out_comp = cmd_comp
        .arg("completion")
        .output()
        .expect("rnpm completion failed");
    assert!(out_comp.status.success());
    let comp_stdout = String::from_utf8_lossy(&out_comp.stdout);
    assert!(
        comp_stdout.contains("complete -F")
            || comp_stdout.contains("COMP_WORDS")
            || comp_stdout.contains("npm completion"),
        "Completion output should contain bash/sh completion logic"
    );

    // 3. Unknown command returns non-zero exit code (exit code 1 or 2)
    let mut cmd_unknown = create_isolated_rnpm(tmp.path());
    let out_unknown = cmd_unknown
        .arg("nonexistent-command-xyz-987")
        .output()
        .expect("rnpm unknown cmd execution failed");
    assert!(
        !out_unknown.status.success(),
        "Unknown command must exit with non-zero status"
    );
}

// ============================================================================
// 7. CLI TORTURE: NPX -Y VS --NO NON-TTY CONSENT
// ============================================================================

#[test]
fn test_cli_npx_consent_modes() {
    let tmp = tempdir().unwrap();

    // 1. --no-yes or --yes=false cancels missing package with exit code 1
    let mut cmd_no = create_isolated_rnpm(tmp.path());
    let out_no = cmd_no
        .args(["exec", "--yes=false", "--", "missing-remote-pkg-9999"])
        .output()
        .expect("exec --yes=false failed");
    assert_eq!(out_no.status.code(), Some(1));
    let stderr_no = String::from_utf8_lossy(&out_no.stderr);
    assert!(
        stderr_no.contains("npx canceled due to missing packages and no YES option"),
        "stderr: {stderr_no}"
    );

    // 2. -y with local executable succeeds
    let mut cmd_yes = create_isolated_rnpm(tmp.path());
    let out_yes = cmd_yes
        .args(["exec", "-y", "--", "node", "-e", "console.log('CONSENT_PASSED')"])
        .output()
        .expect("exec -y failed");
    assert!(out_yes.status.success());
    let stdout_yes = String::from_utf8_lossy(&out_yes.stdout);
    assert!(stdout_yes.contains("CONSENT_PASSED"));
}

// ============================================================================
// 8. SEMVER EXTREME STRESS & TORTURE
// ============================================================================

#[test]
fn test_semver_complex_or_unions() {
    // Empty parts in || union match wildcard (>=0.0.0)
    let r1 = Range::parse("1.2.3 ||").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("5.0.0").unwrap()));

    let r2 = Range::parse("|| 1.2.3").unwrap();
    assert!(r2.satisfies(&Version::parse("5.0.0").unwrap()));

    let r3 = Range::parse("||").unwrap();
    assert!(r3.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r3.satisfies(&Version::parse("99.99.99").unwrap()));

    let r4 = Range::parse("1.0.0 || 2.0.0 ||").unwrap();
    assert!(r4.satisfies(&Version::parse("3.0.0").unwrap()));

    // Prerelease unions
    let r_pre = Range::parse("1.0.0-alpha || 2.0.0-beta").unwrap();
    assert!(r_pre.satisfies(&Version::parse("1.0.0-alpha").unwrap()));
    assert!(r_pre.satisfies(&Version::parse("2.0.0-beta").unwrap()));
    assert!(!r_pre.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(!r_pre.satisfies(&Version::parse("1.0.0-rc").unwrap()));

    // Huge || chain (1000 sets) without quadratic blowup or stack overflow
    let large_chain = (0..1000)
        .map(|i| format!("1.0.{i}"))
        .collect::<Vec<_>>()
        .join(" || ");
    let r_large = Range::parse(&large_chain).unwrap();
    assert!(r_large.satisfies(&Version::parse("1.0.500").unwrap()));
    assert!(!r_large.satisfies(&Version::parse("2.0.0").unwrap()));
}

#[test]
fn test_semver_hyphen_ranges() {
    // Exact hyphen range: 1.2.3 - 2.3.4 -> >=1.2.3 <=2.3.4
    let r1 = Range::parse("1.2.3 - 2.3.4").unwrap();
    assert!(r1.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r1.satisfies(&Version::parse("2.0.0").unwrap()));
    assert!(r1.satisfies(&Version::parse("2.3.4").unwrap()));
    assert!(!r1.satisfies(&Version::parse("2.3.5").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.2.2").unwrap()));

    // Partial right side: 1.2 - 2 -> >=1.2.0 <3.0.0-0
    let r2 = Range::parse("1.2 - 2").unwrap();
    assert!(r2.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("2.9.9").unwrap()));
    assert!(!r2.satisfies(&Version::parse("3.0.0").unwrap()));

    // 1 - 2 -> >=1.0.0 <3.0.0-0
    let r3 = Range::parse("1 - 2").unwrap();
    assert!(r3.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r3.satisfies(&Version::parse("2.99.99").unwrap()));
    assert!(!r3.satisfies(&Version::parse("3.0.0").unwrap()));

    // 1.2.3 - 2.3 -> >=1.2.3 <2.4.0-0
    let r4 = Range::parse("1.2.3 - 2.3").unwrap();
    assert!(r4.satisfies(&Version::parse("2.3.99").unwrap()));
    assert!(!r4.satisfies(&Version::parse("2.4.0").unwrap()));

    // Wildcards in hyphen range
    let r5 = Range::parse("1.2.3 - *").unwrap();
    assert!(r5.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(r5.satisfies(&Version::parse("99.0.0").unwrap()));
    assert!(!r5.satisfies(&Version::parse("1.2.2").unwrap()));

    let r6 = Range::parse("* - 1.2.3").unwrap();
    assert!(r6.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r6.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(!r6.satisfies(&Version::parse("1.2.4").unwrap()));

    // Hyphen range with prereleases
    let r7 = Range::parse("1.2.3-alpha - 2.3.4-beta").unwrap();
    assert!(r7.satisfies(&Version::parse("1.2.3-alpha").unwrap()));
    assert!(r7.satisfies(&Version::parse("2.3.4-beta").unwrap()));
}

#[test]
fn test_semver_wildcard_ranges() {
    let r_star = Range::parse("*").unwrap();
    assert!(r_star.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(r_star.satisfies(&Version::parse("10.20.30").unwrap()));

    let r_empty = Range::parse("").unwrap();
    assert!(r_empty.satisfies(&Version::parse("1.0.0").unwrap()));

    let r_x = Range::parse("1.x").unwrap();
    assert!(r_x.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r_x.satisfies(&Version::parse("1.99.99").unwrap()));
    assert!(!r_x.satisfies(&Version::parse("2.0.0").unwrap()));

    let r_x_cap = Range::parse("1.X").unwrap();
    assert!(r_x_cap.satisfies(&Version::parse("1.5.0").unwrap()));

    let r_patch_wildcard = Range::parse("1.2.*").unwrap();
    assert!(r_patch_wildcard.satisfies(&Version::parse("1.2.0").unwrap()));
    assert!(r_patch_wildcard.satisfies(&Version::parse("1.2.99").unwrap()));
    assert!(!r_patch_wildcard.satisfies(&Version::parse("1.3.0").unwrap()));

    // > * and < * are impossible ranges (<0.0.0-0)
    let r_gt_star = Range::parse("> *").unwrap();
    assert!(!r_gt_star.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(!r_gt_star.satisfies(&Version::parse("1.0.0").unwrap()));

    let r_lt_star = Range::parse("< *").unwrap();
    assert!(!r_lt_star.satisfies(&Version::parse("0.0.0").unwrap()));
    assert!(!r_lt_star.satisfies(&Version::parse("1.0.0").unwrap()));

    // >= * and <= * are valid wildcards
    let r_gte_star = Range::parse(">= *").unwrap();
    assert!(r_gte_star.satisfies(&Version::parse("1.0.0").unwrap()));
    let r_lte_star = Range::parse("<= *").unwrap();
    assert!(r_lte_star.satisfies(&Version::parse("1.0.0").unwrap()));
}

#[test]
fn test_semver_caret_tilde_edge_cases() {
    // Caret on 0.0.x
    let c1 = Range::parse("^0.0.x").unwrap();
    assert!(c1.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(c1.satisfies(&Version::parse("0.0.99").unwrap()));
    assert!(!c1.satisfies(&Version::parse("0.1.0").unwrap()));

    let c2 = Range::parse("^0.0.1").unwrap();
    assert!(c2.satisfies(&Version::parse("0.0.1").unwrap()));
    assert!(!c2.satisfies(&Version::parse("0.0.2").unwrap()));

    // Caret on 0.x
    let c3 = Range::parse("^0.x").unwrap();
    assert!(c3.satisfies(&Version::parse("0.1.2").unwrap()));
    assert!(c3.satisfies(&Version::parse("0.99.99").unwrap()));
    assert!(!c3.satisfies(&Version::parse("1.0.0").unwrap()));

    let c4 = Range::parse("^0.1.2").unwrap();
    assert!(c4.satisfies(&Version::parse("0.1.2").unwrap()));
    assert!(c4.satisfies(&Version::parse("0.1.9").unwrap()));
    assert!(!c4.satisfies(&Version::parse("0.2.0").unwrap()));

    // Tilde on 0.0.x
    let t1 = Range::parse("~0.0.x").unwrap();
    assert!(t1.satisfies(&Version::parse("0.0.5").unwrap()));
    assert!(!t1.satisfies(&Version::parse("0.1.0").unwrap()));

    let t2 = Range::parse("~0.x").unwrap();
    assert!(t2.satisfies(&Version::parse("0.5.0").unwrap()));
    assert!(!t2.satisfies(&Version::parse("1.0.0").unwrap()));

    let t3 = Range::parse("~1.2.3").unwrap();
    assert!(t3.satisfies(&Version::parse("1.2.3").unwrap()));
    assert!(t3.satisfies(&Version::parse("1.2.99").unwrap()));
    assert!(!t3.satisfies(&Version::parse("1.3.0").unwrap()));
}

#[test]
fn test_semver_prerelease_rules() {
    // Prerelease version satisfies comparator only if that comparator explicitly references the same tuple
    let r1 = Range::parse(">=1.0.0-alpha <2.0.0").unwrap();
    assert!(r1.satisfies(&Version::parse("1.0.0-alpha").unwrap()));
    assert!(r1.satisfies(&Version::parse("1.0.0-beta").unwrap()));
    assert!(!r1.satisfies(&Version::parse("1.2.0-beta").unwrap()));

    // ^1.0.0 excludes 1.2.0-beta and 2.0.0-alpha
    let r2 = Range::parse("^1.0.0").unwrap();
    assert!(!r2.satisfies(&Version::parse("1.2.0-beta").unwrap()));
    assert!(!r2.satisfies(&Version::parse("2.0.0-alpha").unwrap()));
    assert!(r2.satisfies(&Version::parse("1.0.0").unwrap()));
    assert!(r2.satisfies(&Version::parse("1.5.0").unwrap()));
}

#[test]
fn test_semver_build_metadata() {
    let v1 = Version::parse("1.2.3+build.123").unwrap();
    assert_eq!(v1.build, vec!["build".to_string(), "123".to_string()]);

    let v2 = Version::parse("1.2.3+other.build").unwrap();
    assert_eq!(v1, v2, "Build metadata must be ignored in version equality");

    // Empty build metadata is invalid
    assert!(Version::parse("1.2.3+").is_err());
    assert!(Version::parse("1.2.3+.").is_err());
    assert!(Version::parse("1.2.3+foo..bar").is_err());

    // Invalid character in build metadata
    assert!(Version::parse("1.2.3+build#1").is_err());
}

#[test]
fn test_semver_leading_zeroes_and_prefixes() {
    // Leading v, =, =v are allowed
    assert!(Version::parse("=1.2.3").is_ok());
    assert!(Version::parse("v1.2.3").is_ok());
    assert!(Version::parse("=v1.2.3").is_ok());
    assert!(Version::parse("  v1.2.3  ").is_ok());

    // Multiple duplicate prefixes are rejected
    assert!(Version::parse("==1.2.3").is_err());
    assert!(Version::parse("vv1.2.3").is_err());

    // Leading zeroes in numeric segments are forbidden by SemVer 2.0.0
    assert!(Version::parse("01.2.3").is_err());
    assert!(Version::parse("1.02.3").is_err());
    assert!(Version::parse("1.2.03").is_err());
    assert!(Range::parse("^01.2.3").is_err());

    // Numeric prereleases with leading zeroes are forbidden
    assert!(Version::parse("1.0.0-01").is_err());
    assert!(Range::parse("1.0.0-01").is_err());

    // Prerelease on partial version is an invalid range
    assert!(Range::parse("1.2-alpha").is_err());
    assert!(Range::parse("^1.2-alpha").is_err());
    assert!(Range::parse("~1.x-alpha").is_err());
}

#[test]
fn test_semver_malformed_and_oversized_no_panic() {
    // Malformed inputs return Err without panic
    assert!(Range::parse(">>> 1.2.3").is_err());
    assert!(Range::parse("not-a-range").is_err());
    assert!(Range::parse("^").is_err());
    assert!(Range::parse("~").is_err());
    assert!(Range::parse(">").is_err());
    assert!(Range::parse("v").is_err());

    // Numeric overflow
    assert!(Range::parse("999999999999999999999999999999999999999999").is_err());

    // Oversized range (100KB) rejected without blowup
    let huge_str = "1.0.0 || ".repeat(15000);
    assert!(Range::parse(&huge_str).is_err());
}

// ============================================================================
// 9. MANIFEST EXTREME STRESS & TORTURE
// ============================================================================

#[test]
fn test_manifest_utf8_bom_handling() {
    let json_raw = "{\n  \"name\": \"bom-pkg\",\n  \"version\": \"1.0.0\"\n}\n";
    let bom_str = format!("\u{feff}{json_raw}");
    let manifest = Manifest::from_str(&bom_str).unwrap();
    assert_eq!(manifest.name.as_deref(), Some("bom-pkg"));
    assert!(manifest.format.has_bom);

    // Byte slice with 0xEF 0xBB 0xBF
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(json_raw.as_bytes());
    let manifest_bytes = Manifest::from_slice(&bom_bytes).unwrap();
    assert_eq!(manifest_bytes.name.as_deref(), Some("bom-pkg"));
}

#[test]
fn test_manifest_bin_sanitization_and_path_traversal() {
    let manifest_json = r#"{
        "name": "malicious-bin-test",
        "version": "1.0.0",
        "bin": {
            "../evil": "./cli.js",
            "passwd": "../../../../etc/passwd",
            "/bin/sh": "/bin/sh",
            "": "empty.js",
            ".": "dot.js",
            "..": "dotdot.js"
        }
    }"#;
    let manifest = Manifest::from_str(manifest_json).unwrap();
    let entries = manifest.bin_entries();

    // Verify bin keys are stripped of path traversals to basename
    let evil_entry = entries.iter().find(|(k, _)| k == "evil");
    assert!(evil_entry.is_some(), "Key '../evil' should normalize to 'evil'");
    assert_eq!(evil_entry.unwrap().1, "./cli.js");

    // Verify bin targets are cleansed of traversal escapes
    let passwd_entry = entries.iter().find(|(k, _)| k == "passwd");
    assert!(passwd_entry.is_some());
    assert_eq!(passwd_entry.unwrap().1, "etc/passwd");

    // Absolute script path is stripped of leading slash
    let sh_entry = entries.iter().find(|(k, _)| k == "sh");
    assert!(sh_entry.is_some());
    assert_eq!(sh_entry.unwrap().1, "bin/sh");

    // Empty keys or '.'/'..' are discarded
    assert!(!entries.iter().any(|(k, _)| k.is_empty() || k == "." || k == ".."));
}

#[test]
fn test_manifest_single_bin_with_and_without_name() {
    // Single bin with package name
    let named_json = r#"{
        "name": "@scope/cli-tool",
        "bin": "./bin/run.js"
    }"#;
    let manifest_named = Manifest::from_str(named_json).unwrap();
    assert_eq!(
        manifest_named.bin_entries(),
        vec![("cli-tool".to_string(), "./bin/run.js".to_string())]
    );

    // Single bin without package name is dropped per npm-normalize-package-bin
    let unnamed_json = r#"{
        "bin": "./bin/run.js"
    }"#;
    let manifest_unnamed = Manifest::from_str(unnamed_json).unwrap();
    assert!(
        manifest_unnamed.bin_entries().is_empty(),
        "Single bin string without package name must be discarded"
    );
}

#[test]
fn test_manifest_bin_array_support() {
    let arr_json = r#"{
        "name": "array-bin-pkg",
        "bin": ["bin/my-tool.js", "../other/helper.js"]
    }"#;
    let manifest = Manifest::from_str(arr_json).unwrap();
    let entries = manifest.bin_entries();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, "helper.js");
    assert_eq!(entries[0].1, "other/helper.js");
    assert_eq!(entries[1].0, "my-tool.js");
    assert_eq!(entries[1].1, "bin/my-tool.js");
}

#[test]
fn test_manifest_bundled_dependencies_boolean_array_object() {
    // Boolean true -> bundles all dependencies
    let json_bool_true = r#"{
        "name": "bundle-true",
        "dependencies": {
            "dep-a": "1.0.0",
            "dep-b": "2.0.0"
        },
        "bundleDependencies": true
    }"#;
    let m1 = Manifest::from_str(json_bool_true).unwrap();
    let mut b1 = m1.bundled_package_names();
    b1.sort();
    assert_eq!(b1, vec!["dep-a", "dep-b"]);

    // Boolean false
    let json_bool_false = r#"{
        "name": "bundle-false",
        "dependencies": { "dep-a": "1.0.0" },
        "bundleDependencies": false
    }"#;
    let m2 = Manifest::from_str(json_bool_false).unwrap();
    assert!(m2.bundled_package_names().is_empty());

    // Array of names
    let json_array = r#"{
        "name": "bundle-array",
        "bundledDependencies": ["dep-x", "dep-y"]
    }"#;
    let m3 = Manifest::from_str(json_array).unwrap();
    assert_eq!(m3.bundled_package_names(), vec!["dep-x", "dep-y"]);

    // Object of names (auto-translated to list of keys per npm)
    let json_obj = r#"{
        "name": "bundle-obj",
        "bundleDependencies": {
            "dep-one": true,
            "dep-two": false
        }
    }"#;
    let m4 = Manifest::from_str(json_obj).unwrap();
    let mut b4 = m4.bundled_package_names();
    b4.sort();
    assert_eq!(b4, vec!["dep-one", "dep-two"]);
}

#[test]
fn test_manifest_os_cpu_libc_negations() {
    let json = r#"{
        "name": "platform-pkg",
        "os": ["!win32", "darwin"],
        "cpu": "!arm64",
        "libc": ["glibc"]
    }"#;
    let manifest = Manifest::from_str(json).unwrap();
    assert_eq!(
        manifest.os.as_deref().unwrap(),
        &["!win32".to_string(), "darwin".to_string()]
    );
    assert_eq!(manifest.cpu.as_deref().unwrap(), &["!arm64".to_string()]);
    assert_eq!(manifest.libc.as_deref().unwrap(), &["glibc".to_string()]);
}

#[test]
fn test_manifest_invalid_json_trailing_garbage_non_utf8() {
    // Trailing non-whitespace garbage
    let trailing_garbage = r#"{"name": "valid"} extra_garbage"#;
    assert!(Manifest::from_str(trailing_garbage).is_err());

    // Incomplete JSON
    assert!(Manifest::from_str(r#"{"name": "unclosed""#).is_err());

    // Non-UTF8 byte sequence
    let invalid_utf8_bytes = [0x7B, 0x22, 0x6E, 0x61, 0x6D, 0x65, 0x22, 0x3A, 0xFF, 0x7D];
    assert!(Manifest::from_slice(&invalid_utf8_bytes).is_err());
}
