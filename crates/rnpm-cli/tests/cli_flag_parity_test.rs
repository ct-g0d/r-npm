use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn setup_base_fixture(dir: &std::path::Path) {
    let pkgs_dir = dir.join("packages");
    fs::create_dir_all(&pkgs_dir).unwrap();

    // pkg-prod
    let pkg_prod_dir = pkgs_dir.join("pkg-prod");
    fs::create_dir_all(&pkg_prod_dir).unwrap();
    fs::write(
        pkg_prod_dir.join("package.json"),
        r#"{"name": "pkg-prod", "version": "1.0.0", "main": "index.js"}"#,
    )
    .unwrap();
    fs::write(
        pkg_prod_dir.join("index.js"),
        "module.exports = 'pkg-prod';",
    )
    .unwrap();

    // pkg-dev
    let pkg_dev_dir = pkgs_dir.join("pkg-dev");
    fs::create_dir_all(&pkg_dev_dir).unwrap();
    fs::write(
        pkg_dev_dir.join("package.json"),
        r#"{"name": "pkg-dev", "version": "1.0.0", "main": "index.js"}"#,
    )
    .unwrap();
    fs::write(pkg_dev_dir.join("index.js"), "module.exports = 'pkg-dev';").unwrap();

    // pkg-opt (darwin + arm64 only)
    let pkg_opt_dir = pkgs_dir.join("pkg-opt");
    fs::create_dir_all(&pkg_opt_dir).unwrap();
    fs::write(
        pkg_opt_dir.join("package.json"),
        r#"{"name": "pkg-opt", "version": "1.0.0", "main": "index.js", "os": ["darwin"], "cpu": ["arm64"]}"#,
    ).unwrap();
    fs::write(pkg_opt_dir.join("index.js"), "module.exports = 'pkg-opt';").unwrap();

    // pkg-funded
    let pkg_funded_dir = pkgs_dir.join("pkg-funded");
    fs::create_dir_all(&pkg_funded_dir).unwrap();
    fs::write(
        pkg_funded_dir.join("package.json"),
        r#"{"name": "pkg-funded", "version": "1.0.0", "main": "index.js", "funding": "https://example.com/donate"}"#,
    ).unwrap();
    fs::write(
        pkg_funded_dir.join("index.js"),
        "module.exports = 'pkg-funded';",
    )
    .unwrap();

    // Root package.json
    fs::write(
        dir.join("package.json"),
        r#"{
            "name": "fixture-app",
            "version": "1.0.0",
            "dependencies": {
                "pkg-prod": "file:./packages/pkg-prod",
                "pkg-funded": "file:./packages/pkg-funded"
            },
            "devDependencies": {
                "pkg-dev": "file:./packages/pkg-dev"
            },
            "optionalDependencies": {
                "pkg-opt": "file:./packages/pkg-opt"
            }
        }"#,
    )
    .unwrap();
}

#[test]
fn test_include_overrides_omit_precedence() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. --omit=dev --include=dev (include overrides omit)
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--omit=dev", "--include=dev"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let node_modules = temp.path().join("node_modules");
    assert!(
        node_modules.join("pkg-prod").exists(),
        "pkg-prod must be installed"
    );
    assert!(
        node_modules.join("pkg-dev").exists(),
        "pkg-dev must be installed because --include=dev overrides --omit=dev"
    );

    // 2. Order invariance: --include=dev --omit=dev (include still wins)
    let temp_rev = tempdir().unwrap();
    setup_base_fixture(temp_rev.path());

    let output_rev = Command::new(rnpm_bin)
        .current_dir(temp_rev.path())
        .args(["install", "--include=dev", "--omit=dev"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output_rev.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_rev.stderr)
    );
    assert!(
        temp_rev
            .path()
            .join("node_modules")
            .join("pkg-dev")
            .exists(),
        "pkg-dev must be installed regardless of flag order"
    );

    // 3. Omit only: --omit=dev (dev is omitted)
    let temp_omit = tempdir().unwrap();
    setup_base_fixture(temp_omit.path());

    let output_omit = Command::new(rnpm_bin)
        .current_dir(temp_omit.path())
        .args(["install", "--omit=dev"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_omit.status.success());
    let nm_omit = temp_omit.path().join("node_modules");
    assert!(nm_omit.join("pkg-prod").exists());
    assert!(
        !nm_omit.join("pkg-dev").exists(),
        "pkg-dev must NOT be installed when omitted"
    );

    // 4. NODE_ENV=production overridden by --include=dev
    let temp_prod_env = tempdir().unwrap();
    setup_base_fixture(temp_prod_env.path());

    let output_prod_env = Command::new(rnpm_bin)
        .current_dir(temp_prod_env.path())
        .env("NODE_ENV", "production")
        .args(["install", "--include=dev"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_prod_env.status.success());
    assert!(
        temp_prod_env
            .path()
            .join("node_modules")
            .join("pkg-dev")
            .exists(),
        "pkg-dev must be installed when --include=dev overrides NODE_ENV=production"
    );

    // 5. --include=prod does not omit dev
    let temp_inc_prod = tempdir().unwrap();
    setup_base_fixture(temp_inc_prod.path());

    let output_inc_prod = Command::new(rnpm_bin)
        .current_dir(temp_inc_prod.path())
        .args(["install", "--include=prod"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_inc_prod.status.success());
    let nm_inc = temp_inc_prod.path().join("node_modules");
    assert!(nm_inc.join("pkg-prod").exists());
    assert!(nm_inc.join("pkg-dev").exists());
}

#[test]
fn test_no_package_lock_and_package_lock_false() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. --no-package-lock
    let temp1 = tempdir().unwrap();
    setup_base_fixture(temp1.path());

    let output1 = Command::new(rnpm_bin)
        .current_dir(temp1.path())
        .args(["install", "--no-package-lock"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output1.stderr)
    );
    assert!(
        temp1.path().join("node_modules").join("pkg-prod").exists(),
        "node_modules/pkg-prod must be installed"
    );
    assert!(
        !temp1.path().join("package-lock.json").exists(),
        "package-lock.json must NOT be created when --no-package-lock is used"
    );

    // 2. --package-lock=false
    let temp2 = tempdir().unwrap();
    setup_base_fixture(temp2.path());

    let output2 = Command::new(rnpm_bin)
        .current_dir(temp2.path())
        .args(["install", "--package-lock=false"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        temp2.path().join("node_modules").join("pkg-prod").exists(),
        "node_modules/pkg-prod must be installed"
    );
    assert!(
        !temp2.path().join("package-lock.json").exists(),
        "package-lock.json must NOT be created when --package-lock=false is used"
    );

    // 3. Existing lockfile is neither read nor overwritten
    let temp3 = tempdir().unwrap();
    setup_base_fixture(temp3.path());
    let existing_lock_content = r#"{"name": "pre-existing", "lockfileVersion": 3, "packages": {}}"#;
    fs::write(
        temp3.path().join("package-lock.json"),
        existing_lock_content,
    )
    .unwrap();

    let output3 = Command::new(rnpm_bin)
        .current_dir(temp3.path())
        .args(["install", "--no-package-lock"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output3.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output3.stderr)
    );
    let current_lock_content = fs::read_to_string(temp3.path().join("package-lock.json")).unwrap();
    assert_eq!(
        current_lock_content, existing_lock_content,
        "Existing package-lock.json must NOT be modified when --no-package-lock is used"
    );
}

#[test]
fn test_dry_run_simulation_without_filesystem_mutation() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    let initial_pkg_json = fs::read_to_string(temp.path().join("package.json")).unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--dry-run"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rnpm: dry-run: would install") || stdout.contains("would install"),
        "stdout must report dry-run simulation notices: {stdout}"
    );

    // Verify complete absence of filesystem mutation
    assert!(
        !temp.path().join("node_modules").exists(),
        "node_modules must NOT be created during --dry-run"
    );
    assert!(
        !temp.path().join("package-lock.json").exists(),
        "package-lock.json must NOT be created during --dry-run"
    );
    let after_pkg_json = fs::read_to_string(temp.path().join("package.json")).unwrap();
    assert_eq!(
        initial_pkg_json, after_pkg_json,
        "package.json must NOT be mutated during --dry-run"
    );
}

#[test]
fn test_platform_overrides() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Target platform matches pkg-opt (darwin + arm64)
    let temp1 = tempdir().unwrap();
    setup_base_fixture(temp1.path());

    let output1 = Command::new(rnpm_bin)
        .current_dir(temp1.path())
        .args(["install", "--os=darwin", "--cpu=arm64"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output1.stderr)
    );
    assert!(
        temp1.path().join("node_modules").join("pkg-opt").exists(),
        "pkg-opt must be installed when target platform matches --os=darwin --cpu=arm64"
    );

    // 2. Target platform does NOT match pkg-opt (linux + x64)
    let temp2 = tempdir().unwrap();
    setup_base_fixture(temp2.path());

    let output2 = Command::new(rnpm_bin)
        .current_dir(temp2.path())
        .args(["install", "--os=linux", "--cpu=x64"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        !temp2.path().join("node_modules").join("pkg-opt").exists(),
        "pkg-opt must be skipped when target platform is incompatible (--os=linux --cpu=x64)"
    );
    let lockfile2 = fs::read_to_string(temp2.path().join("package-lock.json")).unwrap();
    assert!(
        lockfile2.contains("pkg-opt"),
        "Incompatible optional packages must remain in the lockfile for cross-platform parity"
    );

    // 3. Cross-platform lockfile generation with --package-lock-only
    let temp3 = tempdir().unwrap();
    setup_base_fixture(temp3.path());

    let output3 = Command::new(rnpm_bin)
        .current_dir(temp3.path())
        .args([
            "install",
            "--package-lock-only",
            "--os=darwin",
            "--cpu=arm64",
        ])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output3.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output3.stderr)
    );
    let lockfile_str = fs::read_to_string(temp3.path().join("package-lock.json")).unwrap();
    assert!(
        lockfile_str.contains("pkg-opt"),
        "Generated lockfile must contain pkg-opt evaluated against target platform"
    );
}

#[test]
fn test_audit_and_fund_controls() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Default install displays funding notice and audit check
    let temp_def = tempdir().unwrap();
    setup_base_fixture(temp_def.path());

    let output_def = Command::new(rnpm_bin)
        .current_dir(temp_def.path())
        .args(["install"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output_def.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_def.stderr)
    );
    let stdout_def = String::from_utf8_lossy(&output_def.stdout);
    assert!(
        stdout_def.contains("looking for funding") || stdout_def.contains("funding"),
        "Default install should display funding notice: {stdout_def}"
    );

    // 2. --no-fund suppresses funding notices
    let temp_no_fund = tempdir().unwrap();
    setup_base_fixture(temp_no_fund.path());

    let output_no_fund = Command::new(rnpm_bin)
        .current_dir(temp_no_fund.path())
        .args(["install", "--no-fund"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_no_fund.status.success());
    let stdout_no_fund = String::from_utf8_lossy(&output_no_fund.stdout);
    assert!(
        !stdout_no_fund.contains("looking for funding"),
        "Funding notice must be suppressed with --no-fund"
    );

    // 3. --fund=false suppresses funding notices
    let temp_fund_false = tempdir().unwrap();
    setup_base_fixture(temp_fund_false.path());

    let output_fund_false = Command::new(rnpm_bin)
        .current_dir(temp_fund_false.path())
        .args(["install", "--fund=false"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_fund_false.status.success());
    let stdout_fund_false = String::from_utf8_lossy(&output_fund_false.stdout);
    assert!(
        !stdout_fund_false.contains("looking for funding"),
        "Funding notice must be suppressed with --fund=false"
    );

    // 4. --no-audit suppresses audit check
    let temp_no_audit = tempdir().unwrap();
    setup_base_fixture(temp_no_audit.path());

    let output_no_audit = Command::new(rnpm_bin)
        .current_dir(temp_no_audit.path())
        .args(["install", "--no-audit"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_no_audit.status.success());
    let stdout_no_audit = String::from_utf8_lossy(&output_no_audit.stdout);
    assert!(
        !stdout_no_audit.contains("vulnerabilities"),
        "Audit notice must be suppressed with --no-audit"
    );

    // 5. --audit=false suppresses audit check
    let temp_audit_false = tempdir().unwrap();
    setup_base_fixture(temp_audit_false.path());

    let output_audit_false = Command::new(rnpm_bin)
        .current_dir(temp_audit_false.path())
        .args(["install", "--audit=false"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(output_audit_false.status.success());
    let stdout_audit_false = String::from_utf8_lossy(&output_audit_false.stdout);
    assert!(
        !stdout_audit_false.contains("vulnerabilities"),
        "Audit notice must be suppressed with --audit=false"
    );
}

#[test]
fn test_workspace_root_options() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    // Create a monorepo workspace
    let ws_dir = temp.path().join("ws");
    fs::create_dir_all(&ws_dir).unwrap();

    let marker_file = temp.path().join("ws-log.txt");
    let escaped_marker = marker_file.to_string_lossy().replace('\\', "/");

    let pkg_a_dir = ws_dir.join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        format!(
            r#"{{
                "name": "pkg-a",
                "version": "1.0.0",
                "scripts": {{
                    "test": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'pkg-a\\n')\""
                }}
            }}"#
        ),
    ).unwrap();

    fs::write(
        temp.path().join("package.json"),
        format!(
            r#"{{
                "name": "root-pkg",
                "version": "1.0.0",
                "workspaces": ["ws/*"],
                "scripts": {{
                    "test": "node -e \"require('fs').appendFileSync('{escaped_marker}', 'root\\n')\""
                }},
                "dependencies": {{
                    "pkg-prod": "file:./packages/pkg-prod"
                }}
            }}"#
        ),
    ).unwrap();

    // 1. Without --workspace-root: only pkg-a runs
    let _ = fs::remove_file(&marker_file);
    let output1 = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["run", "test", "--workspace=pkg-a"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output1.stderr)
    );
    let log1 = fs::read_to_string(&marker_file).unwrap_or_default();
    assert!(log1.contains("pkg-a"), "pkg-a must have run");
    assert!(
        !log1.contains("root"),
        "root must NOT run without --workspace-root"
    );

    // 2. With --workspace-root: both pkg-a AND root run
    let _ = fs::remove_file(&marker_file);
    let output2 = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["run", "test", "--workspace=pkg-a", "--workspace-root"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    let log2 = fs::read_to_string(&marker_file).unwrap_or_default();
    assert!(log2.contains("pkg-a"), "pkg-a must run");
    assert!(
        log2.contains("root"),
        "root must run when --workspace-root is specified: {log2}"
    );

    // 3. With --include-workspace-root alias: both pkg-a AND root run
    let _ = fs::remove_file(&marker_file);
    let output3 = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args([
            "run",
            "test",
            "--workspace=pkg-a",
            "--include-workspace-root",
        ])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output3.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output3.stderr)
    );
    let log3 = fs::read_to_string(&marker_file).unwrap_or_default();
    assert!(log3.contains("pkg-a"));
    assert!(log3.contains("root"));
}

#[test]
fn test_include_peer_and_optional_combinations() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // --omit=optional,peer --include=optional,peer
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args([
            "install",
            "--omit=optional,peer",
            "--include=optional,peer",
            "--os=darwin",
            "--cpu=arm64",
        ])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let node_modules = temp.path().join("node_modules");
    assert!(
        node_modules.join("pkg-opt").exists(),
        "pkg-opt must be installed because --include=optional overrides --omit=optional"
    );
}

#[test]
fn test_dry_run_with_add_packages_preserves_package_json() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    let initial_pkg_json = fs::read_to_string(temp.path().join("package.json")).unwrap();

    let output = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args([
            "install",
            "file:./packages/pkg-dev",
            "--save-dev",
            "--dry-run",
        ])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("would add") || stdout.contains("would install"));

    // Verify package.json untouched
    let after_pkg_json = fs::read_to_string(temp.path().join("package.json")).unwrap();
    assert_eq!(initial_pkg_json, after_pkg_json);
    assert!(!temp.path().join("node_modules").exists());
}

#[test]
fn test_workspace_root_install_options() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();
    setup_base_fixture(temp.path());

    // Create a monorepo workspace
    let ws_dir = temp.path().join("ws");
    let pkg_a_dir = ws_dir.join("pkg-a");
    fs::create_dir_all(&pkg_a_dir).unwrap();
    fs::write(
        pkg_a_dir.join("package.json"),
        r#"{
            "name": "pkg-a",
            "version": "1.0.0",
            "dependencies": {
                "pkg-dev": "file:./packages/pkg-dev"
            }
        }"#,
    )
    .unwrap();

    fs::write(
        temp.path().join("package.json"),
        r#"{
            "name": "root-pkg",
            "version": "1.0.0",
            "workspaces": ["ws/*"],
            "dependencies": {
                "pkg-prod": "file:./packages/pkg-prod"
            }
        }"#,
    )
    .unwrap();

    // 1. Install targeting only workspace pkg-a without root
    let output1 = Command::new(rnpm_bin)
        .current_dir(temp.path())
        .args(["install", "--workspace=pkg-a"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output1.stderr)
    );
    let node_modules = temp.path().join("node_modules");
    assert!(
        node_modules.join("pkg-dev").exists(),
        "pkg-a's dependency must be installed"
    );

    // 2. Install targeting workspace pkg-a AND workspace root
    let temp2 = tempdir().unwrap();
    setup_base_fixture(temp2.path());
    let ws_dir2 = temp2.path().join("ws");
    let pkg_a_dir2 = ws_dir2.join("pkg-a");
    fs::create_dir_all(&pkg_a_dir2).unwrap();
    fs::write(
        pkg_a_dir2.join("package.json"),
        r#"{
            "name": "pkg-a",
            "version": "1.0.0",
            "dependencies": {
                "pkg-dev": "file:./packages/pkg-dev"
            }
        }"#,
    )
    .unwrap();
    fs::write(
        temp2.path().join("package.json"),
        r#"{
            "name": "root-pkg",
            "version": "1.0.0",
            "workspaces": ["ws/*"],
            "dependencies": {
                "pkg-prod": "file:./packages/pkg-prod"
            }
        }"#,
    )
    .unwrap();

    let output2 = Command::new(rnpm_bin)
        .current_dir(temp2.path())
        .args(["install", "--workspace=pkg-a", "--workspace-root"])
        .output()
        .expect("Failed to execute rnpm");

    assert!(
        output2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    let node_modules2 = temp2.path().join("node_modules");
    assert!(
        node_modules2.join("pkg-dev").exists(),
        "pkg-a's dependency must be installed"
    );
    assert!(
        node_modules2.join("pkg-prod").exists(),
        "root dependency must also be installed with --workspace-root"
    );
}
