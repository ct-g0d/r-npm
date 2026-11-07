use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_audit_fix_compatible_resolution() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-compat-fix",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.15"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-compat-fix",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-compat-fix",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.15"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.15",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let advisories_json = serde_json::json!({
        "lodash": [
            {
                "id": 1065,
                "name": "lodash",
                "severity": "high",
                "vulnerable_versions": "<4.17.21",
                "title": "Prototype Pollution in lodash",
                "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .args(["audit", "fix"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix");

    assert!(
        output.status.success(),
        "audit fix must succeed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fixed 1 vulnerability (1 high) in 1 package"),
        "stdout must contain fixed summary, got:\n{stdout}"
    );
    assert!(
        stdout.contains("found 0 vulnerabilities"),
        "stdout must report 0 remaining vulnerabilities, got:\n{stdout}"
    );

    // Verify package.json and package-lock.json updated to 4.17.21
    let updated_pkg = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(
        updated_pkg.contains("\"lodash\": \"^4.17.21\""),
        "package.json must be updated to ^4.17.21, got:\n{updated_pkg}"
    );

    let updated_lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(
        updated_lock.contains("\"version\": \"4.17.21\""),
        "package-lock.json must be updated to version 4.17.21, got:\n{updated_lock}"
    );
    assert!(
        updated_lock.contains("lodash-4.17.21.tgz"),
        "package-lock.json resolved URL must be updated to 4.17.21, got:\n{updated_lock}"
    );
}

#[test]
fn test_audit_fix_incompatible_requires_force() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-incompat-fix",
        "version": "1.0.0",
        "dependencies": {
            "minimist": "^0.0.8"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-incompat-fix",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-incompat-fix",
                "version": "1.0.0",
                "dependencies": {
                    "minimist": "^0.0.8"
                }
            },
            "node_modules/minimist": {
                "version": "0.0.8",
                "resolved": "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let advisories_json = serde_json::json!({
        "minimist": [
            {
                "id": 1003,
                "name": "minimist",
                "severity": "critical",
                "vulnerable_versions": "<1.2.6",
                "title": "Prototype Pollution in minimist",
                "url": "https://github.com/advisories/GHSA-vh95-rmgr-6w4m"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    // 1. Without --force: breaking semver upgrade must NOT be applied
    let output = Command::new(rnpm_bin)
        .args(["audit", "fix"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("found 0 vulnerabilities to fix"),
        "stdout must report 0 vulnerabilities to fix without --force, got:\n{stdout}"
    );
    assert!(
        stderr.contains(
            "Semver-major updates or transitive dependencies may require `rnpm audit fix --force`"
        ),
        "stderr must explain semver-major updates require --force, got:\n{stderr}"
    );

    // Verify package.json is unmodified
    let unchanged_pkg = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(unchanged_pkg.contains("\"minimist\": \"^0.0.8\""));

    // 2. With --force: breaking upgrade is allowed
    let output_force = Command::new(rnpm_bin)
        .args(["audit", "fix", "--force"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix --force");

    assert!(output_force.status.success());
    let stdout_force = String::from_utf8_lossy(&output_force.stdout);
    let stderr_force = String::from_utf8_lossy(&output_force.stderr);
    assert!(
        stderr_force.contains("npm warn audit --force installing breaking changes if necessary"),
        "stderr must warn about breaking changes with --force, got:\n{stderr_force}"
    );
    assert!(
        stdout_force.contains("fixed 1 vulnerability (1 critical) in 1 package"),
        "stdout must report 1 critical fixed, got:\n{stdout_force}"
    );

    // Verify package.json was updated with --force
    let updated_pkg = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(
        updated_pkg.contains("\"minimist\": \"^1.2.6\""),
        "package.json must be upgraded to ^1.2.6 with --force, got:\n{updated_pkg}"
    );

    let updated_lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(
        updated_lock.contains("\"version\": \"1.2.6\""),
        "package-lock.json must be upgraded to version 1.2.6, got:\n{updated_lock}"
    );
}

#[test]
fn test_audit_fix_dry_run() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-dry-run-fix",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.15"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-dry-run-fix",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-dry-run-fix",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.15"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.15"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let advisories_json = serde_json::json!({
        "lodash": [
            {
                "id": 1065,
                "name": "lodash",
                "severity": "high",
                "vulnerable_versions": "<4.17.21"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .args(["audit", "fix", "--dry-run"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix --dry-run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would update lodash from 4.17.15 to 4.17.21"),
        "stdout must show what would be updated, got:\n{stdout}"
    );
    assert!(
        stdout.contains("fixed 1 vulnerability (1 high) in 1 package"),
        "stdout must show dry-run fixed summary, got:\n{stdout}"
    );

    // Files must be untouched on disk
    let disk_pkg = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(disk_pkg.contains("\"lodash\": \"^4.17.15\""));
    let disk_lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(disk_lock.contains("\"version\": \"4.17.15\""));
}

#[test]
fn test_audit_fix_multi_package_severities() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-multi-fix",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.15",
            "debug": "^2.6.0"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-multi-fix",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-multi-fix",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.15",
                    "debug": "^2.6.0"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.15"
            },
            "node_modules/debug": {
                "version": "2.6.0"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let advisories_json = serde_json::json!({
        "lodash": [
            {
                "id": 1065,
                "name": "lodash",
                "severity": "high",
                "vulnerable_versions": "<4.17.21"
            }
        ],
        "debug": [
            {
                "id": 1004,
                "name": "debug",
                "severity": "low",
                "vulnerable_versions": "<2.6.9"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .args(["audit", "fix"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fixed 2 vulnerabilities (1 low, 1 high) in 2 packages"),
        "stdout must report exact multi-severity summary, got:\n{stdout}"
    );
    assert!(stdout.contains("found 0 vulnerabilities"));
}
