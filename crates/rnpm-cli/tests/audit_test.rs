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

    // Verify package.json preserved declared range (matching npm 11 behavior)
    let updated_pkg = fs::read_to_string(project_dir.join("package.json")).unwrap();
    assert!(
        updated_pkg.contains("\"lodash\": \"^4.17.15\""),
        "package.json declared range should be preserved, got:\n{updated_pkg}"
    );

    let updated_lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    assert!(
        updated_lock.contains("\"version\": \"4.18.1\"")
            || updated_lock.contains("\"version\": \"4.17.21\""),
        "package-lock.json must be updated to fixed version, got:\n{updated_lock}"
    );
    assert!(
        updated_lock.contains("lodash-4.18.1.tgz") || updated_lock.contains("lodash-4.17.21.tgz"),
        "package-lock.json resolved URL must be updated to fixed version, got:\n{updated_lock}"
    );
    assert!(
        updated_lock.contains("\"integrity\":"),
        "package-lock.json must include real integrity hash"
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

    assert_eq!(
        output.status.code(),
        Some(1),
        "unresolved vulnerabilities must fail audit fix"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("# npm audit report"),
        "stdout must report the remaining vulnerabilities: {stdout}"
    );
    assert!(
        stdout.contains("npm audit fix --force"),
        "stdout must explain the required forced remediation: {stdout}"
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
        updated_lock.contains("\"version\": \"1.2.8\"")
            || updated_lock.contains("\"version\": \"1.2.6\""),
        "package-lock.json must be upgraded to version 1.2.x, got:\n{updated_lock}"
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
        stdout.contains("fixed 2 vulnerabilities (1 high, 1 low) in 2 packages"),
        "stdout must report exact multi-severity summary, got:\n{stdout}"
    );
    assert!(stdout.contains("found 0 vulnerabilities"));
}

#[test]
fn test_audit_fix_reifies_real_package_files_and_lockfile_ci() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let iso_dir = tmp.path().join("iso");
    let iso_cache = iso_dir.join("cache");

    let pkg_json = serde_json::json!({
        "name": "test-disk-reify",
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
        "name": "test-disk-reify",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-disk-reify",
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
                "vulnerable_versions": "<4.17.21"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    let fix_out = Command::new(rnpm_bin)
        .args(["audit", "fix"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .env("NPM_CONFIG_CACHE", iso_cache.join("_cacache"))
        .env("RNPM_STORE_DIR", iso_dir.join("store"))
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix");
    assert!(
        fix_out.status.success(),
        "audit fix must succeed: {:?}",
        fix_out
    );

    // 1. Verify real package files were reified on disk
    let lodash_pkg_json = project_dir
        .join("node_modules")
        .join("lodash")
        .join("package.json");
    assert!(
        lodash_pkg_json.exists(),
        "node_modules/lodash/package.json must exist on disk"
    );
    let lodash_content = fs::read_to_string(&lodash_pkg_json).unwrap();
    assert!(
        !lodash_content.contains("\"4.17.15\""),
        "node_modules/lodash on disk must no longer be 4.17.15"
    );

    // 2. Verify lockfile has valid integrity hash
    let lock_content = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
    let lock_val: serde_json::Value = serde_json::from_str(&lock_content).unwrap();
    let lodash_entry = lock_val["packages"]["node_modules/lodash"]
        .as_object()
        .unwrap();
    assert!(
        lodash_entry.contains_key("integrity"),
        "fixed package in lockfile must have real integrity hash"
    );

    // Use an isolated npm-compatible content cache for both ci implementations.
    let iso_prefix = iso_dir.join("prefix");
    let iso_userconfig = iso_dir.join(".npmrc");
    let iso_globalconfig = iso_dir.join("global.npmrc");
    let iso_appdata = iso_dir.join("appdata");
    let iso_localappdata = iso_dir.join("localappdata");
    let _ = fs::create_dir_all(&iso_cache);
    let _ = fs::create_dir_all(&iso_prefix);
    let _ = fs::create_dir_all(&iso_appdata);
    let _ = fs::create_dir_all(&iso_localappdata);
    let _ = fs::write(&iso_userconfig, "registry=http://127.0.0.1:9/\n");
    let _ = fs::write(&iso_globalconfig, "");

    // 3. Verify rnpm ci and populate the tarball content used by offline npm ci.
    let ci_out = Command::new(rnpm_bin)
        .args(["ci", "--cache"])
        .arg(iso_cache.join("_cacache"))
        .env("RNPM_STORE_DIR", iso_dir.join("store"))
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ci");
    assert!(
        ci_out.status.success(),
        "rnpm ci must succeed on fixed project: {:?}",
        ci_out
    );

    // Seed npm's native content layout from the exact verified rnpm tarball.
    // rnpm also supports a legacy layout that npm itself does not read.
    let integrity =
        rnpm_core::integrity::Integrity::parse(lodash_entry["integrity"].as_str().unwrap())
            .unwrap();
    let cache = rnpm_cache::Cache::new(iso_cache.join("_cacache")).unwrap();
    let tarball = cache.get_by_integrity(&integrity).unwrap().unwrap();
    let digest = &integrity.entries[0];
    let hex = data_encoding::HEXLOWER.encode(&digest.digest);
    let npm_blob = iso_cache
        .join("_cacache/content-v2")
        .join(digest.algorithm.as_str())
        .join(&hex[..2])
        .join(&hex[2..4])
        .join(&hex[4..]);
    fs::create_dir_all(npm_blob.parent().unwrap()).unwrap();
    fs::write(npm_blob, tarball).unwrap();

    // 4. Verify npm ls --all and npm ci succeed if npm is installed on machine.
    let npm_cmd = if cfg!(windows) { "npm.cmd" } else { "npm" };
    if let Ok(npm_ls) = Command::new(npm_cmd)
        .args(["ls", "--all"])
        .current_dir(project_dir)
        .env("HOME", &iso_dir)
        .env("USERPROFILE", &iso_dir)
        .env("npm_config_userconfig", &iso_userconfig)
        .env("npm_config_globalconfig", &iso_globalconfig)
        .env("NPM_CONFIG_PREFIX", &iso_prefix)
        .env("PREFIX", &iso_prefix)
        .env("USERCONFIG", &iso_userconfig)
        .env("GLOBALCONFIG", &iso_globalconfig)
        .env("CACHE", &iso_cache)
        .env("NPM_CONFIG_CACHE", &iso_cache)
        .env("npm_config_cache", &iso_cache)
        .env("APPDATA", &iso_appdata)
        .env("LOCALAPPDATA", &iso_localappdata)
        .output()
    {
        assert!(
            npm_ls.status.success(),
            "npm ls --all must succeed on fixed project: {}",
            String::from_utf8_lossy(&npm_ls.stderr)
        );
    }
    if let Ok(npm_ci) = Command::new(npm_cmd)
        .args(["ci", "--offline", "--cache"])
        .arg(&iso_cache)
        .current_dir(project_dir)
        .env("HOME", &iso_dir)
        .env("USERPROFILE", &iso_dir)
        .env("npm_config_userconfig", &iso_userconfig)
        .env("npm_config_globalconfig", &iso_globalconfig)
        .env("NPM_CONFIG_PREFIX", &iso_prefix)
        .env("PREFIX", &iso_prefix)
        .env("USERCONFIG", &iso_userconfig)
        .env("GLOBALCONFIG", &iso_globalconfig)
        .env("CACHE", &iso_cache)
        .env("NPM_CONFIG_CACHE", &iso_cache)
        .env("npm_config_cache", &iso_cache)
        .env("APPDATA", &iso_appdata)
        .env("LOCALAPPDATA", &iso_localappdata)
        .output()
    {
        assert!(
            npm_ci.status.success(),
            "offline npm ci must succeed on fixed project: {}",
            String::from_utf8_lossy(&npm_ci.stderr)
        );
    }
}
