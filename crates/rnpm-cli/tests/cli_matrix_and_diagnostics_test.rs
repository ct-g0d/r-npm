use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_clean_install_aliases_invocation() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Verify clean-install, ci, and ic are recognized subcommands (e.g. via --help)
    for cmd in ["ci", "clean-install", "ic"] {
        let output = Command::new(rnpm_bin)
            .arg(cmd)
            .arg("--help")
            .output()
            .expect("Failed to execute rnpm command");

        assert!(output.status.success(), "Command '{cmd} --help' must succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("package-lock.json"),
            "Command '{cmd}' help output should describe lockfile installation, got: {stdout}"
        );
    }
}

#[test]
fn test_extended_commands_cli_help_matrix() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let cases = [
        ("team", vec!["team"]),
        ("search", vec!["search", "lodash"]),
        ("star", vec!["star", "express"]),
        ("doctor", vec!["doctor"]),
    ];

    for (cmd_name, args) in cases {
        let mut help_args = args.clone();
        help_args.push("--help");
        let output = Command::new(rnpm_bin)
            .args(&help_args)
            .output()
            .expect("Failed to execute rnpm command");

        assert!(output.status.success(), "Implemented command '{cmd_name} --help' must succeed: {}", String::from_utf8_lossy(&output.stderr));
        assert!(!output.stdout.is_empty(), "Implemented command '{cmd_name}' should emit help text");
    }
}

#[test]
fn test_audit_cli_workflow_with_dependency_classifications_and_none_threshold() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let package_json = serde_json::json!({
        "name": "audit-classifications-app",
        "version": "1.0.0",
        "dependencies": {
            "prod-dep": "^1.0.0"
        },
        "devDependencies": {
            "dev-dep": "^1.0.0"
        },
        "peerDependencies": {
            "peer-dep": "^1.0.0",
            "peer-opt-dep": "^1.0.0"
        },
        "peerDependenciesMeta": {
            "peer-opt-dep": {
                "optional": true
            }
        },
        "optionalDependencies": {
            "opt-dep": "^1.0.0"
        }
    });
    fs::write(project_dir.join("package.json"), serde_json::to_string_pretty(&package_json).unwrap()).unwrap();

    let lockfile_json = serde_json::json!({
        "name": "audit-classifications-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "audit-classifications-app",
                "version": "1.0.0",
                "dependencies": {
                    "prod-dep": "^1.0.0"
                },
                "devDependencies": {
                    "dev-dep": "^1.0.0"
                },
                "peerDependencies": {
                    "peer-dep": "^1.0.0",
                    "peer-opt-dep": "^1.0.0"
                },
                "peerDependenciesMeta": {
                    "peer-opt-dep": {
                        "optional": true
                    }
                },
                "optionalDependencies": {
                    "opt-dep": "^1.0.0"
                }
            },
            "node_modules/prod-dep": {
                "version": "1.0.0"
            },
            "node_modules/dev-dep": {
                "version": "1.0.0",
                "dev": true
            },
            "node_modules/opt-dep": {
                "version": "1.0.0",
                "optional": true
            },
            "node_modules/peer-dep": {
                "version": "1.0.0",
                "peer": true
            },
            "node_modules/peer-opt-dep": {
                "version": "1.0.0",
                "peer": true,
                "peerOptional": true
            }
        }
    });
    fs::write(project_dir.join("package-lock.json"), serde_json::to_string_pretty(&lockfile_json).unwrap()).unwrap();

    // Provide an empty advisories.json in project_dir so fetch_advisories succeeds offline with 0 vulns
    fs::write(project_dir.join("advisories.json"), "{}").unwrap();

    let output = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--audit-level")
        .arg("none")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");

    assert!(output.status.success(), "Audit with clean lockfile and audit-level none must succeed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("found 0 vulnerabilities"));
}

#[test]
fn test_audit_missing_lockfile_emits_enolock() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();

    let output = Command::new(rnpm_bin)
        .arg("audit")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm audit");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("npm error code ENOLOCK"), "Expected ENOLOCK, got: {stderr}");
    assert!(stderr.contains("This command requires an existing lockfile."));
}

#[test]
fn test_audit_threshold_exit_codes() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let package_json = serde_json::json!({
        "name": "audit-threshold-app",
        "version": "1.0.0",
        "dependencies": {
            "vuln-pkg": "^1.0.0"
        }
    });
    fs::write(project_dir.join("package.json"), serde_json::to_string_pretty(&package_json).unwrap()).unwrap();

    let lockfile_json = serde_json::json!({
        "name": "audit-threshold-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "audit-threshold-app",
                "version": "1.0.0",
                "dependencies": {
                    "vuln-pkg": "^1.0.0"
                }
            },
            "node_modules/vuln-pkg": {
                "version": "1.0.0"
            }
        }
    });
    fs::write(project_dir.join("package-lock.json"), serde_json::to_string_pretty(&lockfile_json).unwrap()).unwrap();

    // High severity advisory for vuln-pkg
    let advisories_json = serde_json::json!({
        "vuln-pkg": [
            {
                "id": 101,
                "name": "vuln-pkg",
                "severity": "high",
                "vulnerable_versions": "<=1.0.0",
                "title": "High severity flaw in vuln-pkg",
                "url": "https://example.com/advisory/101"
            }
        ]
    });
    fs::write(project_dir.join("advisories.json"), serde_json::to_string_pretty(&advisories_json).unwrap()).unwrap();

    // 1. Audit level moderate: high severity >= moderate threshold -> must exit 1
    let out_fail = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--audit-level")
        .arg("moderate")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert_eq!(out_fail.status.code(), Some(1), "Expected exit 1 for high severity >= moderate");

    // 2. Audit level critical: high severity < critical threshold -> must exit 0
    let out_pass = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--audit-level")
        .arg("critical")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert!(out_pass.status.success(), "Expected exit 0 for high severity < critical");

    // 3. Audit level none: always exits 0 even with vulnerabilities present
    let out_none = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--audit-level")
        .arg("none")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert!(out_none.status.success(), "Expected exit 0 for --audit-level none");
}

#[test]
fn test_audit_malformed_lockfile_emits_ejsonparse() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    fs::write(project_dir.join("package.json"), "{\"name\":\"test\"}").unwrap();
    fs::write(project_dir.join("package-lock.json"), "{\n  \"lockfileVersion\": 3,\n  \"invalid\": ").unwrap();

    let output = Command::new(rnpm_bin)
        .arg("audit")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("npm error code EJSONPARSE"), "Expected EJSONPARSE, got: {stderr}");
    assert!(!stderr.contains("npm error npm error code"), "Double header detected in output: {stderr}");
}

#[test]
fn test_additional_aliases_and_flag_routing() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Install aliases 'add' and 'isntall'
    for alias in ["add", "isntall"] {
        let output = Command::new(rnpm_bin)
            .arg(alias)
            .arg("--help")
            .output()
            .expect("Failed to execute rnpm");
        assert!(output.status.success(), "Command '{alias} --help' should succeed");
    }

    // Ci supports --offline
    let output = Command::new(rnpm_bin)
        .arg("ci")
        .arg("--help")
        .output()
        .expect("Failed to execute rnpm");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--offline"));

    // Search is parsed as an implemented command.
    let output = Command::new(rnpm_bin)
        .arg("search")
        .arg("--help")
        .output()
        .expect("Failed to execute rnpm");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Search the registry"));

    // Additional unsupported flags --production on install
    let flag_args = ["install", "--production"];
    let output = Command::new(rnpm_bin)
        .args(flag_args)
        .output()
        .expect("Failed to execute rnpm");
    assert!(!output.status.success(), "Flag args '{:?}' must fail", flag_args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("npm error code ERR_UNSUPPORTED_FLAG"), "Expected ERR_UNSUPPORTED_FLAG for '{:?}', got: {stderr}", flag_args);
}

#[test]
fn test_cli_peer_dependency_flags_and_resolution() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // 1. Verify --legacy-peer-deps and --strict-peer-deps appear in help for install, ci, and update
    for cmd in ["install", "ci", "update"] {
        let output = Command::new(rnpm_bin)
            .arg(cmd)
            .arg("--help")
            .output()
            .expect("Failed to run rnpm help");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("--legacy-peer-deps"), "{cmd} --help must contain --legacy-peer-deps");
        assert!(stdout.contains("--strict-peer-deps"), "{cmd} --help must contain --strict-peer-deps");
    }

    // 2. Verify flags are supported on install, ci, update and rejected on audit
    for cmd in ["install", "ci", "update", "i", "clean-install", "up"] {
        for flag in ["--legacy-peer-deps", "--strict-peer-deps"] {
            let output = Command::new(rnpm_bin)
                .args([cmd, flag, "--help"])
                .output()
                .expect("Failed to run command");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("ERR_UNSUPPORTED_FLAG"),
                "Flag {flag} on {cmd} must not be gated as ERR_UNSUPPORTED_FLAG"
            );
        }
    }

    for flag in ["--legacy-peer-deps", "--strict-peer-deps"] {
        let output = Command::new(rnpm_bin)
            .args(["audit", flag])
            .output()
            .expect("Failed to run command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("npm error code ERR_UNSUPPORTED_FLAG"),
            "Flag {flag} on audit must be gated as ERR_UNSUPPORTED_FLAG, got: {stderr}"
        );
    }
}
