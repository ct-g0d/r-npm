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

        assert!(
            output.status.success(),
            "Command '{cmd} --help' must succeed"
        );
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

        assert!(
            output.status.success(),
            "Implemented command '{cmd_name} --help' must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.stdout.is_empty(),
            "Implemented command '{cmd_name}' should emit help text"
        );
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
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&package_json).unwrap(),
    )
    .unwrap();

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
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    // Provide an empty advisories.json in project_dir so fetch_advisories succeeds offline with 0 vulns
    fs::write(project_dir.join("advisories.json"), "{}").unwrap();

    let output = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--audit-level")
        .arg("none")
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");

    assert!(
        output.status.success(),
        "Audit with clean lockfile and audit-level none must succeed: {:?}",
        output
    );
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
    assert!(
        stderr.contains("npm error code ENOLOCK"),
        "Expected ENOLOCK, got: {stderr}"
    );
    assert!(stderr.contains("This command requires an existing lockfile."));
}

// Audits calculate affected published versions as well as reading advisories.
fn audit_packument_registry(requests: usize) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let body = r#"{"name":"vuln-pkg","dist-tags":{"latest":"1.1.0"},"versions":{"1.0.0":{"name":"vuln-pkg","version":"1.0.0"},"1.1.0":{"name":"vuln-pkg","version":"1.1.0"}}}"#;
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
    });
    url
}

#[test]
fn test_audit_threshold_exit_codes() {
    let registry = audit_packument_registry(3);
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
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&package_json).unwrap(),
    )
    .unwrap();

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
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

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
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    // 1. Audit level moderate: high severity >= moderate threshold -> must exit 1
    let out_fail = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--registry")
        .arg(&registry)
        .arg("--audit-level")
        .arg("moderate")
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert_eq!(
        out_fail.status.code(),
        Some(1),
        "Expected exit 1 for high severity >= moderate"
    );

    // 2. Audit level critical: high severity < critical threshold -> must exit 0
    let out_pass = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--registry")
        .arg(&registry)
        .arg("--audit-level")
        .arg("critical")
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert!(
        out_pass.status.success(),
        "Expected exit 0 for high severity < critical"
    );

    // 3. Audit level none: always exits 0 even with vulnerabilities present
    let out_none = Command::new(rnpm_bin)
        .arg("audit")
        .arg("--registry")
        .arg(&registry)
        .arg("--audit-level")
        .arg("none")
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");
    assert!(
        out_none.status.success(),
        "Expected exit 0 for --audit-level none"
    );
}

#[test]
fn test_audit_malformed_lockfile_emits_ejsonparse() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    fs::write(project_dir.join("package.json"), "{\"name\":\"test\"}").unwrap();
    fs::write(
        project_dir.join("package-lock.json"),
        "{\n  \"lockfileVersion\": 3,\n  \"invalid\": ",
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .arg("audit")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error code EJSONPARSE"),
        "Expected EJSONPARSE, got: {stderr}"
    );
    assert!(
        !stderr.contains("npm error npm error code"),
        "Double header detected in output: {stderr}"
    );
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
        assert!(
            output.status.success(),
            "Command '{alias} --help' should succeed"
        );
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

    // Peer-resolution flags are still unsupported for pack.
    let flag_args = ["pack", "--legacy-peer-deps"];
    let output = Command::new(rnpm_bin)
        .args(flag_args)
        .output()
        .expect("Failed to execute rnpm");
    assert!(
        !output.status.success(),
        "Flag args '{:?}' must fail",
        flag_args
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("npm error code ERR_UNSUPPORTED_FLAG"),
        "Expected ERR_UNSUPPORTED_FLAG for '{:?}', got: {stderr}",
        flag_args
    );

    let project = tempdir().unwrap();
    fs::write(project.path().join("package.json"), r#"{"name":"bundle-routing","version":"1.0.0"}"#).unwrap();
    let output = Command::new(rnpm_bin)
        .args(["install", "--save-bundle", "--ignore-scripts", "--no-audit", "--no-fund"])
        .current_dir(project.path())
        .output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
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
        assert!(
            stdout.contains("--legacy-peer-deps"),
            "{cmd} --help must contain --legacy-peer-deps"
        );
        assert!(
            stdout.contains("--strict-peer-deps"),
            "{cmd} --help must contain --strict-peer-deps"
        );
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

#[test]
fn test_audit_advisories_json_gated_by_env() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-gating",
        "version": "1.0.0",
        "dependencies": {
            "vuln-pkg": "^1.0.0"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-gating",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-gating",
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
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let advisories_json = serde_json::json!({
        "vuln-pkg": [
            {
                "id": 999,
                "name": "vuln-pkg",
                "severity": "high",
                "vulnerable_versions": "<=1.0.0",
                "title": "Fake advisory",
                "url": "https://example.com/fake"
            }
        ]
    });
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    // Without RNPM_TEST_MOCK_ADVISORIES, advisories.json in project_dir is NOT read.
    // Offline/no registry will fail or not load the fake advisory.
    let output = Command::new(rnpm_bin)
        .arg("audit")
        .env_remove("RNPM_TEST_MOCK_ADVISORIES")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit");

    // The fake advisory should NOT have triggered the exit 1 with "Fake advisory"
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Fake advisory"),
        "Arbitrary project must not inject advisories without RNPM_TEST_MOCK_ADVISORIES"
    );
}

#[test]
fn test_audit_fix_force_diagnostics() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-fix",
        "version": "1.0.0"
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-fix",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-fix",
                "version": "1.0.0"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    // Test audit fix without vulns
    let output = Command::new(rnpm_bin)
        .args(["audit", "fix"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("found 0 vulnerabilities"));

    // Test audit fix --force diagnostic
    let output_force = Command::new(rnpm_bin)
        .args(["audit", "fix", "--force"])
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm audit fix --force");
    assert!(output_force.status.success());
    let stderr = String::from_utf8_lossy(&output_force.stderr);
    assert!(stderr.contains("npm warn using --force") || stderr.contains("npm warn audit"));
}

#[test]
fn test_ci_timing_wireup() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-ci-timing",
        "version": "1.0.0"
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!({
        "name": "test-ci-timing",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-ci-timing",
                "version": "1.0.0"
            }
        }
    });
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .args(["ci", "--timing"])
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm ci --timing");

    assert!(
        output.status.success(),
        "ci --timing should succeed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Timing Summary:"),
        "Must output Timing Summary: {stdout}"
    );
    assert!(stdout.contains("plan"), "Must contain plan phase: {stdout}");
    assert!(
        stdout.contains("metadata"),
        "Must contain metadata phase: {stdout}"
    );
    assert!(
        stdout.contains("Counters & Metrics:"),
        "Must output Counters & Metrics: {stdout}"
    );
}

#[test]
fn test_post_install_concise_audit_summary_no_full_table() {
    let registry = audit_packument_registry(1);
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();

    let pkg_json = serde_json::json!({
        "name": "test-concise-audit",
        "version": "1.0.0",
        "optionalDependencies": {
            "vuln-pkg": "1.0.0"
        }
    });
    fs::write(
        project_dir.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).unwrap(),
    )
    .unwrap();

    let lockfile_json = serde_json::json!(
        {
            "name": "test-concise-audit",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "test-concise-audit",
                    "version": "1.0.0",
                    "optionalDependencies": {
                        "vuln-pkg": "1.0.0"
                    }
                },
                "node_modules/vuln-pkg": {
                    "version": "1.0.0",
                    "optional": true,
                    "os": ["nonexistent_os"]
                }
            }
        }
    );
    fs::write(
        project_dir.join("package-lock.json"),
        serde_json::to_string_pretty(&lockfile_json).unwrap(),
    )
    .unwrap();

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
    fs::write(
        project_dir.join("advisories.json"),
        serde_json::to_string_pretty(&advisories_json).unwrap(),
    )
    .unwrap();

    let output = Command::new(rnpm_bin)
        .arg("install")
        .arg("--registry")
        .arg(&registry)
        .env("RNPM_TEST_MOCK_ADVISORIES", "1")
        .env_remove("NPM_CONFIG_AUDIT")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm install");

    assert!(
        output.status.success(),
        "install should succeed: {:?}",
        output
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 high severity vulnerability") || stdout.contains("found 1 vulnerability"),
        "Must output concise summary: {stdout}"
    );
    assert!(
        stdout.contains("npm audit fix"),
        "Must suggest npm audit fix: {stdout}"
    );
    assert!(
        !stdout.contains("# npm audit report"),
        "Must NOT output full advisory table during install: {stdout}"
    );
}
