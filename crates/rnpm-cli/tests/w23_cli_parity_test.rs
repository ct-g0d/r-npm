use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_version_invalid_arg_no_eunknown() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "version-test-app",
        "version": "1.0.0"
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .args(["version", "invalid-arg"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm version");

    assert!(!out.status.success(), "Expected failure for invalid version");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm error Invalid version: invalid-arg"),
        "stderr should contain 'npm error Invalid version: invalid-arg', got: {stderr}"
    );
    assert!(
        !stderr.contains("code EUNKNOWN"),
        "stderr must NOT contain 'code EUNKNOWN', got: {stderr}"
    );
}

#[test]
fn test_completion_stdout_hashbang_line1() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let out = Command::new(rnpm_bin)
        .arg("completion")
        .env("MSYSTEM", "MINGW64")
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm completion");

    assert!(out.status.success(), "rnpm completion should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let line1 = lines.next().expect("Expected at least one line");
    let line2 = lines.next().expect("Expected at least two lines");

    assert_eq!(
        line1, "###-begin-npm-completion-###",
        "Line 1 must match npm 11.20.0 completion.js (which strips leading #! shebang)"
    );
    assert_eq!(line2, "#", "Line 2 must be '#'");
}

#[test]
fn test_outdated_before_flag_syntax() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "outdated-test-app",
        "version": "1.0.0"
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    // Test --before=<date>
    let out_eq = Command::new(rnpm_bin)
        .args(["outdated", "--before=2024-01-01"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm outdated --before=<date>");

    assert!(
        out_eq.status.success(),
        "rnpm outdated --before=<date> failed: {}",
        String::from_utf8_lossy(&out_eq.stderr)
    );

    // Test --before <date>
    let out_space = Command::new(rnpm_bin)
        .args(["outdated", "--before", "2024-01-01"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm outdated --before <date>");

    assert!(
        out_space.status.success(),
        "rnpm outdated --before <date> failed: {}",
        String::from_utf8_lossy(&out_space.stderr)
    );
}

#[test]
fn test_sbom_cyclonedx_missing_dependency_esbomproblems() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "sbom-missing-app",
        "version": "1.0.0",
        "dependencies": {
            "nonexistent-missing-dep": "^1.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .args(["sbom", "--sbom-format=cyclonedx"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm sbom");

    assert!(!out.status.success(), "Expected failure for missing dependency");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm error code ESBOMPROBLEMS"),
        "stderr should contain 'npm error code ESBOMPROBLEMS', got: {stderr}"
    );
    assert!(
        stderr.contains("missing: nonexistent-missing-dep@^1.0.0, required by sbom-missing-app@1.0.0"),
        "stderr should describe the missing dependency, got: {stderr}"
    );
}

#[test]
fn test_sbom_cyclonedx_invalid_dependency_esbomproblems() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "sbom-invalid-app",
        "version": "1.0.0",
        "dependencies": {
            "invalid-dep": "^2.0.0"
        }
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let dep_dir = tmp.path().join("node_modules").join("invalid-dep");
    fs::create_dir_all(&dep_dir).unwrap();
    let dep_pkg = serde_json::json!({
        "name": "invalid-dep",
        "version": "1.0.0"
    });
    fs::write(dep_dir.join("package.json"), dep_pkg.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .args(["sbom", "--sbom-format=cyclonedx"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm sbom");

    assert!(!out.status.success(), "Expected failure for invalid dependency");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("npm error code ESBOMPROBLEMS"),
        "stderr should contain 'npm error code ESBOMPROBLEMS', got: {stderr}"
    );
    assert!(
        stderr.contains("invalid: invalid-dep@1.0.0, ^2.0.0 required by sbom-invalid-app@1.0.0"),
        "stderr should describe the invalid dependency, got: {stderr}"
    );
}

#[test]
fn test_sbom_cyclonedx_extraneous_dependency_succeeds() {
    let tmp = tempdir().unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    let pkg_json = serde_json::json!({
        "name": "sbom-extraneous-app",
        "version": "1.0.0"
    });
    fs::write(tmp.path().join("package.json"), pkg_json.to_string()).unwrap();

    let extra_dir = tmp.path().join("node_modules").join("extra-dep");
    fs::create_dir_all(&extra_dir).unwrap();
    let extra_pkg = serde_json::json!({
        "name": "extra-dep",
        "version": "1.0.0"
    });
    fs::write(extra_dir.join("package.json"), extra_pkg.to_string()).unwrap();

    let out = Command::new(rnpm_bin)
        .args(["sbom", "--sbom-format=cyclonedx"])
        .current_dir(tmp.path())
        .output()
        .expect("Failed to execute rnpm sbom");

    assert!(
        out.status.success(),
        "Expected success for extraneous dependency, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("cdx:npm:package:extraneous"),
        "stdout should mark dependency as extraneous, got: {stdout}"
    );
}
