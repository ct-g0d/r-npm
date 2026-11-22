use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_config_edit_launches_editor_and_creates_header() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    #[cfg(windows)]
    let editor_cmd = {
        let script = project_dir.join("test_editor.bat");
        std::fs::write(&script, "@echo off\r\necho injected_option=injected_val >> \"%~1\"\r\nexit /b 0\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let editor_cmd = {
        let script = project_dir.join("test_editor.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'injected_option=injected_val' >> \"$1\"\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    let target_npmrc = project_dir.join(".npmrc");
    assert!(!target_npmrc.exists(), "Target .npmrc should not exist prior to edit");

    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg(format!("--editor={editor_cmd}"))
        .arg("--location=project")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm config edit");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(target_npmrc.exists(), "Target .npmrc should have been created");
    let content = std::fs::read_to_string(&target_npmrc).unwrap();

    // Verify npm's comment header is present
    assert!(
        content.contains("; npm projectconfig file:"),
        "Missing header comment in .npmrc:\n{content}"
    );
    assert!(
        content.contains("; this is a simple ini-formatted file"),
        "Missing ini format notice in .npmrc:\n{content}"
    );
    assert!(
        content.contains("; lines that start with semi-colons are comments"),
        "Missing comments notice in .npmrc:\n{content}"
    );

    // Verify the editor test-script executed and appended its edit
    assert!(
        content.contains("injected_option=injected_val"),
        "Editor did not append configured option into .npmrc:\n{content}"
    );
}

#[test]
fn test_config_edit_editor_env_precedence() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    #[cfg(windows)]
    let editor_cmd = {
        let script = project_dir.join("env_editor.bat");
        std::fs::write(&script, "@echo off\r\necho env_option=env_val >> \"%~1\"\r\nexit /b 0\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let editor_cmd = {
        let script = project_dir.join("env_editor.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'env_option=env_val' >> \"$1\"\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    let target_npmrc = project_dir.join(".npmrc");

    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg("--location=project")
        .env("EDITOR", &editor_cmd)
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm config edit with EDITOR env");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&target_npmrc).unwrap();
    assert!(
        content.contains("env_option=env_val"),
        "EDITOR environment variable editor was not executed:\n{content}"
    );
}

#[test]
fn test_config_edit_propagates_editor_failure() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    #[cfg(windows)]
    let failing_editor = {
        let script = project_dir.join("failing_editor.bat");
        std::fs::write(&script, "@echo off\r\nexit /b 42\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let failing_editor = {
        let script = project_dir.join("failing_editor.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 42\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg(format!("--editor={failing_editor}"))
        .arg("--location=project")
        .current_dir(project_dir)
        .output()
        .expect("Failed to execute rnpm config edit");

    assert!(!output.status.success(), "Command should have failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("42"),
        "Expected error exit code 42 in stderr: {stderr}"
    );
}
