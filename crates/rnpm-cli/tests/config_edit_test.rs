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

#[test]
fn test_bare_config_edit_defaults_to_user_config_when_project_npmrc_exists() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    std::fs::create_dir_all(&project_dir).unwrap();
    let user_home = tmp.path().join("home");
    std::fs::create_dir_all(&user_home).unwrap();
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Existing project .npmrc
    let project_npmrc = project_dir.join(".npmrc");
    std::fs::write(&project_npmrc, "; original project config\n").unwrap();

    let user_npmrc = user_home.join(".npmrc");

    #[cfg(windows)]
    let editor_cmd = {
        let script = tmp.path().join("test_editor1.bat");
        std::fs::write(&script, "@echo off\r\necho bare_edit=user_success >> \"%~1\"\r\nexit /b 0\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let editor_cmd = {
        let script = tmp.path().join("test_editor1.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'bare_edit=user_success' >> \"$1\"\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    // Run bare `rnpm config edit` without --location
    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg(format!("--editor={editor_cmd}"))
        .current_dir(&project_dir)
        .env("HOME", &user_home)
        .env("USERPROFILE", &user_home)
        .env_remove("npm_config_userconfig")
        .env_remove("NPM_CONFIG_USERCONFIG")
        .env_remove("USERCONFIG")
        .output()
        .expect("Failed to execute bare rnpm config edit");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Project .npmrc must remain untouched!
    let project_content = std::fs::read_to_string(&project_npmrc).unwrap();
    assert_eq!(project_content, "; original project config\n");

    // User .npmrc must have been created/edited!
    assert!(user_npmrc.exists(), "User .npmrc was not created");
    let user_content = std::fs::read_to_string(&user_npmrc).unwrap();
    assert!(user_content.contains("; npm userconfig file:"));
    assert!(user_content.contains("bare_edit=user_success"));
}

#[test]
fn test_config_edit_honors_explicit_userconfig_cli_flag() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    std::fs::create_dir_all(&project_dir).unwrap();
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    let custom_userconfig = custom_dir.join("my-user.npmrc");
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Project has its own .npmrc
    let project_npmrc = project_dir.join(".npmrc");
    std::fs::write(&project_npmrc, "; project .npmrc\n").unwrap();

    #[cfg(windows)]
    let editor_cmd = {
        let script = tmp.path().join("test_editor2.bat");
        std::fs::write(&script, "@echo off\r\necho custom_flag=flag_success >> \"%~1\"\r\nexit /b 0\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let editor_cmd = {
        let script = tmp.path().join("test_editor2.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'custom_flag=flag_success' >> \"$1\"\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg(format!("--editor={editor_cmd}"))
        .arg(format!("--userconfig={}", custom_userconfig.display()))
        .current_dir(&project_dir)
        .output()
        .expect("Failed to execute rnpm config edit with --userconfig");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Project .npmrc must remain untouched!
    let project_content = std::fs::read_to_string(&project_npmrc).unwrap();
    assert_eq!(project_content, "; project .npmrc\n");

    // Custom userconfig file must receive the edit and header!
    assert!(custom_userconfig.exists(), "Custom userconfig file was not created");
    let custom_content = std::fs::read_to_string(&custom_userconfig).unwrap();
    assert!(custom_content.contains("; npm userconfig file:"));
    assert!(custom_content.contains("custom_flag=flag_success"));
}

#[test]
fn test_config_edit_honors_npm_config_userconfig_env() {
    let tmp = tempdir().unwrap();
    let project_dir = tmp.path().join("proj");
    std::fs::create_dir_all(&project_dir).unwrap();
    let custom_dir = tmp.path().join("custom_env");
    std::fs::create_dir_all(&custom_dir).unwrap();
    let env_userconfig = custom_dir.join("env-user.npmrc");
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Project has its own .npmrc
    let project_npmrc = project_dir.join(".npmrc");
    std::fs::write(&project_npmrc, "; project .npmrc\n").unwrap();

    #[cfg(windows)]
    let editor_cmd = {
        let script = tmp.path().join("test_editor3.bat");
        std::fs::write(&script, "@echo off\r\necho env_flag=env_success >> \"%~1\"\r\nexit /b 0\r\n").unwrap();
        script.to_string_lossy().to_string()
    };

    #[cfg(not(windows))]
    let editor_cmd = {
        let script = tmp.path().join("test_editor3.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'env_flag=env_success' >> \"$1\"\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
        script.to_string_lossy().to_string()
    };

    let output = Command::new(rnpm_bin)
        .arg("config")
        .arg("edit")
        .arg(format!("--editor={editor_cmd}"))
        .env("npm_config_userconfig", &env_userconfig)
        .current_dir(&project_dir)
        .output()
        .expect("Failed to execute rnpm config edit with npm_config_userconfig");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Project .npmrc must remain untouched!
    let project_content = std::fs::read_to_string(&project_npmrc).unwrap();
    assert_eq!(project_content, "; project .npmrc\n");

    // Env userconfig file must receive the edit and header!
    assert!(env_userconfig.exists(), "Env userconfig file was not created");
    let env_content = std::fs::read_to_string(&env_userconfig).unwrap();
    assert!(env_content.contains("; npm userconfig file:"));
    assert!(env_content.contains("env_flag=env_success"));
}
