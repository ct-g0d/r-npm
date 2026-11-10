use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_file_spec_normalization_parity() {
    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let temp = tempdir().unwrap();

    // 1. Create sibling package
    let sibling_dir = temp.path().join("sibling");
    fs::create_dir_all(&sibling_dir).unwrap();
    fs::write(
        sibling_dir.join("package.json"),
        r#"{"name":"sibling","version":"1.0.0"}"#,
    )
    .unwrap();

    // 2. Create absolute target package
    let abs_dir = temp.path().join("abspkg");
    fs::create_dir_all(&abs_dir).unwrap();
    fs::write(
        abs_dir.join("package.json"),
        r#"{"name":"abspkg","version":"1.0.0"}"#,
    )
    .unwrap();

    // 3. Create consumer app
    let app_dir = temp.path().join("app");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(
        app_dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();

    // Create subpackage inside consumer app
    let sub_dir = app_dir.join("subpkg");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(
        sub_dir.join("package.json"),
        r#"{"name":"subpkg","version":"1.0.0"}"#,
    )
    .unwrap();

    // Install file:./subpkg
    let status1 = Command::new(rnpm_bin)
        .current_dir(&app_dir)
        .args(["install", "file:./subpkg"])
        .status()
        .expect("Failed to run rnpm install file:./subpkg");
    assert!(status1.success());

    // Install file:../sibling
    let status2 = Command::new(rnpm_bin)
        .current_dir(&app_dir)
        .args(["install", "file:../sibling"])
        .status()
        .expect("Failed to run rnpm install file:../sibling");
    assert!(status2.success());

    // Install file:///abs_path
    let abs_posix = abs_dir.to_str().unwrap().replace('\\', "/");
    let abs_file_url = if abs_posix.starts_with('/') {
        format!("file://{abs_posix}")
    } else {
        format!("file:///{abs_posix}")
    };

    let status3 = Command::new(rnpm_bin)
        .current_dir(&app_dir)
        .args(["install", &abs_file_url])
        .status()
        .expect("Failed to run rnpm install file:///abs");
    assert!(status3.success());

    // Verify package.json dependencies
    let pkg_json_str = fs::read_to_string(app_dir.join("package.json")).unwrap();
    let pkg_json: serde_json::Value = serde_json::from_str(&pkg_json_str).unwrap();
    let deps = pkg_json.get("dependencies").unwrap();

    assert_eq!(deps.get("subpkg").unwrap().as_str().unwrap(), "file:subpkg");
    assert_eq!(deps.get("sibling").unwrap().as_str().unwrap(), "file:../sibling");
    assert_eq!(deps.get("abspkg").unwrap().as_str().unwrap(), "file:../abspkg");

    // Verify package-lock.json
    let lock_str = fs::read_to_string(app_dir.join("package-lock.json")).unwrap();
    let lock_json: serde_json::Value = serde_json::from_str(&lock_str).unwrap();
    let packages = lock_json.get("packages").unwrap();

    assert_eq!(
        packages.get("").unwrap().get("dependencies").unwrap().get("subpkg").unwrap().as_str().unwrap(),
        "file:subpkg"
    );
    assert_eq!(
        packages.get("").unwrap().get("dependencies").unwrap().get("sibling").unwrap().as_str().unwrap(),
        "file:../sibling"
    );
    assert_eq!(
        packages.get("").unwrap().get("dependencies").unwrap().get("abspkg").unwrap().as_str().unwrap(),
        "file:../abspkg"
    );

    assert_eq!(
        packages.get("node_modules/subpkg").unwrap().get("resolved").unwrap().as_str().unwrap(),
        "subpkg"
    );
    assert_eq!(
        packages.get("node_modules/sibling").unwrap().get("resolved").unwrap().as_str().unwrap(),
        "../sibling"
    );
    assert_eq!(
        packages.get("node_modules/abspkg").unwrap().get("resolved").unwrap().as_str().unwrap(),
        "../abspkg"
    );
}
