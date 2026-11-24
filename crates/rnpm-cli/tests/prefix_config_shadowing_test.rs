use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_prefix_config_shadowing_run_script() {
    let tmp = tempdir().expect("tempdir");
    let outer_dir = tmp.path().join("outer");
    let sub_dir = outer_dir.join("sub");
    fs::create_dir_all(&sub_dir).expect("create sub_dir");

    // Outer directory has an .npmrc with a distinct config setting
    fs::write(
        outer_dir.join("package.json"),
        r#"{"name":"outer-pkg","version":"1.0.0"}"#,
    )
    .expect("write outer package.json");
    fs::write(
        outer_dir.join(".npmrc"),
        "test_pref_shadow_key=outer_shadow_val\n",
    )
    .expect("write outer .npmrc");

    // Sub directory has its own .npmrc and a package.json with a run script
    fs::write(
        sub_dir.join("package.json"),
        r#"{
  "name": "sub-pkg",
  "version": "1.0.0",
  "scripts": {
    "show": "node -e \"console.log('OUTPUT:' + (process.env.npm_config_test_pref_shadow_key || 'UNSET'))\""
  }
}"#,
    )
    .expect("write sub package.json");
    fs::write(
        sub_dir.join(".npmrc"),
        "test_pref_shadow_key=inner_sub_val\n",
    )
    .expect("write sub .npmrc");

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Invoke from outer_dir with --prefix ./sub
    let output = Command::new(rnpm_bin)
        .current_dir(&outer_dir)
        .args(["--prefix", "./sub", "run", "show"])
        .output()
        .expect("execute rnpm --prefix ./sub run show");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success(),
        "Command failed with code {:?}. Output:\n{combined}",
        output.status.code()
    );

    // Must resolve the prefix's .npmrc value, NOT the invocation directory's leaked value!
    assert!(
        combined.contains("inner_sub_val"),
        "Expected sub .npmrc value 'inner_sub_val' in output, got:\n{combined}"
    );
    assert!(
        !combined.contains("outer_shadow_val"),
        "Leaked outer .npmrc value 'outer_shadow_val' into prefixed script invocation!\n{combined}"
    );
}

#[test]
fn test_prefix_config_shadowing_run_env() {
    let tmp = tempdir().expect("tempdir");
    let outer_dir = tmp.path().join("outer");
    let sub_dir = outer_dir.join("sub");
    fs::create_dir_all(&sub_dir).expect("create sub_dir");

    fs::write(
        outer_dir.join("package.json"),
        r#"{"name":"outer-pkg","version":"1.0.0"}"#,
    )
    .expect("write outer package.json");
    fs::write(
        outer_dir.join(".npmrc"),
        "test_pref_env_key=outer_env_val\n",
    )
    .expect("write outer .npmrc");

    fs::write(
        sub_dir.join("package.json"),
        r#"{"name":"sub-pkg","version":"1.0.0"}"#,
    )
    .expect("write sub package.json");
    fs::write(
        sub_dir.join(".npmrc"),
        "test_pref_env_key=inner_env_val\n",
    )
    .expect("write sub .npmrc");

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");

    // Test with short flag -C as well
    let output = Command::new(rnpm_bin)
        .current_dir(&outer_dir)
        .args(["--prefix", "sub", "run", "env"])
        .output()
        .expect("execute rnpm --prefix sub run env");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}").to_lowercase();

    assert!(
        output.status.success(),
        "Command failed with code {:?}. Output:\n{stdout}\n{stderr}",
        output.status.code()
    );

    assert!(
        combined.contains("npm_config_test_pref_env_key=inner_env_val"),
        "Expected inner_env_val in lifecycle env output, got:\n{stdout}"
    );
    assert!(
        !combined.contains("outer_env_val"),
        "Leaked outer_env_val in lifecycle env output!\n{stdout}"
    );
}
