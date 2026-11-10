use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn run(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_rnpm"))
        .current_dir(dir)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn fixture(dir: &Path) {
    fs::write(
        dir.join("package.json"),
        "{\n  \"name\": \"parity-fixture\",\n  \"version\": \"1.0.0\",\n  \"private\": true\n}\n",
    )
    .unwrap();
}

#[test]
fn init_yes_preserves_order_and_adds_commonjs_type() {
    let tmp = tempdir().unwrap();
    fixture(tmp.path());
    let output = run(tmp.path(), &["init", "-y", "--silent"]);
    let expected = "{\n  \"name\": \"parity-fixture\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"description\": \"\",\n  \"main\": \"index.js\",\n  \"scripts\": {\n    \"test\": \"echo \\\"Error: no test specified\\\" && exit 1\"\n  },\n  \"keywords\": [],\n  \"author\": \"\",\n  \"license\": \"ISC\",\n  \"type\": \"commonjs\"\n}\n";
    assert_eq!(
        fs::read_to_string(tmp.path().join("package.json")).unwrap(),
        expected
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "Wrote to {}:\n\n{}\n\n\n",
            tmp.path().join("package.json").display(),
            expected.trim_end()
        )
    );
}

#[test]
fn test_init_live_npm_comparison() {
    let tmp_rnpm = tempdir().unwrap();
    let tmp_npm = tempdir().unwrap();

    let rnpm_bin = env!("CARGO_BIN_EXE_rnpm");
    let rnpm_res = Command::new(rnpm_bin)
        .current_dir(tmp_rnpm.path())
        .args(["init", "-y"])
        .output()
        .expect("rnpm init -y failed");
    assert!(rnpm_res.status.success());

    let npm_res = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "npm.cmd", "init", "-y"])
        .current_dir(tmp_npm.path())
        .output();
    if let Ok(npm_out) = npm_res {
        if npm_out.status.success() {
            let rnpm_pkg: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(tmp_rnpm.path().join("package.json")).unwrap()
            ).unwrap();
            let npm_pkg: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(tmp_npm.path().join("package.json")).unwrap()
            ).unwrap();

            assert_eq!(rnpm_pkg.get("version"), npm_pkg.get("version"));
            assert_eq!(rnpm_pkg.get("main"), npm_pkg.get("main"));
            assert_eq!(rnpm_pkg.get("scripts"), npm_pkg.get("scripts"));
            assert_eq!(rnpm_pkg.get("license"), npm_pkg.get("license"));

            let rnpm_stdout = String::from_utf8_lossy(&rnpm_res.stdout);
            let npm_stdout = String::from_utf8_lossy(&npm_out.stdout);
            assert!(rnpm_stdout.starts_with("Wrote to "));
            assert!(npm_stdout.starts_with("Wrote to "));
        }
    }
}

