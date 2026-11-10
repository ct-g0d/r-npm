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
