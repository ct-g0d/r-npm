use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

fn rnpm_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rnpm")
}

fn run_cmd(dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(rnpm_bin());
    cmd.current_dir(dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args(args);
    cmd.output().expect("failed to execute rnpm")
}

fn git_cmd(path: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(path);
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", path.join(".empty_gitconfig"));
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

fn init_git_repo(path: &Path) {
    let _ = fs::write(path.join(".empty_gitconfig"), "");
    let out = git_cmd(path)
        .args(["init"])
        .output()
        .expect("git init failed");
    assert!(out.status.success(), "git init failed: {:?}", out);

    git_cmd(path)
        .args(["config", "user.name", "Test User"])
        .output()
        .expect("git config user.name failed");

    git_cmd(path)
        .args(["config", "user.email", "test@example.com"])
        .output()
        .expect("git config user.email failed");

    git_cmd(path)
        .args(["config", "commit.gpgSign", "false"])
        .output()
        .expect("git config commit.gpgSign failed");

    git_cmd(path)
        .args(["config", "tag.gpgSign", "false"])
        .output()
        .expect("git config tag.gpgSign failed");
}

#[test]
fn test_config_fix_repairs_unscoped_auth_and_deprecated_keys() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let npmrc_content = r#"
# Sample configuration
; Another comment
_authToken=secret123
_auth=base64auth
email=testuser@example.com
username=alice
_password=secretpass
global-style=true
legacy-bundling=true
only=prod
production=true
shrinkwrap=false
also=dev
dev=true
optional=false
init.author.name=Alice Author
init.author.email=alice@example.com
init.author.url=https://alice.example.com
init.license=MIT
init.version=2.0.0
_authtoken=to-delete
-authtoken=also-delete
valid-setting=keep-me
"#;
    fs::write(root.join(".npmrc"), npmrc_content).unwrap();

    let output = run_cmd(root, &["config", "fix", "--location=project"], &[]);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let repaired = fs::read_to_string(root.join(".npmrc")).unwrap();

    // Verify auth keys scoped to registry
    assert!(repaired.contains("//registry.npmjs.org/:_authToken=secret123"));
    assert!(repaired.contains("//registry.npmjs.org/:_auth=base64auth"));
    assert!(repaired.contains("//registry.npmjs.org/:email=testuser@example.com"));
    assert!(repaired.contains("//registry.npmjs.org/:username=alice"));
    assert!(repaired.contains("//registry.npmjs.org/:_password=secretpass"));

    // Verify deprecated keys repaired
    assert!(repaired.contains("install-strategy=shallow"));
    assert!(repaired.contains("install-strategy=nested"));
    assert!(repaired.contains("omit=dev"));
    assert!(repaired.contains("package-lock=false"));
    assert!(repaired.contains("include=dev"));
    assert!(repaired.contains("omit=optional"));
    assert!(repaired.contains("init-author-name=Alice Author"));
    assert!(repaired.contains("init-author-email=alice@example.com"));
    assert!(repaired.contains("init-author-url=https://alice.example.com"));
    assert!(repaired.contains("init-license=MIT"));
    assert!(repaired.contains("init-version=2.0.0"));

    // Verify deleted keys
    assert!(!repaired.contains("_authtoken"));
    assert!(!repaired.contains("-authtoken"));

    // Verify comments and valid settings preserved
    assert!(repaired.contains("# Sample configuration"));
    assert!(repaired.contains("; Another comment"));
    assert!(repaired.contains("valid-setting=keep-me"));
}

#[test]
fn test_config_fix_deletes_unmatched_username_or_password() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join(".npmrc"), "username=solo_user\n").unwrap();
    let output = run_cmd(root, &["config", "fix", "--location=project"], &[]);
    assert!(output.status.success());
    let content = fs::read_to_string(root.join(".npmrc")).unwrap();
    assert!(!content.contains("username"));

    fs::write(root.join(".npmrc"), "_password=solo_pass\n").unwrap();
    let output2 = run_cmd(root, &["config", "fix", "--location=project"], &[]);
    assert!(output2.status.success());
    let content2 = fs::read_to_string(root.join(".npmrc")).unwrap();
    assert!(!content2.contains("_password"));
}

#[test]
fn test_completion_script_generation() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // When COMP_CWORD/COMP_LINE/COMP_POINT are not set, output init script
    let out_default = run_cmd(root, &["completion"], &[("MSYSTEM", "MINGW64")]);
    assert!(out_default.status.success());
    let stdout = String::from_utf8_lossy(&out_default.stdout);
    assert!(stdout.contains("###-begin-rnpm-completion-###"));
    assert!(stdout.contains("_rnpm_completion"));
    assert!(stdout.contains("complete -o default -F _rnpm_completion rnpm"));

    #[cfg(windows)]
    {
        let out_win = run_cmd(root, &["completion"], &[]);
        assert!(!out_win.status.success());
        let stderr = String::from_utf8_lossy(&out_win.stderr);
        assert!(stderr.contains("npm completion supported only in MINGW / Git bash on Windows"));
    }

    let out_fish = run_cmd(root, &["completion", "fish"], &[]);
    assert!(out_fish.status.success());
    let stdout_fish = String::from_utf8_lossy(&out_fish.stdout);
    assert!(stdout_fish.contains("complete -c rnpm -f -a"));

    let out_pwsh = run_cmd(root, &["completion", "powershell"], &[]);
    assert!(out_pwsh.status.success());
    let stdout_pwsh = String::from_utf8_lossy(&out_pwsh.stdout);
    assert!(stdout_pwsh.contains("Register-ArgumentCompleter -Native -CommandName rnpm"));
}

#[test]
fn test_dynamic_completion_subcommands_and_flags() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Complete subcommands starting with "in"
    let out = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "1"),
            ("COMP_LINE", "rnpm in"),
            ("COMP_POINT", "7"),
        ],
    );
    assert!(out.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(lines.contains(&"init"));
    assert!(lines.contains(&"install"));
    assert!(!lines.contains(&"test"));
    assert!(!lines.contains(&"version"));

    // 2. Complete flags starting with "--gl"
    let out_flag = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "1"),
            ("COMP_LINE", "rnpm --gl"),
            ("COMP_POINT", "9"),
        ],
    );
    assert!(out_flag.status.success());
    let flag_lines: Vec<&str> = std::str::from_utf8(&out_flag.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(flag_lines.contains(&"--global"));
}

#[test]
fn test_dynamic_completion_run_scripts() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "completion-app",
  "scripts": {
    "build": "vite build",
    "test": "vitest",
    "lint": "eslint ."
  }
}"#,
    )
    .unwrap();

    // Test completing script names when typing `rnpm run <TAB>`
    let out = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "2"),
            ("COMP_LINE", "rnpm run "),
            ("COMP_POINT", "9"),
        ],
    );
    assert!(out.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(lines.contains(&"build"));
    assert!(lines.contains(&"test"));
    assert!(lines.contains(&"lint"));

    // Test completing with prefix `rnpm run b<TAB>`
    let out_prefix = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "2"),
            ("COMP_LINE", "rnpm run b"),
            ("COMP_POINT", "10"),
        ],
    );
    assert!(out_prefix.status.success());
    let prefix_lines: Vec<&str> = std::str::from_utf8(&out_prefix.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(prefix_lines.contains(&"build"));
    assert!(!prefix_lines.contains(&"test"));
    assert!(!prefix_lines.contains(&"lint"));
}

#[test]
fn test_dynamic_completion_config_and_cache() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. `rnpm config <TAB>`
    let out_cfg = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "2"),
            ("COMP_LINE", "rnpm config "),
            ("COMP_POINT", "12"),
        ],
    );
    assert!(out_cfg.status.success());
    let cfg_lines: Vec<&str> = std::str::from_utf8(&out_cfg.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(cfg_lines.contains(&"set"));
    assert!(cfg_lines.contains(&"get"));
    assert!(cfg_lines.contains(&"delete"));
    assert!(cfg_lines.contains(&"fix"));

    // 2. `rnpm config fix <TAB>` -> completes known config keys
    let out_cfg_get = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "3"),
            ("COMP_LINE", "rnpm config get "),
            ("COMP_POINT", "16"),
        ],
    );
    assert!(out_cfg_get.status.success());
    let key_lines: Vec<&str> = std::str::from_utf8(&out_cfg_get.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(key_lines.contains(&"registry"));
    assert!(key_lines.contains(&"init-author-name"));
    assert!(key_lines.contains(&"shell"));

    // 3. `rnpm cache <TAB>`
    let out_cache = run_cmd(
        root,
        &["completion"],
        &[
            ("COMP_CWORD", "2"),
            ("COMP_LINE", "rnpm cache "),
            ("COMP_POINT", "11"),
        ],
    );
    assert!(out_cache.status.success());
    let cache_lines: Vec<&str> = std::str::from_utf8(&out_cache.stdout)
        .unwrap()
        .lines()
        .collect();
    assert!(cache_lines.contains(&"clean"));
    assert!(cache_lines.contains(&"verify"));
    assert!(cache_lines.contains(&"ls"));
    assert!(cache_lines.contains(&"add"));
}

#[test]
fn test_init_knobs_from_npmrc() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let npmrc_content = r#"
init-author-name=Jane Doe
init-author-email=jane@example.org
init-author-url=https://jane.example.org
init-license=Apache-2.0
init-version=3.1.4
init-type=module
init-module=dist/index.cjs
"#;
    fs::write(root.join(".npmrc"), npmrc_content).unwrap();

    let out = run_cmd(root, &["init", "-y"], &[]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let pkg_json_str = fs::read_to_string(root.join("package.json")).unwrap();
    let pkg: serde_json::Value = serde_json::from_str(&pkg_json_str).unwrap();

    assert_eq!(
        pkg.get("author").and_then(|v| v.as_str()),
        Some("Jane Doe <jane@example.org> (https://jane.example.org)")
    );
    assert_eq!(pkg.get("license").and_then(|v| v.as_str()), Some("Apache-2.0"));
    assert_eq!(pkg.get("version").and_then(|v| v.as_str()), Some("3.1.4"));
    assert_eq!(pkg.get("type").and_then(|v| v.as_str()), Some("module"));
    assert_eq!(pkg.get("main").and_then(|v| v.as_str()), Some("dist/index.cjs"));
}

#[test]
fn test_version_knobs_tag_prefix_and_commit_hooks() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    init_git_repo(root);

    let pkg_json = r#"{
  "name": "version-knobs-pkg",
  "version": "1.0.0"
}"#;
    fs::write(root.join("package.json"), pkg_json).unwrap();

    git_cmd(root).args(["add", "package.json"]).output().unwrap();
    git_cmd(root).args(["commit", "-m", "initial"]).output().unwrap();

    // 1. Create failing pre-commit hook
    let hooks_dir = root.join(".git").join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();
    let pre_commit = hooks_dir.join(if cfg!(windows) { "pre-commit.bat" } else { "pre-commit" });
    fs::write(&pre_commit, if cfg!(windows) { "@echo off\r\nexit /b 1\r\n" } else { "#!/bin/sh\nexit 1\n" }).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&pre_commit).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&pre_commit, perms).unwrap();
    }

    // 2. Configure tag-version-prefix and commit-hooks=false in .npmrc
    let npmrc_content = "tag-version-prefix=release-\ncommit-hooks=false\n";
    fs::write(root.join(".npmrc"), npmrc_content).unwrap();

    // 3. Run rnpm version minor
    let out = run_cmd(root, &["version", "minor"], &[]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("release-1.1.0"), "stdout: {stdout}");

    // Verify tag was created with custom prefix
    let tag_check = git_cmd(root).args(["tag", "-l", "release-1.1.0"]).output().unwrap();
    let tag_out = String::from_utf8_lossy(&tag_check.stdout);
    assert!(tag_out.contains("release-1.1.0"));
}

#[test]
fn test_explore_shell_from_npmrc() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let pkg_dir = root.join("node_modules").join("explore-test-pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "explore-test-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Write a node script to create the marker file
    let out_file = root.join("explore_output.txt");
    let record_js = root.join("record.js");
    let script_content = format!(
        "require('fs').writeFileSync({}, 'explore_ok');",
        serde_json::to_string(&out_file.to_string_lossy().to_string()).unwrap()
    );
    fs::write(&record_js, script_content).unwrap();

    // Configure shell in .npmrc
    let shell_val = if cfg!(windows) {
        std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    };
    fs::write(root.join(".npmrc"), format!("shell={shell_val}\n")).unwrap();

    let out = run_cmd(
        root,
        &[
            "explore",
            "explore-test-pkg",
            "--",
            "node",
            record_js.to_str().unwrap(),
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "explore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_file.exists(), "Output marker file should have been created");
    assert_eq!(fs::read_to_string(&out_file).unwrap(), "explore_ok");
}
