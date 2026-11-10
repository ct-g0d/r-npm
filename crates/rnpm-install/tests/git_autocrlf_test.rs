use rnpm_install::{InstallOptions, Installer};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn run_git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("Failed to execute git");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

struct EnvVarGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, val: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(ref prev) = self.prev {
            std::env::set_var(self.key, prev);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[tokio::test]
async fn test_git_dependency_honors_autocrlf_and_preserves_cr() {
    // Isolated temp git config file to avoid touching user's real ~/.gitconfig
    let config_dir = tempdir().unwrap();
    let gitconfig_path = config_dir.path().join(".gitconfig");

    let _global_guard = EnvVarGuard::set("GIT_CONFIG_GLOBAL", gitconfig_path.to_str().unwrap());
    let _nosystem_guard = EnvVarGuard::set("GIT_CONFIG_NOSYSTEM", "1");

    // Initialize test git repository with files having LF, CRLF, and lone CR bytes
    let repo_dir = tempdir().unwrap();
    run_git(repo_dir.path(), &["init"]);
    run_git(repo_dir.path(), &["config", "user.name", "Tester"]);
    run_git(repo_dir.path(), &["config", "user.email", "test@example.com"]);
    run_git(repo_dir.path(), &["config", "core.autocrlf", "false"]);
    run_git(repo_dir.path(), &["config", "core.eol", "lf"]);

    let manifest = serde_json::json!({
        "name": "crlf-git-dep",
        "version": "1.0.0"
    });
    std::fs::write(repo_dir.path().join("package.json"), manifest.to_string()).unwrap();
    std::fs::write(repo_dir.path().join("lf.txt"), b"line1\nline2\n").unwrap();
    std::fs::write(repo_dir.path().join("crlf.txt"), b"crlf1\r\ncrlf2\r\n").unwrap();
    std::fs::write(repo_dir.path().join("cr.txt"), b"cr1\rcr2\r").unwrap();

    run_git(repo_dir.path(), &["add", "."]);
    run_git(repo_dir.path(), &["commit", "-m", "add eol test files"]);

    let path_str = repo_dir.path().to_str().unwrap().replace('\\', "/");
    let git_url = if path_str.starts_with('/') {
        format!("git+file://{path_str}")
    } else {
        format!("git+file:///{path_str}")
    };

    // =========================================================================
    // Case 1: core.autocrlf = true (LF becomes CRLF, CRLF stays CRLF, CR stays CR)
    // =========================================================================
    std::fs::write(&gitconfig_path, "[core]\n\tautocrlf = true\n").unwrap();

    let proj1_dir = tempdir().unwrap();
    let cache1_dir = tempdir().unwrap();
    let consumer_manifest = serde_json::json!({
        "name": "consumer-crlf-true",
        "dependencies": {
            "crlf-git-dep": git_url.clone()
        }
    });
    std::fs::write(
        proj1_dir.path().join("package.json"),
        consumer_manifest.to_string(),
    )
    .unwrap();

    let mut installer1 = Installer::new(InstallOptions {
        project_dir: proj1_dir.path().to_path_buf(),
        cache_dir: Some(cache1_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    installer1
        .install()
        .await
        .expect("Install crlf git dep (autocrlf=true) failed");

    let dep_dir1 = proj1_dir.path().join("node_modules").join("crlf-git-dep");
    let lf_bytes1 = std::fs::read(dep_dir1.join("lf.txt")).unwrap();
    let crlf_bytes1 = std::fs::read(dep_dir1.join("crlf.txt")).unwrap();
    let cr_bytes1 = std::fs::read(dep_dir1.join("cr.txt")).unwrap();

    // When autocrlf=true, LF must become CRLF
    assert_eq!(
        lf_bytes1, b"line1\r\nline2\r\n",
        "LF must become CRLF under core.autocrlf=true"
    );
    // CRLF must remain CRLF
    assert_eq!(crlf_bytes1, b"crlf1\r\ncrlf2\r\n", "CRLF must remain CRLF");
    // Lone CR must remain lone CR
    assert_eq!(cr_bytes1, b"cr1\rcr2\r", "Lone CR must remain lone CR");

    // =========================================================================
    // Case 2: core.autocrlf = false (LF remains LF, CRLF stays CRLF, CR stays CR)
    // =========================================================================
    std::fs::write(&gitconfig_path, "[core]\n\tautocrlf = false\n").unwrap();

    let proj2_dir = tempdir().unwrap();
    let cache2_dir = tempdir().unwrap();
    let consumer_manifest2 = serde_json::json!({
        "name": "consumer-crlf-false",
        "dependencies": {
            "crlf-git-dep": git_url.clone()
        }
    });
    std::fs::write(
        proj2_dir.path().join("package.json"),
        consumer_manifest2.to_string(),
    )
    .unwrap();

    let mut installer2 = Installer::new(InstallOptions {
        project_dir: proj2_dir.path().to_path_buf(),
        cache_dir: Some(cache2_dir.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    installer2
        .install()
        .await
        .expect("Install crlf git dep (autocrlf=false) failed");

    let dep_dir2 = proj2_dir.path().join("node_modules").join("crlf-git-dep");
    let lf_bytes2 = std::fs::read(dep_dir2.join("lf.txt")).unwrap();
    let crlf_bytes2 = std::fs::read(dep_dir2.join("crlf.txt")).unwrap();
    let cr_bytes2 = std::fs::read(dep_dir2.join("cr.txt")).unwrap();

    // When autocrlf=false, LF must remain LF
    assert_eq!(
        lf_bytes2, b"line1\nline2\n",
        "LF must remain LF under core.autocrlf=false"
    );
    // CRLF must remain CRLF
    assert_eq!(crlf_bytes2, b"crlf1\r\ncrlf2\r\n", "CRLF must remain CRLF");
    // Lone CR must remain lone CR
    assert_eq!(cr_bytes2, b"cr1\rcr2\r", "Lone CR must remain lone CR");
}
