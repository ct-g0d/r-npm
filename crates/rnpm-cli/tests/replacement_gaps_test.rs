use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

mod common;

fn run(oracle: bool, dir: &Path, config: &Path, args: &[&str]) -> Output {
    let isolated = common::isolated_npm(config);
    let mut cmd = if oracle {
        common::isolated_npm(config)
    } else {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rnpm"));
        for (key, value) in isolated.get_envs() {
            if let Some(value) = value {
                cmd.env(key, value);
            } else {
                cmd.env_remove(key);
            }
        }
        cmd
    };
    cmd.current_dir(dir)
        .args(args)
        .env("NPM_CONFIG_AUDIT", "false")
        .env("NPM_CONFIG_FUND", "false")
        .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
        .env("NPM_CONFIG_UNICODE", "true")
        .output()
        .unwrap()
}

#[test]
fn pack_ignore_precedence_and_archive_bytes_match_npm() {
    for (files, root_ignore, nested_ignore) in [
        (vec!["keep.js"], "keep.js\n", ""),
        (vec!["lib"], "lib\n", "omit.js\n"),
        (vec!["lib/keep.js"], "lib\n", "keep.js\n"),
    ] {
        let tmp = tempdir().unwrap();
        let mut archives = Vec::new();
        let mut json = Vec::new();
        for oracle in [true, false] {
            let dir = tmp.path().join(if oracle { "npm" } else { "rnpm" });
            fs::create_dir_all(dir.join("lib")).unwrap();
            let manifest =
                serde_json::json!({"name":"archive-parity", "version":"1.0.0", "files":files});
            fs::write(dir.join("package.json"), manifest.to_string()).unwrap();
            fs::write(dir.join(".npmignore"), root_ignore).unwrap();
            fs::write(dir.join("lib/.npmignore"), nested_ignore).unwrap();
            for path in ["keep.js", "lib/keep.js", "lib/omit.js"] {
                fs::write(dir.join(path), path).unwrap();
            }
            let out = run(
                oracle,
                &dir,
                &tmp.path().join(format!("config-{oracle}")),
                &["pack", "--json", "--ignore-scripts"],
            );
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            json.push(serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap());
            archives.push(fs::read(dir.join("archive-parity-1.0.0.tgz")).unwrap());
        }
        assert_eq!(json[0], json[1]);
        assert_eq!(
            archives[0], archives[1],
            "Complete compressed bytes must match"
        );
    }
}

#[test]
fn ls_optional_peer_missing_invalid_and_extraneous_match_npm() {
    for kind in ["missing", "invalid", "extraneous", "only-extraneous"] {
        for json in [false, true] {
            let tmp = tempdir().unwrap();
            let mut outputs = Vec::new();
            for oracle in [true, false] {
                let dir = tmp.path().join(if oracle { "npm" } else { "rnpm" });
                fs::create_dir_all(&dir).unwrap();
                let manifest = if kind == "only-extraneous" {
                    serde_json::json!({"name":"root", "version":"1.0.0"})
                } else {
                    serde_json::json!({"name":"root","version":"1.0.0","dependencies":{"required":"^1.0.0"},"optionalDependencies":{"optional":"1.0.0"},"peerDependencies":{"peer":"1.0.0","optional-peer":"1.0.0"},"peerDependenciesMeta":{"optional-peer":{"optional":true}}})
                };
                fs::write(dir.join("package.json"), manifest.to_string()).unwrap();
                for (name, version) in [
                    (
                        "required",
                        if kind == "invalid" { "2.0.0" } else { "1.0.0" },
                    ),
                    ("extra", "1.0.0"),
                ] {
                    if (name == "required" && kind != "missing" && kind != "only-extraneous")
                        || (name == "extra" && kind.contains("extraneous"))
                    {
                        fs::create_dir_all(dir.join("node_modules").join(name)).unwrap();
                        fs::write(
                            dir.join("node_modules").join(name).join("package.json"),
                            serde_json::json!({"name":name,"version":version}).to_string(),
                        )
                        .unwrap();
                    }
                }
                let args = if json {
                    vec!["ls", "--all", "--json"]
                } else {
                    vec!["ls", "--all"]
                };
                let out = run(
                    oracle,
                    &dir,
                    &tmp.path().join(format!("config-{oracle}")),
                    &args,
                );
                let stdout = String::from_utf8(out.stdout)
                    .unwrap()
                    .replace(&dir.to_string_lossy().replace('\\', "\\\\"), "<fixture>")
                    .replace(dir.to_string_lossy().as_ref(), "<fixture>")
                    .replace("\r\n", "\n");
                outputs.push((out.status.code(), stdout));
            }
            assert_eq!(outputs[0], outputs[1], "{kind}, json={json}");
        }
    }
}

#[test]
fn empty_uninstall_dedupe_pkg_and_link_outputs_match_npm() {
    for args in [
        vec!["uninstall", "absent"],
        vec!["dedupe"],
        vec!["find-dupes"],
        vec!["pkg", "get", "name"],
        vec!["link", "--ignore-scripts"],
        vec!["install-test"],
        vec!["install-ci-test"],
    ] {
        let tmp = tempdir().unwrap();
        let mut outputs = Vec::new();
        for oracle in [true, false] {
            let dir = tmp.path().join(if oracle { "npm" } else { "rnpm" });
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("package.json"),
                r#"{"name":"empty-project","version":"1.0.0","scripts":{"test":"node -p 123"}}"#,
            )
            .unwrap();
            if args[0] == "install-ci-test" {
                assert!(run(
                    oracle,
                    &dir,
                    &tmp.path().join(format!("config-{oracle}")),
                    &["install", "--ignore-scripts"]
                )
                .status
                .success());
            }
            let out = run(
                oracle,
                &dir,
                &tmp.path().join(format!("config-{oracle}")),
                &args,
            );
            assert!(out.status.success());
            if args[0] == "link" {
                let prefix = tmp.path().join(format!("config-{oracle}")).join("prefix");
                let linked = prefix
                    .join(if cfg!(windows) {
                        "node_modules"
                    } else {
                        "lib/node_modules"
                    })
                    .join("empty-project/package.json");
                assert!(linked.is_file());
            }
            let text = String::from_utf8(out.stdout).unwrap();
            let normalized = text
                .lines()
                .map(|line| {
                    if line.starts_with("added ")
                        || line.starts_with("removed ")
                        || line.starts_with("up to date in ")
                    {
                        if let Some((before, _)) = line.rsplit_once(" in ") {
                            return format!("{before} in <time>");
                        }
                    }
                    line.to_string()
                })
                .collect::<Vec<_>>()
                .join("\n")
                + if text.ends_with('\n') { "\n" } else { "" };
            let lock = fs::read(dir.join("package-lock.json"))
                .ok()
                .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
            outputs.push((normalized, lock));
        }
        assert_eq!(outputs[0], outputs[1], "{args:?}");
    }
}

#[test]
fn lifecycle_failure_writes_a_real_diagnostic_log() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("package.json"), r#"{"name":"fails","version":"1.0.0","scripts":{"postinstall":"node -e \"process.exit(7)\""}}"#).unwrap();
    let out = run(
        false,
        tmp.path(),
        &tmp.path().join("isolated"),
        &["install"],
    );
    assert_eq!(out.status.code(), Some(7));
    let stderr = String::from_utf8(out.stderr).unwrap();
    let path = stderr
        .lines()
        .find_map(|line| {
            line.strip_prefix("npm error A complete log of this run can be found in: ")
        })
        .unwrap();
    let log = fs::read_to_string(path).unwrap();
    assert!(log.contains("process.exit(7)"));
    assert!(tmp.path().join("package-lock.json").is_file());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registry_save_cache_audit_and_outdated_use_real_mock_data() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let archive = |version: &str| {
        let bytes =
            serde_json::to_vec(&serde_json::json!({"name":"mock-dep","version":version})).unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut builder = tar::Builder::new(&mut gzip);
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", &bytes[..])
                .unwrap();
            builder.finish().unwrap();
        }
        gzip.finish().unwrap()
    };
    let archives = Arc::new([archive("1.0.0"), archive("2.0.0")]);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server_archives = archives.clone();
    let server_seen = seen.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let archives = server_archives.clone();
            let seen = server_seen.clone();
            tokio::spawn(async move {
                let mut request = vec![0; 16384];
                let n = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let url = request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                seen.lock().unwrap().push(url.to_string());
                let body = if url.ends_with(".tgz") {
                    archives[usize::from(url.contains("2.0.0"))].clone()
                } else if url.contains("/security/") {
                    b"{}".to_vec()
                } else {
                    let versions: serde_json::Map<String, serde_json::Value> = ["1.0.0", "2.0.0"].into_iter().enumerate().map(|(i, version)| {
                        let integrity = rnpm_core::integrity::Integrity::from_bytes(&archives[i], rnpm_core::integrity::Algorithm::Sha512).to_string();
                        (version.into(), serde_json::json!({"name":"mock-dep","version":version,"dist":{"tarball":format!("http://{addr}/mock-dep-{version}.tgz"),"integrity":integrity}}))
                    }).collect();
                    serde_json::to_vec(&serde_json::json!({"name":"mock-dep","dist-tags":{"latest":"2.0.0"},"versions":versions})).unwrap()
                };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    let tmp = tempdir().unwrap();
    for (setting, spec, expected) in [
        ("save-exact=true", "mock-dep@1.0.0", "1.0.0"),
        ("save-prefix=~", "mock-dep@1.0.0", "~1.0.0"),
        ("", "mock-dep@~1.0.0", "~1.0.0"),
    ] {
        let dir = tmp.path().join(expected.replace(['~', '.'], "_"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"manifest-name","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            dir.join(".npmrc"),
            format!("registry=http://{addr}/\n{setting}\n"),
        )
        .unwrap();
        let config = tmp
            .path()
            .join(format!("config-{}", expected.replace(['~', '.'], "_")));
        let out = run(false, &dir, &config, &["install", spec, "--ignore-scripts"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("package.json")).unwrap()).unwrap();
        assert_eq!(manifest["dependencies"]["mock-dep"], expected);
        let out = run(false, &dir, &config, &["audit", "--json"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["metadata"]["dependencies"]["prod"], 2);
        let out = run(false, &dir, &config, &["outdated", "--json"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            report["mock-dep"]["dependent"],
            dir.file_name().unwrap().to_str().unwrap()
        );
        let out = run(false, &dir, &config, &["cache", "add", "mock-dep@1.0.0"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty());
        let cached = rnpm_cache::Cache::new(config.join("cache"))
            .unwrap()
            .get("pacote:tarball:mock-dep@1.0.0")
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(cached, archives[0]);
        let out = run(false, &dir, &config, &["cache", "ls", "pacote:tarball:"]);
        assert_eq!(
            String::from_utf8(out.stdout).unwrap().trim(),
            "pacote:tarball:mock-dep@1.0.0"
        );
        let out = run(false, &dir, &config, &["ping", "--json"]);
        assert!(out.status.success());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("npm notice PING"));
        assert!(stderr.contains("npm notice PONG"));
        let out = run(false, &dir, &config, &["search", "--json", "anything"]);
        assert!(out.status.success());
        assert_eq!(out.stdout, b"\n[]\n\n");
        let out = run(
            false,
            &dir,
            &config,
            &["diff", "--diff=mock-dep@1.0.0", "--diff=mock-dep@2.0.0"],
        );
        assert!(out.status.success());
        assert!(String::from_utf8(out.stdout)
            .unwrap()
            .contains("index v1.0.0..v2.0.0 100644"));
        let out = run(
            false,
            &dir,
            &config,
            &["unpublish", "mock-dep@1.0.0", "--force"],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .any(|url| url.contains("/security/")));
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .any(|url| url == "/mock-dep-1.0.0.tgz/-rev/undefined"));
    server.abort();
}

#[test]
fn approval_without_resolved_lockfile_uses_name_and_warns_like_npm() {
    let tmp = tempdir().unwrap();
    let mut results = Vec::new();
    for oracle in [true, false] {
        let dir = tmp.path().join(if oracle { "npm" } else { "rnpm" });
        fs::create_dir_all(dir.join("node_modules/dep")).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"app","dependencies":{"dep":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("node_modules/dep/package.json"),
            r#"{"name":"dep","version":"1.0.0","scripts":{"install":"node -p 123"}}"#,
        )
        .unwrap();
        let output = run(
            oracle,
            &dir,
            &tmp.path().join(format!("config-{oracle}")),
            &["approve-scripts", "dep"],
        );
        assert!(output.status.success());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("package.json")).unwrap()).unwrap();
        results.push((output.stdout, output.stderr, manifest));
    }
    assert_eq!(results[0], results[1]);
}
