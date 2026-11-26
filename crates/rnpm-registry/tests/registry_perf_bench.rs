#![allow(clippy::field_reassign_with_default)]

use bytes::Bytes;
use data_encoding::BASE64;
use rnpm_registry::{
    parse_full_packument, parse_install_packument, AbbreviatedPackageMetadata,
    PackumentFetchOptions, RegistryClient, RegistryClientConfig,
};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::hint::black_box;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use url::Url;

fn build_synthetic_packuments(
    pkg_name: &str,
    version_count: usize,
) -> (Bytes, Bytes) {
    let mut full_versions = serde_json::Map::with_capacity(version_count);
    let mut abbrev_versions = serde_json::Map::with_capacity(version_count);
    let mut time_map = serde_json::Map::with_capacity(version_count + 2);
    time_map.insert(
        "created".to_string(),
        serde_json::Value::String("2020-01-01T00:00:00.000Z".to_string()),
    );
    time_map.insert(
        "modified".to_string(),
        serde_json::Value::String("2025-11-01T00:00:00.000Z".to_string()),
    );

    let mut latest = String::new();
    for i in 0..version_count {
        let major = i / 100;
        let minor = (i / 10) % 10;
        let patch = i % 10;
        let ver = format!("{major}.{minor}.{patch}");
        latest.clone_from(&ver);

        let mut deps = serde_json::Map::new();
        deps.insert("ms".into(), "^2.1.2".into());
        deps.insert("debug".into(), "^4.3.4".into());
        deps.insert("tslib".into(), "^2.6.0".into());
        deps.insert("@types/node".into(), ">=18.0.0".into());

        let mut dev_deps = serde_json::Map::new();
        dev_deps.insert("typescript".into(), "^5.4.0".into());
        dev_deps.insert("vitest".into(), "^1.5.0".into());
        dev_deps.insert("eslint".into(), "^9.0.0".into());

        let mut scripts = serde_json::Map::new();
        scripts.insert("build".into(), "tsc -p tsconfig.json".into());
        scripts.insert("test".into(), "vitest run".into());
        if i % 25 == 0 {
            scripts.insert("postinstall".into(), "node scripts/postinstall.js".into());
        }

        let mut dist = serde_json::Map::new();
        dist.insert(
            "tarball".into(),
            format!("https://registry.npmjs.org/{pkg_name}/-/{pkg_name}-{ver}.tgz").into(),
        );
        dist.insert(
            "integrity".into(),
            "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                .into(),
        );
        dist.insert("shasum".into(), "da39a3ee5e6b4b0d3255bfef95601890afd80709".into());
        dist.insert("fileCount".into(), 42.into());
        dist.insert("unpackedSize".into(), 128_450.into());

        let mut engines = serde_json::Map::new();
        engines.insert("node".into(), ">=18.12.0".into());

        // Abbreviated version (npm install-v1 shape + real-world extra fields)
        let mut av = serde_json::Map::new();
        av.insert("name".into(), pkg_name.into());
        av.insert("version".into(), ver.clone().into());
        av.insert("dist".into(), dist.clone().into());
        av.insert("dependencies".into(), deps.clone().into());
        av.insert("devDependencies".into(), dev_deps.clone().into());
        av.insert("engines".into(), engines.clone().into());
        av.insert("scripts".into(), scripts.clone().into());
        if i % 3 == 0 {
            av.insert("os".into(), serde_json::json!(["linux", "darwin", "win32"]));
            av.insert("cpu".into(), serde_json::json!(["x64", "arm64"]));
        }
        if i % 4 == 0 {
            av.insert(
                "funding".into(),
                serde_json::json!({"type": "github", "url": "https://github.com/sponsors/example"}),
            );
            av.insert("_hasShrinkwrap".into(), false.into());
        }
        if i % 10 == 0 {
            av.insert("hasInstallScript".into(), true.into());
        }
        abbrev_versions.insert(ver.clone(), av.clone().into());

        // Full version adds heavy documentation/tooling/bundler metadata present in real npm packuments
        let mut fv = av;
        fv.insert("license".into(), "MIT".into());
        fv.insert(
            "description".into(),
            "High-throughput synthetic benchmark package with realistic npm metadata bloat"
                .into(),
        );
        fv.insert(
            "keywords".into(),
            serde_json::json!(["benchmark", "cli", "parser", "async", "utility", "npm"]),
        );
        fv.insert(
            "repository".into(),
            serde_json::json!({"type": "git", "url": format!("git+https://github.com/org/{pkg_name}.git")}),
        );
        fv.insert(
            "homepage".into(),
            format!("https://github.com/org/{pkg_name}#readme").into(),
        );
        fv.insert(
            "bugs".into(),
            serde_json::json!({"url": format!("https://github.com/org/{pkg_name}/issues")}),
        );
        fv.insert(
            "maintainers".into(),
            serde_json::json!([
                {"name": "alice", "email": "alice@example.com"},
                {"name": "bob", "email": "bob@example.com"},
                {"name": "carol", "email": "carol@example.com"}
            ]),
        );
        fv.insert(
            "author".into(),
            serde_json::json!({"name": "Alice Example", "email": "alice@example.com"}),
        );
        fv.insert("main".into(), "./dist/index.cjs".into());
        fv.insert("module".into(), "./dist/index.mjs".into());
        fv.insert("types".into(), "./dist/index.d.ts".into());
        fv.insert(
            "exports".into(),
            serde_json::json!({
                ".": {
                    "types": "./dist/index.d.ts",
                    "import": "./dist/index.mjs",
                    "require": "./dist/index.cjs"
                },
                "./subpath": {
                    "types": "./dist/subpath.d.ts",
                    "default": "./dist/subpath.mjs"
                }
            }),
        );
        fv.insert(
            "files".into(),
            serde_json::json!(["dist", "bin", "README.md", "LICENSE"]),
        );
        fv.insert(
            "typesVersions".into(),
            serde_json::json!({"*": {"*": ["dist/*"]}}),
        );
        fv.insert("eslintConfig".into(), serde_json::json!({"extends": ["eslint:recommended"]}));
        fv.insert("prettier".into(), serde_json::json!({"singleQuote": true, "semi": false}));
        fv.insert("gitHead".into(), "abcdef1234567890abcdef1234567890abcdef12".into());
        fv.insert("_id".into(), format!("{pkg_name}@{ver}").into());
        fv.insert("_nodeVersion".into(), "20.11.0".into());
        fv.insert("_npmVersion".into(), "10.2.4".into());

        full_versions.insert(ver.clone(), fv.into());
        time_map.insert(
            ver,
            serde_json::Value::String("2024-05-15T12:34:56.789Z".to_string()),
        );
    }

    let mut dist_tags = serde_json::Map::new();
    dist_tags.insert("latest".into(), latest.into());
    dist_tags.insert("next".into(), "2.0.0".into());

    let abbrev_doc = serde_json::json!({
        "name": pkg_name,
        "modified": "2025-11-01T00:00:00.000Z",
        "dist-tags": dist_tags,
        "versions": abbrev_versions,
    });

    let readme = "# Benchmark Package\n\n".to_string()
        + &"Detailed documentation paragraph repeated to mirror real npm README payloads.\n".repeat(450);

    let full_doc = serde_json::json!({
        "_id": pkg_name,
        "_rev": "123-abcdef",
        "name": pkg_name,
        "description": "Synthetic full packument for performance benchmarking",
        "dist-tags": dist_tags,
        "versions": full_versions,
        "time": time_map,
        "maintainers": [
            {"name": "alice", "email": "alice@example.com"},
            {"name": "bob", "email": "bob@example.com"}
        ],
        "repository": {"type": "git", "url": format!("git+https://github.com/org/{pkg_name}.git")},
        "readme": readme,
        "readmeFilename": "README.md",
        "users": {"user1": true, "user2": true, "user3": true},
        "license": "MIT"
    });

    (
        Bytes::from(serde_json::to_vec(&abbrev_doc).unwrap()),
        Bytes::from(serde_json::to_vec(&full_doc).unwrap()),
    )
}

struct MockRegistryState {
    abbreviated: HashMap<String, Bytes>,
    full: HashMap<String, Bytes>,
    etags: HashMap<String, String>,
    tarball_256k: Bytes,
}

async fn handle_keepalive_conn(mut stream: TcpStream, state: Arc<MockRegistryState>) {
    let _ = stream.set_nodelay(true);
    let mut buf = vec![0u8; 16 * 1024];
    let mut filled = 0usize;

    loop {
        let header_end = loop {
            if let Some(pos) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if filled == buf.len() {
                buf.resize(buf.len() * 2, 0);
            }
            match stream.read(&mut buf[filled..]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => filled += n,
            }
        };

        let (resp_hdr, resp_body, close_conn) = {
            let header_bytes = &buf[..header_end];
            let header_str = match std::str::from_utf8(header_bytes) {
                Ok(s) => s,
                Err(_) => return,
            };

            let mut lines = header_str.split("\r\n");
            let req_line = lines.next().unwrap_or("");
            let mut parts = req_line.split_whitespace();
            let _method = parts.next().unwrap_or("GET");
            let target = parts.next().unwrap_or("/");
            let path = target.split('?').next().unwrap_or(target);

            let mut accept_abbrev = false;
            let mut if_none_match: Option<&str> = None;
            let mut close_conn = false;

            for line in lines {
                if line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let v = v.trim();
                    if k.eq_ignore_ascii_case("accept") {
                        accept_abbrev = v.contains("vnd.npm.install-v1+json");
                    } else if k.eq_ignore_ascii_case("if-none-match") {
                        if_none_match = Some(v);
                    } else if k.eq_ignore_ascii_case("connection")
                        && v.eq_ignore_ascii_case("close")
                    {
                        close_conn = true;
                    }
                }
            }

            if path.contains("/-/") {
                let body = &state.tarball_256k;
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nETag: \"tb-256k\"\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                );
                (hdr, Some(body), close_conn)
            } else {
                let pkg = path.trim_start_matches('/');
                if let Some(etag) = state.etags.get(pkg) {
                    if if_none_match == Some(etag.as_str()) {
                        let content_type = if accept_abbrev {
                            "application/vnd.npm.install-v1+json"
                        } else {
                            "application/json"
                        };
                        let hdr = format!(
                            "HTTP/1.1 304 Not Modified\r\nContent-Type: {content_type}\r\nETag: {etag}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        );
                        (hdr, None, close_conn)
                    } else {
                        let (content_type, body) = if accept_abbrev {
                            (
                                "application/vnd.npm.install-v1+json",
                                state.abbreviated.get(pkg).unwrap(),
                            )
                        } else {
                            ("application/json", state.full.get(pkg).unwrap())
                        };
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            body.len()
                        );
                        (hdr, Some(body), close_conn)
                    }
                } else {
                    (
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                            .to_string(),
                        None,
                        close_conn,
                    )
                }
            }
        };

        let remaining = filled - header_end;
        if remaining > 0 {
            buf.copy_within(header_end..filled, 0);
        }
        filled = remaining;

        if stream.write_all(resp_hdr.as_bytes()).await.is_err() {
            return;
        }
        if let Some(body) = resp_body {
            if stream.write_all(body).await.is_err() {
                return;
            }
        }

        if close_conn {
            return;
        }
    }
}

async fn start_mock_registry(state: Arc<MockRegistryState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let st = Arc::clone(&state);
            tokio::spawn(handle_keepalive_conn(stream, st));
        }
    });
    (addr, handle)
}

fn measure_sync<F: FnMut()>(warmup: usize, iters: usize, mut f: F) -> Duration {
    for _ in 0..warmup {
        f();
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    t0.elapsed()
}

#[test]
#[ignore]
fn bench_packument_parsing() {
    let (abbrev_300, full_300) = build_synthetic_packuments("perf-pkg-300", 300);
    println!(
        "\n[bench_packument_parsing] abbrev_300={} bytes, full_300={} bytes",
        abbrev_300.len(),
        full_300.len()
    );

    let full_install_dur = measure_sync(3, 25, || {
        let meta = parse_install_packument(black_box(&full_300)).unwrap();
        black_box(meta.versions.len());
    });

    let abbrev_install_dur = measure_sync(5, 60, || {
        let meta = parse_install_packument(black_box(&abbrev_300)).unwrap();
        black_box(meta.versions.len());
    });

    let full_full_dur = measure_sync(3, 25, || {
        let meta = parse_full_packument(black_box(&full_300)).unwrap();
        black_box(meta.versions.len());
    });

    let serde_abbrev_dur = measure_sync(5, 60, || {
        let meta: AbbreviatedPackageMetadata =
            serde_json::from_slice(black_box(&abbrev_300)).unwrap();
        black_box(meta.versions.len());
    });

    println!(
        "parse_install_packument(full_300, 25x):   {:.2} ms ({:.3} ms/iter)",
        full_install_dur.as_secs_f64() * 1000.0,
        full_install_dur.as_secs_f64() * 1000.0 / 25.0
    );
    println!(
        "parse_install_packument(abbrev_300, 60x): {:.2} ms ({:.3} ms/iter)",
        abbrev_install_dur.as_secs_f64() * 1000.0,
        abbrev_install_dur.as_secs_f64() * 1000.0 / 60.0
    );
    println!(
        "parse_full_packument(full_300, 25x):      {:.2} ms ({:.3} ms/iter)",
        full_full_dur.as_secs_f64() * 1000.0,
        full_full_dur.as_secs_f64() * 1000.0 / 25.0
    );
    println!(
        "serde_from_slice(abbrev_300, 60x):        {:.2} ms ({:.3} ms/iter)",
        serde_abbrev_dur.as_secs_f64() * 1000.0,
        serde_abbrev_dur.as_secs_f64() * 1000.0 / 60.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_registry_http_and_tarballs() {
    let mut abbreviated = HashMap::new();
    let mut full = HashMap::new();
    let mut etags = HashMap::new();
    let mut pkg_names = Vec::with_capacity(64);

    for i in 0..64 {
        let name = format!("bench-pkg-{i:02}");
        let (abbrev_bytes, full_bytes) = build_synthetic_packuments(&name, 220);
        abbreviated.insert(name.clone(), abbrev_bytes);
        full.insert(name.clone(), full_bytes);
        etags.insert(name.clone(), format!("\"v1-{name}\""));
        pkg_names.push(name);
    }

    let tarball_256k = Bytes::from(vec![0x5Au8; 256 * 1024]);
    let state = Arc::new(MockRegistryState {
        abbreviated,
        full,
        etags,
        tarball_256k,
    });
    let (addr, server_handle) = start_mock_registry(Arc::clone(&state)).await;
    let base_url = Url::parse(&format!("http://{addr}/")).unwrap();

    let mut cfg = RegistryClientConfig::default();
    cfg.default_registry = base_url.clone();
    cfg.auth_token = Some("bench-token-secret".into());
    cfg.trusted_hosts.insert("127.0.0.1".into());
    cfg.max_concurrent_requests = 64;
    cfg.pool_max_idle_per_host = 64;
    cfg.circuit_breaker_enabled = false;
    let client = RegistryClient::with_config(cfg.clone()).unwrap();

    let mut cb_cfg = cfg;
    cb_cfg.circuit_breaker_enabled = true;
    let cb_client = RegistryClient::with_config(cb_cfg).unwrap();

    // 1. Burst 64 unique packages (abbrev install metadata)
    let unique_reqs: Vec<(String, Option<String>)> =
        pkg_names.iter().map(|n| (n.clone(), None)).collect();
    for _ in 0..2 {
        let r = client
            .get_package_metadata_install_conditional_concurrent(&unique_reqs)
            .await;
        assert_eq!(r.len(), 64);
    }
    let t0 = Instant::now();
    for _ in 0..8 {
        let r = client
            .get_package_metadata_install_conditional_concurrent(&unique_reqs)
            .await;
        black_box(r.len());
    }
    let meta_unique_dur = t0.elapsed();

    // 2. Burst 160 overlapping requests (16 packages * 10 concurrent callers each)
    let mut overlap_reqs = Vec::with_capacity(160);
    for _round in 0..10 {
        for pkg in pkg_names.iter().take(16) {
            overlap_reqs.push((pkg.clone(), None));
        }
    }
    for _ in 0..2 {
        let r = client
            .get_package_metadata_install_conditional_concurrent(&overlap_reqs)
            .await;
        assert_eq!(r.len(), 160);
    }
    client.reset_http_metrics();
    let t0 = Instant::now();
    for _ in 0..8 {
        let r = client
            .get_package_metadata_install_conditional_concurrent(&overlap_reqs)
            .await;
        black_box(r.len());
    }
    let meta_overlap_dur = t0.elapsed();
    let overlap_http_reqs = client.http_requests();

    // 3. Burst 128 conditional 304 revalidations with circuit breaker + auth enabled
    let mut reval_reqs = Vec::with_capacity(128);
    for _ in 0..2 {
        for name in &pkg_names {
            reval_reqs.push((name.clone(), Some(format!("\"v1-{name}\""))));
        }
    }
    for _ in 0..2 {
        let r = cb_client
            .get_package_metadata_conditional_concurrent(&reval_reqs)
            .await;
        assert_eq!(r.len(), 128);
    }
    cb_client.reset_http_metrics();
    let t0 = Instant::now();
    for _ in 0..12 {
        let r = cb_client
            .get_package_metadata_conditional_concurrent(&reval_reqs)
            .await;
        black_box(r.len());
    }
    let meta_304_dur = t0.elapsed();

    // 4. Tarball downloads to memory: 32 unique URLs x 256 KB
    let tb_unique_urls: Vec<String> = (0..32)
        .map(|i| format!("{base_url}bench-pkg-{i:02}/-/bench-pkg-{i:02}-1.0.0.tgz"))
        .collect();
    for _ in 0..2 {
        let r = client.download_tarballs_concurrent(&tb_unique_urls).await;
        assert_eq!(r.len(), 32);
    }
    let t0 = Instant::now();
    for _ in 0..8 {
        let r = client.download_tarballs_concurrent(&tb_unique_urls).await;
        black_box(r.len());
    }
    let tb_unique_dur = t0.elapsed();

    // 5. Tarball downloads to memory: 64 overlapping requests across 8 URLs x 256 KB
    let mut tb_overlap_urls = Vec::with_capacity(64);
    for _ in 0..8 {
        for i in 0..8 {
            tb_overlap_urls.push(format!("{base_url}bench-pkg-{i:02}/-/bench-pkg-{i:02}-1.0.0.tgz"));
        }
    }
    for _ in 0..2 {
        let r = client.download_tarballs_concurrent(&tb_overlap_urls).await;
        assert_eq!(r.len(), 64);
    }
    let t0 = Instant::now();
    for _ in 0..8 {
        let r = client.download_tarballs_concurrent(&tb_overlap_urls).await;
        black_box(r.len());
    }
    let tb_overlap_dur = t0.elapsed();

    // 6. Tarball downloads directly to disk: 24 files x 256 KB
    let tmp = tempfile::tempdir().unwrap();
    let disk_targets: Vec<(String, PathBuf)> = (0..24)
        .map(|i| {
            (
                format!("{base_url}bench-pkg-{i:02}/-/bench-pkg-{i:02}-1.0.0.tgz"),
                tmp.path().join(format!("pkg-{i:02}.tgz")),
            )
        })
        .collect();
    let disk_pairs: Vec<(&str, &std::path::Path)> = disk_targets
        .iter()
        .map(|(u, p)| (u.as_str(), p.as_path()))
        .collect();
    for _ in 0..2 {
        let r = client.download_tarballs_to_files_concurrent(&disk_pairs).await;
        assert_eq!(r.len(), 24);
    }
    let t0 = Instant::now();
    for _ in 0..6 {
        let r = client.download_tarballs_to_files_concurrent(&disk_pairs).await;
        black_box(r.len());
    }
    let tb_disk_dur = t0.elapsed();

    // 7. Tarball stream + SHA-512 SRI integrity calculation concurrently (32 x 256 KB)
    async fn run_stream_hash_burst(client: &RegistryClient, urls: &[String]) {
        let sem = Arc::new(Semaphore::new(32));
        let mut js = tokio::task::JoinSet::new();
        for u in urls {
            let cl = client.clone();
            let url = u.clone();
            let s = Arc::clone(&sem);
            js.spawn(async move {
                let _p = s.acquire().await.unwrap();
                let mut stream = cl.download_tarball(&url).await.unwrap();
                let mut hasher = Sha512::new();
                let mut total = 0usize;
                while let Some(chunk) = stream.chunk().await.unwrap() {
                    total += chunk.len();
                    hasher.update(&chunk);
                }
                let digest = hasher.finalize();
                let sri = format!("sha512-{}", BASE64.encode(&digest));
                (total, sri)
            });
        }
        while let Some(res) = js.join_next().await {
            black_box(res.unwrap());
        }
    }
    for _ in 0..2 {
        run_stream_hash_burst(&client, &tb_unique_urls).await;
    }
    let t0 = Instant::now();
    for _ in 0..8 {
        run_stream_hash_burst(&client, &tb_unique_urls).await;
    }
    let tb_stream_hash_dur = t0.elapsed();

    // 8. Lazy client initialization cost (no network call) vs eager client initialization
    let t0 = Instant::now();
    for _ in 0..500 {
        let cl = RegistryClient::with_config(RegistryClientConfig::default()).unwrap();
        black_box(cl);
    }
    let lazy_init_dur = t0.elapsed();

    let eager_probe_url = Url::parse("https://registry.npmjs.org/pkg").unwrap();
    let t0 = Instant::now();
    for _ in 0..25 {
        let cl = RegistryClient::with_config(RegistryClientConfig::default()).unwrap();
        let _ = black_box(cl.client_for_url(&eager_probe_url));
    }
    let eager_init_dur = t0.elapsed();

    // 9. Abbreviated vs Full wire bytes & fetch latency + negotiated representation-specific 304 cache hit
    let full_only_reqs: Vec<(String, Option<String>)> =
        pkg_names.iter().map(|n| (n.clone(), None)).collect();
    let t0 = Instant::now();
    for _ in 0..8 {
        let r = client
            .get_package_metadata_full_conditional_concurrent(&full_only_reqs)
            .await;
        black_box(r.len());
    }
    let meta_full_unique_dur = t0.elapsed();
    let full_wire_bytes_per_burst: usize =
        state.full.values().map(|b| b.len()).sum();
    let abbrev_wire_bytes_per_burst: usize =
        state.abbreviated.values().map(|b| b.len()).sum();

    // Populate negotiated abbreviated cache once, then time cached 304 revalidations
    for name in &pkg_names {
        let m = client
            .get_package_metadata_negotiated(name, PackumentFetchOptions::abbreviated())
            .await
            .unwrap();
        black_box(m.versions.len());
    }
    let t0 = Instant::now();
    for _ in 0..2 {
        for name in &pkg_names {
            let m = client
                .get_package_metadata_negotiated(name, PackumentFetchOptions::abbreviated())
                .await
                .unwrap();
            black_box(m.versions.len());
        }
    }
    let meta_negotiated_cached_dur = t0.elapsed();

    // 10. Streaming ring SHA-512 single-pass tarball download (32 x 256 KB)
    async fn run_ring_sha512_burst(client: &RegistryClient, urls: &[String]) {
        let mut js = tokio::task::JoinSet::new();
        for u in urls {
            let cl = client.clone();
            let url = u.clone();
            js.spawn(async move { cl.download_tarball_bytes_with_sha512(&url).await.unwrap() });
        }
        while let Some(res) = js.join_next().await {
            black_box(res.unwrap());
        }
    }
    for _ in 0..2 {
        run_ring_sha512_burst(&client, &tb_unique_urls).await;
    }
    let t0 = Instant::now();
    for _ in 0..8 {
        run_ring_sha512_burst(&client, &tb_unique_urls).await;
    }
    let tb_ring_sha512_dur = t0.elapsed();

    println!("\n[bench_registry_http_and_tarballs]");
    println!(
        "meta_install_64_unique (8x):          {:.2} ms ({:.2} ms/burst)",
        meta_unique_dur.as_secs_f64() * 1000.0,
        meta_unique_dur.as_secs_f64() * 1000.0 / 8.0
    );
    println!(
        "meta_full_64_unique (8x):             {:.2} ms ({:.2} ms/burst, wire={} B -> abbrev={} B)",
        meta_full_unique_dur.as_secs_f64() * 1000.0,
        meta_full_unique_dur.as_secs_f64() * 1000.0 / 8.0,
        full_wire_bytes_per_burst,
        abbrev_wire_bytes_per_burst
    );
    println!(
        "meta_install_160_overlapping (8x):    {:.2} ms ({:.2} ms/burst, http_reqs={})",
        meta_overlap_dur.as_secs_f64() * 1000.0,
        meta_overlap_dur.as_secs_f64() * 1000.0 / 8.0,
        overlap_http_reqs
    );
    println!(
        "meta_revalidate_128_304_cb (12x):     {:.2} ms ({:.2} ms/burst)",
        meta_304_dur.as_secs_f64() * 1000.0,
        meta_304_dur.as_secs_f64() * 1000.0 / 12.0
    );
    println!(
        "meta_negotiated_cached_304 (128x):    {:.2} ms ({:.4} ms/req)",
        meta_negotiated_cached_dur.as_secs_f64() * 1000.0,
        meta_negotiated_cached_dur.as_secs_f64() * 1000.0 / 128.0
    );
    println!(
        "tarball_mem_32_unique_256k (8x):      {:.2} ms ({:.2} ms/burst)",
        tb_unique_dur.as_secs_f64() * 1000.0,
        tb_unique_dur.as_secs_f64() * 1000.0 / 8.0
    );
    println!(
        "tarball_mem_64_overlapping_256k (8x): {:.2} ms ({:.2} ms/burst)",
        tb_overlap_dur.as_secs_f64() * 1000.0,
        tb_overlap_dur.as_secs_f64() * 1000.0 / 8.0
    );
    println!(
        "tarball_disk_24_files_256k (6x):      {:.2} ms ({:.2} ms/burst)",
        tb_disk_dur.as_secs_f64() * 1000.0,
        tb_disk_dur.as_secs_f64() * 1000.0 / 6.0
    );
    println!(
        "tarball_stream_sha512_32x256k (8x):   {:.2} ms ({:.2} ms/burst)",
        tb_stream_hash_dur.as_secs_f64() * 1000.0,
        tb_stream_hash_dur.as_secs_f64() * 1000.0 / 8.0
    );
    println!(
        "tarball_singlepass_sha512_32x256k (8x): {:.2} ms ({:.2} ms/burst)",
        tb_ring_sha512_dur.as_secs_f64() * 1000.0,
        tb_ring_sha512_dur.as_secs_f64() * 1000.0 / 8.0
    );
    println!(
        "client_init_lazy (500x) vs eager (25x): {:.3} us/init vs {:.3} ms/init",
        lazy_init_dur.as_secs_f64() * 1_000_000.0 / 500.0,
        eager_init_dur.as_secs_f64() * 1000.0 / 25.0
    );

    server_handle.abort();
}
