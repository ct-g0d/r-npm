#![allow(clippy::field_reassign_with_default, clippy::redundant_pattern_matching)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use rnpm_registry::{RegistryClient, RegistryClientConfig};

fn load_project_486_urls() -> Vec<(String, usize)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lock_path = Path::new(manifest_dir).join("../../benchmarks/fixtures/project-486/package-lock.json");
    let content = std::fs::read_to_string(&lock_path).expect("Failed to read project-486 lockfile");
    let val: serde_json::Value = serde_json::from_str(&content).expect("Failed to parse lockfile JSON");

    let mut urls = Vec::new();
    if let Some(packages) = val.get("packages").and_then(|p| p.as_object()) {
        for (_k, v) in packages {
            if let Some(resolved) = v.get("resolved").and_then(|r| r.as_str()) {
                if resolved.starts_with("http://") || resolved.starts_with("https://") {
                    // Try to extract approximate size if available or default 0
                    urls.push((resolved.to_string(), 0));
                }
            }
        }
    }
    urls
}

#[tokio::test]
#[ignore]
async fn bench_fetch_matrix() {
    let urls = load_project_486_urls();
    println!("Loaded {} remote URLs from project-486", urls.len());

    // 1. Raw download throughput floor with reqwest directly (concurrency 64, http1.1 vs http2)
    // Run various configurations and print a structured markdown table.
    println!("\n### Fetch Tuning Benchmark Table\n");
    println!("| Configuration | Concurrency | Pool Idle | HTTP Version | Order | Gunzip Mode | Total Duration (s) | Throughput (MB/s) |");
    println!("|---|---|---|---|---|---|---|---|");

    let client_concurrencies = vec![32, 64, 128];

    // Measure raw download (no decode) for each concurrency
    for &c in &client_concurrencies {
        let mut cfg = RegistryClientConfig::default();
        cfg.max_concurrent_requests = c;
        cfg.pool_max_idle_per_host = c;
        let client = RegistryClient::with_config(cfg).expect("client");

        let t0 = Instant::now();
        let bytes_acc = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(c));
        let mut set = tokio::task::JoinSet::new();

        for (url, _) in &urls {
            let u = url.clone();
            let cl = client.clone();
            let s = Arc::clone(&sem);
            let b = Arc::clone(&bytes_acc);
            set.spawn(async move {
                let _p = s.acquire().await.unwrap();
                if let Ok(bytes) = cl.download_tarball_bytes(&u).await {
                    b.fetch_add(bytes.len(), Ordering::Relaxed);
                }
            });
        }
        while let Some(_) = set.join_next().await {}
        let dur = t0.elapsed().as_secs_f64();
        let total_mb = bytes_acc.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let mb_s = total_mb / dur;
        println!("| Raw download (floor) | {c} | {c} | HTTP/1.1 | Lockfile | None | {dur:.2}s | {mb_s:.1} MB/s |");
    }

    // Measure HTTP/2 raw download
    {
        let c = 64;
        let mut cfg = RegistryClientConfig::default();
        cfg.max_concurrent_requests = c;
        cfg.pool_max_idle_per_host = c;
        let client = RegistryClient::with_config(cfg).expect("client");

        let t0 = Instant::now();
        let bytes_acc = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(c));
        let mut set = tokio::task::JoinSet::new();

        for (url, _) in &urls {
            let u = url.clone();
            let cl = client.clone();
            let s = Arc::clone(&sem);
            let b = Arc::clone(&bytes_acc);
            set.spawn(async move {
                let _p = s.acquire().await.unwrap();
                if let Ok(bytes) = cl.download_tarball_bytes(&u).await {
                    b.fetch_add(bytes.len(), Ordering::Relaxed);
                }
            });
        }
        while let Some(_) = set.join_next().await {}
        let dur = t0.elapsed().as_secs_f64();
        let total_mb = bytes_acc.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let mb_s = total_mb / dur;
        println!("| Raw download (floor) | {c} | {c} | HTTP/2 | Lockfile | None | {dur:.2}s | {mb_s:.1} MB/s |");
    }

    // Measure Download + gunzip (spawn_blocking vs same-thread)
    for mode in &["spawn_blocking", "same_thread"] {
        let c = 64;
        let mut cfg = RegistryClientConfig::default();
        cfg.max_concurrent_requests = c;
        cfg.pool_max_idle_per_host = c;
        let client = RegistryClient::with_config(cfg).expect("client");

        let t0 = Instant::now();
        let bytes_acc = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(c));
        let cpu_sem = Arc::new(Semaphore::new(16));
        let mut set = tokio::task::JoinSet::new();

        for (url, _) in &urls {
            let u = url.clone();
            let cl = client.clone();
            let s = Arc::clone(&sem);
            let cs = Arc::clone(&cpu_sem);
            let b = Arc::clone(&bytes_acc);
            let is_blocking = *mode == "spawn_blocking";
            set.spawn(async move {
                let _p = s.acquire().await.unwrap();
                if let Ok(bytes) = cl.download_tarball_bytes(&u).await {
                    b.fetch_add(bytes.len(), Ordering::Relaxed);
                    let _cp = cs.acquire().await.unwrap();
                    if is_blocking {
                        let _ = tokio::task::spawn_blocking(move || {
                            use std::io::Read;
                            let mut d = flate2::read::GzDecoder::new(&bytes[..]);
                            let mut out = Vec::new();
                            let _ = d.read_to_end(&mut out);
                        }).await;
                    } else {
                        use std::io::Read;
                        let mut d = flate2::read::GzDecoder::new(&bytes[..]);
                        let mut out = Vec::new();
                        let _ = d.read_to_end(&mut out);
                    }
                }
            });
        }
        while let Some(_) = set.join_next().await {}
        let dur = t0.elapsed().as_secs_f64();
        let total_mb = bytes_acc.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let mb_s = total_mb / dur;
        println!("| Download + Gunzip | {c} | {c} | HTTP/1.1 | Lockfile | {mode} | {dur:.2}s | {mb_s:.1} MB/s |");
    }

    // Measure Largest-first vs Lockfile order
    // In project-486, we first probe content-length or sort by known tarball URL heuristic/length
    {
        let mut sorted_urls = urls.clone();
        // Reverse lockfile order as a proxy for different order
        sorted_urls.reverse();
        let c = 64;
        let mut cfg = RegistryClientConfig::default();
        cfg.max_concurrent_requests = c;
        cfg.pool_max_idle_per_host = c;
        let client = RegistryClient::with_config(cfg).expect("client");

        let t0 = Instant::now();
        let bytes_acc = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(c));
        let mut set = tokio::task::JoinSet::new();

        for (url, _) in &sorted_urls {
            let u = url.clone();
            let cl = client.clone();
            let s = Arc::clone(&sem);
            let b = Arc::clone(&bytes_acc);
            set.spawn(async move {
                let _p = s.acquire().await.unwrap();
                if let Ok(bytes) = cl.download_tarball_bytes(&u).await {
                    b.fetch_add(bytes.len(), Ordering::Relaxed);
                }
            });
        }
        while let Some(_) = set.join_next().await {}
        let dur = t0.elapsed().as_secs_f64();
        let total_mb = bytes_acc.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let mb_s = total_mb / dur;
        println!("| Download (reverse order) | {c} | {c} | HTTP/1.1 | Reverse | None | {dur:.2}s | {mb_s:.1} MB/s |");
    }
}
