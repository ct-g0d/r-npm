use flate2::write::GzEncoder;
use flate2::Compression;
use rnpm_cache::{Cache, PackStore};
use rnpm_core::{Algorithm, Integrity};
use std::sync::Arc;
use std::time::Instant;
use tar::{Builder, Header};
use tempfile::tempdir;

fn make_pseudo_random_bytes(seed: usize, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = (seed as u64).wrapping_add(0x9e3779b97f4a7c15);
    for i in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Mix printable ASCII JSON/JS-like patterns so gzip compression is realistic (~3:1 - 4:1)
        let b = if i % 64 == 0 {
            b'\n'
        } else if i % 7 == 0 {
            b' '
        } else {
            b'a' + ((x % 26) as u8)
        };
        out.push(b);
    }
    out
}

fn build_realistic_tarball(pkg_idx: usize, file_count: usize, file_size: usize) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = Builder::new(&mut gz);
        let pkg_json = format!(
            "{{\"name\":\"bench-pkg-{pkg_idx}\",\"version\":\"1.0.{pkg_idx}\",\"main\":\"lib/index.js\"}}"
        );
        let mut h_pkg = Header::new_gnu();
        h_pkg.set_size(pkg_json.len() as u64);
        h_pkg.set_mode(0o644);
        h_pkg.set_cksum();
        tar.append_data(&mut h_pkg, "package/package.json", pkg_json.as_bytes())
            .unwrap();

        for f in 0..file_count {
            let payload = make_pseudo_random_bytes(pkg_idx * 1000 + f, file_size);
            let path = format!("package/src/mod_{}/file_{f}.js", f % 8);
            let mut h = Header::new_gnu();
            h.set_size(payload.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, &path, &payload[..]).unwrap();
        }
        tar.finish().unwrap();
    }
    gz.finish().unwrap()
}

#[test]
#[ignore]
fn bench_rnpm_cache_hot_paths() {
    println!("\n=== rnpm-cache Release Performance Benchmark ===");

    // Prepare deterministic test datasets
    let num_entries = 60usize;
    let packument_payloads: Vec<(String, Vec<u8>, Integrity)> = (0..num_entries)
        .map(|i| {
            let data = make_pseudo_random_bytes(i + 100, 48 * 1024);
            let integ = Integrity::from_bytes(&data, Algorithm::Sha512);
            (format!("bench-pkg-{i}"), data, integ)
        })
        .collect();

    let tarball_payloads: Vec<(String, Vec<u8>, Integrity, String)> = (0..40)
        .map(|i| {
            let tgz = build_realistic_tarball(i, 35, 2048);
            let integ = Integrity::from_bytes(&tgz, Algorithm::Sha512);
            let integ_str = integ.to_string();
            let url = format!("https://registry.npmjs.org/bench-pkg-{i}/-/bench-pkg-{i}-1.0.{i}.tgz");
            (url, tgz, integ, integ_str)
        })
        .collect();

    let large_tarball = build_realistic_tarball(999, 250, 4096);
    let large_integ = Integrity::from_bytes(&large_tarball, Algorithm::Sha512).to_string();

    // 1. Cache put (cold)
    let cache_dir = tempdir().unwrap();
    let cache = Cache::new(cache_dir.path()).unwrap();

    let t0 = Instant::now();
    for (name, data, _) in &packument_payloads {
        cache
            .put_packument("https://registry.npmjs.org", name, data, None)
            .unwrap();
    }
    let put_packument_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 2. Cache put_with_integrity (tarballs)
    let t0 = Instant::now();
    for (url, tgz, integ, _) in &tarball_payloads {
        cache
            .put_with_integrity(url, tgz, Some(integ), None)
            .unwrap();
    }
    let put_with_integ_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 3. Cache put identical (warm re-put / 304 revalidation)
    let t0 = Instant::now();
    for (name, data, _) in &packument_payloads {
        cache
            .put_packument("https://registry.npmjs.org", name, data, None)
            .unwrap();
    }
    let reput_packument_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 4. Cache get (hit) - packuments + tarballs x 5 rounds
    let t0 = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..5 {
        for (name, _, _) in &packument_payloads {
            let (_, bytes) = cache
                .get_packument_with_accept(
                    "https://registry.npmjs.org",
                    name,
                    None,
                )
                .unwrap()
                .unwrap();
            total_bytes += bytes.len();
        }
        for (url, _, _, _) in &tarball_payloads {
            let (_, bytes) = cache.get(url).unwrap().unwrap();
            total_bytes += bytes.len();
        }
    }
    let get_hit_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(total_bytes > 0);

    // 5. Cache get_by_integrity / get_by_sha512 hit x 5 rounds
    let t0 = Instant::now();
    for _ in 0..5 {
        for (_, _, integ, _) in &tarball_payloads {
            let bytes = cache.get_by_integrity(integ).unwrap().unwrap();
            total_bytes += bytes.len();
        }
    }
    let get_by_integ_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(total_bytes > 0);

    // 6. Cache miss (URLs + packuments)
    let t0 = Instant::now();
    for i in 0..200 {
        let miss_url = format!("https://registry.npmjs.org/missing-{i}/-/missing-{i}-1.0.0.tgz");
        assert!(cache.get(&miss_url).unwrap().is_none());
        assert!(cache
            .get_packument_with_accept(
                "https://registry.npmjs.org",
                &format!("missing-pkg-{i}"),
                Some("application/vnd.npm.install-v1+json"),
            )
            .unwrap()
            .is_none());
    }
    let get_miss_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 7. Cache verify
    let t0 = Instant::now();
    let report = cache.verify().unwrap();
    let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(report.is_clean());

    // 8. Cache put_file_with_integrity (streaming file hashing + copy)
    let src_dir = tempdir().unwrap();
    let mut file_inputs = Vec::new();
    for i in 0..20 {
        let p = src_dir.path().join(format!("blob_{i}.tgz"));
        let data = make_pseudo_random_bytes(5000 + i, 256 * 1024);
        let integ = Integrity::from_bytes(&data, Algorithm::Sha512);
        std::fs::write(&p, &data).unwrap();
        file_inputs.push((format!("file-key-{i}"), p, integ));
    }
    let t0 = Instant::now();
    for (k, p, integ) in &file_inputs {
        cache
            .put_file_with_integrity(k, p, Some(integ), None)
            .unwrap();
    }
    let put_file_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 9. Contended 16-worker cache hammering (put + get on shared & unique keys)
    let contended_dir = tempdir().unwrap();
    let contended_cache = Arc::new(Cache::new(contended_dir.path()).unwrap());
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for tid in 0..16 {
            let c = Arc::clone(&contended_cache);
            s.spawn(move || {
                for iter in 0..15 {
                    let shared_key = format!("https://registry.npmjs.org/contended-{}/-/c.tgz", iter % 3);
                    let payload = format!("contended-payload-{tid}-{iter}").into_bytes();
                    let _ = c.put(&shared_key, &payload, None);
                    let _ = c.get(&shared_key);

                    let unique_key = format!("https://registry.npmjs.org/u-{tid}-{iter}/-/u.tgz");
                    let udata = format!("unique-data-{tid}-{iter}").into_bytes();
                    c.put(&unique_key, &udata, None).unwrap();
                    let _ = c.get(&unique_key).unwrap().unwrap();
                }
            });
        }
    });
    let contended_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 10. PackStore: put_package_from_verified_tarball_deferred (40 packages)
    let store_dir = tempdir().unwrap();
    let store = PackStore::new(store_dir.path()).unwrap();
    let t0 = Instant::now();
    for (_, tgz, _, integ_str) in &tarball_payloads {
        store
            .put_package_from_verified_tarball_deferred(integ_str, tgz)
            .unwrap();
    }
    let pack_from_verified_deferred_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 11. PackStore: put_package_from_tarball (verify + tar + pack + CAS, fresh store)
    let store_cas_dir = tempdir().unwrap();
    let store_cas = PackStore::new(store_cas_dir.path()).unwrap();
    let t0 = Instant::now();
    for (_, tgz, _, integ_str) in &tarball_payloads {
        store_cas
            .put_package_from_tarball(integ_str, tgz)
            .unwrap();
    }
    let pack_from_tarball_cas_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 12. PackStore: decode_package_tarball + put_decoded_package (CI cold path)
    let store_ci_dir = tempdir().unwrap();
    let store_ci = PackStore::new(store_ci_dir.path()).unwrap();
    let extract_base = tempdir().unwrap();
    let t0 = Instant::now();
    for (i, (_, tgz, _, integ_str)) in tarball_payloads.iter().enumerate() {
        let target = extract_base.path().join(format!("pkg-{i}"));
        let decoded = PackStore::decode_package_tarball(tgz, &target, &format!("pkg-{i}")).unwrap();
        store_ci
            .put_decoded_package(integ_str, &target, &decoded, false)
            .unwrap();
    }
    let decode_and_put_ci_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 13. PackStore: large tarball put_package_from_tarball
    let t0 = Instant::now();
    for _ in 0..5 {
        let store_tmp = tempdir().unwrap();
        let st = PackStore::new(store_tmp.path()).unwrap();
        st.put_package_from_tarball(&large_integ, &large_tarball)
            .unwrap();
    }
    let large_tarball_pack_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 14. PackStore: cold disk has_package_pack + get_package_pack across 16 threads (mmap_cache cleared)
    store.clear_mmap_cache();
    let t0 = Instant::now();
    for _ in 0..3 {
        store.clear_mmap_cache();
        for (_, _, _, integ_str) in &tarball_payloads {
            assert!(store.has_package_pack(integ_str));
        }
        let store_ref = &store;
        let payloads_ref = &tarball_payloads;
        let next = std::sync::atomic::AtomicUsize::new(0);
        let next_ref = &next;
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(move || loop {
                    let idx = next_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if idx >= payloads_ref.len() {
                        break;
                    }
                    let pack = store_ref
                        .get_package_pack(&payloads_ref[idx].3)
                        .unwrap()
                        .unwrap();
                    assert!(!pack.data().is_empty());
                });
            }
        });
    }
    let cold_pack_load_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 15. PackStore: cold disk get_package_pack when CAS is populated (has_cas_files = true)
    let t0 = Instant::now();
    for _ in 0..3 {
        store_cas.clear_mmap_cache();
        for (_, _, _, integ_str) in &tarball_payloads {
            let pack = store_cas.get_package_pack(integ_str).unwrap().unwrap();
            assert!(!pack.data().is_empty());
        }
    }
    let cold_pack_load_cas_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 16. PackStore: warm materialize_pack (40 packages)
    let mat_dir = tempdir().unwrap();
    let t0 = Instant::now();
    for (i, (_, _, _, integ_str)) in tarball_payloads.iter().enumerate() {
        let target = mat_dir.path().join(format!("p-{i}"));
        store.materialize_pack(integ_str, &target, None).unwrap();
    }
    let materialize_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!("| Benchmark | Duration (ms) |");
    println!("|---|---:|");
    println!("| cache_put_packument_cold (60x 48KB) | {put_packument_ms:.2} |");
    println!("| cache_put_with_integrity_cold (40x ~25KB) | {put_with_integ_ms:.2} |");
    println!("| cache_put_packument_reput (60x 48KB) | {reput_packument_ms:.2} |");
    println!("| cache_get_hit (5x100 lookups) | {get_hit_ms:.2} |");
    println!("| cache_get_by_integrity_hit (5x40 lookups) | {get_by_integ_ms:.2} |");
    println!("| cache_get_miss (400 misses) | {get_miss_ms:.2} |");
    println!("| cache_verify (100 blobs + 100 indices) | {verify_ms:.2} |");
    println!("| cache_put_file_with_integrity (20x 256KB) | {put_file_ms:.2} |");
    println!("| cache_contended_16_workers | {contended_ms:.2} |");
    println!("| pack_from_verified_tarball_deferred (40 pkgs) | {pack_from_verified_deferred_ms:.2} |");
    println!("| pack_from_tarball_with_cas (40 pkgs) | {pack_from_tarball_cas_ms:.2} |");
    println!("| pack_decode_and_put_ci (40 pkgs) | {decode_and_put_ci_ms:.2} |");
    println!("| pack_large_tarball_with_cas (5x 251 files) | {large_tarball_pack_ms:.2} |");
    println!("| pack_cold_load_no_cas (3x40 pkgs) | {cold_pack_load_ms:.2} |");
    println!("| pack_cold_load_with_cas (3x40 pkgs) | {cold_pack_load_cas_ms:.2} |");
    println!("| pack_materialize (40 pkgs) | {materialize_ms:.2} |");

    // Micro-benchmarks to isolate CPU vs I/O
    use sha2::{Digest, Sha256, Sha512};
    use std::io::Read;
    let hash_buf = vec![0x5Au8; 64 * 1024];
    let t0 = Instant::now();
    let mut dummy = 0u8;
    for _ in 0..2000 {
        let d = Sha512::digest(&hash_buf);
        dummy ^= d[0];
    }
    let sha512_128mb_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t0 = Instant::now();
    for _ in 0..2000 {
        let d = Sha256::digest(&hash_buf);
        dummy ^= d[0];
    }
    let sha256_128mb_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let t0 = Instant::now();
    for _ in 0..5 {
        for (_, tgz, _, _) in &tarball_payloads {
            let mut gz = flate2::read::GzDecoder::new(&tgz[..]);
            let mut out = Vec::with_capacity(80 * 1024);
            gz.read_to_end(&mut out).unwrap();
            dummy ^= out[0];
        }
    }
    let raw_gunzip_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!("| [micro] sha512_128MB | {sha512_128mb_ms:.2} |");
    println!("| [micro] sha256_128MB | {sha256_128mb_ms:.2} |");
    println!("| [micro] raw_gunzip_5x40_pkgs | {raw_gunzip_ms:.2} |");
    assert_ne!(dummy, 255);
}
