use rnpm_cache::storage::Cache;
use rnpm_core::{Algorithm, Integrity};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_multiprocess_stress_cache_contention_16_workers() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_root = temp_dir.path().join("stress-shared-cache");
    let cache = Arc::new(
        Cache::new(&cache_root)
            .unwrap()
            .with_lock_timeout(Duration::from_secs(30)),
    );

    let num_workers = 16;
    let iterations_per_worker = 15;
    let mut handles = Vec::new();
    let failure_count = Arc::new(AtomicUsize::new(0));
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Shared payloads representing tarballs and metadata entries
    let payloads = Arc::new(vec![
        (
            "package-express-4.18.2",
            b"EXPRESS_TARBALL_DATA_BLOB_BYTE_SEQUENCE_12345".to_vec(),
        ),
        (
            "package-react-18.2.0",
            b"REACT_DOM_TARBALL_DATA_BLOB_BYTE_SEQUENCE_67890".to_vec(),
        ),
        (
            "package-chalk-4.1.2",
            b"CHALK_COLOR_DATA_BLOB_BYTE_SEQUENCE_ABCDEF".to_vec(),
        ),
        (
            "package-lodash-4.17.21",
            b"LODASH_UTILS_DATA_BLOB_BYTE_SEQUENCE_GHIJKL".to_vec(),
        ),
        (
            "package-typescript-5.3.3",
            b"TYPESCRIPT_COMPILER_BLOB_BYTE_SEQUENCE_MNOPQR".to_vec(),
        ),
    ]);

    // Spawn 16 concurrent workers hammering the exact same keys and blobs simultaneously
    for worker_id in 0..num_workers {
        let cache_clone = cache.clone();
        let payloads_clone = payloads.clone();
        let fail_cnt = failure_count.clone();

        let handle = std::thread::spawn(move || {
            for iter in 0..iterations_per_worker {
                let payload_idx = (worker_id + iter) % payloads_clone.len();
                let (key, data) = &payloads_clone[payload_idx];

                let integrity = Integrity::from_bytes(data, Algorithm::Sha512);

                // Alternates between put (blob + index) and separate put_blob
                if iter % 2 == 0 {
                    match cache_clone.put(
                        key,
                        data,
                        Some(serde_json::json!({ "worker": worker_id, "iter": iter })),
                    ) {
                        Ok(entry) => {
                            // Read back blob
                            match cache_clone.get_by_sha512(&entry.sha512_hex) {
                                Ok(Some(read_bytes)) => {
                                    if &read_bytes != data {
                                        eprintln!("Worker {worker_id} data mismatch!");
                                        fail_cnt.fetch_add(1, Ordering::SeqCst);
                                    }
                                }
                                Ok(None) => {
                                    eprintln!("Worker {worker_id} blob not found after put!");
                                    fail_cnt.fetch_add(1, Ordering::SeqCst);
                                }
                                Err(e) => {
                                    eprintln!("Worker {worker_id} get_by_sha512 error: {e:?}");
                                    fail_cnt.fetch_add(1, Ordering::SeqCst);
                                }
                            }

                            // Read back index entry
                            match cache_clone.get_index_entry(key) {
                                Ok(Some(idx_entry)) => {
                                    if idx_entry.sha512_hex != entry.sha512_hex {
                                        eprintln!("Worker {worker_id} index mismatch!");
                                        fail_cnt.fetch_add(1, Ordering::SeqCst);
                                    }
                                }
                                Ok(None) => {
                                    eprintln!("Worker {worker_id} index not found after put!");
                                    fail_cnt.fetch_add(1, Ordering::SeqCst);
                                }
                                Err(e) => {
                                    eprintln!("Worker {worker_id} get_index_entry error: {e:?}");
                                    fail_cnt.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Worker {worker_id} put error: {e:?}");
                            fail_cnt.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                } else {
                    match cache_clone.put_blob(data, Some(&integrity)) {
                        Ok(digest) => match cache_clone.get_by_sha512(&digest) {
                            Ok(Some(read_bytes)) => {
                                if &read_bytes != data {
                                    eprintln!("Worker {worker_id} blob data mismatch!");
                                    fail_cnt.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            Ok(None) => {
                                eprintln!("Worker {worker_id} blob missing after put_blob!");
                                fail_cnt.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(e) => {
                                eprintln!("Worker {worker_id} get_by_sha512 error: {e:?}");
                                fail_cnt.fetch_add(1, Ordering::SeqCst);
                            }
                        },
                        Err(e) => {
                            eprintln!("Worker {worker_id} put_blob error: {e:?}");
                            fail_cnt.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Also run concurrent cache verification in a separate thread while workers write
    let cache_verify_clone = cache.clone();
    let stop_signal_clone = stop_signal.clone();
    let verify_fail_cnt = failure_count.clone();
    let verify_handle = std::thread::spawn(move || {
        while !stop_signal_clone.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(40));
            if let Ok(report) = cache_verify_clone.verify() {
                if report.corrupted_blobs > 0 || report.corrupted_indices > 0 {
                    eprintln!("Cache corruption observed during concurrency: {report:?}");
                    verify_fail_cnt.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    });

    for h in handles {
        h.join().unwrap();
    }
    stop_signal.store(true, Ordering::SeqCst);
    verify_handle.join().unwrap();

    assert_eq!(
        failure_count.load(Ordering::SeqCst),
        0,
        "No failures or data corruptions permitted under 16-worker contention"
    );

    // Final strict verification
    let report = cache.verify().unwrap();
    assert_eq!(
        report.corrupted_blobs, 0,
        "Final check: zero corrupted blobs"
    );
    assert_eq!(
        report.corrupted_indices, 0,
        "Final check: zero corrupted indices"
    );
    assert_eq!(
        report.orphaned_indices, 0,
        "Final check: zero orphaned indices"
    );
    assert!(report.verified_blobs > 0, "Expected verified blobs");
    assert!(report.verified_indices > 0, "Expected verified indices");
}
