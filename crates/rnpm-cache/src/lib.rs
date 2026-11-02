//! Content-addressable cache storage for rnpm.
//!
//! Provides content-addressable storage (blobs stored by sha512 digest),
//! index metadata mapping keys to integrity and attributes,
//! atomic writes using temporary files on the same filesystem/volume,
//! cross-process file locking using fs4, and automated corruption recovery
//! (purging corrupt files and signaling a miss for re-fetching).

pub mod error;
pub mod index;
pub mod lock;
pub mod storage;

pub use error::CacheError;
pub use index::IndexEntry;
pub use lock::CacheLock;
pub use storage::{Cache, VerifyReport};

#[cfg(test)]
mod tests {
    use super::*;
    use rnpm_core::{Algorithm, Integrity};
    use tempfile::tempdir;

    #[test]
    fn test_cache_put_and_get() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let data = b"package tarball content v1.0.0";
        let key = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz";

        let entry = cache.put(key, data, None).unwrap();
        assert_eq!(entry.key, key);
        assert_eq!(entry.size, data.len() as u64);

        // Verify retrieval by key
        let (retrieved_entry, retrieved_data) = cache.get(key).unwrap().expect("Cache hit expected");
        assert_eq!(retrieved_entry.integrity, entry.integrity);
        assert_eq!(retrieved_data, data);

        // Verify retrieval by sha512
        let by_digest = cache
            .get_by_sha512(&entry.sha512_hex)
            .unwrap()
            .expect("Blob hit expected");
        assert_eq!(by_digest, data);
    }

    #[test]
    fn test_corrupted_blob_recovery() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let data = b"valid content before corruption";
        let key = "https://registry.npmjs.org/corrupt-test/-/corrupt-test-1.0.0.tgz";

        let entry = cache.put(key, data, None).unwrap();
        let blob_path = cache.blob_path(&entry.sha512_hex);
        assert!(blob_path.exists());

        // Now intentionally corrupt the blob file on disk
        std::fs::write(&blob_path, b"intentionally corrupted bytes").unwrap();

        // Calling get() should detect corruption, purge the corrupted file, and return None (miss)
        let result = cache.get(key).unwrap();
        assert!(result.is_none(), "Corrupted entry should return None (miss)");

        // Verify the corrupted blob file was PURGED from disk!
        assert!(
            !blob_path.exists(),
            "Corrupted file must be purged from disk"
        );

        // Calling get_by_sha512 directly also returns None
        let digest_result = cache.get_by_sha512(&entry.sha512_hex).unwrap();
        assert!(digest_result.is_none());

        // Now we should be able to safely re-put and re-fetch (simulating re-fetch from registry)
        let new_entry = cache.put(key, data, None).unwrap();
        assert!(cache.blob_path(&new_entry.sha512_hex).exists());
        let (_, refetched) = cache.get(key).unwrap().expect("Refetched entry hit");
        assert_eq!(refetched, data);
    }

    #[test]
    fn test_atomic_writes_on_same_volume() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        // Verify tmp_dir is inside cache root (same volume/filesystem)
        assert!(cache.tmp_dir().starts_with(cache.root()));

        let data = b"atomic write verification payload";
        let integrity = Integrity::from_bytes(data, Algorithm::Sha512);

        let sha512_hex = cache.put_blob(data, Some(&integrity)).unwrap();
        let blob_path = cache.blob_path(&sha512_hex);
        assert!(blob_path.exists());

        // Ensure temp folder has no leftover files
        let tmp_entries: Vec<_> = std::fs::read_dir(cache.tmp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(tmp_entries.len(), 0, "No temp files should remain after atomic rename");
    }

    #[test]
    fn test_cross_process_file_locking() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let lock1 = cache.lock_key("concurrent-key").unwrap();

        // Trying to acquire an exclusive lock on the same key should fail with would-block or return None
        let lock_path = cache.lock_path("idx_concurrent-key");
        // Try non-blocking acquisition
        let _try_lock = CacheLock::try_acquire_exclusive(&lock_path);
        // On Windows / Unix, when locked by lock1, try_lock should either be Ok(None) or Err(WouldBlock)
        drop(lock1);

        // After dropping lock1, lock can be acquired
        let lock2 = cache.lock_key("concurrent-key");
        assert!(lock2.is_ok());
    }

    #[test]
    fn test_put_blob_integrity_mismatch_fails() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let data = b"actual payload";
        let fake_integrity = Integrity::from_bytes(b"different payload", Algorithm::Sha512);

        let err = cache.put_blob(data, Some(&fake_integrity)).unwrap_err();
        assert!(matches!(err, CacheError::IntegrityMismatch { .. }));
    }

    #[test]
    fn test_concurrent_puts_and_locks() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path()).unwrap());

        let mut handles = Vec::new();
        // Spawn 8 concurrent threads putting both same and different keys
        for i in 0..8 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                // Shared key contended by all threads
                let shared_key = "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz";
                let shared_data = b"shared content written concurrently";
                let entry1 = cache_clone.put(shared_key, shared_data, None).unwrap();
                assert_eq!(entry1.size, shared_data.len() as u64);

                // Unique key per thread
                let unique_key = format!("https://registry.npmjs.org/pkg-{i}/-/pkg-{i}-1.0.0.tgz");
                let unique_data = format!("unique content for thread {i}").into_bytes();
                let entry2 = cache_clone.put(&unique_key, &unique_data, None).unwrap();
                assert_eq!(entry2.size, unique_data.len() as u64);

                // Verify immediate retrieval
                let (_, retrieved) = cache_clone.get(&unique_key).unwrap().expect("Cache hit expected");
                assert_eq!(retrieved, unique_data);
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().expect("Worker thread panicked");
        }

        // Verify shared key is consistent and valid
        let (_, retrieved_shared) = cache.get("https://registry.npmjs.org/shared/-/shared-1.0.0.tgz").unwrap().expect("Shared cache hit");
        assert_eq!(retrieved_shared, b"shared content written concurrently");

        // Verify no leftover .tmp files
        let tmp_entries: Vec<_> = std::fs::read_dir(cache.tmp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(tmp_entries.len(), 0, "No orphaned temporary files in cache tmp directory");
    }

    #[test]
    fn test_corrupt_index_auto_recovery() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key = "https://registry.npmjs.org/bad-index/-/bad-index-1.0.0.tgz";
        let data = b"some payload";
        let _ = cache.put(key, data, None).unwrap();

        let index_path = IndexEntry::path_for_key(cache.root(), key);
        assert!(index_path.exists());

        // Corrupt the index JSON with invalid syntax
        std::fs::write(&index_path, b"{ not valid json syntax ...").unwrap();

        // get() should handle corrupt JSON, purge the file, and return None (miss)
        let res = cache.get(key).unwrap();
        assert!(res.is_none(), "Corrupted index must return cache miss");
        assert!(!index_path.exists(), "Corrupted index must be purged");
    }

    #[test]
    fn test_non_utf8_index_corruption_recovery() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key = "https://registry.npmjs.org/binary-corrupt/-/binary-corrupt-1.0.0.tgz";
        let data = b"payload";
        let _ = cache.put(key, data, None).unwrap();

        let index_path = IndexEntry::path_for_key(cache.root(), key);
        assert!(index_path.exists());

        // Corrupt the index file with invalid UTF-8 binary bytes
        std::fs::write(&index_path, [0xFF, 0xFE, 0xFD, 0x00, 0x80]).unwrap();

        let res = cache.get(key).unwrap();
        assert!(res.is_none(), "Non-UTF8 corrupt index must return cache miss");
        assert!(!index_path.exists(), "Non-UTF8 corrupt index must be purged");
    }

    #[test]
    fn test_lock_timeout_and_recovery() {
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let lock_path = cache.lock_path("test-timeout-lock");

        // Acquire lock1
        let lock1 = CacheLock::acquire_exclusive(&lock_path).unwrap();

        // Attempting to acquire with a very short timeout should fail with TimedOut / LockFailed
        let start = std::time::Instant::now();
        let err = CacheLock::acquire_exclusive_timeout(&lock_path, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(45));

        drop(lock1);

        // After dropping lock1, lock can be acquired immediately
        let lock2 = CacheLock::acquire_exclusive_timeout(&lock_path, Duration::from_millis(500));
        assert!(lock2.is_ok());
    }

    #[test]
    fn test_clean_stale_temp_files() {
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        // Create dummy temp files
        let tmp1 = cache.tmp_dir().join("test_old.tmp");
        let tmp2 = cache.tmp_dir().join("test_fresh.tmp");
        std::fs::write(&tmp1, b"old temp").unwrap();
        std::fs::write(&tmp2, b"fresh temp").unwrap();

        // Clean files older than 0 seconds (all files)
        let cleaned = cache.clean_stale_temp_files(Duration::from_secs(0)).unwrap();
        assert_eq!(cleaned, 2);
        assert!(!tmp1.exists());
        assert!(!tmp2.exists());
    }

    #[test]
    fn test_purge_corrupted_sweep() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        // 1. Put valid entry
        let key = "https://registry.npmjs.org/sweep-test/-/sweep-test-1.0.0.tgz";
        let data = b"valid sweep data";
        let entry = cache.put(key, data, None).unwrap();

        // 2. Put corrupted file in content-v2
        let blob_path = cache.blob_path(&entry.sha512_hex);
        std::fs::write(&blob_path, b"corrupted bytes").unwrap();

        // 3. Put corrupted index
        let index_path = IndexEntry::path_for_key(cache.root(), key);
        std::fs::write(&index_path, b"not json").unwrap();

        // Run sweep
        let purged = cache.purge_corrupted().unwrap();
        assert!(purged >= 2, "Sweep must purge both corrupted blob and corrupted index");
        assert!(!blob_path.exists());
        assert!(!index_path.exists());
    }

    fn run_cache_multiprocess_worker(worker_id: &str, cache_dir: &str) {
        let cache = Cache::new(cache_dir).expect("Worker failed to init cache");

        // 1. Write unique keys
        for item in 0..15 {
            let key = format!("https://registry.npmjs.org/{worker_id}-pkg-{item}/-/{worker_id}-pkg-{item}-1.0.0.tgz");
            let data = format!("{worker_id} payload data {item}").into_bytes();
            cache.put(&key, &data, None).expect("Worker failed to put unique key");

            let (_, read_back) = cache.get(&key).expect("Worker failed get").expect("Must hit cache");
            assert_eq!(read_back, data);
        }

        // 2. Contend on shared keys across all workers
        let shared_key = "https://registry.npmjs.org/multiprocess-shared/-/multiprocess-shared-1.0.0.tgz";
        for i in 0..5 {
            let shared_data = format!("shared multiprocess payload from {worker_id} iter {i}").into_bytes();
            let _ = cache.put(shared_key, &shared_data, None);
            let _ = cache.get(shared_key);
        }
    }

    #[test]
    fn test_concurrent_multiprocess_cache_reads_writes() {
        // If launched as a child worker process:
        if let Ok(worker_id) = std::env::var("RNPM_CACHE_WORKER_ID") {
            let cache_dir = std::env::var("RNPM_CACHE_DIR").expect("RNPM_CACHE_DIR must be set");
            run_cache_multiprocess_worker(&worker_id, &cache_dir);
            return;
        }

        // Main test coordinator:
        let dir = tempdir().unwrap();
        let cache_dir_str = dir.path().to_str().unwrap().to_string();
        let current_exe = std::env::current_exe().unwrap();

        // Spawn 4 child processes concurrently
        let mut children = Vec::new();
        for i in 0..4 {
            let child = std::process::Command::new(&current_exe)
                .args(["--nocapture", "tests::test_concurrent_multiprocess_cache_reads_writes"])
                .env("RNPM_CACHE_WORKER_ID", format!("worker-{i}"))
                .env("RNPM_CACHE_DIR", &cache_dir_str)
                .spawn()
                .expect("Failed to spawn cache worker process");
            children.push(child);
        }

        // Coordinator also performs concurrent cache operations in parallel with the 4 child processes
        let cache = Cache::new(dir.path()).unwrap();
        for i in 0..20 {
            let key = format!("https://registry.npmjs.org/coord-pkg-{i}/-/coord-pkg-{i}-1.0.0.tgz");
            let data = format!("coordinator payload {i}").into_bytes();
            cache.put(&key, &data, None).unwrap();
            let (_, retrieved) = cache.get(&key).unwrap().expect("Coordinator read miss");
            assert_eq!(retrieved, data);
        }

        // Wait for all child processes and assert they exited successfully
        for mut child in children {
            let status = child.wait().expect("Failed to wait on child process");
            assert!(status.success(), "Child worker process exited with failure: {:?}", status);
        }

        // Verify all keys written by workers are present and uncorrupted
        for w in 0..4 {
            for item in 0..15 {
                let key = format!("https://registry.npmjs.org/worker-{w}-pkg-{item}/-/worker-{w}-pkg-{item}-1.0.0.tgz");
                let expected_data = format!("worker-{w} payload data {item}").into_bytes();
                let (_, retrieved) = cache.get(&key).unwrap().expect("Worker key should be in cache");
                assert_eq!(retrieved, expected_data, "Data mismatch for key {key}");
            }
        }

        // Verify shared key written by all workers concurrently
        let shared_key = "https://registry.npmjs.org/multiprocess-shared/-/multiprocess-shared-1.0.0.tgz";
        let (_, shared_data) = cache.get(shared_key).unwrap().expect("Shared key must exist");
        assert!(shared_data.starts_with(b"shared multiprocess payload"));

        // Verify no temporary files remain in tmp directory
        let tmp_entries: Vec<_> = std::fs::read_dir(cache.tmp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(tmp_entries.len(), 0, "No orphaned temp files after multiprocess stress");
    }

    #[test]
    fn test_simulated_stale_lock_recovery() {
        use std::thread::sleep;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap()
            .with_lock_timeout(Duration::from_millis(150))
            .with_stale_threshold(Duration::from_millis(40));

        let lock_path = cache.lock_path("idx_simulated_stale");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        // Create an abandoned lock file simulating a dead process
        std::fs::write(&lock_path, b"pid=9999999 time=1000\n").unwrap();
        assert!(lock_path.exists());

        // Wait so the lock file age exceeds the 40ms stale threshold
        sleep(Duration::from_millis(60));

        // Attempt to acquire lock on the stale path
        let acquired = CacheLock::acquire_exclusive_with_options(
            &lock_path,
            Duration::from_millis(100),
            Duration::from_millis(40),
        );

        assert!(
            acquired.is_ok(),
            "Must successfully auto-recover abandoned stale lock: {:?}",
            acquired.err()
        );

        let lock = acquired.unwrap();
        assert!(lock.path().exists());

        // Drop the lock guard to release the exclusive lock before reading file content on Windows
        drop(lock);

        // Content of lock should have been overwritten with current pid
        let content = std::fs::read_to_string(&lock_path).unwrap();
        let current_pid = std::process::id();
        assert!(
            content.contains(&format!("pid={current_pid}")),
            "Lock file must be refreshed with current PID, got: {content}"
        );
    }

    #[test]
    fn test_rapid_lock_timeouts_and_contention() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let cache = Arc::new(
            Cache::new(dir.path()).unwrap()
                .with_lock_timeout(Duration::from_millis(20))
                .with_stale_threshold(Duration::from_secs(60))
        );

        let lock_path = cache.lock_path("rapid_contention_lock");

        // Primary lock holder acquires exclusive lock
        let primary_lock = CacheLock::acquire_exclusive(&lock_path).unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let timeout_count = Arc::new(AtomicUsize::new(0));

        let mut workers = Vec::new();
        // Spawn 8 worker threads that rapidly attempt to acquire the held lock with 15ms timeout
        for _ in 0..8 {
            let lp = lock_path.clone();
            let r = Arc::clone(&running);
            let tc = Arc::clone(&timeout_count);
            let h = thread::spawn(move || {
                while r.load(Ordering::Relaxed) {
                    let res = CacheLock::acquire_exclusive_timeout(&lp, Duration::from_millis(15));
                    if let Err(e) = res {
                        if e.kind() == std::io::ErrorKind::TimedOut {
                            tc.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            });
            workers.push(h);
        }

        // Let workers hammer the lock and experience rapid timeouts
        thread::sleep(Duration::from_millis(120));
        assert!(
            timeout_count.load(Ordering::Relaxed) > 10,
            "Expected multiple rapid timeouts under contention, got {}",
            timeout_count.load(Ordering::Relaxed)
        );

        // Signal workers to stop
        running.store(false, Ordering::Relaxed);
        for h in workers {
            h.join().unwrap();
        }

        // Release the primary lock
        drop(primary_lock);

        // Now rapid acquisition must immediately succeed
        let fresh_lock = CacheLock::acquire_exclusive_timeout(&lock_path, Duration::from_millis(200));
        assert!(fresh_lock.is_ok(), "Lock must be immediately acquirable after release");
    }

    #[test]
    fn test_concurrent_high_parallel_cache_hammering() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path()).unwrap());

        let mut handles = Vec::new();
        // 16 parallel threads performing concurrent cache operations
        for thread_idx in 0..16 {
            let c = Arc::clone(&cache);
            let h = thread::spawn(move || {
                for iter in 0..10 {
                    // Contended shared key
                    let shared_key = format!("https://registry.npmjs.org/contended-{}/-/contended.tgz", iter % 3);
                    let payload = format!("contended-payload-{thread_idx}-{iter}").into_bytes();
                    let _ = c.put(&shared_key, &payload, None);
                    let _ = c.get(&shared_key);

                    // Thread-local unique key
                    let unique_key = format!("https://registry.npmjs.org/unique-{thread_idx}-{iter}/-/unique.tgz");
                    let unique_data = format!("unique-data-{thread_idx}-{iter}").into_bytes();
                    c.put(&unique_key, &unique_data, None).unwrap();
                    let (_, retrieved) = c.get(&unique_key).unwrap().expect("Must hit cache");
                    assert_eq!(retrieved, unique_data);
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().expect("Worker thread panicked under cache hammering");
        }

        // Clean temp sweep
        let remaining_tmp = cache.clean_stale_temp_files(std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(remaining_tmp, 0, "No temporary files should be orphaned");
    }

    #[test]
    fn test_verify_healthy_cache() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        for i in 0..5 {
            let key = format!("https://registry.npmjs.org/healthy-pkg-{i}/-/healthy-{i}.tgz");
            let data = format!("healthy payload content {i}").into_bytes();
            cache.put(&key, &data, None).unwrap();
        }

        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 5);
        assert_eq!(report.verified_indices, 5);
        assert_eq!(report.corrupted_blobs, 0);
        assert_eq!(report.corrupted_indices, 0);
        assert_eq!(report.orphaned_indices, 0);
        assert_eq!(report.stale_temp_files_cleaned, 0);
        assert!(report.is_clean());
        assert_eq!(report.total_purged(), 0);
        assert_eq!(report.total_verified(), 10);
        assert!(report.total_blob_bytes > 0);

        // Verify Display trait
        let display_str = format!("{report}");
        assert!(display_str.contains("5 blobs verified"));
        assert!(display_str.contains("5 index entries verified"));

        // Verify that all entries can still be read
        for i in 0..5 {
            let key = format!("https://registry.npmjs.org/healthy-pkg-{i}/-/healthy-{i}.tgz");
            let expected_data = format!("healthy payload content {i}").into_bytes();
            let (_, data) = cache.get(&key).unwrap().expect("Must find entry");
            assert_eq!(data, expected_data);
        }
    }

    #[test]
    fn test_verify_corrupted_blob_and_orphaned_index() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key1 = "https://registry.npmjs.org/pkg-corrupt/-/pkg-corrupt-1.0.0.tgz";
        let entry1 = cache.put(key1, b"valid original data 1", None).unwrap();

        let key2 = "https://registry.npmjs.org/pkg-intact/-/pkg-intact-1.0.0.tgz";
        let _entry2 = cache.put(key2, b"valid original data 2", None).unwrap();

        // Deliberately corrupt blob 1 on disk
        let blob1_path = cache.blob_path(&entry1.sha512_hex);
        assert!(blob1_path.exists());
        std::fs::write(&blob1_path, b"bad checksum bytes").unwrap();

        let report = cache.verify().unwrap();
        assert_eq!(report.corrupted_blobs, 1, "Blob 1 must be detected as corrupted and purged");
        assert_eq!(report.verified_blobs, 1, "Blob 2 must be verified successfully");
        assert_eq!(report.orphaned_indices, 1, "Index 1 must be purged as orphan since its blob was purged");
        assert_eq!(report.verified_indices, 1, "Index 2 must remain verified");
        assert_eq!(report.corrupted_indices, 0);
        assert_eq!(report.stale_temp_files_cleaned, 0);
        assert!(!report.is_clean());

        // Blob 1 must be deleted from disk
        assert!(!blob1_path.exists(), "Corrupted blob 1 must no longer exist");

        // Index 1 must be deleted from disk
        let index1_path = IndexEntry::path_for_key(cache.root(), key1);
        assert!(!index1_path.exists(), "Orphaned index 1 must no longer exist");

        // get(key1) should now return None (miss)
        let get1 = cache.get(key1).unwrap();
        assert!(get1.is_none());

        // get(key2) should still succeed
        let (_, get2_data) = cache.get(key2).unwrap().expect("Key 2 must be intact");
        assert_eq!(get2_data, b"valid original data 2");
    }

    #[test]
    fn test_verify_corrupted_index_purged() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key1 = "https://registry.npmjs.org/idx-corrupt/-/idx-corrupt-1.0.0.tgz";
        let entry1 = cache.put(key1, b"blob data 1", None).unwrap();

        let key2 = "https://registry.npmjs.org/idx-intact/-/idx-intact-1.0.0.tgz";
        let _ = cache.put(key2, b"blob data 2", None).unwrap();

        // Corrupt index 1 with invalid JSON syntax
        let index1_path = IndexEntry::path_for_key(cache.root(), key1);
        assert!(index1_path.exists());
        std::fs::write(&index1_path, b"{{{{ invalid json content").unwrap();

        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 2, "Both blobs are intact");
        assert_eq!(report.corrupted_blobs, 0);
        assert_eq!(report.corrupted_indices, 1, "Index 1 must be purged as corrupted");
        assert_eq!(report.verified_indices, 1, "Index 2 must be verified");
        assert_eq!(report.orphaned_indices, 0);

        assert!(!index1_path.exists(), "Corrupt index 1 must be purged");
        // But blob 1 is still preserved in CAS storage
        let blob1_path = cache.blob_path(&entry1.sha512_hex);
        assert!(blob1_path.exists(), "Intact blob 1 must be preserved in content-v2");

        // get(key1) is a miss, get(key2) is a hit
        assert!(cache.get(key1).unwrap().is_none());
        assert!(cache.get(key2).unwrap().is_some());
    }

    #[test]
    fn test_verify_missing_blob_orphaned_index() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key = "https://registry.npmjs.org/orphan-pkg/-/orphan-pkg-1.0.0.tgz";
        let entry = cache.put(key, b"ephemeral data", None).unwrap();

        let blob_path = cache.blob_path(&entry.sha512_hex);
        let index_path = IndexEntry::path_for_key(cache.root(), key);
        assert!(blob_path.exists());
        assert!(index_path.exists());

        // Remove blob directly from disk
        std::fs::remove_file(&blob_path).unwrap();

        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 0);
        assert_eq!(report.corrupted_blobs, 0);
        assert_eq!(report.orphaned_indices, 1, "Index pointing to missing blob must be purged");
        assert_eq!(report.verified_indices, 0);
        assert!(!index_path.exists(), "Orphaned index must be purged from disk");
    }

    #[test]
    fn test_verify_stale_temp_files() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        let key = "https://registry.npmjs.org/temp-pkg/-/temp-pkg-1.0.0.tgz";
        cache.put(key, b"valid payload", None).unwrap();

        // Create 3 stale temp files and a temp subdirectory in tmp
        let tmp1 = cache.tmp_dir().join("stale_worker1.tmp");
        let tmp2 = cache.tmp_dir().join("stale_worker2.tmp");
        let tmp3 = cache.tmp_dir().join("stale_worker3.tmp");
        let tmp_sub = cache.tmp_dir().join("stale_subdir");
        std::fs::create_dir_all(&tmp_sub).unwrap();
        let tmp4 = tmp_sub.join("nested.tmp");
        std::fs::write(&tmp1, b"partial write 1").unwrap();
        std::fs::write(&tmp2, b"partial write 2").unwrap();
        std::fs::write(&tmp3, b"partial write 3").unwrap();
        std::fs::write(&tmp4, b"nested tmp").unwrap();

        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 1);
        assert_eq!(report.verified_indices, 1);
        assert!(report.stale_temp_files_cleaned >= 3);

        // Verify tmp_dir is empty
        let remaining_tmp: Vec<_> = std::fs::read_dir(cache.tmp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(remaining_tmp.len(), 0);

        // Second verification should be completely clean
        let clean_report = cache.verify().unwrap();
        assert!(clean_report.is_clean());
    }

    #[test]
    fn test_verify_complex_combined_corruptions() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        // 1. Two healthy entries
        cache.put("key-healthy-1", b"healthy-data-1", None).unwrap();
        cache.put("key-healthy-2", b"healthy-data-2", None).unwrap();

        // 2. Corrupted blob entry
        let corrupt_entry = cache.put("key-corrupt-blob", b"original data before corruption", None).unwrap();
        let corrupt_blob_path = cache.blob_path(&corrupt_entry.sha512_hex);
        std::fs::write(&corrupt_blob_path, b"totally mismatched digest content").unwrap();

        // 3. Corrupted index entry (garbage UTF-8)
        let corrupt_idx_key = "key-corrupt-index";
        cache.put(corrupt_idx_key, b"valid blob but broken index", None).unwrap();
        let corrupt_idx_path = IndexEntry::path_for_key(cache.root(), corrupt_idx_key);
        std::fs::write(&corrupt_idx_path, [0x80, 0x81, 0xFF, 0xFE, 0x00]).unwrap();

        // 4. Orphaned index entry (delete blob)
        let orphan_key = "key-orphan";
        let orphan_entry = cache.put(orphan_key, b"orphan payload", None).unwrap();
        std::fs::remove_file(cache.blob_path(&orphan_entry.sha512_hex)).unwrap();

        // 5. Stale temp files
        let tmp_file1 = cache.tmp_dir().join("crash_leftover_1.tmp");
        let tmp_file2 = cache.tmp_dir().join("crash_leftover_2.tmp");
        std::fs::write(&tmp_file1, b"abandoned write").unwrap();
        std::fs::write(&tmp_file2, b"abandoned write").unwrap();

        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 3, "2 healthy blobs + 1 orphan-index blob");
        assert_eq!(report.corrupted_blobs, 1, "1 corrupted blob purged");
        assert_eq!(report.verified_indices, 2, "2 healthy indices");
        assert_eq!(report.corrupted_indices, 1, "1 non-utf8 corrupted index purged");
        assert_eq!(report.orphaned_indices, 2, "1 orphan-key + 1 corrupt-blob-key orphaned indices");
        assert_eq!(report.stale_temp_files_cleaned, 2, "2 stale temp files cleaned");
        assert_eq!(report.total_purged(), 6);
        assert!(!report.is_clean());

        // Now run verify again - cache must be 100% clean
        let second_report = cache.verify().unwrap();
        assert!(second_report.is_clean());
        assert_eq!(second_report.verified_blobs, 3);
        assert_eq!(second_report.verified_indices, 2);
        assert_eq!(second_report.total_purged(), 0);

        // Healthy entries still retrieve correctly
        assert_eq!(cache.get("key-healthy-1").unwrap().unwrap().1, b"healthy-data-1");
        assert_eq!(cache.get("key-healthy-2").unwrap().unwrap().1, b"healthy-data-2");
    }

    #[test]
    fn test_clean_purges_all_contents_and_handles_readonly_attributes() {
        let dir = tempdir().unwrap();
        let cache = Cache::new(dir.path()).unwrap();

        // Populate with multiple entries
        for i in 0..6 {
            let key = format!("https://registry.npmjs.org/clean-pkg-{i}/-/pkg-{i}.tgz");
            let data = format!("clean test payload {i}").into_bytes();
            let entry = cache.put(&key, &data, None).unwrap();

            // Set readonly attribute on some blob files and index files
            if i % 2 == 0 {
                let blob_path = cache.blob_path(&entry.sha512_hex);
                let mut perms = std::fs::metadata(&blob_path).unwrap().permissions();
                perms.set_readonly(true);
                std::fs::set_permissions(&blob_path, perms).unwrap();

                let index_path = IndexEntry::path_for_key(cache.root(), &key);
                let mut iperms = std::fs::metadata(&index_path).unwrap().permissions();
                iperms.set_readonly(true);
                std::fs::set_permissions(&index_path, iperms).unwrap();
            }
        }

        // Add readonly temp file
        let tmp_file = cache.tmp_dir().join("readonly_temp.tmp");
        std::fs::write(&tmp_file, b"readonly temp file").unwrap();
        let mut tperms = std::fs::metadata(&tmp_file).unwrap().permissions();
        tperms.set_readonly(true);
        std::fs::set_permissions(&tmp_file, tperms).unwrap();

        // Add lock file
        let lock_path = cache.lock_path("sample_lock");
        std::fs::write(&lock_path, b"dummy lock").unwrap();

        // Execute cache clean
        cache.clean().expect("Cache clean must succeed even with readonly files");

        // Verify content-v2, index-v5, tmp, locks directories exist but are empty
        assert!(cache.root().join("content-v2").join("sha512").exists());
        assert!(cache.root().join("index-v5").exists());
        assert!(cache.tmp_dir().exists());
        assert!(cache.root().join("locks").exists());

        let tmp_entries: Vec<_> = std::fs::read_dir(cache.tmp_dir()).unwrap().collect();
        assert_eq!(tmp_entries.len(), 0);

        let index_entries: Vec<_> = std::fs::read_dir(cache.root().join("index-v5")).unwrap().collect();
        assert_eq!(index_entries.len(), 0);

        // Verify cache is immediately usable for put and get
        let post_clean_key = "https://registry.npmjs.org/fresh-pkg/-/fresh-1.0.0.tgz";
        let post_clean_data = b"post clean valid content";
        let entry = cache.put(post_clean_key, post_clean_data, None).unwrap();
        assert_eq!(entry.size, post_clean_data.len() as u64);

        let (_, retrieved) = cache.get(post_clean_key).unwrap().expect("Must retrieve post-clean entry");
        assert_eq!(retrieved, post_clean_data);

        // Verification on post-clean cache is clean
        let report = cache.verify().unwrap();
        assert_eq!(report.verified_blobs, 1);
        assert_eq!(report.verified_indices, 1);
        assert!(report.is_clean());
    }

    #[test]
    fn test_stress_concurrent_writes_verify_and_clean() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let cache = Arc::new(Cache::new(dir.path()).unwrap());
        let running = Arc::new(AtomicBool::new(true));

        let mut workers = Vec::new();

        // 6 writer threads performing concurrent puts
        for w in 0..6 {
            let c = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for iter in 0..10 {
                    let key = format!("https://registry.npmjs.org/stress-w{w}-{iter}/-/pkg.tgz");
                    let data = format!("stress payload w{w} iter {iter}").into_bytes();
                    c.put(&key, &data, None).expect("Worker put failed");
                    let (_, retrieved) = c.get(&key).expect("Worker get failed").expect("Must hit cache");
                    assert_eq!(retrieved, data);
                    thread::sleep(Duration::from_millis(2));
                }
            });
            workers.push(handle);
        }

        // 2 verifier threads continuously running verify concurrently with writers
        for _v in 0..2 {
            let c = Arc::clone(&cache);
            let r = Arc::clone(&running);
            let handle = thread::spawn(move || {
                while r.load(Ordering::Relaxed) {
                    let _ = c.verify();
                    thread::sleep(Duration::from_millis(10));
                }
            });
            workers.push(handle);
        }

        // Let threads stress the cache concurrently
        thread::sleep(Duration::from_millis(150));
        running.store(false, Ordering::Relaxed);

        for w in workers {
            w.join().expect("Stress thread panicked");
        }

        // Cache verification after stress
        let report = cache.verify().unwrap();
        assert!(report.verified_blobs > 0);
        assert!(report.verified_indices > 0);

        // Cache clean after stress
        cache.clean().unwrap();

        // Cache must be usable again
        let final_entry = cache.put("final-key", b"final data", None).unwrap();
        assert_eq!(final_entry.size, 10);
        let (_, final_data) = cache.get("final-key").unwrap().expect("Must retrieve final entry");
        assert_eq!(final_data, b"final data");
    }
}
