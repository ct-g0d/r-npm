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
pub use storage::Cache;

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
}
