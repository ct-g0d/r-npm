use crate::error::CacheError;
use crate::index::IndexEntry;
use crate::lock::CacheLock;
use data_encoding::HEXLOWER;
use rnpm_core::{Algorithm, Integrity, IntegrityError};
use sha2::{Digest, Sha512};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Content-addressable cache manager.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Initialize a cache instance at the given root directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("content-v2").join("sha512"))?;
        fs::create_dir_all(root.join("index-v5"))?;
        fs::create_dir_all(root.join("tmp"))?;
        fs::create_dir_all(root.join("locks"))?;
        Ok(Self { root })
    }

    /// Root directory of this cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Temp directory located on the SAME filesystem/volume for atomic renames.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Compute storage path for a SHA-512 digest hex string.
    pub fn blob_path(&self, sha512_hex: &str) -> PathBuf {
        let hex = sha512_hex.to_ascii_lowercase();
        let p1 = if hex.len() >= 2 { &hex[0..2] } else { "xx" };
        let p2 = if hex.len() >= 4 { &hex[2..4] } else { "yy" };
        self.root
            .join("content-v2")
            .join("sha512")
            .join(p1)
            .join(p2)
            .join(&hex)
    }

    /// Compute lock file path for a given resource name.
    pub fn lock_path(&self, name: &str) -> PathBuf {
        let safe_name = name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();
        self.root.join("locks").join(format!("{safe_name}.lock"))
    }

    /// Acquire an exclusive cross-process lock for a key.
    pub fn lock_key(&self, key: &str) -> Result<CacheLock, CacheError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        let hash = HEXLOWER.encode(&hasher.finalize());
        let lock_path = self.lock_path(&format!("idx_{hash}"));
        CacheLock::acquire_exclusive(&lock_path).map_err(CacheError::Io)
    }

    /// Acquire an exclusive cross-process lock for a blob digest.
    pub fn lock_blob(&self, sha512_hex: &str) -> Result<CacheLock, CacheError> {
        let lock_path = self.lock_path(&format!("blob_{sha512_hex}"));
        CacheLock::acquire_exclusive(&lock_path).map_err(CacheError::Io)
    }

    /// Create a unique temporary file path within `<cache_root>/tmp` (guaranteed on same volume).
    fn create_temp_path(&self, prefix: &str) -> PathBuf {
        let count = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let filename = format!("{prefix}_{pid}_{now}_{count}.tmp");
        self.tmp_dir().join(filename)
    }

    /// Atomically store raw bytes into content-addressable storage.
    ///
    /// Writes to a temporary file in `<cache_root>/tmp`, verifies the checksum,
    /// and then renames to the final content-addressable path.
    pub fn put_blob(
        &self,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
    ) -> Result<String, CacheError> {
        // Calculate SHA-512
        let mut hasher = Sha512::new();
        hasher.update(data);
        let digest_bytes = hasher.finalize();
        let sha512_hex = HEXLOWER.encode(&digest_bytes);

        // Verify against expected integrity if provided
        if let Some(expected) = expected_integrity {
            expected.verify(data).map_err(|e| match e {
                IntegrityError::Mismatch {
                    algorithm: _,
                    expected,
                    actual,
                } => CacheError::IntegrityMismatch {
                    key: sha512_hex.clone(),
                    expected,
                    actual,
                },
                other => CacheError::Core(rnpm_core::CoreError::Integrity(other)),
            })?;
        }

        let target_path = self.blob_path(&sha512_hex);
        if target_path.exists() {
            // Check if existing file has valid content
            if let Ok(existing_bytes) = fs::read(&target_path) {
                let mut h = Sha512::new();
                h.update(&existing_bytes);
                if HEXLOWER.encode(&h.finalize()) == sha512_hex {
                    // Blob already exists and is uncorrupted
                    return Ok(sha512_hex);
                }
            }
            // If existing file is corrupted, remove it first
            let _ = fs::remove_file(&target_path);
        }

        // Staging step: Write to temporary file on the SAME filesystem/volume
        let temp_path = self.create_temp_path("blob");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(data)?;
            file.flush()?;
        }

        // Verify checksum of written temp file
        {
            let mut read_file = File::open(&temp_path)?;
            let mut buf = Vec::new();
            read_file.read_to_end(&mut buf)?;
            let mut verify_hasher = Sha512::new();
            verify_hasher.update(&buf);
            let written_hex = HEXLOWER.encode(&verify_hasher.finalize());
            if written_hex != sha512_hex {
                let _ = fs::remove_file(&temp_path);
                return Err(CacheError::IntegrityMismatch {
                    key: sha512_hex.clone(),
                    expected: sha512_hex.clone(),
                    actual: written_hex,
                });
            }
        }

        // Ensure target directory exists
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Acquire lock and rename atomically
        let _blob_lock = self.lock_blob(&sha512_hex)?;
        if target_path.exists() {
            if let Ok(existing_bytes) = fs::read(&target_path) {
                let mut h = Sha512::new();
                h.update(&existing_bytes);
                if HEXLOWER.encode(&h.finalize()) == sha512_hex {
                    // Another worker already populated target_path; clean up temp and succeed
                    let _ = fs::remove_file(&temp_path);
                    return Ok(sha512_hex);
                }
            }
            let _ = fs::remove_file(&target_path);
        }

        if let Err(err) = fs::rename(&temp_path, &target_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(CacheError::Io(err));
        }
        debug!("Atomically stored blob {}", target_path.display());

        Ok(sha512_hex)
    }

    /// Retrieve a blob by its SHA-512 hex digest.
    ///
    /// If the file on disk is corrupted (checksum mismatch), it is automatically
    /// PURGED and `Ok(None)` is returned (signaling a cache miss for re-fetch).
    pub fn get_by_sha512(&self, sha512_hex: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let blob_path = self.blob_path(sha512_hex);
        if !blob_path.exists() {
            return Ok(None);
        }

        let bytes = match fs::read(&blob_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CacheError::Io(e)),
        };

        // Verify SHA-512 checksum of cached data
        let mut hasher = Sha512::new();
        hasher.update(&bytes);
        let actual_hex = HEXLOWER.encode(&hasher.finalize());

        if !actual_hex.eq_ignore_ascii_case(sha512_hex) {
            warn!(
                "Cached blob {} is corrupted (expected {}, got {})! Purging corrupt entry and signaling cache miss.",
                blob_path.display(),
                sha512_hex,
                actual_hex
            );
            // Purge corrupt file
            let _ = fs::remove_file(&blob_path);
            return Ok(None);
        }

        Ok(Some(bytes))
    }

    /// Retrieve an index entry by key.
    pub fn get_index_entry(&self, key: &str) -> Result<Option<IndexEntry>, CacheError> {
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if !index_path.exists() {
            return Ok(None);
        }

        let content = match fs::read_to_string(&index_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CacheError::Io(e)),
        };

        match serde_json::from_str::<IndexEntry>(&content) {
            Ok(entry) => Ok(Some(entry)),
            Err(err) => {
                warn!(
                    "Corrupt index entry at {}: {err}. Purging corrupt index.",
                    index_path.display()
                );
                let _ = fs::remove_file(&index_path);
                Ok(None)
            }
        }
    }

    /// Store an entry into the cache with key mapping.
    ///
    /// Stores the blob content, creates the index metadata, and writes both atomically.
    pub fn put(
        &self,
        key: &str,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        // First, put blob in content-addressable storage
        let sha512_hex = self.put_blob(data, None)?;
        let integrity = Integrity::from_bytes(data, Algorithm::Sha512).to_string();

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            data.len() as u64,
            metadata,
        );

        // Put index entry with atomic write and cross-process lock
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.create_temp_path("index");
        {
            let json_bytes = serde_json::to_vec_pretty(&entry)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(&json_bytes)?;
            file.flush()?;
        }

        let _key_lock = self.lock_key(key)?;
        if index_path.exists() {
            let _ = fs::remove_file(&index_path);
        }
        if let Err(err) = fs::rename(&temp_path, &index_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(CacheError::Io(err));
        }

        Ok(entry)
    }

    /// Retrieve cached data and index metadata by key.
    ///
    /// If the blob is missing or corrupted, both the blob and index entry are purged,
    /// and `Ok(None)` is returned to signal a cache miss for re-fetching.
    pub fn get(&self, key: &str) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        let entry = match self.get_index_entry(key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        match self.get_by_sha512(&entry.sha512_hex)? {
            Some(bytes) => Ok(Some((entry, bytes))),
            None => {
                // Blob was corrupted or missing! Purge the stale index entry as well.
                let index_path = IndexEntry::path_for_key(&self.root, key);
                let _ = fs::remove_file(&index_path);
                warn!(
                    "Blob for index key '{key}' was corrupted or missing. Stale index purged."
                );
                Ok(None)
            }
        }
    }

    /// Purge a specific key and its blob from the cache.
    pub fn purge_key(&self, key: &str) -> Result<(), CacheError> {
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if let Some(entry) = self.get_index_entry(key)? {
            let blob_path = self.blob_path(&entry.sha512_hex);
            let _ = fs::remove_file(&blob_path);
        }
        let _ = fs::remove_file(&index_path);
        Ok(())
    }
}
