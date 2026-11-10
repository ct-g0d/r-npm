use crate::error::CacheError;
use crate::index::IndexEntry;
use crate::lock::CacheLock;
use data_encoding::HEXLOWER;
use rnpm_core::{Algorithm, Integrity, IntegrityError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Clear readonly attribute on Windows or Unix.
fn make_writable(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path).or_else(|_| fs::metadata(path)) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

/// Recursively clear readonly attribute on all files and subdirectories.
fn clear_readonly_recursive(path: &Path) {
    make_writable(path);
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    clear_readonly_recursive(&entry.path());
                }
            }
        }
    }
}

/// Helper to reliably remove a file, clearing Windows readonly attributes and retrying on transient locks.
fn remove_file_with_retries(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    make_writable(path);

    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                make_writable(path);
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(200));
            }
        }
    }
}

/// Helper to reliably remove a directory tree, clearing Windows readonly attributes and retrying on transient locks.
fn remove_dir_all_with_retries(dir: &Path) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    clear_readonly_recursive(dir);

    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                clear_readonly_recursive(dir);
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(250));
            }
        }
    }
}

/// Recursively collect all files under a directory.
pub(crate) fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, out);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
}

/// Detailed report returned by `Cache::verify`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Number of valid content-addressable blobs verified against their SHA-512 digests.
    pub verified_blobs: usize,
    /// Number of corrupted or unreadable blobs purged.
    pub corrupted_blobs: usize,
    /// Total byte size of verified content blobs.
    pub total_blob_bytes: u64,
    /// Number of valid index entries verified against existing blobs.
    pub verified_indices: usize,
    /// Number of corrupted or unreadable index entries purged.
    pub corrupted_indices: usize,
    /// Number of orphaned index entries purged (pointed to missing or corrupted blobs).
    pub orphaned_indices: usize,
    /// Number of stale temporary files cleaned up from `tmp`.
    pub stale_temp_files_cleaned: usize,
}

impl VerifyReport {
    /// Check whether the cache was completely healthy and required no purging.
    pub fn is_clean(&self) -> bool {
        self.corrupted_blobs == 0
            && self.corrupted_indices == 0
            && self.orphaned_indices == 0
            && self.stale_temp_files_cleaned == 0
    }

    /// Total number of purged items (corrupted blobs, corrupted indices, orphaned indices, and stale temp files).
    pub fn total_purged(&self) -> usize {
        self.corrupted_blobs
            + self.corrupted_indices
            + self.orphaned_indices
            + self.stale_temp_files_cleaned
    }

    /// Total number of verified valid items (blobs and index entries).
    pub fn total_verified(&self) -> usize {
        self.verified_blobs + self.verified_indices
    }
}

impl std::fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache Verify: {} blobs verified ({} bytes), {} corrupted blobs purged, {} index entries verified, {} corrupted indices purged, {} orphaned indices purged, {} stale temp files cleaned",
            self.verified_blobs,
            self.total_blob_bytes,
            self.corrupted_blobs,
            self.verified_indices,
            self.corrupted_indices,
            self.orphaned_indices,
            self.stale_temp_files_cleaned,
        )
    }
}

/// Helper to reliably rename a temporary file to its target path with retries on Windows transient locks.
fn rename_with_retries(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        if let Some(parent) = to.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                // If destination exists, try removing it first before retrying rename
                if attempts > 1 && to.exists() {
                    let _ = remove_file_with_retries(to);
                }
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(250));
            }
        }
    }
}

/// Helper to reliably read a file with retries on Windows transient file sharing locks.
fn read_file_with_retries(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut attempts = 0;
    let mut delay = Duration::from_millis(5);
    loop {
        attempts += 1;
        match fs::read(path) {
            Ok(bytes) => return Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(e),
            Err(e) => {
                if attempts >= 10 {
                    return Err(e);
                }
                let jitter = (attempts as u64 * 3) % 7;
                sleep(delay + Duration::from_millis(jitter));
                delay = delay.saturating_mul(2).min(Duration::from_millis(150));
            }
        }
    }
}

/// Helper to reliably read a UTF-8 file with retries on Windows transient file sharing locks.
fn read_to_string_with_retries(path: &Path) -> std::io::Result<String> {
    let bytes = read_file_with_retries(path)?;
    String::from_utf8(bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Content-addressable cache manager.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
    lock_timeout: Duration,
    stale_threshold: Duration,
    has_content: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Cache {
    /// Initialize a cache instance at the given root directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        let content_sha512 = root.join("content-v2").join("sha512");
        let initial_has_content = fs::read_dir(&content_sha512)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        fs::create_dir_all(&content_sha512)?;
        fs::create_dir_all(root.join("index-v5"))?;
        fs::create_dir_all(root.join("tmp"))?;
        fs::create_dir_all(root.join("locks"))?;
        Ok(Self {
            root,
            lock_timeout: CacheLock::DEFAULT_TIMEOUT,
            stale_threshold: CacheLock::DEFAULT_STALE_THRESHOLD,
            has_content: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(initial_has_content)),
        })
    }

    /// Configure custom lock acquisition timeout.
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Configure custom stale lock threshold.
    pub fn with_stale_threshold(mut self, threshold: Duration) -> Self {
        self.stale_threshold = threshold;
        self
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

    /// Compute storage path for a digest hex string under a specific algorithm (cacache content-v2/<algo> layout).
    pub fn blob_path_for_algo(&self, algo: Algorithm, hex_str: &str) -> PathBuf {
        let hex = hex_str.to_ascii_lowercase();
        let p1 = if hex.len() >= 2 { &hex[0..2] } else { "xx" };
        let p2 = if hex.len() >= 4 { &hex[2..4] } else { "yy" };
        self.root
            .join("content-v2")
            .join(algo.as_str())
            .join(p1)
            .join(p2)
            .join(&hex)
    }

    /// Compute lock file path for a given resource name.
    pub fn lock_path(&self, name: &str) -> PathBuf {
        let safe_name = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        self.root.join("locks").join(format!("{safe_name}.lock"))
    }

    /// Acquire an exclusive cross-process lock for a key with custom options.
    pub fn lock_key_with_options(
        &self,
        key: &str,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<CacheLock, CacheError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(key.as_bytes());
        let hash = HEXLOWER.encode(&hasher.finalize());
        let lock_path = self.lock_path(&format!("idx_{hash}"));
        CacheLock::acquire_exclusive_with_options(&lock_path, timeout, stale_threshold).map_err(
            |e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    CacheError::LockFailed(lock_path.display().to_string())
                } else {
                    CacheError::Io(e)
                }
            },
        )
    }

    /// Acquire an exclusive cross-process lock for a key.
    pub fn lock_key(&self, key: &str) -> Result<CacheLock, CacheError> {
        self.lock_key_with_options(key, self.lock_timeout, self.stale_threshold)
    }

    /// Acquire an exclusive cross-process lock for a blob digest with custom options.
    pub fn lock_blob_with_options(
        &self,
        sha512_hex: &str,
        timeout: Duration,
        stale_threshold: Duration,
    ) -> Result<CacheLock, CacheError> {
        let lock_path = self.lock_path(&format!("blob_{sha512_hex}"));
        CacheLock::acquire_exclusive_with_options(&lock_path, timeout, stale_threshold).map_err(
            |e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    CacheError::LockFailed(lock_path.display().to_string())
                } else {
                    CacheError::Io(e)
                }
            },
        )
    }

    /// Acquire an exclusive cross-process lock for a blob digest.
    pub fn lock_blob(&self, sha512_hex: &str) -> Result<CacheLock, CacheError> {
        self.lock_blob_with_options(sha512_hex, self.lock_timeout, self.stale_threshold)
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
        let tmp = self.tmp_dir();
        let _ = fs::create_dir_all(&tmp);
        tmp.join(filename)
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
            let _ = remove_file_with_retries(&target_path);
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
                    let _ = remove_file_with_retries(&temp_path);
                    return Ok(sha512_hex);
                }
            }
            let _ = remove_file_with_retries(&target_path);
        }

        if let Err(err) = rename_with_retries(&temp_path, &target_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }
        self.has_content.store(true, std::sync::atomic::Ordering::Release);
        debug!("Atomically stored blob {}", target_path.display());

        Ok(sha512_hex)
    }

    /// Store a pre-verified blob directly by its known SHA-512 hex digest, skipping redundant hashing.
    pub fn put_blob_direct(&self, data: &[u8], sha512_hex: &str) -> Result<(), CacheError> {
        let target_path = self.blob_path(sha512_hex);
        if target_path.exists() {
            self.has_content.store(true, std::sync::atomic::Ordering::Release);
            return Ok(());
        }
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = rnpm_fs::write_file_fast(&target_path, data, 0o644, 0);
        self.has_content.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Retrieve a blob by its SHA-512 hex digest.
    ///
    /// If the file on disk is corrupted (checksum mismatch or unreadable), it is automatically
    /// PURGED and `Ok(None)` is returned (signaling a cache miss for re-fetch).
    pub fn get_by_sha512(&self, sha512_hex: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let blob_path = self.blob_path(sha512_hex);
        if !blob_path.exists() {
            return Ok(None);
        }

        let bytes = match read_file_with_retries(&blob_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                warn!(
                    "Unreadable or corrupt blob at {} ({e}). Purging corrupted entry.",
                    blob_path.display()
                );
                let _ = remove_file_with_retries(&blob_path);
                return Ok(None);
            }
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
            let _ = remove_file_with_retries(&blob_path);
            return Ok(None);
        }

        Ok(Some(bytes))
    }

    /// Retrieve an index entry by key.
    ///
    /// If the index file is corrupted (invalid JSON, non-UTF-8, or mismatched key),
    /// it is automatically PURGED and `Ok(None)` is returned.
    pub fn get_index_entry(&self, key: &str) -> Result<Option<IndexEntry>, CacheError> {
        // First try exact key
        if let Some(entry) = self.get_index_entry_internal(key)? {
            return Ok(Some(entry));
        }

        // Try npm cacache / pacote key aliases
        if key.starts_with("http://") || key.starts_with("https://") {
            let alias = format!("make-fetch-happen:request-cache:{key}");
            if let Some(entry) = self.get_index_entry_internal(&alias)? {
                return Ok(Some(entry));
            }
        } else if let Some(stripped) = key.strip_prefix("make-fetch-happen:request-cache:") {
            if let Some(entry) = self.get_index_entry_internal(stripped)? {
                return Ok(Some(entry));
            }
        } else if !key.contains(':') {
            let alias = format!("pacote:packument:{key}");
            if let Some(entry) = self.get_index_entry_internal(&alias)? {
                return Ok(Some(entry));
            }
        } else if let Some(stripped) = key.strip_prefix("pacote:packument:") {
            if let Some(entry) = self.get_index_entry_internal(stripped)? {
                return Ok(Some(entry));
            }
            if stripped.contains("://") {
                if let Some((protocol, rest)) = stripped.split_once("://") {
                    if let Some((host_part, name_part)) = rest.split_once(':') {
                        if host_part.ends_with('/') {
                            let trimmed_host = host_part.trim_end_matches('/');
                            let alt_key =
                                format!("pacote:packument:{protocol}://{trimmed_host}:{name_part}");
                            if let Some(entry) = self.get_index_entry_internal(&alt_key)? {
                                return Ok(Some(entry));
                            }
                        } else {
                            let alt_key =
                                format!("pacote:packument:{protocol}://{host_part}/:{name_part}");
                            if let Some(entry) = self.get_index_entry_internal(&alt_key)? {
                                return Ok(Some(entry));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn get_index_entry_internal(&self, key: &str) -> Result<Option<IndexEntry>, CacheError> {
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if !index_path.exists() {
            return Ok(None);
        }

        let content = match read_to_string_with_retries(&index_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                warn!(
                    "Non-UTF8 or unreadable index entry at {} ({e}). Purging corrupt index.",
                    index_path.display()
                );
                let _ = remove_file_with_retries(&index_path);
                return Ok(None);
            }
        };

        for line in content.lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let json_str = if let Some(tab_pos) = trimmed.find('\t') {
                &trimmed[tab_pos + 1..]
            } else {
                trimmed
            };

            match serde_json::from_str::<IndexEntry>(json_str) {
                Ok(mut entry) => {
                    if entry.key == key {
                        if let Err(err) = Integrity::parse(&entry.integrity) {
                            warn!(
                                "Index entry at {} has unparseable SSRI integrity '{}' ({err}). Purging corrupt index.",
                                index_path.display(),
                                entry.integrity
                            );
                            let _ = remove_file_with_retries(&index_path);
                            return Ok(None);
                        }

                        if entry.sha512_hex.is_empty() {
                            if let Ok(parsed) = Integrity::parse(&entry.integrity) {
                                if let Some(sha512) = parsed
                                    .entries
                                    .iter()
                                    .find(|e| e.algorithm == Algorithm::Sha512)
                                {
                                    entry.sha512_hex = HEXLOWER.encode(&sha512.digest);
                                }
                            }
                        }

                        return Ok(Some(entry));
                    } else {
                        warn!(
                            "Index entry at {} has key mismatch (expected '{}', got '{}'). Purging corrupt index.",
                            index_path.display(),
                            key,
                            entry.key
                        );
                        let _ = remove_file_with_retries(&index_path);
                        return Ok(None);
                    }
                }
                Err(err) => {
                    warn!(
                        "Corrupt index entry at {}: {err}. Purging corrupt index.",
                        index_path.display()
                    );
                    let _ = remove_file_with_retries(&index_path);
                    return Ok(None);
                }
            }
        }

        // Fallback for multi-line pretty-printed single JSON
        match serde_json::from_str::<IndexEntry>(&content) {
            Ok(mut entry) => {
                if entry.key == key {
                    if let Err(err) = Integrity::parse(&entry.integrity) {
                        warn!(
                            "Index entry at {} has unparseable SSRI integrity '{}' ({err}). Purging corrupt index.",
                            index_path.display(),
                            entry.integrity
                        );
                        let _ = remove_file_with_retries(&index_path);
                        return Ok(None);
                    }
                    if entry.sha512_hex.is_empty() {
                        if let Ok(parsed) = Integrity::parse(&entry.integrity) {
                            if let Some(sha512) = parsed
                                .entries
                                .iter()
                                .find(|e| e.algorithm == Algorithm::Sha512)
                            {
                                entry.sha512_hex = HEXLOWER.encode(&sha512.digest);
                            }
                        }
                    }
                    Ok(Some(entry))
                } else {
                    let _ = remove_file_with_retries(&index_path);
                    Ok(None)
                }
            }
            Err(_) => {
                warn!(
                    "Corrupt index entry at {}. Purging corrupt index.",
                    index_path.display()
                );
                let _ = remove_file_with_retries(&index_path);
                Ok(None)
            }
        }
    }

    /// Store an entry into the cache with key mapping and strict integrity verification.
    ///
    /// If `expected_integrity` is provided, verifies it BEFORE writing blob or index entry;
    /// if mismatch, returns `CacheError::IntegrityMismatch` immediately without touching cache files!
    pub fn put_with_integrity(
        &self,
        key: &str,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        // If expected_integrity is provided, verify it BEFORE writing blob or index entry
        if let Some(expected) = expected_integrity {
            expected.verify(data).map_err(|e| match e {
                IntegrityError::Mismatch {
                    expected, actual, ..
                } => CacheError::IntegrityMismatch {
                    key: key.to_string(),
                    expected,
                    actual,
                },
                other => CacheError::Core(rnpm_core::CoreError::Integrity(other)),
            })?;
        }

        // Put blob in content-addressable storage
        let sha512_hex = if let Some(expected) = expected_integrity {
            if let Some(sha_entry) = expected.entries.iter().find(|e| e.algorithm == Algorithm::Sha512) {
                let hex = HEXLOWER.encode(&sha_entry.digest);
                self.put_blob_direct(data, &hex)?;
                hex
            } else {
                self.put_blob(data, None)?
            }
        } else {
            self.put_blob(data, None)?
        };
        let integrity = if let Some(expected) = expected_integrity {
            expected.to_string()
        } else {
            Integrity::from_bytes(data, Algorithm::Sha512).to_string()
        };

        let metadata_val = match metadata {
            Some(m) => match serde_json::from_slice::<serde_json::Value>(m) {
                Ok(val) => Some(val),
                Err(_) => match std::str::from_utf8(m) {
                    Ok(s) => Some(serde_json::Value::String(s.to_string())),
                    Err(_) => Some(serde_json::Value::String(HEXLOWER.encode(m))),
                },
            },
            None => None,
        };

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            data.len() as u64,
            metadata_val,
        );

        // Put index entry with atomic write and cross-process lock
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.create_temp_path("index");
        {
            let json_str = serde_json::to_string(&entry)?;
            let mut hasher = sha1::Sha1::new();
            hasher.update(json_str.as_bytes());
            let hash = HEXLOWER.encode(&hasher.finalize());
            let line = format!("{hash}\t{json_str}\n");

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(line.as_bytes())?;
            file.flush()?;
        }

        let _key_lock = self.lock_key(key)?;
        if index_path.exists() {
            let _ = remove_file_with_retries(&index_path);
        }
        if let Err(err) = rename_with_retries(&temp_path, &index_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }

        Ok(entry)
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
            let json_str = serde_json::to_string(&entry)?;
            let mut hasher = sha1::Sha1::new();
            hasher.update(json_str.as_bytes());
            let hash = HEXLOWER.encode(&hasher.finalize());
            let line = format!("{hash}\t{json_str}\n");

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(line.as_bytes())?;
            file.flush()?;
        }

        let _key_lock = self.lock_key(key)?;
        if let Err(err) = rename_with_retries(&temp_path, &index_path) {
            let _ = remove_file_with_retries(&temp_path);
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

        if !entry.sha512_hex.is_empty() {
            if let Some(bytes) = self.get_by_sha512(&entry.sha512_hex)? {
                if let Ok(expected_integrity) = Integrity::parse(&entry.integrity) {
                    if let Err(err) = expected_integrity.verify(&bytes) {
                        warn!(
                            "SSRI SHA-512 integrity mismatch for key '{key}': {err}. Auto-purging corrupt entry and treating as cache miss."
                        );
                        let index_path = IndexEntry::path_for_key(&self.root, &entry.key);
                        let _ = remove_file_with_retries(&index_path);
                        let blob_path = self.blob_path(&entry.sha512_hex);
                        let _ = remove_file_with_retries(&blob_path);
                        return Ok(None);
                    }
                }
                return Ok(Some((entry, bytes)));
            }
        }

        if let Ok(parsed_integrity) = Integrity::parse(&entry.integrity) {
            if let Some(bytes) = self.get_by_integrity(&parsed_integrity)? {
                return Ok(Some((entry, bytes)));
            }
        }

        let index_path = IndexEntry::path_for_key(&self.root, &entry.key);
        let _ = remove_file_with_retries(&index_path);
        warn!("Blob for index key '{key}' was corrupted or missing. Stale index purged.");
        Ok(None)
    }

    /// Retrieve the local filesystem path to a cached blob without reading the contents into memory.
    /// This enables zero-copy streaming extraction and inspection.
    pub fn get_blob_path(&self, key: &str) -> Result<Option<(IndexEntry, PathBuf)>, CacheError> {
        let entry = match self.get_index_entry(key)? {
            Some(e) => e,
            None => return Ok(None),
        };

        if !entry.sha512_hex.is_empty() {
            let blob_path = self.blob_path(&entry.sha512_hex);
            if blob_path.exists() {
                return Ok(Some((entry, blob_path)));
            }
        }

        if let Ok(parsed_integrity) = Integrity::parse(&entry.integrity) {
            let mut sorted_entries = parsed_integrity.entries.clone();
            sorted_entries.sort_by_key(|a| std::cmp::Reverse(a.algorithm));

            for ssri in sorted_entries {
                let hex = HEXLOWER.encode(&ssri.digest);
                let blob_path = self.blob_path_for_algo(ssri.algorithm, &hex);
                if blob_path.exists() {
                    return Ok(Some((entry, blob_path)));
                }
            }
        }

        Ok(None)
    }

    /// Store a local file into content-addressable storage with key mapping and strict integrity verification.
    /// Streams content from `source_path` in bounded chunks to avoid buffering the whole file in memory.
    pub fn put_file_with_integrity(
        &self,
        key: &str,
        source_path: &Path,
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        use std::io::Read;

        let mut file = fs::File::open(source_path).map_err(CacheError::Io)?;
        let mut hasher = Sha512::new();
        let mut buffer = [0u8; 65536];
        let mut total_size = 0u64;

        loop {
            let bytes_read = file.read(&mut buffer).map_err(CacheError::Io)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            total_size += bytes_read as u64;
        }

        let sha512_bytes = hasher.finalize();
        let sha512_hex = HEXLOWER.encode(&sha512_bytes);

        if let Some(expected) = expected_integrity {
            if let Some(sha512_entry) = expected
                .entries
                .iter()
                .find(|e| e.algorithm == Algorithm::Sha512)
            {
                if sha512_entry.digest.as_slice() != sha512_bytes.as_slice() {
                    return Err(CacheError::IntegrityMismatch {
                        key: key.to_string(),
                        expected: sha512_entry.to_string(),
                        actual: format!("sha512-{}", data_encoding::BASE64.encode(&sha512_bytes)),
                    });
                }
            }
        }

        let target_path = self.blob_path(&sha512_hex);
        if !target_path.exists() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let temp_path = self.create_temp_path("blob");
            fs::copy(source_path, &temp_path)?;
            let _ = rename_with_retries(&temp_path, &target_path);
        }

        let integrity = if let Some(expected) = expected_integrity {
            expected.to_string()
        } else {
            format!("sha512-{}", data_encoding::BASE64.encode(&sha512_bytes))
        };

        let metadata_val = match metadata {
            Some(m) => match serde_json::from_slice::<serde_json::Value>(m) {
                Ok(val) => Some(val),
                Err(_) => match std::str::from_utf8(m) {
                    Ok(s) => Some(serde_json::Value::String(s.to_string())),
                    Err(_) => Some(serde_json::Value::String(HEXLOWER.encode(m))),
                },
            },
            None => None,
        };

        let entry = IndexEntry::new(
            key.to_string(),
            integrity,
            sha512_hex,
            total_size,
            metadata_val,
        );

        let index_path = IndexEntry::path_for_key(&self.root, key);
        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_path = self.create_temp_path("index");
        {
            let json_str = serde_json::to_string(&entry)?;
            let mut h = sha1::Sha1::new();
            h.update(json_str.as_bytes());
            let hash = HEXLOWER.encode(&h.finalize());
            let line = format!("{hash}\t{json_str}\n");

            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            f.write_all(line.as_bytes())?;
            f.flush()?;
        }

        let _key_lock = self.lock_key(key)?;
        if index_path.exists() {
            let _ = remove_file_with_retries(&index_path);
        }
        if let Err(err) = rename_with_retries(&temp_path, &index_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }

        Ok(entry)
    }

    /// Retrieve a blob by its SSRI Integrity descriptor.
    /// If corrupted, auto-purges the corrupt blob, logs a diagnostic, and returns `Ok(None)` for clean re-fetching.
    pub fn get_by_integrity(&self, integrity: &Integrity) -> Result<Option<Vec<u8>>, CacheError> {
        if !self.has_content.load(std::sync::atomic::Ordering::Acquire) {
            let content_v2 = self.root.join("content-v2");
            let any_entry = fs::read_dir(&content_v2)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            if !any_entry {
                return Ok(None);
            }
            self.has_content.store(true, std::sync::atomic::Ordering::Release);
        }
        let mut sorted_entries = integrity.entries.clone();
        sorted_entries.sort_by_key(|a| std::cmp::Reverse(a.algorithm));

        for entry in sorted_entries {
            let hex = HEXLOWER.encode(&entry.digest);
            let blob_path = self.blob_path_for_algo(entry.algorithm, &hex);
            match fs::read(&blob_path) {
                Ok(bytes) => {
                    if let Err(err) = integrity.verify(&bytes) {
                        warn!("SSRI verification failed for blob {hex}: {err}. Auto-purging.");
                        let _ = remove_file_with_retries(&blob_path);
                    } else {
                        return Ok(Some(bytes));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(CacheError::Io(e)),
            }
        }
        Ok(None)
    }

    /// Purge a specific key and its blob from the cache.
    pub fn purge_key(&self, key: &str) -> Result<(), CacheError> {
        let _key_lock = self.lock_key(key);
        let index_path = IndexEntry::path_for_key(&self.root, key);
        if let Some(entry) = self.get_index_entry(key)? {
            let blob_path = self.blob_path(&entry.sha512_hex);
            let _ = remove_file_with_retries(&blob_path);
        }
        let _ = remove_file_with_retries(&index_path);
        Ok(())
    }

    /// Helper to construct a registry-scoped cache key for packument metadata.
    pub fn packument_key(registry: &str, name: &str, accept: Option<&str>) -> String {
        packument_key(registry, name, accept)
    }

    /// Retrieve packument metadata scoped by registry URL and optional accept header.
    ///
    /// Preserves isolation so cached metadata from a test registry or private registry
    /// is not served for registry.npmjs.org or other registries.
    pub fn get_packument(
        &self,
        registry: &str,
        name: &str,
    ) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        self.get_packument_with_accept(registry, name, None)
    }

    /// Retrieve packument metadata scoped by registry URL and specific accept header.
    pub fn get_packument_with_accept(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<Option<(IndexEntry, Vec<u8>)>, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        if let Some(res) = self.get(&key)? {
            return Ok(Some(res));
        }

        // Try trailing slash alternative on registry URL
        let reg_with_slash = format!("{}/", registry.trim_end_matches('/'));
        let alt_key = match accept {
            Some(a) if !a.is_empty() => format!("pacote:packument:{reg_with_slash}:{name}:{a}"),
            _ => format!("pacote:packument:{reg_with_slash}:{name}"),
        };
        if alt_key != key {
            if let Some(res) = self.get(&alt_key)? {
                return Ok(Some(res));
            }
        }

        // If an accept header was provided, also fallback to the key without accept header
        if accept.is_some() {
            let key_no_accept = Self::packument_key(registry, name, None);
            if let Some(res) = self.get(&key_no_accept)? {
                return Ok(Some(res));
            }
        } else {
            let key_abbrev =
                Self::packument_key(registry, name, Some("application/vnd.npm.install-v1+json"));
            if let Some(res) = self.get(&key_abbrev)? {
                return Ok(Some(res));
            }
        }

        Ok(None)
    }

    /// Store packument metadata scoped by registry URL.
    pub fn put_packument(
        &self,
        registry: &str,
        name: &str,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        self.put_packument_with_accept(registry, name, None, data, metadata)
    }

    /// Store packument metadata scoped by registry URL and optional accept header.
    pub fn put_packument_with_accept(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
        data: &[u8],
        metadata: Option<serde_json::Value>,
    ) -> Result<IndexEntry, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.put(&key, data, metadata)
    }

    /// Store packument metadata scoped by registry URL and optional accept header with strict integrity verification.
    pub fn put_packument_with_integrity(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
        data: &[u8],
        expected_integrity: Option<&Integrity>,
        metadata: Option<&[u8]>,
    ) -> Result<IndexEntry, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.put_with_integrity(&key, data, expected_integrity, metadata)
    }

    /// Retrieve the local filesystem path to a cached packument blob without reading it into memory.
    pub fn get_packument_blob_path(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<Option<(IndexEntry, PathBuf)>, CacheError> {
        let key = Self::packument_key(registry, name, accept);
        if let Some(res) = self.get_blob_path(&key)? {
            return Ok(Some(res));
        }

        let reg_with_slash = format!("{}/", registry.trim_end_matches('/'));
        let alt_key = match accept {
            Some(a) if !a.is_empty() => format!("pacote:packument:{reg_with_slash}:{name}:{a}"),
            _ => format!("pacote:packument:{reg_with_slash}:{name}"),
        };
        if alt_key != key {
            if let Some(res) = self.get_blob_path(&alt_key)? {
                return Ok(Some(res));
            }
        }

        if accept.is_some() {
            let key_no_accept = Self::packument_key(registry, name, None);
            if let Some(res) = self.get_blob_path(&key_no_accept)? {
                return Ok(Some(res));
            }
        }

        Ok(None)
    }

    /// Purge a scoped packument entry from the cache.
    pub fn purge_packument(
        &self,
        registry: &str,
        name: &str,
        accept: Option<&str>,
    ) -> Result<(), CacheError> {
        let key = Self::packument_key(registry, name, accept);
        self.purge_key(&key)
    }

    /// Clean up any orphaned temporary files in `<cache_root>/tmp` older than `max_age`.
    pub fn clean_stale_temp_files(&self, max_age: Duration) -> Result<usize, CacheError> {
        let mut count = 0;
        let pid = std::process::id();
        let in_flight_blob = format!("blob_{pid}_");
        let in_flight_idx = format!("index_{pid}_");

        if let Ok(entries) = fs::read_dir(self.tmp_dir()) {
            let now = SystemTime::now();
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                let should_remove = if let Ok(meta) = fs::metadata(&path) {
                    let mtime = meta.modified().unwrap_or(now);
                    let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);

                    if max_age.is_zero() {
                        // If file is an active in-flight temporary file created by the current process recently (< 5000ms),
                        // preserve it so concurrent threads are not interrupted under thread starvation.
                        !((file_name.starts_with(&in_flight_blob)
                            || file_name.starts_with(&in_flight_idx))
                            && age < Duration::from_millis(5000))
                    } else {
                        age >= max_age
                    }
                } else {
                    false
                };

                if should_remove {
                    if path.is_dir() {
                        if remove_dir_all_with_retries(&path).is_ok() {
                            count += 1;
                        }
                    } else if remove_file_with_retries(&path).is_ok() {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Purge all cache contents (content, index, tmp, locks) cleanly handling Windows file attributes.
    pub fn clean(&self) -> Result<(), CacheError> {
        let targets = [
            self.root.join("content-v2"),
            self.root.join("index-v5"),
            self.root.join("tmp"),
            self.root.join("locks"),
            self.root.join("_fingerprints"),
        ];

        for dir in &targets {
            if dir.exists() {
                remove_dir_all_with_retries(dir)?;
            }
        }

        // Also clean any stray files or directories directly in self.root
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let _ = remove_file_with_retries(&path);
                } else if path.is_dir() {
                    let _ = remove_dir_all_with_retries(&path);
                }
            }
        }

        // Recreate essential cache directory layout
        fs::create_dir_all(self.root.join("content-v2").join("sha512"))?;
        fs::create_dir_all(self.root.join("index-v5"))?;
        fs::create_dir_all(self.root.join("tmp"))?;
        fs::create_dir_all(self.root.join("locks"))?;
        fs::create_dir_all(self.root.join("_fingerprints"))?;

        Ok(())
    }

    /// Verify all `content-v2` SHA-512 blobs against their digests, purge corrupted blobs,
    /// scan `index-v5` entries, purge corrupted indices or orphaned indices pointing to missing blobs,
    /// clean stale temporary files in `tmp`, and return a detailed `VerifyReport`.
    pub fn verify(&self) -> Result<VerifyReport, CacheError> {
        let mut report = VerifyReport::default();
        let mut valid_blobs = HashSet::new();

        // 1. Verify content-v2 blobs against their digests and purge corrupted ones
        let content_dir = self.root.join("content-v2").join("sha512");
        if content_dir.exists() {
            let mut blob_paths = Vec::new();
            collect_files_recursive(&content_dir, &mut blob_paths);

            for path in blob_paths {
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let is_hex =
                    file_name.len() == 128 && file_name.chars().all(|c| c.is_ascii_hexdigit());

                if !is_hex {
                    warn!(
                        "Invalid blob file name '{}' in content-v2. Purging.",
                        path.display()
                    );
                    let _ = remove_file_with_retries(&path);
                    report.corrupted_blobs += 1;
                    continue;
                }

                match read_file_with_retries(&path) {
                    Ok(bytes) => {
                        let mut hasher = Sha512::new();
                        hasher.update(&bytes);
                        let actual = HEXLOWER.encode(&hasher.finalize());
                        if actual.eq_ignore_ascii_case(file_name) {
                            report.verified_blobs += 1;
                            report.total_blob_bytes += bytes.len() as u64;
                            valid_blobs.insert(actual.to_ascii_lowercase());
                        } else {
                            warn!(
                                "Corrupted blob detected at {} (expected {}, got {}). Purging.",
                                path.display(),
                                file_name,
                                actual
                            );
                            let _ = remove_file_with_retries(&path);
                            report.corrupted_blobs += 1;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Concurrent rename or cleanup; safely skip
                        continue;
                    }
                    Err(e) => {
                        warn!("Unreadable blob at {} ({}). Purging.", path.display(), e);
                        let _ = remove_file_with_retries(&path);
                        report.corrupted_blobs += 1;
                    }
                }
            }
        }

        // 2. Scan index-v5 entries, purge corrupted indices or orphaned indices pointing to missing blobs
        let index_dir = self.root.join("index-v5");
        if index_dir.exists() {
            let mut index_paths = Vec::new();
            collect_files_recursive(&index_dir, &mut index_paths);

            for path in index_paths {
                let content = match read_to_string_with_retries(&path) {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Concurrent rename or cleanup; safely skip
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Unreadable index file at {} ({}). Purging.",
                            path.display(),
                            e
                        );
                        let _ = remove_file_with_retries(&path);
                        report.corrupted_indices += 1;
                        continue;
                    }
                };

                let parsed_entry = {
                    let mut last = None;
                    let mut all_valid = true;
                    let mut has_lines = false;
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        has_lines = true;
                        let json_str = if let Some(tab_pos) = trimmed.find('\t') {
                            &trimmed[tab_pos + 1..]
                        } else {
                            trimmed
                        };
                        if let Ok(mut entry) = serde_json::from_str::<IndexEntry>(json_str) {
                            if entry.sha512_hex.is_empty() {
                                if let Ok(parsed) = Integrity::parse(&entry.integrity) {
                                    if let Some(sha512) = parsed
                                        .entries
                                        .iter()
                                        .find(|e| e.algorithm == Algorithm::Sha512)
                                    {
                                        entry.sha512_hex = HEXLOWER.encode(&sha512.digest);
                                    }
                                }
                            }
                            if Integrity::parse(&entry.integrity).is_ok() {
                                last = Some(entry);
                            } else {
                                all_valid = false;
                                break;
                            }
                        } else {
                            all_valid = false;
                            break;
                        }
                    }
                    if all_valid && last.is_some() {
                        last
                    } else if !has_lines {
                        if let Ok(mut entry) = serde_json::from_str::<IndexEntry>(&content) {
                            if entry.sha512_hex.is_empty() {
                                if let Ok(parsed) = Integrity::parse(&entry.integrity) {
                                    if let Some(sha512) = parsed
                                        .entries
                                        .iter()
                                        .find(|e| e.algorithm == Algorithm::Sha512)
                                    {
                                        entry.sha512_hex = HEXLOWER.encode(&sha512.digest);
                                    }
                                }
                            }
                            if Integrity::parse(&entry.integrity).is_ok() {
                                Some(entry)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                let entry = match parsed_entry {
                    Some(e) if !e.key.is_empty() && !e.sha512_hex.is_empty() => e,
                    _ => {
                        warn!(
                            "Corrupted or malformed index entry at {}. Purging.",
                            path.display()
                        );
                        let _ = remove_file_with_retries(&path);
                        report.corrupted_indices += 1;
                        continue;
                    }
                };

                let digest = entry.sha512_hex.to_ascii_lowercase();
                let is_valid = if valid_blobs.contains(&digest) {
                    true
                } else {
                    let bpath = self.blob_path(&digest);
                    if bpath.exists() {
                        if let Ok(bytes) = fs::read(&bpath) {
                            let mut hasher = Sha512::new();
                            hasher.update(&bytes);
                            let actual = HEXLOWER.encode(&hasher.finalize());
                            if actual.eq_ignore_ascii_case(&digest) {
                                valid_blobs.insert(digest.clone());
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                if is_valid {
                    report.verified_indices += 1;
                } else {
                    warn!(
                        "Orphaned index entry at {} points to missing blob {}. Purging.",
                        path.display(),
                        entry.sha512_hex
                    );
                    let _ = remove_file_with_retries(&path);
                    report.orphaned_indices += 1;
                }
            }
        }

        // 3. Clean stale temporary files in tmp
        report.stale_temp_files_cleaned = self.clean_stale_temp_files(Duration::from_secs(0))?;

        Ok(report)
    }

    /// Audit and purge all corrupted entries in the cache (blobs and index entries).
    /// Returns the number of purged corrupted files.
    pub fn purge_corrupted(&self) -> Result<usize, CacheError> {
        let mut purged = 0;

        // 1. Audit content blobs
        let content_dir = self.root.join("content-v2").join("sha512");
        if content_dir.exists() {
            purged += self.audit_and_purge_dir(&content_dir, true)?;
        }

        // 2. Audit index entries
        let index_dir = self.root.join("index-v5");
        if index_dir.exists() {
            purged += self.audit_and_purge_dir(&index_dir, false)?;
        }

        Ok(purged)
    }

    fn audit_and_purge_dir(&self, dir: &Path, is_blob: bool) -> Result<usize, CacheError> {
        let mut count = 0;
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    count += self.audit_and_purge_dir(&path, is_blob)?;
                } else if path.is_file() {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if is_blob {
                        // For blob: filename is expected sha512 hex
                        if let Ok(bytes) = fs::read(&path) {
                            let mut hasher = Sha512::new();
                            hasher.update(&bytes);
                            let actual = HEXLOWER.encode(&hasher.finalize());
                            if !actual.eq_ignore_ascii_case(file_name) {
                                let _ = remove_file_with_retries(&path);
                                count += 1;
                            }
                        } else {
                            let _ = remove_file_with_retries(&path);
                            count += 1;
                        }
                    } else {
                        // For index: parse JSON
                        if let Ok(content) = fs::read_to_string(&path) {
                            if serde_json::from_str::<IndexEntry>(&content).is_err() {
                                let _ = remove_file_with_retries(&path);
                                count += 1;
                            }
                        } else {
                            let _ = remove_file_with_retries(&path);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// Compute storage path for a project fast-path fingerprint keyed by its canonical directory.
    pub fn fingerprint_path(&self, project_dir: &Path) -> PathBuf {
        let canonical = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.to_path_buf());
        let path_str = canonical.to_string_lossy();
        let normalized = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
        #[cfg(windows)]
        let normalized_str = normalized.to_ascii_lowercase().replace('\\', "/");
        #[cfg(not(windows))]
        let normalized_str = normalized.to_string();

        let mut hasher = Sha256::new();
        hasher.update(normalized_str.as_bytes());
        let key = HEXLOWER.encode(&hasher.finalize());
        self.root
            .join("_fingerprints")
            .join(format!("{}.json", key))
    }

    /// Retrieve the cached project fingerprint for a project directory.
    pub fn get_project_fingerprint(
        &self,
        project_dir: &Path,
    ) -> Result<Option<String>, CacheError> {
        let path = self.fingerprint_path(project_dir);
        if !path.exists() {
            return Ok(None);
        }
        let data = match fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        #[derive(Deserialize)]
        struct FingerprintRecord {
            fingerprint: String,
        }
        if let Ok(record) = serde_json::from_str::<FingerprintRecord>(&data) {
            Ok(Some(record.fingerprint))
        } else {
            Ok(None)
        }
    }

    /// Store a project fingerprint in cache keyed by canonical project directory.
    pub fn set_project_fingerprint(
        &self,
        project_dir: &Path,
        fingerprint: &str,
    ) -> Result<(), CacheError> {
        let target_path = self.fingerprint_path(project_dir);
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let canonical = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.to_path_buf());
        let record = serde_json::json!({
            "project_path": canonical.to_string_lossy(),
            "fingerprint": fingerprint,
            "updated_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        let serialized = serde_json::to_vec_pretty(&record)?;

        let temp_path = self.create_temp_path("fingerprint");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(&serialized)?;
            file.flush()?;
        }

        if target_path.exists() {
            let _ = remove_file_with_retries(&target_path);
        }
        if let Err(err) = rename_with_retries(&temp_path, &target_path) {
            let _ = remove_file_with_retries(&temp_path);
            return Err(CacheError::Io(err));
        }
        Ok(())
    }
}

/// Helper to construct a registry-scoped cache key for packument metadata.
/// Scopes the key by registry URL and optional accept header.
pub fn packument_key(registry: &str, name: &str, accept: Option<&str>) -> String {
    let reg = registry.trim_end_matches('/');
    match accept {
        Some(a) if !a.is_empty() => format!("pacote:packument:{reg}:{name}:{a}"),
        _ => format!("pacote:packument:{reg}:{name}"),
    }
}
