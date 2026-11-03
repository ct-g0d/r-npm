use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Index entry metadata mapping a key to content integrity and attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub key: String,
    pub integrity: String,
    #[serde(default)]
    pub sha512_hex: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub time: u64,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

impl IndexEntry {
    pub fn new(
        key: String,
        integrity: String,
        sha512_hex: String,
        size: u64,
        metadata: Option<serde_json::Value>,
    ) -> Self {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            key,
            integrity,
            sha512_hex,
            size,
            time,
            metadata,
        }
    }

    /// Compute the index file path for a cache key.
    pub fn path_for_key(cache_dir: &Path, key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = HEXLOWER.encode(&hasher.finalize());
        let p1 = &hash[0..2];
        let p2 = &hash[2..4];
        cache_dir.join("index-v5").join(p1).join(p2).join(&hash)
    }
}
