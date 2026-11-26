use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Encode `bytes` as lowercase hex into a caller-supplied buffer (`out.len() == bytes.len() * 2`).
#[inline]
pub(crate) fn encode_hex_lower<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a str {
    debug_assert_eq!(out.len(), bytes.len() * 2);
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX_CHARS[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }
    // All bytes come from `HEX_CHARS`, which is strictly ASCII.
    unsafe { std::str::from_utf8_unchecked(out) }
}

#[inline]
pub(crate) fn sha256_hex_stack<'a>(data: &[u8], out: &'a mut [u8; 64]) -> &'a str {
    let digest = Sha256::digest(data);
    encode_hex_lower(&digest, out)
}

#[inline]
pub(crate) fn npm_index_path_from_hash(cache_dir: &Path, hash: &str) -> PathBuf {
    let p1 = &hash[0..2];
    let p2 = &hash[2..4];
    let mut npm_style = PathBuf::with_capacity(cache_dir.as_os_str().len() + 80);
    npm_style.push(cache_dir);
    npm_style.push("index-v5");
    npm_style.push(p1);
    npm_style.push(p2);
    npm_style.push(&hash[4..]);
    npm_style
}

#[inline]
pub(crate) fn legacy_index_path_from_npm(npm_path: &Path, hash: &str) -> PathBuf {
    let mut legacy_style = npm_path.to_path_buf();
    legacy_style.set_file_name(hash);
    legacy_style
}

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
        let mut hex_buf = [0u8; 64];
        let hash = sha256_hex_stack(key.as_bytes(), &mut hex_buf);
        let p1 = &hash[0..2];
        let p2 = &hash[2..4];
        let mut npm_style = PathBuf::with_capacity(cache_dir.as_os_str().len() + 80);
        npm_style.push(cache_dir);
        npm_style.push("index-v5");
        npm_style.push(p1);
        npm_style.push(p2);
        npm_style.push(&hash[4..]);
        if npm_style.exists() {
            return npm_style;
        }
        let mut legacy_style = npm_style.clone();
        legacy_style.set_file_name(hash);
        if legacy_style.exists() {
            legacy_style
        } else {
            npm_style
        }
    }
}
