use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

#[derive(Clone, Copy, Default)]
pub(crate) struct FxBuildHasher;

impl BuildHasher for FxBuildHasher {
    type Hasher = FxHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FxHasher { hash: 0 }
    }
}

pub(crate) struct FxHasher {
    hash: u64,
}

const FX_K: u64 = 0x517cc1b727220a95;

impl FxHasher {
    #[inline]
    fn add_word(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_K);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            let word = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
            self.add_word(word);
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            let word = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64;
            self.add_word(word);
            bytes = &bytes[4..];
        }
        if bytes.len() >= 2 {
            let word = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64;
            self.add_word(word);
            bytes = &bytes[2..];
        }
        if !bytes.is_empty() {
            self.add_word(bytes[0] as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add_word(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add_word(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add_word(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add_word(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add_word(i as u64);
    }
}

pub(crate) type FxHashMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub(crate) type FxHashSet<T> = HashSet<T, FxBuildHasher>;

#[inline]
pub(crate) fn fx_map_with_capacity<K, V>(cap: usize) -> FxHashMap<K, V> {
    HashMap::with_capacity_and_hasher(cap, FxBuildHasher)
}

#[inline]
pub(crate) fn fx_set_with_capacity<T>(cap: usize) -> FxHashSet<T> {
    HashSet::with_capacity_and_hasher(cap, FxBuildHasher)
}
