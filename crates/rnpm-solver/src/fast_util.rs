use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

/// Fast non-cryptographic FxHash for solver-internal maps and sets.
/// Eliminates SipHash overhead and OS RNG initialization (`RandomState::new()`).
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

pub(crate) type FastMap<K, V> = HashMap<K, V, FxBuildHasher>;
pub(crate) type FastSet<T> = HashSet<T, FxBuildHasher>;

#[inline]
pub(crate) fn fast_map_with_capacity<K, V>(cap: usize) -> FastMap<K, V> {
    HashMap::with_capacity_and_hasher(cap, FxBuildHasher)
}

#[inline]
pub(crate) fn fast_set_with_capacity<T>(cap: usize) -> FastSet<T> {
    HashSet::with_capacity_and_hasher(cap, FxBuildHasher)
}

#[inline]
pub(crate) fn hash_str_fx(s: &str) -> u64 {
    let mut h = FxHasher { hash: 0 };
    h.write(s.as_bytes());
    h.write_usize(s.len());
    h.finish()
}

/// Compact 32-bit identifier for interned strings within a single solver run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SymId(pub u32);

/// Safe open-addressed string interner with zero allocations on cache hit.
#[derive(Debug, Clone)]
pub(crate) struct StringInterner {
    strings: Vec<String>,
    hashes: Vec<u64>,
    /// Power-of-two table storing `idx + 1` (`0` = empty slot).
    buckets: Vec<u32>,
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::with_capacity(128)
    }
}

impl StringInterner {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        let bucket_len = (cap * 2).max(16).next_power_of_two();
        Self {
            strings: Vec::with_capacity(cap),
            hashes: Vec::with_capacity(cap),
            buckets: vec![0; bucket_len],
        }
    }

    #[inline]
    pub(crate) fn get(&self, id: SymId) -> &str {
        &self.strings[id.0 as usize]
    }

    #[inline]
    pub(crate) fn intern(&mut self, s: &str) -> SymId {
        let hash = hash_str_fx(s);
        let mask = self.buckets.len() - 1;
        let mut slot = (hash as usize) & mask;
        loop {
            let entry = self.buckets[slot];
            if entry == 0 {
                break;
            }
            let idx = (entry - 1) as usize;
            if self.hashes[idx] == hash && self.strings[idx] == s {
                return SymId(idx as u32);
            }
            slot = (slot + 1) & mask;
        }

        let idx = self.strings.len();
        self.strings.push(s.to_string());
        self.hashes.push(hash);

        if (idx + 1) * 10 >= self.buckets.len() * 7 {
            self.rehash();
        } else {
            self.buckets[slot] = (idx + 1) as u32;
        }
        SymId(idx as u32)
    }

    #[inline]
    pub(crate) fn intern_owned(&mut self, s: String) -> SymId {
        let hash = hash_str_fx(&s);
        let mask = self.buckets.len() - 1;
        let mut slot = (hash as usize) & mask;
        loop {
            let entry = self.buckets[slot];
            if entry == 0 {
                break;
            }
            let idx = (entry - 1) as usize;
            if self.hashes[idx] == hash && self.strings[idx] == s {
                return SymId(idx as u32);
            }
            slot = (slot + 1) & mask;
        }

        let idx = self.strings.len();
        self.strings.push(s);
        self.hashes.push(hash);

        if (idx + 1) * 10 >= self.buckets.len() * 7 {
            self.rehash();
        } else {
            self.buckets[slot] = (idx + 1) as u32;
        }
        SymId(idx as u32)
    }

    fn rehash(&mut self) {
        let new_len = (self.buckets.len() * 2).max(16);
        let mask = new_len - 1;
        let mut new_buckets = vec![0u32; new_len];
        for (idx, &hash) in self.hashes.iter().enumerate() {
            let mut slot = (hash as usize) & mask;
            while new_buckets[slot] != 0 {
                slot = (slot + 1) & mask;
            }
            new_buckets[slot] = (idx + 1) as u32;
        }
        self.buckets = new_buckets;
    }
}

pub(crate) const NO_ANCESTOR: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct AncestorEntry {
    parent: u32,
    name: SymId,
}

/// Arena-backed ancestor chain eliminating `Vec<String>` clones on every placed package.
#[derive(Debug, Clone, Default)]
pub(crate) struct AncestorArena {
    entries: Vec<AncestorEntry>,
}

impl AncestorArena {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, parent: u32, name: SymId) -> u32 {
        let id = self.entries.len() as u32;
        self.entries.push(AncestorEntry { parent, name });
        id
    }

    pub(crate) fn push_slice(&mut self, slice: &[String], interner: &mut StringInterner) -> u32 {
        let mut head = NO_ANCESTOR;
        for s in slice {
            let sym = interner.intern(s);
            head = self.push(head, sym);
        }
        head
    }

    #[inline]
    pub(crate) fn contains_any(&self, mut head: u32, target: SymId, alias: Option<SymId>) -> bool {
        while head != NO_ANCESTOR {
            let e = self.entries[head as usize];
            if e.name == target || alias.is_some_and(|a| e.name == a) {
                return true;
            }
            head = e.parent;
        }
        false
    }

    pub(crate) fn find_cycle_path(
        &self,
        mut head: u32,
        target: SymId,
        alias: Option<SymId>,
        interner: &StringInterner,
    ) -> Option<Vec<String>> {
        let mut rev = Vec::new();
        let mut match_rev_idx = None;
        while head != NO_ANCESTOR {
            let e = self.entries[head as usize];
            if e.name == target || alias.is_some_and(|a| e.name == a) {
                match_rev_idx = Some(rev.len());
            }
            rev.push(interner.get(e.name).to_string());
            head = e.parent;
        }
        let idx = match_rev_idx?;
        rev.truncate(idx + 1);
        rev.reverse();
        rev.push(interner.get(target).to_string());
        Some(rev)
    }

    pub(crate) fn to_vec(&self, mut head: u32, interner: &StringInterner) -> Vec<String> {
        let mut out = Vec::new();
        while head != NO_ANCESTOR {
            let e = self.entries[head as usize];
            out.push(interner.get(e.name).to_string());
            head = e.parent;
        }
        out.reverse();
        out
    }
}
