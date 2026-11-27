use crate::error::IntegrityError;
use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use std::io::Read;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
}

impl Algorithm {
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    pub fn compute_digest(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
            Algorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
            Algorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
            Algorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(bytes);
                hasher.finalize().to_vec()
            }
        }
    }

    pub fn hasher(&self) -> IntegrityHasher {
        IntegrityHasher::new(*self)
    }

    pub fn compute_digest_reader<R: Read>(&self, mut reader: R) -> std::io::Result<Vec<u8>> {
        let mut hasher = self.hasher();
        let mut buf = [0u8; 65536];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize())
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[inline]
fn parse_algorithm(s: &str) -> Option<Algorithm> {
    let b = s.as_bytes();
    match b.len() {
        4 => {
            if b == b"sha1" || s.eq_ignore_ascii_case("sha1") {
                Some(Algorithm::Sha1)
            } else {
                None
            }
        }
        6 => match s {
            "sha512" => Some(Algorithm::Sha512),
            "sha256" => Some(Algorithm::Sha256),
            "sha384" => Some(Algorithm::Sha384),
            _ if s.eq_ignore_ascii_case("sha512") => Some(Algorithm::Sha512),
            _ if s.eq_ignore_ascii_case("sha256") => Some(Algorithm::Sha256),
            _ if s.eq_ignore_ascii_case("sha384") => Some(Algorithm::Sha384),
            _ => None,
        },
        _ => None,
    }
}

impl FromStr for Algorithm {
    type Err = IntegrityError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_algorithm(s).ok_or_else(|| IntegrityError::UnsupportedAlgorithm(s.to_string()))
    }
}

pub enum IntegrityHasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl IntegrityHasher {
    pub fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha1 => IntegrityHasher::Sha1(Sha1::new()),
            Algorithm::Sha256 => IntegrityHasher::Sha256(Sha256::new()),
            Algorithm::Sha384 => IntegrityHasher::Sha384(Sha384::new()),
            Algorithm::Sha512 => IntegrityHasher::Sha512(Sha512::new()),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            IntegrityHasher::Sha1(h) => h.update(bytes),
            IntegrityHasher::Sha256(h) => h.update(bytes),
            IntegrityHasher::Sha384(h) => h.update(bytes),
            IntegrityHasher::Sha512(h) => h.update(bytes),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            IntegrityHasher::Sha1(h) => h.finalize().to_vec(),
            IntegrityHasher::Sha256(h) => h.finalize().to_vec(),
            IntegrityHasher::Sha384(h) => h.finalize().to_vec(),
            IntegrityHasher::Sha512(h) => h.finalize().to_vec(),
        }
    }

    pub fn finalize_integrity(self, algorithm: Algorithm) -> Integrity {
        let digest = self.finalize();
        Integrity {
            entries: vec![IntegrityEntry::new(algorithm, digest)],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntegrityEntry {
    pub algorithm: Algorithm,
    pub digest: Vec<u8>,
    pub digest_base64: String,
}

#[inline]
fn decode_base64_digest(b64_bytes: &[u8]) -> Option<Vec<u8>> {
    // Fast path for standard 4-byte-aligned base64 (e.g. 88-byte sha512, 44-byte sha256, 28-byte sha1)
    if !b64_bytes.is_empty() && (b64_bytes.len() & 3) == 0 {
        if let Some(out) = decode_base64_aligned_fast(b64_bytes) {
            return Some(out);
        }
    }
    let decode_len = BASE64.decode_len(b64_bytes.len()).ok()?;
    // SHA-512 base64 is 88 bytes -> decode_len is 66, so stack buffer must exceed 66 bytes.
    if decode_len <= 96 {
        let mut stack_buf = [0u8; 96];
        let written = BASE64.decode_mut(b64_bytes, &mut stack_buf[..decode_len]).ok()?;
        let mut out = Vec::with_capacity(written);
        out.extend_from_slice(&stack_buf[..written]);
        Some(out)
    } else {
        BASE64.decode(b64_bytes).ok()
    }
}

const B64_DEC_TABLE: [i8; 256] = {
    let mut t = [-1i8; 256];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i as i8;
        t[(b'a' + i) as usize] = (i + 26) as i8;
        i += 1;
    }
    let mut d = 0u8;
    while d < 10 {
        t[(b'0' + d) as usize] = (d + 52) as i8;
        d += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t
};

#[inline]
fn decode_base64_aligned_fast(bytes: &[u8]) -> Option<Vec<u8>> {
    let len = bytes.len();
    let pad = if bytes[len - 1] == b'=' {
        if bytes[len - 2] == b'=' {
            2
        } else {
            1
        }
    } else {
        0
    };
    let out_len = (len / 4) * 3 - pad;
    let mut out = Vec::with_capacity(out_len);
    let full_quads = if pad == 0 { len } else { len - 4 };
    let mut i = 0usize;
    while i < full_quads {
        let a = B64_DEC_TABLE[bytes[i] as usize];
        let b = B64_DEC_TABLE[bytes[i + 1] as usize];
        let c = B64_DEC_TABLE[bytes[i + 2] as usize];
        let d = B64_DEC_TABLE[bytes[i + 3] as usize];
        if (a | b | c | d) < 0 {
            return None;
        }
        let v = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
        i += 4;
    }
    if pad == 1 {
        let a = B64_DEC_TABLE[bytes[i] as usize];
        let b = B64_DEC_TABLE[bytes[i + 1] as usize];
        let c = B64_DEC_TABLE[bytes[i + 2] as usize];
        if (a | b | c) < 0 || (c & 0x03) != 0 {
            return None;
        }
        let v = ((a as u32) << 12) | ((b as u32) << 6) | (c as u32);
        out.push((v >> 10) as u8);
        out.push((v >> 2) as u8);
    } else if pad == 2 {
        let a = B64_DEC_TABLE[bytes[i] as usize];
        let b = B64_DEC_TABLE[bytes[i + 1] as usize];
        if (a | b) < 0 || (b & 0x0f) != 0 {
            return None;
        }
        let v = ((a as u32) << 6) | (b as u32);
        out.push((v >> 4) as u8);
    }
    Some(out)
}

impl IntegrityEntry {
    pub fn new(algorithm: Algorithm, digest: Vec<u8>) -> Self {
        let digest_base64 = BASE64.encode(&digest);
        Self {
            algorithm,
            digest,
            digest_base64,
        }
    }

    pub fn from_base64(algorithm: Algorithm, base64_str: &str) -> Result<Self, IntegrityError> {
        let digest = decode_base64_digest(base64_str.as_bytes())
            .ok_or_else(|| IntegrityError::InvalidBase64(base64_str.to_string()))?;
        Ok(Self {
            algorithm,
            digest,
            digest_base64: base64_str.to_string(),
        })
    }
}

impl fmt::Display for IntegrityEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm, self.digest_base64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integrity {
    pub entries: Vec<IntegrityEntry>,
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl Integrity {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn parse(input: &str) -> Result<Self, IntegrityError> {
        // Fast path for single clean SRI token (e.g. "sha512-...==") with zero whitespace scanning
        let bytes = input.as_bytes();
        let fast_prefix = if bytes.len() > 7 && bytes[6] == b'-' {
            match &bytes[..6] {
                b"sha512" => Some((Algorithm::Sha512, 7)),
                b"sha256" => Some((Algorithm::Sha256, 7)),
                b"sha384" => Some((Algorithm::Sha384, 7)),
                _ => None,
            }
        } else if bytes.len() > 5 && bytes[..5] == *b"sha1-" {
            Some((Algorithm::Sha1, 5))
        } else {
            None
        };
        if let Some((algo, off)) = fast_prefix {
            let base64_str = &input[off..];
            if let Some(digest) = decode_base64_digest(base64_str.as_bytes()) {
                return Ok(Self {
                    entries: vec![IntegrityEntry {
                        algorithm: algo,
                        digest,
                        digest_base64: base64_str.to_string(),
                    }],
                });
            }
        } else if let Some((algo_str, base64_str)) = input.split_once('-') {
            if !algo_str.is_empty() && !base64_str.is_empty() {
                if let Some(algo) = parse_algorithm(algo_str) {
                    if let Some(digest) = decode_base64_digest(base64_str.as_bytes()) {
                        return Ok(Self {
                            entries: vec![IntegrityEntry {
                                algorithm: algo,
                                digest,
                                digest_base64: base64_str.to_string(),
                            }],
                        });
                    }
                }
            }
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(IntegrityError::Empty);
        }

        let mut entries = Vec::with_capacity(2);
        for token in trimmed.split_whitespace() {
            let Some((algo_str, base64_str)) = token.split_once('-') else {
                return Err(IntegrityError::InvalidFormat(token.to_string()));
            };
            if algo_str.is_empty() || base64_str.is_empty() {
                return Err(IntegrityError::InvalidFormat(token.to_string()));
            }

            let algo = Algorithm::from_str(algo_str)?;
            let entry = IntegrityEntry::from_base64(algo, base64_str)?;
            entries.push(entry);
        }

        if entries.is_empty() {
            return Err(IntegrityError::Empty);
        }

        Ok(Self { entries })
    }

    /// Zero-allocation validation and strongest algorithm extraction from an integrity string.
    pub fn strongest_algorithm_str(input: &str) -> Result<Option<Algorithm>, IntegrityError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(IntegrityError::Empty);
        }

        let mut strongest: Option<Algorithm> = None;
        let mut decode_buf = [0u8; 128];
        for token in trimmed.split_whitespace() {
            let Some((algo_str, base64_str)) = token.split_once('-') else {
                return Err(IntegrityError::InvalidFormat(token.to_string()));
            };
            if algo_str.is_empty() || base64_str.is_empty() {
                return Err(IntegrityError::InvalidFormat(token.to_string()));
            }

            let algo = Algorithm::from_str(algo_str)?;
            let b64_bytes = base64_str.as_bytes();
            match BASE64.decode_len(b64_bytes.len()) {
                Ok(out_len) if out_len <= decode_buf.len() => {
                    BASE64
                        .decode_mut(b64_bytes, &mut decode_buf[..out_len])
                        .map_err(|_| IntegrityError::InvalidBase64(base64_str.to_string()))?;
                }
                Ok(_) => {
                    BASE64
                        .decode(b64_bytes)
                        .map_err(|_| IntegrityError::InvalidBase64(base64_str.to_string()))?;
                }
                Err(_) => return Err(IntegrityError::InvalidBase64(base64_str.to_string())),
            }

            strongest = Some(strongest.map_or(algo, |curr| curr.max(algo)));
        }

        match strongest {
            Some(algo) => Ok(Some(algo)),
            None => Err(IntegrityError::Empty),
        }
    }

    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Self {
        let digest = algorithm.compute_digest(bytes);
        Self {
            entries: vec![IntegrityEntry::new(algorithm, digest)],
        }
    }

    pub fn from_reader<R: Read>(reader: R, algorithm: Algorithm) -> std::io::Result<Self> {
        let digest = algorithm.compute_digest_reader(reader)?;
        Ok(Self {
            entries: vec![IntegrityEntry::new(algorithm, digest)],
        })
    }

    pub fn strongest_algorithm(&self) -> Option<Algorithm> {
        self.entries.iter().map(|e| e.algorithm).max()
    }

    fn verify_digest(&self, strongest: Algorithm, actual_digest: &[u8]) -> Result<(), IntegrityError> {
        let mut first_expected: Option<&str> = None;
        for candidate in &self.entries {
            if candidate.algorithm == strongest {
                if first_expected.is_none() {
                    first_expected = Some(&candidate.digest_base64);
                }
                if constant_time_eq(&candidate.digest, actual_digest) {
                    return Ok(());
                }
            }
        }

        let actual_base64 = BASE64.encode(actual_digest);
        let expected_base64 = first_expected.unwrap_or_default();

        Err(IntegrityError::Mismatch {
            algorithm: strongest.to_string(),
            expected: format!("{strongest}-{expected_base64}"),
            actual: format!("{strongest}-{actual_base64}"),
        })
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<(), IntegrityError> {
        let strongest = self.strongest_algorithm().ok_or(IntegrityError::Empty)?;
        let mut buf = [0u8; 64];
        let digest_len = match strongest {
            Algorithm::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(bytes);
                buf[..20].copy_from_slice(&hasher.finalize());
                20
            }
            Algorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                buf[..32].copy_from_slice(&hasher.finalize());
                32
            }
            Algorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(bytes);
                buf[..48].copy_from_slice(&hasher.finalize());
                48
            }
            Algorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(bytes);
                buf[..64].copy_from_slice(&hasher.finalize());
                64
            }
        };
        self.verify_digest(strongest, &buf[..digest_len])
    }

    pub fn verify_reader<R: Read>(&self, reader: R) -> Result<(), IntegrityError> {
        let strongest = self.strongest_algorithm().ok_or(IntegrityError::Empty)?;
        let actual_digest = strongest
            .compute_digest_reader(reader)
            .map_err(|e| IntegrityError::Mismatch {
                algorithm: strongest.to_string(),
                expected: "valid stream".to_string(),
                actual: format!("i/o error reading stream: {e}"),
            })?;
        self.verify_digest(strongest, &actual_digest)
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{entry}")?;
        }
        Ok(())
    }
}

impl FromStr for Integrity {
    type Err = IntegrityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Integrity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Integrity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IntegrityVisitor;

        impl<'de> serde::de::Visitor<'de> for IntegrityVisitor {
            type Value = Integrity;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an SRI integrity string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Integrity::parse(v).map_err(serde::de::Error::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Integrity::parse(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(IntegrityVisitor)
    }
}
