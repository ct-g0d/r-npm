use crate::error::IntegrityError;
use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
}

impl Algorithm {
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
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = IntegrityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Algorithm::Sha1),
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            other => Err(IntegrityError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntegrityEntry {
    pub algorithm: Algorithm,
    pub digest: Vec<u8>,
    pub digest_base64: String,
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
        let digest = BASE64
            .decode(base64_str.as_bytes())
            .map_err(|_| IntegrityError::InvalidBase64(base64_str.to_string()))?;
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

impl Integrity {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn parse(input: &str) -> Result<Self, IntegrityError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(IntegrityError::Empty);
        }

        let mut entries = Vec::new();
        for token in trimmed.split_whitespace() {
            let parts: Vec<&str> = token.splitn(2, '-').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err(IntegrityError::InvalidFormat(token.to_string()));
            }

            let algo = Algorithm::from_str(parts[0])?;
            let entry = IntegrityEntry::from_base64(algo, parts[1])?;
            entries.push(entry);
        }

        if entries.is_empty() {
            return Err(IntegrityError::Empty);
        }

        Ok(Self { entries })
    }

    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Self {
        let digest = algorithm.compute_digest(bytes);
        Self {
            entries: vec![IntegrityEntry::new(algorithm, digest)],
        }
    }

    pub fn strongest_algorithm(&self) -> Option<Algorithm> {
        self.entries.iter().map(|e| e.algorithm).max()
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<(), IntegrityError> {
        let strongest = self.strongest_algorithm().ok_or(IntegrityError::Empty)?;
        let actual_digest = strongest.compute_digest(bytes);
        let actual_base64 = BASE64.encode(&actual_digest);

        // Filter by the strongest algorithm
        let candidates: Vec<&IntegrityEntry> = self
            .entries
            .iter()
            .filter(|e| e.algorithm == strongest)
            .collect();

        for candidate in &candidates {
            if candidate.digest == actual_digest {
                return Ok(());
            }
        }

        let expected_base64 = candidates
            .first()
            .map(|e| e.digest_base64.clone())
            .unwrap_or_default();

        Err(IntegrityError::Mismatch {
            algorithm: strongest.to_string(),
            expected: format!("{}-{}", strongest, expected_base64),
            actual: format!("{}-{}", strongest, actual_base64),
        })
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
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
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Integrity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Integrity::parse(&s).map_err(serde::de::Error::custom)
    }
}
