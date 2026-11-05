use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::error::SemverError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrereleaseId {
    Numeric(u64),
    Alpha(String),
}

impl PartialOrd for PrereleaseId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrereleaseId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PrereleaseId::Numeric(a), PrereleaseId::Numeric(b)) => a.cmp(b),
            // Numeric identifiers always have lower precedence than alphanumeric
            (PrereleaseId::Numeric(_), PrereleaseId::Alpha(_)) => Ordering::Less,
            (PrereleaseId::Alpha(_), PrereleaseId::Numeric(_)) => Ordering::Greater,
            (PrereleaseId::Alpha(a), PrereleaseId::Alpha(b)) => a.cmp(b),
        }
    }
}

impl fmt::Display for PrereleaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrereleaseId::Numeric(n) => write!(f, "{n}"),
            PrereleaseId::Alpha(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Vec<PrereleaseId>,
    pub build: Vec<String>,
}

impl Version {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease: Vec::new(),
            build: Vec::new(),
        }
    }

    pub fn parse(input: &str) -> Result<Self, SemverError> {
        let trimmed = input.trim();
        // node-semver strips leading 'v', 'V', or '='
        let s = trimmed.trim_start_matches(['v', 'V', '=', ' ']);
        let s = s.trim();
        if s.is_empty() {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        // Split off build metadata first '+'
        let (ver_pre, build) = if let Some(idx) = s.find('+') {
            let b_str = &s[idx + 1..];
            let builds: Vec<String> = b_str.split('.').map(|p| p.trim().to_string()).collect();
            (&s[..idx], builds)
        } else {
            (s, Vec::new())
        };

        // Split off prerelease '-'
        let (ver_part, prerelease) = if let Some(idx) = ver_pre.find('-') {
            let p_str = &ver_pre[idx + 1..];
            if p_str.is_empty() {
                return Err(SemverError::InvalidVersion(input.to_string()));
            }
            let mut pres = Vec::new();
            for part in p_str.split('.') {
                let part = part.trim();
                if part.is_empty() {
                    return Err(SemverError::InvalidPrerelease(p_str.to_string()));
                }
                // Check if part is purely numeric and has no leading zero (or 0 itself)
                if part.chars().all(|c| c.is_ascii_digit())
                    && (part.len() == 1 || !part.starts_with('0'))
                {
                    if let Ok(n) = part.parse::<u64>() {
                        pres.push(PrereleaseId::Numeric(n));
                        continue;
                    }
                }
                pres.push(PrereleaseId::Alpha(part.to_string()));
            }
            (&ver_pre[..idx], pres)
        } else {
            (ver_pre, Vec::new())
        };

        // Parse major.minor.patch
        let parts: Vec<&str> = ver_part.split('.').collect();
        if parts.len() != 3 {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        let major = parts[0]
            .trim()
            .parse::<u64>()
            .map_err(|_| SemverError::InvalidVersion(input.to_string()))?;
        let minor = parts[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| SemverError::InvalidVersion(input.to_string()))?;
        let patch = parts[2]
            .trim()
            .parse::<u64>()
            .map_err(|_| SemverError::InvalidVersion(input.to_string()))?;

        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
            build,
        })
    }

    /// Loose version parsing supporting "v", "=", leading/trailing spaces,
    /// and partial versions like "1", "1.2" which default missing minor/patch to 0.
    pub fn parse_loose(input: &str) -> Result<Self, SemverError> {
        let trimmed = input.trim();
        // node-semver loose mode strips leading 'v', 'V', '=', and whitespace
        let s = trimmed.trim_start_matches(['v', 'V', '=', ' ']);
        let s = s.trim();
        if s.is_empty() {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        // Split off build metadata first '+'
        let (ver_pre, build) = if let Some(idx) = s.find('+') {
            let b_str = &s[idx + 1..];
            let builds: Vec<String> = b_str.split('.').map(|p| p.trim().to_string()).collect();
            (&s[..idx], builds)
        } else {
            (s, Vec::new())
        };

        // Split off prerelease '-'
        let (ver_part, prerelease) = if let Some(idx) = ver_pre.find('-') {
            let p_str = &ver_pre[idx + 1..];
            if p_str.is_empty() {
                return Err(SemverError::InvalidVersion(input.to_string()));
            }
            let mut pres = Vec::new();
            for part in p_str.split('.') {
                let part = part.trim();
                if part.is_empty() {
                    return Err(SemverError::InvalidPrerelease(p_str.to_string()));
                }
                // Check if part is numeric (no leading zeroes except 0 itself)
                if part.chars().all(|c| c.is_ascii_digit())
                    && (part.len() == 1 || !part.starts_with('0'))
                {
                    if let Ok(n) = part.parse::<u64>() {
                        pres.push(PrereleaseId::Numeric(n));
                        continue;
                    }
                }
                pres.push(PrereleaseId::Alpha(part.to_string()));
            }
            (&ver_pre[..idx], pres)
        } else {
            (ver_pre, Vec::new())
        };

        // Parse major[.minor[.patch]]
        let parts: Vec<&str> = ver_part.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        let major = parts[0]
            .trim()
            .parse::<u64>()
            .map_err(|_| SemverError::InvalidVersion(input.to_string()))?;

        let minor = if parts.len() > 1 {
            parts[1]
                .trim()
                .parse::<u64>()
                .map_err(|_| SemverError::InvalidVersion(input.to_string()))?
        } else {
            0
        };

        let patch = if parts.len() > 2 {
            parts[2]
                .trim()
                .parse::<u64>()
                .map_err(|_| SemverError::InvalidVersion(input.to_string()))?
        } else {
            0
        };

        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
            build,
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare major, minor, patch
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Compare prereleases
        // 1. Version without prerelease has higher precedence than with prerelease
        match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                let min_len = self.prerelease.len().min(other.prerelease.len());
                for i in 0..min_len {
                    match self.prerelease[i].cmp(&other.prerelease[i]) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                self.prerelease.len().cmp(&other.prerelease.len())
            }
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.major.hash(state);
        self.minor.hash(state);
        self.patch.hash(state);
        self.prerelease.hash(state);
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.prerelease.is_empty() {
            write!(f, "-")?;
            for (i, p) in self.prerelease.iter().enumerate() {
                if i > 0 {
                    write!(f, ".")?;
                }
                write!(f, "{p}")?;
            }
        }
        if !self.build.is_empty() {
            write!(f, "+")?;
            for (i, b) in self.build.iter().enumerate() {
                if i > 0 {
                    write!(f, ".")?;
                }
                write!(f, "{b}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for Version {
    type Err = SemverError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Version::parse(&s).map_err(serde::de::Error::custom)
    }
}
