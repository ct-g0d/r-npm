use crate::error::SemverError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrereleaseId {
    Numeric(u64),
    Alpha(String),
}

impl PartialOrd for PrereleaseId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrereleaseId {
    #[inline]
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

#[inline]
pub(crate) fn parse_u64_segment(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    // SemVer 2.0.0 §2: Numeric segments MUST NOT contain leading zeroes
    if bytes.len() > 1 && bytes[0] == b'0' {
        return None;
    }
    let mut val: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(val)
}

#[inline]
pub(crate) fn parse_loose_u64_segment(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(val)
}

/// Zero-allocation parser for pure `MAJOR.MINOR.PATCH` with no prerelease/build metadata.
#[inline]
pub(crate) fn parse_fast_u64_triplet(s: &str) -> Option<(u64, u64, u64)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut dot1 = None;
    let mut dot2 = None;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            if dot1.is_none() {
                dot1 = Some(i);
            } else if dot2.is_none() {
                dot2 = Some(i);
            } else {
                return None; // More than 2 dots
            }
        } else if !b.is_ascii_digit() {
            return None; // Any non-digit (including -, +, whitespace)
        }
    }

    let d1 = dot1?;
    let d2 = dot2?;

    let s0 = &bytes[..d1];
    let s1 = &bytes[d1 + 1..d2];
    let s2 = &bytes[d2 + 1..];

    let major = parse_u64_segment(s0)?;
    let minor = parse_u64_segment(s1)?;
    let patch = parse_u64_segment(s2)?;

    Some((major, minor, patch))
}

impl Version {
    #[inline]
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
        // Support leading '=' and/or 'v'/'V' prefix (e.g. '=1.2.3', 'v1.2.3', '=v1.2.3')
        let s = trimmed.strip_prefix('=').unwrap_or(trimmed);
        let s = s
            .strip_prefix('v')
            .or_else(|| s.strip_prefix('V'))
            .unwrap_or(s);
        let s = s.trim();
        // node-semver never accepts inner whitespace: "2.5.0 - 3" is a range.
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        // Fast path: pure major.minor.patch with zero heap allocations (95% common case)
        if let Some((major, minor, patch)) = parse_fast_u64_triplet(s) {
            return Ok(Self {
                major,
                minor,
                patch,
                prerelease: Vec::new(),
                build: Vec::new(),
            });
        }

        // If string contains only digits and dots, but failed parse_fast_u64_triplet,
        // it means it had leading zeroes ("01.2.3"), too many/few dots ("1.2" or "1.2.3.4"),
        // or numeric overflow. Without '-' or '+', it is definitively an invalid version.
        if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        // Split off build metadata first '+'
        let (ver_pre, build) = if let Some(idx) = s.find('+') {
            let b_str = &s[idx + 1..];
            if b_str.is_empty() {
                return Err(SemverError::InvalidVersion(input.to_string()));
            }
            let mut builds = Vec::new();
            for part in b_str.split('.') {
                let part = part.trim();
                if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(SemverError::InvalidVersion(input.to_string()));
                }
                builds.push(part.to_string());
            }
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
                if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(SemverError::InvalidPrerelease(p_str.to_string()));
                }
                // Check if part is purely numeric
                if part.chars().all(|c| c.is_ascii_digit()) {
                    // SemVer 2.0.0 §9: Numeric identifiers MUST NOT include leading zeroes
                    if part.len() > 1 && part.starts_with('0') {
                        return Err(SemverError::InvalidPrerelease(p_str.to_string()));
                    }
                    let n = part
                        .parse::<u64>()
                        .map_err(|_| SemverError::InvalidPrerelease(p_str.to_string()))?;
                    pres.push(PrereleaseId::Numeric(n));
                } else {
                    pres.push(PrereleaseId::Alpha(part.to_string()));
                }
            }
            (&ver_pre[..idx], pres)
        } else {
            (ver_pre, Vec::new())
        };

        // Parse major.minor.patch without allocating a Vec
        let mut split = ver_part.split('.');
        let p0 = split.next();
        let p1 = split.next();
        let p2 = split.next();
        if split.next().is_some() {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }
        let (p0, p1, p2) = match (p0, p1, p2) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Err(SemverError::InvalidVersion(input.to_string())),
        };

        let major = parse_u64_segment(p0.trim().as_bytes())
            .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;
        let minor = parse_u64_segment(p1.trim().as_bytes())
            .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;
        let patch = parse_u64_segment(p2.trim().as_bytes())
            .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;

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
        // node-semver never accepts inner whitespace: "2.5.0 - 3" is a range.
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }

        // Fast path: if s contains only digits and dots, parse 1..=3 segments directly
        if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            let mut split = s.split('.');
            let p0 = split.next();
            let p1 = split.next();
            let p2 = split.next();
            if split.next().is_some() {
                return Err(SemverError::InvalidVersion(input.to_string()));
            }
            let p0 = p0.ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;
            let major = parse_loose_u64_segment(p0.as_bytes())
                .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;
            let minor = if let Some(p1) = p1 {
                parse_loose_u64_segment(p1.as_bytes())
                    .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?
            } else {
                0
            };
            let patch = if let Some(p2) = p2 {
                parse_loose_u64_segment(p2.as_bytes())
                    .ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?
            } else {
                0
            };
            return Ok(Self {
                major,
                minor,
                patch,
                prerelease: Vec::new(),
                build: Vec::new(),
            });
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
                // In loose mode, parse all-digit segments as numeric (e.g. 01 -> 1)
                if part.chars().all(|c| c.is_ascii_digit()) {
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

        // Parse major[.minor[.patch]] without allocating a Vec
        let mut split = ver_part.split('.');
        let p0 = split.next();
        let p1 = split.next();
        let p2 = split.next();
        if split.next().is_some() {
            return Err(SemverError::InvalidVersion(input.to_string()));
        }
        let p0 = p0.ok_or_else(|| SemverError::InvalidVersion(input.to_string()))?;
        let major = p0
            .trim()
            .parse::<u64>()
            .map_err(|_| SemverError::InvalidVersion(input.to_string()))?;

        let minor = if let Some(p1) = p1 {
            p1.trim()
                .parse::<u64>()
                .map_err(|_| SemverError::InvalidVersion(input.to_string()))?
        } else {
            0
        };

        let patch = if let Some(p2) = p2 {
            p2.trim()
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

    #[inline]
    pub fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }

    /// Bumps this version according to node-semver `inc(release, identifier)` rules.
    pub fn inc(&self, release: &str, identifier: Option<&str>) -> Result<Self, SemverError> {
        let mut v = self.clone();
        v.build.clear(); // Incrementing drops build metadata in semver
        match release {
            "major" => {
                if v.minor != 0 || v.patch != 0 || v.prerelease.is_empty() {
                    v.major = v.major.checked_add(1).ok_or_else(|| {
                        SemverError::InvalidVersion("Numeric overflow in major version increment".to_string())
                    })?;
                }
                v.minor = 0;
                v.patch = 0;
                v.prerelease.clear();
            }
            "minor" => {
                if v.patch != 0 || v.prerelease.is_empty() {
                    v.minor = v.minor.checked_add(1).ok_or_else(|| {
                        SemverError::InvalidVersion("Numeric overflow in minor version increment".to_string())
                    })?;
                }
                v.patch = 0;
                v.prerelease.clear();
            }
            "patch" => {
                if v.prerelease.is_empty() {
                    v.patch = v.patch.checked_add(1).ok_or_else(|| {
                        SemverError::InvalidVersion("Numeric overflow in patch version increment".to_string())
                    })?;
                }
                v.prerelease.clear();
            }
            "premajor" => {
                v.prerelease.clear();
                v.patch = 0;
                v.minor = 0;
                v.major = v.major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidVersion("Numeric overflow in major version increment".to_string())
                })?;
                v.inc_pre(identifier);
            }
            "preminor" => {
                v.prerelease.clear();
                v.patch = 0;
                v.minor = v.minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidVersion("Numeric overflow in minor version increment".to_string())
                })?;
                v.inc_pre(identifier);
            }
            "prepatch" => {
                v.prerelease.clear();
                v.patch = v.patch.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidVersion("Numeric overflow in patch version increment".to_string())
                })?;
                v.inc_pre(identifier);
            }
            "prerelease" => {
                if v.prerelease.is_empty() {
                    v.patch = v.patch.checked_add(1).ok_or_else(|| {
                        SemverError::InvalidVersion("Numeric overflow in patch version increment".to_string())
                    })?;
                }
                v.inc_pre(identifier);
            }
            _ => {
                return Err(SemverError::InvalidVersion(format!(
                    "Invalid release type: {release}"
                )))
            }
        }
        Ok(v)
    }

    fn inc_pre(&mut self, identifier: Option<&str>) {
        let base: u64 = 0;
        if self.prerelease.is_empty() {
            self.prerelease = vec![PrereleaseId::Numeric(base)];
        } else {
            let mut incremented = false;
            let mut i = self.prerelease.len();
            while i > 0 {
                i -= 1;
                if let PrereleaseId::Numeric(n) = &mut self.prerelease[i] {
                    *n = n.saturating_add(1);
                    incremented = true;
                    break;
                }
            }
            if !incremented {
                self.prerelease.push(PrereleaseId::Numeric(base));
            }
        }

        if let Some(id) = identifier {
            let id_parts: Vec<&str> = id.split('.').collect();
            // Check if current prerelease starts with id_parts
            let mut matches = self.prerelease.len() >= id_parts.len();
            if matches {
                for (idx, part) in id_parts.iter().enumerate() {
                    let matches_part = match &self.prerelease[idx] {
                        PrereleaseId::Alpha(s) => s == *part,
                        PrereleaseId::Numeric(n) => n.to_string() == *part,
                    };
                    if !matches_part {
                        matches = false;
                        break;
                    }
                }
            }
            if matches {
                let next_idx = id_parts.len();
                if next_idx < self.prerelease.len() {
                    if let PrereleaseId::Numeric(_) = self.prerelease[next_idx] {
                        // Keep current incremented number
                    } else {
                        self.set_prerelease_id_base(id_parts, base);
                    }
                } else {
                    self.set_prerelease_id_base(id_parts, base);
                }
            } else {
                self.set_prerelease_id_base(id_parts, base);
            }
        }
    }

    fn set_prerelease_id_base(&mut self, id_parts: Vec<&str>, base: u64) {
        let mut new_pres = Vec::new();
        for p in id_parts {
            if let Ok(n) = p.parse::<u64>() {
                new_pres.push(PrereleaseId::Numeric(n));
            } else {
                new_pres.push(PrereleaseId::Alpha(p.to_string()));
            }
        }
        new_pres.push(PrereleaseId::Numeric(base));
        self.prerelease = new_pres;
    }
}

impl PartialOrd for Version {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
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

        // Fast path: if neither has prerelease, versions are equal
        if self.prerelease.is_empty() && other.prerelease.is_empty() {
            return Ordering::Equal;
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
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major
            && self.minor == other.minor
            && self.patch == other.patch
            && self.prerelease == other.prerelease
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    #[inline]
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
        struct VersionVisitor;

        impl<'de> serde::de::Visitor<'de> for VersionVisitor {
            type Value = Version;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a semver version string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Version::parse(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(VersionVisitor)
    }
}
