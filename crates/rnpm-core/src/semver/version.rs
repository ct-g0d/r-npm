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

/// Single-pass prefix parser for strict `MAJOR.MINOR.PATCH` segments.
/// Returns `(major, minor, patch, bytes_consumed)`.
#[inline]
pub(crate) fn parse_strict_triplet_prefix(bytes: &[u8]) -> Option<(u64, u64, u64, usize)> {
    let len = bytes.len();
    if len < 5 {
        return None;
    }

    let mut i = 0usize;
    let mut vals = [0u64; 3];

    let mut seg = 0usize;
    while seg < 3 {
        if i >= len {
            return None;
        }
        let b0 = bytes[i];
        if !b0.is_ascii_digit() {
            return None;
        }
        i += 1;

        if b0 == b'0' {
            // SemVer 2.0.0 §2: numeric identifiers MUST NOT contain leading zeroes
            if i < len && bytes[i].is_ascii_digit() {
                return None;
            }
            vals[seg] = 0;
        } else {
            let mut val = (b0 - b'0') as u64;
            while i < len {
                let b = bytes[i];
                if !b.is_ascii_digit() {
                    break;
                }
                val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
                i += 1;
            }
            vals[seg] = val;
        }

        if seg < 2 {
            if i >= len || bytes[i] != b'.' {
                return None;
            }
            i += 1;
        }
        seg += 1;
    }

    Some((vals[0], vals[1], vals[2], i))
}

/// Single-pass prefix parser for loose `MAJOR[.MINOR[.PATCH]]` (allows leading zeroes).
#[inline]
fn parse_loose_prefix(bytes: &[u8]) -> Option<(u64, u64, u64, usize)> {
    let len = bytes.len();
    if len == 0 {
        return None;
    }

    let mut i = 0usize;
    let mut vals = [0u64; 3];
    let mut seg = 0usize;

    loop {
        if i >= len || !bytes[i].is_ascii_digit() {
            return None;
        }
        let mut val = (bytes[i] - b'0') as u64;
        i += 1;
        while i < len {
            let b = bytes[i];
            if !b.is_ascii_digit() {
                break;
            }
            val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
            i += 1;
        }
        vals[seg] = val;
        seg += 1;

        if seg < 3 && i < len && bytes[i] == b'.' {
            i += 1;
            continue;
        }
        break;
    }

    Some((vals[0], vals[1], vals[2], i))
}

#[inline]
fn parse_prerelease_list(
    pre_str: &str,
    full_tail: &str,
    orig_input: &str,
    loose: bool,
) -> Result<Vec<PrereleaseId>, SemverError> {
    if pre_str.is_empty() {
        return Err(SemverError::InvalidVersion(orig_input.to_string()));
    }
    let bytes = pre_str.as_bytes();
    let len = bytes.len();
    let mut pres = Vec::new();
    let mut start = 0usize;

    loop {
        let mut end = start;
        let mut all_digits = true;
        let mut num_val: u64 = 0;
        let mut num_ok = true;

        while end < len {
            let b = bytes[end];
            if b == b'.' {
                break;
            }
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                if full_tail.chars().any(char::is_whitespace) {
                    return Err(SemverError::InvalidVersion(orig_input.to_string()));
                }
                return Err(SemverError::InvalidPrerelease(pre_str.to_string()));
            }
            if all_digits {
                if b.is_ascii_digit() {
                    if num_ok {
                        match num_val
                            .checked_mul(10)
                            .and_then(|v| v.checked_add((b - b'0') as u64))
                        {
                            Some(v) => num_val = v,
                            None => num_ok = false,
                        }
                    }
                } else {
                    all_digits = false;
                }
            }
            end += 1;
        }

        let seg_len = end - start;
        if seg_len == 0 {
            if full_tail.chars().any(char::is_whitespace) {
                return Err(SemverError::InvalidVersion(orig_input.to_string()));
            }
            return Err(SemverError::InvalidPrerelease(pre_str.to_string()));
        }

        if all_digits {
            if !loose {
                if !num_ok || (seg_len > 1 && bytes[start] == b'0') {
                    if full_tail.chars().any(char::is_whitespace) {
                        return Err(SemverError::InvalidVersion(orig_input.to_string()));
                    }
                    return Err(SemverError::InvalidPrerelease(pre_str.to_string()));
                }
                pres.push(PrereleaseId::Numeric(num_val));
            } else if num_ok {
                pres.push(PrereleaseId::Numeric(num_val));
            } else {
                pres.push(PrereleaseId::Alpha(pre_str[start..end].to_string()));
            }
        } else {
            pres.push(PrereleaseId::Alpha(pre_str[start..end].to_string()));
        }

        if end == len {
            break;
        }
        start = end + 1;
    }

    Ok(pres)
}

#[inline]
fn parse_strict_build_list(b_str: &str, orig_input: &str) -> Result<Vec<String>, SemverError> {
    if b_str.is_empty() {
        return Err(SemverError::InvalidVersion(orig_input.to_string()));
    }
    let bytes = b_str.as_bytes();
    let len = bytes.len();
    let mut builds = Vec::new();
    let mut start = 0usize;

    loop {
        let mut end = start;
        while end < len && bytes[end] != b'.' {
            let b = bytes[end];
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                return Err(SemverError::InvalidVersion(orig_input.to_string()));
            }
            end += 1;
        }
        if end == start {
            return Err(SemverError::InvalidVersion(orig_input.to_string()));
        }
        builds.push(b_str[start..end].to_string());
        if end == len {
            break;
        }
        start = end + 1;
    }

    Ok(builds)
}

#[inline]
fn write_u64_rev(mut n: u64, buf: &mut [u8; 64], mut pos: usize) -> usize {
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return pos;
        }
    }
}

#[inline]
pub(crate) fn format_simple_version(
    major: u64,
    minor: u64,
    patch: u64,
    buf: &mut [u8; 64],
) -> &str {
    let mut pos = 64usize;
    pos = write_u64_rev(patch, buf, pos);
    pos -= 1;
    buf[pos] = b'.';
    pos = write_u64_rev(minor, buf, pos);
    pos -= 1;
    buf[pos] = b'.';
    pos = write_u64_rev(major, buf, pos);
    std::str::from_utf8(&buf[pos..]).unwrap_or("")
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
        let raw_bytes = input.as_bytes();
        let s = if !raw_bytes.is_empty()
            && raw_bytes[0].is_ascii_digit()
            && raw_bytes[raw_bytes.len() - 1] > b' '
            && raw_bytes[raw_bytes.len() - 1] < 0x80
        {
            input
        } else {
            let trimmed = input.trim();
            // Support leading '=' and/or 'v'/'V' prefix (e.g. '=1.2.3', 'v1.2.3', '=v1.2.3')
            let s = trimmed.strip_prefix('=').unwrap_or(trimmed);
            let s = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            s.trim()
        };

        let bytes = s.as_bytes();
        let Some((major, minor, patch, pos)) = parse_strict_triplet_prefix(bytes) else {
            return Err(SemverError::InvalidVersion(input.to_string()));
        };

        // Fast path: pure major.minor.patch with zero heap allocations (~95% common case)
        if pos == bytes.len() {
            return Ok(Self {
                major,
                minor,
                patch,
                prerelease: Vec::new(),
                build: Vec::new(),
            });
        }

        let tail = &s[pos..];
        match bytes[pos] {
            b'+' => {
                let build = parse_strict_build_list(&s[pos + 1..], input)?;
                Ok(Self {
                    major,
                    minor,
                    patch,
                    prerelease: Vec::new(),
                    build,
                })
            }
            b'-' => {
                let after_dash = &s[pos + 1..];
                let (pre_str, build) = if let Some(plus_rel) = after_dash.find('+') {
                    let b_str = &after_dash[plus_rel + 1..];
                    let build = parse_strict_build_list(b_str, input)?;
                    (&after_dash[..plus_rel], build)
                } else {
                    (after_dash, Vec::new())
                };
                let prerelease = parse_prerelease_list(pre_str, tail, input, false)?;
                Ok(Self {
                    major,
                    minor,
                    patch,
                    prerelease,
                    build,
                })
            }
            _ => Err(SemverError::InvalidVersion(input.to_string())),
        }
    }

    /// Loose version parsing supporting "v", "=", leading/trailing spaces,
    /// and partial versions like "1", "1.2" which default missing minor/patch to 0.
    pub fn parse_loose(input: &str) -> Result<Self, SemverError> {
        let raw_bytes = input.as_bytes();
        let s = if !raw_bytes.is_empty()
            && raw_bytes[0].is_ascii_digit()
            && raw_bytes[raw_bytes.len() - 1] > b' '
            && raw_bytes[raw_bytes.len() - 1] < 0x80
        {
            input
        } else {
            let trimmed = input.trim();
            // node-semver loose mode strips leading 'v', 'V', '=', and whitespace
            let s = trimmed.trim_start_matches(['v', 'V', '=', ' ']);
            s.trim()
        };

        let bytes = s.as_bytes();
        let Some((major, minor, patch, pos)) = parse_loose_prefix(bytes) else {
            return Err(SemverError::InvalidVersion(input.to_string()));
        };

        if pos == bytes.len() {
            return Ok(Self {
                major,
                minor,
                patch,
                prerelease: Vec::new(),
                build: Vec::new(),
            });
        }

        let tail = &s[pos..];
        match bytes[pos] {
            b'+' => {
                if tail.chars().any(char::is_whitespace) {
                    return Err(SemverError::InvalidVersion(input.to_string()));
                }
                let build: Vec<String> = s[pos + 1..].split('.').map(str::to_string).collect();
                Ok(Self {
                    major,
                    minor,
                    patch,
                    prerelease: Vec::new(),
                    build,
                })
            }
            b'-' => {
                let after_dash = &s[pos + 1..];
                let (pre_str, build) = if let Some(plus_rel) = after_dash.find('+') {
                    if tail.chars().any(char::is_whitespace) {
                        return Err(SemverError::InvalidVersion(input.to_string()));
                    }
                    let build: Vec<String> = after_dash[plus_rel + 1..]
                        .split('.')
                        .map(str::to_string)
                        .collect();
                    (&after_dash[..plus_rel], build)
                } else {
                    (after_dash, Vec::new())
                };
                let prerelease = parse_prerelease_list(pre_str, tail, input, true)?;
                Ok(Self {
                    major,
                    minor,
                    patch,
                    prerelease,
                    build,
                })
            }
            _ => Err(SemverError::InvalidVersion(input.to_string())),
        }
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

        // Compare prereleases: version without prerelease has higher precedence
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
        if self.prerelease.is_empty() && self.build.is_empty() {
            let mut buf = [0u8; 64];
            let s = format_simple_version(self.major, self.minor, self.patch, &mut buf);
            serializer.serialize_str(s)
        } else {
            serializer.serialize_str(&self.to_string())
        }
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
