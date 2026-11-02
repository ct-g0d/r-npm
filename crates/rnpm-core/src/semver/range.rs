use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::error::SemverError;
use super::comparator::{Comparator, Op};
use super::version::{PrereleaseId, Version};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparatorSet {
    pub comparators: Vec<Comparator>,
}

impl ComparatorSet {
    pub fn matches(&self, version: &Version) -> bool {
        // node-semver prerelease rule:
        // If a version has a prerelease tag, it will only satisfy a comparator set
        // if at least one comparator in the set has the same (major, minor, patch)
        // AND that comparator also has a prerelease tag.
        if version.is_prerelease() {
            let has_matching_prerelease_comparator = self.comparators.iter().any(|comp| {
                comp.version.is_prerelease()
                    && comp.version.major == version.major
                    && comp.version.minor == version.minor
                    && comp.version.patch == version.patch
            });
            if !has_matching_prerelease_comparator {
                return false;
            }
        }

        // All comparators in the set must match
        self.comparators.iter().all(|c| c.matches(version))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub raw: String,
    pub sets: Vec<ComparatorSet>,
}

impl Range {
    pub fn parse(input: &str) -> Result<Self, SemverError> {
        let trimmed = input.trim();
        let raw = trimmed.to_string();

        if trimmed.is_empty() || trimmed == "*" || trimmed == "x" || trimmed == "X" {
            // Matches any version >= 0.0.0
            return Ok(Self {
                raw,
                sets: vec![ComparatorSet {
                    comparators: vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))],
                }],
            });
        }

        // Sets are separated by '||'
        let or_parts: Vec<&str> = trimmed.split("||").collect();
        let mut sets = Vec::new();

        for or_part in or_parts {
            let set_str = or_part.trim();
            if set_str.is_empty() {
                continue;
            }

            let comparators = parse_comparator_set(set_str)?;
            sets.push(ComparatorSet { comparators });
        }

        if sets.is_empty() {
            return Err(SemverError::InvalidRange(input.to_string()));
        }

        Ok(Self { raw, sets })
    }

    pub fn satisfies(&self, version: &Version) -> bool {
        // Any set matching satisfies the range (OR)
        self.sets.iter().any(|set| set.matches(version))
    }
}

impl Version {
    pub fn satisfies(&self, range: &Range) -> bool {
        range.satisfies(self)
    }
}

/// Helper struct for partial versions in ranges (e.g. "1.x", "1.2", "~1", "^0.2.3")
#[derive(Debug, Clone)]
struct PartialVersion {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
    prerelease: Vec<PrereleaseId>,
}

fn is_wildcard(s: &str) -> bool {
    s == "*" || s.eq_ignore_ascii_case("x")
}

fn parse_partial_version(input: &str) -> Result<PartialVersion, SemverError> {
    let s = input.trim().trim_start_matches(|c| c == 'v' || c == 'V' || c == '=' || c == ' ');
    let s = s.trim();
    if s.is_empty() {
        return Err(SemverError::InvalidRange(input.to_string()));
    }
    if is_wildcard(s) {
        return Ok(PartialVersion {
            major: None,
            minor: None,
            patch: None,
            prerelease: Vec::new(),
        });
    }

    // Split off build metadata (ignored in range comparison)
    let s = if let Some(idx) = s.find('+') {
        &s[..idx]
    } else {
        s
    };

    // Split off prerelease
    let (ver_part, prerelease) = if let Some(idx) = s.find('-') {
        let p_str = &s[idx + 1..];
        if p_str.is_empty() {
            return Err(SemverError::InvalidRange(input.to_string()));
        }
        let mut pres = Vec::new();
        for part in p_str.split('.') {
            let part = part.trim();
            if part.is_empty() {
                return Err(SemverError::InvalidRange(input.to_string()));
            }
            if part.chars().all(|c| c.is_ascii_digit())
                && !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
            {
                if let Ok(n) = part.parse::<u64>() {
                    pres.push(PrereleaseId::Numeric(n));
                    continue;
                }
            }
            pres.push(PrereleaseId::Alpha(part.to_string()));
        }
        (&s[..idx], pres)
    } else {
        (s, Vec::new())
    };

    let parts: Vec<&str> = ver_part.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(SemverError::InvalidRange(input.to_string()));
    }

    let major = if is_wildcard(parts[0].trim()) {
        None
    } else {
        Some(parts[0].trim().parse::<u64>().map_err(|_| SemverError::InvalidRange(input.to_string()))?)
    };

    let minor = if parts.len() < 2 || is_wildcard(parts[1].trim()) {
        None
    } else {
        Some(parts[1].trim().parse::<u64>().map_err(|_| SemverError::InvalidRange(input.to_string()))?)
    };

    let patch = if parts.len() < 3 || is_wildcard(parts[2].trim()) {
        None
    } else {
        Some(parts[2].trim().parse::<u64>().map_err(|_| SemverError::InvalidRange(input.to_string()))?)
    };

    Ok(PartialVersion {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn make_version_with_pre(major: u64, minor: u64, patch: u64, pre: Vec<PrereleaseId>) -> Version {
    Version {
        major,
        minor,
        patch,
        prerelease: pre,
        build: Vec::new(),
    }
}

fn upper_bound_version(major: u64, minor: u64, patch: u64) -> Version {
    // node-semver uses <X.Y.Z-0 to exclude prereleases of the upper bound
    Version {
        major,
        minor,
        patch,
        prerelease: vec![PrereleaseId::Numeric(0)],
        build: Vec::new(),
    }
}

fn parse_comparator_set(input: &str) -> Result<Vec<Comparator>, SemverError> {
    // Check for hyphen range: e.g. "1.2.3 - 2.3.4"
    // Note: hyphen ranges have whitespace around '-'
    let tokens = tokenize_set(input);
    let mut comparators = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        if i + 2 < tokens.len() && tokens[i + 1] == "-" {
            // Hyphen range: token[i] - token[i+2]
            let from = parse_partial_version(&tokens[i])?;
            let to = parse_partial_version(&tokens[i + 2])?;

            // Lower bound: >= from
            let from_ver = make_version_with_pre(
                from.major.unwrap_or(0),
                from.minor.unwrap_or(0),
                from.patch.unwrap_or(0),
                from.prerelease,
            );
            comparators.push(Comparator::new(Op::Gte, from_ver));

            // Upper bound:
            // If `to.patch` is specified: <= to
            // If `to.minor` specified, no patch: < to.major.(to.minor + 1).0-0
            // If only `to.major` specified: < (to.major + 1).0.0-0
            if let Some(patch) = to.patch {
                let to_ver = make_version_with_pre(
                    to.major.unwrap_or(0),
                    to.minor.unwrap_or(0),
                    patch,
                    to.prerelease,
                );
                comparators.push(Comparator::new(Op::Lte, to_ver));
            } else if let Some(minor) = to.minor {
                let next_minor = minor
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                let to_ver = upper_bound_version(to.major.unwrap_or(0), next_minor, 0);
                comparators.push(Comparator::new(Op::Lt, to_ver));
            } else if let Some(major) = to.major {
                let next_major = major
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                let to_ver = upper_bound_version(next_major, 0, 0);
                comparators.push(Comparator::new(Op::Lt, to_ver));
            }

            i += 3;
            continue;
        }

        // Expand single token
        let token = &tokens[i];
        let expanded = expand_token(token)?;
        comparators.extend(expanded);
        i += 1;
    }

    if comparators.is_empty() {
        comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
    }

    Ok(comparators)
}

fn tokenize_set(input: &str) -> Vec<String> {
    let raw_parts: Vec<&str> = input.split_whitespace().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < raw_parts.len() {
        let part = raw_parts[i];

        // Check if part is a prefix operator or combination
        let mut op = String::new();
        let mut consumed = 0;

        if (part == ">" || part == "<") && i + 1 < raw_parts.len() && raw_parts[i + 1] == "=" {
            op = format!("{}=", part);
            consumed = 2;
        } else if part == "~" && i + 1 < raw_parts.len() && raw_parts[i + 1] == ">" {
            op = "~>".to_string();
            consumed = 2;
        } else if part == ">="
            || part == "<="
            || part == ">"
            || part == "<"
            || part == "="
            || part == "~"
            || part == "^"
            || part == "~>"
            || part == "v"
            || part == "V"
        {
            op = part.to_string();
            consumed = 1;
        }

        if !op.is_empty() {
            // Check if there is a next part that is NOT a hyphen range separator
            if i + consumed < raw_parts.len() && raw_parts[i + consumed] != "-" {
                let next_part = raw_parts[i + consumed];
                tokens.push(format!("{}{}", op, next_part));
                i += consumed + 1;
                continue;
            } else {
                tokens.push(op);
                i += consumed;
                continue;
            }
        }

        // Not a prefix operator, push as-is
        tokens.push(part.to_string());
        i += 1;
    }
    tokens
}

fn expand_token(input: &str) -> Result<Vec<Comparator>, SemverError> {
    let t = input.trim();
    if t.is_empty() {
        return Err(SemverError::InvalidRange(format!("Standalone operator without version or wildcard: {input}")));
    }
    if is_wildcard(t) {
        return Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))]);
    }

    // Caret ranges: ^1.2.3
    if let Some(rest) = t.strip_prefix('^') {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(SemverError::InvalidRange(format!("Standalone operator without version or wildcard: {input}")));
        }
        let p = parse_partial_version(rest)?;
        let major = p.major.unwrap_or(0);
        let minor = p.minor.unwrap_or(0);
        let patch = p.patch.unwrap_or(0);

        let lower = make_version_with_pre(major, minor, patch, p.prerelease);

        // Calculate upper bound per node-semver:
        let upper = if p.major.is_none() {
            // ^* -> >=0.0.0
            return Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))]);
        } else if major > 0 {
            // ^1.2.3 -> <2.0.0-0
            let next_major = major
                .checked_add(1)
                .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
            upper_bound_version(next_major, 0, 0)
        } else if p.minor.is_none() {
            // ^0.x -> <1.0.0-0
            upper_bound_version(1, 0, 0)
        } else if minor > 0 {
            // ^0.2.3 -> <0.3.0-0
            let next_minor = minor
                .checked_add(1)
                .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
            upper_bound_version(0, next_minor, 0)
        } else if p.patch.is_none() {
            // ^0.0.x -> <0.1.0-0
            upper_bound_version(0, 1, 0)
        } else {
            // ^0.0.3 -> <0.0.4-0
            let next_patch = patch
                .checked_add(1)
                .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
            upper_bound_version(0, 0, next_patch)
        };

        return Ok(vec![
            Comparator::new(Op::Gte, lower),
            Comparator::new(Op::Lt, upper),
        ]);
    }

    // Tilde ranges: ~1.2.3, ~>1.2.3
    let t_stripped = if let Some(r) = t.strip_prefix("~>") {
        Some(r)
    } else {
        t.strip_prefix('~')
    };
    if let Some(rest) = t_stripped {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(SemverError::InvalidRange(format!("Standalone operator without version or wildcard: {input}")));
        }
        let p = parse_partial_version(rest)?;
        let major = p.major.unwrap_or(0);
        let minor = p.minor.unwrap_or(0);
        let patch = p.patch.unwrap_or(0);

        let lower = make_version_with_pre(major, minor, patch, p.prerelease);

        let upper = if p.major.is_none() {
            return Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))]);
        } else if p.minor.is_none() {
            // ~1 -> <2.0.0-0
            let next_major = major
                .checked_add(1)
                .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
            upper_bound_version(next_major, 0, 0)
        } else {
            // ~1.2 or ~1.2.3 -> <1.3.0-0
            let next_minor = minor
                .checked_add(1)
                .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
            upper_bound_version(major, next_minor, 0)
        };

        return Ok(vec![
            Comparator::new(Op::Gte, lower),
            Comparator::new(Op::Lt, upper),
        ]);
    }

    // Check operators: >=, <=, >, <, =
    let (op_opt, rest) = if let Some(r) = t.strip_prefix(">=") {
        (Some(Op::Gte), r)
    } else if let Some(r) = t.strip_prefix("<=") {
        (Some(Op::Lte), r)
    } else if let Some(r) = t.strip_prefix('>') {
        (Some(Op::Gt), r)
    } else if let Some(r) = t.strip_prefix('<') {
        (Some(Op::Lt), r)
    } else if let Some(r) = t.strip_prefix('=') {
        (Some(Op::Eq), r)
    } else {
        (None, t)
    };

    let rest = rest.trim();
    if op_opt.is_some() && rest.is_empty() {
        return Err(SemverError::InvalidRange(format!("Standalone operator without version: {input}")));
    }

    let p = parse_partial_version(rest)?;

    match op_opt {
        None => {
            // Bare partial version: e.g. "1.2.3", "1.2", "1"
            if p.major.is_none() {
                // "*"
                Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))])
            } else if p.minor.is_none() {
                // "1" -> >=1.0.0 <2.0.0-0
                let major = p.major.unwrap();
                let next_major = major
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![
                    Comparator::new(Op::Gte, Version::new(major, 0, 0)),
                    Comparator::new(Op::Lt, upper_bound_version(next_major, 0, 0)),
                ])
            } else if p.patch.is_none() {
                // "1.2" -> >=1.2.0 <1.3.0-0
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![
                    Comparator::new(Op::Gte, Version::new(major, minor, 0)),
                    Comparator::new(Op::Lt, upper_bound_version(major, next_minor, 0)),
                ])
            } else {
                // Exact version
                let v = make_version_with_pre(p.major.unwrap(), p.minor.unwrap(), p.patch.unwrap(), p.prerelease);
                Ok(vec![Comparator::new(Op::Eq, v)])
            }
        }
        Some(Op::Eq) => {
            // "=1.2.3" or "=1.2" or "=*"
            if p.major.is_none() {
                Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))])
            } else if p.minor.is_none() {
                let major = p.major.unwrap();
                let next_major = major
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![
                    Comparator::new(Op::Gte, Version::new(major, 0, 0)),
                    Comparator::new(Op::Lt, upper_bound_version(next_major, 0, 0)),
                ])
            } else if p.patch.is_none() {
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![
                    Comparator::new(Op::Gte, Version::new(major, minor, 0)),
                    Comparator::new(Op::Lt, upper_bound_version(major, next_minor, 0)),
                ])
            } else {
                let v = make_version_with_pre(p.major.unwrap(), p.minor.unwrap(), p.patch.unwrap(), p.prerelease);
                Ok(vec![Comparator::new(Op::Eq, v)])
            }
        }
        Some(Op::Gte) => {
            let v = make_version_with_pre(
                p.major.unwrap_or(0),
                p.minor.unwrap_or(0),
                p.patch.unwrap_or(0),
                p.prerelease,
            );
            Ok(vec![Comparator::new(Op::Gte, v)])
        }
        Some(Op::Gt) => {
            if p.minor.is_none() {
                // >1.x -> >=2.0.0
                let major = p.major.unwrap_or(0);
                let next_major = major
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![Comparator::new(Op::Gte, Version::new(next_major, 0, 0))])
            } else if p.patch.is_none() {
                // >1.2.x -> >=1.3.0
                let major = p.major.unwrap_or(0);
                let minor = p.minor.unwrap();
                let next_minor = minor
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![Comparator::new(Op::Gte, Version::new(major, next_minor, 0))])
            } else {
                let v = make_version_with_pre(p.major.unwrap_or(0), p.minor.unwrap(), p.patch.unwrap(), p.prerelease);
                Ok(vec![Comparator::new(Op::Gt, v)])
            }
        }
        Some(Op::Lt) => {
            if p.minor.is_none() {
                // <1.x -> <1.0.0-0
                let major = p.major.unwrap_or(0);
                Ok(vec![Comparator::new(Op::Lt, upper_bound_version(major, 0, 0))])
            } else if p.patch.is_none() {
                // <1.2.x -> <1.2.0-0
                let major = p.major.unwrap_or(0);
                let minor = p.minor.unwrap();
                Ok(vec![Comparator::new(Op::Lt, upper_bound_version(major, minor, 0))])
            } else {
                let v = make_version_with_pre(p.major.unwrap_or(0), p.minor.unwrap(), p.patch.unwrap(), p.prerelease);
                Ok(vec![Comparator::new(Op::Lt, v)])
            }
        }
        Some(Op::Lte) => {
            if p.major.is_none() {
                Ok(vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))])
            } else if p.minor.is_none() {
                // <=1.x -> <2.0.0-0
                let major = p.major.unwrap();
                let next_major = major
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![Comparator::new(Op::Lt, upper_bound_version(next_major, 0, 0))])
            } else if p.patch.is_none() {
                // <=1.2.x -> <1.3.0-0
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor
                    .checked_add(1)
                    .ok_or_else(|| SemverError::InvalidRange(format!("Version number overflow: {input}")))?;
                Ok(vec![Comparator::new(Op::Lt, upper_bound_version(major, next_minor, 0))])
            } else {
                let v = make_version_with_pre(p.major.unwrap(), p.minor.unwrap(), p.patch.unwrap(), p.prerelease);
                Ok(vec![Comparator::new(Op::Lte, v)])
            }
        }
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl FromStr for Range {
    type Err = SemverError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Range {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Range::parse(&s).map_err(serde::de::Error::custom)
    }
}
