use super::comparator::{Comparator, Op};
use super::version::{PrereleaseId, Version};
use crate::error::SemverError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparatorSet {
    pub comparators: Vec<Comparator>,
}

impl ComparatorSet {
    #[inline]
    pub fn matches(&self, version: &Version) -> bool {
        let all_match = match self.comparators.as_slice() {
            [c] => c.matches(version),
            [c1, c2] => c1.matches(version) && c2.matches(version),
            comps => comps.iter().all(|c| c.matches(version)),
        };
        if !all_match {
            return false;
        }

        // node-semver prerelease rule:
        // If a version has a prerelease tag, it will only satisfy a comparator set
        // if at least one comparator in the set has the same (major, minor, patch)
        // AND that comparator also has a prerelease tag.
        if version.is_prerelease() {
            return self.comparators.iter().any(|comp| {
                comp.version.is_prerelease()
                    && comp.version.major == version.major
                    && comp.version.minor == version.minor
                    && comp.version.patch == version.patch
            });
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub raw: String,
    pub sets: Vec<ComparatorSet>,
}

#[inline]
fn is_wildcard_comp(comp: &Comparator) -> bool {
    comp.op == Op::Gte
        && comp.version.major == 0
        && comp.version.minor == 0
        && comp.version.patch == 0
        && comp.version.prerelease.is_empty()
}

#[derive(Clone, Copy)]
pub(crate) struct StackComparator {
    pub op: Op,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub is_upper_pre0: bool,
}

impl StackComparator {
    #[inline]
    pub const fn new(op: Op, major: u64, minor: u64, patch: u64, is_upper_pre0: bool) -> Self {
        Self {
            op,
            major,
            minor,
            patch,
            is_upper_pre0,
        }
    }

    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.op == Op::Gte
            && self.major == 0
            && self.minor == 0
            && self.patch == 0
            && !self.is_upper_pre0
    }
}

#[inline]
fn expand_fast_partial_bounds(op: FastOp, p: FastPartial) -> Option<([StackComparator; 2], usize)> {
    let major = p.major.unwrap_or(0);
    let minor = p.minor.unwrap_or(0);
    let patch = p.patch.unwrap_or(0);
    let zero = StackComparator::new(Op::Gte, 0, 0, 0, false);
    let lt0 = StackComparator::new(Op::Lt, 0, 0, 0, true);

    match op {
        FastOp::Caret => {
            if p.major.is_none() {
                return Some(([zero, zero], 1));
            }
            let upper = if major > 0 {
                (major.checked_add(1)?, 0, 0)
            } else if p.minor.is_none() {
                (1, 0, 0)
            } else if minor > 0 {
                (0, minor.checked_add(1)?, 0)
            } else if p.patch.is_none() {
                (0, 1, 0)
            } else {
                (0, 0, patch.checked_add(1)?)
            };
            Some((
                [
                    StackComparator::new(Op::Gte, major, minor, patch, false),
                    StackComparator::new(Op::Lt, upper.0, upper.1, upper.2, true),
                ],
                2,
            ))
        }
        FastOp::Tilde => {
            if p.major.is_none() {
                return Some(([zero, zero], 1));
            }
            let upper = if p.minor.is_none() {
                (major.checked_add(1)?, 0, 0)
            } else {
                (major, minor.checked_add(1)?, 0)
            };
            Some((
                [
                    StackComparator::new(Op::Gte, major, minor, patch, false),
                    StackComparator::new(Op::Lt, upper.0, upper.1, upper.2, true),
                ],
                2,
            ))
        }
        FastOp::Exact => {
            if p.major.is_none() {
                Some(([zero, zero], 1))
            } else if p.minor.is_none() {
                let next_major = major.checked_add(1)?;
                Some((
                    [
                        StackComparator::new(Op::Gte, major, 0, 0, false),
                        StackComparator::new(Op::Lt, next_major, 0, 0, true),
                    ],
                    2,
                ))
            } else if p.patch.is_none() {
                let next_minor = minor.checked_add(1)?;
                Some((
                    [
                        StackComparator::new(Op::Gte, major, minor, 0, false),
                        StackComparator::new(Op::Lt, major, next_minor, 0, true),
                    ],
                    2,
                ))
            } else {
                Some(([StackComparator::new(Op::Eq, major, minor, patch, false), zero], 1))
            }
        }
        FastOp::Gte => Some(([StackComparator::new(Op::Gte, major, minor, patch, false), zero], 1)),
        FastOp::Gt => {
            let c = if p.major.is_none() {
                lt0
            } else if p.minor.is_none() {
                StackComparator::new(Op::Gte, major.checked_add(1)?, 0, 0, false)
            } else if p.patch.is_none() {
                StackComparator::new(Op::Gte, major, minor.checked_add(1)?, 0, false)
            } else {
                StackComparator::new(Op::Gt, major, minor, patch, false)
            };
            Some(([c, zero], 1))
        }
        FastOp::Lt => {
            let c = if p.major.is_none() {
                lt0
            } else if p.minor.is_none() {
                StackComparator::new(Op::Lt, major, 0, 0, true)
            } else if p.patch.is_none() {
                StackComparator::new(Op::Lt, major, minor, 0, true)
            } else {
                StackComparator::new(Op::Lt, major, minor, patch, false)
            };
            Some(([c, zero], 1))
        }
        FastOp::Lte => {
            let c = if p.major.is_none() {
                zero
            } else if p.minor.is_none() {
                StackComparator::new(Op::Lt, major.checked_add(1)?, 0, 0, true)
            } else if p.patch.is_none() {
                StackComparator::new(Op::Lt, major, minor.checked_add(1)?, 0, true)
            } else {
                StackComparator::new(Op::Lte, major, minor, patch, false)
            };
            Some(([c, zero], 1))
        }
    }
}

#[inline]
fn push_stack_comp(
    out: &mut [StackComparator; 4],
    len: &mut usize,
    c: StackComparator,
) -> Option<()> {
    if *len >= out.len() {
        return None;
    }
    out[*len] = c;
    *len += 1;
    Some(())
}

#[inline]
fn push_fast_partial_stack(
    op: FastOp,
    p: FastPartial,
    out: &mut [StackComparator; 4],
    len: &mut usize,
) -> Option<()> {
    let (bounds, count) = expand_fast_partial_bounds(op, p)?;
    for c in &bounds[..count] {
        push_stack_comp(out, len, *c)?;
    }
    Some(())
}

/// Zero-alloc fast stack parser for single-set non-prerelease range expressions (`<= 4` comparators).
pub(crate) fn try_parse_fast_set_stack(s: &str, out: &mut [StackComparator; 4]) -> Option<usize> {
    let trimmed = s.trim();
    let mut len = 0usize;
    if trimmed.is_empty() || trimmed == "*" || trimmed == "x" || trimmed == "X" {
        out[0] = StackComparator::new(Op::Gte, 0, 0, 0, false);
        return Some(1);
    }

    let (op, rest) = split_fast_op_prefix(trimmed);
    if let Some(p) = parse_fast_partial_token(rest) {
        push_fast_partial_stack(op, p, out, &mut len)?;
        return Some(len);
    }

    if trimmed.contains("||") {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    if matches!(first, ">=" | "<=" | ">" | "<" | "=" | "~" | "^" | "~>") {
        return None;
    }

    let p1 = parts.next();
    if p1 == Some("-") {
        let to_str = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let from_p = parse_fast_partial_token(first.strip_prefix('=').unwrap_or(first))?;
        let to_p = parse_fast_partial_token(to_str.strip_prefix('=').unwrap_or(to_str))?;
        if let Some(fm) = from_p.major {
            push_stack_comp(
                out,
                &mut len,
                StackComparator::new(
                    Op::Gte,
                    fm,
                    from_p.minor.unwrap_or(0),
                    from_p.patch.unwrap_or(0),
                    false,
                ),
            )?;
        }
        if let Some(tp) = to_p.patch {
            push_stack_comp(
                out,
                &mut len,
                StackComparator::new(
                    Op::Lte,
                    to_p.major.unwrap_or(0),
                    to_p.minor.unwrap_or(0),
                    tp,
                    false,
                ),
            )?;
        } else if let Some(tm) = to_p.minor {
            push_stack_comp(
                out,
                &mut len,
                StackComparator::new(
                    Op::Lt,
                    to_p.major.unwrap_or(0),
                    tm.checked_add(1)?,
                    0,
                    true,
                ),
            )?;
        } else if let Some(tmaj) = to_p.major {
            push_stack_comp(
                out,
                &mut len,
                StackComparator::new(Op::Lt, tmaj.checked_add(1)?, 0, 0, true),
            )?;
        }
        if len == 0 {
            out[0] = StackComparator::new(Op::Gte, 0, 0, 0, false);
            len = 1;
        }
        return Some(len);
    }

    let (op0, rest0) = split_fast_op_prefix(first);
    push_fast_partial_stack(op0, parse_fast_partial_token(rest0)?, out, &mut len)?;
    if let Some(tok) = p1 {
        let (op_k, rest_k) = split_fast_op_prefix(tok);
        push_fast_partial_stack(op_k, parse_fast_partial_token(rest_k)?, out, &mut len)?;
    }
    for tok in parts {
        if tok == "-" {
            return None;
        }
        let (op_k, rest_k) = split_fast_op_prefix(tok);
        push_fast_partial_stack(op_k, parse_fast_partial_token(rest_k)?, out, &mut len)?;
    }

    Some(len)
}

#[derive(Clone, Copy)]
enum FastOp {
    Exact,
    Caret,
    Tilde,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Copy)]
struct FastPartial {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
}

/// Zero-alloc single-pass parser for a partial dotted token (no `+`, `-`, or whitespace).
/// Supports wildcards `*`, `x`, `X` and strict numeric segments.
#[inline]
fn parse_fast_partial_token(s: &str) -> Option<FastPartial> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    while i < len && matches!(bytes[i], b'v' | b'V' | b'=') {
        i += 1;
    }
    if i >= len {
        return None;
    }

    let mut segs: [Option<u64>; 3] = [None; 3];
    let mut count = 0usize;

    loop {
        if count >= 3 || i >= len {
            return None;
        }
        let b0 = bytes[i];
        if b0 == b'*' || b0 == b'x' || b0 == b'X' {
            i += 1;
            segs[count] = None;
        } else if b0.is_ascii_digit() {
            i += 1;
            if b0 == b'0' {
                if i < len && bytes[i].is_ascii_digit() {
                    return None;
                }
                segs[count] = Some(0);
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
                segs[count] = Some(val);
            }
        } else {
            return None;
        }

        count += 1;
        if i == len {
            break;
        }
        if bytes[i] != b'.' {
            return None;
        }
        i += 1;
        if i == len {
            return None; // trailing dot
        }
    }

    Some(FastPartial {
        major: segs[0],
        minor: segs[1],
        patch: segs[2],
    })
}

#[inline]
fn split_fast_op_prefix(s: &str) -> (FastOp, &str) {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return (FastOp::Exact, s);
    }
    match bytes[0] {
        b'^' => (FastOp::Caret, &s[1..]),
        b'~' => {
            if bytes.len() > 1 && bytes[1] == b'>' {
                (FastOp::Tilde, &s[2..])
            } else {
                (FastOp::Tilde, &s[1..])
            }
        }
        b'>' => {
            if bytes.len() > 1 && bytes[1] == b'=' {
                (FastOp::Gte, &s[2..])
            } else {
                (FastOp::Gt, &s[1..])
            }
        }
        b'<' => {
            if bytes.len() > 1 && bytes[1] == b'=' {
                (FastOp::Lte, &s[2..])
            } else {
                (FastOp::Lt, &s[1..])
            }
        }
        b'=' => (FastOp::Exact, &s[1..]),
        _ => (FastOp::Exact, s),
    }
}

#[inline]
fn stack_to_comparator(c: &StackComparator) -> Comparator {
    let ver = if c.is_upper_pre0 {
        upper_bound_version(c.major, c.minor, c.patch)
    } else {
        Version::new(c.major, c.minor, c.patch)
    };
    Comparator::new(c.op, ver)
}

#[inline]
fn push_fast_partial_comparators(
    op: FastOp,
    p: FastPartial,
    input_for_err: &str,
    out: &mut Vec<Comparator>,
) -> Result<(), SemverError> {
    let (bounds, count) = expand_fast_partial_bounds(op, p).ok_or_else(|| {
        SemverError::InvalidRange(format!("Version number overflow: {input_for_err}"))
    })?;
    for c in &bounds[..count] {
        out.push(stack_to_comparator(c));
    }
    Ok(())
}

/// Evaluates a fast partial comparator directly against a release (non-prerelease) `Version`
/// without heap allocations. Returns `Err` on integer overflow just like `Range::parse`.
#[inline]
fn eval_fast_partial_on_release(
    op: FastOp,
    p: FastPartial,
    v: (u64, u64, u64),
    input_for_err: &str,
) -> Result<bool, SemverError> {
    let (bounds, count) = expand_fast_partial_bounds(op, p).ok_or_else(|| {
        SemverError::InvalidRange(format!("Version number overflow: {input_for_err}"))
    })?;
    Ok(bounds[..count].iter().all(|c| {
        let bv = (c.major, c.minor, c.patch);
        match c.op {
            Op::Eq => v == bv,
            Op::Gt => v > bv,
            Op::Gte => v >= bv,
            // Release versions have no prerelease, so `< X.Y.Z-0` and `< X.Y.Z` are both `v < (X, Y, Z)`.
            Op::Lt => v < bv,
            Op::Lte => v <= bv,
        }
    }))
}

/// Fast path for a single comparator token without whitespace or prerelease/build tags.
#[inline]
fn try_fast_comparator_set(
    s: &str,
    input_for_err: &str,
) -> Option<Result<ComparatorSet, SemverError>> {
    if s.is_empty() || s == "*" || s == "x" || s == "X" {
        return Some(Ok(ComparatorSet {
            comparators: vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))],
        }));
    }

    let (op, rest) = split_fast_op_prefix(s);
    let partial = parse_fast_partial_token(rest)?;
    let mut comparators = Vec::with_capacity(2);
    if let Err(e) = push_fast_partial_comparators(op, partial, input_for_err, &mut comparators) {
        return Some(Err(e));
    }
    Some(Ok(ComparatorSet { comparators }))
}

impl Range {
    pub fn parse(input: &str) -> Result<Self, SemverError> {
        let trimmed = input.trim();

        if trimmed.len() > 65536 {
            return Err(SemverError::InvalidRange(
                "Range string exceeds maximum length".to_string(),
            ));
        }

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

        // Fast path: single simple expression (rejects whitespace, '||', '-', '+' inside token)
        if let Some(res) = try_fast_comparator_set(trimmed, input) {
            let set = res?;
            return Ok(Self {
                raw,
                sets: vec![set],
            });
        }

        // Split on '||' without extra contains scans
        let Some((first_or, rest_or)) = trimmed.split_once("||") else {
            let comparators = parse_comparator_set(trimmed)?;
            return Ok(Self {
                raw,
                sets: vec![ComparatorSet { comparators }],
            });
        };

        let mut sets = Vec::with_capacity(2);
        let mut has_wildcard_set = false;

        for or_part in std::iter::once(first_or).chain(rest_or.split("||")) {
            let set_str = or_part.trim();
            if set_str.is_empty() {
                // In node-semver, an empty set in an || union represents a wildcard >=0.0.0
                sets.push(ComparatorSet {
                    comparators: vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))],
                });
                has_wildcard_set = true;
                continue;
            }

            if let Some(res) = try_fast_comparator_set(set_str, input) {
                let set = res?;
                if set.comparators.len() == 1 && is_wildcard_comp(&set.comparators[0]) {
                    has_wildcard_set = true;
                }
                sets.push(set);
                continue;
            }

            let comparators = parse_comparator_set(set_str)?;
            if comparators.len() == 1 && is_wildcard_comp(&comparators[0]) {
                has_wildcard_set = true;
            }
            sets.push(ComparatorSet { comparators });
        }

        // If any set in the || union is a wildcard (>=0.0.0), node-semver collapses to a single wildcard set
        if has_wildcard_set && sets.len() > 1 {
            sets = vec![ComparatorSet {
                comparators: vec![Comparator::new(Op::Gte, Version::new(0, 0, 0))],
            }];
        }

        Ok(Self { raw, sets })
    }

    /// Zero-allocation fast evaluation of `range_str` against `version`.
    /// Falls back to full `Range::parse` only for prerelease versions or non-simple syntax.
    #[inline]
    pub fn satisfies_str(range_str: &str, version: &Version) -> Result<bool, SemverError> {
        let trimmed = range_str.trim();
        if trimmed.len() > 65536 {
            return Err(SemverError::InvalidRange(
                "Range string exceeds maximum length".to_string(),
            ));
        }

        if !version.prerelease.is_empty() {
            return Self::parse(range_str).map(|r| r.satisfies(version));
        }

        let v = (version.major, version.minor, version.patch);
        if trimmed.is_empty() || trimmed == "*" || trimmed == "x" || trimmed == "X" {
            return Ok(true);
        }

        if let Some(matched) = try_eval_fast_set(trimmed, v, range_str) {
            return matched;
        }

        if let Some((first_or, rest_or)) = trimmed.split_once("||") {
            let mut matched = false;
            for or_part in std::iter::once(first_or).chain(rest_or.split("||")) {
                let set_str = or_part.trim();
                if set_str.is_empty() {
                    matched = true;
                    continue;
                }
                match try_eval_fast_set(set_str, v, range_str) {
                    Some(Ok(m)) => {
                        if m {
                            matched = true;
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Self::parse(range_str).map(|r| r.satisfies(version)),
                }
            }
            return Ok(matched);
        }

        Self::parse(range_str).map(|r| r.satisfies(version))
    }

    /// Checks if this range normalizes to node-semver's ANY wildcard (`*`, `""`, `x`, `*.*`, `>=0.0.0`, etc.).
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.sets.len() == 1
            && self.sets[0].comparators.len() == 1
            && is_wildcard_comp(&self.sets[0].comparators[0])
    }

    #[inline]
    pub fn satisfies(&self, version: &Version) -> bool {
        match self.sets.as_slice() {
            [s] => s.matches(version),
            sets => sets.iter().any(|set| set.matches(version)),
        }
    }
}

/// Evaluates a single comparator set (no `||`) against a release version without allocations.
#[inline]
fn try_eval_fast_set(
    set_str: &str,
    v: (u64, u64, u64),
    input_for_err: &str,
) -> Option<Result<bool, SemverError>> {
    if set_str == "*" || set_str == "x" || set_str == "X" {
        return Some(Ok(true));
    }

    // Single token fast path (no whitespace)
    let (op, rest) = split_fast_op_prefix(set_str);
    if let Some(p) = parse_fast_partial_token(rest) {
        return Some(eval_fast_partial_on_release(op, p, v, input_for_err));
    }

    // Space-separated simple comparators or simple hyphen range: iterate without Vec
    let mut parts = set_str.split_whitespace();
    let first = parts.next()?;
    if matches!(
        first,
        ">=" | "<=" | ">" | "<" | "=" | "~" | "^" | "~>"
    ) {
        return None;
    }

    let p1 = parts.next();
    if p1 == Some("-") {
        // Hyphen range: `from - to`
        let to_str = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let from_s = first.strip_prefix('=').unwrap_or(first);
        let to_s = to_str.strip_prefix('=').unwrap_or(to_str);
        let from_p = parse_fast_partial_token(from_s)?;
        let to_p = parse_fast_partial_token(to_s)?;

        let mut ok = true;
        if let Some(fm) = from_p.major {
            ok &= v >= (fm, from_p.minor.unwrap_or(0), from_p.patch.unwrap_or(0));
        }
        if let Some(tp) = to_p.patch {
            ok &= v <= (to_p.major.unwrap_or(0), to_p.minor.unwrap_or(0), tp);
        } else if let Some(tm) = to_p.minor {
            let next_minor = match tm.checked_add(1) {
                Some(n) => n,
                None => {
                    return Some(Err(SemverError::InvalidRange(format!(
                        "Version number overflow: {input_for_err}"
                    ))));
                }
            };
            ok &= v < (to_p.major.unwrap_or(0), next_minor, 0);
        } else if let Some(tmaj) = to_p.major {
            let next_major = match tmaj.checked_add(1) {
                Some(n) => n,
                None => {
                    return Some(Err(SemverError::InvalidRange(format!(
                        "Version number overflow: {input_for_err}"
                    ))));
                }
            };
            ok &= v < (next_major, 0, 0);
        }
        return Some(Ok(ok));
    }

    // Multi-comparator AND sequence without hyphen ranges or standalone operators
    let (op0, rest0) = split_fast_op_prefix(first);
    let fp0 = parse_fast_partial_token(rest0)?;
    let mut all_ok = match eval_fast_partial_on_release(op0, fp0, v, input_for_err) {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };

    if let Some(tok) = p1 {
        let (op_k, rest_k) = split_fast_op_prefix(tok);
        let fp_k = parse_fast_partial_token(rest_k)?;
        match eval_fast_partial_on_release(op_k, fp_k, v, input_for_err) {
            Ok(m) => all_ok &= m,
            Err(e) => return Some(Err(e)),
        }
    }

    for tok in parts {
        if tok == "-" {
            return None;
        }
        let (op_k, rest_k) = split_fast_op_prefix(tok);
        let fp_k = parse_fast_partial_token(rest_k)?;
        match eval_fast_partial_on_release(op_k, fp_k, v, input_for_err) {
            Ok(m) => all_ok &= m,
            Err(e) => return Some(Err(e)),
        }
    }

    Some(Ok(all_ok))
}

impl Version {
    #[inline]
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

#[inline]
fn is_wildcard(s: &str) -> bool {
    s == "*" || s.eq_ignore_ascii_case("x")
}

fn parse_partial_version(input: &str) -> Result<PartialVersion, SemverError> {
    let s = input.trim().trim_start_matches(['v', 'V', '=', ' ']);
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

    // Split off build metadata (ignored in range comparison, but validated)
    let s = if let Some(idx) = s.find('+') {
        let b_str = &s[idx + 1..];
        if b_str.is_empty() {
            return Err(SemverError::InvalidRange(input.to_string()));
        }
        for part in b_str.split('.') {
            let part = part.trim();
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(SemverError::InvalidRange(input.to_string()));
            }
        }
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
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(SemverError::InvalidRange(input.to_string()));
            }
            if part.chars().all(|c| c.is_ascii_digit()) {
                if part.len() > 1 && part.starts_with('0') {
                    return Err(SemverError::InvalidRange(input.to_string()));
                }
                let n = part
                    .parse::<u64>()
                    .map_err(|_| SemverError::InvalidRange(input.to_string()))?;
                pres.push(PrereleaseId::Numeric(n));
            } else {
                pres.push(PrereleaseId::Alpha(part.to_string()));
            }
        }
        (&s[..idx], pres)
    } else {
        (s, Vec::new())
    };

    let mut parts_iter = ver_part.split('.');
    let p0 = parts_iter.next();
    let p1 = parts_iter.next();
    let p2 = parts_iter.next();
    if parts_iter.next().is_some() {
        return Err(SemverError::InvalidRange(input.to_string()));
    }
    let p0 = match p0 {
        Some(p) => p,
        None => return Err(SemverError::InvalidRange(input.to_string())),
    };
    let parts_count = 1 + (p1.is_some() as usize) + (p2.is_some() as usize);

    // SemVer 2.0.0 / node-semver rule:
    // Prereleases on partial versions (e.g. 1.2-alpha, ^1.2-alpha, 1.x-alpha) are invalid ranges
    if !prerelease.is_empty()
        && (parts_count < 3
            || is_wildcard(p0.trim())
            || p1.is_some_and(|p| is_wildcard(p.trim()))
            || p2.is_some_and(|p| is_wildcard(p.trim())))
    {
        return Err(SemverError::InvalidRange(input.to_string()));
    }

    let parse_segment = |part: &str| -> Result<Option<u64>, SemverError> {
        let p = part.trim();
        if is_wildcard(p) {
            return Ok(None);
        }
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return Err(SemverError::InvalidRange(input.to_string()));
        }
        if p.len() > 1 && p.starts_with('0') {
            return Err(SemverError::InvalidRange(input.to_string()));
        }
        p.parse::<u64>()
            .map(Some)
            .map_err(|_| SemverError::InvalidRange(input.to_string()))
    };

    let major = parse_segment(p0)?;
    let minor = match p1 {
        Some(p) => parse_segment(p)?,
        None => None,
    };
    let patch = match p2 {
        Some(p) => parse_segment(p)?,
        None => None,
    };

    Ok(PartialVersion {
        major,
        minor,
        patch,
        prerelease,
    })
}

#[inline]
fn make_version_with_pre(major: u64, minor: u64, patch: u64, pre: Vec<PrereleaseId>) -> Version {
    Version {
        major,
        minor,
        patch,
        prerelease: pre,
        build: Vec::new(),
    }
}

#[inline]
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

enum SetToken<'a> {
    Merged(&'static str, &'a str),
    Raw(&'a str),
}

struct TokenStream<'a> {
    iter: std::str::SplitWhitespace<'a>,
    raw_buf: [Option<&'a str>; 2],
    tok_buf: [Option<SetToken<'a>>; 2],
}

impl<'a> TokenStream<'a> {
    #[inline]
    fn new(input: &'a str) -> Self {
        Self {
            iter: input.split_whitespace(),
            raw_buf: [None, None],
            tok_buf: [None, None],
        }
    }

    #[inline]
    fn raw_next(&mut self) -> Option<&'a str> {
        if let Some(s) = self.raw_buf[0].take() {
            self.raw_buf[0] = self.raw_buf[1].take();
            Some(s)
        } else {
            self.iter.next()
        }
    }

    #[inline]
    fn raw_peek(&mut self, idx: usize) -> Option<&'a str> {
        if idx == 0 {
            if self.raw_buf[0].is_none() {
                self.raw_buf[0] = self.iter.next();
            }
            self.raw_buf[0]
        } else {
            if self.raw_buf[0].is_none() {
                self.raw_buf[0] = self.iter.next();
            }
            if self.raw_buf[1].is_none() {
                self.raw_buf[1] = self.iter.next();
            }
            self.raw_buf[1]
        }
    }

    #[inline]
    fn pull_token(&mut self) -> Option<SetToken<'a>> {
        let part = self.raw_next()?;
        let op: Option<&'static str> = if (part == ">" || part == "<") && self.raw_peek(0) == Some("=") {
            self.raw_next();
            Some(if part == ">" { ">=" } else { "<=" })
        } else if part == "~" && self.raw_peek(0) == Some(">") {
            self.raw_next();
            Some("~>")
        } else {
            match part {
                ">=" => Some(">="),
                "<=" => Some("<="),
                ">" => Some(">"),
                "<" => Some("<"),
                "=" => Some("="),
                "~" => Some("~"),
                "^" => Some("^"),
                "~>" => Some("~>"),
                _ => None,
            }
        };

        if let Some(op_str) = op {
            if let Some(next_part) = self.raw_peek(0) {
                if next_part != "-" {
                    self.raw_next();
                    return Some(SetToken::Merged(op_str, next_part));
                }
            }
            return Some(SetToken::Raw(op_str));
        }

        Some(SetToken::Raw(part))
    }

    #[inline]
    fn next_token(&mut self) -> Option<SetToken<'a>> {
        if let Some(tok) = self.tok_buf[0].take() {
            self.tok_buf[0] = self.tok_buf[1].take();
            Some(tok)
        } else {
            self.pull_token()
        }
    }

    #[inline]
    fn ensure_peek_two(&mut self) {
        if self.tok_buf[0].is_none() {
            self.tok_buf[0] = self.pull_token();
        }
        if self.tok_buf[1].is_none() {
            self.tok_buf[1] = self.pull_token();
        }
    }
}

#[inline]
fn parse_hyphen_operand(tok: SetToken<'_>) -> Result<PartialVersion, SemverError> {
    match tok {
        SetToken::Raw(s) => parse_partial_version(s),
        SetToken::Merged("=", arg) => parse_partial_version(arg),
        SetToken::Merged(op, arg) => Err(SemverError::InvalidRange(format!("{op}{arg}"))),
    }
}

fn parse_comparator_set(input: &str) -> Result<Vec<Comparator>, SemverError> {
    let mut stream = TokenStream::new(input);
    let mut comparators = Vec::with_capacity(2);

    while let Some(tok0) = stream.next_token() {
        stream.ensure_peek_two();
        let is_hyphen = matches!(stream.tok_buf[0], Some(SetToken::Raw("-")))
            && stream.tok_buf[1].is_some();

        if is_hyphen {
            let _hyphen = stream.next_token();
            let tok2 = stream.next_token().expect("checked peek");
            let from = parse_hyphen_operand(tok0)?;
            let to = parse_hyphen_operand(tok2)?;

            if let Some(from_major) = from.major {
                let from_ver = make_version_with_pre(
                    from_major,
                    from.minor.unwrap_or(0),
                    from.patch.unwrap_or(0),
                    from.prerelease,
                );
                comparators.push(Comparator::new(Op::Gte, from_ver));
            }

            if let Some(patch) = to.patch {
                let to_ver = make_version_with_pre(
                    to.major.unwrap_or(0),
                    to.minor.unwrap_or(0),
                    patch,
                    to.prerelease,
                );
                comparators.push(Comparator::new(Op::Lte, to_ver));
            } else if let Some(minor) = to.minor {
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {input}"))
                })?;
                let to_ver = upper_bound_version(to.major.unwrap_or(0), next_minor, 0);
                comparators.push(Comparator::new(Op::Lt, to_ver));
            } else if let Some(major) = to.major {
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {input}"))
                })?;
                let to_ver = upper_bound_version(next_major, 0, 0);
                comparators.push(Comparator::new(Op::Lt, to_ver));
            }
            continue;
        }

        expand_token_into(tok0, &mut comparators)?;
    }

    if comparators.is_empty() {
        comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
    }

    Ok(comparators)
}

#[inline]
fn expand_token_into(
    tok: SetToken<'_>,
    comparators: &mut Vec<Comparator>,
) -> Result<(), SemverError> {
    let (op_prefix, rest_input) = match tok {
        SetToken::Merged(op_str, arg) => (Some(op_str), arg),
        SetToken::Raw(raw) => {
            let t = raw.trim();
            if t.is_empty() {
                return Err(SemverError::InvalidRange(format!(
                    "Standalone operator without version or wildcard: {raw}"
                )));
            }
            if is_wildcard(t) {
                comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
                return Ok(());
            }
            let (fop, frest) = split_fast_op_prefix(t);
            if let Some(fp) = parse_fast_partial_token(frest) {
                return push_fast_partial_comparators(fop, fp, raw, comparators);
            }
            (None, t)
        }
    };

    if let Some(op_str) = op_prefix {
        let (fop, _) = split_fast_op_prefix(op_str);
        if let Some(fp) = parse_fast_partial_token(rest_input) {
            return push_fast_partial_comparators(fop, fp, rest_input, comparators);
        }
    }

    let (op_tag, rest, full_display) = match op_prefix {
        Some(op) => (Some(op), rest_input.trim(), None),
        None => {
            if let Some(r) = rest_input.strip_prefix('^') {
                (Some("^"), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix("~>").or_else(|| rest_input.strip_prefix('~')) {
                (Some("~"), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix(">=") {
                (Some(">="), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix("<=") {
                (Some("<="), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix('>') {
                (Some(">"), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix('<') {
                (Some("<"), r.trim(), Some(rest_input))
            } else if let Some(r) = rest_input.strip_prefix('=') {
                (Some("="), r.trim(), Some(rest_input))
            } else {
                (None, rest_input, Some(rest_input))
            }
        }
    };

    if op_tag.is_some() && rest.is_empty() {
        let err_label = full_display.unwrap_or(op_tag.unwrap_or(""));
        return Err(SemverError::InvalidRange(format!(
            "Standalone operator without version: {err_label}"
        )));
    }

    let err_ctx = || full_display.map(|s| s.to_string()).unwrap_or_else(|| format!("{}{}", op_tag.unwrap_or(""), rest_input));
    let p = parse_partial_version(rest)?;

    match op_tag {
        Some("^") => {
            let major = p.major.unwrap_or(0);
            let minor = p.minor.unwrap_or(0);
            let patch = p.patch.unwrap_or(0);
            let lower = make_version_with_pre(major, minor, patch, p.prerelease);
            let upper = if p.major.is_none() {
                comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
                return Ok(());
            } else if major > 0 {
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                upper_bound_version(next_major, 0, 0)
            } else if p.minor.is_none() {
                upper_bound_version(1, 0, 0)
            } else if minor > 0 {
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                upper_bound_version(0, next_minor, 0)
            } else if p.patch.is_none() {
                upper_bound_version(0, 1, 0)
            } else {
                let next_patch = patch.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                upper_bound_version(0, 0, next_patch)
            };
            comparators.push(Comparator::new(Op::Gte, lower));
            comparators.push(Comparator::new(Op::Lt, upper));
        }
        Some("~") | Some("~>") => {
            let major = p.major.unwrap_or(0);
            let minor = p.minor.unwrap_or(0);
            let patch = p.patch.unwrap_or(0);
            let lower = make_version_with_pre(major, minor, patch, p.prerelease);
            let upper = if p.major.is_none() {
                comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
                return Ok(());
            } else if p.minor.is_none() {
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                upper_bound_version(next_major, 0, 0)
            } else {
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                upper_bound_version(major, next_minor, 0)
            };
            comparators.push(Comparator::new(Op::Gte, lower));
            comparators.push(Comparator::new(Op::Lt, upper));
        }
        None | Some("=") => {
            if p.major.is_none() {
                comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
            } else if p.minor.is_none() {
                let major = p.major.unwrap();
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Gte, Version::new(major, 0, 0)));
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(next_major, 0, 0)));
            } else if p.patch.is_none() {
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Gte, Version::new(major, minor, 0)));
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(major, next_minor, 0)));
            } else {
                let v = make_version_with_pre(
                    p.major.unwrap(),
                    p.minor.unwrap(),
                    p.patch.unwrap(),
                    p.prerelease,
                );
                comparators.push(Comparator::new(Op::Eq, v));
            }
        }
        Some(">=") => {
            let v = make_version_with_pre(
                p.major.unwrap_or(0),
                p.minor.unwrap_or(0),
                p.patch.unwrap_or(0),
                p.prerelease,
            );
            comparators.push(Comparator::new(Op::Gte, v));
        }
        Some(">") => {
            if p.major.is_none() {
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(0, 0, 0)));
            } else if p.minor.is_none() {
                let major = p.major.unwrap();
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Gte, Version::new(next_major, 0, 0)));
            } else if p.patch.is_none() {
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Gte, Version::new(major, next_minor, 0)));
            } else {
                let v = make_version_with_pre(
                    p.major.unwrap(),
                    p.minor.unwrap(),
                    p.patch.unwrap(),
                    p.prerelease,
                );
                comparators.push(Comparator::new(Op::Gt, v));
            }
        }
        Some("<") => {
            if p.major.is_none() {
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(0, 0, 0)));
            } else if p.minor.is_none() {
                comparators.push(Comparator::new(
                    Op::Lt,
                    upper_bound_version(p.major.unwrap(), 0, 0),
                ));
            } else if p.patch.is_none() {
                comparators.push(Comparator::new(
                    Op::Lt,
                    upper_bound_version(p.major.unwrap(), p.minor.unwrap(), 0),
                ));
            } else {
                let v = make_version_with_pre(
                    p.major.unwrap(),
                    p.minor.unwrap(),
                    p.patch.unwrap(),
                    p.prerelease,
                );
                comparators.push(Comparator::new(Op::Lt, v));
            }
        }
        Some("<=") => {
            if p.major.is_none() {
                comparators.push(Comparator::new(Op::Gte, Version::new(0, 0, 0)));
            } else if p.minor.is_none() {
                let major = p.major.unwrap();
                let next_major = major.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(next_major, 0, 0)));
            } else if p.patch.is_none() {
                let major = p.major.unwrap();
                let minor = p.minor.unwrap();
                let next_minor = minor.checked_add(1).ok_or_else(|| {
                    SemverError::InvalidRange(format!("Version number overflow: {}", err_ctx()))
                })?;
                comparators.push(Comparator::new(Op::Lt, upper_bound_version(major, next_minor, 0)));
            } else {
                let v = make_version_with_pre(
                    p.major.unwrap(),
                    p.minor.unwrap(),
                    p.patch.unwrap(),
                    p.prerelease,
                );
                comparators.push(Comparator::new(Op::Lte, v));
            }
        }
        _ => unreachable!(),
    }

    Ok(())
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
        struct RangeVisitor;

        impl<'de> serde::de::Visitor<'de> for RangeVisitor {
            type Value = Range;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a semver range string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Range::parse(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(RangeVisitor)
    }
}
