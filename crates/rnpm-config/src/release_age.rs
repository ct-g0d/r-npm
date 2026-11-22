//! Implementation of npm 11.20.0 release-age exclusion matching.
//!
//! Exemption patterns in `min-release-age-exclude` are exact package names
//! or `minimatch` globs (such as `@myorg/*`, `my-*-pkg`, or `**`).
//! Matching follows npm 11.20.0's `release-age-exclude.js` with minimatch options
//! `{ nonegate: true, nocomment: true, noext: true }`.

/// Check whether a package name matches a single glob pattern according to
/// npm's minimatch configuration (`nonegate: true, nocomment: true, noext: true`).
pub fn match_package_pattern(pattern: &str, name: &str) -> bool {
    let expanded = expand_braces(pattern);
    expanded.iter().any(|p| match_single_pattern(p, name))
}

fn match_single_pattern(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    let pat_segments: Vec<&str> = pattern.split('/').collect();
    let name_segments: Vec<&str> = name.split('/').collect();
    match_segments(&pat_segments, &name_segments)
}

const MAX_EXPANSIONS: usize = 1024;

/// Expand bash-style braces in a pattern, matching npm 11.20.0 `minimatch` behavior.
///
/// Supports:
/// - `{foo,bar}` -> `["foo", "bar"]`
/// - `@scope/{a,b}` -> `["@scope/a", "@scope/b"]`
/// - Nested braces: `{a,{b,c}}` -> `["a", "b", "c"]`
/// - Numeric ranges: `{1..3}` -> `["1", "2", "3"]`, `{01..03}` -> `["01", "02", "03"]`
/// - Alpha ranges: `{a..c}` -> `["a", "b", "c"]`
/// - Unmatched/single braces without commas or ranges: `{single}` -> `["{single}"]`
///
/// Protected by a maximum expansion cap (`MAX_EXPANSIONS = 1024`) against DoS.
pub fn expand_braces(pattern: &str) -> Vec<String> {
    if !pattern.contains('{') || !pattern.contains('}') {
        return vec![pattern.to_string()];
    }

    let mut results = Vec::new();
    let mut queue = vec![pattern.to_string()];

    while let Some(current) = queue.pop() {
        if results.len() >= MAX_EXPANSIONS {
            break;
        }

        if let Some((start, end, options)) = find_expandable_brace(&current) {
            let prefix = &current[..start];
            let suffix = &current[end + 1..];

            for opt in options.into_iter().rev() {
                if queue.len() + results.len() >= MAX_EXPANSIONS {
                    break;
                }
                queue.push(format!("{prefix}{opt}{suffix}"));
            }
        } else {
            results.push(current);
        }
    }

    if results.is_empty() {
        vec![pattern.to_string()]
    } else {
        results
    }
}

fn find_expandable_brace(s: &str) -> Option<(usize, usize, Vec<String>)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'{' {
            let start = i;
            let mut depth = 1;
            let mut j = i + 1;
            let mut found_end = None;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'{' {
                    depth += 1;
                } else if bytes[j] == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        found_end = Some(j);
                        break;
                    }
                }
                j += 1;
            }

            if let Some(end) = found_end {
                let inner = &s[start + 1..end];
                let parts = split_top_level_commas(inner);
                if parts.len() > 1 {
                    return Some((start, end, parts));
                } else if let Some(range_parts) = parse_brace_range(inner) {
                    return Some((start, end, range_parts));
                }
            }
        }
        i += 1;
    }
    None
}

fn split_top_level_commas(inner: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut depth = 0;
    let chars: Vec<char> = inner.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            cur.push(c);
            if i + 1 < chars.len() {
                i += 1;
                cur.push(chars[i]);
            }
        } else if c == '{' {
            depth += 1;
            cur.push(c);
        } else if c == '}' {
            if depth > 0 {
                depth -= 1;
            }
            cur.push(c);
        } else if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    parts.push(cur);
    parts
}

fn parse_brace_range(inner: &str) -> Option<Vec<String>> {
    if inner.contains(',') {
        return None;
    }
    let segments: Vec<&str> = inner.split("..").collect();
    if segments.len() != 2 && segments.len() != 3 {
        return None;
    }
    let start_str = segments[0];
    let end_str = segments[1];
    let step_str = if segments.len() == 3 {
        Some(segments[2])
    } else {
        None
    };

    if let (Ok(start), Ok(end)) = (start_str.parse::<i64>(), end_str.parse::<i64>()) {
        let step = if let Some(st) = step_str {
            st.parse::<i64>().ok()?.abs().max(1)
        } else {
            1
        };
        let pad_len = if (start_str.starts_with('0') && start_str.len() > 1)
            || (start_str.starts_with("-0") && start_str.len() > 2)
            || (end_str.starts_with('0') && end_str.len() > 1)
            || (end_str.starts_with("-0") && end_str.len() > 2)
        {
            start_str.len().max(end_str.len())
        } else {
            0
        };

        let mut res = Vec::new();
        if start <= end {
            let mut cur = start;
            while cur <= end && res.len() < MAX_EXPANSIONS {
                if pad_len > 0 {
                    res.push(format!("{:0width$}", cur, width = pad_len));
                } else {
                    res.push(cur.to_string());
                }
                cur = cur.saturating_add(step);
                if cur == i64::MAX {
                    break;
                }
            }
        } else {
            let mut cur = start;
            while cur >= end && res.len() < MAX_EXPANSIONS {
                if pad_len > 0 {
                    res.push(format!("{:0width$}", cur, width = pad_len));
                } else {
                    res.push(cur.to_string());
                }
                cur = cur.saturating_sub(step);
                if cur == i64::MIN {
                    break;
                }
            }
        }
        return Some(res);
    }

    if start_str.len() == 1 && end_str.len() == 1 {
        let s_char = start_str.chars().next()?;
        let e_char = end_str.chars().next()?;
        if (s_char.is_ascii_lowercase() && e_char.is_ascii_lowercase())
            || (s_char.is_ascii_uppercase() && e_char.is_ascii_uppercase())
        {
            let step = if let Some(st) = step_str {
                st.parse::<usize>().ok()?.max(1)
            } else {
                1
            };
            let mut res = Vec::new();
            if s_char <= e_char {
                let mut cur = s_char as u8;
                let end = e_char as u8;
                while cur <= end && res.len() < MAX_EXPANSIONS {
                    res.push((cur as char).to_string());
                    cur = cur.saturating_add(step as u8);
                    if cur > end {
                        break;
                    }
                }
            } else {
                let mut cur = s_char as u8;
                let end = e_char as u8;
                while cur >= end && res.len() < MAX_EXPANSIONS {
                    res.push((cur as char).to_string());
                    if (cur as usize) < step {
                        break;
                    }
                    cur -= step as u8;
                }
            }
            return Some(res);
        }
    }

    None
}

/// Determine whether a package name is exempt from the `min-release-age` /
/// `before` release-age filter, based on the `min-release-age-exclude` config.
///
/// Returns `false` if `name` is empty or `patterns` is empty.
pub fn is_release_age_excluded<S: AsRef<str>>(name: &str, patterns: &[S]) -> bool {
    let name = name.trim();
    if name.is_empty() || patterns.is_empty() {
        return false;
    }
    patterns.iter().any(|p| {
        let pat = p.as_ref().trim();
        !pat.is_empty() && match_package_pattern(pat, name)
    })
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some(&"**") => {
            match_segments(&pat[1..], txt)
                || (!txt.is_empty() && match_segments(pat, &txt[1..]))
        }
        Some(seg) => {
            !txt.is_empty() && match_segment(seg, txt[0]) && match_segments(&pat[1..], &txt[1..])
        }
    }
}

fn match_segment(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    if t.first() == Some(&'.') && matches!(p.first(), Some('*') | Some('?') | Some('[')) {
        return false;
    }
    go(&p, &t)
}

fn go(p: &[char], t: &[char]) -> bool {
    match p.first() {
        None => t.is_empty(),
        Some('*') => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
        Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
        Some('[') => {
            let Some(end) = p.iter().skip(1).position(|c| *c == ']').map(|i| i + 1) else {
                return !t.is_empty() && t[0] == '[' && go(&p[1..], &t[1..]);
            };
            let Some(&c) = t.first() else { return false };
            let mut class = &p[1..end];
            let negate = matches!(class.first(), Some('!') | Some('^'));
            if negate {
                class = &class[1..];
            }
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == '-' {
                    hit |= class[i] <= c && c <= class[i + 2];
                    i += 3;
                } else {
                    hit |= class[i] == c;
                    i += 1;
                }
            }
            hit != negate && go(&p[end + 1..], &t[1..])
        }
        Some('\\') if p.len() > 1 => !t.is_empty() && t[0] == p[1] && go(&p[2..], &t[1..]),
        Some(&c) => !t.is_empty() && t[0] == c && go(&p[1..], &t[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_matches() {
        assert!(is_release_age_excluded("foo", &["foo"]));
        assert!(is_release_age_excluded("@myorg/pkg", &["@myorg/pkg"]));
        assert!(!is_release_age_excluded("foo", &["bar"]));
        assert!(!is_release_age_excluded("@myorg/pkg", &["@other/pkg"]));
    }

    #[test]
    fn test_scope_wildcard_matching() {
        assert!(is_release_age_excluded("@myorg/foo", &["@myorg/*"]));
        assert!(is_release_age_excluded("@myorg/bar-baz", &["@myorg/*"]));
        assert!(!is_release_age_excluded("@other/foo", &["@myorg/*"]));
        assert!(!is_release_age_excluded("foo", &["@myorg/*"]));
        // @myorg alone does NOT match @myorg/foo (matching npm 11.20.0 minimatch behavior)
        assert!(!is_release_age_excluded("@myorg/foo", &["@myorg"]));
    }

    #[test]
    fn test_globstar_matching() {
        assert!(is_release_age_excluded("@myorg/foo", &["@myorg/**"]));
        assert!(is_release_age_excluded("foo", &["**"]));
        assert!(is_release_age_excluded("@myorg/foo", &["**"]));
        assert!(is_release_age_excluded("foo", &["**/foo"]));
        assert!(is_release_age_excluded("@scope/foo", &["**/foo"]));
        assert!(!is_release_age_excluded("@scope/bar", &["**/foo"]));
    }

    #[test]
    fn test_unscoped_wildcard() {
        // In minimatch, `*` matches unscoped package names, but NOT scoped packages with `/`
        assert!(is_release_age_excluded("foo", &["*"]));
        assert!(is_release_age_excluded("my-pkg", &["*"]));
        assert!(!is_release_age_excluded("@myorg/foo", &["*"]));
    }

    #[test]
    fn test_scoped_generic_wildcard() {
        assert!(is_release_age_excluded("@myorg/foo", &["@*/*"]));
        assert!(is_release_age_excluded("@any/pkg", &["@*/*"]));
        assert!(!is_release_age_excluded("foo", &["@*/*"]));
    }

    #[test]
    fn test_prefix_suffix_wildcards() {
        assert!(is_release_age_excluded("@myorg/bar-baz", &["@myorg/bar-*"]));
        assert!(!is_release_age_excluded("@myorg/other", &["@myorg/bar-*"]));
        assert!(is_release_age_excluded("test-pkg", &["test-*"]));
        assert!(is_release_age_excluded("my-lib", &["*-lib"]));
    }

    #[test]
    fn test_single_char_and_class() {
        assert!(is_release_age_excluded("foo", &["?oo"]));
        assert!(!is_release_age_excluded("@scope/foo", &["?oo"]));
        assert!(is_release_age_excluded("@scope/foo", &["@scope/?oo"]));
        assert!(is_release_age_excluded("foo", &["fo[o-z]"]));
        assert!(!is_release_age_excluded("bar", &["fo[o-z]"]));
    }

    #[test]
    fn test_nonegate_and_nocomment() {
        // nonegate: true means !foo is literal !foo, not a negation
        assert!(is_release_age_excluded("!foo", &["!foo"]));
        assert!(!is_release_age_excluded("foo", &["!foo"]));

        // nocomment: true means #foo is literal #foo
        assert!(is_release_age_excluded("#foo", &["#foo"]));
        assert!(!is_release_age_excluded("foo", &["#foo"]));
    }

    #[test]
    fn test_empty_and_null_cases() {
        assert!(!is_release_age_excluded("", &["foo"]));
        assert!(!is_release_age_excluded("foo", &[] as &[&str]));
        assert!(!is_release_age_excluded("   ", &["foo"]));
        assert!(!is_release_age_excluded("foo", &["   "]));
    }

    #[test]
    fn test_brace_expansion_exclude() {
        // {foo,bar}
        assert!(is_release_age_excluded("foo", &["{foo,bar}"]));
        assert!(is_release_age_excluded("bar", &["{foo,bar}"]));
        assert!(!is_release_age_excluded("baz", &["{foo,bar}"]));

        // @scope/{a,b}
        assert!(is_release_age_excluded("@scope/a", &["@scope/{a,b}"]));
        assert!(is_release_age_excluded("@scope/b", &["@scope/{a,b}"]));
        assert!(!is_release_age_excluded("@scope/c", &["@scope/{a,b}"]));
        assert!(!is_release_age_excluded("a", &["@scope/{a,b}"]));

        // nested {a,{b,c}}
        assert!(is_release_age_excluded("a", &["{a,{b,c}}"]));
        assert!(is_release_age_excluded("b", &["{a,{b,c}}"]));
        assert!(is_release_age_excluded("c", &["{a,{b,c}}"]));
        assert!(!is_release_age_excluded("d", &["{a,{b,c}}"]));

        // unmatched {single}
        assert!(is_release_age_excluded("{single}", &["{single}"]));
        assert!(!is_release_age_excluded("single", &["{single}"]));

        // wildcard + braces @org/{foo-*,bar}
        assert!(is_release_age_excluded("@org/foo-1", &["@org/{foo-*,bar}"]));
        assert!(is_release_age_excluded("@org/foo-alpha", &["@org/{foo-*,bar}"]));
        assert!(is_release_age_excluded("@org/bar", &["@org/{foo-*,bar}"]));
        assert!(!is_release_age_excluded("@org/baz", &["@org/{foo-*,bar}"]));
        assert!(!is_release_age_excluded("foo-1", &["@org/{foo-*,bar}"]));

        // numeric ranges
        assert!(is_release_age_excluded("pkg-1", &["pkg-{1..3}"]));
        assert!(is_release_age_excluded("pkg-2", &["pkg-{1..3}"]));
        assert!(is_release_age_excluded("pkg-3", &["pkg-{1..3}"]));
        assert!(!is_release_age_excluded("pkg-4", &["pkg-{1..3}"]));
    }

    #[test]
    fn test_expand_braces_cases() {
        assert_eq!(expand_braces("{foo,bar}"), vec!["foo", "bar"]);
        assert_eq!(expand_braces("@scope/{a,b}"), vec!["@scope/a", "@scope/b"]);
        assert_eq!(expand_braces("{a,{b,c}}"), vec!["a", "b", "c"]);
        assert_eq!(expand_braces("{single}"), vec!["{single}"]);
        assert_eq!(expand_braces("@org/{foo-*,bar}"), vec!["@org/foo-*", "@org/bar"]);
        assert_eq!(expand_braces("pkg-{1..3}"), vec!["pkg-1", "pkg-2", "pkg-3"]);
    }
}
