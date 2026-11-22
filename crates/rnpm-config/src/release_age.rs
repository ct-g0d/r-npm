//! Implementation of npm 11.20.0 release-age exclusion matching.
//!
//! Exemption patterns in `min-release-age-exclude` are exact package names
//! or `minimatch` globs (such as `@myorg/*`, `my-*-pkg`, or `**`).
//! Matching follows npm 11.20.0's `release-age-exclude.js` with minimatch options
//! `{ nonegate: true, nocomment: true, noext: true }`.

/// Check whether a package name matches a single glob pattern according to
/// npm's minimatch configuration (`nonegate: true, nocomment: true, noext: true`).
pub fn match_package_pattern(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    let pat_segments: Vec<&str> = pattern.split('/').collect();
    let name_segments: Vec<&str> = name.split('/').collect();
    match_segments(&pat_segments, &name_segments)
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
}
