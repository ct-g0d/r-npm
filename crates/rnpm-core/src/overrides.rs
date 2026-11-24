use crate::error::OverrideError;
use crate::manifest::Manifest;
use crate::semver::{
    comparator::{Comparator, Op},
    range::ComparatorSet,
    Range, Version,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Value in an override definition: either an exact spec string or a nested map of overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OverrideValue {
    Exact(String),
    Nested(BTreeMap<String, OverrideValue>),
}

/// Overrides engine implementing npm RFC 36 package overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub rules: BTreeMap<String, OverrideValue>,
    /// Root dependencies map (for reference overrides like `"$foo"`).
    pub root_dependencies: BTreeMap<String, String>,
}

impl Overrides {
    pub fn new(
        rules: BTreeMap<String, OverrideValue>,
        root_dependencies: BTreeMap<String, String>,
    ) -> Self {
        Self {
            rules,
            root_dependencies,
        }
    }

    /// Parse overrides from package.json `overrides` field.
    ///
    /// Supports npm RFC 36 arrow syntax (`>`) such as:
    /// - `"foo > bar": "2.0.0"`
    /// - `"foo@1.0.0 > bar": "2.0.0"`
    /// - `"@scope/a > @scope/b": "1.0.0"`
    /// - `"a > b > c": "1.0.0"`
    pub fn from_json_value(
        value: Option<&serde_json::Value>,
        root_dependencies: BTreeMap<String, String>,
    ) -> Self {
        let mut rules = BTreeMap::new();
        if let Some(val) = value {
            parse_overrides_into_map(val, &mut rules);
        }
        Self::new(rules, root_dependencies)
    }

    /// Construct overrides from a manifest.
    pub fn from_manifest(
        manifest: &Manifest,
    ) -> Result<Self, OverrideError> {
        Ok(Self::from_json_value(
            manifest.extra.get("overrides"),
            Self::reference_specs(manifest),
        ))
    }

    /// Specs that `$name` override references resolve to. arborist's
    /// edge.js looks in devDependencies, optionalDependencies, dependencies,
    /// then peerDependencies of the root package.
    pub fn reference_specs(manifest: &Manifest) -> BTreeMap<String, String> {
        let mut specs = BTreeMap::new();
        for section in [
            &manifest.peer_dependencies,
            &manifest.dependencies,
            &manifest.optional_dependencies,
            &manifest.dev_dependencies,
        ] {
            // An empty spec is falsy in arborist, so it never resolves.
            for (name, spec) in section {
                if !spec.is_empty() {
                    specs.insert(name.clone(), spec.clone());
                }
            }
        }
        specs
    }

    /// Check if a dependency should be overridden.
    ///
    /// - `dep_name`: the real or alias name being requested
    /// - `requested_spec`: the specifier string declared in manifest (e.g. `^1.0.0`)
    /// - `ancestors`: names of packages in the dependency chain from root down to parent
    pub fn resolve_override(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[&str],
    ) -> Result<Option<String>, OverrideError> {
        self.resolve_override_with_caller(dep_name, requested_spec, ancestors, None)
    }

    /// Optimized overload accepting `&[String]` to bypass intermediate slice allocation.
    pub fn resolve_override_strings(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[String],
    ) -> Result<Option<String>, OverrideError> {
        self.resolve_override_with_caller(dep_name, requested_spec, ancestors, None)
    }

    pub fn resolve_override_with_caller<T: AsRef<str>>(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[T],
        caller_specs: Option<&BTreeMap<String, String>>,
    ) -> Result<Option<String>, OverrideError> {
        self.resolve_override_in_context(
            dep_name,
            requested_spec,
            ancestors,
            &self.root_dependencies,
            caller_specs,
        )
    }

    /// A candidate's virtual tree has the incoming parent's package as its
    /// root. `$name` references there can differ from the attached tree's
    /// project-root references while Arborist checks peer placement.
    pub fn resolve_override_in_context<T: AsRef<str>>(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[T],
        reference_root: &BTreeMap<String, String>,
        caller_specs: Option<&BTreeMap<String, String>>,
    ) -> Result<Option<String>, OverrideError> {
        if self.rules.is_empty() {
            return Ok(None);
        }

        let mut matched_val = None;

        // 1. Check nested scoped overrides along ancestor chain
        for i in 0..ancestors.len() {
            let slice = &ancestors[i..];
            if let Some(val) = self.find_in_nested(&self.rules, slice, dep_name, requested_spec) {
                matched_val = Some(val);
                break;
            }
        }

        // 2. If no nested override matched, check top-level global overrides
        if matched_val.is_none() {
            matched_val = self.find_direct(&self.rules, dep_name, requested_spec);
        }

        // 3. Extract the target spec string
        let Some(val) = matched_val else {
            return Ok(None);
        };
        let raw_override = match val {
            OverrideValue::Exact(s) => s.clone(),
            OverrideValue::Nested(map) => {
                if let Some(OverrideValue::Exact(s)) = map.get(".") {
                    s.clone()
                } else {
                    return Ok(None);
                }
            }
        };

        // 4. Resolve reference override ($pkg) if present, following chained references with cycle detection
        let mut current_spec = raw_override;
        let mut visited_refs = BTreeSet::new();

        while let Some(ref_name) = current_spec.strip_prefix('$') {
            if !visited_refs.insert(ref_name.to_string()) {
                return Err(OverrideError::UnresolvableReference(format!(
                    "cyclic reference override ${ref_name}"
                )));
            }

            if let Some(ref_spec) = reference_root.get(ref_name) {
                current_spec = ref_spec.clone();
            } else if let Some(caller_spec) = caller_specs.and_then(|specs| specs.get(ref_name)) {
                current_spec = caller_spec.clone();
            } else {
                return Err(OverrideError::UnresolvableReference(ref_name.to_string()));
            }
        }

        Ok(Some(current_spec))
    }

    fn find_direct<'a>(
        &self,
        rules: &'a BTreeMap<String, OverrideValue>,
        dep_name: &str,
        requested_spec: &str,
    ) -> Option<&'a OverrideValue> {
        // First check spec-targeted override: e.g. "debug@^2.0.0"
        for (k, v) in rules {
            if let Some((k_name, k_spec)) = parse_key_and_spec(k) {
                if k_name == dep_name && spec_matches(k_spec, requested_spec) {
                    return Some(v);
                }
            }
        }

        // Then check exact package name: e.g. "semver"
        if let Some(v) = rules.get(dep_name) {
            return Some(v);
        }

        None
    }

    fn find_in_nested<'a, T: AsRef<str>>(
        &self,
        rules: &'a BTreeMap<String, OverrideValue>,
        ancestors: &[T],
        dep_name: &str,
        requested_spec: &str,
    ) -> Option<&'a OverrideValue> {
        if ancestors.is_empty() {
            return self.find_direct(rules, dep_name, requested_spec);
        }

        let parent_str = ancestors[0].as_ref();
        let (parent_name, parent_ver) = parse_key_and_spec(parent_str).unwrap_or((parent_str, ""));

        for (k, v) in rules {
            let (k_name, k_spec) = parse_key_and_spec(k).unwrap_or((k.as_str(), ""));

            let matches_parent = if k_name != parent_name {
                false
            } else if !k_spec.is_empty() && !parent_ver.is_empty() {
                spec_matches(k_spec, parent_ver)
            } else {
                true
            };

            if matches_parent {
                if let OverrideValue::Nested(nested_map) = v {
                    if ancestors.len() > 1 {
                        for next_idx in 1..ancestors.len() {
                            if let Some(res) = self.find_in_nested(
                                nested_map,
                                &ancestors[next_idx..],
                                dep_name,
                                requested_spec,
                            ) {
                                return Some(res);
                            }
                        }
                    }
                    if let Some(res) = self.find_direct(nested_map, dep_name, requested_spec) {
                        return Some(res);
                    }
                }
            }
        }

        None
    }
}

fn parse_override_val(val: &serde_json::Value) -> Option<OverrideValue> {
    match val {
        serde_json::Value::String(s) => Some(OverrideValue::Exact(s.clone())),
        serde_json::Value::Number(n) => Some(OverrideValue::Exact(n.to_string())),
        serde_json::Value::Object(_) => {
            let mut sub_map = BTreeMap::new();
            parse_overrides_into_map(val, &mut sub_map);
            Some(OverrideValue::Nested(sub_map))
        }
        _ => None,
    }
}

fn parse_overrides_into_map(val: &serde_json::Value, rules: &mut BTreeMap<String, OverrideValue>) {
    let serde_json::Value::Object(map) = val else {
        return;
    };

    for (k, v) in map {
        let Some(parsed_val) = parse_override_val(v) else {
            continue;
        };

        let parts = split_arrow_key(k);
        insert_override_rule(rules, &parts, parsed_val);
    }
}

/// Splits an override key on arrow `>` separators, preserving `@` scopes and `>=`/`>` comparators.
fn split_arrow_key(key: &str) -> Vec<String> {
    if !key.contains('>') {
        return vec![key.trim().to_string()];
    }

    let mut parts = Vec::new();
    let chars: Vec<char> = key.chars().collect();
    let mut last_idx = 0;
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '>' {
            let is_comparator = is_comparator_gt(&chars, i, last_idx);
            if !is_comparator {
                let part: String = chars[last_idx..i].iter().collect();
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
                last_idx = i + 1;
            }
        }
        i += 1;
    }

    let last_part: String = chars[last_idx..].iter().collect();
    let trimmed = last_part.trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }

    if parts.is_empty() {
        vec![key.trim().to_string()]
    } else {
        parts
    }
}

/// Checks whether a `>` character at index `i` is a semver comparator (e.g. `>=1.0.0`, `>1.0.0`, `@ > 1.0.0`)
/// rather than an override arrow separator `>`.
fn is_comparator_gt(chars: &[char], i: usize, segment_start: usize) -> bool {
    // 1. Always treat `>=` as a comparator
    if i + 1 < chars.len() && chars[i + 1] == '=' {
        return true;
    }

    // 2. Must be in a version context (after a version '@')
    if !has_version_context(chars, segment_start, i) {
        return false;
    }

    // 3. In a version context, '>' followed by a digit or 'v' + digit is a comparator (e.g. `>1.0.0`, `> 1.0.0`)
    let next_non_ws = (i + 1..chars.len()).find(|&k| !chars[k].is_whitespace());
    if let Some(next) = next_non_ws {
        if chars[next].is_ascii_digit() {
            return true;
        }
        if (chars[next] == 'v' || chars[next] == 'V')
            && next + 1 < chars.len()
            && chars[next + 1].is_ascii_digit()
        {
            return true;
        }
    }
    false
}

/// Checks whether there is a version specifier '@' within `chars[start..end]`.
/// A leading '@' (e.g. `@scope/pkg`) is a package scope prefix, not a version specifier.
fn has_version_context(chars: &[char], start: usize, end: usize) -> bool {
    let mut at_count = 0;
    let mut first_non_ws_is_at = false;
    let mut found_first_non_ws = false;

    for &ch in &chars[start..end] {
        if !found_first_non_ws && !ch.is_whitespace() {
            found_first_non_ws = true;
            if ch == '@' {
                first_non_ws_is_at = true;
            }
        }
        if ch == '@' {
            at_count += 1;
        }
    }

    if at_count == 0 {
        false
    } else if first_non_ws_is_at {
        at_count > 1
    } else {
        true
    }
}

/// Inserts a multi-hop override path into a nested `BTreeMap<String, OverrideValue>`.
fn insert_override_rule(
    map: &mut BTreeMap<String, OverrideValue>,
    parts: &[String],
    value: OverrideValue,
) {
    if parts.is_empty() {
        return;
    }

    if parts.len() == 1 {
        let target = &parts[0];
        match map.get_mut(target) {
            None => {
                map.insert(target.clone(), value);
            }
            Some(existing) => match (&mut *existing, value) {
                (OverrideValue::Exact(ref mut curr), OverrideValue::Exact(new_val)) => {
                    *curr = new_val;
                }
                (OverrideValue::Nested(existing_map), OverrideValue::Exact(new_val)) => {
                    existing_map.insert(".".to_string(), OverrideValue::Exact(new_val));
                }
                (OverrideValue::Exact(curr), OverrideValue::Nested(mut incoming_map)) => {
                    let old_val = std::mem::take(curr);
                    incoming_map.insert(".".to_string(), OverrideValue::Exact(old_val));
                    *existing = OverrideValue::Nested(incoming_map);
                }
                (OverrideValue::Nested(existing_map), OverrideValue::Nested(incoming_map)) => {
                    for (k, v) in incoming_map {
                        insert_override_rule(existing_map, &[k], v);
                    }
                }
            },
        }
    } else {
        let first = &parts[0];
        let sub_map = match map.get_mut(first) {
            Some(OverrideValue::Nested(sub)) => sub,
            Some(OverrideValue::Exact(curr)) => {
                let old_val = std::mem::take(curr);
                let mut new_map = BTreeMap::new();
                new_map.insert(".".to_string(), OverrideValue::Exact(old_val));
                *map.get_mut(first).unwrap() = OverrideValue::Nested(new_map);
                match map.get_mut(first).unwrap() {
                    OverrideValue::Nested(sub) => sub,
                    _ => unreachable!(),
                }
            }
            None => {
                map.insert(first.clone(), OverrideValue::Nested(BTreeMap::new()));
                match map.get_mut(first).unwrap() {
                    OverrideValue::Nested(sub) => sub,
                    _ => unreachable!(),
                }
            }
        };
        insert_override_rule(sub_map, &parts[1..], value);
    }
}

impl Overrides {
    /// Whether any rule, at any depth, names `name`.
    pub fn mentions(&self, name: &str) -> bool {
        fn walk(rules: &BTreeMap<String, OverrideValue>, name: &str) -> bool {
            rules.iter().any(|(key, value)| {
                parse_key_and_spec(key).map_or(key.as_str(), |(key_name, _)| key_name) == name
                    || matches!(value, OverrideValue::Nested(nested) if walk(nested, name))
            })
        }
        walk(&self.rules, name)
    }
}

/// Parses "name@spec" while respecting scoped package names like "@scope/pkg@^1.0.0".
fn parse_key_and_spec(key: &str) -> Option<(&str, &str)> {
    if key.starts_with('@') {
        let slash = key.find('/')?;
        let after_slash = &key[slash + 1..];
        let at = after_slash.find('@')?;
        let split_idx = slash + 1 + at;
        Some((key[..split_idx].trim(), key[split_idx + 1..].trim()))
    } else {
        let at = key.find('@')?;
        Some((key[..at].trim(), key[at + 1..].trim()))
    }
}

/// Determines if two semver comparators intersect (can be simultaneously satisfied).
fn comparator_intersects(c1: &Comparator, c2: &Comparator) -> bool {
    // If either comparator is equality:
    if c1.op == Op::Eq {
        if c1.version.is_prerelease() {
            let has_matching_prerelease = c2.version.is_prerelease()
                && c2.version.major == c1.version.major
                && c2.version.minor == c1.version.minor
                && c2.version.patch == c1.version.patch;
            if !has_matching_prerelease {
                return false;
            }
        }
        return c2.matches(&c1.version);
    }
    if c2.op == Op::Eq {
        if c2.version.is_prerelease() {
            let has_matching_prerelease = c1.version.is_prerelease()
                && c1.version.major == c2.version.major
                && c1.version.minor == c2.version.minor
                && c1.version.patch == c2.version.patch;
            if !has_matching_prerelease {
                return false;
            }
        }
        return c1.matches(&c2.version);
    }

    // Both are increasing (> or >=)
    let c1_inc = matches!(c1.op, Op::Gt | Op::Gte);
    let c2_inc = matches!(c2.op, Op::Gt | Op::Gte);
    if c1_inc && c2_inc {
        return true;
    }

    // Both are decreasing (< or <=)
    let c1_dec = matches!(c1.op, Op::Lt | Op::Lte);
    let c2_dec = matches!(c2.op, Op::Lt | Op::Lte);
    if c1_dec && c2_dec {
        return true;
    }

    // Same version and both inclusive (>= and <=)
    if c1.version == c2.version
        && matches!(c1.op, Op::Gte | Op::Lte)
        && matches!(c2.op, Op::Gte | Op::Lte)
    {
        return true;
    }

    // Opposite directions: c1 increasing, c2 decreasing
    if c1_inc && c2_dec {
        if c2.version.is_prerelease()
            && !c1.version.is_prerelease()
            && c1.version.major == c2.version.major
            && c1.version.minor == c2.version.minor
            && c1.version.patch == c2.version.patch
        {
            return false;
        }
        if c1.version < c2.version {
            return true;
        }
    }

    // Opposite directions: c1 decreasing, c2 increasing
    if c1_dec && c2_inc {
        if c1.version.is_prerelease()
            && !c2.version.is_prerelease()
            && c1.version.major == c2.version.major
            && c1.version.minor == c2.version.minor
            && c1.version.patch == c2.version.patch
        {
            return false;
        }
        if c1.version > c2.version {
            return true;
        }
    }

    false
}

/// Checks whether all comparators within a ComparatorSet can be simultaneously satisfied.
fn comparator_set_is_satisfiable(cs: &ComparatorSet) -> bool {
    for i in 0..cs.comparators.len() {
        for j in (i + 1)..cs.comparators.len() {
            if !comparator_intersects(&cs.comparators[i], &cs.comparators[j]) {
                return false;
            }
        }
    }
    true
}

/// Checks if two ComparatorSets intersect (their conjunction is satisfiable).
fn comparator_sets_intersect(cs1: &ComparatorSet, cs2: &ComparatorSet) -> bool {
    if !comparator_set_is_satisfiable(cs1) || !comparator_set_is_satisfiable(cs2) {
        return false;
    }
    for c1 in &cs1.comparators {
        for c2 in &cs2.comparators {
            if !comparator_intersects(c1, c2) {
                return false;
            }
        }
    }
    true
}

/// Checks if two semver Ranges intersect, matching node-semver `semver.intersects(r1, r2)`.
pub fn ranges_intersect(r1: &Range, r2: &Range) -> bool {
    if r1.sets.is_empty() || r2.sets.is_empty() {
        return false;
    }
    for s1 in &r1.sets {
        for s2 in &r2.sets {
            if comparator_sets_intersect(s1, s2) {
                return true;
            }
        }
    }
    false
}

/// Determines if the requested spec matches the pattern spec in a spec-targeted override.
fn spec_matches(pattern_spec: &str, requested_spec: &str) -> bool {
    let p = pattern_spec.trim();
    let mut r = requested_spec.trim();
    if p == r {
        return true;
    }

    // Strip workspace: prefix if present, e.g. workspace:^1.0.0 -> ^1.0.0
    r = r.strip_prefix("workspace:").unwrap_or(r).trim();
    if r == "*" || r == "^" || r == "~" || r.is_empty() {
        r = "*";
    }
    if p == r {
        return true;
    }

    // If requested_spec is an alias, e.g. "npm:react@^18.0.0" or "npm:@scope/pkg@^18.0.0"
    if let Some(rest) = r.strip_prefix("npm:") {
        if let Some((_, sub_spec)) = parse_key_and_spec(rest) {
            r = sub_spec;
        } else if let Some(at_idx) = rest.rfind('@') {
            r = &rest[at_idx + 1..];
        } else {
            // Bare alias like "npm:react" defaults to "*"
            r = "*";
        }
    }

    // If requested_spec contains #semver:
    if let Some(idx) = r.find("#semver:") {
        r = &r[idx + 8..];
    }

    if p == r {
        return true;
    }

    // Wildcards: "*" or "x" or "X" match anything
    if p == "*" || p.eq_ignore_ascii_case("x") || r == "*" || r.eq_ignore_ascii_case("x") {
        return true;
    }

    // If both can be parsed as ranges, test for intersection
    if let (Ok(p_range), Ok(r_range)) = (Range::parse(p), Range::parse(r)) {
        return ranges_intersect(&p_range, &r_range);
    }

    // If requested is exact version and pattern is range
    if let (Ok(p_range), Ok(r_ver)) = (Range::parse(p), Version::parse(r)) {
        return p_range.satisfies(&r_ver);
    }

    // If pattern is exact version and requested is range
    if let (Ok(p_ver), Ok(r_range)) = (Version::parse(p), Range::parse(r)) {
        return r_range.satisfies(&p_ver);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_override() {
        let json = serde_json::json!({
            "semver": "7.5.4"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        let res = overrides
            .resolve_override("semver", "^6.3.0", &["foo", "bar"])
            .unwrap();
        assert_eq!(res, Some("7.5.4".to_string()));
    }

    #[test]
    fn test_nested_scoped_override() {
        let json = serde_json::json!({
            "foo": {
                "bar": "2.0.0"
            }
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // Under foo: overridden to 2.0.0
        let under_foo = overrides
            .resolve_override("bar", "^1.0.0", &["foo"])
            .unwrap();
        assert_eq!(under_foo, Some("2.0.0".to_string()));

        // Under qux: not overridden
        let under_qux = overrides
            .resolve_override("bar", "^1.0.0", &["qux"])
            .unwrap();
        assert_eq!(under_qux, None);
    }

    #[test]
    fn test_reference_override_resolves_dev_dependency_first() {
        // rollup's published manifest: "overrides": { "vite": "$vite" } with vite in devDependencies.
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "name": "root",
            "version": "1.0.0",
            "dependencies": { "shared": "^1.0.0" },
            "devDependencies": { "vite": "^7.0.0", "shared": "^2.0.0" },
            "overrides": { "vite": "$vite", "shared": "$shared" }
        }))
        .unwrap();
        let overrides = Overrides::from_manifest(&manifest).unwrap();
        assert_eq!(
            overrides
                .resolve_override("vite", "^5.0.0", &["plugin"])
                .unwrap(),
            Some("^7.0.0".into())
        );
        assert_eq!(
            overrides
                .resolve_override("shared", "^1.0.0", &["plugin"])
                .unwrap(),
            Some("^2.0.0".into())
        );
    }

    #[test]
    fn test_spec_targeted_override() {
        let json = serde_json::json!({
            "debug@^2.0.0": "2.6.9"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        let match_spec = overrides.resolve_override("debug", "^2.0.0", &[]).unwrap();
        assert_eq!(match_spec, Some("2.6.9".to_string()));

        let no_match = overrides.resolve_override("debug", "^4.0.0", &[]).unwrap();
        assert_eq!(no_match, None);
    }

    #[test]
    fn test_reference_override() {
        let json = serde_json::json!({
            "foo": "$foo"
        });
        let mut root_deps = BTreeMap::new();
        root_deps.insert("foo".to_string(), "1.2.3".to_string());

        let overrides = Overrides::from_json_value(Some(&json), root_deps);

        let res = overrides
            .resolve_override("foo", "^2.0.0", &["parent"])
            .unwrap();
        assert_eq!(res, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_unresolvable_reference_override_errors() {
        let json = serde_json::json!({
            "foo": "$missing"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());
        let err = overrides
            .resolve_override("foo", "^2.0.0", &["parent"])
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("Unable to resolve reference $missing"));
    }

    #[test]
    fn test_reference_override_falls_back_to_caller_package() {
        let json = serde_json::json!({
            "typescript": "$typescript"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());
        let mut caller_specs = BTreeMap::new();
        caller_specs.insert("typescript".to_string(), ">=5.0.4 <5.8".to_string());

        let res = overrides
            .resolve_override_with_caller(
                "typescript",
                "^5.5.4",
                &["dts-buddy"],
                Some(&caller_specs),
            )
            .unwrap();
        assert_eq!(res, Some(">=5.0.4 <5.8".to_string()));
    }

    #[test]
    fn test_arrow_syntax_overrides() {
        let json = serde_json::json!({
            "foo > bar": "2.0.0",
            "foo@1.0.0 > baz": "3.0.0",
            "@scope/a > @scope/b": "1.0.0",
            "a > b > c": "4.0.0",
            "nested": {
                "x > y": "5.0.0"
            }
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // Under foo: bar is 2.0.0
        assert_eq!(
            overrides
                .resolve_override("bar", "^1.0.0", &["foo"])
                .unwrap(),
            Some("2.0.0".to_string())
        );

        // Under foo: baz is 3.0.0
        assert_eq!(
            overrides
                .resolve_override("baz", "^1.0.0", &["foo"])
                .unwrap(),
            Some("3.0.0".to_string())
        );

        // Under @scope/a: @scope/b is 1.0.0
        assert_eq!(
            overrides
                .resolve_override("@scope/b", "*", &["@scope/a"])
                .unwrap(),
            Some("1.0.0".to_string())
        );

        // Under a > b: c is 4.0.0
        assert_eq!(
            overrides
                .resolve_override("c", "^1.0.0", &["a", "b"])
                .unwrap(),
            Some("4.0.0".to_string())
        );

        // Under nested > x: y is 5.0.0
        assert_eq!(
            overrides
                .resolve_override("y", "^1.0.0", &["nested", "x"])
                .unwrap(),
            Some("5.0.0".to_string())
        );

        // Top level lookup for bar should be None
        assert_eq!(
            overrides.resolve_override("bar", "^1.0.0", &[]).unwrap(),
            None
        );
    }

    #[test]
    fn test_arrow_syntax_with_comparators_and_spaces() {
        let json = serde_json::json!({
            "foo@ >= 1.0.0 > bar": "2.0.0",
            "foo@ >1.0.0 > baz": "3.0.0",
            "foo@> 1.0.0 > qux": "4.0.0",
            "target@>=2.0.0": "2.5.0",
            "@scope/pkg @ ^1.0.0 > child": "1.2.3"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        assert_eq!(
            overrides.resolve_override("bar", "^1.0.0", &["foo"]).unwrap(),
            Some("2.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("baz", "^1.0.0", &["foo"]).unwrap(),
            Some("3.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("qux", "^1.0.0", &["foo"]).unwrap(),
            Some("4.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("child", "*", &["@scope/pkg"]).unwrap(),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            overrides.resolve_override("target", "2.1.0", &[]).unwrap(),
            Some("2.5.0".to_string())
        );
    }

    #[test]
    fn test_workspace_spec_matches_override() {
        let json = serde_json::json!({
            "dep@^1.0.0": "1.9.9",
            "shared@*": "2.0.0"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        assert_eq!(
            overrides.resolve_override("dep", "workspace:^1.2.0", &[]).unwrap(),
            Some("1.9.9".to_string())
        );
        assert_eq!(
            overrides.resolve_override("shared", "workspace:*", &[]).unwrap(),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_arrow_syntax_advanced_comparators() {
        // Direct testing of split_arrow_key for complex semver comparator patterns
        assert_eq!(
            split_arrow_key("foo@>=1.0.0 > bar"),
            vec!["foo@>=1.0.0", "bar"]
        );
        assert_eq!(
            split_arrow_key("foo@ >1.0.0 > bar"),
            vec!["foo@ >1.0.0", "bar"]
        );
        assert_eq!(
            split_arrow_key("foo@<2.0.0 >1.0.0 > bar"),
            vec!["foo@<2.0.0 >1.0.0", "bar"]
        );
        assert_eq!(
            split_arrow_key("foo@1.0.0 || >2.0.0 > bar"),
            vec!["foo@1.0.0 || >2.0.0", "bar"]
        );

        // Verification through full Overrides resolution
        let json = serde_json::json!({
            "foo@>=1.0.0 > bar": "2.0.0",
            "alpha@ >1.0.0 > beta": "3.0.0",
            "gamma@<2.0.0 >1.0.0 > delta": "4.0.0",
            "epsilon@1.0.0 || >2.0.0 > zeta": "5.0.0"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());
        assert_eq!(
            overrides.resolve_override("bar", "*", &["foo"]).unwrap(),
            Some("2.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("beta", "*", &["alpha"]).unwrap(),
            Some("3.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("delta", "*", &["gamma"]).unwrap(),
            Some("4.0.0".to_string())
        );
        assert_eq!(
            overrides.resolve_override("zeta", "*", &["epsilon"]).unwrap(),
            Some("5.0.0".to_string())
        );
    }

    #[test]
    fn test_chained_and_cyclic_reference_overrides() {
        let json = serde_json::json!({
            "pkg-a": "$pkg-b",
            "pkg-c": "$pkg-d",
            "pkg-d": "$pkg-c"
        });
        let mut root_deps = BTreeMap::new();
        root_deps.insert("pkg-b".to_string(), "$pkg-final".to_string());
        root_deps.insert("pkg-final".to_string(), "1.2.3".to_string());

        let overrides = Overrides::from_json_value(Some(&json), root_deps);

        // Chained reference $pkg-a -> $pkg-b -> $pkg-final -> 1.2.3
        let res = overrides.resolve_override("pkg-a", "^1.0.0", &[]).unwrap();
        assert_eq!(res, Some("1.2.3".to_string()));

        // Cyclic reference $pkg-c -> $pkg-d -> $pkg-c must return error, not hang or panic
        let err = overrides.resolve_override("pkg-c", "^1.0.0", &[]);
        assert!(err.is_err());
    }

    #[test]
    fn test_selector_range_intersection() {
        let json = serde_json::json!({
            "debug@1.2.0": "2.0.0",
            "foo@>=1.5.0 <2.0.0": "3.0.0"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // debug@1.2.0 intersects with requested ^1.0.0
        assert_eq!(
            overrides.resolve_override("debug", "^1.0.0", &[]).unwrap(),
            Some("2.0.0".to_string())
        );

        // foo@>=1.5.0 <2.0.0 intersects with requested ^1.0.0
        assert_eq!(
            overrides.resolve_override("foo", "^1.0.0", &[]).unwrap(),
            Some("3.0.0".to_string())
        );

        // Does not match non-intersecting range
        assert_eq!(
            overrides.resolve_override("debug", "^2.0.0", &[]).unwrap(),
            None
        );
    }

    #[test]
    fn test_aliased_dependency_spec_override() {
        let json = serde_json::json!({
            "my-react@^18.0.0": "18.3.1"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // Alias spec "npm:react@^18.2.0" unwraps and intersects with ^18.0.0
        let res = overrides
            .resolve_override("my-react", "npm:react@^18.2.0", &[])
            .unwrap();
        assert_eq!(res, Some("18.3.1".to_string()));
    }

    #[test]
    fn test_nested_override_with_intermediate_packages() {
        let json = serde_json::json!({
            "parent > target": "9.9.9"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // Ancestor chain has an intermediate package: ["parent", "intermediate"]
        let res = overrides
            .resolve_override("target", "1.0.0", &["parent", "intermediate"])
            .unwrap();
        assert_eq!(res, Some("9.9.9".to_string()));
    }

    #[test]
    fn test_ranges_intersect_prerelease_exclusion() {
        let r1 = Range::parse("^1.0.0").unwrap();
        let r_pre = Range::parse("2.0.0-alpha.1").unwrap();
        // ^1.0.0 must NOT intersect with 2.0.0-alpha.1 per node-semver prerelease rule
        assert!(!ranges_intersect(&r1, &r_pre));

        let r2 = Range::parse("<2.0.0-beta.1").unwrap();
        // <2.0.0-beta.1 explicitly targets 2.0.0 prereleases, so it DOES intersect
        assert!(ranges_intersect(&r2, &r_pre));
    }

    #[test]
    fn test_bare_alias_spec_override() {
        let json = serde_json::json!({
            "my-react@*": "18.3.1"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        // Bare alias "npm:react" defaults to "*"
        let res = overrides
            .resolve_override("my-react", "npm:react", &[])
            .unwrap();
        assert_eq!(res, Some("18.3.1".to_string()));
    }
}
