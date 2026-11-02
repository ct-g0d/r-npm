use std::collections::BTreeMap;
use rnpm_core::semver::{Range, Version};
use serde::{Deserialize, Serialize};

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
    pub fn from_manifest(manifest: &rnpm_core::manifest::Manifest) -> Result<Self, crate::error::SolverError> {
        Ok(Self::from_json_value(
            manifest.extra.get("overrides"),
            manifest.dependencies.clone(),
        ))
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
    ) -> Option<String> {
        self.resolve_override_generic(dep_name, requested_spec, ancestors)
    }

    /// Optimized overload accepting `&[String]` to bypass intermediate slice allocation.
    pub fn resolve_override_strings(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[String],
    ) -> Option<String> {
        self.resolve_override_generic(dep_name, requested_spec, ancestors)
    }

    fn resolve_override_generic<T: AsRef<str>>(
        &self,
        dep_name: &str,
        requested_spec: &str,
        ancestors: &[T],
    ) -> Option<String> {
        if self.rules.is_empty() {
            return None;
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
        let raw_override = match matched_val? {
            OverrideValue::Exact(s) => s.clone(),
            OverrideValue::Nested(map) => {
                if let Some(OverrideValue::Exact(s)) = map.get(".") {
                    s.clone()
                } else {
                    return None;
                }
            }
        };

        // 4. Resolve reference override ($pkg) if present
        if let Some(ref_name) = raw_override.strip_prefix('$') {
            if let Some(ref_spec) = self.root_dependencies.get(ref_name) {
                Some(ref_spec.clone())
            } else {
                Some(raw_override)
            }
        } else {
            Some(raw_override)
        }
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
                        if let Some(res) = self.find_in_nested(
                            nested_map,
                            &ancestors[1..],
                            dep_name,
                            requested_spec,
                        ) {
                            return Some(res);
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

/// Splits an override key on arrow `>` separators, preserving `@` scopes and `>=` comparators.
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
            // Check if this '>' is a comparator rather than an arrow separator:
            // 1. Followed by '=' (e.g. '>=')
            // 2. Preceded by '@' (e.g. '@>')
            let is_comparator = (i + 1 < chars.len() && chars[i + 1] == '=')
                || (i > 0 && chars[i - 1] == '@');
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

/// Parses "name@spec" while respecting scoped package names like "@scope/pkg@^1.0.0".
fn parse_key_and_spec(key: &str) -> Option<(&str, &str)> {
    if key.starts_with('@') {
        let slash = key.find('/')?;
        let after_slash = &key[slash + 1..];
        let at = after_slash.find('@')?;
        let split_idx = slash + 1 + at;
        Some((&key[..split_idx], &key[split_idx + 1..]))
    } else {
        let at = key.find('@')?;
        Some((&key[..at], &key[at + 1..]))
    }
}

/// Determines if the requested spec matches the pattern spec in a spec-targeted override.
fn spec_matches(pattern_spec: &str, requested_spec: &str) -> bool {
    let p = pattern_spec.trim();
    let r = requested_spec.trim();
    if p == r {
        return true;
    }

    // Wildcards: "*" or "x" or "X" match anything
    if p == "*" || p.eq_ignore_ascii_case("x") {
        return true;
    }

    // Try semver range matching if requested_spec is an exact version
    if let (Ok(p_range), Ok(r_ver)) = (Range::parse(p), Version::parse(r)) {
        return p_range.satisfies(&r_ver);
    }

    // If both can be parsed as ranges, check if requested range's lower bound satisfies pattern range
    if let (Ok(p_range), Ok(r_range)) = (Range::parse(p), Range::parse(r)) {
        if let Some(first_set) = r_range.sets.first() {
            if let Some(first_comp) = first_set.comparators.first() {
                if p_range.satisfies(&first_comp.version) {
                    return true;
                }
            }
        }
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

        let res = overrides.resolve_override("semver", "^6.3.0", &["foo", "bar"]);
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
        let under_foo = overrides.resolve_override("bar", "^1.0.0", &["foo"]);
        assert_eq!(under_foo, Some("2.0.0".to_string()));

        // Under qux: not overridden
        let under_qux = overrides.resolve_override("bar", "^1.0.0", &["qux"]);
        assert_eq!(under_qux, None);
    }

    #[test]
    fn test_spec_targeted_override() {
        let json = serde_json::json!({
            "debug@^2.0.0": "2.6.9"
        });
        let overrides = Overrides::from_json_value(Some(&json), BTreeMap::new());

        let match_spec = overrides.resolve_override("debug", "^2.0.0", &[]);
        assert_eq!(match_spec, Some("2.6.9".to_string()));

        let no_match = overrides.resolve_override("debug", "^4.0.0", &[]);
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

        let res = overrides.resolve_override("foo", "^2.0.0", &["parent"]);
        assert_eq!(res, Some("1.2.3".to_string()));
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
        assert_eq!(overrides.resolve_override("bar", "^1.0.0", &["foo"]), Some("2.0.0".to_string()));

        // Under foo: baz is 3.0.0
        assert_eq!(overrides.resolve_override("baz", "^1.0.0", &["foo"]), Some("3.0.0".to_string()));

        // Under @scope/a: @scope/b is 1.0.0
        assert_eq!(overrides.resolve_override("@scope/b", "*", &["@scope/a"]), Some("1.0.0".to_string()));

        // Under a > b: c is 4.0.0
        assert_eq!(overrides.resolve_override("c", "^1.0.0", &["a", "b"]), Some("4.0.0".to_string()));

        // Under nested > x: y is 5.0.0
        assert_eq!(overrides.resolve_override("y", "^1.0.0", &["nested", "x"]), Some("5.0.0".to_string()));

        // Top level lookup for bar should be None
        assert_eq!(overrides.resolve_override("bar", "^1.0.0", &[]), None);
    }
}
