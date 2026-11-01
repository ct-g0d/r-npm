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
    pub fn from_json_value(
        value: Option<&serde_json::Value>,
        root_dependencies: BTreeMap<String, String>,
    ) -> Self {
        let rules = if let Some(val) = value {
            serde_json::from_value::<BTreeMap<String, OverrideValue>>(val.clone())
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Self::new(rules, root_dependencies)
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

    fn find_in_nested<'a>(
        &self,
        rules: &'a BTreeMap<String, OverrideValue>,
        ancestors: &[&str],
        dep_name: &str,
        requested_spec: &str,
    ) -> Option<&'a OverrideValue> {
        if ancestors.is_empty() {
            return self.find_direct(rules, dep_name, requested_spec);
        }

        let parent = ancestors[0];
        for (k, v) in rules {
            let matches_parent = if let Some((k_name, _)) = parse_key_and_spec(k) {
                k_name == parent
            } else {
                k == parent
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

    // Try semver range matching if both can be parsed as ranges
    if let (Ok(p_range), Ok(r_ver)) = (Range::parse(p), Version::parse(r)) {
        return p_range.satisfies(&r_ver);
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
}
