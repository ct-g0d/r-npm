use crate::error::OverrideError;
use crate::manifest::Manifest;
use crate::semver::{
    comparator::{Comparator, Op},
    range::{try_parse_fast_set_stack, ComparatorSet, StackComparator},
    Range, Version,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Value in an override definition: either an exact spec string or a nested map of overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OverrideValue {
    Exact(String),
    Nested(BTreeMap<String, OverrideValue>),
}

/// Pre-compiled pattern for an override rule key or target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecompiledPattern {
    Any,
    ExactVersion(Version),
    SemverRange(Range),
    Raw(String),
}

impl PrecompiledPattern {
    pub fn compile(raw_spec: &str) -> Self {
        let mut p = raw_spec.trim();
        p = p.strip_prefix("workspace:").unwrap_or(p).trim();
        let p_extracted = extract_semver_range_from_spec(p);
        let p_str = p_extracted.as_deref().unwrap_or(p).trim();

        if p_str == "*"
            || p_str == "^"
            || p_str == "~"
            || p_str.is_empty()
            || p_str.eq_ignore_ascii_case("x")
        {
            return PrecompiledPattern::Any;
        }

        if let Ok(ver) = Version::parse(p_str) {
            return PrecompiledPattern::ExactVersion(ver);
        }

        if let Ok(range) = Range::parse(p_str) {
            return PrecompiledPattern::SemverRange(range);
        }

        PrecompiledPattern::Raw(p_str.to_string())
    }

    pub fn matches(&self, requested_spec: &str) -> bool {
        let mut r = requested_spec.trim();
        if matches!(self, PrecompiledPattern::Any) {
            return true;
        }

        r = r.strip_prefix("workspace:").unwrap_or(r).trim();
        if r == "*" || r == "^" || r == "~" || r.is_empty() || r.eq_ignore_ascii_case("x") {
            return true;
        }

        if let Some(rest) = r.strip_prefix("npm:") {
            if let Some((_, sub_spec)) = parse_key_and_spec(rest) {
                r = sub_spec;
            } else if let Some(at_idx) = rest.rfind('@') {
                r = &rest[at_idx + 1..];
            } else {
                r = "*";
            }
            if r == "*" || r == "^" || r == "~" || r.is_empty() || r.eq_ignore_ascii_case("x") {
                return true;
            }
        }

        let r_extracted = if r.contains('#') {
            extract_semver_range_from_spec(r)
        } else {
            None
        };
        let r_str = r_extracted.as_deref().unwrap_or(r).trim();
        if r_str == "*" || r_str.eq_ignore_ascii_case("x") {
            return true;
        }

        match self {
            PrecompiledPattern::Any => true,
            PrecompiledPattern::ExactVersion(p_ver) => {
                Range::satisfies_str(r_str, p_ver).unwrap_or(false)
            }
            PrecompiledPattern::SemverRange(p_range) => {
                if let Some(res) = ranges_intersect_simple_str(p_range, r_str) {
                    return res;
                }
                if !r_str
                    .as_bytes()
                    .first()
                    .is_some_and(|&b| matches!(b, b'^' | b'~' | b'>' | b'<'))
                {
                    if let Ok(r_ver) = Version::parse(r_str) {
                        return p_range.satisfies(&r_ver);
                    }
                }
                if let Ok(r_range) = Range::parse(r_str) {
                    return ranges_intersect(p_range, &r_range);
                }
                false
            }
            PrecompiledPattern::Raw(s) => s == r_str,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompiledRule {
    pub raw_key: String,
    pub pkg_name: String,
    pub pattern: PrecompiledPattern,
    pub has_spec: bool,
    pub nested: Option<PrecompiledNode>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrecompiledNode {
    pub rules_by_pkg: BTreeMap<String, Vec<PrecompiledRule>>,
}

impl PrecompiledNode {
    pub fn compile(
        rules: &BTreeMap<String, OverrideValue>,
        all_targets: &mut HashSet<String>,
    ) -> Self {
        let mut rules_by_pkg: BTreeMap<String, Vec<PrecompiledRule>> = BTreeMap::new();

        for (k, v) in rules {
            let (k_name, k_spec, has_spec) = if let Some((name, spec)) = parse_key_and_spec(k) {
                (name, spec, true)
            } else {
                (k.as_str(), "", false)
            };

            all_targets.insert(k_name.to_string());

            let pattern = if has_spec {
                PrecompiledPattern::compile(k_spec)
            } else {
                PrecompiledPattern::Any
            };

            let nested = if let OverrideValue::Nested(ref sub_map) = v {
                Some(PrecompiledNode::compile(sub_map, all_targets))
            } else {
                None
            };

            let rule = PrecompiledRule {
                raw_key: k.clone(),
                pkg_name: k_name.to_string(),
                pattern,
                has_spec,
                nested,
            };

            rules_by_pkg
                .entry(k_name.to_string())
                .or_default()
                .push(rule);
        }

        Self { rules_by_pkg }
    }

    pub fn find_direct<'a>(
        &self,
        rules: &'a BTreeMap<String, OverrideValue>,
        dep_name: &str,
        requested_spec: &str,
    ) -> Option<&'a OverrideValue> {
        let rule_list = self.rules_by_pkg.get(dep_name)?;

        // 1. Check spec-targeted overrides in declaration order
        for rule in rule_list {
            if rule.has_spec && rule.pattern.matches(requested_spec) {
                return rules.get(&rule.raw_key);
            }
        }

        // 2. Check exact package name override (e.g. "semver")
        for rule in rule_list {
            if !rule.has_spec {
                return rules.get(&rule.raw_key);
            }
        }

        None
    }

    pub fn find_in_nested<'a, T: AsRef<str>>(
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

        let rule_list = self.rules_by_pkg.get(parent_name)?;

        for rule in rule_list {
            let (Some(ref nested_node), Some(OverrideValue::Nested(ref nested_map))) =
                (&rule.nested, rules.get(&rule.raw_key))
            else {
                continue;
            };

            let matches_parent = if rule.has_spec && !parent_ver.is_empty() {
                rule.pattern.matches(parent_ver)
            } else {
                true
            };

            if matches_parent {
                if ancestors.len() > 1 {
                    for next_idx in 1..ancestors.len() {
                        if let Some(res) = nested_node.find_in_nested(
                            nested_map,
                            &ancestors[next_idx..],
                            dep_name,
                            requested_spec,
                        ) {
                            return Some(res);
                        }
                    }
                }
                if let Some(res) = nested_node.find_direct(nested_map, dep_name, requested_spec) {
                    return Some(res);
                }
            }
        }

        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompiledOverrides {
    pub all_target_names: HashSet<String>,
    pub root_node: PrecompiledNode,
    pub rules_snapshot: BTreeMap<String, OverrideValue>,
    pub rules_len: usize,
    pub compiled: bool,
}

impl Default for PrecompiledOverrides {
    fn default() -> Self {
        Self {
            all_target_names: HashSet::new(),
            root_node: PrecompiledNode::default(),
            rules_snapshot: BTreeMap::new(),
            rules_len: 0,
            compiled: true,
        }
    }
}

impl PrecompiledOverrides {
    pub fn compile(rules: &BTreeMap<String, OverrideValue>) -> Self {
        let mut all_targets = HashSet::new();
        let root_node = PrecompiledNode::compile(rules, &mut all_targets);
        Self {
            all_target_names: all_targets,
            root_node,
            rules_snapshot: rules.clone(),
            rules_len: rules.len(),
            compiled: true,
        }
    }

    pub fn matches_rules(&self, rules: &BTreeMap<String, OverrideValue>) -> bool {
        self.compiled && self.rules_len == rules.len() && &self.rules_snapshot == rules
    }
}

/// Overrides engine implementing npm RFC 36 package overrides.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub rules: BTreeMap<String, OverrideValue>,
    /// Root dependencies map (for reference overrides like `"$foo"`).
    pub root_dependencies: BTreeMap<String, String>,
    indexed: PrecompiledOverrides,
}

impl PartialEq for Overrides {
    fn eq(&self, other: &Self) -> bool {
        self.rules == other.rules && self.root_dependencies == other.root_dependencies
    }
}

impl Eq for Overrides {}

impl Overrides {
    pub fn new(
        rules: BTreeMap<String, OverrideValue>,
        root_dependencies: BTreeMap<String, String>,
    ) -> Self {
        let indexed = PrecompiledOverrides::compile(&rules);
        Self {
            rules,
            root_dependencies,
            indexed,
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
        let Some(overrides_val) = manifest.extra.get("overrides") else {
            return Ok(Self::default());
        };
        let mut rules = BTreeMap::new();
        parse_overrides_into_map(overrides_val, &mut rules);
        if rules.is_empty() {
            return Ok(Self::default());
        }
        Ok(Self::new(rules, Self::reference_specs(manifest)))
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

        let fallback_indexed;
        let indexed = if self.indexed.matches_rules(&self.rules) {
            &self.indexed
        } else {
            fallback_indexed = PrecompiledOverrides::compile(&self.rules);
            &fallback_indexed
        };

        // O(1) fast check: If dep_name is not targeted anywhere in overrides, exit immediately
        if !indexed.all_target_names.contains(dep_name) {
            return Ok(None);
        }

        let mut matched_val = None;

        // 1. Check nested scoped overrides along ancestor chain
        for i in 0..ancestors.len() {
            let slice = &ancestors[i..];
            if let Some(val) = indexed.root_node.find_in_nested(&self.rules, slice, dep_name, requested_spec) {
                matched_val = Some(val);
                break;
            }
        }

        // 2. If no nested override matched, check top-level global overrides
        if matched_val.is_none() {
            matched_val = indexed.root_node.find_direct(&self.rules, dep_name, requested_spec);
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

    let mut parts = Vec::with_capacity(2);
    let bytes = key.as_bytes();
    let mut last_idx = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'>' && !is_comparator_gt(key, i, last_idx) {
            let trimmed = key[last_idx..i].trim();
            if !trimmed.is_empty() {
                parts.push(trimmed.to_string());
            }
            last_idx = i + 1;
        }
        i += 1;
    }

    let trimmed = key[last_idx..].trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }

    if parts.is_empty() {
        vec![key.trim().to_string()]
    } else {
        parts
    }
}

/// Checks whether a `>` character at byte index `i` is a semver comparator (e.g. `>=1.0.0`, `>1.0.0`, `@ > 1.0.0`)
/// rather than an override arrow separator `>`.
fn is_comparator_gt(key: &str, i: usize, segment_start: usize) -> bool {
    let bytes = key.as_bytes();
    // 1. Always treat `>=` as a comparator
    if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
        return true;
    }

    // 2. Must be in a version context (after a version '@')
    if !has_version_context(&bytes[segment_start..i]) {
        return false;
    }

    // 3. In a version context, '>' followed by a digit or 'v' + digit is a comparator (e.g. `>1.0.0`, `> 1.0.0`)
    let mut rem = key[i + 1..].trim_start().as_bytes();
    if rem.is_empty() {
        return false;
    }
    if rem[0].is_ascii_digit() {
        return true;
    }
    if (rem[0] == b'v' || rem[0] == b'V') && rem.len() > 1 {
        rem = &rem[1..];
        return rem[0].is_ascii_digit();
    }
    false
}

/// Checks whether there is a version specifier '@' within `segment`.
/// A leading '@' (e.g. `@scope/pkg`) is a package scope prefix, not a version specifier.
fn has_version_context(segment: &[u8]) -> bool {
    let mut at_count = 0usize;
    let mut first_non_ws_is_at = false;
    let mut found_first_non_ws = false;

    for &b in segment {
        if !found_first_non_ws && !b.is_ascii_whitespace() && b < 0x80 {
            found_first_non_ws = true;
            if b == b'@' {
                first_non_ws_is_at = true;
            }
        }
        if b == b'@' {
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
        if self.indexed.matches_rules(&self.rules) {
            return self.indexed.all_target_names.contains(name);
        }
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

/// Tests whether version `v` satisfies comparator `c` under node-semver rules:
/// - `v` must satisfy the comparison operator `c.op`
/// - If `v` is a prerelease, `c` must also have a prerelease with the same (major, minor, patch) tuple
fn single_comparator_matches(c: &Comparator, v: &Version) -> bool {
    if !c.matches(v) {
        return false;
    }
    if v.is_prerelease() {
        return c.version.is_prerelease()
            && c.version.major == v.major
            && c.version.minor == v.minor
            && c.version.patch == v.patch;
    }
    true
}

/// Determines if two semver comparators intersect, matching node-semver `Comparator.prototype.intersects`.
fn comparator_intersects(c1: &Comparator, c2: &Comparator) -> bool {
    // 1. If either comparator is equality / exact version:
    if c1.op == Op::Eq {
        return single_comparator_matches(c2, &c1.version);
    }
    if c2.op == Op::Eq {
        return single_comparator_matches(c1, &c2.version);
    }

    // 2. Special case: <0.0.0 or <0.0.0-0 can match no version in semver
    if (c1.op == Op::Lt && c1.version.major == 0 && c1.version.minor == 0 && c1.version.patch == 0)
        || (c2.op == Op::Lt && c2.version.major == 0 && c2.version.minor == 0 && c2.version.patch == 0)
    {
        return false;
    }

    // 3. Same direction increasing (> or >=)
    let c1_inc = matches!(c1.op, Op::Gt | Op::Gte);
    let c2_inc = matches!(c2.op, Op::Gt | Op::Gte);
    if c1_inc && c2_inc {
        return true;
    }

    // 4. Same direction decreasing (< or <=)
    let c1_dec = matches!(c1.op, Op::Lt | Op::Lte);
    let c2_dec = matches!(c2.op, Op::Lt | Op::Lte);
    if c1_dec && c2_dec {
        return true;
    }

    // 5. Same SemVer and both sides are inclusive (<= or >=)
    if c1.version == c2.version
        && matches!(c1.op, Op::Gte | Op::Lte)
        && matches!(c2.op, Op::Gte | Op::Lte)
    {
        return true;
    }

    // 6. Opposite directions: increasing < decreasing
    if c1_inc && c2_dec && c1.version < c2.version {
        return true;
    }
    if c1_dec && c2_inc && c1.version > c2.version {
        return true;
    }

    false
}

/// Checks if a comparator set is internally satisfiable, matching node-semver `isSatisfiable`.
fn is_set_satisfiable(cs: &ComparatorSet) -> bool {
    let comps = &cs.comparators;
    for i in 0..comps.len() {
        for j in i + 1..comps.len() {
            if !comparator_intersects(&comps[i], &comps[j]) {
                return false;
            }
        }
    }
    true
}

/// Checks if two ComparatorSets intersect (every pair across sets intersects and both are satisfiable),
/// matching node-semver `Range.prototype.intersects`.
fn comparator_sets_intersect(cs1: &ComparatorSet, cs2: &ComparatorSet) -> bool {
    if !is_set_satisfiable(cs1) || !is_set_satisfiable(cs2) {
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

/// Compares a full `Version` against a stack-allocated `StackComparator` tuple.
#[inline]
fn cmp_version_to_stack(v: &Version, s: &StackComparator) -> Ordering {
    match (v.major, v.minor, v.patch).cmp(&(s.major, s.minor, s.patch)) {
        Ordering::Equal => match (v.prerelease.is_empty(), s.is_upper_pre0) {
            (true, false) => Ordering::Equal,
            (true, true) => Ordering::Greater,
            (false, false) => Ordering::Less,
            (false, true) => {
                // Compare v.prerelease against [Numeric(0)]
                let p0 = match v.prerelease.first() {
                    Some(crate::semver::version::PrereleaseId::Numeric(0)) => Ordering::Equal,
                    Some(crate::semver::version::PrereleaseId::Numeric(_)) => Ordering::Greater,
                    Some(crate::semver::version::PrereleaseId::Alpha(_)) => Ordering::Greater,
                    None => Ordering::Greater,
                };
                match p0 {
                    Ordering::Equal => v.prerelease.len().cmp(&1),
                    ord => ord,
                }
            }
        },
        ord => ord,
    }
}

#[inline]
fn eval_op_ord(op: Op, ord: Ordering) -> bool {
    match op {
        Op::Eq => ord == Ordering::Equal,
        Op::Gt => ord == Ordering::Greater,
        Op::Gte => ord != Ordering::Less,
        Op::Lt => ord == Ordering::Less,
        Op::Lte => ord != Ordering::Greater,
    }
}

#[inline]
fn single_comp_matches_stack(c: &Comparator, s: &StackComparator) -> bool {
    let rev = cmp_version_to_stack(&c.version, s).reverse();
    if !eval_op_ord(c.op, rev) {
        return false;
    }
    !s.is_upper_pre0
        || (c.version.is_prerelease()
            && c.version.major == s.major
            && c.version.minor == s.minor
            && c.version.patch == s.patch)
}

#[inline]
fn stack_comp_matches_version(s: &StackComparator, v: &Version) -> bool {
    let ord = cmp_version_to_stack(v, s);
    if !eval_op_ord(s.op, ord) {
        return false;
    }
    !v.is_prerelease()
        || (s.is_upper_pre0 && s.major == v.major && s.minor == v.minor && s.patch == v.patch)
}

#[inline]
fn cmp_stack_pair(a: &StackComparator, b: &StackComparator) -> Ordering {
    match (a.major, a.minor, a.patch).cmp(&(b.major, b.minor, b.patch)) {
        Ordering::Equal => match (a.is_upper_pre0, b.is_upper_pre0) {
            (true, true) | (false, false) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        },
        ord => ord,
    }
}

#[inline]
fn bounds_intersect(op1: Op, is_lt0_1: bool, op2: Op, is_lt0_2: bool, ord: Ordering) -> bool {
    if is_lt0_1 || is_lt0_2 {
        return false;
    }
    let inc1 = matches!(op1, Op::Gt | Op::Gte);
    let inc2 = matches!(op2, Op::Gt | Op::Gte);
    let dec1 = matches!(op1, Op::Lt | Op::Lte);
    let dec2 = matches!(op2, Op::Lt | Op::Lte);
    (inc1 && inc2)
        || (dec1 && dec2)
        || (ord == Ordering::Equal && matches!(op1, Op::Gte | Op::Lte) && matches!(op2, Op::Gte | Op::Lte))
        || (inc1 && dec2 && ord == Ordering::Less)
        || (dec1 && inc2 && ord == Ordering::Greater)
}

#[inline]
fn stack_comparator_intersects(s1: &StackComparator, s2: &StackComparator) -> bool {
    if s1.op == Op::Eq {
        return eval_op_ord(s2.op, cmp_stack_pair(s1, s2))
            && (!s1.is_upper_pre0
                || (s2.is_upper_pre0
                    && s2.major == s1.major
                    && s2.minor == s1.minor
                    && s2.patch == s1.patch));
    }
    if s2.op == Op::Eq {
        return eval_op_ord(s1.op, cmp_stack_pair(s2, s1))
            && (!s2.is_upper_pre0
                || (s1.is_upper_pre0
                    && s1.major == s2.major
                    && s1.minor == s2.minor
                    && s1.patch == s2.patch));
    }
    bounds_intersect(
        s1.op,
        s1.op == Op::Lt && s1.major == 0 && s1.minor == 0 && s1.patch == 0,
        s2.op,
        s2.op == Op::Lt && s2.major == 0 && s2.minor == 0 && s2.patch == 0,
        cmp_stack_pair(s1, s2),
    )
}

#[inline]
fn comparator_stack_intersects(c: &Comparator, s: &StackComparator) -> bool {
    if c.op == Op::Eq {
        return stack_comp_matches_version(s, &c.version);
    }
    if s.op == Op::Eq {
        return single_comp_matches_stack(c, s);
    }
    bounds_intersect(
        c.op,
        c.op == Op::Lt && c.version.major == 0 && c.version.minor == 0 && c.version.patch == 0,
        s.op,
        s.op == Op::Lt && s.major == 0 && s.minor == 0 && s.patch == 0,
        cmp_version_to_stack(&c.version, s),
    )
}

/// Zero-allocation fast path checking if `r1` intersects a simple single-set semver string `r2_str`.
#[inline]
fn ranges_intersect_simple_str(r1: &Range, r2_str: &str) -> Option<bool> {
    if r1.sets.is_empty() {
        return Some(false);
    }
    let mut s2_buf = [StackComparator::new(Op::Eq, 0, 0, 0, false); 4];
    let s2_len = try_parse_fast_set_stack(r2_str, &mut s2_buf)?;
    let s2 = &s2_buf[..s2_len];

    // Check internal satisfiability of s2
    for i in 0..s2.len() {
        for j in i + 1..s2.len() {
            if !stack_comparator_intersects(&s2[i], &s2[j]) {
                return Some(false);
            }
        }
    }

    if r1.is_wildcard() {
        return Some(true);
    }

    if s2.len() == 1 && s2[0].is_wildcard() {
        return Some(r1.sets.iter().any(|s| {
            is_set_satisfiable(s)
                && !s.comparators.iter().any(|c| c.op == Op::Eq && c.version.is_prerelease())
        }));
    }

    for set1 in &r1.sets {
        if !is_set_satisfiable(set1) {
            continue;
        }
        let mut all_ok = true;
        'pair: for c1 in &set1.comparators {
            for c2 in s2 {
                if !comparator_stack_intersects(c1, c2) {
                    all_ok = false;
                    break 'pair;
                }
            }
        }
        if all_ok {
            return Some(true);
        }
    }
    Some(false)
}

/// Checks if two semver Ranges intersect, matching node-semver `semver.intersects(r1, r2)`.
pub fn ranges_intersect(r1: &Range, r2: &Range) -> bool {
    if r1.sets.is_empty() || r2.sets.is_empty() {
        return false;
    }
    // node-semver Comparator.prototype.intersects handles wildcard / empty comparator:
    // When r1 is wildcard, any satisfiable r2 intersects.
    if r1.is_wildcard() {
        return r2.sets.iter().any(is_set_satisfiable);
    }
    // When r2 is wildcard, r1 intersects unless r1 is exclusively an exact prerelease version
    if r2.is_wildcard() {
        return r1.sets.iter().any(|s| {
            is_set_satisfiable(s)
                && !s.comparators.iter().any(|c| c.op == Op::Eq && c.version.is_prerelease())
        });
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

fn percent_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(h1), Some(h2)) = (h1, h2) {
                if let Ok(val) =
                    u8::from_str_radix(std::str::from_utf8(&[h1, h2]).unwrap_or(""), 16)
                {
                    bytes.push(val);
                    continue;
                }
                bytes.push(b'%');
                bytes.push(h1);
                bytes.push(h2);
            } else {
                bytes.push(b'%');
                if let Some(h1) = h1 {
                    bytes.push(h1);
                }
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
}

fn extract_semver_range_from_spec(spec: &str) -> Option<String> {
    let hash_idx = spec.find('#')?;
    let fragment = spec[hash_idx + 1..].trim();
    let raw = fragment
        .strip_prefix("semver:")
        .or_else(|| fragment.strip_prefix("semver%3A"))
        .or_else(|| fragment.strip_prefix("semver%3a"))?;
    Some(percent_decode(raw).trim().to_string())
}

/// Determines if the requested spec matches the pattern spec in a spec-targeted override.
#[allow(dead_code)]
pub fn spec_matches(pattern_spec: &str, requested_spec: &str) -> bool {
    PrecompiledPattern::compile(pattern_spec).matches(requested_spec)
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
        root_deps.insert("pkg-c".to_string(), "$pkg-d".to_string());
        root_deps.insert("pkg-d".to_string(), "$pkg-c".to_string());

        let overrides = Overrides::from_json_value(Some(&json), root_deps);

        // Chained reference $pkg-a -> $pkg-b -> $pkg-final -> 1.2.3
        let res = overrides.resolve_override("pkg-a", "^1.0.0", &[]).unwrap();
        assert_eq!(res, Some("1.2.3".to_string()));

        // Cyclic reference $pkg-c -> $pkg-d -> $pkg-c must return error, not hang or panic
        let err = overrides.resolve_override("pkg-c", "^1.0.0", &[]);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("cyclic"));
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

    #[test]
    fn test_node_semver_intersection_full_suite() {
        // Prerelease tuple matching against caret ranges:
        let r_caret = Range::parse("^1.0.0-alpha.1").unwrap();
        assert!(!ranges_intersect(&r_caret, &Range::parse("1.0.0-alpha.1").unwrap()));
        assert!(!ranges_intersect(&r_caret, &Range::parse("1.0.0-alpha.2").unwrap()));
        assert!(!ranges_intersect(&r_caret, &Range::parse("1.0.0-beta.1").unwrap()));
        assert!(ranges_intersect(&r_caret, &Range::parse("1.0.0").unwrap()));
        assert!(!ranges_intersect(&r_caret, &Range::parse("2.0.0").unwrap()));

        // Empty ranges & wildcards (node-semver semantics):
        let r_empty1 = Range::parse("").unwrap();
        let r_empty2 = Range::parse("").unwrap();
        let r_star = Range::parse("*").unwrap();
        let r_stable = Range::parse("1.0.0").unwrap();
        let r_pre = Range::parse("1.0.0-alpha.1").unwrap();
        assert!(ranges_intersect(&r_empty1, &r_empty2));
        assert!(ranges_intersect(&r_empty1, &r_star));
        assert!(ranges_intersect(&r_empty1, &r_stable));
        // * and "" intersect with prereleases when wildcard is left operand in node-semver:
        assert!(ranges_intersect(&r_empty1, &r_pre));
        assert!(ranges_intersect(&r_star, &r_pre));
        // Reverse direction: exact prerelease against wildcard does not intersect in node-semver:
        assert!(!ranges_intersect(&r_pre, &r_empty1));
        assert!(!ranges_intersect(&r_pre, &r_star));
        // node-semver normalizes >=0.0.0 (and *.*, x.x.x) to ANY, while >=0.0.0-0 has a prerelease:
        assert!(ranges_intersect(&Range::parse(">=0.0.0").unwrap(), &r_pre));
        assert!(!ranges_intersect(&r_pre, &Range::parse(">=0.0.0").unwrap()));
        assert!(!ranges_intersect(&Range::parse(">=0.0.0-0").unwrap(), &r_pre));

        // >=1.0.0-0 checks:
        let r_ge_zero = Range::parse(">=1.0.0-0").unwrap();
        assert!(ranges_intersect(&r_ge_zero, &Range::parse("<1.0.0").unwrap()));
        assert!(ranges_intersect(&r_ge_zero, &Range::parse(">=1.0.0").unwrap()));
        assert!(!ranges_intersect(&r_ge_zero, &Range::parse("<1.0.0-0").unwrap()));

        // Non-overlapping prerelease range vs wider stable range:
        let r_alpha_beta = Range::parse(">1.0.0-alpha.1 <1.0.0-beta.1").unwrap();
        let r_wide = Range::parse(">0.9.0 <2.0.0").unwrap();
        assert!(ranges_intersect(&r_alpha_beta, &r_wide));

        // Overlapping lower bounds:
        let r_alpha1_lt1 = Range::parse(">=1.0.0-alpha.1 <1.0.0").unwrap();
        let r_alpha2 = Range::parse(">=1.0.0-alpha.2").unwrap();
        assert!(ranges_intersect(&r_alpha1_lt1, &r_alpha2));

        // Multi-comparator OR ranges:
        let r_or = Range::parse("1.0.0 || 2.0.0").unwrap();
        assert!(ranges_intersect(&r_or, &Range::parse("2.0.0").unwrap()));
        assert!(!ranges_intersect(&r_or, &Range::parse("3.0.0").unwrap()));

        // Strict less than vs greater-or-equal on exact same version:
        let r_lt_alpha = Range::parse("<1.0.0-alpha.1").unwrap();
        let r_gte_alpha = Range::parse(">=1.0.0-alpha.1").unwrap();
        assert!(!ranges_intersect(&r_lt_alpha, &r_gte_alpha));

        // Impossible ranges <0.0.0 against non-wildcard comparators:
        let r_impossible = Range::parse("<0.0.0").unwrap();
        assert!(!ranges_intersect(&r_impossible, &Range::parse("<1.0.0").unwrap()));
        assert!(!ranges_intersect(&r_impossible, &Range::parse(">=1.0.0").unwrap()));
        assert!(ranges_intersect(&r_impossible, &r_star));
    }

    #[test]
    fn test_spec_matches_ancestor_prereleases_and_url_encoded_semver() {
        // Ancestor version matching rule keySpec per Arborist override-set:
        // ^1.0.0-alpha.1 satisfies 1.0.0-alpha.1 and 1.0.0-alpha.2
        assert!(spec_matches("^1.0.0-alpha.1", "1.0.0-alpha.1"));
        assert!(spec_matches("^1.0.0-alpha.1", "1.0.0-alpha.2"));
        assert!(spec_matches("^1.0.0-alpha.1", "1.0.0"));
        assert!(!spec_matches("^1.0.0-alpha.1", "2.0.0"));

        // URL-encoded #semver%3A and #semver%3a in requested spec:
        assert!(spec_matches(
            "^1.5.0",
            "git+https://github.com/org/repo.git#semver:^1.0.0"
        ));
        assert!(spec_matches(
            "^1.5.0",
            "git+https://github.com/org/repo.git#semver%3A^1.0.0"
        ));
        assert!(spec_matches(
            "^1.5.0",
            "git+https://github.com/org/repo.git#semver%3a%5E1.0.0"
        ));
        assert!(!spec_matches(
            "^2.0.0",
            "git+https://github.com/org/repo.git#semver%3A^1.0.0"
        ));

        // Symmetric workspace: prefix stripping in spec_matches:
        assert!(spec_matches("workspace:^1.0.0", "^1.2.0"));
        assert!(spec_matches("workspace:^1.0.0", "workspace:^1.2.0"));
        assert!(spec_matches("workspace:*", "^1.0.0"));
        assert!(!spec_matches("workspace:^2.0.0", "^1.2.0"));

        // Normalized wildcard variants (*.*, x.x.x) intersect with prereleases on the left:
        let r_pre = Range::parse("1.0.0-alpha.1").unwrap();
        assert!(ranges_intersect(&Range::parse("*.*").unwrap(), &r_pre));
        assert!(ranges_intersect(&Range::parse("x.x.x").unwrap(), &r_pre));
        assert!(!ranges_intersect(&r_pre, &Range::parse("*.*").unwrap()));
    }
}
