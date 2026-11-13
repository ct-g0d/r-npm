use super::InspectedNode;
use rnpm_core::semver::{Op, Range, Version};
use serde_json::Value;

fn split_key(key: &str) -> (&str, &str) {
    let start = usize::from(key.starts_with('@'));
    key[start..].find('@').map_or((key, "*"), |at| {
        (&key[..start + at], &key[start + at + 1..])
    })
}

fn intersects(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (Range::parse(a), Range::parse(b)) else {
        return true;
    };
    // Every satisfiable comparator intersection has a lower-bound witness.
    for left in &a.sets {
        for right in &b.sets {
            let mut candidates = vec![Version::new(0, 0, 0)];
            for comp in left.comparators.iter().chain(&right.comparators) {
                candidates.push(comp.version.clone());
                if comp.op == Op::Gt {
                    let mut after = comp.version.clone();
                    after.patch += 1;
                    candidates.push(after);
                }
            }
            if candidates
                .iter()
                .any(|v| left.matches(v) && right.matches(v))
            {
                return true;
            }
        }
    }
    false
}

fn walk(
    node: &mut InspectedNode,
    scopes: &[Value],
    root_manifest: &Value,
    repaired: &mut Vec<String>,
) {
    for child in node.dependencies.values_mut() {
        let raw_spec = child.required.clone().unwrap_or_else(|| "*".to_string());
        let rule = scopes.iter().rev().find_map(|scope| {
            scope
                .as_object()
                .into_iter()
                .flatten()
                .find(|(key, _)| {
                    let (name, spec) = split_key(key);
                    name == child.name && intersects(spec, &raw_spec)
                })
                .map(|(_, rule)| rule.clone())
        });
        let mut child_scopes = scopes.to_vec();
        if let Some(rule) = rule {
            let replacement = rule
                .as_str()
                .or_else(|| rule.get(".").and_then(Value::as_str));
            if let Some(replacement) = replacement {
                let replacement = if let Some(reference) = replacement.strip_prefix('$') {
                    [
                        "dependencies",
                        "devDependencies",
                        "optionalDependencies",
                        "peerDependencies",
                    ]
                    .iter()
                    .find_map(|section| root_manifest[*section][reference].as_str())
                    .unwrap_or(replacement)
                } else if replacement.is_empty() {
                    "*"
                } else {
                    replacement
                };
                child.overridden = true;
                child.required = Some(replacement.to_string());
                if child
                    .version
                    .as_deref()
                    .and_then(|v| Version::parse(v).ok())
                    .zip(Range::parse(replacement).ok())
                    .is_some_and(|(v, r)| r.satisfies(&v))
                {
                    child.invalid = None;
                    child.problems.retain(|p| !p.starts_with("invalid:"));
                    if let Some(path) = &child.path {
                        repaired.push(path.display().to_string());
                    }
                }
            }
            if rule.is_object() {
                child_scopes.push(rule);
            }
        }
        walk(child, &child_scopes, root_manifest, repaired);
    }
}

pub(super) fn apply(root: &mut InspectedNode) {
    let manifest = root.raw_manifest.clone().unwrap_or_default();
    let Some(overrides) = manifest.get("overrides") else {
        return;
    };
    let mut repaired = Vec::new();
    walk(
        root,
        std::slice::from_ref(overrides),
        &manifest,
        &mut repaired,
    );
    root.problems
        .retain(|p| !p.starts_with("invalid:") || !repaired.iter().any(|path| p.ends_with(path)));
}
