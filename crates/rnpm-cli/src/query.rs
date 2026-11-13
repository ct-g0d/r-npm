use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::inspect_tree::{build_dependency_tree, InspectedNode, TreeOptions};
use rnpm_core::semver::{Range, Version};

/// Options for query command.
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    pub selector: Option<String>,
    pub package_lock_only: bool,
    pub registry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrOp {
    Exact,     // =
    Prefix,    // ^=
    Suffix,    // $=
    Substring, // *=
    Tilde,     // ~=
    Dash,      // |=
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleSelector {
    Universal,
    Type(String),
    Class(String),
    PseudoClass {
        name: String,
        arg: Option<String>,
    },
    Attribute {
        name: String,
        op: Option<AttrOp>,
        val: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Combinator {
    Child,      // >
    Descendant, // ' '
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundSelector {
    pub simple: Vec<SimpleSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplexSelector {
    pub head: CompoundSelector,
    pub tail: Vec<(Combinator, CompoundSelector)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySelector {
    pub selectors: Vec<ComplexSelector>,
}

impl QuerySelector {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Ok(QuerySelector {
                selectors: vec![ComplexSelector {
                    head: CompoundSelector {
                        simple: vec![SimpleSelector::Universal],
                    },
                    tail: Vec::new(),
                }],
            });
        }

        // Split by top-level commas (union)
        let comma_splits = split_top_level_commas(trimmed)?;
        let mut selectors = Vec::new();

        for part in comma_splits {
            let s = parse_complex_selector(part.trim())?;
            selectors.push(s);
        }

        Ok(QuerySelector { selectors })
    }
}

fn split_top_level_commas(s: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0;
    let mut bracket_depth = 0;
    let mut in_quotes = None;

    for ch in s.chars() {
        if let Some(q) = in_quotes {
            current.push(ch);
            if ch == q {
                in_quotes = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_quotes = Some(ch);
                current.push(ch);
            }
            '(' => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' => {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
                current.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                current.push(ch);
            }
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    Ok(parts)
}

fn parse_complex_selector(s: &str) -> Result<ComplexSelector, String> {
    let tokens = tokenize_selector(s)?;
    if tokens.is_empty() {
        return Err("Empty selector".to_string());
    }

    let mut compound_tokens: Vec<Vec<String>> = Vec::new();
    let mut combinators: Vec<Combinator> = Vec::new();
    let mut current_compound = Vec::new();

    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok == ">" {
            if current_compound.is_empty() {
                return Err("Unexpected '>' at start or duplicate combinator".to_string());
            }
            compound_tokens.push(std::mem::take(&mut current_compound));
            combinators.push(Combinator::Child);
        } else if tok == " " {
            if !current_compound.is_empty() && i + 1 < tokens.len() && tokens[i + 1] != ">" {
                compound_tokens.push(std::mem::take(&mut current_compound));
                combinators.push(Combinator::Descendant);
            }
        } else {
            current_compound.push(tok.clone());
        }
        i += 1;
    }

    if !current_compound.is_empty() {
        compound_tokens.push(current_compound);
    }

    if compound_tokens.is_empty() {
        return Err("No compound selectors found".to_string());
    }

    let head = parse_compound_selector(&compound_tokens[0])?;
    let mut tail = Vec::new();

    for (idx, comb) in combinators.into_iter().enumerate() {
        if idx + 1 < compound_tokens.len() {
            let next_compound = parse_compound_selector(&compound_tokens[idx + 1])?;
            tail.push((comb, next_compound));
        }
    }

    Ok(ComplexSelector { head, tail })
}

fn tokenize_selector(s: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut chars = s.chars().peekable();
    let mut current = String::new();

    while let Some(&ch) = chars.peek() {
        if ch == '[' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            let mut bracket = String::new();
            for b in chars.by_ref() {
                bracket.push(b);
                if b == ']' {
                    break;
                }
            }
            tokens.push(bracket);
        } else if ch == ':' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            chars.next(); // consume ':'
            let mut pseudo = String::from(":");
            let mut paren_depth = 0;
            while let Some(&p) = chars.peek() {
                if p == '(' {
                    paren_depth += 1;
                    pseudo.push(chars.next().unwrap());
                } else if p == ')' {
                    paren_depth -= 1;
                    pseudo.push(chars.next().unwrap());
                    if paren_depth == 0 {
                        break;
                    }
                } else if paren_depth == 0
                    && (p == ' ' || p == '>' || p == '[' || p == ':' || p == '.')
                {
                    break;
                } else {
                    pseudo.push(chars.next().unwrap());
                }
            }
            tokens.push(pseudo);
        } else if ch == '.' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            chars.next(); // consume '.'
            let mut class_name = String::from(".");
            while let Some(&c) = chars.peek() {
                if c == ' ' || c == '>' || c == '[' || c == ':' || c == '.' {
                    break;
                }
                class_name.push(chars.next().unwrap());
            }
            tokens.push(class_name);
        } else if ch == '>' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            chars.next();
            tokens.push(">".to_string());
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            while let Some(&w) = chars.peek() {
                if w.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(" ".to_string());
        } else {
            current.push(chars.next().unwrap());
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

fn parse_compound_selector(tokens: &[String]) -> Result<CompoundSelector, String> {
    let mut simple = Vec::new();

    for tok in tokens {
        if tok == "*" {
            simple.push(SimpleSelector::Universal);
        } else if let Some(class_name) = tok.strip_prefix('.') {
            simple.push(SimpleSelector::Class(class_name.to_string()));
        } else if let Some(pseudo_content) = tok.strip_prefix(':') {
            if let Some(paren_idx) = pseudo_content.find('(') {
                let name = &pseudo_content[..paren_idx];
                let arg = pseudo_content[paren_idx + 1..]
                    .strip_suffix(')')
                    .unwrap_or(&pseudo_content[paren_idx + 1..]);
                simple.push(SimpleSelector::PseudoClass {
                    name: name.to_string(),
                    arg: Some(arg.to_string()),
                });
            } else {
                simple.push(SimpleSelector::PseudoClass {
                    name: pseudo_content.to_string(),
                    arg: None,
                });
            }
        } else if tok.starts_with('[') && tok.ends_with(']') {
            let inner = &tok[1..tok.len() - 1].trim();
            simple.push(parse_attribute_selector(inner)?);
        } else {
            // Type name
            simple.push(SimpleSelector::Type(
                tok.strip_prefix('#').unwrap_or(tok).to_string(),
            ));
        }
    }

    Ok(CompoundSelector { simple })
}

fn parse_attribute_selector(s: &str) -> Result<SimpleSelector, String> {
    let ops = [
        ("|=", AttrOp::Dash),
        ("^=", AttrOp::Prefix),
        ("$=", AttrOp::Suffix),
        ("*=", AttrOp::Substring),
        ("~=", AttrOp::Tilde),
        ("=", AttrOp::Exact),
    ];

    for (op_str, op_enum) in ops {
        if let Some((name_part, val_part)) = s.split_once(op_str) {
            let name = name_part.trim().to_string();
            let mut val = val_part.trim().to_string();
            if (val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\''))
            {
                val = val[1..val.len() - 1].to_string();
            }
            return Ok(SimpleSelector::Attribute {
                name,
                op: Some(op_enum),
                val: Some(val),
            });
        }
    }

    Ok(SimpleSelector::Attribute {
        name: s.trim().to_string(),
        op: None,
        val: None,
    })
}

fn get_nested_json_val<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut curr = root;
    for part in path.split('.') {
        match curr {
            Value::Object(map) => {
                curr = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(curr)
}

fn matches_simple(
    selector: &SimpleSelector,
    node: &InspectedNode,
    all_nodes_map: &HashMap<String, &InspectedNode>,
) -> bool {
    match selector {
        SimpleSelector::Universal => true,
        SimpleSelector::Type(name) => node.name == *name,
        SimpleSelector::Class(cls) => match cls.as_str() {
            "dev" => node.dev,
            "optional" => node.optional,
            "peer" => node.peer,
            "prod" => !node.dev && !node.optional && !node.peer,
            "workspace" => node.is_workspace,
            _ => false,
        },
        SimpleSelector::PseudoClass { name, arg } => match name.as_str() {
            "root" | "scope" => node.location.is_empty(),
            "extraneous" => node.extraneous,
            "invalid" => node.invalid.is_some(),
            "missing" => node.missing,
            "outdated" => node
                .query_context
                .get("outdated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            "dev" => node.dev,
            "prod" => !node.dev && !node.optional && !node.peer,
            "optional" => node.optional,
            "peer" => node.peer,
            "empty" => node.to.is_empty(),
            "deduped" => node.deduped,
            "overridden" => node.overridden,
            "workspace" => {
                node.location.starts_with("packages/") || node.location.starts_with("workspaces/")
            }
            "link" => node.is_link,
            "private" => node
                .raw_manifest
                .as_ref()
                .and_then(|m| m.get("private"))
                .is_some_and(|v| v == &Value::Bool(true)),
            "is" => arg
                .as_deref()
                .and_then(|s| QuerySelector::parse(s).ok())
                .is_some_and(|q| matches_query(&q, node, all_nodes_map)),
            "project" => node.location.is_empty(),
            "semver" => {
                if let (Some(range_str), Some(ver_str)) = (arg, &node.version) {
                    if let (Ok(r), Ok(v)) =
                        (Range::parse(range_str.trim()), Version::parse(ver_str))
                    {
                        r.satisfies(&v)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            "not" => {
                if let Some(inner_sel_str) = arg {
                    if let Ok(parsed) = QuerySelector::parse(inner_sel_str) {
                        !matches_query(&parsed, node, all_nodes_map)
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            "has" => {
                if let Some(inner_sel_str) = arg {
                    if let Ok(parsed) = QuerySelector::parse(inner_sel_str) {
                        // Check if any direct child matches
                        node.to.iter().any(|child_loc| {
                            if let Some(child_node) = all_nodes_map.get(child_loc) {
                                matches_query(&parsed, child_node, all_nodes_map)
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        },
        SimpleSelector::Attribute { name, op, val } => {
            let actual = node
                .raw_manifest
                .as_ref()
                .and_then(|m| get_nested_json_val(m, name));
            let fallback = match name.as_str() {
                "name" => Some(Value::String(node.name.clone())),
                "version" => node.version.clone().map(Value::String),
                _ => None,
            };
            let actual = actual.or(fallback.as_ref());
            if op.is_none() {
                return actual.is_some_and(|v| match v {
                    Value::Null | Value::Bool(false) => false,
                    Value::String(s) => !s.is_empty(),
                    Value::Number(n) => n.as_f64() != Some(0.0),
                    _ => true,
                });
            }
            let Some(expected) = val else {
                return false;
            };
            let candidates: Vec<_> = match actual {
                Some(Value::Array(items)) => items.iter().collect(),
                Some(value) => vec![value],
                None => Vec::new(),
            };
            candidates.iter().any(|value| {
                let text = value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string());
                match op {
                    Some(AttrOp::Exact) => text == *expected,
                    Some(AttrOp::Prefix) => text.starts_with(expected),
                    Some(AttrOp::Suffix) => text.ends_with(expected),
                    Some(AttrOp::Substring) => text.contains(expected),
                    Some(AttrOp::Tilde) => text
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|part| part == expected),
                    Some(AttrOp::Dash) => text.starts_with(&format!("{expected}-")),
                    None => false,
                }
            })
        }
    }
}

fn matches_compound(
    compound: &CompoundSelector,
    node: &InspectedNode,
    all_nodes_map: &HashMap<String, &InspectedNode>,
) -> bool {
    compound
        .simple
        .iter()
        .all(|s| matches_simple(s, node, all_nodes_map))
}

fn matches_complex(
    complex: &ComplexSelector,
    node: &InspectedNode,
    all_nodes_map: &HashMap<String, &InspectedNode>,
) -> bool {
    if complex.tail.is_empty() {
        return matches_compound(&complex.head, node, all_nodes_map);
    }

    // Match backwards from target node
    let (last_comb, last_compound) = complex.tail.last().unwrap();
    if !matches_compound(last_compound, node, all_nodes_map) {
        return false;
    }

    // Build prefix complex selector without the last element
    let mut prefix_tail = complex.tail.clone();
    prefix_tail.pop();
    let prefix_complex = ComplexSelector {
        head: complex.head.clone(),
        tail: prefix_tail,
    };

    match last_comb {
        Combinator::Child => {
            // Direct parent must match prefix_complex
            node.from.iter().any(|parent_loc| {
                if let Some(parent_node) = all_nodes_map.get(parent_loc) {
                    matches_complex(&prefix_complex, parent_node, all_nodes_map)
                } else {
                    false
                }
            })
        }
        Combinator::Descendant => {
            // Any ancestor must match prefix_complex
            let mut visited = HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            for p in &node.from {
                queue.push_back(p.clone());
            }

            while let Some(ancestor_loc) = queue.pop_front() {
                if !visited.insert(ancestor_loc.clone()) {
                    continue;
                }
                if let Some(ancestor_node) = all_nodes_map.get(&ancestor_loc) {
                    if matches_complex(&prefix_complex, ancestor_node, all_nodes_map) {
                        return true;
                    }
                    for p in &ancestor_node.from {
                        queue.push_back(p.clone());
                    }
                }
            }

            false
        }
    }
}

pub fn matches_query(
    query: &QuerySelector,
    node: &InspectedNode,
    all_nodes_map: &HashMap<String, &InspectedNode>,
) -> bool {
    query
        .selectors
        .iter()
        .any(|complex| matches_complex(complex, node, all_nodes_map))
}

/// Main entrypoint for `rnpm query`.
pub async fn run_query(project_dir: &Path, options: &QueryOptions) -> anyhow::Result<i32> {
    let tree_opts = TreeOptions {
        package_lock_only: options.package_lock_only,
        ..Default::default()
    };

    let mut root_node = build_dependency_tree(project_dir, &tree_opts)?;
    normalize_workspace_nodes(&mut root_node, project_dir);
    let all_nodes = root_node.collect_all_nodes();

    let mut all_nodes_map = HashMap::new();
    for node in &all_nodes {
        all_nodes_map.insert(node.location.clone(), *node);
    }

    let selector_str = options.selector.as_deref().unwrap_or("*");
    let query_selector = match QuerySelector::parse(selector_str) {
        Ok(q) => q,
        Err(err) => {
            eprintln!("npm error code EQUERY");
            eprintln!("npm error Invalid query selector: {err}");
            return Ok(1);
        }
    };

    let mut matched_json_nodes = Vec::new();

    for node in all_nodes {
        if matches_query(&query_selector, node, &all_nodes_map) {
            matched_json_nodes.push(ordered_query_node(node));
        }
    }

    let json_output = serde_json::to_string_pretty(&matched_json_nodes)?;
    println!("{json_output}");

    Ok(0)
}

fn normalize_workspace_nodes(node: &mut InspectedNode, root: &Path) {
    let mut replacements = HashMap::new();
    let workspaces: HashSet<_> = rnpm_core::workspace::discover_workspaces(root)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| {
            m.path
                .strip_prefix(root)
                .ok()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
        })
        .collect();
    fn normalize(
        node: &mut InspectedNode,
        root: &Path,
        replacements: &mut HashMap<String, String>,
        workspaces: &HashSet<String>,
    ) {
        node.is_workspace = node
            .realpath
            .as_ref()
            .and_then(|p| p.strip_prefix(root).ok())
            .is_some_and(|p| workspaces.contains(&p.to_string_lossy().replace('\\', "/")));
        if let (Some(path), Some(realpath)) = (&node.path, &node.realpath) {
            if path != realpath {
                if let Ok(location) = realpath.strip_prefix(root) {
                    let location = location.to_string_lossy().replace('\\', "/");
                    replacements.insert(node.location.clone(), location.clone());
                    node.location = location;
                    node.path = Some(realpath.clone());
                    node.from.clear();
                    node.resolved = None;
                }
            }
        }
        for child in node.dependencies.values_mut() {
            normalize(child, root, replacements, workspaces);
        }
    }
    fn fix_from(node: &mut InspectedNode, replacements: &HashMap<String, String>) {
        for from in &mut node.from {
            if let Some(target) = replacements.get(from) {
                *from = target.clone();
            }
        }
        for child in node.dependencies.values_mut() {
            fix_from(child, replacements);
        }
    }
    normalize(node, root, &mut replacements, &workspaces);
    fix_from(node, &replacements);
}

fn ordered_query_node(node: &InspectedNode) -> rnpm_core::ordered_json::OrderedJsonValue {
    use rnpm_core::ordered_json::OrderedJsonValue;
    let computed = node.to_query_json();
    let mut map: rnpm_core::ordered_json::OrderedJsonMap = node
        .path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p.join("package.json")).ok())
        .and_then(|s| serde_json::from_str::<OrderedJsonValue>(&s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_else(|| {
            let mut map = rnpm_core::ordered_json::OrderedJsonMap::new();
            for key in ["name", "version"] {
                if let Some(value) = computed.get(key) {
                    map.insert(key.to_string(), value.clone().into());
                }
            }
            if let Some(Value::Object(raw)) = &node.raw_manifest {
                for (key, value) in raw {
                    map.insert(key.clone(), value.clone().into());
                }
            }
            map
        });
    for key in [
        "_id",
        "pkgid",
        "location",
        "path",
        "realpath",
        "resolved",
        "from",
        "to",
        "dev",
        "inBundle",
        "deduped",
        "overridden",
        "queryContext",
    ] {
        if let Some(value) = computed.get(key) {
            map.insert(key.to_string(), value.clone().into());
        }
    }
    OrderedJsonValue::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_selectors() {
        let q = QuerySelector::parse(":root").unwrap();
        assert_eq!(q.selectors.len(), 1);
        assert_eq!(
            q.selectors[0].head.simple[0],
            SimpleSelector::PseudoClass {
                name: "root".to_string(),
                arg: None
            }
        );

        let q = QuerySelector::parse("[name=react]").unwrap();
        assert_eq!(
            q.selectors[0].head.simple[0],
            SimpleSelector::Attribute {
                name: "name".to_string(),
                op: Some(AttrOp::Exact),
                val: Some("react".to_string()),
            }
        );

        let q = QuerySelector::parse("[version^=18]").unwrap();
        assert_eq!(
            q.selectors[0].head.simple[0],
            SimpleSelector::Attribute {
                name: "version".to_string(),
                op: Some(AttrOp::Prefix),
                val: Some("18".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_combinator_child_and_descendant() {
        let q = QuerySelector::parse(":root > [name=react]").unwrap();
        assert_eq!(q.selectors.len(), 1);
        assert_eq!(q.selectors[0].tail.len(), 1);
        assert_eq!(q.selectors[0].tail[0].0, Combinator::Child);

        let q = QuerySelector::parse(":root [name=react]").unwrap();
        assert_eq!(q.selectors[0].tail[0].0, Combinator::Descendant);
    }

    #[test]
    fn test_parse_union_commas() {
        let q = QuerySelector::parse(":root, [name=react]").unwrap();
        assert_eq!(q.selectors.len(), 2);
    }

    #[test]
    fn test_matches_query_node() {
        let mut root = InspectedNode::new_root(
            "my-app".to_string(),
            Some("1.0.0".to_string()),
            Path::new("."),
        );
        root.location = String::new();

        let mut child = InspectedNode::new_root(
            "react".to_string(),
            Some("18.2.0".to_string()),
            Path::new("."),
        );
        child.location = "node_modules/react".to_string();
        child.from.push(String::new());
        root.to.push("node_modules/react".to_string());

        let mut map = HashMap::new();
        map.insert(root.location.clone(), &root);
        map.insert(child.location.clone(), &child);

        let q_root = QuerySelector::parse(":root").unwrap();
        assert!(matches_query(&q_root, &root, &map));
        assert!(!matches_query(&q_root, &child, &map));

        let q_react = QuerySelector::parse("[name=react]").unwrap();
        assert!(matches_query(&q_react, &child, &map));
        assert!(!matches_query(&q_react, &root, &map));

        let q_ver = QuerySelector::parse("[version^=18]").unwrap();
        assert!(matches_query(&q_ver, &child, &map));

        let q_child = QuerySelector::parse(":root > [name=react]").unwrap();
        assert!(matches_query(&q_child, &child, &map));
    }
}
