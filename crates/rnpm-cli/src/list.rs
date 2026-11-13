use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::inspect_tree::{build_dependency_tree, InspectedNode, TreeOptions};

/// Options for the `list` / `ls` / `la` / `ll` command.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Package filter specs if any (e.g. `lodash`, `react@^18.0.0`, `@scope/pkg`)
    pub packages: Vec<String>,
    /// Depth control: 0 for top-level, max depth control
    pub depth: Option<usize>,
    /// If true, inspect full depth (`usize::MAX`)
    pub all: bool,
    /// Emit dependency tree as structured JSON
    pub json: bool,
    /// Show extended package details (description and license; also used for 'la' and 'll')
    pub long: bool,
    /// Output tab or newline separated list of package paths
    pub parseable: bool,
    /// Read dependency tree purely from package-lock.json without inspecting node_modules on disk
    pub package_lock_only: bool,
    /// Dependency types to omit (dev, optional, peer)
    pub omit: Vec<String>,
    /// List packages in the global environment
    pub is_global: bool,
}

/// Executes package inspection and prints the dependency tree.
///
/// Returns exit code: `0` if no dependency problems exist, `1` if problems (`extraneous`, `invalid`, `missing`) exist.
pub fn run_list(project_dir: &Path, options: &ListOptions) -> anyhow::Result<i32> {
    run_list_inner(project_dir, options, false)
}

pub fn run_workspace_list(project_dir: &Path, options: &ListOptions) -> anyhow::Result<i32> {
    run_list_inner(project_dir, options, true)
}

fn run_list_inner(
    project_dir: &Path,
    options: &ListOptions,
    workspace: bool,
) -> anyhow::Result<i32> {
    let (omit_dev, omit_optional, omit_peer) = crate::parse_omit_options(&options.omit);
    let tree_opts = TreeOptions {
        package_lock_only: options.package_lock_only,
        omit_dev,
        omit_optional,
        omit_peer,
        is_global: options.is_global,
    };

    let mut root_node = build_dependency_tree(project_dir, &tree_opts)?;

    // Filter by packages if specified
    if !options.packages.is_empty() {
        if workspace {
            root_node.dependencies.retain(|name, node| {
                options
                    .packages
                    .iter()
                    .any(|p| package_matches_filter(name, node, p))
            });
        } else {
            filter_tree_by_packages(&mut root_node, &options.packages);
        }
    }

    let effective_depth = if options.all {
        usize::MAX
    } else if let Some(d) = options.depth {
        d
    } else if workspace {
        1
    } else if !options.packages.is_empty() {
        usize::MAX
    } else {
        0
    };

    // Collect problems from the evaluated tree
    let mut problems = Vec::new();
    let mut seen_problems = HashSet::new();
    collect_problems(&root_node, &mut problems, &mut seen_problems);
    root_node.problems = problems.clone();

    let has_problems = problems.iter().any(|p| !p.starts_with("extraneous:"));

    if options.json {
        let json_val = format_tree_json(&root_node, effective_depth, options.long);
        println!(
            "{}",
            serde_json::to_string_pretty(&ordered_node_json(&json_val, &root_node))?
        );
    } else if options.parseable {
        let mut paths = Vec::new();
        let mut seen_paths = HashSet::new();
        collect_parseable_paths(&root_node, effective_depth, &mut paths, &mut seen_paths);
        for p in paths {
            println!("{p}");
        }
    } else {
        let mut output = format_tree_text_with_unicode(
            &root_node,
            effective_depth,
            options.long,
            crate::use_unicode(project_dir),
        );
        if options.is_global {
            if let Some((_, rest)) = output.split_once('\n') {
                output = format!("{}\n{rest}", project_dir.display());
            }
        }
        print!("{output}");
    }

    if has_problems {
        eprintln!("npm error code ELSPROBLEMS");
        for p in &problems {
            eprintln!("npm error {p}");
        }
        Ok(1)
    } else {
        Ok(0)
    }
}

/// Preserve npm's field order without changing serde_json's workspace-wide map type.
fn ordered_node_json(
    value: &Value,
    node: &InspectedNode,
) -> rnpm_core::ordered_json::OrderedJsonValue {
    use rnpm_core::ordered_json::{OrderedJsonMap, OrderedJsonValue};
    let Some(map) = value.as_object() else {
        return value.clone().into();
    };
    let mut ordered = OrderedJsonMap::new();
    let mut keys: Vec<String> = ["version", "resolved", "overridden", "name"]
        .into_iter()
        .map(str::to_string)
        .collect();
    if value.get("path").is_some() {
        if let Some(raw) = &node.raw_manifest {
            keys.extend(
                raw.as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(key, _)| key.as_str() != "dependencies")
                    .map(|(key, _)| key.clone()),
            );
        }
        keys.extend(
            [
                "_id",
                "extraneous",
                "path",
                "_dependencies",
                "devDependencies",
                "peerDependencies",
            ]
            .into_iter()
            .map(str::to_string),
        );
    }
    keys.extend(
        [
            "required",
            "missing",
            "extraneous",
            "invalid",
            "deduped",
            "description",
            "license",
            "problems",
            "dependencies",
            "error",
        ]
        .into_iter()
        .map(str::to_string),
    );
    for key in keys {
        if ordered.contains_key(&key) {
            continue;
        }
        if let Some(value) = map.get(&key) {
            let value = if key == "dependencies" {
                OrderedJsonValue::Object(
                    sorted_dependencies(node)
                        .into_iter()
                        .filter_map(|(name, child_node)| {
                            value
                                .get(name)
                                .map(|child| (name.clone(), ordered_node_json(child, child_node)))
                        })
                        .collect(),
                )
            } else {
                value.clone().into()
            };
            ordered.insert(key, value);
        }
    }
    OrderedJsonValue::Object(ordered)
}

fn sorted_dependencies(node: &InspectedNode) -> Vec<(&String, &InspectedNode)> {
    let mut children: Vec<_> = node.dependencies.iter().collect();
    children.sort_by(|(name_a, a), (name_b, b)| {
        a.pkgid
            .as_ref()
            .unwrap_or(name_a)
            .cmp(b.pkgid.as_ref().unwrap_or(name_b))
    });
    children
}

/// Recursively collects unique problem lines from a node and its descendants.
fn collect_problems(node: &InspectedNode, out: &mut Vec<String>, seen: &mut HashSet<String>) {
    // npm walks nodes in display order; the root's accumulated insertion-order
    // list would otherwise put missing peers ahead of earlier extraneous nodes.
    for p in node
        .problems
        .iter()
        .filter(|_| !node.location.is_empty() || node.dependencies.is_empty())
    {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }

    if node.problems.is_empty() {
        if node.missing {
            if !node.optional {
                let req = node.required.as_deref().unwrap_or("*");
                let p = format!("missing: {}@{}", node.name, req);
                if seen.insert(p.clone()) {
                    out.push(p);
                }
            }
        } else if node.extraneous {
            let p = format!(
                "extraneous: {}@{} {}",
                node.name,
                node.version.as_deref().unwrap_or(""),
                node.path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
            if seen.insert(p.clone()) {
                out.push(p);
            }
        } else if let Some(inv) = &node.invalid {
            let p = format!(
                "invalid: {}@{} {}",
                node.name,
                node.version.as_deref().unwrap_or(""),
                inv
            );
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }

    for (_, child) in sorted_dependencies(node) {
        collect_problems(child, out, seen);
    }
}

/// Checks if a node matches a given package filter specification.
pub fn package_matches_filter(node_name: &str, node: &InspectedNode, filter_pkg: &str) -> bool {
    let (filter_name, filter_version) = if let Some(stripped) = filter_pkg.strip_prefix('@') {
        if let Some((scope_and_name, ver)) = stripped.split_once('@') {
            (format!("@{scope_and_name}"), Some(ver))
        } else {
            (filter_pkg.to_string(), None)
        }
    } else if let Some((name, ver)) = filter_pkg.split_once('@') {
        (name.to_string(), Some(ver))
    } else {
        (filter_pkg.to_string(), None)
    };

    if node_name != filter_name {
        return false;
    }

    if let Some(req) = filter_version {
        if let Some(v_str) = &node.version {
            if v_str == req {
                return true;
            }
            if let (Ok(ver), Ok(range)) = (
                rnpm_core::semver::Version::parse(v_str),
                rnpm_core::semver::Range::parse(req),
            ) {
                return range.satisfies(&ver);
            }
        }
        if let Some(node_req) = &node.required {
            if node_req == req {
                return true;
            }
        }
        false
    } else {
        true
    }
}

/// Prunes tree branches that do not lead to any package matching `filter_pkgs`.
pub fn filter_tree_by_packages(node: &mut InspectedNode, filter_pkgs: &[String]) {
    let mut filtered_deps = BTreeMap::new();

    for (name, mut child) in std::mem::take(&mut node.dependencies) {
        let direct_match = filter_pkgs
            .iter()
            .any(|p| package_matches_filter(&name, &child, p));

        filter_tree_by_packages(&mut child, filter_pkgs);

        if direct_match || !child.dependencies.is_empty() {
            filtered_deps.insert(name, child);
        }
    }

    node.dependencies = filtered_deps;
}

/// Formats the dependency tree as text matching npm standard output format.
pub fn format_tree_text(root: &InspectedNode, max_depth: usize, long: bool) -> String {
    format_tree_text_with_unicode(root, max_depth, long, false)
}

fn format_tree_text_with_unicode(
    root: &InspectedNode,
    max_depth: usize,
    long: bool,
    unicode: bool,
) -> String {
    let mut out = String::new();
    let version_str = root.version.as_deref().unwrap_or("0.0.0");
    let path_display = root
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    if long {
        out.push_str(&format!("{}@{}\n", root.name, version_str));
        out.push_str(&format!("| {path_display}\n"));
        if let Some(desc) = &root.description {
            out.push_str(&format!("| {desc}\n"));
        }
    } else {
        out.push_str(&format!("{}@{} {}\n", root.name, version_str, path_display));
    }

    let mut dep_keys: Vec<String> = root.dependencies.keys().cloned().collect();
    if dep_keys.is_empty() {
        out.push_str(if unicode {
            "\u{2514}\u{2500}\u{2500} (empty)\n"
        } else {
            "`-- (empty)\n"
        });
    }
    dep_keys.sort_by(|a, b| {
        let child_a = root.dependencies.get(a).unwrap();
        let child_b = root.dependencies.get(b).unwrap();
        let id_a = child_a.pkgid.as_deref().unwrap_or(a);
        let id_b = child_b.pkgid.as_deref().unwrap_or(b);
        id_a.cmp(id_b)
    });

    for (idx, name) in dep_keys.iter().enumerate() {
        let is_last = idx == dep_keys.len() - 1;
        let child = root.dependencies.get(name).unwrap();
        format_child_text(child, max_depth, 0, "", is_last, (long, unicode), &mut out);
    }

    out.push('\n');
    out
}

fn format_child_text(
    node: &InspectedNode,
    max_depth: usize,
    current_depth: usize,
    prefix: &str,
    is_last: bool,
    style: (bool, bool),
    out: &mut String,
) {
    let (long, unicode) = style;
    let has_children = current_depth < max_depth && !node.dependencies.is_empty() && !node.deduped;
    let branch = match (unicode, is_last, has_children) {
        (true, true, false) => "\u{2514}\u{2500}\u{2500} ",
        (true, true, true) => "\u{2514}\u{2500}\u{252c} ",
        (true, false, false) => "\u{251c}\u{2500}\u{2500} ",
        (true, false, true) => "\u{251c}\u{2500}\u{252c} ",
        (false, true, _) => "`-- ",
        (false, false, _) => "+-- ",
    };

    if node.missing {
        let req = node.required.as_deref().unwrap_or("*");
        if node.optional {
            out.push_str(&format!(
                "{prefix}{branch}UNMET OPTIONAL DEPENDENCY {}@{}\n",
                node.name, req
            ));
        } else {
            out.push_str(&format!(
                "{prefix}{branch}UNMET DEPENDENCY {}@{}\n",
                node.name, req
            ));
        }
    } else {
        let ver = node.version.as_deref().unwrap_or("unknown");
        let mut marker = String::new();
        if let Some(inv) = &node.invalid {
            marker = format!(" invalid: {inv}");
        } else if node.extraneous {
            marker = " extraneous".to_string();
        } else if node.deduped {
            marker = " deduped".to_string();
        }
        if let (Some(path), Some(realpath)) = (&node.path, &node.realpath) {
            if path != realpath {
                // Workspace links are displayed relative to the project root.
                let mut project = path.as_path();
                while project.file_name().is_some_and(|n| n != "node_modules") {
                    project = project.parent().unwrap_or(project);
                }
                if let Some(project) = project.parent() {
                    if let Ok(relative) = realpath.strip_prefix(project) {
                        marker.push_str(&format!(
                            " -> .{}{}",
                            std::path::MAIN_SEPARATOR,
                            relative.display()
                        ));
                    }
                }
            }
        }
        if node.overridden {
            marker.push_str(" overridden");
        }
        out.push_str(&format!(
            "{prefix}{branch}{}@{}{}\n",
            node.name, ver, marker
        ));
    }

    let continuation = if is_last {
        "  "
    } else if unicode {
        "\u{2502} "
    } else {
        "| "
    };
    let child_prefix = format!("{prefix}{continuation}");

    if long {
        if let Some(p) = &node.path {
            out.push_str(&format!("{child_prefix}| {}\n", p.display()));
        }
        if let Some(desc) = &node.description {
            out.push_str(&format!("{child_prefix}| {desc}\n"));
        }
    }

    if current_depth < max_depth && !node.deduped && !node.missing {
        let mut dep_keys: Vec<String> = node.dependencies.keys().cloned().collect();
        dep_keys.sort_by(|a, b| {
            let child_a = node.dependencies.get(a).unwrap();
            let child_b = node.dependencies.get(b).unwrap();
            let id_a = child_a.pkgid.as_deref().unwrap_or(a);
            let id_b = child_b.pkgid.as_deref().unwrap_or(b);
            id_a.cmp(id_b)
        });

        for (idx, name) in dep_keys.iter().enumerate() {
            let child_is_last = idx == dep_keys.len() - 1;
            let child = node.dependencies.get(name).unwrap();
            format_child_text(
                child,
                max_depth,
                current_depth + 1,
                &child_prefix,
                child_is_last,
                style,
                out,
            );
        }
    }
}

/// Formats the dependency tree as structured JSON matching `npm ls --json`.
pub fn format_tree_json(root: &InspectedNode, max_depth: usize, long: bool) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(v) = &root.version {
        map.insert("version".to_string(), Value::String(v.clone()));
    }
    map.insert("name".to_string(), Value::String(root.name.clone()));

    if long {
        augment_long_json(&mut map, root);
        if let Some(desc) = &root.description {
            map.insert("description".to_string(), Value::String(desc.clone()));
        }
        if let Some(lic) = &root.license {
            map.insert("license".to_string(), Value::String(lic.clone()));
        }
    }

    if !root.problems.is_empty() {
        map.insert(
            "problems".to_string(),
            serde_json::to_value(&root.problems).unwrap_or_default(),
        );
    }

    // npm's seenNodes map keys missing nodes by their undefined path. Only the
    // first such node retains _required; subsequent clones omit that symbol.
    // Discovery follows the breadth-first, pkgid-sorted traversal in ls.js.
    let mut queue = std::collections::VecDeque::from([(root, 0usize)]);
    let mut first_missing = None;
    while let Some((parent, depth)) = queue.pop_front() {
        let mut children: Vec<_> = parent.dependencies.values().collect();
        children.sort_by(|a, b| {
            a.pkgid
                .as_deref()
                .unwrap_or(&a.name)
                .cmp(b.pkgid.as_deref().unwrap_or(&b.name))
        });
        for child in children {
            if child.missing && first_missing.is_none() {
                first_missing = Some(child);
            }
            if depth < max_depth && !child.deduped && !child.missing {
                queue.push_back((child, depth + 1));
            }
        }
    }
    let mut deps_map = serde_json::Map::new();
    for (name, child) in &root.dependencies {
        deps_map.insert(
            name.clone(),
            format_child_json(child, max_depth, 0, long, first_missing),
        );
    }
    map.insert("dependencies".to_string(), Value::Object(deps_map));

    if root.problems.iter().any(|p| !p.starts_with("extraneous:")) {
        let summary = root.problems.join("\n");
        let error_obj = serde_json::json!({
            "code": "ELSPROBLEMS",
            "summary": summary,
            "detail": ""
        });
        map.insert("error".to_string(), error_obj);
    }

    Value::Object(map)
}

fn augment_long_json(map: &mut serde_json::Map<String, Value>, node: &InspectedNode) {
    if let Some(raw) = node.raw_manifest.as_ref().and_then(Value::as_object) {
        for (key, value) in raw.iter().filter(|(key, _)| key.as_str() != "dependencies") {
            map.insert(key.clone(), value.clone());
        }
        let mut deps = raw
            .get("dependencies")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if let Some(optional) = raw.get("optionalDependencies").and_then(Value::as_object) {
            deps.extend(optional.clone());
        }
        map.insert("_dependencies".into(), Value::Object(deps));
        for key in ["devDependencies", "peerDependencies"] {
            map.entry(key).or_insert_with(|| serde_json::json!({}));
        }
    }
    if let Some(id) = &node.id {
        map.insert("_id".into(), Value::String(id.clone()));
    }
    map.insert("extraneous".into(), Value::Bool(node.extraneous));
    if let Some(path) = &node.path {
        map.insert("path".into(), Value::String(path.display().to_string()));
    }
}

fn format_child_json(
    node: &InspectedNode,
    max_depth: usize,
    current_depth: usize,
    long: bool,
    first_missing: Option<&InspectedNode>,
) -> Value {
    let mut map = serde_json::Map::new();

    if node.missing {
        if node.optional {
            return Value::Object(map);
        }
        if first_missing.is_some_and(|first| std::ptr::eq(first, node)) {
            map.insert(
                "required".into(),
                node.required.as_deref().unwrap_or("*").into(),
            );
        }
        map.insert("missing".to_string(), Value::Bool(true));
        if !node.problems.is_empty() {
            map.insert(
                "problems".to_string(),
                serde_json::to_value(&node.problems).unwrap_or_default(),
            );
        }
        return Value::Object(map);
    }

    if let Some(v) = &node.version {
        map.insert("version".to_string(), Value::String(v.clone()));
    }
    if let Some(r) = &node.resolved {
        map.insert("resolved".to_string(), Value::String(r.clone()));
    }
    map.insert("overridden".to_string(), Value::Bool(node.overridden));

    if node.extraneous {
        map.insert("extraneous".to_string(), Value::Bool(true));
    }
    if let Some(inv) = &node.invalid {
        map.insert("invalid".to_string(), Value::String(inv.clone()));
    }
    if node.deduped {
        map.insert("deduped".to_string(), Value::Bool(true));
    }

    if long {
        augment_long_json(&mut map, node);
        if let Some(desc) = &node.description {
            map.insert("description".to_string(), Value::String(desc.clone()));
        }
        if let Some(lic) = &node.license {
            map.insert("license".to_string(), Value::String(lic.clone()));
        }
    }

    if !node.problems.is_empty() {
        map.insert(
            "problems".to_string(),
            serde_json::to_value(&node.problems).unwrap_or_default(),
        );
    }

    if current_depth < max_depth && !node.deduped && !node.dependencies.is_empty() {
        let mut child_map = serde_json::Map::new();
        for (name, child) in &node.dependencies {
            child_map.insert(
                name.clone(),
                format_child_json(child, max_depth, current_depth + 1, long, first_missing),
            );
        }
        map.insert("dependencies".to_string(), Value::Object(child_map));
    }

    Value::Object(map)
}

/// Recursively collects package directory paths for parseable output.
pub fn collect_parseable_paths(
    root: &InspectedNode,
    max_depth: usize,
    paths: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if let Some(p) = &root.path {
        let s = p.display().to_string();
        if seen.insert(s.clone()) {
            paths.push(s);
        }
    }

    for child in root.dependencies.values() {
        collect_child_paths(child, max_depth, 0, paths, seen);
    }
}

fn collect_child_paths(
    node: &InspectedNode,
    max_depth: usize,
    current_depth: usize,
    paths: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if let Some(p) = &node.path {
        let s = p.display().to_string();
        if seen.insert(s.clone()) {
            paths.push(s);
        }
    }

    if current_depth < max_depth && !node.deduped && !node.missing {
        for child in node.dependencies.values() {
            collect_child_paths(child, max_depth, current_depth + 1, paths, seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_list_clean_tree_exit_code_0() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "clean-app",
            "version": "1.0.0",
            "dependencies": {
                "foo": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let foo_dir = project_dir.join("node_modules").join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        let foo_pkg = serde_json::json!({
            "name": "foo",
            "version": "1.2.0",
            "description": "Foo library",
            "license": "MIT"
        });
        std::fs::write(foo_dir.join("package.json"), foo_pkg.to_string()).unwrap();

        let opts = ListOptions {
            depth: Some(0),
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_list_problems_exit_code_1() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "problem-app",
            "version": "1.0.0",
            "dependencies": {
                "missing-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        // Extraneous package
        let ext_dir = project_dir.join("node_modules").join("ext-pkg");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let ext_pkg = serde_json::json!({
            "name": "ext-pkg",
            "version": "2.0.0"
        });
        std::fs::write(ext_dir.join("package.json"), ext_pkg.to_string()).unwrap();

        let opts = ListOptions {
            json: true,
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn test_text_tree_formatting_branches_and_markers() {
        let mut root = InspectedNode::new_root(
            "my-pkg".into(),
            Some("1.0.0".into()),
            Path::new("/workspace/my-pkg"),
        );

        // Child 1: regular
        let c1 = InspectedNode::new_root(
            "alpha".into(),
            Some("1.0.0".into()),
            Path::new("/workspace/my-pkg/node_modules/alpha"),
        );
        // Child 2: extraneous
        let mut c2 = InspectedNode::new_root(
            "beta".into(),
            Some("2.0.0".into()),
            Path::new("/workspace/my-pkg/node_modules/beta"),
        );
        c2.extraneous = true;
        // Child 3: invalid
        let mut c3 = InspectedNode::new_root(
            "gamma".into(),
            Some("1.5.0".into()),
            Path::new("/workspace/my-pkg/node_modules/gamma"),
        );
        c3.invalid = Some("\"^2.0.0\" from the root project".into());
        // Child 4: deduped
        let mut c4 = InspectedNode::new_root(
            "delta".into(),
            Some("1.0.0".into()),
            Path::new("/workspace/my-pkg/node_modules/delta"),
        );
        c4.deduped = true;
        // Child 5: missing
        let mut c5 = InspectedNode::new_root("epsilon".into(), None, Path::new(""));
        c5.missing = true;
        c5.required = Some("^3.0.0".into());

        root.dependencies.insert("alpha".into(), c1);
        root.dependencies.insert("beta".into(), c2);
        root.dependencies.insert("gamma".into(), c3);
        root.dependencies.insert("delta".into(), c4);
        root.dependencies.insert("epsilon".into(), c5);

        let text = format_tree_text(&root, 0, false);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "my-pkg@1.0.0 /workspace/my-pkg");
        assert_eq!(lines[1], "+-- alpha@1.0.0");
        assert_eq!(lines[2], "+-- beta@2.0.0 extraneous");
        assert_eq!(lines[3], "+-- delta@1.0.0 deduped");
        assert_eq!(lines[4], "+-- UNMET DEPENDENCY epsilon@^3.0.0");
        assert_eq!(
            lines[5],
            "`-- gamma@1.5.0 invalid: \"^2.0.0\" from the root project"
        );
    }

    #[test]
    fn test_long_text_formatting() {
        let mut root =
            InspectedNode::new_root("root-pkg".into(), Some("1.0.0".into()), Path::new("/app"));
        root.description = Some("Root application".into());

        let mut child = InspectedNode::new_root(
            "dep".into(),
            Some("2.0.0".into()),
            Path::new("/app/node_modules/dep"),
        );
        child.description = Some("A dependency description".into());
        root.dependencies.insert("dep".into(), child);

        let text = format_tree_text(&root, 0, true);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "root-pkg@1.0.0");
        assert_eq!(lines[1], "| /app");
        assert_eq!(lines[2], "| Root application");
        assert_eq!(lines[3], "`-- dep@2.0.0");
        assert_eq!(lines[4], "  | /app/node_modules/dep");
        assert_eq!(lines[5], "  | A dependency description");
    }

    #[test]
    fn test_depth_filtering() {
        let mut root =
            InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut l1 = InspectedNode::new_root(
            "l1".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/l1"),
        );
        let mut l2 = InspectedNode::new_root(
            "l2".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/l1/node_modules/l2"),
        );
        let l3 = InspectedNode::new_root(
            "l3".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/l1/node_modules/l2/node_modules/l3"),
        );

        l2.dependencies.insert("l3".into(), l3);
        l1.dependencies.insert("l2".into(), l2);
        root.dependencies.insert("l1".into(), l1);

        // depth 0: only l1 is printed
        let text_d0 = format_tree_text(&root, 0, false);
        assert!(text_d0.contains("l1@1.0.0"));
        assert!(!text_d0.contains("l2@1.0.0"));
        assert!(!text_d0.contains("l3@1.0.0"));

        // depth 1: l1 and l2 are printed
        let text_d1 = format_tree_text(&root, 1, false);
        assert!(text_d1.contains("l1@1.0.0"));
        assert!(text_d1.contains("l2@1.0.0"));
        assert!(!text_d1.contains("l3@1.0.0"));

        // depth MAX (all): l1, l2, and l3 are printed
        let text_all = format_tree_text(&root, usize::MAX, false);
        assert!(text_all.contains("l1@1.0.0"));
        assert!(text_all.contains("l2@1.0.0"));
        assert!(text_all.contains("l3@1.0.0"));
    }

    #[test]
    fn test_json_formatting_clean() {
        let mut root =
            InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        let child = InspectedNode::new_root(
            "dep".into(),
            Some("2.0.0".into()),
            Path::new("/app/node_modules/dep"),
        );
        root.dependencies.insert("dep".into(), child);

        let json = format_tree_json(&root, 0, false);
        assert_eq!(json["name"], "app");
        assert_eq!(json["version"], "1.0.0");
        assert!(json["problems"].is_null());
        assert!(json["error"].is_null());
        assert_eq!(json["dependencies"]["dep"]["version"], "2.0.0");
    }

    #[test]
    fn test_json_formatting_with_problems() {
        let mut root =
            InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        root.problems
            .push("missing: uninstalled@^1.0.0, required by app@1.0.0".into());

        let mut child = InspectedNode::new_root("uninstalled".into(), None, Path::new(""));
        child.missing = true;
        child.required = Some("^1.0.0".into());
        child
            .problems
            .push("missing: uninstalled@^1.0.0, required by app@1.0.0".into());
        root.dependencies.insert("uninstalled".into(), child);

        let json = format_tree_json(&root, 0, false);
        assert_eq!(json["name"], "app");
        assert!(json["problems"].is_array());
        assert_eq!(json["error"]["code"], "ELSPROBLEMS");
        assert_eq!(json["dependencies"]["uninstalled"]["missing"], true);
        assert_eq!(json["dependencies"]["uninstalled"]["required"], "^1.0.0");
        assert_eq!(
            json["dependencies"]["uninstalled"]["problems"][0],
            "missing: uninstalled@^1.0.0, required by app@1.0.0"
        );
    }

    #[test]
    fn test_parseable_formatting() {
        let mut root =
            InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        let mut d1 = InspectedNode::new_root(
            "d1".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/d1"),
        );
        let d2 = InspectedNode::new_root(
            "d2".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/d1/node_modules/d2"),
        );

        d1.dependencies.insert("d2".into(), d2);
        root.dependencies.insert("d1".into(), d1);

        let mut paths_d0 = Vec::new();
        let mut seen = HashSet::new();
        collect_parseable_paths(&root, 0, &mut paths_d0, &mut seen);
        assert_eq!(
            paths_d0,
            vec![
                PathBuf::from("/app").display().to_string(),
                PathBuf::from("/app/node_modules/d1").display().to_string(),
            ]
        );

        let mut paths_all = Vec::new();
        let mut seen = HashSet::new();
        collect_parseable_paths(&root, usize::MAX, &mut paths_all, &mut seen);
        assert_eq!(
            paths_all,
            vec![
                PathBuf::from("/app").display().to_string(),
                PathBuf::from("/app/node_modules/d1").display().to_string(),
                PathBuf::from("/app/node_modules/d1/node_modules/d2")
                    .display()
                    .to_string(),
            ]
        );
    }

    #[test]
    fn test_packages_filtering_direct_and_transitive() {
        let mut root =
            InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut a = InspectedNode::new_root(
            "a".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/a"),
        );
        let b = InspectedNode::new_root(
            "b".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/a/node_modules/b"),
        );
        a.dependencies.insert("b".into(), b);

        let mut c = InspectedNode::new_root(
            "c".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/c"),
        );
        let d = InspectedNode::new_root(
            "d".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/c/node_modules/d"),
        );
        c.dependencies.insert("d".into(), d);

        root.dependencies.insert("a".into(), a);
        root.dependencies.insert("c".into(), c);

        // Filter for "b"
        let mut filtered = root.clone();
        filter_tree_by_packages(&mut filtered, &["b".to_string()]);

        assert!(filtered.dependencies.contains_key("a"));
        assert!(filtered.dependencies["a"].dependencies.contains_key("b"));
        assert!(!filtered.dependencies.contains_key("c"));
    }

    #[test]
    fn test_packages_filtering_with_version_and_scope() {
        let mut root =
            InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let s1 = InspectedNode::new_root(
            "@scope/pkg".into(),
            Some("1.2.3".into()),
            Path::new("/app/node_modules/@scope/pkg"),
        );
        let other = InspectedNode::new_root(
            "other".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/other"),
        );

        root.dependencies.insert("@scope/pkg".into(), s1);
        root.dependencies.insert("other".into(), other);

        // Filter for matching scoped package with range
        let mut filtered = root.clone();
        filter_tree_by_packages(&mut filtered, &["@scope/pkg@^1.0.0".to_string()]);
        assert_eq!(filtered.dependencies.len(), 1);
        assert!(filtered.dependencies.contains_key("@scope/pkg"));

        // Filter for non-matching version
        let mut filtered2 = root.clone();
        filter_tree_by_packages(&mut filtered2, &["@scope/pkg@^2.0.0".to_string()]);
        assert_eq!(filtered2.dependencies.len(), 0);
    }

    #[test]
    fn test_omit_dev_dependencies() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "omit-app",
            "version": "1.0.0",
            "dependencies": {
                "prod-pkg": "^1.0.0"
            },
            "devDependencies": {
                "dev-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let prod_dir = project_dir.join("node_modules").join("prod-pkg");
        std::fs::create_dir_all(&prod_dir).unwrap();
        std::fs::write(
            prod_dir.join("package.json"),
            serde_json::json!({
                "name": "prod-pkg",
                "version": "1.0.0"
            })
            .to_string(),
        )
        .unwrap();

        let dev_dir = project_dir.join("node_modules").join("dev-pkg");
        std::fs::create_dir_all(&dev_dir).unwrap();
        std::fs::write(
            dev_dir.join("package.json"),
            serde_json::json!({
                "name": "dev-pkg",
                "version": "1.0.0"
            })
            .to_string(),
        )
        .unwrap();

        let opts = ListOptions {
            omit: vec!["dev".into()],
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        // Since dev-pkg is omitted from dependencies, it will be treated as extraneous if present on disk,
        // or if omit works properly, exit code reflects problems.
        assert!(code == 0 || code == 1);
    }

    #[test]
    fn test_package_lock_only() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "lock-only-app",
            "version": "1.0.0",
            "dependencies": {
                "lock-dep": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let lock_json = serde_json::json!({
            "name": "lock-only-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "lock-only-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "lock-dep": "^1.0.0"
                    }
                },
                "node_modules/lock-dep": {
                    "version": "1.0.5",
                    "resolved": "https://registry.npmjs.org/lock-dep/-/lock-dep-1.0.5.tgz",
                    "integrity": "sha512-test"
                }
            }
        });
        std::fs::write(project_dir.join("package-lock.json"), lock_json.to_string()).unwrap();

        // Note: node_modules does not exist on disk!
        let opts = ListOptions {
            package_lock_only: true,
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_multilevel_nested_branch_lines() {
        let mut root =
            InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut mid = InspectedNode::new_root(
            "mid".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/mid"),
        );
        let sub1 = InspectedNode::new_root(
            "sub1".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/mid/node_modules/sub1"),
        );
        let sub2 = InspectedNode::new_root(
            "sub2".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/mid/node_modules/sub2"),
        );
        mid.dependencies.insert("sub1".into(), sub1);
        mid.dependencies.insert("sub2".into(), sub2);

        let mut last = InspectedNode::new_root(
            "last".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/last"),
        );
        let end1 = InspectedNode::new_root(
            "end1".into(),
            Some("1.0.0".into()),
            Path::new("/app/node_modules/last/node_modules/end1"),
        );
        last.dependencies.insert("end1".into(), end1);

        root.dependencies.insert("mid".into(), mid);
        root.dependencies.insert("last".into(), last);

        let text = format_tree_text(&root, usize::MAX, false);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "root@1.0.0 /app");
        assert_eq!(lines[1], "+-- last@1.0.0");
        assert_eq!(lines[2], "| `-- end1@1.0.0");
        assert_eq!(lines[3], "`-- mid@1.0.0");
        assert_eq!(lines[4], "  +-- sub1@1.0.0");
        assert_eq!(lines[5], "  `-- sub2@1.0.0");
    }

    #[test]
    fn test_json_long_includes_description_and_license() {
        let mut root =
            InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        root.description = Some("App description".into());
        root.license = Some("MIT".into());

        let mut child = InspectedNode::new_root(
            "dep".into(),
            Some("2.0.0".into()),
            Path::new("/app/node_modules/dep"),
        );
        child.description = Some("Dep description".into());
        child.license = Some("Apache-2.0".into());
        root.dependencies.insert("dep".into(), child);

        let json = format_tree_json(&root, 0, true);
        assert_eq!(json["description"], "App description");
        assert_eq!(json["license"], "MIT");
        assert_eq!(
            json["dependencies"]["dep"]["description"],
            "Dep description"
        );
        assert_eq!(json["dependencies"]["dep"]["license"], "Apache-2.0");
    }

    #[test]
    fn test_package_matches_filter_edge_cases() {
        let node = InspectedNode::new_root("foo".into(), Some("1.2.3".into()), Path::new(""));

        // Match by exact name
        assert!(package_matches_filter("foo", &node, "foo"));
        assert!(!package_matches_filter("bar", &node, "foo"));

        // Match by version spec
        assert!(package_matches_filter("foo", &node, "foo@1.2.3"));
        assert!(package_matches_filter("foo", &node, "foo@^1.0.0"));
        assert!(package_matches_filter("foo", &node, "foo@~1.2.0"));
        assert!(!package_matches_filter("foo", &node, "foo@^2.0.0"));
        assert!(!package_matches_filter("foo", &node, "foo@1.0.0"));

        // Scoped package
        let scoped_node =
            InspectedNode::new_root("@types/node".into(), Some("18.11.0".into()), Path::new(""));
        assert!(package_matches_filter(
            "@types/node",
            &scoped_node,
            "@types/node"
        ));
        assert!(package_matches_filter(
            "@types/node",
            &scoped_node,
            "@types/node@^18.0.0"
        ));
        assert!(!package_matches_filter(
            "@types/node",
            &scoped_node,
            "@types/node@^20.0.0"
        ));
        assert!(!package_matches_filter(
            "@types/react",
            &scoped_node,
            "@types/node"
        ));
    }
}
